// Package transport publishes spooled events to the collector over NATS.
//
// The node holds a publish-only, subject-scoped credential. Server-side account
// permissions restrict it to `honeynet.events.<node_id>.>` with no subscribe
// rights on any subject, so compromising a sensor yields no visibility into the
// rest of the fleet and no ability to forge another node's events. See design
// doc section 4.4.
package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/honeynet/node/internal/spool"
)

// Config describes how to reach the collector.
type Config struct {
	URL      string
	NodeID   string
	Subject  string
	CertFile string
	KeyFile  string
	CAFile   string

	// BatchSize bounds how many spooled records are published per drain cycle.
	BatchSize int
	// DrainInterval is the idle poll period. Publication is also triggered
	// immediately on append via Notify.
	DrainInterval time.Duration
}

// DefaultConfig returns publication settings tuned for a sensor on a
// commodity VPS link.
func DefaultConfig(nodeID string) Config {
	return Config{
		NodeID:        nodeID,
		Subject:       "honeynet.events." + nodeID,
		BatchSize:     256,
		DrainInterval: 2 * time.Second,
	}
}

// Publisher drains a spool into NATS.
type Publisher struct {
	cfg    Config
	sp     *spool.Spool
	log    *slog.Logger
	nc     *nats.Conn
	notify chan struct{}
}

// New creates a Publisher. The NATS connection is established lazily by Run so
// that a node still starts -- and still records to its spool -- when the
// collector is unreachable at boot.
func New(cfg Config, sp *spool.Spool, log *slog.Logger) *Publisher {
	return &Publisher{cfg: cfg, sp: sp, log: log, notify: make(chan struct{}, 1)}
}

// Notify signals that new records are available, so the next drain happens
// immediately rather than waiting for the poll interval.
func (p *Publisher) Notify() {
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

func (p *Publisher) connect() error {
	if p.nc != nil && p.nc.IsConnected() {
		return nil
	}

	opts := []nats.Option{
		nats.Name("honeynode/" + p.cfg.NodeID),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			p.log.Warn("collector link down, buffering to spool", "err", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			p.log.Info("collector link restored")
		}),
	}

	// mTLS is mandatory in production. It is optional only so the local test
	// harness can run against a plain nats-server without a PKI.
	if p.cfg.CertFile != "" && p.cfg.KeyFile != "" {
		opts = append(opts, nats.ClientCert(p.cfg.CertFile, p.cfg.KeyFile))
	}
	if p.cfg.CAFile != "" {
		opts = append(opts, nats.RootCAs(p.cfg.CAFile))
	}

	nc, err := nats.Connect(p.cfg.URL, opts...)
	if err != nil {
		return fmt.Errorf("connect %s: %w", p.cfg.URL, err)
	}
	p.nc = nc
	return nil
}

// Run drains the spool until the context is cancelled.
func (p *Publisher) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.cfg.DrainInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Best-effort final flush so a clean shutdown does not strand
			// events that are already durably recorded.
			_ = p.drain()
			if p.nc != nil {
				_ = p.nc.Drain()
			}
			return ctx.Err()
		case <-ticker.C:
		case <-p.notify:
		}

		if err := p.drain(); err != nil && !errors.Is(err, nats.ErrConnectionClosed) {
			p.log.Debug("drain cycle incomplete", "err", err)
		}
	}
}

func (p *Publisher) drain() error {
	if err := p.connect(); err != nil {
		return err
	}

	for {
		batch, err := p.sp.Peek(p.cfg.BatchSize)
		if err != nil {
			return fmt.Errorf("peek spool: %w", err)
		}
		if len(batch.Blobs) == 0 {
			return nil
		}

		for _, blob := range batch.Blobs {
			if err := p.nc.Publish(p.cfg.Subject, blob); err != nil {
				return fmt.Errorf("publish: %w", err)
			}
		}

		// Flush before acking. Without this the records would be deleted from
		// the spool while still sitting in the client's write buffer, and a
		// crash here would lose them.
		if err := p.nc.FlushTimeout(10 * time.Second); err != nil {
			return fmt.Errorf("flush: %w", err)
		}
		if err := p.sp.Ack(batch.Keys); err != nil {
			return fmt.Errorf("ack spool: %w", err)
		}

		if len(batch.Blobs) < p.cfg.BatchSize {
			return nil
		}
	}
}

// Close releases the NATS connection.
func (p *Publisher) Close() {
	if p.nc != nil {
		_ = p.nc.Drain()
		p.nc.Close()
	}
}
