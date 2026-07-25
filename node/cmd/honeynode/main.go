// Command honeynode is the honeypot sensor.
//
// It terminates attacker connections on emulated services, records everything
// observed to a durable local spool, and publishes to the collector over NATS.
//
// Containment: the binary has no execution path for attacker input and opens no
// outbound connection other than to the collector. See design doc section 4.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/honeynet/node/internal/config"
	"github.com/honeynet/node/internal/personality"
	"github.com/honeynet/node/internal/protocols/sshd"
	"github.com/honeynet/node/internal/protocols/telnet"
	"github.com/honeynet/node/internal/session"
	"github.com/honeynet/node/internal/spool"
	"github.com/honeynet/node/internal/transport"
)

// buildVersion is stamped at link time:
//
//	go build -ldflags "-X main.buildVersion=$(git describe --tags)"
var buildVersion = "dev"

func main() {
	var (
		configPath  = flag.String("config", "honeynode.json", "path to config file")
		showIdent   = flag.Bool("identity", false, "print the derived machine identity and exit")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("honeynode", buildVersion)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}

	log := newLogger(cfg.LogLevel)
	p := personality.Derive(cfg.PersonalitySeed)

	if *showIdent {
		printIdentity(p)
		return
	}

	if err := run(cfg, p, log); err != nil {
		log.Error("node exited with error", "err", err)
		os.Exit(1)
	}
}

func run(cfg config.Config, p *personality.Personality, log *slog.Logger) error {
	log.Info("honeynode starting",
		"version", buildVersion,
		"node_id", cfg.NodeID,
		"hostname", p.Hostname,
		"distro", p.Distro.PrettyName,
		"kernel", p.KernelRel)

	sp, err := spool.Open(spool.Options{Path: cfg.SpoolPath, MaxBytes: cfg.SpoolMaxBytes})
	if err != nil {
		return fmt.Errorf("open spool: %w", err)
	}
	defer func() { _ = sp.Close() }()

	if depth, err := sp.Depth(); err == nil && depth > 0 {
		log.Info("resuming with unpublished events", "depth", depth)
	}

	tcfg := transport.DefaultConfig(cfg.NodeID)
	tcfg.URL = cfg.NATSURL
	tcfg.CertFile = cfg.CertFile
	tcfg.KeyFile = cfg.KeyFile
	tcfg.CAFile = cfg.CAFile
	pub := transport.New(tcfg, sp, log)
	defer pub.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := pub.Run(gctx); err != nil && gctx.Err() == nil {
			return fmt.Errorf("publisher: %w", err)
		}
		return nil
	})

	started := 0

	if cfg.SSHAddr != "" {
		srv, err := sshd.New(sshd.Config{
			NodeID:           cfg.NodeID,
			Addr:             cfg.SSHAddr,
			HostKeyPath:      cfg.HostKeyPath,
			MaxSessions:      cfg.MaxSessions,
			MaxSessionsPerIP: cfg.MaxSessionsPerIP,
			IdleTimeout:      cfg.SessionIdleTimeout,
			MaxDuration:      cfg.SessionMaxDuration,
		}, p, sp, log, pub.Notify)
		if err != nil {
			return fmt.Errorf("ssh listener: %w", err)
		}
		started++
		g.Go(func() error {
			if err := srv.ListenAndServe(gctx); err != nil && gctx.Err() == nil {
				return fmt.Errorf("ssh listener: %w", err)
			}
			return nil
		})
	}

	if cfg.TelnetAddr != "" {
		srv := telnet.New(telnet.Config{
			NodeID:           cfg.NodeID,
			Addr:             cfg.TelnetAddr,
			MaxSessions:      cfg.MaxSessions,
			MaxSessionsPerIP: cfg.MaxSessionsPerIP,
			IdleTimeout:      cfg.SessionIdleTimeout,
			MaxDuration:      cfg.SessionMaxDuration,
		}, p, sp, log, pub.Notify)
		started++
		g.Go(func() error {
			if err := srv.ListenAndServe(gctx); err != nil && gctx.Err() == nil {
				return fmt.Errorf("telnet listener: %w", err)
			}
			return nil
		})
	}

	if started == 0 {
		return fmt.Errorf("no protocol listeners configured")
	}

	g.Go(func() error {
		return heartbeat(gctx, cfg, sp, pub, log)
	})

	log.Info("honeynode ready", "listeners", started)

	err = g.Wait()
	if ctx.Err() != nil {
		log.Info("shutdown complete")
		return nil
	}
	return err
}

// heartbeat reports liveness and spool health on a fixed interval.
func heartbeat(ctx context.Context, cfg config.Config, sp *spool.Spool, pub *transport.Publisher, log *slog.Logger) error {
	interval := time.Duration(cfg.HeartbeatSec) * time.Second
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		depth, err := sp.Depth()
		if err != nil {
			log.Warn("spool depth unavailable", "err", err)
			continue
		}
		dropped := sp.Dropped()
		if dropped > 0 {
			log.Warn("spool has dropped events; corpus has gaps", "dropped", dropped)
		}

		if err := session.EmitHeartbeat(cfg.NodeID, sp, time.Since(start), depth, dropped, 0, buildVersion); err != nil {
			log.Warn("heartbeat append failed", "err", err)
			continue
		}
		pub.Notify()
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// printIdentity dumps the derived machine identity. Useful when provisioning a
// fleet: an operator can confirm that two nodes really do look like different
// machines before exposing either of them.
func printIdentity(p *personality.Personality) {
	fmt.Printf("seed:      %s\n", p.Seed)
	fmt.Printf("hostname:  %s\n", p.Hostname)
	fmt.Printf("distro:    %s\n", p.Distro.PrettyName)
	fmt.Printf("kernel:    %s\n", p.KernelRel)
	fmt.Printf("cpu:       %s (%d cores)\n", p.CPUModel, p.CPUCores)
	fmt.Printf("memory:    %d MB\n", p.MemTotalKB/1024)
	fmt.Printf("mac:       %s\n", p.MACAddr)
	fmt.Printf("internal:  %s\n", p.InternalIP)
	fmt.Printf("boot:      %s (up %s)\n", p.BootTime.Format(time.RFC3339), p.Uptime().Round(time.Hour))
	fmt.Printf("ssh:       %s\n", p.SSHBanner)
	fmt.Printf("machineid: %s\n", p.MachineID())
	fmt.Printf("users:     ")
	for i, u := range p.Users {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("%s(%d)", u.Name, u.UID)
	}
	fmt.Printf("\npackages:  %d installed\n", len(p.Packages))
}
