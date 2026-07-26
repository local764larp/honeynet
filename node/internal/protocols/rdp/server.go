// Package rdp implements the RDP honeypot listener.
//
// RDP is the most-attacked service on the public internet after SSH, driven by
// ransomware crews spraying credentials against exposed 3389. What this
// responder captures is the connection-request layer: the mstshash cookie
// (which routinely carries the attacker's own hostname or the target username
// baked into their tooling) and the requested security protocols.
//
// It deliberately stops before completing the handshake. Full NLA credential
// recovery requires terminating TLS and speaking CredSSP/NTLM, which is a large
// attack surface to run on an exposed box for a marginal gain: the cookie and
// the negotiation pattern already fingerprint the tool and the campaign, and
// most sprayers never finish the handshake against a host that stalls. The
// responder offers RDP-standard security to nudge clients into disclosing more
// in the clear, then lets the connection lapse.
//
// Containment: this package reads from and writes to an accepted connection.
// It never dials out.
package rdp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/honeynet/node/gen/honeynet/v1"
	"github.com/honeynet/node/internal/personality"
	"github.com/honeynet/node/internal/session"
)

// Config parameterises the RDP listener.
type Config struct {
	NodeID           string
	Addr             string
	MaxSessionsPerIP int
	ReadTimeout      time.Duration
}

// Server is the RDP honeypot.
type Server struct {
	cfg    Config
	p      *personality.Personality
	sink   session.Sink
	log    *slog.Logger
	notify func()

	mu    sync.Mutex
	perIP map[string]int
	ln    net.Listener
}

// New constructs the listener.
func New(cfg Config, p *personality.Personality, sink session.Sink, log *slog.Logger, notify func()) *Server {
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 15 * time.Second
	}
	return &Server{cfg: cfg, p: p, sink: sink, log: log, notify: notify, perIP: map[string]int{}}
}

// ListenAndServe runs until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Addr, err)
	}
	s.ln = ln
	s.log.Info("rdp honeypot listening", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warn("rdp accept failed", "err", err)
			continue
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer func() {
		_ = conn.Close()
		if rec := recover(); rec != nil {
			s.log.Error("rdp handler panicked", "recovered", rec)
		}
	}()

	peer := peerFrom(conn.RemoteAddr(), conn.LocalAddr())
	if !s.acquire(peer.SrcIp) {
		return
	}
	defer s.release(peer.SrcIp)

	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))

	// Read the X.224 Connection Request.
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return
	}
	req := buf[:n]

	rec := session.New(s.cfg.NodeID, s.sink, s.log, pb.Protocol_PROTOCOL_RDP, peer)
	rec.SessionStart("", nil, nil, nil, nil)

	cr := parseConnectionRequest(req)

	rec.RDPConnect(session.RDPConnectEvent{
		Cookie:             cr.Cookie,
		Username:           cr.RoutingToken,
		RequestedProtocols: cr.protocolNames(),
	})
	s.notify()

	s.log.Info("rdp connection",
		"session", rec.ID(), "peer", peer.SrcIp,
		"cookie", cr.Cookie, "protocols", strings.Join(cr.protocolNames(), ","))

	// Respond with a Negotiation Response selecting standard RDP security.
	// Offering the weakest option is what encourages a client to continue in a
	// form we can observe rather than immediately wrapping everything in TLS.
	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.ReadTimeout))
	_, _ = conn.Write(negotiationResponse())

	// Read one more PDU if the client sends it -- an MCS Connect Initial often
	// carries the client name and build in cleartext.
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))
	n2, err := conn.Read(buf)
	if err == nil && n2 > 0 {
		if info := parseClientInfo(buf[:n2]); info.ClientName != "" || info.Build != "" {
			rec.RDPConnect(session.RDPConnectEvent{
				Cookie:      cr.Cookie,
				ClientName:  info.ClientName,
				ClientBuild: info.Build,
			})
			s.notify()
			s.log.Info("rdp client info",
				"session", rec.ID(), "client", info.ClientName, "build", info.Build)
		}
	}

	reason := pb.SessionEndReason_SESSION_END_REASON_CLIENT_CLOSED
	if ctx.Err() != nil {
		reason = pb.SessionEndReason_SESSION_END_REASON_NODE_SHUTDOWN
	}
	rec.SessionEnd(reason, "")
	s.notify()
}

func (s *Server) acquire(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxSessionsPerIP > 0 && s.perIP[ip] >= s.cfg.MaxSessionsPerIP {
		return false
	}
	s.perIP[ip]++
	return true
}

func (s *Server) release(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.perIP[ip]--
	if s.perIP[ip] <= 0 {
		delete(s.perIP, ip)
	}
}

func peerFrom(remote, local net.Addr) *pb.Peer {
	p := &pb.Peer{}
	if h, port, err := net.SplitHostPort(remote.String()); err == nil {
		p.SrcIp = h
		if n, err := strconv.Atoi(port); err == nil {
			p.SrcPort = uint32(n)
		}
	}
	if local != nil {
		if h, port, err := net.SplitHostPort(local.String()); err == nil {
			p.DstIp = h
			if n, err := strconv.Atoi(port); err == nil {
				p.DstPort = uint32(n)
			}
		}
	}
	return p
}
