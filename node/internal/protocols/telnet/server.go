// Package telnet implements the Telnet honeypot listener.
//
// Telnet remains the highest-yield sensor protocol on the public internet: the
// IoT botnet families sweep :23 continuously, and unlike SSH there is no
// handshake to negotiate before credentials arrive. Sessions here are short,
// scripted, and numerous.
//
// Containment matches the SSH listener -- the connection is terminated locally
// and handed to the shell emulator, which has no execution path.
package telnet

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	pb "github.com/honeynet/node/gen/honeynet/v1"
	"github.com/honeynet/node/internal/personality"
	"github.com/honeynet/node/internal/session"
	"github.com/honeynet/node/internal/shell"
	"github.com/honeynet/node/internal/credentials"
	"github.com/honeynet/node/internal/vfs"
)

// Telnet command bytes (RFC 854) and the options worth negotiating.
const (
	iac  = 255
	dont = 254
	doo  = 253
	wont = 252
	will = 251
	sb   = 250
	se   = 240

	optEcho           = 1
	optSuppressGoAhead = 3
	optTerminalType   = 24
	optNAWS           = 31
)

// Config parameterises the Telnet listener.
type Config struct {
	// NodeID is stamped into every emitted envelope. Carried separately from
	// the personality seed -- see the note on sshd.Config.
	NodeID string
	Addr   string

	// CredentialSecret keys the node's accepted logins, shared with the SSH
	// listener so that one box does not have two different password sets.
	CredentialSecret string

	MaxSessions      int
	MaxSessionsPerIP int
	IdleTimeout      time.Duration
	MaxDuration      time.Duration

	// MaxAuthAttempts is how many login prompts a client gets before the node
	// hangs up, matching login(1), which gives up after three.
	//
	// It used to be the count after which the node admitted the client
	// regardless of what they typed. That made persistence alone sufficient to
	// get a shell, which is not a property any real system has and which a
	// scanner confirms by typing garbage three times.
	MaxAuthAttempts int
}

// Server is the Telnet honeypot.
type Server struct {
	cfg    Config
	p      *personality.Personality
	sink   session.Sink
	log    *slog.Logger
	notify func()

	policy *credentials.Policy

	mu    sync.Mutex
	perIP map[string]int
	total int

	ln net.Listener
}

// New constructs the listener.
func New(cfg Config, p *personality.Personality, sink session.Sink, log *slog.Logger, notify func()) *Server {
	if cfg.MaxAuthAttempts <= 0 {
		cfg.MaxAuthAttempts = 3
	}
	return &Server{
		cfg: cfg, p: p, sink: sink, log: log, notify: notify,
		perIP: map[string]int{},

		// Same roster and same secret as the SSH listener: a box has one set
		// of accounts, and a password that works on port 22 but not on port 23
		// is a contradiction worth nothing to us and everything to a scanner.
		policy: credentials.NewPolicy(cfg.CredentialSecret, credentials.AccountsFrom(p.AccountNames())),
	}
}

// ListenAndServe runs until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Addr, err)
	}
	s.ln = ln
	s.log.Info("telnet honeypot listening", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warn("telnet accept failed", "err", err)
			continue
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer func() {
		_ = conn.Close()
		// A panic in a protocol handler must not take down the node. Bots send
		// deliberately malformed input, and losing the whole sensor to one
		// crafted frame would be a denial of service against our own fleet.
		if rec := recover(); rec != nil {
			s.log.Error("telnet handler panicked", "recovered", rec)
		}
	}()

	peer := peerFrom(conn.RemoteAddr(), conn.LocalAddr())
	if !s.acquire(peer.SrcIp) {
		return
	}
	defer s.release(peer.SrcIp)

	r := session.New(s.cfg.NodeID, s.sink, s.log, pb.Protocol_PROTOCOL_TELNET, peer)
	r.SessionStart("", nil, nil, nil, nil)
	s.notify()
	s.log.Info("telnet session opened", "session", r.ID(), "peer", peer.SrcIp)

	deadline := time.Now().Add(s.cfg.MaxDuration)
	if s.cfg.MaxDuration <= 0 {
		deadline = time.Now().Add(30 * time.Minute)
	}

	tc := &telnetConn{
		conn:   conn,
		br:     bufio.NewReader(conn),
		idle:   s.cfg.IdleTimeout,
		maxEnd: deadline,
	}

	tc.negotiate()

	user, ok := s.authenticate(tc, r)
	if !ok {
		r.SessionEnd(pb.SessionEndReason_SESSION_END_REASON_CLIENT_CLOSED, "")
		s.notify()
		return
	}

	fsys := vfs.New(s.p)
	hooks := shell.Hooks{
		OnCommand: func(ev shell.CommandEvent) { r.Command(ev); s.notify() },
		OnArtifact: func(ev shell.ArtifactEvent) {
			s.log.Info("artifact referenced (not fetched)",
				"session", r.ID(), "url", ev.URL, "tool", ev.ViaTool)
			r.Artifact(ev)
			s.notify()
		},
		OnUpload: func(ev shell.UploadEvent) { r.Upload(ev); s.notify() },
	}

	lim := shell.DefaultLimits()
	if s.cfg.MaxDuration > 0 {
		lim.MaxDuration = s.cfg.MaxDuration
	}

	sh := shell.New(s.p, fsys, tc, user, true, hooks, lim)
	runErr := sh.RunInteractive()

	reason := pb.SessionEndReason_SESSION_END_REASON_CLIENT_CLOSED
	switch {
	case errors.Is(runErr, shell.ErrLimitExceeded):
		reason = pb.SessionEndReason_SESSION_END_REASON_LIMIT_EXCEEDED
	case ctx.Err() != nil:
		reason = pb.SessionEndReason_SESSION_END_REASON_NODE_SHUTDOWN
	}
	r.SessionEnd(reason, "")
	s.notify()

	s.log.Info("telnet session closed",
		"session", r.ID(), "peer", peer.SrcIp, "commands", sh.CommandCount())
}

// authenticate runs the login/password exchange, recording every pair.
func (s *Server) authenticate(tc *telnetConn, r *session.Recorder) (string, bool) {
	host := s.p.Hostname

	for attempt := 1; ; attempt++ {
		fmt.Fprintf(tc, "\r\n%s login: ", host)
		user, err := tc.readLine(true)
		if err != nil {
			return "", false
		}
		if user == "" {
			continue
		}

		fmt.Fprintf(tc, "Password: ")
		pass, err := tc.readLine(false)
		if err != nil {
			return "", false
		}

		granted := s.policy.Accept(user, pass)
		r.AuthAttempt(pb.AuthMethod_AUTH_METHOD_PASSWORD, user, pass, granted)
		s.notify()

		if granted {
			fmt.Fprintf(tc, "\r\n")
			return user, true
		}

		time.Sleep(session.Jitter(s.p.AuthFailBaseMS, s.p.AuthFailJitterMS))
		fmt.Fprintf(tc, "\r\nLogin incorrect\r\n")

		// login(1) gives up rather than prompting forever. Prompting forever
		// is both unlike a real system and an invitation to sit on the socket
		// running a wordlist through it.
		if attempt >= s.cfg.MaxAuthAttempts {
			fmt.Fprintf(tc, "\r\nMaximum number of tries exceeded (%d)\r\n", s.cfg.MaxAuthAttempts)
			return "", false
		}
	}
}

func (s *Server) acquire(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.MaxSessions > 0 && s.total >= s.cfg.MaxSessions {
		return false
	}
	if s.cfg.MaxSessionsPerIP > 0 && s.perIP[ip] >= s.cfg.MaxSessionsPerIP {
		return false
	}
	s.total++
	s.perIP[ip]++
	return true
}

func (s *Server) release(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
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

// telnetConn adapts a raw TCP connection into the io.ReadWriter the shell
// expects, stripping IAC negotiation from the byte stream.
type telnetConn struct {
	conn   net.Conn
	br     *bufio.Reader
	idle   time.Duration
	maxEnd time.Time
}

// negotiate sends the option offers a real telnetd opens with. Clients that
// reply are tolerated; clients that ignore it -- most loaders do -- are equally
// fine, because the reader strips whatever comes back.
func (t *telnetConn) negotiate() {
	_, _ = t.conn.Write([]byte{
		iac, will, optEcho,
		iac, will, optSuppressGoAhead,
		iac, doo, optTerminalType,
		iac, doo, optNAWS,
	})
}

func (t *telnetConn) refreshDeadline() {
	d := time.Now().Add(t.idle)
	if t.idle <= 0 {
		d = time.Now().Add(3 * time.Minute)
	}
	if !t.maxEnd.IsZero() && d.After(t.maxEnd) {
		d = t.maxEnd
	}
	_ = t.conn.SetReadDeadline(d)
}

// Read delivers payload bytes with IAC sequences removed.
func (t *telnetConn) Read(p []byte) (int, error) {
	t.refreshDeadline()

	n := 0
	for n < len(p) {
		b, err := t.br.ReadByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}

		if b == iac {
			cmd, err := t.br.ReadByte()
			if err != nil {
				return n, err
			}
			switch cmd {
			case will, wont, doo, dont:
				if _, err := t.br.ReadByte(); err != nil { // option byte
					return n, err
				}
			case sb:
				// Subnegotiation runs until IAC SE.
				for {
					c, err := t.br.ReadByte()
					if err != nil {
						return n, err
					}
					if c == iac {
						nxt, err := t.br.ReadByte()
						if err != nil {
							return n, err
						}
						if nxt == se {
							break
						}
					}
				}
			case iac:
				p[n] = iac // escaped literal 0xFF
				n++
			}
			continue
		}

		if b == 0 {
			continue // clients pad CR with NUL
		}

		p[n] = b
		n++

		// Return as soon as the buffered reader is drained, so the shell's
		// keystroke-timing capture sees one read per client packet rather than
		// coalescing an entire pasted line into a single sample.
		if t.br.Buffered() == 0 {
			return n, nil
		}
	}
	return n, nil
}

func (t *telnetConn) Write(p []byte) (int, error) {
	if !t.maxEnd.IsZero() {
		_ = t.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}
	return t.conn.Write(p)
}

// readLine reads a single line for the login prompt, echoing when echo is set.
// Passwords are read with echo off, matching real telnetd.
func (t *telnetConn) readLine(echo bool) (string, error) {
	var buf []byte
	one := make([]byte, 1)
	for {
		n, err := t.Read(one)
		if err != nil {
			return string(buf), err
		}
		if n == 0 {
			continue
		}
		switch one[0] {
		case '\r', '\n':
			if len(buf) == 0 {
				continue
			}
			_, _ = t.Write([]byte("\r\n"))
			return string(buf), nil
		case 0x7f, 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				if echo {
					_, _ = t.Write([]byte("\b \b"))
				}
			}
		default:
			if one[0] >= 0x20 {
				buf = append(buf, one[0])
				if echo {
					_, _ = t.Write(one)
				}
			}
		}
		if len(buf) > 512 {
			return string(buf), io.ErrShortBuffer
		}
	}
}
