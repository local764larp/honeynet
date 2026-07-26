// Package sshd implements the SSH honeypot listener.
//
// Containment: this package terminates SSH and hands the channel to the shell
// emulator. It never allocates a PTY on the host, never spawns a process, and
// never opens an outbound connection on a session's behalf. Port forwarding
// requests are declined -- accepting them would turn the sensor into a relay,
// which design doc section 4.3 forbids.
package sshd

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	pb "github.com/honeynet/node/gen/honeynet/v1"
	"github.com/honeynet/node/internal/credentials"
	"github.com/honeynet/node/internal/personality"
	"github.com/honeynet/node/internal/session"
	"github.com/honeynet/node/internal/shell"
	"github.com/honeynet/node/internal/vfs"
)

type ctxKey string

const (
	ctxKeySniff     ctxKey = "honeynet.sniff"
	ctxKeyRecorder  ctxKey = "honeynet.recorder"
	ctxKeyEndReason ctxKey = "honeynet.end_reason"
)

// Config parameterises the SSH listener.
type Config struct {
	// NodeID is stamped into every emitted envelope. It is carried separately
	// from the personality seed on purpose: the seed shapes the fake machine,
	// while the node ID must match the CN of the client certificate the
	// collector authenticated. Conflating them would let a seed change silently
	// break collector-side identity validation.
	NodeID      string
	Addr        string
	HostKeyPath string

	// CredentialSecret keys the node's accepted logins. Distinct from both the
	// node ID and the personality seed, which are provisioning inputs and
	// therefore guessable; see the credentials package.
	CredentialSecret string

	MaxSessions      int
	MaxSessionsPerIP int
	IdleTimeout      time.Duration
	MaxDuration      time.Duration
}

// Server is the SSH honeypot.
type Server struct {
	cfg    Config
	p      *personality.Personality
	sink   session.Sink
	log    *slog.Logger
	notify func()

	policy  *credentials.Policy
	profile profile

	srv *gliderssh.Server

	mu        sync.Mutex
	perIP     map[string]int
	total     int
	boundAddr string
}

// New constructs the listener. notify is called after each emitted event so the
// publisher can drain promptly rather than waiting for its poll tick.
func New(cfg Config, p *personality.Personality, sink session.Sink, log *slog.Logger, notify func()) (*Server, error) {
	if cfg.CredentialSecret == "" {
		return nil, fmt.Errorf("credential secret is required")
	}

	s := &Server{
		cfg: cfg, p: p, sink: sink, log: log, notify: notify,
		perIP: map[string]int{},

		// One password per account, derived from the node secret and drawn
		// from the wordlists attackers actually spray. The roster comes from
		// the personality so that what authenticates and what appears in
		// /etc/passwd cannot disagree.
		policy:  credentials.NewPolicy(cfg.CredentialSecret, credentials.AccountsFrom(p.AccountNames())),
		profile: profileFor(p.SSHBanner),
	}

	signers, err := loadOrCreateHostKeys(cfg.HostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("host keys: %w", err)
	}

	s.srv = &gliderssh.Server{
		Addr: cfg.Addr,

		// Version drives the server banner. Drawn from the personality so the
		// advertised OpenSSH build matches the distribution the emulated shell
		// claims to be running.
		Version: versionSuffix(p.SSHBanner),

		// Pins the advertised algorithms to that same release. Without this
		// gliderlabs hands x/crypto a zero-value config, and the library's own
		// defaults contradict the banner in the first packet of the handshake.
		ServerConfigCallback: func(gliderssh.Context) *gossh.ServerConfig {
			return s.profile.serverConfig()
		},

		IdleTimeout: cfg.IdleTimeout,
		MaxTimeout:  cfg.MaxDuration,

		Handler:          s.handleSession,
		PasswordHandler:  s.handlePassword,
		PublicKeyHandler: s.handlePublicKey,
		ConnCallback:     s.wrapConn,

		// Every forwarding and side-channel request is refused. A honeypot
		// that proxies is a honeypot that participates in the next attack.
		LocalPortForwardingCallback:   func(gliderssh.Context, string, uint32) bool { return false },
		ReversePortForwardingCallback: func(gliderssh.Context, string, uint32) bool { return false },
		ChannelHandlers: map[string]gliderssh.ChannelHandler{
			"session": gliderssh.DefaultSessionHandler,
		},
		SubsystemHandlers: map[string]gliderssh.SubsystemHandler{
			"sftp": s.handleSFTPRefusal,
		},
	}

	for _, signer := range signers {
		s.srv.AddHostKey(signer)
	}
	return s, nil
}

// versionSuffix converts a full banner ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3") into
// the suffix gliderlabs prepends "SSH-2.0-" to.
func versionSuffix(banner string) string {
	const prefix = "SSH-2.0-"
	if len(banner) > len(prefix) && banner[:len(prefix)] == prefix {
		return banner[len(prefix):]
	}
	return banner
}

// Listen binds the configured address. Split from Serve so that a caller which
// configured port 0 can read the resolved address before traffic starts.
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", s.cfg.Addr, err)
	}
	s.mu.Lock()
	s.boundAddr = ln.Addr().String()
	s.mu.Unlock()
	return ln, nil
}

// Serve accepts connections until the context is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.log.Info("ssh honeypot listening", "addr", ln.Addr().String(), "banner", s.p.SSHBanner)

	go func() {
		<-ctx.Done()
		_ = s.srv.Close()
	}()

	err := s.srv.Serve(ln)
	if errors.Is(err, gliderssh.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// ListenAndServe binds and serves until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := s.Listen()
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Addr reports the resolved bound address once Listen has run, falling back to
// the configured value before that.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.boundAddr != "" {
		return s.boundAddr
	}
	return s.cfg.Addr
}

// wrapConn tees the handshake for HASSH extraction and registers the
// session-end hook.
//
// SessionEnd is emitted on connection teardown rather than on channel close.
// One SSH connection is one attacker session, but a scripted loader opens a
// separate channel per command -- emitting per channel produced one start and
// a dozen ends for the same session_id, which no downstream reconstruction can
// make sense of.
func (s *Server) wrapConn(ctx gliderssh.Context, conn net.Conn) net.Conn {
	sc := newSniffConn(conn, func() { s.finishSession(ctx) })
	ctx.SetValue(ctxKeySniff, sc)
	return sc
}

// finishSession emits the terminal event for a connection, if one ever got far
// enough to have a recorder. Connections that disconnect before offering a
// credential -- bare port scans -- produce nothing, which is correct.
func (s *Server) finishSession(ctx gliderssh.Context) {
	r, ok := ctx.Value(ctxKeyRecorder).(*session.Recorder)
	if !ok {
		return
	}

	reason := pb.SessionEndReason_SESSION_END_REASON_CLIENT_CLOSED
	if v, ok := ctx.Value(ctxKeyEndReason).(pb.SessionEndReason); ok {
		reason = v
	}

	r.SessionEnd(reason, "")
	s.notify()
	s.log.Info("ssh session closed",
		"session", r.ID(), "peer", r.Peer().SrcIp,
		"duration", r.Elapsed().Round(time.Millisecond))
}

// recorderFor lazily creates the session recorder on the first authentication
// attempt, because that is the earliest point at which there is anything worth
// recording.
func (s *Server) recorderFor(ctx gliderssh.Context) *session.Recorder {
	if r, ok := ctx.Value(ctxKeyRecorder).(*session.Recorder); ok {
		return r
	}

	peer := peerFrom(ctx.RemoteAddr(), ctx.LocalAddr())
	r := session.New(s.nodeID(), s.sink, s.log, pb.Protocol_PROTOCOL_SSH, peer)
	ctx.SetValue(ctxKeyRecorder, r)

	hello := clientHello{Banner: ctx.ClientVersion()}
	if sc, ok := ctx.Value(ctxKeySniff).(*sniffConn); ok {
		if parsed := parseHello(sc.captured()); parsed.Parsed {
			hello = parsed
		}
	}
	r.SessionStart(hello.Banner, hello.Kex, hello.Ciphers, hello.MACs, hello.Compression)

	s.log.Info("ssh session opened",
		"session", r.ID(), "peer", peer.SrcIp, "banner", hello.Banner)
	return r
}

func (s *Server) nodeID() string { return s.cfg.NodeID }

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

// handlePassword authenticates against the node's fixed credential set.
//
// Admission depends only on the credential, never on how many times it has been
// tried. The earlier implementation granted access once an attacker had failed
// a threshold number of times, which identified the sensor in one connection:
// six random strings, and one of them opens a shell. Nothing on the internet
// behaves that way.
//
// The door still opens, but through the credential rather than through
// persistence -- see the credentials package for how the node's password is
// drawn from the same lists the botnets are working through.
func (s *Server) handlePassword(ctx gliderssh.Context, password string) bool {
	r := s.recorderFor(ctx)

	granted := s.policy.Accept(ctx.User(), password)
	r.AuthAttempt(pb.AuthMethod_AUTH_METHOD_PASSWORD, ctx.User(), password, granted)
	s.notify()

	if !granted {
		// Real sshd is slow to reject, and the delay is a fingerprinted
		// quantity. Sourced from the personality so it is stable per node.
		time.Sleep(session.Jitter(s.p.AuthFailBaseMS, s.p.AuthFailJitterMS))
	}
	return granted
}

// handlePublicKey records the offered key and always declines.
//
// Declining is deliberate: the client then falls back to password
// authentication and discloses its credential list, which is far more valuable
// than the key alone. The key fingerprint is still recorded, and reused keys
// across sessions link actors that share no source address.
func (s *Server) handlePublicKey(ctx gliderssh.Context, key gliderssh.PublicKey) bool {
	r := s.recorderFor(ctx)
	r.PublicKeyAttempt(ctx.User(), key.Type(), key.Marshal(), false)
	s.notify()
	return false
}

func (s *Server) handleSFTPRefusal(sess gliderssh.Session) {
	if r, ok := sess.Context().Value(ctxKeyRecorder).(*session.Recorder); ok {
		r.Anomaly("sftp_subsystem_requested", "declined")
		s.notify()
	}
	_ = sess.Exit(1)
}

// handleSession runs the emulated shell for an authenticated connection.
func (s *Server) handleSession(sess gliderssh.Session) {
	ctx := sess.Context()
	r, ok := ctx.Value(ctxKeyRecorder).(*session.Recorder)
	if !ok {
		r = s.recorderFor(ctx)
	}

	peerIP := r.Peer().SrcIp
	if !s.acquire(peerIP) {
		// Over the concurrency budget. Closing without a banner mimics a box
		// that is simply out of resources.
		r.Anomaly("session_rejected", "concurrency limit reached")
		ctx.SetValue(ctxKeyEndReason, pb.SessionEndReason_SESSION_END_REASON_LIMIT_EXCEEDED)
		s.notify()
		_ = sess.Exit(1)
		return
	}
	defer s.release(peerIP)

	fsys := vfs.New(s.p)
	_, _, isPty := sess.Pty()

	hooks := shell.Hooks{
		OnCommand: func(ev shell.CommandEvent) {
			r.Command(ev)
			s.notify()
		},
		OnArtifact: func(ev shell.ArtifactEvent) {
			s.log.Info("artifact referenced (not fetched)",
				"session", r.ID(), "url", ev.URL, "tool", ev.ViaTool)
			r.Artifact(ev)
			s.notify()
		},
		OnUpload: func(ev shell.UploadEvent) {
			r.Upload(ev)
			s.notify()
		},
	}

	lim := shell.DefaultLimits()
	if s.cfg.MaxDuration > 0 {
		lim.MaxDuration = s.cfg.MaxDuration
	}
	if s.cfg.IdleTimeout > 0 {
		lim.IdleTimeout = s.cfg.IdleTimeout
	}

	sh := shell.New(s.p, fsys, sess, sess.User(), isPty, hooks, lim)

	var runErr error
	if cmd := sess.RawCommand(); cmd != "" {
		// Non-interactive invocation: `ssh host "wget ...; chmod +x ...".`
		// Bots prefer this because it needs no PTY and delivers the whole
		// payload in one string.
		runErr = sh.RunExec(cmd)
	} else {
		runErr = sh.RunInteractive()
	}

	// The terminal event is emitted by finishSession on connection teardown,
	// not here -- see wrapConn. This channel only records why it ended, so
	// that a limit breach or protocol error is not overwritten by the default
	// when the connection finally closes.
	switch {
	case errors.Is(runErr, shell.ErrLimitExceeded):
		ctx.SetValue(ctxKeyEndReason, pb.SessionEndReason_SESSION_END_REASON_LIMIT_EXCEEDED)
	case runErr != nil && !errors.Is(runErr, shell.ErrSessionEnded):
		ctx.SetValue(ctxKeyEndReason, pb.SessionEndReason_SESSION_END_REASON_PROTOCOL_ERROR)
	}

	s.log.Debug("ssh channel closed",
		"session", r.ID(), "peer", peerIP, "commands", sh.CommandCount())

	_ = sess.Exit(sh.ExitCode())
}

// acquire enforces the global and per-source concurrency budget.
//
// Per-IP limiting matters more than the global cap: a single aggressive scanner
// opening hundreds of connections would otherwise crowd out every other actor,
// biasing the corpus toward whoever is loudest.
func (s *Server) acquire(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total >= s.cfg.MaxSessions {
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

// ---- host keys ----

// loadOrCreateHostKeys returns the node's persistent host keys, generating them
// on first start.
//
// Persistence is not optional. A host key that changes between restarts is
// immediately visible to any scanner that revisits, and revisits are common --
// the same botnets sweep the same ranges continuously.
// The key set mirrors what ssh-keygen -A leaves in /etc/ssh on a stock install:
// RSA, ECDSA and Ed25519. The previous pair -- RSA-2048 and Ed25519 -- was
// visibly wrong in two ways at once, both readable without authenticating:
//
//	ssh-keyscan -t rsa,ecdsa,ed25519 host
//
// A missing ECDSA key means a host that was never initialised by ssh-keygen -A,
// and a 2048-bit RSA modulus means one initialised by something other than a
// modern OpenSSH, which has defaulted to 3072 since 8.0.
func loadOrCreateHostKeys(path string) ([]gossh.Signer, error) {
	if path == "" {
		return nil, fmt.Errorf("host key path is required")
	}

	var signers []gossh.Signer
	// Order matches the sequence sshd offers host key algorithms in.
	for _, spec := range []struct {
		suffix string
		gen    func() ([]byte, error)
	}{
		{"_rsa", generateRSAKey},
		{"_ecdsa", generateECDSAKey},
		{"_ed25519", generateEd25519Key},
	} {
		p := path + spec.suffix
		pemBytes, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			pemBytes, err = spec.gen()
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
				return nil, fmt.Errorf("write host key %s: %w", p, err)
			}
		} else if err != nil {
			return nil, fmt.Errorf("read host key %s: %w", p, err)
		}

		signer, err := gossh.ParsePrivateKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("parse host key %s: %w", p, err)
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

// generateRSAKey produces a 3072-bit key, which is what ssh-keygen -A has
// produced since OpenSSH 8.0. The modulus size is visible to ssh-keyscan
// without authenticating.
func generateRSAKey() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, fmt.Errorf("generate rsa host key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), nil
}

// generateECDSAKey produces the P-256 key ssh-keygen -A creates. Its absence
// was the more visible of the two host key defects.
func generateECDSAKey() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa host key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ecdsa host key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func generateEd25519Key() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 host key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal ed25519 host key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
