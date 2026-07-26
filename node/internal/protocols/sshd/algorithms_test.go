package sshd

import (
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/honeynet/node/internal/personality"
	"github.com/honeynet/node/internal/session"
)

// captureServerKexInit performs the opening half of an SSH handshake by hand
// and returns the algorithm lists the server advertised.
//
// Done at the socket rather than through a client library on purpose. A client
// only reports what was negotiated; an attacker fingerprinting the sensor reads
// what was *offered*, and those are different things. This is the same view
// nmap --script ssh2-enum-algos gets.
func captureServerKexInit(t *testing.T, addr string) clientHello {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	// The server will not send its KEXINIT until it has seen a version string.
	if _, err := conn.Write([]byte("SSH-2.0-FingerprintProbe\r\n")); err != nil {
		t.Fatalf("write version: %v", err)
	}

	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	for len(buf) < 8192 {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if h := parseHello(buf); h.Parsed {
				return h
			}
		}
		if err != nil {
			break
		}
	}

	h := parseHello(buf)
	if !h.Parsed {
		t.Fatalf("could not parse a KEXINIT from %d bytes of server output", len(buf))
	}
	return h
}

func startProbeServer(t *testing.T, seed string) (string, *personality.Personality) {
	t.Helper()

	p := personality.Derive(seed)
	srv, err := New(Config{
		NodeID:           "probe-node",
		Addr:             "127.0.0.1:0",
		HostKeyPath:      filepath.Join(t.TempDir(), "hostkey"),
		CredentialSecret: "probe-secret",
		MaxSessions:      8,
		MaxSessionsPerIP: 4,
		IdleTimeout:      5 * time.Second,
		MaxDuration:      10 * time.Second,
	}, p, session.Sink(nil), slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})), func() {})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() { _ = srv.Serve(t.Context(), ln) }()
	return srv.Addr(), p
}

// The assertion that keeps code and table from drifting: what the sensor puts
// on the wire has to be exactly what the profile says it will.
func TestAdvertisedAlgorithmsMatchProfile(t *testing.T) {
	addr, p := startProbeServer(t, "algo-node")
	want := profileFor(p.SSHBanner)
	got := captureServerKexInit(t, addr)

	assertListsEqual(t, "kex", got.Kex, want.advertisedKex())
	assertListsEqual(t, "ciphers", got.Ciphers, want.Ciphers)
	assertListsEqual(t, "macs", got.MACs, want.MACs)
}

// The specific entry that gave the sensor away. x/crypto/ssh leads its default
// key exchange list with a post-quantum hybrid that no OpenSSH 8.x has ever
// offered, so a banner claiming 8.x alongside it is a contradiction in the
// first packet of the connection.
func TestNoPostQuantumKexIsAdvertised(t *testing.T) {
	addr, _ := startProbeServer(t, "algo-node")
	got := captureServerKexInit(t, addr)

	for _, kex := range got.Kex {
		if strings.Contains(kex, "mlkem") || strings.Contains(kex, "sntrup") {
			t.Errorf("advertised %q; no OpenSSH release we impersonate offers a post-quantum exchange", kex)
		}
	}
}

// A node has to answer identically every time. Algorithm lists that varied
// between connections would be a stronger tell than any single wrong entry,
// and Go map iteration order has produced exactly that class of bug before.
func TestAdvertisementIsStableAcrossConnections(t *testing.T) {
	addr, _ := startProbeServer(t, "algo-node")

	first := captureServerKexInit(t, addr)
	for i := 0; i < 5; i++ {
		next := captureServerKexInit(t, addr)
		assertListsEqual(t, "kex", next.Kex, first.Kex)
		assertListsEqual(t, "ciphers", next.Ciphers, first.Ciphers)
		assertListsEqual(t, "macs", next.MACs, first.MACs)
	}
}

// Every banner in the personality pool must resolve to a table. A banner with
// no profile would fall through to the library defaults and undo all of this.
func TestEveryDerivedBannerResolvesToAProfile(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 300; i++ {
		p := personality.Derive(string(rune('a'+i%26)) + strings.Repeat("x", i%7))
		if seen[p.SSHBanner] {
			continue
		}
		seen[p.SSHBanner] = true

		prof := profileFor(p.SSHBanner)
		if len(prof.KexAlgos) == 0 || len(prof.Ciphers) == 0 || len(prof.MACs) == 0 {
			t.Errorf("banner %q resolved to an empty profile", p.SSHBanner)
		}
		if prof.MaxAuthTries <= 0 {
			t.Errorf("banner %q resolved to a profile with no auth-try limit", p.SSHBanner)
		}
	}
	if len(seen) < 2 {
		t.Errorf("only %d distinct banners across 300 seeds; the pool is not varying", len(seen))
	}
}

func assertListsEqual(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: advertised %d entries, profile has %d\n  got:  %v\n  want: %v",
			label, len(got), len(want), got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s[%d]: advertised %q, profile says %q\n  got:  %v\n  want: %v",
				label, i, got[i], want[i], got, want)
			return
		}
	}
}
