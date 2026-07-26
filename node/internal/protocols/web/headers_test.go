package web_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// rawResponseHeaders performs an HTTP request at the socket and returns the
// header field names in the order they appeared on the wire.
//
// net/http's client normalises and re-orders what it hands back, so it cannot
// see this. A scanner comparing the sensor against a real server reads the
// raw bytes, and so does this.
func rawResponseHeaders(t *testing.T, addr, request string) []string {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}

	var names []string
	br := bufio.NewReader(conn)

	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.") {
		t.Fatalf("unexpected status line %q", status)
	}

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if i := strings.IndexByte(line, ':'); i > 0 {
			names = append(names, line[:i])
		}
	}
	return names
}

const plainGet = "GET / HTTP/1.1\r\nHost: sensor.example\r\nConnection: close\r\n\r\n"

// Ground truth for what the sensor puts on the wire. Not an assertion about
// what is correct -- it records what is actually emitted so the ordering
// assertions below have something real to check.
func TestHeaderOrderIsObservable(t *testing.T) {
	addr := firstOf(startWeb(t, "hdr-node"))
	got := rawResponseHeaders(t, addr, plainGet)

	if len(got) == 0 {
		t.Fatal("response carried no headers")
	}
	t.Logf("wire order: %v", got)
}

// The order has to be identical every time. A server whose header order varies
// between responses is not a server -- nothing that ships behaves that way, and
// two requests would be enough to see it.
func TestHeaderOrderIsStableAcrossRequests(t *testing.T) {
	addr := firstOf(startWeb(t, "hdr-node"))

	first := rawResponseHeaders(t, addr, plainGet)
	for i := 0; i < 8; i++ {
		next := rawResponseHeaders(t, addr, plainGet)
		if strings.Join(next, ",") != strings.Join(first, ",") {
			t.Fatalf("header order changed between responses\n  first: %v\n  now:   %v", first, next)
		}
	}
}

// Real servers lead with their identity. nginx emits Server immediately after
// the status line, then Date; Apache emits Date then Server. Neither sorts
// alphabetically, which is what Go's net/http does with handler-set headers --
// and alphabetical ordering is itself the fingerprint, because no production
// web server produces it.
func TestServerAndDateLeadTheResponse(t *testing.T) {
	addr := firstOf(startWeb(t, "hdr-node"))
	got := rawResponseHeaders(t, addr, plainGet)

	if len(got) < 2 {
		t.Fatalf("expected at least Server and Date, got %v", got)
	}

	lead := map[string]bool{"Server": true, "Date": true}
	for i := 0; i < 2; i++ {
		if !lead[got[i]] {
			t.Errorf("header %d is %q; the first two must be Server and Date, got %v", i, got[i], got)
		}
	}
}

// Alphabetical order is the specific signature of a Go handler. Assert it is
// gone: with Server and Date leading, the sequence cannot also be sorted.
func TestHeaderOrderIsNotAlphabetical(t *testing.T) {
	addr := firstOf(startWeb(t, "hdr-node"))
	got := rawResponseHeaders(t, addr, plainGet)

	if len(got) < 3 {
		t.Skipf("too few headers to judge ordering: %v", got)
	}

	sorted := true
	for i := 1; i < len(got); i++ {
		if strings.ToLower(got[i-1]) > strings.ToLower(got[i]) {
			sorted = false
			break
		}
	}
	if sorted {
		t.Errorf("headers are in alphabetical order %v, which is the net/http signature; "+
			"no production web server emits headers sorted by name", got)
	}
}

// A 404 is the most-requested response on an exposed sensor, since scanners
// sweep paths that do not exist. It must carry the same identity and ordering
// as a served page.
func TestNotFoundKeepsTheSameHeaderShape(t *testing.T) {
	addr := firstOf(startWeb(t, "hdr-node"))

	ok := rawResponseHeaders(t, addr, plainGet)
	missing := rawResponseHeaders(t, addr,
		"GET /nothing-here-at-all HTTP/1.1\r\nHost: sensor.example\r\nConnection: close\r\n\r\n")

	if len(missing) == 0 {
		t.Fatal("404 carried no headers")
	}
	for i := 0; i < 2 && i < len(missing); i++ {
		if missing[i] != ok[i] {
			t.Errorf("404 header %d is %q but a served page leads with %q\n  404: %v\n  200: %v",
				i, missing[i], ok[i], missing, ok)
		}
	}
}

func TestServerHeaderIsPresentAndSingular(t *testing.T) {
	addr := firstOf(startWeb(t, "hdr-node"))
	got := rawResponseHeaders(t, addr, plainGet)

	n := 0
	for _, h := range got {
		if strings.EqualFold(h, "Server") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected exactly one Server header, found %d in %v", n, got)
	}
}

// firstOf reduces startWeb's base URL to the host:port these tests dial
// directly. They talk to the socket rather than through net/http, because the
// client normalises away the very ordering being asserted on.
func firstOf(base string, _ *memSink) string {
	return strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://")
}

var _ = fmt.Sprintf
