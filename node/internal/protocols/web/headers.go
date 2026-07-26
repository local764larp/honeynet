package web

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Response header ordering.
//
// net/http sorts handler-set headers by name before writing them, so the sensor
// emitted Content-Type, Date, Server -- alphabetical. No production web server
// does that. nginx leads with Server then Date; Apache leads with Date then
// Server; IIS has its own sequence again. The order is stable per server and is
// one of the cheapest things to compare against a reference, which is why
// fingerprinting tools read it.
//
// The order cannot be changed through the ResponseWriter API: Header is a map
// and the sort happens inside the transport. The only way to control the bytes
// is to take the connection and write the response directly, which is what this
// file does.
//
// # What this costs
//
// Hijacking means the transport no longer manages the connection, and this
// implementation answers one request and closes rather than reimplementing
// keep-alive. That is a real behavioural difference from nginx, which keeps
// connections open by default -- it is a smaller signal than alphabetical
// header order, but it is not nothing, and closing the loop would mean running
// the request cycle here instead.

// orderedWriter captures a handler's response so it can be re-emitted with the
// header sequence of the impersonated server.
//
// It satisfies http.ResponseWriter so the decoys, which write directly to one,
// need no changes.
type orderedWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
	wrote  bool
}

func newOrderedWriter() *orderedWriter {
	return &orderedWriter{header: make(http.Header), status: http.StatusOK}
}

func (w *orderedWriter) Header() http.Header { return w.header }

func (w *orderedWriter) WriteHeader(status int) {
	if !w.wrote {
		w.status = status
		w.wrote = true
	}
}

func (w *orderedWriter) Write(p []byte) (int, error) {
	w.wrote = true
	return w.body.Write(p)
}

// nginxOrder and apacheOrder are the sequences those servers emit. Headers not
// named here follow in the order the handler set them, which is where a server
// puts anything unusual anyway.
var (
	nginxOrder = []string{
		"Server", "Date", "Content-Type", "Content-Length",
		"Last-Modified", "Connection", "ETag", "Accept-Ranges",
	}
	apacheOrder = []string{
		"Date", "Server", "Last-Modified", "ETag", "Accept-Ranges",
		"Content-Length", "Connection", "Content-Type",
	}
	iisOrder = []string{
		"Content-Type", "Last-Modified", "Accept-Ranges", "ETag",
		"Server", "X-Powered-By", "Date", "Content-Length",
	}
)

// orderFor picks the sequence matching the Server header the node advertises.
// The two have to agree: emitting Apache's order under an nginx banner is the
// same class of contradiction as emitting Ubuntu's MOTD on Debian.
func orderFor(server string) []string {
	switch {
	case strings.HasPrefix(server, "Apache"):
		return apacheOrder
	case strings.HasPrefix(server, "Microsoft-IIS"):
		return iisOrder
	default:
		return nginxOrder
	}
}

// writeOrdered emits the captured response onto a hijacked connection.
//
// Returns false if the connection could not be taken, which leaves the caller
// to fall back to the ordinary writer -- a correct response in the wrong header
// order beats no response at all.
func (w *orderedWriter) writeOrdered(rw http.ResponseWriter, r *http.Request, server string) bool {
	hj, ok := rw.(http.Hijacker)
	if !ok {
		return false
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	// Content-Length and Connection are the transport's to set, and it is no
	// longer in the loop.
	w.header.Set("Content-Length", strconv.Itoa(w.body.Len()))
	w.header.Set("Connection", "close")

	var out bytes.Buffer
	proto := r.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	fmt.Fprintf(&out, "%s %d %s\r\n", proto, w.status, http.StatusText(w.status))

	written := make(map[string]bool, len(w.header))
	for _, name := range orderFor(server) {
		for _, v := range w.header.Values(name) {
			fmt.Fprintf(&out, "%s: %s\r\n", name, v)
		}
		if len(w.header.Values(name)) > 0 {
			written[http.CanonicalHeaderKey(name)] = true
		}
	}
	// Anything the ordering table does not name, in whatever order the handler
	// produced. A real server puts its unusual headers late too.
	for name, values := range w.header {
		if written[http.CanonicalHeaderKey(name)] {
			continue
		}
		for _, v := range values {
			fmt.Fprintf(&out, "%s: %s\r\n", name, v)
		}
	}
	out.WriteString("\r\n")

	// HEAD carries the headers of the equivalent GET and none of the body.
	if r.Method != http.MethodHead {
		out.Write(w.body.Bytes())
	}

	if _, err := buf.Write(out.Bytes()); err != nil {
		return true // connection is gone; the fallback cannot help either
	}
	_ = buf.Flush()
	return true
}

// Compile-time guards: the hijack path depends on these interfaces.
var (
	_ http.ResponseWriter = (*orderedWriter)(nil)
	_ = (*bufio.ReadWriter)(nil)
	_ = net.Conn(nil)
)
