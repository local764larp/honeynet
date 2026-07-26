// Package web implements the HTTP honeypot listener.
//
// Containment: this package imports net/http to *serve*. It never dials. The
// containment lint bans the outbound call surface (http.Get, net.Dial, and
// friends) rather than the import, precisely so that serving is possible and
// fetching is not. Attacker-supplied URLs found in requests are recorded as
// artifact references, exactly as the shell does with wget targets.
package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/honeynet/node/gen/honeynet/v1"
	"github.com/honeynet/node/internal/personality"
	"github.com/honeynet/node/internal/session"
	"github.com/honeynet/node/internal/shell"
)

// maxBodyBytes bounds what one request may push into memory. Generous enough
// for a webshell upload or a serialized payload, tight enough that a sensor
// cannot be memory-exhausted by a POST loop.
const maxBodyBytes = 2 << 20 // 2 MiB

// Config parameterises the HTTP listener.
type Config struct {
	NodeID string
	Addr   string

	// CredentialSecret keys the canary tokens. Must be the same value that was
	// assigned to the personality's TokenSecret, or the tokens planted in the
	// decoy files will not be the tokens this server recognises on callback.
	CredentialSecret string

	// SessionIdle groups requests from one source into a single session.
	// HTTP is stateless, but scanners are not: a sweep of forty paths from one
	// address is one interaction, and recording it as forty unrelated sessions
	// would destroy the sequence information that makes the behaviour legible.
	SessionIdle time.Duration

	MaxSessions      int
	MaxSessionsPerIP int

	// CallbackHost is the authority embedded in canary URLs. Should be the
	// sensor's public name or address.
	CallbackHost string
}

// Server is the HTTP honeypot.
type Server struct {
	cfg    Config
	p      *personality.Personality
	sink   session.Sink
	log    *slog.Logger
	notify func()

	decoys []Decoy
	tokens map[string]string

	mu        sync.Mutex
	sessions  map[string]*liveSession
	boundAddr string

	srv *http.Server
}

type liveSession struct {
	rec      *session.Recorder
	lastSeen time.Time
	requests int
}

// New constructs the listener.
func New(cfg Config, p *personality.Personality, sink session.Sink, log *slog.Logger, notify func()) *Server {
	if cfg.SessionIdle <= 0 {
		cfg.SessionIdle = 2 * time.Minute
	}
	if cfg.CallbackHost == "" {
		cfg.CallbackHost = p.Hostname
	}
	return &Server{
		cfg: cfg, p: p, sink: sink, log: log, notify: notify,
		decoys:   Decoys(),
		tokens:   KnownTokens(cfg.CredentialSecret),
		sessions: map[string]*liveSession{},
	}
}

// Listen binds the configured address.
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

// Addr reports the resolved bound address.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.boundAddr != "" {
		return s.boundAddr
	}
	return s.cfg.Addr
}

// Serve handles requests until the context is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.srv = &http.Server{
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          nil,
	}

	s.log.Info("http honeypot listening", "addr", ln.Addr().String(), "server", serverHeader(s.p))

	sweeper := time.NewTicker(30 * time.Second)
	defer sweeper.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				s.closeAllSessions(pb.SessionEndReason_SESSION_END_REASON_NODE_SHUTDOWN)
				_ = s.srv.Close()
				return
			case <-sweeper.C:
				s.sweepIdle()
			}
		}
	}()

	err := s.srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// ListenAndServe binds and serves.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := s.Listen()
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// handle answers one request.
//
// The response is built into an orderedWriter and only then put on the wire, so
// the header sequence matches the server being impersonated rather than the
// alphabetical order net/http would produce. See headers.go.
func (s *Server) handle(rw http.ResponseWriter, r *http.Request) {
	ow := newOrderedWriter()
	var w http.ResponseWriter = ow

	defer func() {
		// Scanners send deliberately malformed requests. A panic in one
		// handler must not take the sensor down.
		if rec := recover(); rec != nil {
			s.log.Error("http handler panicked", "recovered", rec, "path", r.URL.Path)
		}

		// Emit whatever was built, even on the panic path -- a scanner that
		// tripped a bug must still get a response, or the silence is itself
		// the signal.
		if !ow.writeOrdered(rw, r, serverHeader(s.p)) {
			// Connection could not be hijacked. A correct response in the
			// wrong header order beats no response.
			for name, values := range ow.Header() {
				for _, v := range values {
					rw.Header().Add(name, v)
				}
			}
			rw.WriteHeader(ow.status)
			_, _ = rw.Write(ow.body.Bytes())
		}
	}()

	peer := peerFrom(r.RemoteAddr, s.Addr())

	// Read the body once, bounded, and keep it: it carries webshell uploads,
	// serialized payloads and login credentials.
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		_ = r.Body.Close()
	}

	headers := flattenHeaders(r)

	// Canary callbacks are answered before anything else and never counted as
	// a scan: a hit means a planted file was opened, which is a different and
	// much stronger event than a request for a decoy page.
	if tok, ok := ParseCanaryToken(r.URL.Path); ok {
		s.handleCanary(w, r, peer, tok, headers)
		return
	}

	rec := s.sessionFor(peer)
	if rec == nil {
		// Over budget. Connection refused shape, no decoy served.
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	decoy := s.matchDecoy(r)
	w.Header().Set("Server", serverHeader(s.p))
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))

	status := decoy.Serve(w, r, s.p, s.cfg.CallbackHost)

	attacks := Analyze(r.URL.Path, r.URL.RawQuery, headers, string(body))

	sum := sha256.Sum256(body)
	bodyHash := ""
	if len(body) > 0 {
		bodyHash = hex.EncodeToString(sum[:])
	}

	user, pass := extractCredentials(r, body)

	rec.HTTPRequest(session.HTTPRequestEvent{
		Method:          r.Method,
		Path:            r.URL.Path,
		Query:           r.URL.RawQuery,
		Version:         r.Proto,
		Headers:         headers,
		BodySHA256:      bodyHash,
		BodySize:        uint64(len(body)),
		DecoyProfile:    decoy.Name,
		ResponseStatus:  uint32(status),
		DetectedAttacks: attacks,
		FormUsername:    user,
		FormPassword:    pass,
	})

	// Credentials submitted to a decoy login form are credentials, and belong
	// in the same corpus as the SSH ones rather than buried in a header bag.
	if user != "" || pass != "" {
		rec.AuthAttempt(pb.AuthMethod_AUTH_METHOD_PASSWORD, user, pass, false)
	}

	// Payload URLs, including JNDI callback targets, which are the attacker's
	// own infrastructure and a stronger indicator than the source address.
	for _, u := range ExtractURLs(r.URL.Path, r.URL.RawQuery, headers, string(body)) {
		rec.Artifact(shell.ArtifactEvent{
			URL: u, ViaTool: "http-" + decoy.Name,
			SourceCommand: r.Method + " " + r.URL.RequestURI(),
		})
	}
	for _, target := range ExtractJNDITargets(r.URL.Path, r.URL.RawQuery, headers, string(body)) {
		rec.Artifact(shell.ArtifactEvent{
			URL: "ldap://" + target, ViaTool: "log4shell-jndi",
			SourceCommand: r.Method + " " + r.URL.RequestURI(),
		})
	}

	// A body that looks like a dropped file is recorded as an upload so it
	// lands in the same content-addressed store as SCP payloads.
	if len(body) > 0 && looksLikePayload(attacks, r) {
		rec.Upload(shell.UploadEvent{
			Path:        r.URL.Path,
			Content:     body,
			ClaimedName: uploadName(r),
			Transport:   "http-post",
		})
	}

	if len(attacks) > 0 {
		s.log.Info("web attack observed",
			"session", rec.ID(), "peer", peer.SrcIp,
			"path", r.URL.Path, "decoy", decoy.Name, "attacks", strings.Join(attacks, ","))
	}

	s.notify()
}

func (s *Server) handleCanary(w http.ResponseWriter, r *http.Request, peer *pb.Peer, tok string, headers map[string]string) {
	planted, known := s.tokens[tok]
	if !known {
		planted = PlantedPath(tok)
	}

	rec := session.New(s.cfg.NodeID, s.sink, s.log, pb.Protocol_PROTOCOL_CANARY, peer)
	rec.SessionStart("", nil, nil, nil, nil)
	rec.Canary(session.CanaryEvent{
		TokenID:      tok,
		TokenType:    "url-token",
		PlantedPath:  planted,
		CallbackPeer: peer,
		UserAgent:    r.Header.Get("User-Agent"),
	})
	rec.SessionEnd(pb.SessionEndReason_SESSION_END_REASON_CLIENT_CLOSED, "")
	s.notify()

	s.log.Warn("CANARY TRIGGERED",
		"token", tok, "planted", planted,
		"peer", peer.SrcIp, "ua", r.Header.Get("User-Agent"))

	// Answer with a real pixel so whoever opened the document sees nothing
	// unusual. An error here would tell them the file was bait.
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Server", serverHeader(s.p))
	_, _ = w.Write(canaryPixel)
}

func (s *Server) matchDecoy(r *http.Request) Decoy {
	for _, d := range s.decoys {
		if d.Match(r) {
			return d
		}
	}
	return s.decoys[len(s.decoys)-1]
}

// sessionFor returns the recorder for a source address, opening one if this is
// a new interaction.
func (s *Server) sessionFor(peer *pb.Peer) *session.Recorder {
	s.mu.Lock()
	defer s.mu.Unlock()

	if live, ok := s.sessions[peer.SrcIp]; ok {
		live.lastSeen = time.Now()
		live.requests++
		return live.rec
	}

	if s.cfg.MaxSessions > 0 && len(s.sessions) >= s.cfg.MaxSessions {
		return nil
	}

	rec := session.New(s.cfg.NodeID, s.sink, s.log, pb.Protocol_PROTOCOL_HTTP, peer)
	rec.SessionStart("", nil, nil, nil, nil)
	s.sessions[peer.SrcIp] = &liveSession{rec: rec, lastSeen: time.Now(), requests: 1}
	s.log.Info("http session opened", "session", rec.ID(), "peer", peer.SrcIp)
	return rec
}

// sweepIdle closes sessions whose source has gone quiet.
func (s *Server) sweepIdle() {
	s.mu.Lock()
	var expired []*liveSession
	for ip, live := range s.sessions {
		if time.Since(live.lastSeen) > s.cfg.SessionIdle {
			expired = append(expired, live)
			delete(s.sessions, ip)
		}
	}
	s.mu.Unlock()

	for _, live := range expired {
		live.rec.SessionEnd(pb.SessionEndReason_SESSION_END_REASON_TIMEOUT, "")
		s.log.Info("http session closed",
			"session", live.rec.ID(), "requests", live.requests,
			"duration", live.rec.Elapsed().Round(time.Second))
	}
	if len(expired) > 0 {
		s.notify()
	}
}

func (s *Server) closeAllSessions(reason pb.SessionEndReason) {
	s.mu.Lock()
	all := make([]*liveSession, 0, len(s.sessions))
	for ip, live := range s.sessions {
		all = append(all, live)
		delete(s.sessions, ip)
	}
	s.mu.Unlock()

	for _, live := range all {
		live.rec.SessionEnd(reason, "")
	}
	if len(all) > 0 {
		s.notify()
	}
}

// ---- request helpers ----

func peerFrom(remoteAddr, localAddr string) *pb.Peer {
	p := &pb.Peer{}
	if h, port, err := net.SplitHostPort(remoteAddr); err == nil {
		p.SrcIp = h
		if n, err := strconv.Atoi(port); err == nil {
			p.SrcPort = uint32(n)
		}
	} else {
		p.SrcIp = remoteAddr
	}
	if h, port, err := net.SplitHostPort(localAddr); err == nil {
		p.DstIp = h
		if n, err := strconv.Atoi(port); err == nil {
			p.DstPort = uint32(n)
		}
	}
	return p
}

// flattenHeaders collapses the multi-value header map. Duplicates are joined
// rather than dropped: a request carrying two User-Agent values is itself
// anomalous and worth preserving.
func flattenHeaders(r *http.Request) map[string]string {
	out := make(map[string]string, len(r.Header)+1)
	for k, v := range r.Header {
		out[k] = strings.Join(v, ", ")
	}
	if r.Host != "" {
		out["Host"] = r.Host
	}
	return out
}

// extractCredentials pulls a username and password out of a decoy login
// submission, covering both form posts and HTTP Basic.
func extractCredentials(r *http.Request, body []byte) (string, string) {
	if u, p, ok := r.BasicAuth(); ok {
		return u, p
	}

	if len(body) == 0 {
		return "", ""
	}
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return "", ""
	}

	values, err := parseForm(string(body))
	if err != nil {
		return "", ""
	}

	// Field names vary by decoy; these cover the login forms this package
	// serves plus the common variants scanners submit blind.
	userKeys := []string{"pma_username", "log", "username", "user", "uname", "login", "email", "j_username"}
	passKeys := []string{"pma_password", "pwd", "password", "pass", "psd", "passwd", "j_password"}

	var user, pass string
	for _, k := range userKeys {
		if v := values[k]; v != "" {
			user = v
			break
		}
	}
	for _, k := range passKeys {
		if v := values[k]; v != "" {
			pass = v
			break
		}
	}
	return user, pass
}

// parseForm decodes an application/x-www-form-urlencoded body.
//
// Hand-rolled rather than using url.ParseQuery because that rejects the whole
// body on the first malformed escape, and scanner payloads are full of them --
// losing an entire credential submission to one stray percent sign would be a
// poor trade.
func parseForm(body string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(body, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		key := decodeFormValue(k)
		if key == "" {
			continue
		}
		out[key] = decodeFormValue(v)
	}
	return out, nil
}

func decodeFormValue(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// looksLikePayload decides whether a body is worth storing as an artifact.
func looksLikePayload(attacks []string, r *http.Request) bool {
	for _, a := range attacks {
		if a == AttackWebShell || a == AttackDeserialize {
			return true
		}
	}
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "multipart/form-data") ||
		strings.HasPrefix(ct, "application/octet-stream")
}

func uploadName(r *http.Request) string {
	if cd := r.Header.Get("Content-Disposition"); cd != "" {
		if _, after, ok := strings.Cut(cd, "filename="); ok {
			return strings.Trim(strings.TrimSpace(after), `"`)
		}
	}
	if i := strings.LastIndexByte(r.URL.Path, '/'); i >= 0 && i+1 < len(r.URL.Path) {
		return r.URL.Path[i+1:]
	}
	return "body"
}
