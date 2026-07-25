package web

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/honeynet/node/internal/personality"
)

// CanaryPath is the prefix the sensor answers canary callbacks on.
//
// Deliberately unremarkable. A path containing "canary" would be recognised by
// anyone who looked, and the whole value of a honeyfile is that it is opened
// without suspicion.
const CanaryPath = "/static/img/"

// Token derives a stable canary identifier.
//
// Derived rather than random so that a sensor which restarts still recognises
// tokens it planted before, and so an operator can regenerate an identical
// honeyfile without keeping a database of issued tokens.
func Token(seed, purpose string) string {
	sum := sha256.Sum256([]byte("honeynet/canary/v1:" + seed + ":" + purpose))
	return hex.EncodeToString(sum[:8])
}

// CanaryURL builds the callback URL embedded in a honeyfile.
func CanaryURL(host, token string) string {
	return fmt.Sprintf("http://%s%s%s.png", host, CanaryPath, token)
}

// ParseCanaryToken extracts a token from a request path, returning false when
// the path is not a canary callback.
func ParseCanaryToken(path string) (string, bool) {
	if !strings.HasPrefix(path, CanaryPath) {
		return "", false
	}
	rest := strings.TrimPrefix(path, CanaryPath)
	rest = strings.TrimSuffix(rest, ".png")
	rest = strings.TrimSuffix(rest, ".gif")
	if len(rest) != 16 || strings.ContainsAny(rest, "/?&") {
		return "", false
	}
	if _, err := hex.DecodeString(rest); err != nil {
		return "", false
	}
	return rest, true
}

// dotenvBody renders a Laravel-style .env.
//
// Every secret in it is fake, and the URLs point back at this sensor's canary
// endpoint. Scanners that harvest a .env routinely probe the hosts they find
// in it, so the file is both bait and tripwire: the request for the file tells
// us someone is scanning, and a hit on the embedded URL tells us they parsed
// and acted on the contents, which is a much stronger signal.
func dotenvBody(p *personality.Personality, host string) string {
	tok := Token(p.Seed, "dotenv")
	var b strings.Builder
	b.WriteString("APP_NAME=Laravel\n")
	b.WriteString("APP_ENV=production\n")
	fmt.Fprintf(&b, "APP_KEY=base64:%s\n", Token(p.Seed, "appkey")+Token(p.Seed, "appkey2")+"aGVsbG89")
	b.WriteString("APP_DEBUG=false\n")
	fmt.Fprintf(&b, "APP_URL=http://%s\n\n", p.Hostname)
	b.WriteString("LOG_CHANNEL=stack\nLOG_LEVEL=error\n\n")
	b.WriteString("DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\n")
	b.WriteString("DB_DATABASE=app_production\nDB_USERNAME=app_rw\n")
	fmt.Fprintf(&b, "DB_PASSWORD=%s\n\n", Token(p.Seed, "dbpass"))
	b.WriteString("CACHE_DRIVER=redis\nQUEUE_CONNECTION=redis\nSESSION_DRIVER=redis\n")
	b.WriteString("REDIS_HOST=127.0.0.1\nREDIS_PORT=6379\n\n")
	fmt.Fprintf(&b, "AWS_ACCESS_KEY_ID=AKIA%s\n", strings.ToUpper(Token(p.Seed, "awskey")[:16]))
	fmt.Fprintf(&b, "AWS_SECRET_ACCESS_KEY=%s\n", Token(p.Seed, "awssecret")+Token(p.Seed, "awssecret2")+"wJal")
	b.WriteString("AWS_DEFAULT_REGION=us-east-1\n")
	b.WriteString("AWS_BUCKET=acme-prod-assets\n\n")
	b.WriteString("MAIL_MAILER=smtp\nMAIL_HOST=smtp.mailgun.org\nMAIL_PORT=587\n")
	b.WriteString("MAIL_USERNAME=postmaster@acme-internal.example\n")
	fmt.Fprintf(&b, "MAIL_PASSWORD=%s\n\n", Token(p.Seed, "mailpass"))
	// The tripwire: a plausible internal asset endpoint on this same host.
	fmt.Fprintf(&b, "ASSET_URL=%s\n", CanaryURL(host, tok))
	fmt.Fprintf(&b, "SENTRY_LARAVEL_DSN=https://%s@o447951.ingest.sentry.io/5428537\n", Token(p.Seed, "sentry"))
	return b.String()
}

// actuatorEnv renders a Spring Boot /actuator/env response carrying the same
// kind of bait.
func actuatorEnv(host string) string {
	tok := Token(host, "actuator")
	return fmt.Sprintf(`{"activeProfiles":["production"],"propertySources":[`+
		`{"name":"server.ports","properties":{"local.server.port":{"value":8080}}},`+
		`{"name":"applicationConfig: [classpath:/application.yml]","properties":{`+
		`"spring.datasource.url":{"value":"jdbc:mysql://127.0.0.1:3306/app"},`+
		`"spring.datasource.username":{"value":"app_rw"},`+
		`"spring.datasource.password":{"value":"******"},`+
		`"management.endpoints.web.exposure.include":{"value":"*"},`+
		`"app.asset-base":{"value":"%s"}}}]}`,
		CanaryURL(host, tok))
}

// ---- honeyfiles ----
//
// Files an operator plants on real systems -- file shares, developer laptops,
// backup directories -- so that opening one raises an alert. Unlike the web
// decoys, these are tripwires on infrastructure that has no other reason to be
// touched.

// Honeyfile is a generated bait file.
type Honeyfile struct {
	Name    string
	Token   string
	Type    string
	Content []byte
	// Hint tells the operator where this file is convincing.
	Hint string
}

// GenerateHoneyfiles produces a planting kit for one node.
func GenerateHoneyfiles(seed, callbackHost string) ([]Honeyfile, error) {
	var out []Honeyfile

	docTok := Token(seed, "honeyfile-docx")
	docx, err := buildDocx(CanaryURL(callbackHost, docTok))
	if err != nil {
		return nil, fmt.Errorf("build docx honeyfile: %w", err)
	}
	out = append(out, Honeyfile{
		Name:    "Q4_Salary_Review_CONFIDENTIAL.docx",
		Token:   docTok,
		Type:    "docx-callback",
		Content: docx,
		Hint:    "HR or finance shares; fires when the document is opened in Word",
	})

	awsTok := Token(seed, "honeyfile-aws")
	out = append(out, Honeyfile{
		Name:  "credentials",
		Token: awsTok,
		Type:  "aws-key",
		Content: []byte(fmt.Sprintf(
			"[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s\nregion = us-east-1\n\n"+
				"[deploy]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s\nregion = us-west-2\n",
			strings.ToUpper(Token(seed, "hf-aws-1")[:16]), Token(seed, "hf-aws-2")+Token(seed, "hf-aws-3"),
			strings.ToUpper(Token(seed, "hf-aws-4")[:16]), Token(seed, "hf-aws-5")+Token(seed, "hf-aws-6"))),
		Hint: "plant at ~/.aws/credentials; detection requires CloudTrail alerting on these key IDs",
	})

	envTok := Token(seed, "honeyfile-env")
	out = append(out, Honeyfile{
		Name:    ".env.backup",
		Token:   envTok,
		Type:    "url-token",
		Content: []byte(fmt.Sprintf("DB_PASSWORD=%s\nINTERNAL_API=%s\n", Token(seed, "hf-db"), CanaryURL(callbackHost, envTok))),
		Hint:    "web roots and deployment directories; fires when the API URL is probed",
	})

	return out, nil
}

// buildDocx writes a minimal but valid Word document whose only image is an
// external relationship.
//
// Word resolves external image targets on open, so the fetch is the alert.
// This is the same mechanism commercial canary tokens use; the file is
// genuinely openable, which matters because a corrupt document gets deleted
// rather than opened.
func buildDocx(callbackURL string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	write := func(name, content string) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(content))
		return err
	}

	if err := write("[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="png" ContentType="image/png"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`); err != nil {
		return nil, err
	}

	if err := write("_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`); err != nil {
		return nil, err
	}

	// TargetMode="External" is the whole mechanism: it makes Word fetch the
	// image over the network rather than look for it inside the package.
	if err := write("word/_rels/document.xml.rels", fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdImg1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="%s" TargetMode="External"/>
</Relationships>`, escapeXML(callbackURL))); err != nil {
		return nil, err
	}

	if err := write("word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
            xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
            xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
            xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">
<w:body>
<w:p><w:r><w:t>CONFIDENTIAL - Compensation Review, Q4</w:t></w:r></w:p>
<w:p><w:r><w:t>Distribution restricted to People Operations and the executive team.</w:t></w:r></w:p>
<w:p><w:r><w:drawing>
<wp:inline distT="0" distB="0" distL="0" distR="0">
<wp:extent cx="9525" cy="9525"/>
<wp:docPr id="1" name="Picture 1"/>
<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
<pic:pic>
<pic:nvPicPr><pic:cNvPr id="1" name="header.png"/><pic:cNvPicPr/></pic:nvPicPr>
<pic:blipFill><a:blip r:embed="rIdImg1"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>
<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="9525" cy="9525"/></a:xfrm>
<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>
</pic:pic></a:graphicData></a:graphic>
</wp:inline>
</w:drawing></w:r></w:p>
<w:sectPr><w:pgSz w:w="11906" w:h="16838"/></w:sectPr>
</w:body></w:document>`); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func escapeXML(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;",
	).Replace(s)
}

// canaryPixel is a 1x1 transparent PNG returned to a canary callback, so the
// document renders normally and the person who opened it notices nothing.
var canaryPixel = []byte{
	0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89,
	0x00, 0x00, 0x00, 0x0a, 'I', 'D', 'A', 'T',
	0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
	0x0d, 0x0a, 0x2d, 0xb4,
	0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
}

// tokenPlantedPath maps a token back to where it was planted, so an alert can
// name the compromised location rather than just the token.
var tokenPlantedPath = map[string]string{}

// RegisterToken records where a token was planted.
func RegisterToken(token, path string) { tokenPlantedPath[token] = path }

// PlantedPath returns the recorded location of a token.
func PlantedPath(token string) string {
	if p, ok := tokenPlantedPath[token]; ok {
		return p
	}
	return "unknown"
}

// KnownTokens returns the tokens a node embeds in its own web decoys, so the
// server can distinguish a genuine canary hit from a random request that
// happens to match the path shape.
func KnownTokens(seed string) map[string]string {
	return map[string]string{
		Token(seed, "dotenv"):          "/.env (web decoy)",
		Token(seed, "actuator"):        "/actuator/env (web decoy)",
		Token(seed, "honeyfile-docx"):  "planted document",
		Token(seed, "honeyfile-env"):   "planted .env.backup",
	}
}

// nowRFC3339 is split out so tests can reason about timestamps without
// reaching into the clock.
func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
