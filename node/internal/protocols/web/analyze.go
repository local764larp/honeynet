package web

import (
	"net/url"
	"regexp"
	"strings"
)

// Attack classes recognised in a request. These are the shapes that actually
// arrive at an exposed web sensor in volume; the list is deliberately short,
// because a classifier that fires on everything tells an analyst nothing.
const (
	AttackLog4Shell     = "log4shell"
	AttackSQLi          = "sqli"
	AttackPathTraversal = "path-traversal"
	AttackCommandInj    = "command-injection"
	AttackWebShell      = "webshell-upload"
	AttackXSS           = "xss"
	AttackSSRF          = "ssrf"
	AttackXXE           = "xxe"
	AttackDeserialize   = "deserialization"
	AttackShellshock    = "shellshock"
	AttackSecretProbe   = "secret-file-probe"
)

// jndiSimple catches the unobfuscated majority.
var jndiSimple = regexp.MustCompile(`(?i)\$\{jndi:(ldaps?|rmi|dns|iiop|corba|nds|nis)://`)

// Log4j lookup wrappers used to hide the literal string "jndi".
//
// Matching these with a single regex does not work: the obfuscated form is
// full of closing braces, so any `[^}]*` between the letters stops at the
// first one. The reliable approach is to collapse the wrappers first and then
// look for the plain string, which is what a vulnerable Log4j would itself
// end up resolving.
var (
	// ${lower:j} / ${upper:J}
	lookupCase = regexp.MustCompile(`(?i)\$\{(?:lower|upper):([^${}]{0,64})\}`)
	// ${::-j} and ${env:NAME:-j} / ${sys:prop:-j} default-value forms
	lookupDefault = regexp.MustCompile(`\$\{[a-zA-Z]{0,12}:?[^${}:]{0,64}:-([^${}]{0,64})\}`)
	// ${date:j} and other single-argument lookups
	lookupGeneric = regexp.MustCompile(`\$\{[a-zA-Z]{1,12}:([^${}:]{0,16})\}`)
)

// deobfuscateLookups collapses nested Log4j lookups until the string stops
// changing, bounded so a crafted payload cannot spin here.
func deobfuscateLookups(s string) string {
	if !strings.Contains(s, "${") {
		return s
	}
	for i := 0; i < 6; i++ {
		next := lookupCase.ReplaceAllString(s, "$1")
		next = lookupDefault.ReplaceAllString(next, "$1")
		next = lookupGeneric.ReplaceAllString(next, "$1")
		if next == s {
			break
		}
		s = next
	}
	return s
}

var sqliPattern = regexp.MustCompile(`(?i)(\bunion\b[\s/*]+\bselect\b|` +
	`\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+|` +
	`\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|` +
	`\bwaitfor\s+delay\b|\bexec\s*\(\s*@|` +
	`\bload_file\s*\(|\binto\s+outfile\b|` +
	`information_schema\.|\bextractvalue\s*\(|\bupdatexml\s*\()`)

var traversalPattern = regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e[/\\%]|` +
	`\.\.%2f|\.\.%5c|%252e%252e|/etc/passwd|/etc/shadow|` +
	`\\windows\\win\.ini|/proc/self/environ)`)

var commandInjPattern = regexp.MustCompile(`(?i)([;&|` + "`" + `]\s*(wget|curl|nc|ncat|bash|sh|python|perl|chmod|rm|cat|id|whoami|uname)\b|` +
	`\$\((wget|curl|id|whoami|uname)\b|` +
	`\|\s*(bash|sh)\b|` +
	`%0a\s*(wget|curl|id)\b)`)

var webShellPattern = regexp.MustCompile(`(?i)(<\?php|eval\s*\(\s*\$_(POST|GET|REQUEST)|` +
	`base64_decode\s*\(\s*\$_|system\s*\(\s*\$_|shell_exec\s*\(|passthru\s*\(|` +
	`assert\s*\(\s*\$_|preg_replace\s*\(.*/e|` +
	`<%@\s*page|Runtime\.getRuntime\(\)\.exec)`)

var xssPattern = regexp.MustCompile(`(?i)(<script[\s>]|javascript:|onerror\s*=|onload\s*=|` +
	`<img[^>]+src\s*=\s*['"]?\s*x\b|document\.cookie)`)

var ssrfPattern = regexp.MustCompile(`(?i)(https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|` +
	`169\.254\.169\.254|metadata\.google|\[::1\])|` +
	`\b(file|gopher|dict)://)`)

var xxePattern = regexp.MustCompile(`(?i)(<!ENTITY|<!DOCTYPE[^>]+SYSTEM|SYSTEM\s+["']file://)`)

var deserializePattern = regexp.MustCompile(`(?i)(rO0AB|` + // Java serialized, base64
	`\xac\xed\x00\x05|` + // Java serialized, raw
	`O:\d+:"[A-Za-z_]|` + // PHP serialized object
	`__reduce__|pickle\.loads)`)

// shellshockPattern matches the CVE-2014-6271 environment-variable prologue.
var shellshockPattern = regexp.MustCompile(`\(\s*\)\s*\{\s*[^;]*;\s*\}\s*;`)

// secretPaths are the files scanners probe for hoping an operator left them
// world-readable. Their appearance is not an exploit, but it is a strong
// reconnaissance signal and worth its own class.
var secretPaths = []string{
	"/.env", "/.git/config", "/.git/HEAD", "/.svn/entries", "/.aws/credentials",
	"/config.php.bak", "/wp-config.php.bak", "/.DS_Store", "/backup.sql",
	"/database.yml", "/settings.py", "/id_rsa", "/.ssh/id_rsa",
	"/docker-compose.yml", "/.npmrc", "/.dockercfg", "/server-status",
}

// Analyze classifies a request. Every part of the request is scanned, not just
// the path: Log4Shell in particular arrives almost exclusively in headers, and
// a scanner that only checked the URL would miss the whole campaign.
func Analyze(path, query string, headers map[string]string, body string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(class string) {
		if !seen[class] {
			seen[class] = true
			out = append(out, class)
		}
	}

	// Decode percent-encoding once so obfuscated payloads are caught, but keep
	// the raw form in the haystack too -- some payloads only match encoded.
	decodedPath, _ := url.QueryUnescape(path)
	decodedQuery, _ := url.QueryUnescape(query)

	var headerBlob strings.Builder
	for k, v := range headers {
		headerBlob.WriteString(k)
		headerBlob.WriteString(": ")
		headerBlob.WriteString(v)
		headerBlob.WriteString("\n")
	}
	decodedHeaders, _ := url.QueryUnescape(headerBlob.String())

	haystack := strings.Join([]string{
		path, query, decodedPath, decodedQuery,
		headerBlob.String(), decodedHeaders, body,
	}, "\n")

	// Collapse Log4j lookup wrappers before matching, so the obfuscated form
	// resolves to the same string a vulnerable Log4j would have resolved.
	if jndiSimple.MatchString(haystack) || jndiSimple.MatchString(deobfuscateLookups(haystack)) {
		add(AttackLog4Shell)
	}
	if sqliPattern.MatchString(haystack) {
		add(AttackSQLi)
	}
	if traversalPattern.MatchString(haystack) {
		add(AttackPathTraversal)
	}
	if commandInjPattern.MatchString(haystack) {
		add(AttackCommandInj)
	}
	if webShellPattern.MatchString(haystack) {
		add(AttackWebShell)
	}
	if xssPattern.MatchString(haystack) {
		add(AttackXSS)
	}
	if ssrfPattern.MatchString(haystack) {
		add(AttackSSRF)
	}
	if xxePattern.MatchString(haystack) {
		add(AttackXXE)
	}
	if deserializePattern.MatchString(haystack) {
		add(AttackDeserialize)
	}
	// Shellshock lives in headers only; a body match would be a false positive
	// on any page that happens to contain shell source.
	if shellshockPattern.MatchString(headerBlob.String()) {
		add(AttackShellshock)
	}

	lowerPath := strings.ToLower(decodedPath)
	for _, p := range secretPaths {
		if strings.HasPrefix(lowerPath, p) || strings.HasSuffix(lowerPath, p) {
			add(AttackSecretProbe)
			break
		}
	}

	return out
}

// urlPattern extracts fetchable references from request content. The same rule
// as the shell applies: these are recorded as artifact references and the
// sensor never retrieves them.
var urlPattern = regexp.MustCompile(`(?i)\b(https?|ftp|tftp)://[^\s"'<>)\]}\\|;,]{3,}`)

// ExtractURLs pulls payload URLs out of a request.
//
// Worth doing separately from the shell's extractor because the interesting
// ones here hide in places a command line never has them: JNDI lookup targets,
// SSRF parameters, and the second stage of a command injection.
func ExtractURLs(path, query string, headers map[string]string, body string) []string {
	var parts []string
	parts = append(parts, path, query, body)
	for k, v := range headers {
		parts = append(parts, k+": "+v)
	}

	seen := map[string]bool{}
	var out []string
	for _, p := range parts {
		decoded, err := url.QueryUnescape(p)
		if err != nil {
			decoded = p
		}
		for _, candidate := range urlPattern.FindAllString(p+"\n"+decoded, -1) {
			candidate = strings.TrimRight(candidate, ".,;:")
			if !seen[candidate] {
				seen[candidate] = true
				out = append(out, candidate)
			}
		}
	}
	return out
}

// jndiTarget extracts the callback host from a JNDI lookup. That host is the
// attacker's own infrastructure and is a higher-confidence indicator than the
// source address, which is usually a compromised third party.
var jndiTargetPattern = regexp.MustCompile(`(?i)\$\{jndi:(?:ldaps?|rmi|dns|iiop):/?/?([^/}\s]+)`)

// ExtractJNDITargets returns the callback endpoints of any Log4Shell payloads.
func ExtractJNDITargets(path, query string, headers map[string]string, body string) []string {
	var parts []string
	parts = append(parts, path, query, body)
	for k, v := range headers {
		parts = append(parts, k+": "+v)
	}

	seen := map[string]bool{}
	var out []string
	for _, p := range parts {
		decoded, err := url.QueryUnescape(p)
		if err != nil {
			decoded = p
		}
		// The obfuscated form hides "jndi" but not the callback host; collapse
		// the wrappers so both spellings yield the same target.
		candidates := p + "\n" + decoded + "\n" +
			deobfuscateLookups(p) + "\n" + deobfuscateLookups(decoded)
		for _, m := range jndiTargetPattern.FindAllStringSubmatch(candidates, -1) {
			if len(m) > 1 && m[1] != "" && !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	return out
}
