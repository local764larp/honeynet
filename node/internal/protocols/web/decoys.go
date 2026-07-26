package web

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/honeynet/node/internal/personality"
)

// Decoy is one emulated vulnerable application.
//
// Profiles are chosen by what actually arrives at an exposed web sensor. The
// long tail of scanner paths is enormous, but a handful of targets account for
// most of the volume, and giving those a plausible response is what keeps a
// scanner engaged long enough to send its payload.
type Decoy struct {
	Name string
	// Match decides whether this decoy handles the request.
	Match func(r *http.Request) bool
	// Serve writes the response and returns the status it used.
	Serve func(w http.ResponseWriter, r *http.Request, p *personality.Personality, tok string) int
	// LoginForm marks decoys that accept credentials, so the server knows to
	// look for them in the body.
	LoginForm bool
}

func pathPrefix(prefixes ...string) func(*http.Request) bool {
	return func(r *http.Request) bool {
		p := strings.ToLower(r.URL.Path)
		for _, pre := range prefixes {
			if strings.HasPrefix(p, pre) {
				return true
			}
		}
		return false
	}
}

func pathMatch(re *regexp.Regexp) func(*http.Request) bool {
	return func(r *http.Request) bool { return re.MatchString(strings.ToLower(r.URL.Path)) }
}

// Decoys are evaluated in order; the first match wins, so specific profiles
// precede the catch-all.
func Decoys() []Decoy {
	return []Decoy{
		{
			Name:      "phpmyadmin",
			LoginForm: true,
			Match:     pathPrefix("/phpmyadmin", "/pma", "/phpmyadm", "/mysqladmin", "/db", "/dbadmin", "/myadmin"),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, _ string) int {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("X-Frame-Options", "DENY")
				w.Header().Set("Set-Cookie", "phpMyAdmin=8f2a1c9d4e; path=/; HttpOnly")
				fmt.Fprint(w, phpMyAdminLogin)
				return http.StatusOK
			},
		},
		{
			Name:      "wordpress",
			LoginForm: true,
			Match:     pathPrefix("/wp-login.php", "/wp-admin", "/wordpress/wp-login.php", "/wp/wp-login.php"),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, _ string) int {
				w.Header().Set("Content-Type", "text/html; charset=UTF-8")
				w.Header().Set("X-Powered-By", "PHP/7.4.33")
				fmt.Fprint(w, wordpressLogin)
				return http.StatusOK
			},
		},
		{
			// Serving a .env is the single highest-yield decoy on the internet:
			// scanners that find one immediately try the credentials, which
			// tells us far more than the request alone. Everything in it is a
			// canary -- see canary.go.
			Name:  "dotenv",
			Match: pathMatch(regexp.MustCompile(`(^|/)\.env(\.|$)`)),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, tok string) int {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				fmt.Fprint(w, dotenvBody(p, tok))
				return http.StatusOK
			},
		},
		{
			Name:  "git-exposure",
			Match: pathPrefix("/.git/"),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, _ string) int {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				switch {
				case strings.HasSuffix(r.URL.Path, "/HEAD"):
					fmt.Fprint(w, "ref: refs/heads/main\n")
				case strings.HasSuffix(r.URL.Path, "/config"):
					fmt.Fprint(w, gitConfig)
				default:
					w.WriteHeader(http.StatusNotFound)
					return http.StatusNotFound
				}
				return http.StatusOK
			},
		},
		{
			Name:  "spring-actuator",
			Match: pathPrefix("/actuator", "/manage", "/env", "/heapdump", "/trace"),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, tok string) int {
				w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/env"):
					fmt.Fprint(w, actuatorEnv(tok))
				case strings.HasSuffix(r.URL.Path, "/health"):
					fmt.Fprint(w, `{"status":"UP","groups":["liveness","readiness"]}`)
				default:
					fmt.Fprint(w, actuatorIndex)
				}
				return http.StatusOK
			},
		},
		{
			Name:  "tomcat-manager",
			Match: pathPrefix("/manager/html", "/manager/status", "/host-manager"),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, _ string) int {
				// 401 with a Basic challenge is what draws the credential
				// attempt; serving 200 would end the interaction.
				w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
				w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, tomcat401)
				return http.StatusUnauthorized
			},
			LoginForm: true,
		},
		{
			Name:  "struts2",
			Match: pathMatch(regexp.MustCompile(`\.(action|do)$|/struts`)),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, _ string) int {
				w.Header().Set("Content-Type", "text/html;charset=UTF-8")
				fmt.Fprint(w, strutsShowcase)
				return http.StatusOK
			},
		},
		{
			Name:  "phpunit-rce",
			Match: pathPrefix("/vendor/phpunit", "/vendor/phpoffice"),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, _ string) int {
				// The real bug evaluates the POST body. Returning 200 with no
				// output is what a successful-but-silent exploit looks like,
				// which encourages the follow-up payload we actually want.
				w.Header().Set("Content-Type", "text/html; charset=UTF-8")
				w.Header().Set("X-Powered-By", "PHP/7.2.24")
				return http.StatusOK
			},
		},
		{
			Name:  "cgi-shellshock",
			Match: pathPrefix("/cgi-bin/", "/cgi-sys/", "/cgi-mod/"),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, _ string) int {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "Content-Type: text/plain\n\n")
				return http.StatusOK
			},
		},
		{
			Name:      "router-admin",
			LoginForm: true,
			Match:     pathPrefix("/boaform", "/goform", "/cgi-bin/luci", "/login.cgi", "/setup.cgi"),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, _ string) int {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Server", "Boa/0.94.14rc21")
				fmt.Fprint(w, routerLogin)
				return http.StatusOK
			},
		},
		{
			Name:  "solr-admin",
			Match: pathPrefix("/solr"),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, _ string) int {
				w.Header().Set("Content-Type", "application/json;charset=utf-8")
				fmt.Fprint(w, solrCores)
				return http.StatusOK
			},
		},
		{
			Name:  "liferay-jsonws",
			Match: pathPrefix("/api/jsonws"),
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, _ string) int {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"exception":"No JSON web service action associated with path"}`)
				return http.StatusOK
			},
		},
		{
			Name:  "generic-index",
			Match: func(r *http.Request) bool { return true },
			Serve: func(w http.ResponseWriter, r *http.Request, p *personality.Personality, _ string) int {
				if r.URL.Path == "/" || r.URL.Path == "/index.html" {
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprint(w, nginxIndex(p))
					return http.StatusOK
				}
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, nginx404(p))
				return http.StatusNotFound
			},
		},
	}
}

// serverHeader picks a web server banner consistent with the node's derived
// distribution, so the HTTP surface agrees with what the SSH shell would say.
func serverHeader(p *personality.Personality) string {
	for _, pkg := range p.Packages {
		switch pkg {
		case "nginx":
			return "nginx/1.18.0 (Ubuntu)"
		case "apache2":
			if p.Distro.ID == "centos" {
				return "Apache/2.4.6 (CentOS)"
			}
			return "Apache/2.4.52 (Ubuntu)"
		}
	}
	return "nginx/1.18.0 (Ubuntu)"
}

// ---- templates ----

func nginxIndex(p *personality.Personality) string {
	return `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`
}

func nginx404(p *personality.Personality) string {
	return `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>` + serverHeader(p) + `</center>
</body>
</html>
`
}

const phpMyAdminLogin = `<!DOCTYPE HTML>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8" />
<title>phpMyAdmin</title>
<link rel="stylesheet" type="text/css" href="./themes/pmahomme/css/theme.css" />
</head>
<body class="loginform">
<div class="container">
<a href="https://www.phpmyadmin.net/" target="_blank" class="logo">
<img src="./themes/pmahomme/img/logo_right.png" alt="phpMyAdmin" /></a>
<h1>Welcome to <bdo dir="ltr">phpMyAdmin</bdo></h1>
<form method="post" action="index.php" name="login_form" class="login hide js-show">
    <fieldset>
    <legend>Log in</legend>
    <div class="item">
        <label for="input_username">Username:</label>
        <input type="text" name="pma_username" id="input_username" value="" size="24" class="textfield" />
    </div>
    <div class="item">
        <label for="input_password">Password:</label>
        <input type="password" name="pma_password" id="input_password" value="" size="24" class="textfield" />
    </div>
    <div class="item">
        <label for="select_server">Server Choice:</label>
        <select name="pma_servername" id="select_server">
            <option value="1" selected="selected">localhost</option>
        </select>
    </div>
    </fieldset>
    <fieldset class="tblFooters">
        <input value="Go" type="submit" id="input_go" />
        <input type="hidden" name="target" value="index.php" />
    </fieldset>
</form>
</div>
</body>
</html>
`

const wordpressLogin = `<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; My Site &#8212; WordPress</title>
<link rel='stylesheet' href='/wp-admin/css/login.min.css?ver=6.4.2' media='all' />
</head>
<body class="login no-js login-action-login wp-core-ui locale-en-us">
	<div id="login">
		<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
	<form name="loginform" id="loginform" action="/wp-login.php" method="post">
		<p>
			<label for="user_login">Username or Email Address</label>
			<input type="text" name="log" id="user_login" class="input" value="" size="20" />
		</p>
		<div class="user-pass-wrap">
			<label for="user_pass">Password</label>
			<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" />
		</div>
		<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever" /> <label for="rememberme">Remember Me</label></p>
		<p class="submit">
			<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
			<input type="hidden" name="redirect_to" value="/wp-admin/" />
		</p>
	</form>
	</div>
</body>
</html>
`

const gitConfig = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/acme-internal/webapp.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	name = deploy
	email = deploy@acme-internal.example
`

const actuatorIndex = `{"_links":{"self":{"href":"http://localhost:8080/actuator","templated":false},` +
	`"health":{"href":"http://localhost:8080/actuator/health","templated":false},` +
	`"env":{"href":"http://localhost:8080/actuator/env","templated":false},` +
	`"beans":{"href":"http://localhost:8080/actuator/beans","templated":false},` +
	`"heapdump":{"href":"http://localhost:8080/actuator/heapdump","templated":false}}}`

const tomcat401 = `<html><head><title>401 Unauthorized</title></head>
<body><h1>401 Unauthorized</h1>
<p>You are not authorized to view this page.</p>
<p>If you have already configured the Manager application to allow access and
you have used your browsers back button, used a saved bookmark or similar
then you may have triggered the cross-site request forgery (CSRF) protection
that has been enabled for the HTML interface of the Manager application.</p>
</body></html>
`

const strutsShowcase = `<!DOCTYPE html>
<html><head><title>Struts2 Showcase</title></head>
<body>
<h2>Struts2 Showcase</h2>
<p>Apache Struts 2.3.20</p>
<ul>
<li><a href="/struts2-showcase/showcase.action">Showcase Home</a></li>
<li><a href="/struts2-showcase/fileupload/upload.action">File Upload</a></li>
</ul>
</body></html>
`

const routerLogin = `<html><head><title>Router Login</title></head>
<body bgcolor="#FFFFFF">
<form method="post" action="/boaform/admin/formLogin">
<table><tr><td>Username:</td><td><input type="text" name="username" size="20"></td></tr>
<tr><td>Password:</td><td><input type="password" name="psd" size="20"></td></tr>
<tr><td colspan=2><input type="submit" value="Login"></td></tr></table>
</form>
</body></html>
`

const solrCores = `{"responseHeader":{"status":0,"QTime":2},"initFailures":{},` +
	`"status":{"core0":{"name":"core0","instanceDir":"/var/solr/data/core0",` +
	`"dataDir":"/var/solr/data/core0/data/","config":"solrconfig.xml",` +
	`"schema":"managed-schema","startTime":"2026-02-14T08:11:03.442Z","uptime":13996800000}}}`
