// Package containment holds the executable form of the node's hard safety
// invariants.
//
// These are tests rather than documentation because a containment rule that
// lives only in a design document is a rule that gets broken by the next
// well-meaning refactor. Design doc section 4.1 requires this check to run in
// CI; `go test ./...` is that CI check.
package containment_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbiddenImports must never appear anywhere in the node tree.
//
// os/exec and the process-spawning half of syscall are the execution path. The
// emulated shell answers every command from the in-memory VFS; if any of these
// appear, something has started actually running attacker input.
var forbiddenImports = map[string]string{
	"os/exec":       "the node must never execute attacker input (design doc 4.1)",
	"plugin":        "dynamic code loading is an execution path",
	"unsafe":        "no unsafe pointer arithmetic in a process handling hostile input",
	"net/http/cgi":  "CGI hands requests to a subprocess",
	"os/user":       "leaks real host accounts into emulated responses",
}

// outboundCalls are the ways a sensor could reach out to a third party.
//
// The rule targets calls rather than the net/http import, because the HTTP
// honeypot needs net/http to *serve*. Serving is the product; dialling is the
// hazard. A sensor that opens an outbound connection is either fetching an
// attacker-supplied URL (design doc 4.2) or acting as a relay (4.3), and both
// are the failure modes that get a fleet terminated.
//
// Keys are "package.Symbol" as written at the call site.
var outboundCalls = map[string]string{
	"http.Get":            "fetches a URL; sensors never retrieve attacker-supplied resources (4.2)",
	"http.Post":           "outbound request from a sensor (4.2)",
	"http.PostForm":       "outbound request from a sensor (4.2)",
	"http.Head":           "outbound request from a sensor (4.2)",
	"http.NewRequest":     "constructs an outbound request; sensors only serve (4.2)",
	"http.ReadResponse":   "consumes an outbound response (4.2)",
	"net.Dial":            "opens an arbitrary outbound connection (4.3)",
	"net.DialTimeout":     "opens an arbitrary outbound connection (4.3)",
	"net.DialUDP":         "opens an arbitrary outbound connection (4.3)",
	"net.DialTCP":         "opens an arbitrary outbound connection (4.3)",
	"tls.Dial":            "opens an arbitrary outbound connection (4.3)",
	"tls.DialWithDialer":  "opens an arbitrary outbound connection (4.3)",
}

// outboundCallAllowedDirs may dial, because reaching the collector is the one
// legitimate outbound path a sensor has.
var outboundCallAllowedDirs = map[string]bool{
	"internal/transport": true,
	// The attacker simulator is a test/corpus tool, not part of the sensor. It
	// dials honeypots on purpose.
	"cmd/attacksim": true,
}

// outboundIdents are the package identifiers worth inspecting for the calls
// above. Restricting the scan to these keeps the walk cheap and avoids
// flagging unrelated methods that happen to share a name.
var outboundIdents = map[string]bool{
	"http": true,
	"net":  true,
	"tls":  true,
}

func TestNoExecutionPath(t *testing.T) {
	root := nodeRoot(t)
	fset := token.NewFileSet()

	var violations []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Generated protobuf code and vendored dependencies are out of
			// scope; the rule is about code we write.
			if name := d.Name(); name == "gen" || name == "vendor" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		file, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}

		rel, _ := filepath.Rel(root, path)

		for _, imp := range file.Imports {
			pkg, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}

			if reason, bad := forbiddenImports[pkg]; bad {
				violations = append(violations,
					filepath.ToSlash(rel)+" imports "+pkg+": "+reason)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk node tree: %v", err)
	}

	for _, v := range violations {
		t.Error("containment violation: " + v)
	}
}

// TestNoProcessSpawnCalls catches the syscall-level escape hatches that an
// import check alone would miss, since package syscall has legitimate uses.
func TestNoProcessSpawnCalls(t *testing.T) {
	root := nodeRoot(t)
	fset := token.NewFileSet()

	banned := map[string]bool{
		"StartProcess":  true,
		"ForkExec":      true,
		"Exec":          true,
		"CommandContext": true,
		"Command":       true,
	}

	var violations []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "gen" || name == "vendor" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, path)

		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			// Only flag calls on packages that could actually spawn.
			if ident.Name != "syscall" && ident.Name != "exec" && ident.Name != "os" {
				return true
			}
			if banned[sel.Sel.Name] {
				violations = append(violations,
					filepath.ToSlash(rel)+" calls "+ident.Name+"."+sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk node tree: %v", err)
	}

	for _, v := range violations {
		t.Error("containment violation: " + v)
	}
}

// TestNoOutboundConnections is the anti-relay and no-fetch invariant.
//
// The HTTP honeypot serves, so banning the net/http import outright would be
// wrong. What must never happen is a sensor *dialling* something: that is
// either fetching an attacker-supplied URL or relaying traffic on an
// attacker's behalf, and both are how honeypot operators end up generating
// abuse reports against themselves.
func TestNoOutboundConnections(t *testing.T) {
	root := nodeRoot(t)
	fset := token.NewFileSet()

	var violations []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "gen" || name == "vendor" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		relDir := filepath.ToSlash(filepath.Dir(rel))
		if outboundCallAllowedDirs[relDir] {
			return nil
		}
		// Tests dial the honeypot they just started; that is the point of them.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || !outboundIdents[ident.Name] {
				return true
			}
			key := ident.Name + "." + sel.Sel.Name
			if reason, bad := outboundCalls[key]; bad {
				violations = append(violations,
					filepath.ToSlash(rel)+" calls "+key+": "+reason)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk node tree: %v", err)
	}

	for _, v := range violations {
		t.Error("containment violation: " + v)
	}
}

// nodeRoot resolves the node module root from this test's location.
func nodeRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// internal/containment -> node
	root := filepath.Dir(filepath.Dir(wd))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("could not locate node module root from %s: %v", wd, err)
	}
	return root
}
