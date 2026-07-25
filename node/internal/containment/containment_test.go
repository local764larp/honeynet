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

// outboundPackages are permitted only in the transport layer, which talks to
// the collector, and in the SSH/telnet listeners, which accept inbound
// connections. Anywhere else, an outbound-capable import is how a sensor turns
// into a relay or starts fetching attacker-supplied URLs.
var outboundRestricted = map[string]bool{
	"net/http": true,
}

var outboundAllowedDirs = map[string]bool{
	"internal/transport": true,
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
		relDir := filepath.ToSlash(filepath.Dir(rel))

		for _, imp := range file.Imports {
			pkg, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}

			if reason, bad := forbiddenImports[pkg]; bad {
				violations = append(violations,
					filepath.ToSlash(rel)+" imports "+pkg+": "+reason)
			}

			if outboundRestricted[pkg] && !outboundAllowedDirs[relDir] {
				violations = append(violations,
					filepath.ToSlash(rel)+" imports "+pkg+
						": outbound HTTP is restricted to the transport layer (design doc 4.2/4.3)")
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
