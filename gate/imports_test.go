package gate_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestImports: the gate imports only access, access/internal and the
// standard library, so an app that only guards its API links no passkey or
// single sign-on code.
func TestImports(t *testing.T) {
	t.Parallel()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := 0
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			seen++
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			stdlib := !strings.Contains(strings.Split(path, "/")[0], ".")
			if !stdlib && path != "github.com/cplieger/access" && !strings.HasPrefix(path, "github.com/cplieger/access/internal/") {
				t.Errorf("%s imports %s", name, path)
			}
		}
	}
	if seen == 0 {
		t.Fatal("found no imports in the gate's files")
	}
}
