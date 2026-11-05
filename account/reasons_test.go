package account_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cplieger/access/account"
)

func TestReasonLists(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		got, want []string
	}{
		{"PolicyReasons", account.PolicyReasons(), []string{
			"out_of_band_only", "key_not_current", "admin_target", "scopes_not_subset", "expiry_after_parent",
			"lineage_too_deep", "permission_not_admin", "self_recovery", "other_user", "target_not_eligible",
			"not_principal", "unknown_operation", "not_enabled_user", "not_admin", "self_delete", "last_admin",
			"last_local_admin", "single_owner", "not_owner", "unknown_via", "via_with_actor",
		}},
		{"UsernameReasons", account.UsernameReasons(), []string{"empty", "disallowed_character", "too_long"}},
		{"TextErrorReasons", account.TextErrorReasons(), []string{"disallowed_character", "too_long"}},
		{"TextErrorFields", account.TextErrorFields(), []string{"label", "display_name"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !slices.Equal(tc.got, tc.want) {
				t.Errorf("%s() = %v, want %v", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestReasonProducers reads the package's own producers: every Reason a
// PolicyError, UsernameError or TextError literal sets, and every Field
// checkLine is given, is a listed constant, and every listed value has a
// producer.
func TestReasonProducers(t *testing.T) {
	t.Parallel()
	p := scanProducers(t)
	for _, tc := range []struct {
		name   string
		used   map[string]bool
		listed []string
	}{
		{"PolicyError.Reason", p.policy, account.PolicyReasons()},
		{"UsernameError.Reason", p.username, account.UsernameReasons()},
		{"TextError.Reason", p.text, account.TextErrorReasons()},
		{"TextError.Field", p.fields, account.TextErrorFields()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := slices.Sorted(maps.Keys(tc.used)); !slices.Equal(got, slices.Sorted(slices.Values(tc.listed))) {
				t.Errorf("produced %v, listed %v", got, tc.listed)
			}
		})
	}
	if len(p.unlisted) > 0 {
		t.Errorf("producers not using a constant: %v", p.unlisted)
	}
}

type producers struct {
	policy, username, text, fields map[string]bool
	unlisted                       []string
}

// scanProducers parses the package's non-test files. A refuse call's
// identifier argument named Reason* counts as a PolicyError Reason, which
// is how SingleOwnerPolicy builds its refusals; that closure's own
// reason parameter is the one non-constant Reason allowed.
func scanProducers(t *testing.T) producers {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var parsed []*ast.File
	consts := map[string]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, f)
		ast.Inspect(f, func(n ast.Node) bool {
			if vs, ok := n.(*ast.ValueSpec); ok && len(vs.Names) == len(vs.Values) {
				for i, id := range vs.Names {
					if lit, isLit := vs.Values[i].(*ast.BasicLit); isLit && lit.Kind == token.STRING {
						consts[id.Name], _ = strconv.Unquote(lit.Value)
					}
				}
			}
			return true
		})
	}
	p := producers{policy: map[string]bool{}, username: map[string]bool{}, text: map[string]bool{}, fields: map[string]bool{}}
	record := func(into map[string]bool, e ast.Expr) {
		if id, ok := e.(*ast.Ident); ok {
			if v, declared := consts[id.Name]; declared {
				into[v] = true
				return
			}
			if id.Name == "reason" {
				return
			}
		}
		p.unlisted = append(p.unlisted, fset.Position(e.Pos()).String())
	}
	for _, f := range parsed {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				typ, ok := n.Type.(*ast.Ident)
				if !ok {
					return true
				}
				into := map[string]map[string]bool{"PolicyError": p.policy, "UsernameError": p.username, "TextError": p.text}[typ.Name]
				for _, el := range n.Elts {
					kv, isKV := el.(*ast.KeyValueExpr)
					if !isKV || into == nil {
						continue
					}
					if key, _ := kv.Key.(*ast.Ident); key != nil && key.Name == "Reason" {
						record(into, kv.Value)
					}
				}
			case *ast.CallExpr:
				fn, ok := n.Fun.(*ast.Ident)
				switch {
				case !ok || len(n.Args) == 0:
				case fn.Name == "checkLine":
					record(p.fields, n.Args[0])
				case fn.Name == "refuse":
					if id, isID := n.Args[0].(*ast.Ident); isID && strings.HasPrefix(id.Name, "Reason") {
						record(p.policy, id)
					}
				}
			}
			return true
		})
	}
	return p
}
