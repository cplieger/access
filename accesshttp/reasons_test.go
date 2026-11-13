package accesshttp

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/failreason"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/webauthn"
)

// designOwnReasons is accesshttp's part of the reason list from §7.2 and
// errata E12, E22, E26 and E33, written from the spec, not from ownReasons.
var designOwnReasons = []string{
	"sso_governed", "ttl_too_long", "ttl_negative", "no_change", "expiry_invalid", "redirect_too_long",
	"current_password_required", "session_gone", "pending_too_large", "stale_authentication",
	"flow_invalid", "discovery_failed", "exchange_failed", "token_invalid", "nonce_mismatch",
	"no_username", "provisioning_disabled", "not_admitted", "username_invalid", "recovery",
	"reenable_needs_other_method", "trailing_data", "malformed_json", "content_type", "body",
	"unknown_field", "token_in_query",
}

// wireReasons is every Reason classify gives for the fixed-reason
// producers: each sentinel row, each typed error built from its owner's
// list, the guard's recovery refusal, account's re-enable refusal and each
// fixed refusal of the body, path and query decoders.
func wireReasons(t *testing.T) []string {
	t.Helper()
	errs := []error{
		(&Handler{}).admit(&Descriptor{Class: ClassRecovery}, access.Principal{}),
		failreason.Wrap(access.ErrRecentAuthRequired, failreason.ReenableNeedsOtherMethod),
		&oidc.UsernameError{},
	}
	errs = append(errs, requestReasonErrors(t)...)
	for _, row := range sentinelCodes {
		errs = append(errs, row.err)
	}
	for _, r := range access.PasswordRejections() {
		errs = append(errs, &access.PasswordError{Reason: r})
	}
	for _, r := range account.PolicyReasons() {
		errs = append(errs, &account.PolicyError{Reason: r})
	}
	for _, r := range account.UsernameReasons() {
		errs = append(errs, &account.UsernameError{Reason: r})
	}
	for _, f := range account.TextErrorFields() {
		for _, r := range account.TextErrorReasons() {
			errs = append(errs, &account.TextError{Field: f, Reason: r})
		}
	}
	for _, r := range account.LogFilterReasons() {
		errs = append(errs, &account.LogFilterError{Reason: r})
	}
	for _, r := range webauthn.OriginRejections() {
		errs = append(errs, &webauthn.OriginError{Reason: r})
	}
	var out []string
	for _, err := range errs {
		e, ok := classify(err, ceremonyNone)
		if !ok {
			t.Fatalf("classify(%v) names no code", err)
		}
		if e.Reason != "" {
			out = append(out, e.Reason)
		}
	}
	return out
}

// requestReasonErrors drives each fixed refusal of decodeJSON, readBody and
// decodeQuery once.
func requestReasonErrors(t *testing.T) []error {
	t.Helper()
	body := func(contentType string, r io.Reader) error {
		req := httptest.NewRequest(http.MethodPost, "/", r)
		req.Header.Set("Content-Type", contentType)
		_, err := decodeJSON[LoginRequest](httptest.NewRecorder(), req)
		return err
	}
	_, inQuery := decodeQuery(specNamed(t, "authRecoveryStart"), httptest.NewRequest(http.MethodPost, "/x?token=t", nil))
	errs := []error{
		body("text/plain", strings.NewReader(`{}`)),
		body("application/json", strings.NewReader(`{"username":`)),
		body("application/json", strings.NewReader(`{"username":"a","password":"p"} {}`)),
		body("application/json", strings.NewReader(`{"username":"a","password":"p","admin":true}`)),
		body("application/json", strings.NewReader(`[1]`)),
		body("application/json", iotest.ErrReader(errors.New("reset"))),
		inQuery,
	}
	for _, err := range errs {
		if _, ok := errors.AsType[*requestError](err); !ok {
			t.Fatalf("decoder refusal %v is not a requestError", err)
		}
	}
	return errs
}

func TestReasonTable(t *testing.T) {
	t.Parallel()
	got := Reasons()
	t.Run("own_part", func(t *testing.T) {
		t.Parallel()
		if !slices.Equal(got[:min(len(got), len(designOwnReasons))], designOwnReasons) {
			t.Errorf("Reasons() starts %v, want %v", got[:min(len(got), len(designOwnReasons))], designOwnReasons)
		}
	})
	t.Run("composition", func(t *testing.T) {
		t.Parallel()
		want := slices.Clone(designOwnReasons)
		for _, r := range access.PasswordRejections() {
			want = append(want, string(r))
		}
		want = append(want, account.PolicyReasons()...)
		want = append(want, account.UsernameReasons()...)
		want = append(want, "label_disallowed_character", "label_too_long", "display_name_disallowed_character", "display_name_too_long")
		want = append(want, "log_limit", "log_range", "log_kind", "log_id")
		for _, r := range webauthn.OriginRejections() {
			want = append(want, string(r))
		}
		var dedup []string
		for _, r := range want {
			if !slices.Contains(dedup, r) {
				dedup = append(dedup, r)
			}
		}
		if !slices.Equal(got, dedup) {
			t.Errorf("Reasons() = %v\nwant %v", got, dedup)
		}
	})
	produced := wireReasons(t)
	t.Run("each_produced_reason_listed", func(t *testing.T) {
		t.Parallel()
		for _, r := range produced {
			if !slices.Contains(got, r) {
				t.Errorf("classify produces Reason %q, which Reasons() lacks", r)
			}
		}
	})
	t.Run("each_listed_reason_produced", func(t *testing.T) {
		t.Parallel()
		for _, r := range got {
			if !slices.Contains(produced, r) {
				t.Errorf("Reasons() lists %q, which no producer gives", r)
			}
		}
	})
}

// TestReasonLiterals parses accesshttp's non-test files. A producer's fixed
// Reason is a Reason constant and a code a Code constant, and every Reason
// constant is in ownReasons, so a reason written at a producer fails
// here instead of going missing from Reasons or Codes; only the open
// families (a refused field, path or query key name, provider_error:<code>)
// are computed at run time.
func TestReasonLiterals(t *testing.T) {
	t.Parallel()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	consts := map[string]bool{}
	literals := map[string]string{} // a Code or Reason constant's value: its name
	var reasonConsts []string
	var owned []string // the identifiers ownReasons lists
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.CONST {
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					isCode := isIdentNamed(vs.Type, "Code")
					for i, n := range vs.Names {
						consts[n.Name] = true
						if strings.HasPrefix(n.Name, "Reason") {
							reasonConsts = append(reasonConsts, n.Name)
						}
						if i >= len(vs.Values) || (!isCode && !strings.HasPrefix(n.Name, "Reason")) {
							continue
						}
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							v, _ := strconv.Unquote(lit.Value)
							literals[v] = n.Name
						}
					}
				}
			}
		}
	}
	if len(literals) < len(Codes()) {
		t.Fatalf("found %d Code and Reason constants, fewer than the %d codes", len(literals), len(Codes()))
	}
	// fixed reports a reason expression that is a literal or a constant
	// other than a Reason constant; "" (no reason) is allowed where allowEmpty.
	fixed := func(e ast.Expr, allowEmpty bool) bool {
		switch v := e.(type) {
		case *ast.BasicLit:
			s, _ := strconv.Unquote(v.Value)
			return !allowEmpty || s != ""
		case *ast.Ident:
			return consts[v.Name] && !strings.HasPrefix(v.Name, "Reason")
		default:
			return false
		}
	}
	for _, f := range files {
		tags := map[*ast.BasicLit]bool{}
		report := func(n ast.Node, format string, args ...any) {
			t.Errorf("%s: "+format, append([]any{fset.Position(n.Pos())}, args...)...)
		}
		var fn string
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.GenDecl:
				return v.Tok != token.CONST && v.Tok != token.IMPORT
			case *ast.FuncDecl:
				fn = v.Name.Name
			case *ast.Field:
				if v.Tag != nil {
					tags[v.Tag] = true
				}
			case *ast.BasicLit:
				s, _ := strconv.Unquote(v.Value)
				if c, ok := literals[s]; ok && v.Kind == token.STRING && !tags[v] {
					report(v, "literal %q: write %s", s, c)
				}
			case *ast.CallExpr:
				switch {
				case isIdentNamed(v.Fun, "badRequest") && fixed(v.Args[0], false),
					isIdentNamed(v.Fun, "newError") && fixed(v.Args[1], true):
					report(v, "a fixed reason that is not a Reason constant")
				case isIdentNamed(v.Fun, "Code") && len(v.Args) == 1:
					if _, lit := v.Args[0].(*ast.BasicLit); lit {
						report(v, "a Code conversion of a literal")
					}
				}
			case *ast.KeyValueExpr:
				if (isIdentNamed(v.Key, "reason") || isIdentNamed(v.Key, "Reason")) && fixed(v.Value, true) {
					report(v, "a fixed reason that is not a Reason constant")
				}
			case *ast.ReturnStmt:
				if fn == "typedCode" && len(v.Results) == 3 && fixed(v.Results[1], true) {
					report(v, "a fixed reason that is not a Reason constant")
				}
			case *ast.ValueSpec:
				if len(v.Names) == 1 && v.Names[0].Name == "ownReasons" {
					for _, e := range v.Values[0].(*ast.CompositeLit).Elts {
						if id, ok := e.(*ast.Ident); ok {
							owned = append(owned, id.Name)
						}
					}
				}
				if len(v.Names) == 1 && v.Names[0].Name == "sentinelCodes" {
					for _, row := range v.Values[0].(*ast.CompositeLit).Elts {
						if elts := row.(*ast.CompositeLit).Elts; len(elts) != 3 || fixed(elts[2], true) {
							report(row, "a sentinel row whose reason is not a Reason constant or empty")
						}
					}
				}
			}
			return true
		})
	}
	if len(owned) == 0 {
		t.Fatal("found no ownReasons list of Reason constants")
	}
	for _, name := range reasonConsts {
		if !slices.Contains(owned, name) {
			t.Errorf("%s is not in ownReasons, so Reasons() omits it", name)
		}
	}
}

func isIdentNamed(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}
