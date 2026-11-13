package accesshttp

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/access/oidc"
)

func decodeOn(t *testing.T, name, rawQuery string) (any, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/x?"+rawQuery, nil)
	v, err := decodeQuery(specNamed(t, name), r)
	if err != nil || !v.IsValid() {
		return nil, err
	}
	return v.Interface(), nil
}

func refusedKey(err error) string {
	if re, ok := errors.AsType[*requestError](err); ok {
		return re.reason
	}
	return ""
}

func TestQueryDecode(t *testing.T) {
	ok := []struct {
		name, route, query string
		want               any
	}{
		{"mediation_conditional", "authLoginPasskeyBegin", "mediation=conditional", PasskeyBeginQuery{Mediation: "conditional"}},
		{"mediation_absent", "authLoginPasskeyBegin", "", PasskeyBeginQuery{}},
		{"unknown_key_ignored", "authLoginPasskeyBegin", "iss=x&mediation=conditional", PasskeyBeginQuery{Mediation: "conditional"}},
		{"keep_both", "authRecoveryPasskeyFinish", "keep_sessions=true&keep_keys=true", RecoveryPasskeyFinishQuery{KeepSessions: true, KeepKeys: true}},
		{"keep_absent", "authRecoveryPasskeyFinish", "", RecoveryPasskeyFinishQuery{}},
		{"key", "authAdminUsers", "key=42", AdminUsersQuery{Key: 42}},
		{"key_absent", "authAdminUsers", "other=1", AdminUsersQuery{}},
		{"signin_redirect", "authOIDCStartSignIn", "redirect=%2Fsettings%3Ftab%3D1", OIDCSignInQuery{Redirect: "/settings?tab=1"}},
		{"signin_repeated", "authOIDCStartSignIn", "redirect=/a&redirect=/b", OIDCSignInQuery{Redirect: "/"}},
		{"signin_refused", "authOIDCStartSignIn", "redirect=%2F%2Fevil.example", OIDCSignInQuery{Redirect: "/"}},
		{"signin_at_the_cap", "authOIDCStartSignIn", "redirect=/" + strings.Repeat("a", oidc.MaxRedirectBytes-1), OIDCSignInQuery{Redirect: "/" + strings.Repeat("a", oidc.MaxRedirectBytes-1)}},
		{"signin_too_long", "authOIDCStartSignIn", "redirect=/" + strings.Repeat("a", 512), OIDCSignInQuery{Redirect: "/"}},
		{"callback_first_values", "authOIDCCallback", "state=s1&state=s2&code=c&iss=https%3A%2F%2Fidp&error=e1&error=e2", OIDCCallbackQuery{State: "s1", Code: "c", Error: "e1"}},
		{"callback_skips_malformed", "authOIDCCallback", "state=%ZZ&state=s2&code=c;x", OIDCCallbackQuery{State: "s2"}},
		{"signin_malformed", "authOIDCStartSignIn", "redirect=%ZZ", OIDCSignInQuery{Redirect: "/"}},
		{"signin_semicolon", "authOIDCStartSignIn", "redirect=/a;b", OIDCSignInQuery{Redirect: "/"}},
		{"malformed_unknown_key_ignored", "authAdminUsers", "other=%ZZ&key=7", AdminUsersQuery{Key: 7}},
		{"escaped_key", "authAdminUsers", "%6Bey=7", AdminUsersQuery{Key: 7}},
		{"empty_pairs_skipped", "authAdminUsers", "&&key=7", AdminUsersQuery{Key: 7}},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeOn(t, tc.route, tc.query)
			if err != nil || got != tc.want {
				t.Errorf("decode %q = %+v, %v; want %+v", tc.query, got, err, tc.want)
			}
		})
	}
	refused := []struct {
		name, route, query, key string
	}{
		{"mediation_other", "authLoginPasskeyBegin", "mediation=x", "mediation"},
		{"mediation_repeated", "authLoginPasskeyBegin", "mediation=conditional&mediation=conditional", "mediation"},
		{"keep_keys_one", "authRecoveryPasskeyFinish", "keep_keys=1", "keep_keys"},
		{"keep_sessions_false", "authRecoveryPasskeyFinish", "keep_sessions=false", "keep_sessions"},
		{"key_zero", "authAdminUsers", "key=0", "key"},
		{"key_negative", "authAdminUsers", "key=-1", "key"},
		{"key_text", "authAdminUsers", "key=x", "key"},
		{"key_leading_zero", "authAdminUsers", "key=01", "key"},
		{"key_plus", "authAdminUsers", "key=%2B1", "key"},
		{"key_overflow", "authAdminUsers", "key=9223372036854775808", "key"},
		{"key_repeated", "authAdminUsers", "key=1&key=2", "key"},
		{"key_malformed_escape", "authAdminUsers", "key=%ZZ", "key"},
		{"key_semicolon_pair", "authAdminUsers", "key=1;key=2", "key"},
		{"key_after_semicolon", "authAdminUsers", "x=1;key=2", "key"},
		{"key_escaped_and_plain", "authAdminUsers", "%6Bey=1&key=2", "key"},
		{"key_escaped_malformed", "authAdminUsers", "%6Bey=%ZZ", "key"},
		{"mediation_malformed_escape", "authLoginPasskeyBegin", "mediation=%ZZ", "mediation"},
		{"keep_keys_malformed_escape", "authRecoveryPasskeyFinish", "keep_keys=%ZZ", "keep_keys"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeOn(t, tc.route, tc.query)
			if refusedKey(err) != tc.key {
				t.Errorf("decode %q = %v, want auth_bad_request naming %q", tc.query, err, tc.key)
			}
		})
	}
}

func TestTokenOnlyInQueryRefused(t *testing.T) {
	for _, name := range []string{"authSetupPassword", "authSetupPasskeyBegin", "authRecoveryStart", "authInviteAcceptPassword"} {
		for _, query := range []string{"token=abc", "token=%ZZ", "%74oken=abc", "x=1;token=abc", "token"} {
			t.Run(name+"_"+query, func(t *testing.T) {
				if _, err := decodeOn(t, name, query); refusedKey(err) != "token_in_query" {
					t.Errorf("query %q = %v, want auth_bad_request token_in_query", query, err)
				}
			})
		}
	}
	t.Run("through_the_route", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		rt := e.route(t, "authRecoveryStart")
		r := request(rt, `{"token":"abc"}`)
		r.URL.RawQuery = "token=abc"
		w := do(rt, r)
		errs := e.errs.all()
		if w.Code != http.StatusBadRequest || len(errs) != 1 || errs[0].Reason != "token_in_query" {
			t.Errorf("status %d errors %+v, want 400 token_in_query", w.Code, errs)
		}
	})
}

// queryReads are the request members that read a query or a form.
var queryReads = map[string]bool{"Form": true, "PostForm": true, "FormValue": true, "PostFormValue": true, "ParseForm": true, "ParseMultipartForm": true, "MultipartForm": true}

func TestAcceptedQueryReadsMatchDescriptors(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "query.go" {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			onURL := false
			if inner, isSel := sel.X.(*ast.SelectorExpr); isSel && inner.Sel.Name == "URL" {
				onURL = true
			}
			if queryReads[sel.Sel.Name] || (onURL && (sel.Sel.Name == "Query" || sel.Sel.Name == "RawQuery")) {
				t.Errorf("%s: %s reads the query outside query.go", fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}
