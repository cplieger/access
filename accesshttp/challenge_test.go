package accesshttp

import (
	"net/http"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// TestAuthTreeChallenge: every 401 the auth tree answers carries the
// RFC 6750 §3 challenge RFC 9110 §15.5.2 requires, with §3.1's error code
// only on a refused key or a missing scope, and no 403 but the scope
// refusal carries one.
func TestAuthTreeChallenge(t *testing.T) {
	const bare = `Bearer realm="access"`
	challenge := func(t *testing.T, rt Route, r *http.Request, status int, want string) {
		t.Helper()
		w := do(rt, r)
		if w.Code != status {
			t.Fatalf("status %d, want %d", w.Code, status)
		}
		got := w.Result().Header.Values("WWW-Authenticate")
		switch {
		case want == "" && len(got) != 0:
			t.Errorf("WWW-Authenticate %q, want none", got)
		case want != "" && (len(got) != 1 || got[0] != want):
			t.Errorf("WWW-Authenticate %q, want [%q]", got, want)
		}
	}
	t.Run("signed_out", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		rt := e.route(t, "authMe")
		challenge(t, rt, request(rt, ""), http.StatusUnauthorized, bare)
	})
	t.Run("session_gone", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		rt := e.route(t, "authMe")
		token, _ := access.GenerateSessionToken()
		challenge(t, rt, request(rt, "", e.cookie(token)), http.StatusUnauthorized, bare)
	})
	t.Run("session_expired", func(t *testing.T) {
		e := newEnv(t, envOptions{authn: func(_ *env, c *access.Config) { c.AbsTimeout = time.Nanosecond }})
		e.createUser(t, "alice", access.RoleUser)
		rt := e.route(t, "authMe")
		challenge(t, rt, request(rt, "", e.sessionCookie(t, "alice")), http.StatusUnauthorized, bare)
	})
	t.Run("key_refused", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		rt := e.route(t, "authMe")
		unknown, err := access.GenerateAPIKey("")
		if err != nil {
			t.Fatalf("GenerateAPIKey: %v", err)
		}
		challenge(t, rt, bearer(request(rt, ""), unknown.Plaintext), http.StatusUnauthorized, `Bearer realm="access", error="invalid_token"`)
	})
	t.Run("password_refused", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		rt := e.route(t, "authLoginPassword")
		body := jsonBody(t, LoginRequest{Username: "alice", Password: testPassword + "-wrong"})
		challenge(t, rt, request(rt, body), http.StatusUnauthorized, bare)
	})
	t.Run("scope_missing", func(t *testing.T) {
		e := newEnv(t, allScopes)
		e.createUser(t, "root", access.RoleAdmin)
		key := e.mintKey(t, "root", account.NewKey{Label: "reader", Scopes: []string{"read"}})
		rt := e.route(t, "authAdminKeys")
		challenge(t, rt, bearer(request(rt, ""), key.Plaintext), http.StatusForbidden,
			`Bearer realm="access", error="insufficient_scope", scope="`+scopeAdminName+`"`)
	})
	t.Run("session_required_has_none", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		key := e.mintKey(t, "alice", account.NewKey{Label: "k"})
		rt := e.route(t, "authMe")
		challenge(t, rt, bearer(request(rt, ""), key.Plaintext), http.StatusForbidden, "")
	})
	t.Run("cross_origin_has_none", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		rt := e.route(t, "authLogout")
		r := request(rt, "", e.sessionCookie(t, "alice"))
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		challenge(t, rt, r, http.StatusForbidden, "")
	})
	t.Run("realm_from_config", func(t *testing.T) {
		e := newEnv(t, envOptions{authn: func(_ *env, c *access.Config) { c.Realm = "marotte" }})
		rt := e.route(t, "authMe")
		challenge(t, rt, request(rt, ""), http.StatusUnauthorized, `Bearer realm="marotte"`)
	})
}
