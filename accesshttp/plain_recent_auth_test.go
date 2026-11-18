package accesshttp

import (
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/cplieger/access"
)

// staleSession stores a full password session of name on the transport
// secure names, signed in two hours ago and active now, and returns its
// cookie under that transport's name.
func (e *env) staleSession(t *testing.T, name string, secure bool) *http.Cookie {
	t.Helper()
	token, hash := access.GenerateSessionToken()
	now := time.Now()
	s := &access.Session{
		ID: hex.EncodeToString(randomBytes(16)), UserID: e.user(t, name).ID, TokenHash: hash, AuthMethod: access.MethodPassword,
		CreatedAt: now.Add(-2 * time.Hour), LastActivity: now, AuthTime: now.Add(-2 * time.Hour), Secure: secure,
	}
	if err := e.mem.CreateSession(t.Context(), s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	cfg := e.authn.Cookie()
	return &http.Cookie{Name: cfg.CookieName(secure), Value: token.Reveal()}
}

// TestPlainRecentAuth pins recent auth over plain HTTP on the routes: a
// stale plain session is refused with reason sign_in_again, a plain
// password sign-in presenting it replaces it, and the logout ends the
// session the request presented.
func TestPlainRecentAuth(t *testing.T) {
	set := func(t *testing.T, e *env, origin string, cookie *http.Cookie) (int, []access.Error) {
		t.Helper()
		rt := e.route(t, "authPasswordSet")
		before := len(e.errs.all())
		w := do(rt, requestAt(origin, rt.Path, rt, passwordSetBody(t, testPassword, testPassword+"-new"), cookie))
		return w.Code, e.errs.all()[before:]
	}
	gone := func(t *testing.T, e *env, cookie *http.Cookie) bool {
		t.Helper()
		_, found, err := e.mem.SessionByHash(t.Context(), access.SessionHash(cookie.Value))
		if err != nil {
			t.Fatalf("SessionByHash: %v", err)
		}
		return !found
	}
	t.Run("sign_in_again", func(t *testing.T) {
		e := newEnv(t, perRequest)
		e.createUser(t, "alice", access.RoleUser)
		code, errs := set(t, e, plainOrigin, e.staleSession(t, "alice", false))
		if code != http.StatusForbidden || len(errs) != 1 || errs[0].Code != access.CodeRecentAuthRequired || errs[0].Reason != access.ReasonSignInAgain {
			t.Errorf("stale plain authPasswordSet: status %d, errors %+v; want 403 auth_recent_auth_required sign_in_again", code, errs)
		}
	})
	t.Run("secure_no_reason", func(t *testing.T) {
		e := newEnv(t, perRequest)
		e.createUser(t, "alice", access.RoleUser)
		code, errs := set(t, e, testOrigin, e.staleSession(t, "alice", true))
		if code != http.StatusForbidden || len(errs) != 1 || errs[0].Code != access.CodeRecentAuthRequired || errs[0].Reason != "" {
			t.Errorf("stale secure authPasswordSet: status %d, errors %+v; want 403 auth_recent_auth_required with no reason", code, errs)
		}
	})
	t.Run("sign_in_replaces_presented", func(t *testing.T) {
		e := newEnv(t, perRequest)
		e.createUser(t, "alice", access.RoleUser)
		stale := e.staleSession(t, "alice", false)
		rt := e.route(t, "authLoginPassword")
		w := do(rt, requestAt(plainOrigin, rt.Path, rt, jsonBody(t, LoginRequest{Username: "alice", Password: testPassword}), stale))
		if w.Code != http.StatusOK {
			t.Fatalf("plain sign-in presenting the stale session: status %d, errors %+v; want 200", w.Code, e.errs.all())
		}
		if !gone(t, e, stale) {
			t.Error("the presented session survived the fresh sign-in, want it replaced")
		}
		fresh := setCookies(t, w)[stale.Name]
		if fresh == nil {
			t.Fatalf("the sign-in set no %s cookie", stale.Name)
		}
		if code, errs := set(t, e, plainOrigin, &http.Cookie{Name: fresh.Name, Value: fresh.Value}); code != http.StatusNoContent && code != http.StatusOK {
			t.Errorf("authPasswordSet after the fresh sign-in: status %d, errors %+v; want it admitted", code, errs)
		}
	})
	t.Run("logout_ends_presented", func(t *testing.T) {
		e := newEnv(t, perRequest)
		e.createUser(t, "alice", access.RoleUser)
		cookie := e.transportSession(t, "alice", false)
		rt := e.route(t, "authLogout")
		if w := do(rt, requestAt(plainOrigin, rt.Path, rt, "", cookie)); w.Code != http.StatusNoContent {
			t.Fatalf("plain logout: status %d, errors %+v; want 204", w.Code, e.errs.all())
		}
		if !gone(t, e, cookie) {
			t.Error("the presented session survived the logout, want it ended")
		}
	})
}
