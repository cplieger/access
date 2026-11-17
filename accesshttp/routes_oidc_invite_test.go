package accesshttp

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
)

// TestInviteAcceptOIDC accepts an invite by SSO through the routes: POST
// /start/invite {token}, the provider round trip, the callback.
func TestInviteAcceptOIDC(t *testing.T) {
	t.Parallel()
	t.Run("signs_in_the_invited_account", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		token := e.invite(t)
		b := newBrowser(t)
		cb := authorize(t, idp, e.startInvite(t, b, token))
		// OpenID Connect Core 1.0 §3.1.2.1: the invite asks for a fresh
		// sign-in, so a shared browser's provider session binds no one.
		if q := idp.Authorizations()[0]; q.Get("prompt") != "login" || q.Get("max_age") != "0" || q.Has("token") {
			t.Errorf("authorize request %v, want prompt=login and max_age=0 and no invite in it", q)
		}
		w := e.callback(t, b, cb)
		if loc := location(t, w); loc != "/" {
			t.Errorf("Location %q, want /", loc)
		}
		session := e.authn.Cookie()
		if c := cookieNamed(w, session.CookieName(true)); c == nil || c.Value == "" {
			t.Errorf("cookies %v, want a session cookie", w.Result().Cookies())
		}
		u := e.user(t, accesstest.DefaultIdPUsername)
		if u.OIDC != idpIdentity(testIssuer) || u.Role != access.RoleUser {
			t.Errorf("created %+v, want a RoleUser linked to the IdP's identity", u)
		}
	})
	t.Run("taken_name_offers_a_pick", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		e.createUser(t, accesstest.DefaultIdPUsername, access.RoleUser)
		token := e.invite(t)
		b := newBrowser(t)
		w := e.callback(t, b, authorize(t, idp, e.startInvite(t, b, token)))
		if loc := location(t, w); loc != "/signin?oidc=not_linked" {
			t.Fatalf("Location %q, want not_linked", loc)
		}
		rt := e.route(t, "authOIDCPending")
		w = b.send(rt, get(rt, ""))
		var offer PendingLinkResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &offer) != nil || !offer.CanCreate || offer.SuggestedUsername != accesstest.DefaultIdPUsername+"_2" {
			t.Fatalf("pending %d %s, want 200 can_create with %s_2", w.Code, w.Body.String(), accesstest.DefaultIdPUsername)
		}
		create := e.route(t, "authOIDCCreatePending")
		w = b.send(create, request(create, jsonBody(t, PendingCreateRequest{Username: offer.SuggestedUsername})))
		var in SignedInResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &in) != nil || in.User.Username != offer.SuggestedUsername || !in.User.OIDCLinked {
			t.Fatalf("create %d %s, want 200 SignedInResponse for %s, linked", w.Code, w.Body.String(), offer.SuggestedUsername)
		}
		if got := e.user(t, offer.SuggestedUsername); got.Role != access.RoleUser || got.OIDC != idpIdentity(testIssuer) {
			t.Errorf("created %+v, want the invite's RoleUser linked to the identity", got)
		}
		e.wantInviteSpent(t, token)
	})
	// The create route answers a pending cookie that does not
	// open as not found, before any other check.
	t.Run("create_without_pending", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, envOptions{})
		e.useIdP(t, accesstest.IdPOptions{}, nil)
		rt := e.route(t, "authOIDCCreatePending")
		w := do(rt, request(rt, jsonBody(t, PendingCreateRequest{Username: "x"})))
		if errs := e.errs.all(); w.Code != http.StatusNotFound || len(errs) != 1 || errs[0].Code != access.CodeNotFound {
			t.Errorf("status %d errors %+v, want 404 auth_not_found", w.Code, errs)
		}
	})
}

// wantInviteSpent fails unless the invite token is no longer stored.
func (e *env) wantInviteSpent(t *testing.T, token access.Secret) {
	t.Helper()
	if _, found, err := e.mem.OneTimeTokenByHash(t.Context(), access.NewHash(storedHash(token))); err != nil || found {
		t.Errorf("the invite is still stored (%t, %v) after its acceptance", found, err)
	}
}
