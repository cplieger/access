package accesshttp

import (
	"net/http"
	"strings"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// adminLinkPending is the default IdP identity waiting in a pending cookie,
// linked to no account.
var adminLinkPending = pendingPayload{Issuer: testIssuer, Subject: accesstest.DefaultIdPSubject, UsernameHint: "alice"}

// issueForAdminLink stores the owner root and RoleUser alice under SSOOnly,
// with the IdP on when idp, and returns the temporary password an admin
// issued alice out of band.
func (e *env) issueForAdminLink(t testing.TB, idp bool) access.Secret {
	t.Helper()
	if idp {
		e.useIdP(t, accesstest.IdPOptions{}, nil)
	}
	e.createUser(t, "root", access.RoleAdmin)
	e.createUser(t, "alice", access.RoleUser)
	if err := e.mem.SetSSOMode(t.Context(), account.SSOOnly); err != nil {
		t.Fatalf("SetSSOMode: %v", err)
	}
	issued, err := e.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), e.user(t, "alice").ID, account.TemporaryPasswordOptions{})
	if err != nil {
		t.Fatalf("SetTemporaryPassword: %v", err)
	}
	return issued.Password
}

// adminLink is authOIDCLinkByAdmin's post naming name with secret, holding
// adminLinkPending's cookie when pending.
func (e *env) adminLink(t testing.TB, name, secret string, pending bool) *http.Request {
	t.Helper()
	rt := e.route(t, "authOIDCLinkByAdmin")
	r := request(rt, jsonBody(t, PendingLinkByAdminRequest{Username: name, TemporaryPassword: secret}))
	if pending {
		r.AddCookie(e.pendingCookie(t, adminLinkPending))
	}
	return r
}

// TestRouteAuthOIDCLinkByAdmin checks the admin-consent link on the wire,
// a missing pending cookie answering 404 before any hash, and the screens'
// pending-link rows.
func TestRouteAuthOIDCLinkByAdmin(t *testing.T) {
	// The session it answers is by OIDC, the identity is linked and the
	// record spent; the answer is SignedInResponse.
	t.Run("links", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		secret := e.issueForAdminLink(t, true)
		w := do(e.route(t, "authOIDCLinkByAdmin"), e.adminLink(t, "Alice", secret.Reveal(), true))
		got := decoded[SignedInResponse](t, e, w, http.StatusOK)
		alice := e.user(t, "alice")
		if got.User.Username != "alice" || !got.User.OIDCLinked || alice.OIDC != idpIdentity(testIssuer) {
			t.Errorf("answer user %+v, stored link %+v; want alice linked to the pending identity", got.User, alice.OIDC)
		}
		session := e.authn.Cookie()
		if sc := cookieNamed(w, session.CookieName(true)); sc == nil || sc.Value == "" {
			t.Errorf("session cookie %v, want one set", sc)
		}
		if pc := cookieNamed(w, e.pendingCookieName()); pc == nil || pc.MaxAge >= 0 {
			t.Errorf("pending cookie %v, want cleared", pc)
		}
		sessions, err := e.mem.SessionsByUserID(t.Context(), alice.ID)
		if err != nil || len(sessions) != 1 || sessions[0].AuthMethod != access.MethodOIDC {
			t.Errorf("alice's sessions %+v (%v), want one by %s", sessions, err, access.MethodOIDC)
		}
		if _, found, err := e.mem.TemporaryPasswordByUserID(t.Context(), alice.ID); err != nil || found {
			t.Errorf("record left (%t, %v), want it spent", found, err)
		}
	})
	// One ErrInvalidCredentials for a wrong secret; the pending state
	// is kept for another try.
	t.Run("wrong_secret", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.issueForAdminLink(t, true)
		w := do(e.route(t, "authOIDCLinkByAdmin"), e.adminLink(t, "alice", "AAAA-AAAA-AAAA-AAAA", true))
		e.requireRefused(t, w, access.CodeInvalidCredentials)
		if cookieNamed(w, e.pendingCookieName()) != nil {
			t.Errorf("cookies %v, want the pending cookie left as it was", w.Result().Cookies())
		}
		if got := e.user(t, "alice").OIDC; got != (access.OIDCIdentity{}) {
			t.Errorf("alice linked to %+v, want no link", got)
		}
	})
	// A mode that is no longer SSOOnly answers
	// auth_invalid_credentials.
	t.Run("mode_no_longer_only", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		secret := e.issueForAdminLink(t, true)
		if err := e.mem.SetSSOMode(t.Context(), account.SSOForLinked); err != nil {
			t.Fatalf("SetSSOMode: %v", err)
		}
		e.requireRefused(t, do(e.route(t, "authOIDCLinkByAdmin"), e.adminLink(t, "alice", secret.Reveal(), true)), access.CodeInvalidCredentials)
	})
	// No pending cookie answers 404 auth_not_found with no hash.
	// The hash budget is held, so a hash would answer auth_busy.
	t.Run("no_pending_state", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		secret := e.issueForAdminLink(t, true)
		e.holdBudget(t)
		e.requireRefused(t, do(e.route(t, "authOIDCLinkByAdmin"), e.adminLink(t, "alice", secret.Reveal(), false)), access.CodeNotFound)
	})
	// The IP request window is charged before the pending
	// cookie is read.
	t.Run("limiter_before_pending_cookie", func(t *testing.T) {
		e := newEnv(t, limited)
		secret := e.issueForAdminLink(t, true)
		e.spendRequest(t)
		e.requireRefused(t, do(e.route(t, "authOIDCLinkByAdmin"), e.adminLink(t, "alice", secret.Reveal(), false)), access.CodeRateLimited)
	})
	// The temporary password is a required secret, as authLoginPassword's
	// password is.
	t.Run("empty_secret", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.issueForAdminLink(t, true)
		got := e.requireRefused(t, do(e.route(t, "authOIDCLinkByAdmin"), e.adminLink(t, "alice", "", true)), access.CodeBadRequest)
		if got.Reason != "temporary_password" {
			t.Errorf("reason %q, want temporary_password", got.Reason)
		}
	})
}

// relink posts authAdminOIDCRelink for name with body under cookie on
// origin.
func (e *env) relink(t *testing.T, origin, name, body string, cookie *http.Cookie) *http.Request {
	t.Helper()
	rt := e.route(t, "authAdminOIDCRelink")
	return requestAt(origin, strings.Replace(rt.Path, "{id}", e.userID(t, name), 1), rt, body, cookie)
}

// TestRouteAuthAdminOIDCRelink checks authAdminOIDCRelink: the body decodes
// into TemporaryPasswordOptions
// as authAdminTemporaryPassword's does, and the answer is its
// TemporaryPasswordResponse.
func TestRouteAuthAdminOIDCRelink(t *testing.T) {
	t.Run("relinks", func(t *testing.T) {
		e := newEnv(t, passkeys)
		root := e.rootSession(t)
		e.enrol(t, "alice")
		e.mintKey(t, "alice", account.NewKey{Label: "ci"})
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		w := do(e.route(t, "authAdminOIDCRelink"), e.relink(t, testOrigin, "alice", `{"ttl_hours":2}`, root))
		got := decoded[TemporaryPasswordResponse](t, e, w, http.StatusOK)
		if len(got.Password) != 19 || strings.Count(got.Password, "-") != 3 || got.Dormant {
			t.Errorf("answer %+v, want a usable XXXX-XXXX-XXXX-XXXX", got)
		}
		alice := e.user(t, "alice")
		if alice.OIDC != (access.OIDCIdentity{}) {
			t.Errorf("alice linked to %+v, want unlinked", alice.OIDC)
		}
		rec, found, err := e.mem.TemporaryPasswordByUserID(t.Context(), alice.ID)
		if err != nil || !found || !rec.ExpiresAt.Equal(got.ExpiresAt) {
			t.Errorf("record %+v (%t, %v), want the answer's", rec, found, err)
		}
		// With neither option the keys go and the passkeys stay.
		if pk, err := e.mem.PasskeysByUserID(t.Context(), alice.ID); err != nil || len(pk) != 1 {
			t.Errorf("alice's passkeys %d (%v), want kept", len(pk), err)
		}
		if keys, err := e.mem.ListAPIKeysByUserID(t.Context(), alice.ID); err != nil || len(keys) != 0 {
			t.Errorf("alice's keys %d (%v), want revoked", len(keys), err)
		}
	})
	// revoke_passkeys and keep_keys reach the issue.
	t.Run("options", func(t *testing.T) {
		e := newEnv(t, passkeys)
		root := e.rootSession(t)
		e.enrol(t, "alice")
		key := e.mintKey(t, "alice", account.NewKey{Label: "ci"})
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		e.requireStatus(t, do(e.route(t, "authAdminOIDCRelink"), e.relink(t, testOrigin, "alice", `{"revoke_passkeys":true,"keep_keys":true}`, root)), http.StatusOK)
		alice := e.user(t, "alice")
		if pk, err := e.mem.PasskeysByUserID(t.Context(), alice.ID); err != nil || len(pk) != 0 {
			t.Errorf("alice's passkeys %d (%v), want revoked", len(pk), err)
		}
		if keys, err := e.mem.ListAPIKeysByUserID(t.Context(), alice.ID); err != nil || len(keys) != 1 || keys[0].ID != key.Key.ID {
			t.Errorf("alice's keys %+v (%v), want key %d kept", keys, err, key.Key.ID)
		}
	})
	// Under SSOOnly the relink keeps the dormant password (the
	// dormant and password_kept).
	t.Run("dormant", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		root := e.rootSession(t)
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		if err := e.mem.SetSSOMode(t.Context(), account.SSOOnly); err != nil {
			t.Fatalf("SetSSOMode: %v", err)
		}
		got := decoded[TemporaryPasswordResponse](t, e, do(e.route(t, "authAdminOIDCRelink"), e.relink(t, testOrigin, "alice", `{}`, root)), http.StatusOK)
		if !got.Dormant || !got.PasswordKept || e.user(t, "alice").PasswordHash.IsZero() {
			t.Errorf("answer %+v, want dormant and password_kept with the password kept", got)
		}
	})
	// An account that is not linked is ErrNotFound with nothing written.
	t.Run("unlinked", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		root := e.rootSession(t)
		e.requireRefused(t, do(e.route(t, "authAdminOIDCRelink"), e.relink(t, testOrigin, "alice", `{}`, root)), access.CodeNotFound)
		if _, found, err := e.mem.TemporaryPasswordByUserID(t.Context(), e.user(t, "alice").ID); err != nil || found {
			t.Errorf("record stored (%t, %v), want none", found, err)
		}
	})
	// Refused over plain HTTP, since it answers a new secret; the link
	// stays.
	t.Run("plain_refused", func(t *testing.T) {
		e := newEnv(t, perRequest)
		e.createUser(t, "root", access.RoleAdmin)
		e.createUser(t, "alice", access.RoleUser)
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		e.requireRefused(t, do(e.route(t, "authAdminOIDCRelink"), e.relink(t, plainOrigin, "alice", `{}`, e.transportSession(t, "root", false))), access.CodeHTTPSRequired)
		if got := e.user(t, "alice").OIDC; got != idpIdentity(testIssuer) {
			t.Errorf("alice linked to %+v, want the link kept", got)
		}
	})
}
