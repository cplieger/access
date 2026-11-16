package accesshttp

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// issueTemporary posts authAdminTemporaryPassword for name with body under
// cookie on origin.
func (e *env) issueTemporary(t *testing.T, origin, name, body string, cookie *http.Cookie) *http.Request {
	t.Helper()
	rt := e.route(t, "authAdminTemporaryPassword")
	return requestAt(origin, strings.Replace(rt.Path, "{id}", e.userID(t, name), 1), rt, body, cookie)
}

// TestRouteAuthAdminTemporaryPassword is design 4.12's
// authAdminTemporaryPassword row and 4.30's and 4.31's answer: the body
// decodes into TemporaryPasswordOptions, and the answer serialises
// IssuedTemporaryPassword with https_only read after the issue.
func TestRouteAuthAdminTemporaryPassword(t *testing.T) {
	const origin = "https://grelot.example"
	withOrigin := envOptions{rules: func(r *account.Rules) { r.HTTPSOrigin = origin }}
	t.Run("usable", func(t *testing.T) {
		e := newEnv(t, withOrigin)
		root := e.rootSession(t)
		before := time.Now()
		w := do(e.route(t, "authAdminTemporaryPassword"), e.issueTemporary(t, testOrigin, "alice", `{"ttl_hours":2}`, root))
		got := decoded[TemporaryPasswordResponse](t, e, w, http.StatusOK)
		// 4.9: shown as XXXX-XXXX-XXXX-XXXX; 2 hours from the issue.
		if len(got.Password) != 19 || strings.Count(got.Password, "-") != 3 {
			t.Errorf("password %q, want XXXX-XXXX-XXXX-XXXX", got.Password)
		}
		if lo, hi := before.Add(2*time.Hour), time.Now().Add(2*time.Hour); got.ExpiresAt.Before(lo.Add(-time.Second)) || got.ExpiresAt.After(hi.Add(time.Second)) {
			t.Errorf("expires_at %v, want 2 hours after the issue", got.ExpiresAt)
		}
		if got.HTTPSOrigin != origin || got.HTTPSOnly || got.Dormant || got.PasswordKept {
			t.Errorf("answer %+v, want https_origin %s and the three flags false", got, origin)
		}
		for _, key := range []string{`"https_only":false`, `"dormant":false`, `"password_kept":false`} {
			if !strings.Contains(w.Body.String(), key) {
				t.Errorf("body %s lacks %s", w.Body.String(), key)
			}
		}
		rec, found, err := e.mem.TemporaryPasswordByUserID(t.Context(), e.user(t, "alice").ID)
		if err != nil || !found || !rec.ExpiresAt.Equal(got.ExpiresAt) || !e.user(t, "alice").PasswordHash.IsZero() {
			t.Errorf("record %+v (%t, %v), alice's password kept %t; want the answer's record and no password", rec, found, err, !e.user(t, "alice").PasswordHash.IsZero())
		}
	})
	t.Run("no_origin", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		root := e.rootSession(t)
		w := do(e.route(t, "authAdminTemporaryPassword"), e.issueTemporary(t, testOrigin, "alice", `{}`, root))
		e.requireStatus(t, w, http.StatusOK)
		if strings.Contains(w.Body.String(), `"https_origin"`) {
			t.Errorf("body %s holds https_origin with no Rules.HTTPSOrigin", w.Body.String())
		}
	})
	// 4.9's six TemporaryPasswordHTTPSOnly cases are account's; the route
	// carries its answer for the posture and rules the app runs.
	t.Run("https_only", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			opts envOptions
			want bool
		}{
			{name: "secure_posture_password_login_off", opts: envOptions{rules: func(r *account.Rules) { r.DisablePasswordLogin = true }}},
			{name: "per_request_rules_off", opts: perRequest},
			{name: "per_request_password_login_off", opts: with(perRequest, envOptions{rules: func(r *account.Rules) { r.DisablePasswordLogin = true }}), want: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := newEnv(t, tc.opts)
				e.createUser(t, "root", access.RoleAdmin)
				e.createUser(t, "alice", access.RoleUser)
				w := do(e.route(t, "authAdminTemporaryPassword"), e.issueTemporary(t, testOrigin, "alice", `{}`, e.transportSession(t, "root", true)))
				if got := decoded[TemporaryPasswordResponse](t, e, w, http.StatusOK); got.HTTPSOnly != tc.want {
					t.Errorf("https_only %t, want %t", got.HTTPSOnly, tc.want)
				}
			})
		}
	})
	// 4.31: dormant and password_kept are what the issuing Update decided
	// (5.3: an unlinked non-owner under SSOOnly).
	t.Run("dormant", func(t *testing.T) {
		e := newEnv(t, perRequest)
		e.createUser(t, "root", access.RoleAdmin)
		e.createUser(t, "alice", access.RoleUser)
		root := e.transportSession(t, "root", true)
		if err := e.mem.SetSSOMode(t.Context(), account.SSOOnly); err != nil {
			t.Fatalf("SetSSOMode: %v", err)
		}
		w := do(e.route(t, "authAdminTemporaryPassword"), e.issueTemporary(t, testOrigin, "alice", `{}`, root))
		got := decoded[TemporaryPasswordResponse](t, e, w, http.StatusOK)
		if !got.Dormant || !got.PasswordKept || !got.HTTPSOnly || e.user(t, "alice").PasswordHash.IsZero() {
			t.Errorf("answer %+v, alice's password kept %t; want dormant, password_kept and https_only, the password kept", got, !e.user(t, "alice").PasswordHash.IsZero())
		}
	})
	// 4.12: the body's three fields reach TemporaryPasswordOptions.
	t.Run("options", func(t *testing.T) {
		e := newEnv(t, passkeys)
		root := e.rootSession(t)
		e.enrol(t, "alice")
		key := e.mintKey(t, "alice", account.NewKey{Label: "ci"})
		w := do(e.route(t, "authAdminTemporaryPassword"), e.issueTemporary(t, testOrigin, "alice", `{"revoke_passkeys":true,"keep_keys":true}`, root))
		e.requireStatus(t, w, http.StatusOK)
		alice := e.user(t, "alice")
		passkeys, err := e.mem.PasskeysByUserID(t.Context(), alice.ID)
		if err != nil || len(passkeys) != 0 {
			t.Errorf("alice's passkeys %d (%v), want revoked", len(passkeys), err)
		}
		if keys, err := e.mem.ListAPIKeysByUserID(t.Context(), alice.ID); err != nil || len(keys) != 1 || keys[0].ID != key.Key.ID {
			t.Errorf("alice's keys %+v (%v), want key %d kept", keys, err, key.Key.ID)
		}
	})
	// 4.9 "Over plain HTTP": issuing answers a new secret, so it is refused.
	t.Run("plain_refused", func(t *testing.T) {
		e := newEnv(t, perRequest)
		e.createUser(t, "root", access.RoleAdmin)
		e.createUser(t, "alice", access.RoleUser)
		w := do(e.route(t, "authAdminTemporaryPassword"), e.issueTemporary(t, plainOrigin, "alice", `{}`, e.transportSession(t, "root", false)))
		e.requireRefused(t, w, access.CodeHTTPSRequired)
		if _, found, err := e.mem.TemporaryPasswordByUserID(t.Context(), e.user(t, "alice").ID); err != nil || found {
			t.Errorf("record stored (%t, %v), want none", found, err)
		}
	})
	// 4.9 "Never for yourself".
	t.Run("self_recovery", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		root := e.rootSession(t)
		got := e.requireRefused(t, do(e.route(t, "authAdminTemporaryPassword"), e.issueTemporary(t, testOrigin, "root", `{}`, root)), access.CodeForbidden)
		if got.Reason != account.ReasonSelfRecovery {
			t.Errorf("reason %q, want %q", got.Reason, account.ReasonSelfRecovery)
		}
	})
	// 5.5: a linked non-owner under SSOForLinked is refused, reason linked.
	t.Run("linked", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		root := e.rootSession(t)
		e.keepDormant(t, "alice")
		got := e.requireRefused(t, do(e.route(t, "authAdminTemporaryPassword"), e.issueTemporary(t, testOrigin, "alice", `{}`, root)), access.CodeSSOOnly)
		if got.Reason != ReasonLinked {
			t.Errorf("reason %q, want %q", got.Reason, ReasonLinked)
		}
	})
}

// TestAdminUsersSecondFactorRows is design 4.12's UserMethodsView gaining
// totp and temporary_password{expires_at}: the admin list reads each from
// the user's records, and a lapsed temporary password lists as none.
func TestAdminUsersSecondFactorRows(t *testing.T) {
	e := newEnv(t, envOptions{})
	root := e.rootSession(t)
	e.createUser(t, "bob", access.RoleUser)
	now := time.Now().UTC().Truncate(time.Second)
	alice, bob := e.user(t, "alice"), e.user(t, "bob")
	if err := e.mem.SetTOTP(t.Context(), access.TOTP{UserID: alice.ID, Sealed: "sealed", CreatedAt: now}); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	live := now.Add(time.Hour)
	for id, exp := range map[int64]time.Time{alice.ID: live, bob.ID: now.Add(-time.Hour)} {
		if err := e.mem.SetTemporaryPassword(t.Context(), access.TemporaryPassword{UserID: id, Hash: access.NewHash("$argon2id$t"), CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: exp}); err != nil {
			t.Fatalf("SetTemporaryPassword: %v", err)
		}
	}
	w := do(e.route(t, "authAdminUsers"), e.post(t, "authAdminUsers", "", root))
	views := decoded[[]UserView](t, e, w, http.StatusOK)
	want := map[string]UserMethodsView{
		"root":  {Password: true},
		"alice": {Password: true, TOTP: true, TemporaryPassword: &TemporaryPasswordView{ExpiresAt: live}},
		"bob":   {Password: true},
	}
	for _, v := range views {
		if w, ok := want[v.Username]; !ok || v.Methods == nil || !reflect.DeepEqual(*v.Methods, w) {
			t.Errorf("%s methods %s, want %+v", v.Username, indexedJSON(t, v.Methods), w)
		}
	}
	if n := strings.Count(w.Body.String(), `"temporary_password"`); n != 1 {
		t.Errorf("body %s holds temporary_password %d times, want only alice's", w.Body.String(), n)
	}
}

// TestLoginTemporaryPasswordExposed is design 4.9's burn on the wire and
// ui-contract-part4 (b)'s fourth step-1 row: a temporary password posted to
// authLoginPassword over plain HTTP where it cannot finish answers 403
// auth_https_required with reason temporary_password_exposed.
func TestLoginTemporaryPasswordExposed(t *testing.T) {
	e := newEnv(t, with(perRequest, requireRule))
	e.createUser(t, "root", access.RoleAdmin)
	e.createUser(t, "alice", access.RoleUser)
	issued, err := e.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), e.user(t, "alice").ID, account.TemporaryPasswordOptions{})
	if err != nil {
		t.Fatalf("SetTemporaryPassword = %v", err)
	}
	rt := e.route(t, "authLoginPassword")
	before := len(e.errs.all())
	w := do(rt, requestAt(plainOrigin, rt.Path, rt, jsonBody(t, LoginRequest{Username: "alice", Password: issued.Password.Reveal()})))
	e.requireStatus(t, w, http.StatusForbidden)
	errs := e.errs.all()[before:]
	if len(errs) != 1 || errs[0].Code != access.CodeHTTPSRequired || errs[0].Reason != ReasonTemporaryPasswordExposed {
		t.Errorf("errors = %+v, want one auth_https_required with reason %s", errs, ReasonTemporaryPasswordExposed)
	}
}
