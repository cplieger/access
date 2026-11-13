package accesshttp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
)

func TestRouteAuthState(t *testing.T) {
	read := func(t *testing.T, e *env) StateResponse {
		t.Helper()
		w := do(e.route(t, "authState"), e.post(t, "authState", ""))
		var got StateResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
			t.Fatalf("status %d body %q, want 200 StateResponse", w.Code, w.Body.String())
		}
		return got
	}
	t.Run("defaults", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		if got := read(t, e); got != (StateResponse{SetupRequired: true, PasswordLogin: true}) {
			t.Errorf("state %+v, want setup required and password sign-in only", got)
		}
		e.createUser(t, "alice", access.RoleAdmin)
		if got := read(t, e); got.SetupRequired {
			t.Errorf("state %+v after the first user, want setup_required false", got)
		}
	})
	t.Run("configured", func(t *testing.T) {
		e := newEnv(t, with(passkeys, envOptions{rules: func(r *account.Rules) { r.DisablePasswordLogin = true }}))
		if got := read(t, e); got != (StateResponse{SetupRequired: true, Passkeys: true}) {
			t.Errorf("state %+v, want passkeys on and password sign-in off", got)
		}
	})
	t.Run("oidc_provider", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.useIdP(t, accesstest.IdPOptions{}, nil)
		if got := read(t, e); got != (StateResponse{SetupRequired: true, PasswordLogin: true, OIDC: true}) {
			t.Errorf("state %+v, want OIDC sign-in on", got)
		}
	})
}

func TestRouteAuthSetupPassword(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.requireSignedIn(t, do(e.route(t, "authSetupPassword"), e.post(t, "authSetupPassword", setupPasswordBody(t, ""))), "owner")
		if u := e.user(t, "owner"); u.Role != access.RoleAdmin {
			t.Errorf("role %s, want admin", u.Role)
		}
	})
	t.Run("with_token", func(t *testing.T) {
		e := newEnv(t, tokenRequired)
		e.requireSignedIn(t, do(e.route(t, "authSetupPassword"), e.post(t, "authSetupPassword", setupPasswordBody(t, e.setupToken(t)))), "owner")
	})
}

func TestRouteAuthSetupPasskeyBegin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		id, options := e.begin(t, "authSetupPasskeyBegin", "", setupPasskeyBody(t, ""))
		var opts struct {
			PublicKey struct {
				RP struct{ ID string } `json:"rp"`
			} `json:"publicKey"`
		}
		if id == "" || json.Unmarshal(options, &opts) != nil || opts.PublicKey.RP.ID != testRPID {
			t.Errorf("ceremony %q options %s, want an ID and creation options for %s", id, options, testRPID)
		}
	})
}

func TestRouteAuthSetupPasskeyFinish(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		session := e.requireSignedIn(t, do(e.route(t, "authSetupPasskeyFinish"), e.setupFinish(t, "", nil, nil)), "owner")
		if p := e.principal(t, session); p.User.Role != access.RoleAdmin || p.Method != access.MethodPasskey {
			t.Errorf("principal %+v, want an admin signed in by passkey", p)
		}
	})
}

func TestRouteAuthLoginPassword(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		e.requireSignedIn(t, do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", signInBody(t, "alice"))), "alice")
	})
}

func TestRouteAuthLoginPasskeyBegin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		for query, mediation := range map[string]string{"": "", "mediation=conditional": "conditional"} {
			id, options := e.begin(t, "authLoginPasskeyBegin", query, "")
			var opts struct {
				Mediation string `json:"mediation"`
				PublicKey struct {
					RPID string `json:"rpId"`
				} `json:"publicKey"`
			}
			if id == "" || json.Unmarshal(options, &opts) != nil || opts.PublicKey.RPID != testRPID || opts.Mediation != mediation {
				t.Errorf("query %q: ceremony %q options %s, want request options for %s with mediation %q", query, id, options, testRPID, mediation)
			}
		}
	})
}

func TestRouteAuthLoginPasskeyFinish(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, passkeys)
		session := e.requireSignedIn(t, do(e.route(t, "authLoginPasskeyFinish"), e.loginFinish(t, nil)), "alice")
		if p := e.principal(t, session); p.Method != access.MethodPasskey {
			t.Errorf("principal method %s, want passkey", p.Method)
		}
	})
	t.Run("clone_warning", func(t *testing.T) {
		e := newEnv(t, passkeys)
		rt := e.route(t, "authLoginPasskeyFinish")
		var dev *accesstest.PasskeyDevice
		e.requireSignedIn(t, do(rt, e.loginFinish(t, func(d *accesstest.PasskeyDevice) { dev = d })), "alice")
		dev.SignCount = 0
		id, options := e.begin(t, "authLoginPasskeyBegin", "", "")
		w := do(rt, finish(rt, id, dev.Assert(options)))
		var resp SignedInResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &resp) != nil || !resp.CloneWarning {
			t.Errorf("status %d body %q, want 200 with clone_warning for a regressed sign count", w.Code, w.Body.String())
		}
	})
}

func TestRouteAuthLogout(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		session := e.sessionCookie(t, "alice")
		w := do(e.route(t, "authLogout"), e.post(t, "authLogout", "", session))
		if w.Code != http.StatusNoContent {
			t.Fatalf("status %d, want 204", w.Code)
		}
		e.requireCleared(t, w)
		if _, found, err := e.mem.SessionByHash(t.Context(), access.SessionHash(session.Value)); err != nil || found {
			t.Errorf("session still stored (%v, %v)", found, err)
		}
	})
	t.Run("no_cookie", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		w := do(e.route(t, "authLogout"), e.post(t, "authLogout", ""))
		if w.Code != http.StatusNoContent {
			t.Fatalf("status %d, want 204", w.Code)
		}
		e.requireCleared(t, w)
	})
	t.Run("refused_keeps_cookie", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		r := e.post(t, "authLogout", "", e.sessionCookie(t, "alice"))
		e.shutdown(t)
		if w := do(e.route(t, "authLogout"), r); w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 {
			t.Errorf("status %d cookies %v, want 503 and no Set-Cookie", w.Code, w.Result().Cookies())
		}
	})
}

func TestRouteAuthInviteAcceptPassword(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.requireSignedIn(t, do(e.route(t, "authInviteAcceptPassword"), e.post(t, "authInviteAcceptPassword", inviteBody(t, e.invite(t), "invitee", testPassword))), "invitee")
		if u := e.user(t, "invitee"); u.Role != access.RoleUser {
			t.Errorf("role %s, want the invite's user", u.Role)
		}
	})
	t.Run("single_owner", func(t *testing.T) {
		e := newEnv(t, envOptions{edit: func(c *account.Config) { c.Policy = account.SingleOwnerPolicy{} }})
		token, hash := access.GenerateOpaqueToken()
		if err := e.mem.CreateOneTimeToken(t.Context(), access.OneTimeToken{Hash: hash, Purpose: access.PurposeInvite, Role: access.RoleUser, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatalf("CreateOneTimeToken: %v", err)
		}
		w := do(e.route(t, "authInviteAcceptPassword"), e.post(t, "authInviteAcceptPassword", inviteBody(t, token, "invitee", testPassword)))
		if errs := e.errs.all(); w.Code != http.StatusForbidden || len(errs) != 1 || errs[0].Code != access.CodeForbidden {
			t.Errorf("status %d errors %+v, want 403 auth_forbidden", w.Code, errs)
		}
	})
}

// finishCounting counts the WebAuthn finish calls that reach account.
type finishCounting struct {
	accountAPI
	calls atomic.Int32
}

func (f *finishCounting) SetupPasskeyFinish(ctx context.Context, c account.Client, id string, body io.Reader) (account.SignedIn, error) {
	f.calls.Add(1)
	return f.accountAPI.SetupPasskeyFinish(ctx, c, id, body)
}

func (f *finishCounting) PasskeyLoginFinish(ctx context.Context, c account.Client, id string, body io.Reader) (account.SignedIn, error) {
	f.calls.Add(1)
	return f.accountAPI.PasskeyLoginFinish(ctx, c, id, body)
}

func (f *finishCounting) RecoverPasskeyFinish(ctx context.Context, p access.Principal, id string, body io.Reader, opts account.RecoverOptions) error {
	f.calls.Add(1)
	return f.accountAPI.RecoverPasskeyFinish(ctx, p, id, body, opts)
}

func TestFinishBodyTooLarge(t *testing.T) {
	counting := &finishCounting{}
	e := newEnv(t, with(passkeys, envOptions{wrap: func(_ *env, s *account.Service) accountAPI { counting.accountAPI = s; return counting }}))
	e.createUser(t, "alice", access.RoleUser)
	recovery := e.recoveryCookie(t, "alice")
	tooLarge := []byte(longBody(webauthn.MaxResponseBytes + 1))
	for _, name := range []string{"authSetupPasskeyFinish", "authLoginPasskeyFinish", "authRecoveryPasskeyFinish"} {
		t.Run(name, func(t *testing.T) {
			before, calls := len(e.errs.all()), counting.calls.Load()
			w := do(e.route(t, name), finish(e.route(t, name), "any", tooLarge, recovery))
			errs := e.errs.all()[before:]
			if w.Code != http.StatusRequestEntityTooLarge || len(errs) != 1 || errs[0].Code != access.CodeBodyTooLarge {
				t.Errorf("status %d errors %+v, want 413 auth_body_too_large", w.Code, errs)
			}
			if n := counting.calls.Load() - calls; n != 0 {
				t.Errorf("%d account calls, want none", n)
			}
		})
	}
	t.Run("ceremony_kept", func(t *testing.T) {
		dev := e.enrol(t, "alice")
		id, options := e.begin(t, "authLoginPasskeyBegin", "", "")
		rt := e.route(t, "authLoginPasskeyFinish")
		if w := do(rt, finish(rt, id, tooLarge)); w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("overlong finish: status %d, want 413", w.Code)
		}
		e.requireSignedIn(t, do(rt, finish(rt, id, dev.Assert(options))), "alice")
	})
	t.Run("at_cap_reaches_account", func(t *testing.T) {
		calls := counting.calls.Load()
		rt := e.route(t, "authLoginPasskeyFinish")
		do(rt, finish(rt, "any", []byte(longBody(webauthn.MaxResponseBytes))))
		if n := counting.calls.Load() - calls; n != 1 {
			t.Errorf("%d account calls for a body at the cap, want one", n)
		}
	})
}

// tokenCounting counts the token-route calls that reach account.
type tokenCounting struct {
	accountAPI
	calls atomic.Int32
}

func (c *tokenCounting) SetupWithPassword(ctx context.Context, cl account.Client, in account.SetupPassword) (account.SignedIn, error) {
	c.calls.Add(1)
	return c.accountAPI.SetupWithPassword(ctx, cl, in)
}

func (c *tokenCounting) SetupPasskeyBegin(ctx context.Context, cl account.Client, in account.SetupPasskey) (account.PendingCeremony, error) {
	c.calls.Add(1)
	return c.accountAPI.SetupPasskeyBegin(ctx, cl, in)
}

func (c *tokenCounting) StartRecovery(ctx context.Context, cl account.Client, token access.Secret) (account.Recovery, error) {
	c.calls.Add(1)
	return c.accountAPI.StartRecovery(ctx, cl, token)
}

func (c *tokenCounting) AcceptInvitePassword(ctx context.Context, cl account.Client, in account.AcceptInvite) (account.SignedIn, error) {
	c.calls.Add(1)
	return c.accountAPI.AcceptInvitePassword(ctx, cl, in)
}

func TestTokenOnlyInBody(t *testing.T) {
	counting := &tokenCounting{}
	e := newEnv(t, with(passkeys, tokenRequired, envOptions{wrap: func(_ *env, s *account.Service) accountAPI { counting.accountAPI = s; return counting }}))
	setupToken := e.setupToken(t)
	inviteToken := e.invite(t)
	e.createUser(t, "alice", access.RoleUser)
	recovery, err := e.svc.IssueRecovery(t.Context(), account.OutOfBand("test"), e.user(t, "alice").ID, 0)
	if err != nil {
		t.Fatalf("IssueRecovery: %v", err)
	}
	bodies := map[string]string{
		"authSetupPassword":        setupPasswordBody(t, setupToken),
		"authSetupPasskeyBegin":    setupPasskeyBody(t, setupToken),
		"authRecoveryStart":        jsonBody(t, TokenRequest{Token: recovery.Plaintext.Reveal()}),
		"authInviteAcceptPassword": inviteBody(t, inviteToken, "invitee", testPassword),
	}
	for _, rt := range e.h.Routes() {
		if !specNamed(t, rt.Name).tokenBody {
			continue
		}
		t.Run(rt.Name, func(t *testing.T) {
			body, ok := bodies[rt.Name]
			if !ok {
				t.Fatalf("no body for token route %s", rt.Name)
			}
			r := request(rt, body)
			r.URL.RawQuery = "token=" + setupToken
			before, calls := len(e.errs.all()), counting.calls.Load()
			w := do(rt, r)
			errs := e.errs.all()[before:]
			if w.Code != http.StatusBadRequest || len(errs) != 1 || errs[0].Code != access.CodeBadRequest || errs[0].Reason != "token_in_query" {
				t.Errorf("status %d errors %+v, want 400 auth_bad_request token_in_query", w.Code, errs)
			}
			if n := counting.calls.Load() - calls; n != 0 {
				t.Errorf("%d account calls, want none", n)
			}
		})
	}
	t.Run("body_accepted", func(t *testing.T) {
		rt := e.route(t, "authRecoveryStart")
		if w := do(rt, request(rt, bodies["authRecoveryStart"])); w.Code != http.StatusOK {
			t.Errorf("status %d errors %+v, want 200 with the token in the body", w.Code, e.errs.all())
		}
	})
}

func TestRefusedAdmissionHashesNothing(t *testing.T) {
	// With the whole hash budget held, any hash or verify answers
	// auth_busy (the login_admitted row), so a refusal answered as itself
	// hashed nothing.
	cases := []struct {
		name    string
		opts    envOptions
		route   string
		body    func(t *testing.T, e *env) string
		refused bool
		want    access.Code
	}{
		{"login_rate_limited", limited, "authLoginPassword", func(t *testing.T, e *env) string { e.spendAttempt(t); return signInBody(t, "alice") }, true, access.CodeRateLimited},
		{"login_admitted", limited, "authLoginPassword", func(t *testing.T, _ *env) string { return signInBody(t, "alice") }, false, access.CodeBusy},
		{"setup_token_missing", tokenRequired, "authSetupPassword", func(t *testing.T, _ *env) string { return setupPasswordBody(t, "") }, true, access.CodeSetupTokenRequired},
		{"setup_rate_limited", limited, "authSetupPassword", func(t *testing.T, e *env) string { e.spendAttempt(t); return setupPasswordBody(t, "") }, true, access.CodeRateLimited},
		{"invite_token_invalid", envOptions{}, "authInviteAcceptPassword", func(t *testing.T, _ *env) string {
			return inviteBody(t, access.NewSecret("not-an-invite"), "invitee", testPassword)
		}, true, access.CodeTokenInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.opts)
			if tc.route == "authLoginPassword" {
				e.createUser(t, "alice", access.RoleUser)
			}
			body := tc.body(t, e)
			e.holdBudget(t)
			w := do(e.route(t, tc.route), e.post(t, tc.route, body))
			if errs := e.errs.all(); len(errs) != 1 || errs[0].Code != tc.want || w.Code != access.NewError(tc.want, "", nil).Status {
				t.Errorf("status %d errors %+v, want %s (refused: %t)", w.Code, errs, tc.want, tc.refused)
			}
		})
	}
}

func TestPasswordSignInSetsDeviceCookie(t *testing.T) {
	e := newEnv(t, trustLimits)
	e.createUser(t, "alice", access.RoleUser)
	rt := e.route(t, "authLoginPassword")
	w := do(rt, e.post(t, "authLoginPassword", signInBody(t, "alice")))
	e.requireSignedIn(t, w, "alice")
	_, deviceName := e.names()
	device := cookieNamed(w, deviceName)
	if days180 := 180 * 24 * 60 * 60; device.MaxAge != days180 || !device.HttpOnly || device.SameSite != http.SameSiteLaxMode {
		t.Errorf("device cookie %+v, want HttpOnly, Lax, Max-Age %d", device, days180)
	}
	e.requireTrustedDevice(t, "alice", device)
}

// loginBeginRecording records the mode each passkey sign-in begin asks.
type loginBeginRecording struct {
	accountAPI
	modes []account.LoginMode
}

func (l *loginBeginRecording) PasskeyLoginBegin(ctx context.Context, c account.Client, origin webauthn.Origin, mode account.LoginMode) (account.PendingCeremony, error) {
	l.modes = append(l.modes, mode)
	return l.accountAPI.PasskeyLoginBegin(ctx, c, origin, mode)
}

func TestLoginPasskeyBeginQuery(t *testing.T) {
	rec := &loginBeginRecording{}
	e := newEnv(t, with(passkeys, envOptions{wrap: func(_ *env, s *account.Service) accountAPI { rec.accountAPI = s; return rec }}))
	rt := e.route(t, "authLoginPasskeyBegin")
	for _, tc := range []struct {
		query string
		mode  account.LoginMode
	}{{"", account.LoginModal}, {"mediation=conditional", account.LoginConditional}, {"other=x", account.LoginModal}} {
		t.Run("q_"+tc.query, func(t *testing.T) {
			rec.modes = nil
			r := request(rt, "")
			r.URL.RawQuery = tc.query
			if w := do(rt, r); w.Code != http.StatusOK || len(rec.modes) != 1 || rec.modes[0] != tc.mode {
				t.Errorf("status %d modes %v, want 200 and mode %d", w.Code, rec.modes, tc.mode)
			}
		})
	}
	for _, query := range []string{"mediation=x", "mediation=conditional&mediation=conditional", "mediation=%ZZ"} {
		t.Run("refused_"+query, func(t *testing.T) {
			rec.modes = nil
			r := request(rt, "")
			r.URL.RawQuery = query
			before := len(e.errs.all())
			w := do(rt, r)
			errs := e.errs.all()[before:]
			if w.Code != http.StatusBadRequest || len(errs) != 1 || errs[0].Reason != "mediation" || len(rec.modes) != 0 {
				t.Errorf("status %d errors %+v modes %v, want 400 auth_bad_request mediation and no account call", w.Code, errs, rec.modes)
			}
		})
	}
}

func TestGoClientBodyRoundTrips(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.createUser(t, "alice", access.RoleUser)
	body, err := json.Marshal(LoginRequest{Username: "alice", Password: testPassword})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	e.requireSignedIn(t, do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", string(body))), "alice")
}

// TestCredentialBodyContentType refuses a finish body that is not JSON
// before account reads it.
func TestCredentialBodyContentType(t *testing.T) {
	counting := &finishCounting{}
	e := newEnv(t, with(passkeys, envOptions{wrap: func(_ *env, s *account.Service) accountAPI { counting.accountAPI = s; return counting }}))
	rt := e.route(t, "authLoginPasskeyFinish")
	r := finish(rt, "any", []byte(`{}`))
	r.Header.Set("Content-Type", "text/plain")
	w := do(rt, r)
	if errs := e.errs.all(); w.Code != http.StatusBadRequest || len(errs) != 1 || errs[0].Reason != "content_type" || counting.calls.Load() != 0 {
		t.Errorf("status %d errors %+v calls %d, want 400 content_type and no account call", w.Code, errs, counting.calls.Load())
	}
}
