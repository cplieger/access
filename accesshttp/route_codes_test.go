package accesshttp

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// scenarioKey names one operation code of one route.
type scenarioKey struct {
	route string
	code  access.Code
}

// scenario drives its route to its code over the real Service: arrange
// shapes the env and returns the request that must answer it.
type scenario struct {
	arrange func(t *testing.T, e *env) *http.Request
	opts    envOptions
}

// operationScenarios is the operation part of the per-route code table:
// for every route, one scenario per code its account operation answers.
func operationScenarios() map[scenarioKey]scenario {
	out := map[scenarioKey]scenario{}
	maps.Copy(out, publicScenarios())
	maps.Copy(out, recoveryScenarios())
	maps.Copy(out, oidcScenarios())
	maps.Copy(out, selfScenarios())
	maps.Copy(out, adminScenarios())
	return out
}

// with merges envs: edits, authn edits, rules and limits run in order, the
// last wrap, store and mem win and any passkeys sets the relying party.
func with(opts ...envOptions) envOptions {
	var out envOptions
	for _, o := range opts {
		edit, authn, rules, limits := out.edit, out.authn, out.rules, out.limits
		if o.authn != nil {
			out.authn = func(e *env, c *access.Config) {
				if authn != nil {
					authn(e, c)
				}
				o.authn(e, c)
			}
		}
		if o.edit != nil {
			out.edit = func(c *account.Config) {
				if edit != nil {
					edit(c)
				}
				o.edit(c)
			}
		}
		if o.rules != nil {
			out.rules = func(r *account.Rules) {
				if rules != nil {
					rules(r)
				}
				o.rules(r)
			}
		}
		if o.limits != nil {
			out.limits = func(c *ratelimit.Config) {
				if limits != nil {
					limits(c)
				}
				o.limits(c)
			}
		}
		if o.wrap != nil {
			out.wrap = o.wrap
		}
		if o.store != nil {
			out.store = o.store
		}
		if o.mem != nil {
			out.mem = o.mem
		}
		out.passkeys = out.passkeys || o.passkeys
	}
	return out
}

var (
	passkeys      = envOptions{passkeys: true}
	limited       = envOptions{limits: ipLimit}
	tokenRequired = envOptions{rules: func(r *account.Rules) { r.SetupTokenRequired = nil }}
	vanishes      = envOptions{wrap: vanish}
)

// post is a same-origin request for name with body.
func (e *env) post(t *testing.T, name, body string, cookies ...*http.Cookie) *http.Request {
	t.Helper()
	return request(e.route(t, name), body, cookies...)
}

// fromOrigin is r sent from origin.
func fromOrigin(r *http.Request, origin string) *http.Request {
	r.Header.Set("Origin", origin)
	return r
}

const evilOrigin = "https://evil.example.com"

func setupPasswordBody(t *testing.T, token string) string {
	t.Helper()
	return jsonBody(t, SetupPasswordRequest{Token: token, Username: "owner", Password: testPassword})
}

func setupPasskeyBody(t *testing.T, token string) string {
	t.Helper()
	return jsonBody(t, SetupPasskeyBeginRequest{Token: token, Username: "owner"})
}

func (e *env) setupToken(t *testing.T) string {
	t.Helper()
	tok, err := e.svc.IssueSetupToken(t.Context(), account.OutOfBand("test"), 0)
	if err != nil {
		t.Fatalf("IssueSetupToken: %v", err)
	}
	return tok.Reveal()
}

// setupFinish begins a passkey setup and returns its finish request with a
// fresh device's registration, after between runs.
func (e *env) setupFinish(t *testing.T, token string, edit func([]byte) []byte, between func()) *http.Request {
	t.Helper()
	id, options := e.begin(t, "authSetupPasskeyBegin", "", setupPasskeyBody(t, token))
	body := accesstest.NewPasskeyDevice(t).Register(options)
	if edit != nil {
		body = edit(body)
	}
	if between != nil {
		between()
	}
	return finish(e.route(t, "authSetupPasskeyFinish"), id, body)
}

// loginFinish enrols alice's device and returns a passkey sign-in's finish
// request, after between runs.
func (e *env) loginFinish(t *testing.T, between func(dev *accesstest.PasskeyDevice)) *http.Request {
	t.Helper()
	e.createUser(t, "alice", access.RoleUser)
	dev := e.enrol(t, "alice")
	id, options := e.begin(t, "authLoginPasskeyBegin", "", "")
	body := dev.Assert(options)
	if between != nil {
		between(dev)
	}
	return finish(e.route(t, "authLoginPasskeyFinish"), id, body)
}

// recoveryFinish begins a passkey recovery for cookie's session through
// the Service, so a wrapping account sees only the finish, and returns its
// finish request with dev's registration (a fresh device when nil).
func (e *env) recoveryFinish(t *testing.T, cookie *http.Cookie, dev *accesstest.PasskeyDevice, edit func([]byte) []byte, between func()) *http.Request {
	t.Helper()
	origin, err := webauthn.ParseOrigin(testOrigin)
	if err != nil {
		t.Fatalf("ParseOrigin: %v", err)
	}
	pc, err := e.svc.RecoverPasskeyBegin(t.Context(), e.principal(t, cookie), origin)
	if err != nil {
		t.Fatalf("RecoverPasskeyBegin: %v", err)
	}
	if dev == nil {
		dev = accesstest.NewPasskeyDevice(t)
	}
	body := dev.Register(jsonBytes(t, pc.Creation))
	if edit != nil {
		body = edit(body)
	}
	if between != nil {
		between()
	}
	return finish(e.route(t, "authRecoveryPasskeyFinish"), pc.ID, body, cookie)
}

func publicScenarios() map[scenarioKey]scenario {
	shut := func(name, body string) scenario {
		return scenario{arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, name, body)
			e.shutdown(t)
			return r
		}}
	}
	return map[scenarioKey]scenario{
		{"authState", access.CodeUnavailable}: shut("authState", ""),
		{"authLogout", access.CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			r := e.post(t, "authLogout", "", e.sessionCookie(t, "alice"))
			e.shutdown(t)
			return r
		}},

		{"authSetupPassword", access.CodeForbidden}: {opts: envOptions{edit: refuse(account.OpCreateUser)}, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", access.CodeRateLimited}: {opts: limited, arrange: func(t *testing.T, e *env) *http.Request {
			e.spendAttempt(t)
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", access.CodeBusy}: {arrange: func(t *testing.T, e *env) *http.Request {
			e.holdBudget(t)
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", access.CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
			e.shutdown(t)
			return r
		}},
		{"authSetupPassword", access.CodeUsernameInvalid}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", jsonBody(t, SetupPasswordRequest{Username: "", Password: testPassword}))
		}},
		{"authSetupPassword", access.CodePasswordRejected}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", jsonBody(t, SetupPasswordRequest{Username: "owner", Password: "short"}))
		}},
		{"authSetupPassword", access.CodeBreachCheckUnavailable}: {opts: breachDown, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", access.CodeSetupComplete}: {arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "first", access.RoleAdmin)
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", access.CodeSetupTokenRequired}: {opts: tokenRequired, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", access.CodeTokenInvalid}: {opts: tokenRequired, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", setupPasswordBody(t, "not-a-setup-token"))
		}},

		{"authSetupPasskeyBegin", access.CodeRateLimited}: {opts: with(passkeys, limited), arrange: func(t *testing.T, e *env) *http.Request {
			e.spendRequest(t)
			return e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, ""))
		}},
		{"authSetupPasskeyBegin", access.CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, ""))
			e.shutdown(t)
			return r
		}},
		{"authSetupPasskeyBegin", access.CodeUsernameInvalid}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPasskeyBegin", jsonBody(t, SetupPasskeyBeginRequest{Username: ""}))
		}},
		{"authSetupPasskeyBegin", access.CodeSetupComplete}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "first", access.RoleAdmin)
			return e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, ""))
		}},
		{"authSetupPasskeyBegin", access.CodeSetupTokenRequired}: {opts: with(passkeys, tokenRequired), arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, ""))
		}},
		{"authSetupPasskeyBegin", access.CodeTokenInvalid}: {opts: with(passkeys, tokenRequired), arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, "not-a-setup-token"))
		}},
		{"authSetupPasskeyBegin", access.CodePasskeysUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, ""))
		}},
		{"authSetupPasskeyBegin", access.CodeOriginRefused}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return fromOrigin(e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, "")), evilOrigin)
		}},

		{"authSetupPasskeyFinish", access.CodeForbidden}: {opts: with(passkeys, envOptions{edit: refuse(account.OpCreateUser)}), arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", nil, nil)
		}},
		{"authSetupPasskeyFinish", access.CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", nil, func() { e.shutdown(t) })
		}},
		{"authSetupPasskeyFinish", access.CodeSetupComplete}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", nil, func() { e.createUser(t, "first", access.RoleAdmin) })
		}},
		{"authSetupPasskeyFinish", access.CodeTokenInvalid}: {opts: with(passkeys, tokenRequired), arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, e.setupToken(t), nil, func() { e.setupToken(t) })
		}},
		{"authSetupPasskeyFinish", access.CodePasskeysUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", nil, func() { e.rp.Store(nil) })
		}},
		{"authSetupPasskeyFinish", access.CodeCeremonyInvalid}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.setupFinish(t, "", nil, nil)
			r.Header.Set(ceremonyHeader, "not-a-ceremony")
			return r
		}},
		{"authSetupPasskeyFinish", access.CodeNotDiscoverable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", func(b []byte) []byte { return notDiscoverable(t, b) }, nil)
		}},
		{"authSetupPasskeyFinish", access.CodeRegistrationFailed}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", func([]byte) []byte { return []byte(`{}`) }, nil)
		}},

		{"authLoginPassword", access.CodeInvalidCredentials}: {arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			return e.post(t, "authLoginPassword", jsonBody(t, LoginRequest{Username: "alice", Password: "wrong-horse-battery-staple-9"})) // gitleaks:allow (test fixture password)
		}},
		{"authLoginPassword", access.CodeRateLimited}: {opts: limited, arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			e.spendAttempt(t)
			return e.post(t, "authLoginPassword", signInBody(t, "alice"))
		}},
		{"authLoginPassword", access.CodeBusy}: {arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			e.holdBudget(t)
			return e.post(t, "authLoginPassword", signInBody(t, "alice"))
		}},
		{"authLoginPassword", access.CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authLoginPassword", signInBody(t, "alice"))
			e.shutdown(t)
			return r
		}},
		{"authLoginPassword", access.CodeUsernameInvalid}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authLoginPassword", signInBody(t, ""))
		}},
		{"authLoginPassword", access.CodePasswordLoginDisabled}: {opts: envOptions{rules: func(r *account.Rules) { r.DisablePasswordLogin = true }}, arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			return e.post(t, "authLoginPassword", signInBody(t, "alice"))
		}},

		{"authLoginPasskeyBegin", access.CodeRateLimited}: {opts: with(passkeys, limited), arrange: func(t *testing.T, e *env) *http.Request {
			e.spendRequest(t)
			return e.post(t, "authLoginPasskeyBegin", "")
		}},
		{"authLoginPasskeyBegin", access.CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authLoginPasskeyBegin", "")
			e.shutdown(t)
			return r
		}},
		{"authLoginPasskeyBegin", access.CodePasskeysUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authLoginPasskeyBegin", "")
		}},
		{"authLoginPasskeyBegin", access.CodeOriginRefused}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return fromOrigin(e.post(t, "authLoginPasskeyBegin", ""), evilOrigin)
		}},

		{"authLoginPasskeyFinish", access.CodeInvalidCredentials}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.loginFinish(t, func(*accesstest.PasskeyDevice) {
				u := e.user(t, "alice")
				u.Enabled = false
				if err := e.mem.UpdateUser(t.Context(), u); err != nil {
					t.Fatalf("UpdateUser: %v", err)
				}
			})
		}},
		{"authLoginPasskeyFinish", access.CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.loginFinish(t, func(*accesstest.PasskeyDevice) { e.shutdown(t) })
		}},
		{"authLoginPasskeyFinish", access.CodePasskeysUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.loginFinish(t, func(*accesstest.PasskeyDevice) { e.rp.Store(nil) })
		}},
		{"authLoginPasskeyFinish", access.CodeCeremonyInvalid}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.loginFinish(t, nil)
			r.Header.Set(ceremonyHeader, "not-a-ceremony")
			return r
		}},
		{"authLoginPasskeyFinish", access.CodeUnknownCredential}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.loginFinish(t, func(*accesstest.PasskeyDevice) {
				u := e.user(t, "alice")
				creds, err := e.mem.PasskeysByUserID(t.Context(), u.ID)
				if err != nil || len(creds) != 1 {
					t.Fatalf("PasskeysByUserID = %d, %v", len(creds), err)
				}
				if err := e.mem.DeletePasskey(t.Context(), access.PasskeyRef{ID: creds[0].ID, UserID: u.ID}); err != nil {
					t.Fatalf("DeletePasskey: %v", err)
				}
			})
		}},
		{"authLoginPasskeyFinish", access.CodeAssertionFailed}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.loginFinish(t, nil)
			return finish(e.route(t, "authLoginPasskeyFinish"), r.Header.Get(ceremonyHeader), []byte(`{}`))
		}},

		{"authInviteAcceptPassword", access.CodeForbidden}: {opts: envOptions{edit: refuse(account.OpCreateUser)}, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authInviteAcceptPassword", inviteBody(t, e.invite(t), "invitee", testPassword))
		}},
		{"authInviteAcceptPassword", access.CodeRateLimited}: {opts: limited, arrange: func(t *testing.T, e *env) *http.Request {
			body := inviteBody(t, e.invite(t), "invitee", testPassword)
			e.spendAttempt(t)
			return e.post(t, "authInviteAcceptPassword", body)
		}},
		{"authInviteAcceptPassword", access.CodeBusy}: {arrange: func(t *testing.T, e *env) *http.Request {
			body := inviteBody(t, e.invite(t), "invitee", testPassword)
			e.holdBudget(t)
			return e.post(t, "authInviteAcceptPassword", body)
		}},
		{"authInviteAcceptPassword", access.CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authInviteAcceptPassword", inviteBody(t, e.invite(t), "invitee", testPassword))
			e.shutdown(t)
			return r
		}},
		{"authInviteAcceptPassword", access.CodeUsernameInvalid}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authInviteAcceptPassword", inviteBody(t, e.invite(t), "", testPassword))
		}},
		{"authInviteAcceptPassword", access.CodeUsernameTaken}: {arrange: func(t *testing.T, e *env) *http.Request {
			body := inviteBody(t, e.invite(t), "alice", testPassword)
			e.createUser(t, "alice", access.RoleUser)
			return e.post(t, "authInviteAcceptPassword", body)
		}},
		{"authInviteAcceptPassword", access.CodePasswordRejected}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authInviteAcceptPassword", inviteBody(t, e.invite(t), "invitee", "short"))
		}},
		{"authInviteAcceptPassword", access.CodeBreachCheckUnavailable}: {opts: breachDown, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authInviteAcceptPassword", inviteBody(t, e.invite(t), "invitee", testPassword))
		}},
		{"authInviteAcceptPassword", access.CodeTokenInvalid}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authInviteAcceptPassword", inviteBody(t, access.NewSecret("not-an-invite"), "invitee", testPassword))
		}},
	}
}

func inviteBody(t *testing.T, token access.Secret, name, password string) string {
	t.Helper()
	return jsonBody(t, InviteAcceptRequest{Token: token.Reveal(), Username: name, Password: password})
}

func recoveryPasswordBody(t *testing.T, password string) string {
	t.Helper()
	return jsonBody(t, RecoverPasswordRequest{Password: password})
}

func recoveryScenarios() map[scenarioKey]scenario {
	// alice opens a recovery session from an out-of-band link.
	alice := func(t *testing.T, e *env) *http.Cookie {
		t.Helper()
		e.createUser(t, "alice", access.RoleUser)
		return e.recoveryCookie(t, "alice")
	}
	tokenBody := func(t *testing.T, token string) string {
		t.Helper()
		return jsonBody(t, TokenRequest{Token: token})
	}
	return map[scenarioKey]scenario{
		{"authRecoveryStart", access.CodeRateLimited}: {opts: limited, arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			issued, err := e.svc.IssueRecovery(t.Context(), account.OutOfBand("test"), e.user(t, "alice").ID, 0)
			if err != nil {
				t.Fatalf("IssueRecovery: %v", err)
			}
			e.spendAttempt(t)
			return e.post(t, "authRecoveryStart", tokenBody(t, issued.Plaintext.Reveal()))
		}},
		{"authRecoveryStart", access.CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authRecoveryStart", tokenBody(t, "some-token"))
			e.shutdown(t)
			return r
		}},
		{"authRecoveryStart", access.CodeTokenInvalid}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryStart", tokenBody(t, "not-a-recovery-token"))
		}},

		{"authRecoveryPassword", access.CodeSessionExpired}: {opts: vanishes, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, testPassword), alice(t, e))
		}},
		{"authRecoveryPassword", access.CodeBusy}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, testPassword), alice(t, e))
			e.holdBudget(t)
			return r
		}},
		{"authRecoveryPassword", access.CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, testPassword), alice(t, e))
			e.shutdown(t)
			return r
		}},
		{"authRecoveryPassword", access.CodePasswordRejected}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, "short"), alice(t, e))
		}},
		{"authRecoveryPassword", access.CodeBreachCheckUnavailable}: {opts: breachDown, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, testPassword), alice(t, e))
		}},
		{"authRecoveryPassword", access.CodeTokenInvalid}: {opts: keyScopes, arrange: func(t *testing.T, e *env) *http.Request {
			cookie, revoke := e.keyIssuedRecovery(t)
			revoke()
			return e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, testPassword), cookie)
		}},

		{"authRecoveryPasskeyBegin", access.CodeSessionExpired}: {opts: with(passkeys, vanishes), arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryPasskeyBegin", "", alice(t, e))
		}},
		{"authRecoveryPasskeyBegin", access.CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authRecoveryPasskeyBegin", "", alice(t, e))
			e.shutdown(t)
			return r
		}},
		{"authRecoveryPasskeyBegin", access.CodePasskeysUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryPasskeyBegin", "", alice(t, e))
		}},
		{"authRecoveryPasskeyBegin", access.CodeOriginRefused}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return fromOrigin(e.post(t, "authRecoveryPasskeyBegin", "", alice(t, e)), evilOrigin)
		}},

		{"authRecoveryPasskeyFinish", access.CodeSessionExpired}: {opts: with(passkeys, vanishes), arrange: func(t *testing.T, e *env) *http.Request {
			return e.recoveryFinish(t, alice(t, e), nil, nil, nil)
		}},
		{"authRecoveryPasskeyFinish", access.CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.recoveryFinish(t, alice(t, e), nil, nil, func() { e.shutdown(t) })
		}},
		{"authRecoveryPasskeyFinish", access.CodeTokenInvalid}: {opts: with(passkeys, keyScopes), arrange: func(t *testing.T, e *env) *http.Request {
			cookie, revoke := e.keyIssuedRecovery(t)
			return e.recoveryFinish(t, cookie, nil, nil, revoke)
		}},
		{"authRecoveryPasskeyFinish", access.CodeDuplicateCredential}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "root", access.RoleAdmin)
			held := e.enrol(t, "root")
			return e.recoveryFinish(t, alice(t, e), held, nil, nil)
		}},
		{"authRecoveryPasskeyFinish", access.CodePasskeysUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.recoveryFinish(t, alice(t, e), nil, nil, func() { e.rp.Store(nil) })
		}},
		{"authRecoveryPasskeyFinish", access.CodeCeremonyInvalid}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.recoveryFinish(t, alice(t, e), nil, nil, nil)
			r.Header.Set(ceremonyHeader, "not-a-ceremony")
			return r
		}},
		{"authRecoveryPasskeyFinish", access.CodeNotDiscoverable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.recoveryFinish(t, alice(t, e), nil, func(b []byte) []byte { return notDiscoverable(t, b) }, nil)
		}},
		{"authRecoveryPasskeyFinish", access.CodeRegistrationFailed}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.recoveryFinish(t, alice(t, e), nil, func([]byte) []byte { return []byte(`{}`) }, nil)
		}},
	}
}

// redirectedCode is the auth_error a redirect answer carries.
func redirectedCode(t *testing.T, w *httptest.ResponseRecorder) access.Code {
	t.Helper()
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location %q: %v", w.Header().Get("Location"), err)
	}
	return access.Code(loc.Query().Get(markerError))
}
