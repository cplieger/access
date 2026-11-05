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
	code  Code
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
		{"authState", CodeUnavailable}: shut("authState", ""),
		{"authLogout", CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			r := e.post(t, "authLogout", "", e.sessionCookie(t, "alice"))
			e.shutdown(t)
			return r
		}},

		{"authSetupPassword", CodeForbidden}: {opts: envOptions{edit: refuse(account.OpCreateUser)}, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", CodeRateLimited}: {opts: limited, arrange: func(t *testing.T, e *env) *http.Request {
			e.spendAttempt(t)
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", CodeBusy}: {arrange: func(t *testing.T, e *env) *http.Request {
			e.holdBudget(t)
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
			e.shutdown(t)
			return r
		}},
		{"authSetupPassword", CodeUsernameInvalid}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", jsonBody(t, SetupPasswordRequest{Username: "", Password: testPassword}))
		}},
		{"authSetupPassword", CodePasswordRejected}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", jsonBody(t, SetupPasswordRequest{Username: "owner", Password: "short"}))
		}},
		{"authSetupPassword", CodeBreachCheckUnavailable}: {opts: breachDown, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", CodeSetupComplete}: {arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "first", access.RoleAdmin)
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", CodeSetupTokenRequired}: {opts: tokenRequired, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		}},
		{"authSetupPassword", CodeTokenInvalid}: {opts: tokenRequired, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPassword", setupPasswordBody(t, "not-a-setup-token"))
		}},

		{"authSetupPasskeyBegin", CodeRateLimited}: {opts: with(passkeys, limited), arrange: func(t *testing.T, e *env) *http.Request {
			e.spendRequest(t)
			return e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, ""))
		}},
		{"authSetupPasskeyBegin", CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, ""))
			e.shutdown(t)
			return r
		}},
		{"authSetupPasskeyBegin", CodeUsernameInvalid}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPasskeyBegin", jsonBody(t, SetupPasskeyBeginRequest{Username: ""}))
		}},
		{"authSetupPasskeyBegin", CodeSetupComplete}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "first", access.RoleAdmin)
			return e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, ""))
		}},
		{"authSetupPasskeyBegin", CodeSetupTokenRequired}: {opts: with(passkeys, tokenRequired), arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, ""))
		}},
		{"authSetupPasskeyBegin", CodeTokenInvalid}: {opts: with(passkeys, tokenRequired), arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, "not-a-setup-token"))
		}},
		{"authSetupPasskeyBegin", CodePasskeysUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, ""))
		}},
		{"authSetupPasskeyBegin", CodeOriginRefused}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return fromOrigin(e.post(t, "authSetupPasskeyBegin", setupPasskeyBody(t, "")), evilOrigin)
		}},

		{"authSetupPasskeyFinish", CodeForbidden}: {opts: with(passkeys, envOptions{edit: refuse(account.OpCreateUser)}), arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", nil, nil)
		}},
		{"authSetupPasskeyFinish", CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", nil, func() { e.shutdown(t) })
		}},
		{"authSetupPasskeyFinish", CodeSetupComplete}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", nil, func() { e.createUser(t, "first", access.RoleAdmin) })
		}},
		{"authSetupPasskeyFinish", CodeTokenInvalid}: {opts: with(passkeys, tokenRequired), arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, e.setupToken(t), nil, func() { e.setupToken(t) })
		}},
		{"authSetupPasskeyFinish", CodePasskeysUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", nil, func() { e.rp.Store(nil) })
		}},
		{"authSetupPasskeyFinish", CodeCeremonyInvalid}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.setupFinish(t, "", nil, nil)
			r.Header.Set(ceremonyHeader, "not-a-ceremony")
			return r
		}},
		{"authSetupPasskeyFinish", CodeNotDiscoverable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", func(b []byte) []byte { return notDiscoverable(t, b) }, nil)
		}},
		{"authSetupPasskeyFinish", CodeRegistrationFailed}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.setupFinish(t, "", func([]byte) []byte { return []byte(`{}`) }, nil)
		}},

		{"authLoginPassword", CodeInvalidCredentials}: {arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			return e.post(t, "authLoginPassword", jsonBody(t, LoginRequest{Username: "alice", Password: "wrong-horse-battery-staple-9"})) // gitleaks:allow (test fixture password)
		}},
		{"authLoginPassword", CodeRateLimited}: {opts: limited, arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			e.spendAttempt(t)
			return e.post(t, "authLoginPassword", signInBody(t, "alice"))
		}},
		{"authLoginPassword", CodeBusy}: {arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			e.holdBudget(t)
			return e.post(t, "authLoginPassword", signInBody(t, "alice"))
		}},
		{"authLoginPassword", CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authLoginPassword", signInBody(t, "alice"))
			e.shutdown(t)
			return r
		}},
		{"authLoginPassword", CodeUsernameInvalid}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authLoginPassword", signInBody(t, ""))
		}},
		{"authLoginPassword", CodePasswordLoginDisabled}: {opts: envOptions{rules: func(r *account.Rules) { r.DisablePasswordLogin = true }}, arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			return e.post(t, "authLoginPassword", signInBody(t, "alice"))
		}},

		{"authLoginPasskeyBegin", CodeRateLimited}: {opts: with(passkeys, limited), arrange: func(t *testing.T, e *env) *http.Request {
			e.spendRequest(t)
			return e.post(t, "authLoginPasskeyBegin", "")
		}},
		{"authLoginPasskeyBegin", CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authLoginPasskeyBegin", "")
			e.shutdown(t)
			return r
		}},
		{"authLoginPasskeyBegin", CodePasskeysUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authLoginPasskeyBegin", "")
		}},
		{"authLoginPasskeyBegin", CodeOriginRefused}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return fromOrigin(e.post(t, "authLoginPasskeyBegin", ""), evilOrigin)
		}},

		{"authLoginPasskeyFinish", CodeInvalidCredentials}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.loginFinish(t, func(*accesstest.PasskeyDevice) {
				u := e.user(t, "alice")
				u.Enabled = false
				if err := e.mem.UpdateUser(t.Context(), u); err != nil {
					t.Fatalf("UpdateUser: %v", err)
				}
			})
		}},
		{"authLoginPasskeyFinish", CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.loginFinish(t, func(*accesstest.PasskeyDevice) { e.shutdown(t) })
		}},
		{"authLoginPasskeyFinish", CodePasskeysUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.loginFinish(t, func(*accesstest.PasskeyDevice) { e.rp.Store(nil) })
		}},
		{"authLoginPasskeyFinish", CodeCeremonyInvalid}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.loginFinish(t, nil)
			r.Header.Set(ceremonyHeader, "not-a-ceremony")
			return r
		}},
		{"authLoginPasskeyFinish", CodeUnknownCredential}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
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
		{"authLoginPasskeyFinish", CodeAssertionFailed}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.loginFinish(t, nil)
			return finish(e.route(t, "authLoginPasskeyFinish"), r.Header.Get(ceremonyHeader), []byte(`{}`))
		}},

		{"authInviteAcceptPassword", CodeForbidden}: {opts: envOptions{edit: refuse(account.OpCreateUser)}, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authInviteAcceptPassword", inviteBody(t, e.invite(t), "invitee", testPassword))
		}},
		{"authInviteAcceptPassword", CodeRateLimited}: {opts: limited, arrange: func(t *testing.T, e *env) *http.Request {
			body := inviteBody(t, e.invite(t), "invitee", testPassword)
			e.spendAttempt(t)
			return e.post(t, "authInviteAcceptPassword", body)
		}},
		{"authInviteAcceptPassword", CodeBusy}: {arrange: func(t *testing.T, e *env) *http.Request {
			body := inviteBody(t, e.invite(t), "invitee", testPassword)
			e.holdBudget(t)
			return e.post(t, "authInviteAcceptPassword", body)
		}},
		{"authInviteAcceptPassword", CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authInviteAcceptPassword", inviteBody(t, e.invite(t), "invitee", testPassword))
			e.shutdown(t)
			return r
		}},
		{"authInviteAcceptPassword", CodeUsernameInvalid}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authInviteAcceptPassword", inviteBody(t, e.invite(t), "", testPassword))
		}},
		{"authInviteAcceptPassword", CodeUsernameTaken}: {arrange: func(t *testing.T, e *env) *http.Request {
			body := inviteBody(t, e.invite(t), "alice", testPassword)
			e.createUser(t, "alice", access.RoleUser)
			return e.post(t, "authInviteAcceptPassword", body)
		}},
		{"authInviteAcceptPassword", CodePasswordRejected}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authInviteAcceptPassword", inviteBody(t, e.invite(t), "invitee", "short"))
		}},
		{"authInviteAcceptPassword", CodeBreachCheckUnavailable}: {opts: breachDown, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authInviteAcceptPassword", inviteBody(t, e.invite(t), "invitee", testPassword))
		}},
		{"authInviteAcceptPassword", CodeTokenInvalid}: {arrange: func(t *testing.T, e *env) *http.Request {
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
		{"authRecoveryStart", CodeRateLimited}: {opts: limited, arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			issued, err := e.svc.IssueRecovery(t.Context(), account.OutOfBand("test"), e.user(t, "alice").ID, 0)
			if err != nil {
				t.Fatalf("IssueRecovery: %v", err)
			}
			e.spendAttempt(t)
			return e.post(t, "authRecoveryStart", tokenBody(t, issued.Plaintext.Reveal()))
		}},
		{"authRecoveryStart", CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authRecoveryStart", tokenBody(t, "some-token"))
			e.shutdown(t)
			return r
		}},
		{"authRecoveryStart", CodeTokenInvalid}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryStart", tokenBody(t, "not-a-recovery-token"))
		}},

		{"authRecoveryPassword", CodeSessionExpired}: {opts: vanishes, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, testPassword), alice(t, e))
		}},
		{"authRecoveryPassword", CodeBusy}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, testPassword), alice(t, e))
			e.holdBudget(t)
			return r
		}},
		{"authRecoveryPassword", CodeUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, testPassword), alice(t, e))
			e.shutdown(t)
			return r
		}},
		{"authRecoveryPassword", CodePasswordRejected}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, "short"), alice(t, e))
		}},
		{"authRecoveryPassword", CodeBreachCheckUnavailable}: {opts: breachDown, arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, testPassword), alice(t, e))
		}},
		{"authRecoveryPassword", CodeTokenInvalid}: {opts: keyScopes, arrange: func(t *testing.T, e *env) *http.Request {
			cookie, revoke := e.keyIssuedRecovery(t)
			revoke()
			return e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, testPassword), cookie)
		}},

		{"authRecoveryPasskeyBegin", CodeSessionExpired}: {opts: with(passkeys, vanishes), arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryPasskeyBegin", "", alice(t, e))
		}},
		{"authRecoveryPasskeyBegin", CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, "authRecoveryPasskeyBegin", "", alice(t, e))
			e.shutdown(t)
			return r
		}},
		{"authRecoveryPasskeyBegin", CodePasskeysUnavailable}: {arrange: func(t *testing.T, e *env) *http.Request {
			return e.post(t, "authRecoveryPasskeyBegin", "", alice(t, e))
		}},
		{"authRecoveryPasskeyBegin", CodeOriginRefused}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return fromOrigin(e.post(t, "authRecoveryPasskeyBegin", "", alice(t, e)), evilOrigin)
		}},

		{"authRecoveryPasskeyFinish", CodeSessionExpired}: {opts: with(passkeys, vanishes), arrange: func(t *testing.T, e *env) *http.Request {
			return e.recoveryFinish(t, alice(t, e), nil, nil, nil)
		}},
		{"authRecoveryPasskeyFinish", CodeUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.recoveryFinish(t, alice(t, e), nil, nil, func() { e.shutdown(t) })
		}},
		{"authRecoveryPasskeyFinish", CodeTokenInvalid}: {opts: with(passkeys, keyScopes), arrange: func(t *testing.T, e *env) *http.Request {
			cookie, revoke := e.keyIssuedRecovery(t)
			return e.recoveryFinish(t, cookie, nil, nil, revoke)
		}},
		{"authRecoveryPasskeyFinish", CodeDuplicateCredential}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "root", access.RoleAdmin)
			held := e.enrol(t, "root")
			return e.recoveryFinish(t, alice(t, e), held, nil, nil)
		}},
		{"authRecoveryPasskeyFinish", CodePasskeysUnavailable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.recoveryFinish(t, alice(t, e), nil, nil, func() { e.rp.Store(nil) })
		}},
		{"authRecoveryPasskeyFinish", CodeCeremonyInvalid}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			r := e.recoveryFinish(t, alice(t, e), nil, nil, nil)
			r.Header.Set(ceremonyHeader, "not-a-ceremony")
			return r
		}},
		{"authRecoveryPasskeyFinish", CodeNotDiscoverable}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.recoveryFinish(t, alice(t, e), nil, func(b []byte) []byte { return notDiscoverable(t, b) }, nil)
		}},
		{"authRecoveryPasskeyFinish", CodeRegistrationFailed}: {opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
			return e.recoveryFinish(t, alice(t, e), nil, func([]byte) []byte { return []byte(`{}`) }, nil)
		}},
	}
}

// redirectedCode is the auth_error a redirect answer carries.
func redirectedCode(t *testing.T, w *httptest.ResponseRecorder) Code {
	t.Helper()
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location %q: %v", w.Header().Get("Location"), err)
	}
	return Code(loc.Query().Get(markerError))
}
