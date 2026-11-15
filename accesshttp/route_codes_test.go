package accesshttp

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
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
	maps.Copy(out, oidcScenarios())
	maps.Copy(out, selfScenarios())
	maps.Copy(out, adminScenarios())
	maps.Copy(out, ssoScenarios())
	maps.Copy(out, plainScenarios())
	return out
}

// plainScenarios reach auth_https_required from each operation that
// refuses a plain request: an anonymous route's census request without TLS
// under the env's PostureSecure, and every other refused route's census
// request from a plain session under PosturePerRequest, which the guard
// admits.
func plainScenarios() map[scenarioKey]scenario {
	out := map[scenarioKey]scenario{}
	anonymous := []string{
		"authSetupPassword", "authSetupPasskeyBegin", "authSetupPasskeyFinish", "authLoginPassword", "authLoginPasskeyBegin",
		"authLoginPasskeyFinish", "authInviteAcceptPassword", "authOIDCStartSignIn", "authOIDCCallback", "authOIDCPending", "authOIDCCreatePending",
	}
	for _, route := range anonymous {
		out[scenarioKey{route, access.CodeHTTPSRequired}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
			rt := e.route(t, route)
			r := requestFor(rt, censusPathValue(t, rt), censusBody(t, rt))
			r.TLS = nil
			return r
		}}
	}
	for route := range plainRefusedRoutes {
		if slices.Contains(anonymous, route) {
			continue
		}
		out[scenarioKey{route, access.CodeHTTPSRequired}] = scenario{opts: perRequest, arrange: func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "root", access.RoleAdmin)
			e.createUser(t, "alice", access.RoleUser)
			rt := e.route(t, route)
			path := strings.NewReplacer("{id}", censusPathValue(t, rt), "{method}", censusPathValue(t, rt)).Replace(rt.Path)
			return requestAt(plainOrigin, path, rt, censusBody(t, rt), e.transportSession(t, "root", false))
		}}
	}
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
		{"authInviteAcceptPassword", access.CodeSSOOnly}: {arrange: func(t *testing.T, e *env) *http.Request {
			body := inviteBody(t, e.invite(t), "invitee", testPassword)
			if err := e.mem.SetSSOMode(t.Context(), account.SSOOnly); err != nil {
				t.Fatalf("SetSSOMode: %v", err)
			}
			return e.post(t, "authInviteAcceptPassword", body)
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

// redirectedCode is the auth_error a redirect answer carries.
func redirectedCode(t *testing.T, w *httptest.ResponseRecorder) access.Code {
	t.Helper()
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location %q: %v", w.Header().Get("Location"), err)
	}
	return access.Code(loc.Query().Get(markerError))
}
