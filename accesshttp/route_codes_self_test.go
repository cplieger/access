package accesshttp

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// newPassword is a password the rules accept that no fixture user holds.
const newPassword = "another-horse-battery-staple-7"

// otherSessionID is a well-formed session ID no session has.
const otherSessionID = "00000000000000000000000000000000"

// aliceSession stores RoleUser alice and returns her full password session.
func (e *env) aliceSession(t testing.TB) *http.Cookie {
	t.Helper()
	e.createUser(t, "alice", access.RoleUser)
	return e.sessionCookie(t, "alice")
}

// at is a same-origin request for name with id as its {id} or {method}.
func (e *env) at(t testing.TB, name, id, body string, cookies ...*http.Cookie) *http.Request {
	t.Helper()
	return requestFor(e.route(t, name), id, body, cookies...)
}

// testOriginOf is testOrigin as webauthn parses it.
func testOriginOf(t testing.TB) webauthn.Origin {
	t.Helper()
	origin, err := webauthn.ParseOrigin(testOrigin)
	if err != nil {
		t.Fatalf("ParseOrigin: %v", err)
	}
	return origin
}

// passkeyID is the ID of name's only passkey.
func (e *env) passkeyID(t testing.TB, name string) int64 {
	t.Helper()
	creds, err := e.mem.PasskeysByUserID(t.Context(), e.user(t, name).ID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("PasskeysByUserID(%s) = %d, %v; want one", name, len(creds), err)
	}
	return creds[0].ID
}

// sessionIDOf is the ID of the session cookie names.
func (e *env) sessionIDOf(t testing.TB, cookie *http.Cookie) string {
	t.Helper()
	return e.principal(t, cookie).SessionID
}

// spendAccount fails one untrusted attempt on name's account, the whole
// budget under trustLimits.
func (e *env) spendAccount(t testing.TB, name string) {
	t.Helper()
	res, err := e.limiter.Attempt(ratelimit.Attempt{OmitIP: true, Account: ratelimit.AccountKey(name)})
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	res.Fail()
}

// stepUpFinish begins a passkey step-up for cookie's session through the
// Service and returns its finish request with dev's assertion, edited,
// after between runs.
func (e *env) stepUpFinish(t testing.TB, cookie *http.Cookie, dev *accesstest.PasskeyDevice, edit func([]byte) []byte, between func()) *http.Request {
	t.Helper()
	pc, err := e.svc.StepUpPasskeyBegin(t.Context(), e.principal(t, cookie), testOriginOf(t))
	if err != nil {
		t.Fatalf("StepUpPasskeyBegin: %v", err)
	}
	body := dev.Assert(jsonBytes(t, pc.Assertion))
	if edit != nil {
		body = edit(body)
	}
	if between != nil {
		between()
	}
	return finish(e.route(t, "authStepUpPasskeyFinish"), pc.ID, body, cookie)
}

// registerFinish begins a passkey enrolment for cookie's session through
// the Service and returns its finish request with dev's registration (a
// fresh device when nil), edited, after between runs.
func (e *env) registerFinish(t testing.TB, cookie *http.Cookie, dev *accesstest.PasskeyDevice, edit func([]byte) []byte, between func()) *http.Request {
	t.Helper()
	pc, err := e.svc.PasskeyRegisterBegin(t.Context(), e.principal(t, cookie), testOriginOf(t))
	if err != nil {
		t.Fatalf("PasskeyRegisterBegin: %v", err)
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
	return finish(e.route(t, "authPasskeyRegisterFinish"), pc.ID, body, cookie)
}

// passkeySession signs name in with dev through the Service and returns
// the session cookie, whose AuthMethod is passkey.
func (e *env) passkeySession(t testing.TB, dev *accesstest.PasskeyDevice) *http.Cookie {
	t.Helper()
	pc, err := e.svc.PasskeyLoginBegin(t.Context(), account.Client{}, testOriginOf(t), account.LoginModal)
	if err != nil {
		t.Fatalf("PasskeyLoginBegin: %v", err)
	}
	in, err := e.svc.PasskeyLoginFinish(t.Context(), account.Client{}, pc.ID, bytes.NewReader(dev.Assert(jsonBytes(t, pc.Assertion))))
	if err != nil {
		t.Fatalf("PasskeyLoginFinish: %v", err)
	}
	return e.cookie(in.Token)
}

// closing is a scenario whose request is built, then the Service closes.
func closing(opts envOptions, build func(t *testing.T, e *env) *http.Request) scenario {
	return scenario{opts: opts, arrange: func(t *testing.T, e *env) *http.Request {
		r := build(t, e)
		e.shutdown(t)
		return r
	}}
}

// ssoGoverned governs linked accounts by SSO.
var ssoGoverned = envOptions{rules: func(r *account.Rules) { r.SSOGoverned = true }}

// passwordUnusable makes MethodUsable answer false for the password.
var passwordUnusable = envOptions{rules: func(r *account.Rules) {
	r.MethodUsable = func(_ context.Context, _ account.Tx, _ *access.User, m access.Method) bool {
		return m != access.MethodPassword
	}
}}

func selfScenarios() map[scenarioKey]scenario {
	out := map[scenarioKey]scenario{}
	addAccountScenarios(out)
	addPasswordScenarios(out)
	addPasskeyScenarios(out)
	addSessionScenarios(out)
	addKeyScenarios(out)
	return out
}

func addAccountScenarios(out map[scenarioKey]scenario) {
	profile := func(t *testing.T, name string) string {
		t.Helper()
		return jsonBody(t, ProfileRequest{DisplayName: name})
	}
	out[scenarioKey{"authMe", access.CodeSessionExpired}] = scenario{opts: vanishes, arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, "authMe", "", e.aliceSession(t))
	}}
	out[scenarioKey{"authMe", access.CodeUnavailable}] = closing(envOptions{}, func(t *testing.T, e *env) *http.Request {
		return e.post(t, "authMe", "", e.aliceSession(t))
	})

	out[scenarioKey{"authProfile", access.CodeSessionExpired}] = scenario{opts: vanishes, arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, "authProfile", profile(t, "Alice"), e.aliceSession(t))
	}}
	out[scenarioKey{"authProfile", access.CodeUnavailable}] = closing(envOptions{}, func(t *testing.T, e *env) *http.Request {
		return e.post(t, "authProfile", profile(t, "Alice"), e.aliceSession(t))
	})
	out[scenarioKey{"authProfile", access.CodeBadRequest}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, "authProfile", profile(t, "two\nlines"), e.aliceSession(t))
	}}

	const reenable = "authMethodReenable"
	out[scenarioKey{reenable, access.CodeRecentAuthRequired}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.at(t, reenable, string(access.MethodPassword), "", e.aliceSession(t))
	}}
	out[scenarioKey{reenable, access.CodeUnavailable}] = closing(envOptions{}, func(t *testing.T, e *env) *http.Request {
		return e.at(t, reenable, string(access.MethodPasskey), "", e.aliceSession(t))
	})
	out[scenarioKey{reenable, access.CodeMethodNotLocked}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.at(t, reenable, string(access.MethodPasskey), "", e.aliceSession(t))
	}}

	const stepUp = "authStepUpPassword"
	stepUpBody := func(t *testing.T, password string) string {
		t.Helper()
		return jsonBody(t, PasswordRequest{Password: password})
	}
	disabled := &atomic.Bool{}
	out[scenarioKey{stepUp, access.CodeInvalidCredentials}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, stepUp, stepUpBody(t, "not-"+testPassword), e.aliceSession(t))
	}}
	out[scenarioKey{stepUp, access.CodeRateLimited}] = scenario{opts: trustLimits, arrange: func(t *testing.T, e *env) *http.Request {
		r := e.post(t, stepUp, stepUpBody(t, testPassword), e.aliceSession(t))
		e.spendAccount(t, "alice")
		return r
	}}
	out[scenarioKey{stepUp, access.CodeBusy}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		r := e.post(t, stepUp, stepUpBody(t, testPassword), e.aliceSession(t))
		e.holdBudget(t)
		return r
	}}
	out[scenarioKey{stepUp, access.CodeUnavailable}] = closing(envOptions{}, func(t *testing.T, e *env) *http.Request {
		return e.post(t, stepUp, stepUpBody(t, testPassword), e.aliceSession(t))
	})
	out[scenarioKey{stepUp, access.CodePasswordLoginDisabled}] = scenario{
		opts: envOptions{rules: func(r *account.Rules) { r.DisablePasswordLogin = disabled.Load() }},
		arrange: func(t *testing.T, e *env) *http.Request {
			r := e.post(t, stepUp, stepUpBody(t, testPassword), e.aliceSession(t))
			disabled.Store(true)
			return r
		},
	}
	out[scenarioKey{stepUp, access.CodeSessionExpired}] = scenario{opts: ends, arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, stepUp, stepUpBody(t, testPassword), e.aliceSession(t))
	}}
}

func passwordSetBody(t testing.TB, current, password string) string {
	t.Helper()
	return jsonBody(t, PasswordChangeRequest{CurrentPassword: current, Password: password})
}

func passwordRemoveBody(t testing.TB, current string) string {
	t.Helper()
	return jsonBody(t, PasswordRemoveRequest{CurrentPassword: current})
}

func addPasswordScenarios(out map[scenarioKey]scenario) {
	const set = "authPasswordSet"
	change := func(t *testing.T, e *env) *http.Request {
		return e.post(t, set, passwordSetBody(t, testPassword, newPassword), e.aliceSession(t))
	}
	out[scenarioKey{set, access.CodeInvalidCredentials}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, set, passwordSetBody(t, "not-"+testPassword, newPassword), e.aliceSession(t))
	}}
	out[scenarioKey{set, access.CodeForbidden}] = scenario{opts: ssoGoverned, arrange: func(t *testing.T, e *env) *http.Request {
		r := change(t, e)
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		return r
	}}
	out[scenarioKey{set, access.CodeRateLimited}] = scenario{opts: trustLimits, arrange: func(t *testing.T, e *env) *http.Request {
		r := change(t, e)
		e.spendAccount(t, "alice")
		return r
	}}
	out[scenarioKey{set, access.CodeBusy}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		r := change(t, e)
		e.holdBudget(t)
		return r
	}}
	out[scenarioKey{set, access.CodeUnavailable}] = closing(envOptions{}, change)
	out[scenarioKey{set, access.CodeBadRequest}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, set, passwordSetBody(t, "", newPassword), e.aliceSession(t))
	}}
	out[scenarioKey{set, access.CodePasswordRejected}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, set, passwordSetBody(t, testPassword, "short"), e.aliceSession(t))
	}}
	out[scenarioKey{set, access.CodeBreachCheckUnavailable}] = scenario{opts: breachDown, arrange: change}
	out[scenarioKey{set, access.CodeSessionExpired}] = scenario{opts: vanishes, arrange: change}

	const remove = "authPasswordRemove"
	// withPasskey is alice's removal with a passkey left to sign in with.
	withPasskey := func(t *testing.T, e *env, current string) *http.Request {
		cookie := e.aliceSession(t)
		e.enrol(t, "alice")
		return e.post(t, remove, passwordRemoveBody(t, current), cookie)
	}
	right := func(t *testing.T, e *env) *http.Request { return withPasskey(t, e, testPassword) }
	out[scenarioKey{remove, access.CodeInvalidCredentials}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		return withPasskey(t, e, "not-"+testPassword)
	}}
	out[scenarioKey{remove, access.CodeRateLimited}] = scenario{opts: with(passkeys, trustLimits), arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		e.spendAccount(t, "alice")
		return r
	}}
	out[scenarioKey{remove, access.CodeBusy}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		e.holdBudget(t)
		return r
	}}
	out[scenarioKey{remove, access.CodeUnavailable}] = closing(passkeys, right)
	out[scenarioKey{remove, access.CodeBadRequest}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		return withPasskey(t, e, "")
	}}
	out[scenarioKey{remove, access.CodeLastMethod}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, remove, passwordRemoveBody(t, testPassword), e.aliceSession(t))
	}}
	out[scenarioKey{remove, access.CodeNotFound}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		u := e.user(t, "alice")
		u.PasswordHash = access.Hash{}
		if err := e.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		return r
	}}
	out[scenarioKey{remove, access.CodeSessionExpired}] = scenario{opts: with(passkeys, vanishes), arrange: right}
}

func addPasskeyScenarios(out map[scenarioKey]scenario) {
	const stepUpBegin, stepUpFinish = "authStepUpPasskeyBegin", "authStepUpPasskeyFinish"
	// enrolled is alice's password session with a passkey enrolled.
	enrolled := func(t *testing.T, e *env) (*http.Cookie, *accesstest.PasskeyDevice) {
		cookie := e.aliceSession(t)
		return cookie, e.enrol(t, "alice")
	}
	beginWith := func(t *testing.T, e *env) *http.Request {
		cookie, _ := enrolled(t, e)
		return e.post(t, stepUpBegin, "", cookie)
	}
	out[scenarioKey{stepUpBegin, access.CodeSessionExpired}] = scenario{opts: with(passkeys, vanishes), arrange: beginWith}
	out[scenarioKey{stepUpBegin, access.CodeUnavailable}] = closing(passkeys, beginWith)
	out[scenarioKey{stepUpBegin, access.CodePasskeysUnavailable}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, stepUpBegin, "", e.aliceSession(t))
	}}
	out[scenarioKey{stepUpBegin, access.CodeOriginRefused}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		return fromOrigin(beginWith(t, e), evilOrigin)
	}}
	out[scenarioKey{stepUpBegin, access.CodeNotFound}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, stepUpBegin, "", e.aliceSession(t))
	}}

	finishWith := func(edit func([]byte) []byte, between func(t *testing.T, e *env)) func(t *testing.T, e *env) *http.Request {
		return func(t *testing.T, e *env) *http.Request {
			cookie, dev := enrolled(t, e)
			return e.stepUpFinish(t, cookie, dev, edit, func() {
				if between != nil {
					between(t, e)
				}
			})
		}
	}
	out[scenarioKey{stepUpFinish, access.CodeSessionExpired}] = scenario{opts: with(passkeys, vanishes), arrange: finishWith(nil, nil)}
	out[scenarioKey{stepUpFinish, access.CodeUnavailable}] = scenario{opts: passkeys, arrange: finishWith(nil, func(t *testing.T, e *env) { e.shutdown(t) })}
	out[scenarioKey{stepUpFinish, access.CodePasskeysUnavailable}] = scenario{opts: passkeys, arrange: finishWith(nil, func(_ *testing.T, e *env) { e.rp.Store(nil) })}
	out[scenarioKey{stepUpFinish, access.CodeCeremonyInvalid}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		r := finishWith(nil, nil)(t, e)
		r.Header.Set(ceremonyHeader, "not-a-ceremony")
		return r
	}}
	out[scenarioKey{stepUpFinish, access.CodeUnknownCredential}] = scenario{opts: passkeys, arrange: finishWith(nil, func(t *testing.T, e *env) {
		u := e.user(t, "alice")
		if err := e.mem.DeletePasskey(t.Context(), access.PasskeyRef{ID: e.passkeyID(t, "alice"), UserID: u.ID}); err != nil {
			t.Fatalf("DeletePasskey: %v", err)
		}
	})}
	out[scenarioKey{stepUpFinish, access.CodeAssertionFailed}] = scenario{opts: passkeys, arrange: finishWith(func([]byte) []byte { return []byte(`{}`) }, nil)}

	addEnrolmentScenarios(out)

	const rename, removeKey, signals = "authPasskeyRename", "authPasskeyRemove", "authWebAuthnSignals"
	nameBody := func(t *testing.T, name string) string {
		t.Helper()
		return jsonBody(t, NameRequest{Name: name})
	}
	renameOwn := func(t *testing.T, e *env, name string) *http.Request {
		cookie, _ := enrolled(t, e)
		return e.at(t, rename, strconv.FormatInt(e.passkeyID(t, "alice"), 10), nameBody(t, name), cookie)
	}
	out[scenarioKey{rename, access.CodeUnavailable}] = closing(passkeys, func(t *testing.T, e *env) *http.Request { return renameOwn(t, e, "laptop") })
	out[scenarioKey{rename, access.CodeBadRequest}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request { return renameOwn(t, e, "two\nlines") }}
	out[scenarioKey{rename, access.CodeNotFound}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.at(t, rename, "1", nameBody(t, "laptop"), e.aliceSession(t))
	}}

	removeOwn := func(t *testing.T, e *env) *http.Request {
		cookie, _ := enrolled(t, e)
		return e.at(t, removeKey, strconv.FormatInt(e.passkeyID(t, "alice"), 10), "", cookie)
	}
	out[scenarioKey{removeKey, access.CodeSessionExpired}] = scenario{opts: with(passkeys, vanishes), arrange: removeOwn}
	out[scenarioKey{removeKey, access.CodeUnavailable}] = closing(passkeys, removeOwn)
	out[scenarioKey{removeKey, access.CodeLastMethod}] = scenario{opts: with(passkeys, passwordUnusable), arrange: removeOwn}
	out[scenarioKey{removeKey, access.CodeNotFound}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.at(t, removeKey, "1", "", e.aliceSession(t))
	}}

	signalsOf := func(t *testing.T, e *env) *http.Request { return e.post(t, signals, "", e.aliceSession(t)) }
	out[scenarioKey{signals, access.CodeSessionExpired}] = scenario{opts: with(passkeys, vanishes), arrange: signalsOf}
	out[scenarioKey{signals, access.CodeUnavailable}] = closing(passkeys, signalsOf)
	out[scenarioKey{signals, access.CodePasskeysUnavailable}] = scenario{arrange: signalsOf}

	out[scenarioKey{"authPasskeys", access.CodeUnavailable}] = closing(envOptions{}, func(t *testing.T, e *env) *http.Request {
		return e.post(t, "authPasskeys", "", e.aliceSession(t))
	})
}

func addEnrolmentScenarios(out map[scenarioKey]scenario) {
	const begin, finishRoute = "authPasskeyRegisterBegin", "authPasskeyRegisterFinish"
	beginOwn := func(t *testing.T, e *env) *http.Request { return e.post(t, begin, "", e.aliceSession(t)) }
	out[scenarioKey{begin, access.CodeSessionExpired}] = scenario{opts: with(passkeys, vanishes), arrange: beginOwn}
	out[scenarioKey{begin, access.CodeForbidden}] = scenario{opts: with(passkeys, ssoGoverned), arrange: func(t *testing.T, e *env) *http.Request {
		r := beginOwn(t, e)
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		return r
	}}
	out[scenarioKey{begin, access.CodeUnavailable}] = closing(passkeys, beginOwn)
	out[scenarioKey{begin, access.CodePasskeysUnavailable}] = scenario{arrange: beginOwn}
	out[scenarioKey{begin, access.CodeOriginRefused}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		return fromOrigin(beginOwn(t, e), evilOrigin)
	}}

	finishOwn := func(dev func(t *testing.T, e *env) *accesstest.PasskeyDevice, edit func(t *testing.T, b []byte) []byte, between func(t *testing.T, e *env)) func(t *testing.T, e *env) *http.Request {
		return func(t *testing.T, e *env) *http.Request {
			cookie := e.aliceSession(t)
			var d *accesstest.PasskeyDevice
			if dev != nil {
				d = dev(t, e)
			}
			var ed func([]byte) []byte
			if edit != nil {
				ed = func(b []byte) []byte { return edit(t, b) }
			}
			return e.registerFinish(t, cookie, d, ed, func() {
				if between != nil {
					between(t, e)
				}
			})
		}
	}
	out[scenarioKey{finishRoute, access.CodeSessionExpired}] = scenario{opts: with(passkeys, vanishes), arrange: finishOwn(nil, nil, nil)}
	out[scenarioKey{finishRoute, access.CodeForbidden}] = scenario{opts: with(passkeys, ssoGoverned), arrange: finishOwn(nil, nil, func(t *testing.T, e *env) {
		e.linkUser(t, "alice", idpIdentity(testIssuer))
	})}
	out[scenarioKey{finishRoute, access.CodeUnavailable}] = scenario{opts: passkeys, arrange: finishOwn(nil, nil, func(t *testing.T, e *env) { e.shutdown(t) })}
	out[scenarioKey{finishRoute, access.CodeDuplicateCredential}] = scenario{opts: passkeys, arrange: finishOwn(func(t *testing.T, e *env) *accesstest.PasskeyDevice {
		e.createUser(t, "root", access.RoleAdmin)
		return e.enrol(t, "root")
	}, nil, nil)}
	out[scenarioKey{finishRoute, access.CodePasskeysUnavailable}] = scenario{opts: passkeys, arrange: finishOwn(nil, nil, func(_ *testing.T, e *env) { e.rp.Store(nil) })}
	out[scenarioKey{finishRoute, access.CodeCeremonyInvalid}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		r := finishOwn(nil, nil, nil)(t, e)
		r.Header.Set(ceremonyHeader, "not-a-ceremony")
		return r
	}}
	out[scenarioKey{finishRoute, access.CodeNotDiscoverable}] = scenario{opts: passkeys, arrange: finishOwn(nil, func(t *testing.T, b []byte) []byte { return notDiscoverable(t, b) }, nil)}
	out[scenarioKey{finishRoute, access.CodeRegistrationFailed}] = scenario{opts: passkeys, arrange: finishOwn(nil, func(*testing.T, []byte) []byte { return []byte(`{}`) }, nil)}
}

func addSessionScenarios(out map[scenarioKey]scenario) {
	const rename, revoke = "authSessionRename", "authSessionRevoke"
	nameOwn := func(t *testing.T, e *env, label string) *http.Request {
		cookie := e.aliceSession(t)
		return e.at(t, rename, e.sessionIDOf(t, cookie), jsonBody(t, NameRequest{Name: label}), cookie)
	}
	out[scenarioKey{rename, access.CodeUnavailable}] = closing(envOptions{}, func(t *testing.T, e *env) *http.Request { return nameOwn(t, e, "laptop") })
	out[scenarioKey{rename, access.CodeBadRequest}] = scenario{arrange: func(t *testing.T, e *env) *http.Request { return nameOwn(t, e, "two\nlines") }}
	out[scenarioKey{rename, access.CodeNotFound}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.at(t, rename, otherSessionID, jsonBody(t, NameRequest{Name: "laptop"}), e.aliceSession(t))
	}}
	out[scenarioKey{revoke, access.CodeUnavailable}] = closing(envOptions{}, func(t *testing.T, e *env) *http.Request {
		cookie := e.aliceSession(t)
		return e.at(t, revoke, e.sessionIDOf(t, cookie), "", cookie)
	})
	out[scenarioKey{revoke, access.CodeNotFound}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.at(t, revoke, otherSessionID, "", e.aliceSession(t))
	}}
	out[scenarioKey{"authSessions", access.CodeUnavailable}] = closing(envOptions{}, func(t *testing.T, e *env) *http.Request {
		return e.post(t, "authSessions", "", e.aliceSession(t))
	})
	out[scenarioKey{"authSessionsRevokeOthers", access.CodeUnavailable}] = closing(envOptions{}, func(t *testing.T, e *env) *http.Request {
		return e.post(t, "authSessionsRevokeOthers", "", e.aliceSession(t))
	})
}

func keyBody(t testing.TB, label string, scopes ...string) string {
	t.Helper()
	return jsonBody(t, NewKeyRequest{Label: label, Scopes: scopes})
}

func addKeyScenarios(out map[scenarioKey]scenario) {
	const create, rename, rotate, revoke = "authKeyCreate", "authKeyRename", "authKeyRotate", "authKeyRevoke"
	mint := func(t *testing.T, e *env) *http.Request {
		return e.post(t, create, keyBody(t, "ci"), e.aliceSession(t))
	}
	out[scenarioKey{create, access.CodeSessionExpired}] = scenario{opts: ends, arrange: mint}
	out[scenarioKey{create, access.CodeForbidden}] = scenario{opts: envOptions{edit: refuse(account.OpCreateOwnKey)}, arrange: mint}
	out[scenarioKey{create, access.CodeUnavailable}] = closing(envOptions{}, mint)
	out[scenarioKey{create, access.CodeBadRequest}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, create, keyBody(t, "two\nlines"), e.aliceSession(t))
	}}
	out[scenarioKey{create, access.CodeKeyLabelTaken}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		cookie := e.aliceSession(t)
		e.mintKey(t, "alice", account.NewKey{Label: "ci"})
		return e.post(t, create, keyBody(t, "CI"), cookie)
	}}
	out[scenarioKey{create, access.CodeUnknownScope}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, create, keyBody(t, "ci", "unlisted"), e.aliceSession(t))
	}}
	renameOwn := func(name string) func(t *testing.T, e *env) *http.Request {
		return func(t *testing.T, e *env) *http.Request {
			cookie := e.aliceSession(t)
			e.mintKey(t, "alice", account.NewKey{Label: "Agent"})
			k := e.mintKey(t, "alice", account.NewKey{Label: "ci"})
			return e.at(t, rename, strconv.FormatInt(k.Key.ID, 10), jsonBody(t, NameRequest{Name: name}), cookie)
		}
	}
	out[scenarioKey{rename, access.CodeUnavailable}] = closing(envOptions{}, renameOwn("deploy"))
	out[scenarioKey{rename, access.CodeBadRequest}] = scenario{arrange: renameOwn("two\nlines")}
	out[scenarioKey{rename, access.CodeKeyLabelTaken}] = scenario{arrange: renameOwn("agent")}
	out[scenarioKey{rename, access.CodeNotFound}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.at(t, rename, "1", jsonBody(t, NameRequest{Name: "deploy"}), e.aliceSession(t))
	}}
	rotateOwn := func(t *testing.T, e *env) *http.Request {
		cookie := e.aliceSession(t)
		k := e.mintKey(t, "alice", account.NewKey{Label: "ci"})
		return e.at(t, rotate, strconv.FormatInt(k.Key.ID, 10), "", cookie)
	}
	out[scenarioKey{rotate, access.CodeSessionExpired}] = scenario{opts: ends, arrange: rotateOwn}
	out[scenarioKey{rotate, access.CodeForbidden}] = scenario{opts: envOptions{edit: refuse(account.OpRotateKey)}, arrange: rotateOwn}
	out[scenarioKey{rotate, access.CodeUnavailable}] = closing(envOptions{}, rotateOwn)
	out[scenarioKey{rotate, access.CodeNotFound}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.at(t, rotate, "1", "", e.aliceSession(t))
	}}
	out[scenarioKey{revoke, access.CodeUnavailable}] = closing(envOptions{}, func(t *testing.T, e *env) *http.Request {
		return e.at(t, revoke, "1", "", e.aliceSession(t))
	})
	out[scenarioKey{revoke, access.CodeNotFound}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.at(t, revoke, "1", "", e.aliceSession(t))
	}}
	out[scenarioKey{"authKeys", access.CodeUnavailable}] = closing(envOptions{}, func(t *testing.T, e *env) *http.Request {
		return e.post(t, "authKeys", "", e.aliceSession(t))
	})
}
