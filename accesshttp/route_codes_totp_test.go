package accesshttp

import (
	"cmp"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/totp"
)

// giveTOTP stores a TOTP record for name, its secret sealed under sealer
// with design 4.3's purpose, and returns the secret.
func (e *env) giveTOTP(t testing.TB, name string, sealer *access.Sealer) []byte {
	t.Helper()
	u := e.user(t, name)
	secret := totp.NewSecret()
	sealed, err := sealer.SealAtRest("totp:"+strconv.FormatInt(u.ID, 10), secret)
	if err != nil {
		t.Fatalf("SealAtRest: %v", err)
	}
	created := time.Now().Add(-time.Minute) // before any enrolment the test then begins
	if err := e.mem.SetTOTP(t.Context(), access.TOTP{UserID: u.ID, Sealed: sealed, CreatedAt: created}); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	return secret
}

// giveRecoveryCode stores a recovery code record for name; nothing here
// opens it.
func (e *env) giveRecoveryCode(t testing.TB, name string) {
	t.Helper()
	if err := e.mem.SetRecoveryCode(t.Context(), access.RecoveryCode{UserID: e.user(t, name).ID, Hash: access.NewHash("recovery"), CreatedAt: time.Now()}); err != nil {
		t.Fatalf("SetRecoveryCode: %v", err)
	}
}

// unpaddedBase32 is RFC 4648 §6 base32 with no padding, the otpauth
// secret's encoding.
var unpaddedBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// codeNow is secret's code for the current RFC 6238 step.
func codeNow(secret []byte) string { return totp.Code(secret, totp.Step(time.Now())) }

// wrongCode is a well-formed code of secret far outside the window.
func wrongCode(secret []byte) string {
	return totp.Code(secret, totp.Step(time.Now().Add(-20*totp.Period)))
}

// pendingTicket is name's pending sign-in after a correct password, which
// a TOTP record or the rule makes pend.
func (e *env) pendingTicket(t testing.TB, name string) string {
	t.Helper()
	out, err := e.svc.PasswordLogin(t.Context(), account.Client{Secure: true}, account.Credentials{Username: name, Password: access.NewSecret(testPassword)})
	if err != nil || out.Pending == nil {
		t.Fatalf("PasswordLogin(%s) = %v, want a pending sign-in", name, err)
	}
	return out.Pending.Ticket.Reveal()
}

// setUser edits name as stored.
func (e *env) setUser(t testing.TB, name string, edit func(*access.User)) {
	t.Helper()
	u := e.user(t, name)
	edit(u)
	if err := e.mem.UpdateUser(t.Context(), u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

// proofBody is a SecondFactorProof body.
func proofBody(t testing.TB, p SecondFactorProof) string {
	t.Helper()
	return jsonBody(t, p)
}

// assertionProof begins a passkey step-up for cookie's session and answers
// the proof body dev's assertion makes for it.
func (e *env) assertionProof(t testing.TB, cookie *http.Cookie, dev *accesstest.PasskeyDevice) string {
	t.Helper()
	pc, err := e.svc.StepUpPasskeyBegin(t.Context(), e.principal(t, cookie), testOriginOf(t))
	if err != nil {
		t.Fatalf("StepUpPasskeyBegin: %v", err)
	}
	return proofBody(t, SecondFactorProof{Ceremony: pc.ID, Assertion: json.RawMessage(dev.Assert(jsonBytes(t, pc.Assertion)))})
}

// recentSession stores name, a RoleUser, with a password session signed in
// now, which no sign-in rule can turn into a pending sign-in.
func (e *env) recentSession(t testing.TB, name string) *http.Cookie {
	t.Helper()
	e.createUser(t, name, access.RoleUser)
	return e.storedSession(t, name, 0, 0)
}

// flag is a rules edit that turns on when its atomic does.
func flag(f *atomic.Bool, set func(*account.Rules)) envOptions {
	return envOptions{rules: func(r *account.Rules) {
		if f.Load() {
			set(r)
		}
	}}
}

func totpScenarios() map[scenarioKey]scenario {
	out := map[scenarioKey]scenario{}
	addCodeStepScenarios(out)
	addSecondPasskeyScenarios(out)
	addStepUpCodeScenarios(out)
	addTOTPEnrolScenarios(out)
	addTOTPRemoveScenarios(out)
	addRecoveryCodeScenarios(out)
	addProofScenarios(out)
	out[scenarioKey{"authStepUpPassword", access.CodeSecondFactorRequired}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		cookie := e.aliceSession(t)
		e.giveTOTP(t, "alice", e.sealer)
		return e.post(t, "authStepUpPassword", jsonBody(t, PasswordRequest{Password: testPassword}), cookie)
	}}
	out[scenarioKey{"authPasskeys", access.CodeSessionExpired}] = scenario{opts: vanishes, arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, "authPasskeys", "", e.aliceSession(t))
	}}
	return out
}

func addCodeStepScenarios(out map[scenarioKey]scenario) {
	const route = "authLoginCode"
	type made struct {
		ticket string
		secret []byte
	}
	ready := func(t *testing.T, e *env) made {
		e.createUser(t, "alice", access.RoleUser)
		secret := e.giveTOTP(t, "alice", e.sealer)
		return made{ticket: e.pendingTicket(t, "alice"), secret: secret}
	}
	post := func(t *testing.T, e *env, ticket, code string) *http.Request {
		return e.post(t, route, jsonBody(t, CodeRequest{Ticket: ticket, Code: code}))
	}
	out[scenarioKey{route, access.CodeRateLimited}] = scenario{opts: with(totpOn, trustLimits), arrange: func(t *testing.T, e *env) *http.Request {
		m := ready(t, e)
		e.spendAccount(t, "alice")
		return post(t, e, m.ticket, codeNow(m.secret))
	}}
	out[scenarioKey{route, access.CodeUnavailable}] = closing(totpOn, func(t *testing.T, e *env) *http.Request {
		m := ready(t, e)
		return post(t, e, m.ticket, codeNow(m.secret))
	})
	out[scenarioKey{route, access.CodeBadRequest}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return post(t, e, ready(t, e).ticket, "12 34")
	}}
	out[scenarioKey{route, access.CodeTokenInvalid}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return post(t, e, "not-a-ticket", "123456")
	}}
	out[scenarioKey{route, access.CodeCodeInvalid}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		m := ready(t, e)
		return post(t, e, m.ticket, wrongCode(m.secret))
	}}
	out[scenarioKey{route, access.CodeSecondFactorUnavailable}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		e.createUser(t, "alice", access.RoleUser)
		secret := e.giveTOTP(t, "alice", access.NewEphemeralSealer())
		return post(t, e, e.pendingTicket(t, "alice"), codeNow(secret))
	}}
	off := &atomic.Bool{}
	out[scenarioKey{route, access.CodeTOTPDisabled}] = scenario{opts: with(totpOn, flag(off, func(r *account.Rules) { r.DisableTOTP = true })), arrange: func(t *testing.T, e *env) *http.Request {
		m := ready(t, e)
		off.Store(true)
		return post(t, e, m.ticket, codeNow(m.secret))
	}}
}

func addSecondPasskeyScenarios(out map[scenarioKey]scenario) {
	const begin, finishRoute = "authLoginSecondPasskeyBegin", "authLoginSecondPasskeyFinish"
	// ready is alice's ticket listing passkey, with her device.
	ready := func(t *testing.T, e *env) (string, *accesstest.PasskeyDevice) {
		e.createUser(t, "alice", access.RoleUser)
		dev := e.enrol(t, "alice")
		e.giveTOTP(t, "alice", e.sealer)
		return e.pendingTicket(t, "alice"), dev
	}
	beginOf := func(t *testing.T, e *env, ticket string) *http.Request {
		return e.post(t, begin, jsonBody(t, TicketRequest{Ticket: ticket}))
	}
	opts := with(passkeys, totpOn)
	out[scenarioKey{begin, access.CodeRateLimited}] = scenario{opts: with(opts, limited), arrange: func(t *testing.T, e *env) *http.Request {
		ticket, _ := ready(t, e)
		e.spendRequest(t)
		return beginOf(t, e, ticket)
	}}
	out[scenarioKey{begin, access.CodeUnavailable}] = closing(opts, func(t *testing.T, e *env) *http.Request {
		ticket, _ := ready(t, e)
		return beginOf(t, e, ticket)
	})
	out[scenarioKey{begin, access.CodeTokenInvalid}] = scenario{opts: opts, arrange: func(t *testing.T, e *env) *http.Request {
		return beginOf(t, e, "not-a-ticket")
	}}
	out[scenarioKey{begin, access.CodePasskeysUnavailable}] = scenario{opts: opts, arrange: func(t *testing.T, e *env) *http.Request {
		ticket, _ := ready(t, e)
		e.rp.Store(nil)
		return beginOf(t, e, ticket)
	}}
	out[scenarioKey{begin, access.CodeOriginRefused}] = scenario{opts: opts, arrange: func(t *testing.T, e *env) *http.Request {
		ticket, _ := ready(t, e)
		return fromOrigin(beginOf(t, e, ticket), evilOrigin)
	}}

	// finishWith begins alice's second step through the Service, then runs
	// between and answers the finish request with her assertion, edited.
	finishWith := func(edit func([]byte) []byte, between func(t *testing.T, e *env)) func(t *testing.T, e *env) *http.Request {
		return func(t *testing.T, e *env) *http.Request {
			ticket, dev := ready(t, e)
			pc, err := e.svc.SecondFactorPasskeyBegin(t.Context(), account.Client{Secure: true}, access.NewSecret(ticket), testOriginOf(t))
			if err != nil {
				t.Fatalf("SecondFactorPasskeyBegin: %v", err)
			}
			body := dev.Assert(jsonBytes(t, pc.Assertion))
			if edit != nil {
				body = edit(body)
			}
			if between != nil {
				between(t, e)
			}
			return finish(e.route(t, finishRoute), pc.ID, body)
		}
	}
	out[scenarioKey{finishRoute, access.CodeRateLimited}] = scenario{opts: with(opts, trustLimits), arrange: finishWith(nil, func(t *testing.T, e *env) { e.spendAccount(t, "alice") })}
	out[scenarioKey{finishRoute, access.CodeUnavailable}] = scenario{opts: opts, arrange: finishWith(nil, func(t *testing.T, e *env) { e.shutdown(t) })}
	out[scenarioKey{finishRoute, access.CodeTokenInvalid}] = scenario{opts: opts, arrange: finishWith(nil, func(t *testing.T, e *env) {
		e.setUser(t, "alice", func(u *access.User) { u.Enabled = false })
	})}
	out[scenarioKey{finishRoute, access.CodePasskeysUnavailable}] = scenario{opts: opts, arrange: finishWith(nil, func(_ *testing.T, e *env) { e.rp.Store(nil) })}
	out[scenarioKey{finishRoute, access.CodeCeremonyInvalid}] = scenario{opts: opts, arrange: func(t *testing.T, e *env) *http.Request {
		r := finishWith(nil, nil)(t, e)
		r.Header.Set(ceremonyHeader, "not-a-ceremony")
		return r
	}}
	out[scenarioKey{finishRoute, access.CodeUnknownCredential}] = scenario{opts: opts, arrange: finishWith(nil, func(t *testing.T, e *env) {
		if err := e.mem.DeletePasskey(t.Context(), access.PasskeyRef{ID: e.passkeyID(t, "alice"), UserID: e.user(t, "alice").ID}); err != nil {
			t.Fatalf("DeletePasskey: %v", err)
		}
	})}
	out[scenarioKey{finishRoute, access.CodeAssertionFailed}] = scenario{opts: opts, arrange: finishWith(func([]byte) []byte { return []byte(`{}`) }, nil)}
}

func addStepUpCodeScenarios(out map[scenarioKey]scenario) {
	const route = "authStepUpCode"
	// ready is alice's session with a TOTP record sealed under sealer.
	ready := func(t *testing.T, e *env, sealer *access.Sealer) (*http.Cookie, []byte) {
		cookie := e.aliceSession(t)
		if sealer == nil {
			sealer = e.sealer
		}
		return cookie, e.giveTOTP(t, "alice", sealer)
	}
	post := func(t *testing.T, e *env, cookie *http.Cookie, code string) *http.Request {
		return e.post(t, route, jsonBody(t, StepUpCodeRequest{Code: code}), cookie)
	}
	right := func(t *testing.T, e *env) *http.Request {
		cookie, secret := ready(t, e, nil)
		return post(t, e, cookie, codeNow(secret))
	}
	out[scenarioKey{route, access.CodeSessionExpired}] = scenario{opts: with(totpOn, vanishes), arrange: right}
	out[scenarioKey{route, access.CodeRateLimited}] = scenario{opts: with(totpOn, trustLimits), arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		e.spendAccount(t, "alice")
		return r
	}}
	out[scenarioKey{route, access.CodeUnavailable}] = closing(totpOn, right)
	out[scenarioKey{route, access.CodeBadRequest}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		cookie, _ := ready(t, e, nil)
		return post(t, e, cookie, "1234567")
	}}
	out[scenarioKey{route, access.CodeCodeInvalid}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		cookie, secret := ready(t, e, nil)
		return post(t, e, cookie, wrongCode(secret))
	}}
	out[scenarioKey{route, access.CodeSecondFactorUnavailable}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		cookie, secret := ready(t, e, access.NewEphemeralSealer())
		return post(t, e, cookie, codeNow(secret))
	}}
	out[scenarioKey{route, access.CodeTOTPDisabled}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return post(t, e, e.aliceSession(t), "123456")
	}}
	out[scenarioKey{route, access.CodeSSOOnly}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		e.keepDormant(t, "alice")
		return r
	}}
}

func addTOTPEnrolScenarios(out map[scenarioKey]scenario) {
	const begin, finishRoute = "authTOTPBegin", "authTOTPFinish"
	beginOwn := func(t *testing.T, e *env) *http.Request { return e.post(t, begin, "", e.aliceSession(t)) }
	noPassword := func(t *testing.T, e *env) {
		e.setUser(t, "alice", func(u *access.User) { u.PasswordHash = access.Hash{} })
	}
	out[scenarioKey{begin, access.CodeSessionExpired}] = scenario{opts: with(totpOn, vanishes), arrange: beginOwn}
	out[scenarioKey{begin, access.CodeForbidden}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		r := beginOwn(t, e)
		noPassword(t, e)
		return r
	}}
	out[scenarioKey{begin, access.CodeUnavailable}] = closing(totpOn, beginOwn)
	out[scenarioKey{begin, access.CodeTOTPDisabled}] = scenario{arrange: beginOwn}
	out[scenarioKey{begin, access.CodeSSOOnly}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		r := beginOwn(t, e)
		e.keepDormant(t, "alice")
		return r
	}}

	// enrolment begins alice's enrolment through the Service, under a
	// session with an old record sealed under old when it is set.
	type enrolment struct {
		cookie       *http.Cookie
		ticket       string
		secret, prev []byte
	}
	enrolOf := func(t *testing.T, e *env, old *access.Sealer) enrolment {
		cookie := e.aliceSession(t)
		var prev []byte
		if old != nil {
			prev = e.giveTOTP(t, "alice", old)
		}
		en, err := e.svc.BeginTOTP(t.Context(), e.principal(t, cookie))
		if err != nil {
			t.Fatalf("BeginTOTP: %v", err)
		}
		u, err := url.Parse(en.URI.Reveal())
		if err != nil {
			t.Fatalf("the enrolment URI does not parse: %v", err)
		}
		secret, err := unpaddedBase32.DecodeString(u.Query().Get("secret"))
		if err != nil {
			t.Fatalf("the URI's secret is not RFC 4648 base32: %v", err)
		}
		return enrolment{cookie: cookie, ticket: en.Ticket.Reveal(), secret: secret, prev: prev}
	}
	post := func(t *testing.T, e *env, en enrolment, in TOTPFinishRequest) *http.Request {
		in.Ticket = cmp.Or(in.Ticket, en.ticket)
		return e.post(t, finishRoute, jsonBody(t, in), en.cookie)
	}
	right := func(t *testing.T, e *env) *http.Request {
		en := enrolOf(t, e, nil)
		return post(t, e, en, TOTPFinishRequest{Code: codeNow(en.secret)})
	}
	out[scenarioKey{finishRoute, access.CodeSessionExpired}] = scenario{opts: with(totpOn, vanishes), arrange: right}
	out[scenarioKey{finishRoute, access.CodeForbidden}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		noPassword(t, e)
		return r
	}}
	out[scenarioKey{finishRoute, access.CodeRateLimited}] = scenario{opts: with(totpOn, trustLimits), arrange: func(t *testing.T, e *env) *http.Request {
		en := enrolOf(t, e, e.sealer)
		e.spendAccount(t, "alice")
		return post(t, e, en, TOTPFinishRequest{Code: codeNow(en.secret), CurrentCode: codeNow(en.prev)})
	}}
	out[scenarioKey{finishRoute, access.CodeBusy}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		e.holdBudget(t)
		return r
	}}
	out[scenarioKey{finishRoute, access.CodeUnavailable}] = closing(totpOn, right)
	out[scenarioKey{finishRoute, access.CodeBadRequest}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return post(t, e, enrolOf(t, e, nil), TOTPFinishRequest{Code: "abc"})
	}}
	out[scenarioKey{finishRoute, access.CodeTokenInvalid}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return post(t, e, enrolOf(t, e, nil), TOTPFinishRequest{Ticket: "not-a-ticket", Code: "123456"})
	}}
	out[scenarioKey{finishRoute, access.CodeCodeInvalid}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		en := enrolOf(t, e, nil)
		return post(t, e, en, TOTPFinishRequest{Code: wrongCode(en.secret)})
	}}
	out[scenarioKey{finishRoute, access.CodeSecondFactorUnavailable}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		en := enrolOf(t, e, access.NewEphemeralSealer())
		return post(t, e, en, TOTPFinishRequest{Code: codeNow(en.secret), CurrentCode: codeNow(en.prev)})
	}}
	off := &atomic.Bool{}
	out[scenarioKey{finishRoute, access.CodeTOTPDisabled}] = scenario{opts: with(totpOn, flag(off, func(r *account.Rules) { r.DisableTOTP = true })), arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		off.Store(true)
		return r
	}}
	out[scenarioKey{finishRoute, access.CodeSSOOnly}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		e.keepDormant(t, "alice")
		return r
	}}
}

func addTOTPRemoveScenarios(out map[scenarioKey]scenario) {
	const route = "authTOTPRemove"
	removeWith := func(t *testing.T, e *env, body string) *http.Request {
		cookie := e.aliceSession(t)
		e.giveTOTP(t, "alice", e.sealer)
		return e.post(t, route, body, cookie)
	}
	byCode := func(t *testing.T, e *env) *http.Request {
		cookie := e.recentSession(t, "alice")
		secret := e.giveTOTP(t, "alice", e.sealer)
		return e.post(t, route, proofBody(t, SecondFactorProof{Code: codeNow(secret)}), cookie)
	}
	out[scenarioKey{route, access.CodeSessionExpired}] = scenario{opts: with(totpOn, vanishes), arrange: byCode}
	out[scenarioKey{route, access.CodeRecentAuthRequired}] = scenario{opts: with(totpOn, envOptions{rules: func(r *account.Rules) { r.DisableTOTP = true }}), arrange: func(t *testing.T, e *env) *http.Request {
		e.createUser(t, "alice", access.RoleUser)
		e.giveTOTP(t, "alice", e.sealer)
		return e.post(t, route, "", e.staleSession(t, "alice", true))
	}}
	out[scenarioKey{route, access.CodeUnavailable}] = closing(totpOn, byCode)
	out[scenarioKey{route, access.CodeLastMethod}] = scenario{opts: with(totpOn, envOptions{rules: func(r *account.Rules) { r.RequireSecondFactor = true }}), arrange: byCode}
	out[scenarioKey{route, access.CodeNotFound}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, route, proofBody(t, SecondFactorProof{Code: "123456"}), e.aliceSession(t))
	}}
	out[scenarioKey{route, access.CodeBadRequest}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return removeWith(t, e, "{}")
	}}
	out[scenarioKey{route, access.CodeHTTPSRequired}] = scenario{opts: with(totpOn, passkeys, perRequest), arrange: func(t *testing.T, e *env) *http.Request {
		e.createUser(t, "alice", access.RoleUser)
		e.giveTOTP(t, "alice", e.sealer)
		rt := e.route(t, route)
		body := proofBody(t, SecondFactorProof{Ceremony: "c", Assertion: json.RawMessage(`{}`)})
		return requestAt(plainOrigin, rt.Path, rt, body, e.transportSession(t, "alice", false))
	}}
}

// addRecoveryCodeScenarios reach authRecoveryCodeRegenerate's own codes;
// addProofScenarios reaches its proof's.
func addRecoveryCodeScenarios(out map[scenarioKey]scenario) {
	const route = "authRecoveryCodeRegenerate"
	byCode := func(t *testing.T, e *env) *http.Request {
		cookie := e.recentSession(t, "alice")
		secret := e.giveTOTP(t, "alice", e.sealer)
		e.giveRecoveryCode(t, "alice")
		return e.post(t, route, proofBody(t, SecondFactorProof{Code: codeNow(secret)}), cookie)
	}
	out[scenarioKey{route, access.CodeSessionExpired}] = scenario{opts: with(totpOn, vanishes), arrange: byCode}
	out[scenarioKey{route, access.CodeSSOOnly}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		r := byCode(t, e)
		e.keepDormant(t, "alice")
		return r
	}}
	out[scenarioKey{route, access.CodeBusy}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		r := byCode(t, e)
		e.holdBudget(t)
		return r
	}}
	out[scenarioKey{route, access.CodeUnavailable}] = closing(totpOn, byCode)
	out[scenarioKey{route, access.CodeNotFound}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		cookie := e.recentSession(t, "alice")
		secret := e.giveTOTP(t, "alice", e.sealer)
		return e.post(t, route, proofBody(t, SecondFactorProof{Code: codeNow(secret)}), cookie)
	}}
}

// addProofScenarios reach the proof verifier's codes on each route that
// takes a SecondFactorProof (design 4.31), each where its other scenarios
// do not already.
func addProofScenarios(out map[scenarioKey]scenario) {
	type held struct {
		cookie *http.Cookie
		dev    *accesstest.PasskeyDevice
		target int64 // a passkey of alice's other than dev's
		secret []byte
	}
	// hold is alice's recent session holding a passkey on dev, a spare
	// passkey, and a TOTP record sealed under sealer (e.sealer when nil).
	hold := func(t *testing.T, e *env, sealer *access.Sealer) held {
		dev := e.enrolFrom(t, e.recentSession(t, "alice"))
		cookie := e.storedSession(t, "alice", 0, 0) // the registration rotated the first
		devID := e.passkeyID(t, "alice")
		e.addPasskeyFor(t, "alice")
		var target int64
		creds, err := e.mem.PasskeysByUserID(t.Context(), e.user(t, "alice").ID)
		if err != nil {
			t.Fatalf("PasskeysByUserID: %v", err)
		}
		for i := range creds {
			if creds[i].ID != devID {
				target = creds[i].ID
			}
		}
		if sealer == nil {
			sealer = e.sealer
		}
		return held{cookie: cookie, dev: dev, target: target, secret: e.giveTOTP(t, "alice", sealer)}
	}
	routes := map[string]func(t *testing.T, e *env, h held, body string) *http.Request{
		"authTOTPRemove": func(t *testing.T, e *env, h held, body string) *http.Request {
			return e.post(t, "authTOTPRemove", body, h.cookie)
		},
		"authPasskeyRegisterBegin": func(t *testing.T, e *env, h held, body string) *http.Request {
			return e.post(t, "authPasskeyRegisterBegin", body, h.cookie)
		},
		"authPasskeyRemove": func(t *testing.T, e *env, h held, body string) *http.Request {
			return e.at(t, "authPasskeyRemove", strconv.FormatInt(h.target, 10), body, h.cookie)
		},
		"authRecoveryCodeRegenerate": func(t *testing.T, e *env, h held, body string) *http.Request {
			e.giveRecoveryCode(t, "alice")
			return e.post(t, "authRecoveryCodeRegenerate", body, h.cookie)
		},
	}
	base := with(passkeys, totpOn)
	cases := []struct {
		build  func(t *testing.T, e *env, h held) string // the proof body
		after  func(t *testing.T, e *env)                // runs once the body is built
		opts   envOptions
		sealer func() *access.Sealer
		code   access.Code
	}{
		{
			code: access.CodeRateLimited, opts: trustLimits,
			build: func(t *testing.T, _ *env, h held) string {
				return proofBody(t, SecondFactorProof{Code: codeNow(h.secret)})
			},
			after: func(t *testing.T, e *env) { e.spendAccount(t, "alice") },
		},
		{code: access.CodeBadRequest, build: func(*testing.T, *env, held) string { return "{}" }},
		{code: access.CodeCodeInvalid, build: func(t *testing.T, _ *env, h held) string {
			return proofBody(t, SecondFactorProof{Code: wrongCode(h.secret)})
		}},
		{
			code: access.CodeSecondFactorUnavailable, sealer: access.NewEphemeralSealer,
			build: func(t *testing.T, _ *env, h held) string {
				return proofBody(t, SecondFactorProof{Code: codeNow(h.secret)})
			},
		},
		{
			code: access.CodeTOTPDisabled, opts: envOptions{rules: func(r *account.Rules) { r.RequireSecondFactor, r.DisableTOTP = true, true }},
			build: func(t *testing.T, _ *env, h held) string {
				return proofBody(t, SecondFactorProof{Code: codeNow(h.secret)})
			},
		},
		{code: access.CodeCeremonyInvalid, build: func(t *testing.T, _ *env, _ held) string {
			return proofBody(t, SecondFactorProof{Ceremony: "not-a-ceremony", Assertion: json.RawMessage(`{}`)})
		}},
		{code: access.CodeAssertionFailed, build: func(t *testing.T, e *env, h held) string {
			pc, err := e.svc.StepUpPasskeyBegin(t.Context(), e.principal(t, h.cookie), testOriginOf(t))
			if err != nil {
				t.Fatalf("StepUpPasskeyBegin: %v", err)
			}
			return proofBody(t, SecondFactorProof{Ceremony: pc.ID, Assertion: json.RawMessage(`{}`)})
		}},
		{code: access.CodeUnknownCredential, build: func(t *testing.T, e *env, h held) string {
			body := e.assertionProof(t, h.cookie, h.dev)
			creds, err := e.mem.PasskeysByUserID(t.Context(), e.user(t, "alice").ID)
			if err != nil {
				t.Fatalf("PasskeysByUserID: %v", err)
			}
			for i := range creds {
				if creds[i].ID != h.target {
					if err := e.mem.DeletePasskey(t.Context(), access.PasskeyRef{ID: creds[i].ID, UserID: creds[i].UserID}); err != nil {
						t.Fatalf("DeletePasskey: %v", err)
					}
				}
			}
			return body
		}},
		{
			code: access.CodePasskeysUnavailable, build: func(t *testing.T, e *env, h held) string { return e.assertionProof(t, h.cookie, h.dev) },
			after: func(_ *testing.T, e *env) { e.rp.Store(nil) },
		},
	}
	for route, request := range routes {
		for _, tc := range cases {
			key := scenarioKey{route, tc.code}
			if _, written := out[key]; written || route == "authTOTPRemove" && tc.code == access.CodeTOTPDisabled {
				continue
			}
			out[key] = scenario{opts: with(base, tc.opts), arrange: func(t *testing.T, e *env) *http.Request {
				var sealer *access.Sealer
				if tc.sealer != nil {
					sealer = tc.sealer()
				}
				h := hold(t, e, sealer)
				r := request(t, e, h, tc.build(t, e, h))
				if tc.after != nil {
					tc.after(t, e)
				}
				return r
			}}
		}
	}
	out[scenarioKey{"authPasskeyRemove", access.CodeHTTPSRequired}] = scenario{opts: with(base, perRequest), arrange: func(t *testing.T, e *env) *http.Request {
		e.createUser(t, "alice", access.RoleUser)
		e.addPasskeyFor(t, "alice")
		e.giveTOTP(t, "alice", e.sealer)
		rt := e.route(t, "authPasskeyRemove")
		path := strings.Replace(rt.Path, "{id}", strconv.FormatInt(e.passkeyID(t, "alice"), 10), 1)
		body := proofBody(t, SecondFactorProof{Ceremony: "c", Assertion: json.RawMessage(`{}`)})
		return requestAt(plainOrigin, path, rt, body, e.transportSession(t, "alice", false))
	}}
}
