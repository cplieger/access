package accesshttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// registration is the rules with registration in mode.
func registration(mode account.RegistrationMode) envOptions {
	return envOptions{rules: func(r *account.Rules) { r.Registration = mode }}
}

// fullAt is a waiting cap of one, filled by the scenario's arrange.
var fullAt = envOptions{rules: func(r *account.Rules) { r.MaxWaitingRegistrations = 1 }}

func registerBody(t *testing.T, name, password string) string {
	t.Helper()
	return jsonBody(t, RegisterPasswordRequest{Username: name, Password: password})
}

// waitingUser stores name as an account waiting for approval.
func (e *env) waitingUser(t testing.TB, name string) {
	t.Helper()
	e.createUser(t, name, access.RoleUser)
	e.setUser(t, name, func(u *access.User) { u.Enabled, u.WaitingApproval = false, true })
}

// signUpFinish begins a passkey registration of name and returns its
// finish request with a fresh device's registration, edited, after between
// runs.
func (e *env) signUpFinish(t *testing.T, name string, edit func([]byte) []byte, between func()) *http.Request {
	t.Helper()
	id, options := e.begin(t, "authRegisterPasskeyBegin", "", jsonBody(t, RegisterPasskeyBeginRequest{Username: name}))
	body := accesstest.NewPasskeyDevice(t).Register(options)
	if edit != nil {
		body = edit(body)
	}
	if between != nil {
		between()
	}
	return finish(e.route(t, "authRegisterPasskeyFinish"), id, body)
}

// registrationDraftTicket is a password registration's draft ticket under
// the rule.
func (e *env) registrationDraftTicket(t testing.TB) string {
	t.Helper()
	out, err := e.svc.RegisterPassword(t.Context(), account.Client{Secure: true}, account.Registration{Username: "carol", Password: access.NewSecret(testPassword)})
	if err != nil || out.Pending == nil {
		t.Fatalf("RegisterPassword = %v, want a draft", err)
	}
	return out.Pending.Ticket.Reveal()
}

func registerScenarios() map[scenarioKey]scenario {
	out := map[scenarioKey]scenario{}
	addRegisterPasswordScenarios(out)
	addRegisterPasskeyScenarios(out)
	addRegistrationDraftScenarios(out)
	return out
}

func addRegisterPasswordScenarios(out map[scenarioKey]scenario) {
	const route = "authRegisterPassword"
	open, approval := registration(account.RegistrationOpen), registration(account.RegistrationApproval)
	post := func(t *testing.T, e *env) *http.Request {
		return e.post(t, route, registerBody(t, "carol", testPassword))
	}
	out[scenarioKey{route, access.CodeRegistrationClosed}] = scenario{arrange: post}
	out[scenarioKey{route, access.CodeRegistrationFull}] = scenario{opts: with(approval, fullAt), arrange: func(t *testing.T, e *env) *http.Request {
		e.waitingUser(t, "dave")
		return post(t, e)
	}}
	out[scenarioKey{route, access.CodeForbidden}] = scenario{opts: with(open, envOptions{edit: refuse(account.OpCreateUser)}), arrange: post}
	out[scenarioKey{route, access.CodeSSOOnly}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		if err := e.mem.SetSSOMode(t.Context(), account.SSOOnly); err != nil {
			t.Fatalf("SetSSOMode: %v", err)
		}
		return post(t, e)
	}}
	out[scenarioKey{route, access.CodeRateLimited}] = scenario{opts: with(open, limited), arrange: func(t *testing.T, e *env) *http.Request {
		e.spendAttempt(t)
		return post(t, e)
	}}
	out[scenarioKey{route, access.CodeBusy}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		e.holdBudget(t)
		return post(t, e)
	}}
	out[scenarioKey{route, access.CodeUnavailable}] = closing(open, post)
	out[scenarioKey{route, access.CodeUsernameInvalid}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, route, registerBody(t, "", testPassword))
	}}
	out[scenarioKey{route, access.CodeUsernameTaken}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		e.createUser(t, "carol", access.RoleUser)
		return post(t, e)
	}}
	out[scenarioKey{route, access.CodePasswordRejected}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, route, registerBody(t, "carol", "short"))
	}}
	out[scenarioKey{route, access.CodeBreachCheckUnavailable}] = scenario{opts: with(open, breachDown), arrange: post}
}

func addRegisterPasskeyScenarios(out map[scenarioKey]scenario) {
	const begin = "authRegisterPasskeyBegin"
	open := with(passkeys, registration(account.RegistrationOpen))
	beginOf := func(t *testing.T, e *env) *http.Request {
		return e.post(t, begin, jsonBody(t, RegisterPasskeyBeginRequest{Username: "carol"}))
	}
	out[scenarioKey{begin, access.CodeRegistrationClosed}] = scenario{opts: passkeys, arrange: beginOf}
	out[scenarioKey{begin, access.CodeRegistrationFull}] = scenario{opts: with(passkeys, registration(account.RegistrationApproval), fullAt), arrange: func(t *testing.T, e *env) *http.Request {
		e.waitingUser(t, "dave")
		return beginOf(t, e)
	}}
	out[scenarioKey{begin, access.CodeForbidden}] = scenario{opts: with(open, envOptions{edit: refuse(account.OpCreateUser)}), arrange: beginOf}
	out[scenarioKey{begin, access.CodeSSOOnly}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		if err := e.mem.SetSSOMode(t.Context(), account.SSOOnly); err != nil {
			t.Fatalf("SetSSOMode: %v", err)
		}
		return beginOf(t, e)
	}}
	out[scenarioKey{begin, access.CodeRateLimited}] = scenario{opts: with(open, limited), arrange: func(t *testing.T, e *env) *http.Request {
		e.spendRequest(t)
		return beginOf(t, e)
	}}
	out[scenarioKey{begin, access.CodeUnavailable}] = closing(open, beginOf)
	out[scenarioKey{begin, access.CodeUsernameInvalid}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		return e.post(t, begin, jsonBody(t, RegisterPasskeyBeginRequest{Username: ""}))
	}}
	out[scenarioKey{begin, access.CodePasskeysUnavailable}] = scenario{opts: registration(account.RegistrationOpen), arrange: beginOf}
	out[scenarioKey{begin, access.CodeOriginRefused}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		return fromOrigin(beginOf(t, e), evilOrigin)
	}}

	const route = "authRegisterPasskeyFinish"
	mode := &atomic.Int32{}
	mode.Store(int32(account.RegistrationOpen))
	live := with(passkeys, envOptions{rules: func(r *account.Rules) { r.Registration = account.RegistrationMode(mode.Load()) }})
	out[scenarioKey{route, access.CodeRegistrationClosed}] = scenario{opts: live, arrange: func(t *testing.T, e *env) *http.Request {
		return e.signUpFinish(t, "carol", nil, func() { mode.Store(int32(account.RegistrationOff)) })
	}}
	out[scenarioKey{route, access.CodeRegistrationFull}] = scenario{opts: with(passkeys, registration(account.RegistrationApproval), fullAt), arrange: func(t *testing.T, e *env) *http.Request {
		return e.signUpFinish(t, "carol", nil, func() { e.waitingUser(t, "dave") })
	}}
	later := &atomic.Bool{}
	out[scenarioKey{route, access.CodeForbidden}] = scenario{opts: with(open, envOptions{edit: func(c *account.Config) { c.Policy = laterRegistrationPolicy{refuse: later} }}), arrange: func(t *testing.T, e *env) *http.Request {
		return e.signUpFinish(t, "carol", nil, func() { later.Store(true) })
	}}
	out[scenarioKey{route, access.CodeSSOOnly}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		return e.signUpFinish(t, "carol", nil, func() {
			if err := e.mem.SetSSOMode(t.Context(), account.SSOOnly); err != nil {
				t.Fatalf("SetSSOMode: %v", err)
			}
		})
	}}
	out[scenarioKey{route, access.CodeUnavailable}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		return e.signUpFinish(t, "carol", nil, func() { e.shutdown(t) })
	}}
	out[scenarioKey{route, access.CodeUsernameTaken}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		return e.signUpFinish(t, "carol", nil, func() { e.createUser(t, "carol", access.RoleUser) })
	}}
	out[scenarioKey{route, access.CodePasskeysUnavailable}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		return e.signUpFinish(t, "carol", nil, func() { e.rp.Store(nil) })
	}}
	out[scenarioKey{route, access.CodeCeremonyInvalid}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		r := e.signUpFinish(t, "carol", nil, nil)
		r.Header.Set(ceremonyHeader, "not-a-ceremony")
		return r
	}}
	out[scenarioKey{route, access.CodeNotDiscoverable}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		return e.signUpFinish(t, "carol", func(b []byte) []byte { return notDiscoverable(t, b) }, nil)
	}}
	out[scenarioKey{route, access.CodeRegistrationFailed}] = scenario{opts: open, arrange: func(t *testing.T, e *env) *http.Request {
		return e.signUpFinish(t, "carol", func([]byte) []byte { return []byte(`{}`) }, nil)
	}}
}

// addRegistrationDraftScenarios are the pending enrolment finishes'
// answers only a registration draft gives (design 4.17: the finish re-reads
// the mode and re-checks the cap).
func addRegistrationDraftScenarios(out map[scenarioKey]scenario) {
	finishes := map[string]func(t *testing.T, e *env, ticket string, between func()) *http.Request{
		"authPendingTOTPFinish": func(t *testing.T, e *env, ticket string, between func()) *http.Request {
			r := e.pendingTOTPFinish(t, ticket)
			between()
			return r
		},
		"authPendingPasskeyFinish": func(t *testing.T, e *env, ticket string, between func()) *http.Request {
			return e.pendingPasskeyFinish(t, ticket, nil, nil, between)
		},
	}
	// draftRule is the rule with registration in a mode a scenario moves.
	draftRule := func(mode *atomic.Int32) envOptions {
		return with(requireRule, totpOn, fullAt, envOptions{rules: func(r *account.Rules) { r.Registration = account.RegistrationMode(mode.Load()) }})
	}
	for route, finishOf := range finishes {
		closed := &atomic.Int32{}
		closed.Store(int32(account.RegistrationOpen))
		out[scenarioKey{route, access.CodeRegistrationClosed}] = scenario{opts: draftRule(closed), arrange: func(t *testing.T, e *env) *http.Request {
			return finishOf(t, e, e.registrationDraftTicket(t), func() { closed.Store(int32(account.RegistrationOff)) })
		}}
		full := &atomic.Int32{}
		full.Store(int32(account.RegistrationApproval))
		out[scenarioKey{route, access.CodeRegistrationFull}] = scenario{opts: draftRule(full), arrange: func(t *testing.T, e *env) *http.Request {
			return finishOf(t, e, e.registrationDraftTicket(t), func() { e.waitingUser(t, "dave") })
		}}
	}
}

// laterRegistrationPolicy is RolePolicy until refuse is set, then refuses
// a registration's account creation.
type laterRegistrationPolicy struct{ refuse *atomic.Bool }

func (laterRegistrationPolicy) SingleUser() bool { return false }

func (p laterRegistrationPolicy) Authorize(ctx context.Context, d account.Decision) error {
	if p.refuse.Load() && d.Op == account.OpCreateUser && d.Via == account.ViaRegistration {
		return &account.PolicyError{Op: d.Op, Reason: "no_sign_ups"}
	}
	return account.RolePolicy{}.Authorize(ctx, d)
}

// TestRegistrationRoutes is design 4.17's and 4.31's answers on the wire:
// RegistrationOutcome and EnrolmentOutcome's arms, with the session
// cookie only on signed_in.
func TestRegistrationRoutes(t *testing.T) {
	t.Parallel()
	decode := func(t *testing.T, w *httptest.ResponseRecorder, v any) {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("status %d, body %s", w.Code, w.Body.Bytes())
		}
		strictDecode(t, w.Body.Bytes(), v)
	}
	signedInCookie := func(e *env, w *httptest.ResponseRecorder) bool {
		cfg := e.authn.Cookie()
		return cookieNamed(w, cfg.CookieName(true)) != nil
	}
	t.Run("password_open_signs_in", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, registration(account.RegistrationOpen))
		w := do(e.route(t, "authRegisterPassword"), e.post(t, "authRegisterPassword", registerBody(t, "carol", testPassword)))
		var out RegistrationOutcome
		decode(t, w, &out)
		if out.SignedIn == nil || out.SignedIn.User.Username != "carol" || out.Pending != nil || out.WaitingApproval {
			t.Fatalf("RegistrationOutcome = %+v, want signed_in alone", out)
		}
		if !signedInCookie(e, w) {
			t.Error("signed_in set no session cookie")
		}
	})
	t.Run("password_approval_waits", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, registration(account.RegistrationApproval))
		w := do(e.route(t, "authRegisterPassword"), e.post(t, "authRegisterPassword", registerBody(t, "carol", testPassword)))
		if got := w.Body.String(); got != "{\"waiting_approval\":true}\n" {
			t.Errorf("body = %q, want exactly {\"waiting_approval\":true} (design 4.31)", got)
		}
		if c := w.Result().Cookies(); len(c) != 0 {
			t.Errorf("a waiting account's answer set cookies %v, want none", c)
		}
	})
	t.Run("password_rule_pends", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, with(requireRule, totpOn, registration(account.RegistrationApproval)))
		w := do(e.route(t, "authRegisterPassword"), e.post(t, "authRegisterPassword", registerBody(t, "carol", testPassword)))
		var out RegistrationOutcome
		decode(t, w, &out)
		if out.Pending == nil || out.Pending.Next != account.NextEnrol || out.SignedIn != nil {
			t.Fatalf("RegistrationOutcome = %+v, want pending enrol alone", out)
		}
		fw := do(e.route(t, "authPendingTOTPFinish"), e.pendingTOTPFinish(t, out.Pending.Ticket))
		var done EnrolmentOutcome
		decode(t, fw, &done)
		if !done.WaitingApproval || done.RecoveryCode == "" || done.SignedIn != nil {
			t.Errorf("EnrolmentOutcome = %+v, want waiting_approval with the recovery code (design 4.31)", done)
		}
		if c := fw.Result().Cookies(); len(c) != 0 {
			t.Errorf("the waiting finish set cookies %v, want none", c)
		}
	})
	t.Run("passkey_approval_waits", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, with(passkeys, registration(account.RegistrationApproval)))
		w := do(e.route(t, "authRegisterPasskeyFinish"), e.signUpFinish(t, "carol", nil, nil))
		if got := w.Body.String(); got != "{\"waiting_approval\":true}\n" {
			t.Errorf("body = %q, want exactly {\"waiting_approval\":true}", got)
		}
		if c := w.Result().Cookies(); len(c) != 0 {
			t.Errorf("a waiting account's answer set cookies %v, want none", c)
		}
	})
	t.Run("passkey_open_signs_in", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, with(passkeys, requireRule, registration(account.RegistrationOpen)))
		w := do(e.route(t, "authRegisterPasskeyFinish"), e.signUpFinish(t, "carol", nil, nil))
		var out EnrolmentOutcome
		decode(t, w, &out)
		if out.SignedIn == nil || out.SignedIn.User.Username != "carol" || out.WaitingApproval {
			t.Fatalf("EnrolmentOutcome = %+v, want signed_in: a passkey meets the rule", out)
		}
		if !signedInCookie(e, w) {
			t.Error("signed_in set no session cookie")
		}
	})
	t.Run("state_answers_the_mode", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, registration(account.RegistrationApproval))
		w := do(e.route(t, "authState"), e.post(t, "authState", ""))
		var st StateResponse
		decode(t, w, &st)
		if st.Registration != account.RegistrationNameApproval {
			t.Errorf("StateResponse.registration = %q, want approval (design 4.17)", st.Registration)
		}
	})
	t.Run("admin_list_marks_waiting", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, envOptions{})
		root := e.rootSession(t)
		e.waitingUser(t, "carol")
		views := decoded[[]UserView](t, e, do(e.route(t, "authAdminUsers"), e.post(t, "authAdminUsers", "", root)), http.StatusOK)
		for _, v := range views {
			if v.Methods == nil || v.Methods.WaitingApproval != (v.Username == "carol") {
				t.Errorf("%s methods %+v, want waiting_approval on carol alone (design 4.17)", v.Username, v.Methods)
			}
		}
	})
}
