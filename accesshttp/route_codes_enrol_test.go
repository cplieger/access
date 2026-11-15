package accesshttp

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// knownRecoveryCode is a recovery code's 16 Crockford symbols.
const knownRecoveryCode = "7K3M9QW2XZ8R4T6V"

// recoveryTicket stores name with a TOTP record and knownRecoveryCode,
// hashed as the Service stores one, and answers name's pending sign-in.
func (e *env) recoveryTicket(t testing.TB, name string) string {
	t.Helper()
	e.createUser(t, name, access.RoleUser)
	e.giveTOTP(t, name, e.sealer)
	h, err := e.hasher.Hash(t.Context(), knownRecoveryCode)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := e.mem.SetRecoveryCode(t.Context(), access.RecoveryCode{UserID: e.user(t, name).ID, Hash: h}); err != nil {
		t.Fatalf("SetRecoveryCode: %v", err)
	}
	return e.pendingTicket(t, name)
}

// recoveredTicket is name's NextEnrol ticket once knownRecoveryCode
// matched.
func (e *env) recoveredTicket(t testing.TB, name string) string {
	t.Helper()
	out, err := e.svc.SignInWithRecoveryCode(t.Context(), account.Client{Secure: true}, access.NewSecret(e.recoveryTicket(t, name)), knownRecoveryCode)
	if err != nil || out.Pending == nil {
		t.Fatalf("SignInWithRecoveryCode = %v, want a recovered enrolment", err)
	}
	return out.Pending.Ticket.Reveal()
}

// pendingTOTPFinish begins the pending TOTP enrolment of ticket through
// the Service and answers its finish request with a code of the drawn
// secret.
func (e *env) pendingTOTPFinish(t *testing.T, ticket string) *http.Request {
	t.Helper()
	got, err := e.svc.PendingTOTPBegin(t.Context(), account.Client{Secure: true}, access.NewSecret(ticket))
	if err != nil {
		t.Fatalf("PendingTOTPBegin: %v", err)
	}
	secret, err := unpaddedBase32.DecodeString(got.Text.Reveal())
	if err != nil {
		t.Fatalf("the text key %q is not RFC 4648 base32: %v", got.Text.Reveal(), err)
	}
	return e.post(t, "authPendingTOTPFinish", jsonBody(t, CodeRequest{Ticket: ticket, Code: codeNow(secret)}))
}

// pendingPasskeyFinish begins the pending passkey enrolment of ticket
// through the Service and answers its finish request with dev's
// registration (a fresh device when nil), edited, after between runs.
func (e *env) pendingPasskeyFinish(t testing.TB, ticket string, dev *accesstest.PasskeyDevice, edit func([]byte) []byte, between func()) *http.Request {
	t.Helper()
	pc, err := e.svc.PendingPasskeyBegin(t.Context(), account.Client{Secure: true}, access.NewSecret(ticket), testOriginOf(t))
	if err != nil {
		t.Fatalf("PendingPasskeyBegin: %v", err)
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
	return finish(e.route(t, "authPendingPasskeyFinish"), pc.ID, body)
}

func enrolScenarios() map[scenarioKey]scenario {
	out := map[scenarioKey]scenario{}
	addRecoveryStepScenarios(out)
	addPendingTOTPScenarios(out)
	addPendingPasskeyScenarios(out)
	addDraftFinishScenarios(out)
	return out
}

// laterPolicy is RolePolicy until refuse is set, then refuses an invite's
// account creation, so a draft minted before is refused at its finish.
type laterPolicy struct{ refuse *atomic.Bool }

func (laterPolicy) SingleUser() bool { return false }

func (p laterPolicy) Authorize(ctx context.Context, d account.Decision) error {
	if p.refuse.Load() && d.Op == account.OpCreateUser && d.Via == account.ViaInvite {
		return &account.PolicyError{Op: d.Op, Reason: "no_invites"}
	}
	return account.RolePolicy{}.Authorize(ctx, d)
}

// setupDraftTicket is a password setup's draft ticket under the rule.
func (e *env) setupDraftTicket(t testing.TB) string {
	t.Helper()
	out, err := e.svc.SetupWithPassword(t.Context(), account.Client{Secure: true}, account.SetupPassword{Username: "owner", Password: access.NewSecret(testPassword)})
	if err != nil || out.Pending == nil {
		t.Fatalf("SetupWithPassword = %v, want a draft", err)
	}
	return out.Pending.Ticket.Reveal()
}

// inviteDraftTicket is bob's password invite acceptance's draft ticket
// under the rule.
func (e *env) inviteDraftTicket(t testing.TB) string {
	t.Helper()
	out, err := e.svc.AcceptInvitePassword(t.Context(), account.Client{Secure: true}, account.AcceptInvite{Token: e.storedInvite(t), Username: "bob", Password: access.NewSecret(testPassword)})
	if err != nil || out.Pending == nil {
		t.Fatalf("AcceptInvitePassword = %v, want a draft", err)
	}
	return out.Pending.Ticket.Reveal()
}

// addDraftFinishScenarios are the pending enrolment finishes' answers that
// only a draft's creation gives (design 4.4 step 3).
func addDraftFinishScenarios(out map[scenarioKey]scenario) {
	draftRule := with(requireRule, totpOn)
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
	for route, finishOf := range finishes {
		out[scenarioKey{route, access.CodeSetupComplete}] = scenario{opts: draftRule, arrange: func(t *testing.T, e *env) *http.Request {
			return finishOf(t, e, e.setupDraftTicket(t), func() { e.createUser(t, "root", access.RoleAdmin) })
		}}
		out[scenarioKey{route, access.CodeUsernameTaken}] = scenario{opts: draftRule, arrange: func(t *testing.T, e *env) *http.Request {
			return finishOf(t, e, e.inviteDraftTicket(t), func() { e.createUser(t, "bob", access.RoleUser) })
		}}
		out[scenarioKey{route, access.CodeSSOOnly}] = scenario{opts: draftRule, arrange: func(t *testing.T, e *env) *http.Request {
			return finishOf(t, e, e.inviteDraftTicket(t), func() {
				if err := e.mem.SetSSOMode(t.Context(), account.SSOOnly); err != nil {
					t.Fatalf("SetSSOMode: %v", err)
				}
			})
		}}
		later := &atomic.Bool{}
		out[scenarioKey{route, access.CodeForbidden}] = scenario{opts: with(draftRule, envOptions{edit: func(c *account.Config) { c.Policy = laterPolicy{refuse: later} }}), arrange: func(t *testing.T, e *env) *http.Request {
			return finishOf(t, e, e.inviteDraftTicket(t), func() { later.Store(true) })
		}}
	}
}

func addRecoveryStepScenarios(out map[scenarioKey]scenario) {
	const route = "authLoginRecoveryCode"
	post := func(t *testing.T, e *env, ticket, code string) *http.Request {
		return e.post(t, route, jsonBody(t, CodeRequest{Ticket: ticket, Code: code}))
	}
	right := func(t *testing.T, e *env) *http.Request {
		return post(t, e, e.recoveryTicket(t, "alice"), knownRecoveryCode)
	}
	// Design 4.4: the only enrolment the step leads to is TOTP here, which
	// the switch then turns off.
	off := &atomic.Bool{}
	out[scenarioKey{route, access.CodeForbidden}] = scenario{opts: with(totpOn, flag(off, func(r *account.Rules) { r.DisableTOTP = true })), arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		off.Store(true)
		return r
	}}
	out[scenarioKey{route, access.CodeRateLimited}] = scenario{opts: with(totpOn, trustLimits), arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		e.spendAccount(t, "alice")
		return r
	}}
	out[scenarioKey{route, access.CodeBusy}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		r := right(t, e)
		e.holdBudget(t)
		return r
	}}
	out[scenarioKey{route, access.CodeUnavailable}] = closing(totpOn, right)
	out[scenarioKey{route, access.CodeBadRequest}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return post(t, e, e.recoveryTicket(t, "alice"), "7K3M")
	}}
	out[scenarioKey{route, access.CodeTokenInvalid}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return post(t, e, "not-a-ticket", knownRecoveryCode)
	}}
	out[scenarioKey{route, access.CodeCodeInvalid}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return post(t, e, e.recoveryTicket(t, "alice"), "0000-0000-0000-0000")
	}}
}

func addPendingTOTPScenarios(out map[scenarioKey]scenario) {
	const begin, finishRoute = "authPendingTOTPBegin", "authPendingTOTPFinish"
	beginOf := func(t *testing.T, e *env, ticket string) *http.Request {
		return e.post(t, begin, jsonBody(t, TicketRequest{Ticket: ticket}))
	}
	beginOwn := func(t *testing.T, e *env) *http.Request { return beginOf(t, e, e.recoveredTicket(t, "alice")) }
	out[scenarioKey{begin, access.CodeRateLimited}] = scenario{opts: with(totpOn, limited), arrange: func(t *testing.T, e *env) *http.Request {
		r := beginOwn(t, e)
		e.spendRequest(t)
		return r
	}}
	out[scenarioKey{begin, access.CodeUnavailable}] = closing(totpOn, beginOwn)
	out[scenarioKey{begin, access.CodeTokenInvalid}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return beginOf(t, e, "not-a-ticket")
	}}
	beginOff := &atomic.Bool{}
	out[scenarioKey{begin, access.CodeTOTPDisabled}] = scenario{opts: with(totpOn, flag(beginOff, func(r *account.Rules) { r.DisableTOTP = true })), arrange: func(t *testing.T, e *env) *http.Request {
		r := beginOwn(t, e)
		beginOff.Store(true)
		return r
	}}

	finishOwn := func(t *testing.T, e *env) *http.Request { return e.pendingTOTPFinish(t, e.recoveredTicket(t, "alice")) }
	finishOf := func(t *testing.T, e *env, code string) *http.Request {
		ticket := e.recoveredTicket(t, "alice")
		if _, err := e.svc.PendingTOTPBegin(t.Context(), account.Client{Secure: true}, access.NewSecret(ticket)); err != nil {
			t.Fatalf("PendingTOTPBegin: %v", err)
		}
		return e.post(t, finishRoute, jsonBody(t, CodeRequest{Ticket: ticket, Code: code}))
	}
	out[scenarioKey{finishRoute, access.CodeRateLimited}] = scenario{opts: with(totpOn, trustLimits), arrange: func(t *testing.T, e *env) *http.Request {
		r := finishOwn(t, e)
		e.spendAccount(t, "alice")
		return r
	}}
	out[scenarioKey{finishRoute, access.CodeBusy}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		r := finishOwn(t, e)
		e.holdBudget(t)
		return r
	}}
	out[scenarioKey{finishRoute, access.CodeUnavailable}] = closing(totpOn, finishOwn)
	out[scenarioKey{finishRoute, access.CodeBadRequest}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return finishOf(t, e, "12345")
	}}
	out[scenarioKey{finishRoute, access.CodeTokenInvalid}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		r := finishOwn(t, e)
		e.setUser(t, "alice", func(u *access.User) { u.Enabled = false })
		return r
	}}
	out[scenarioKey{finishRoute, access.CodeCodeInvalid}] = scenario{opts: totpOn, arrange: func(t *testing.T, e *env) *http.Request {
		return finishOf(t, e, "000000")
	}}
	finishOff := &atomic.Bool{}
	out[scenarioKey{finishRoute, access.CodeTOTPDisabled}] = scenario{opts: with(totpOn, flag(finishOff, func(r *account.Rules) { r.DisableTOTP = true })), arrange: func(t *testing.T, e *env) *http.Request {
		r := finishOwn(t, e)
		finishOff.Store(true)
		return r
	}}
}

func addPendingPasskeyScenarios(out map[scenarioKey]scenario) {
	const begin, finishRoute = "authPendingPasskeyBegin", "authPendingPasskeyFinish"
	opts := with(passkeys, totpOn)
	beginOf := func(t *testing.T, e *env, ticket string) *http.Request {
		return e.post(t, begin, jsonBody(t, TicketRequest{Ticket: ticket}))
	}
	beginOwn := func(t *testing.T, e *env) *http.Request { return beginOf(t, e, e.recoveredTicket(t, "alice")) }
	out[scenarioKey{begin, access.CodeRateLimited}] = scenario{opts: with(opts, limited), arrange: func(t *testing.T, e *env) *http.Request {
		r := beginOwn(t, e)
		e.spendRequest(t)
		return r
	}}
	out[scenarioKey{begin, access.CodeUnavailable}] = closing(opts, beginOwn)
	out[scenarioKey{begin, access.CodeTokenInvalid}] = scenario{opts: opts, arrange: func(t *testing.T, e *env) *http.Request {
		return beginOf(t, e, "not-a-ticket")
	}}
	out[scenarioKey{begin, access.CodePasskeysUnavailable}] = scenario{opts: opts, arrange: func(t *testing.T, e *env) *http.Request {
		r := beginOwn(t, e)
		e.rp.Store(nil)
		return r
	}}
	out[scenarioKey{begin, access.CodeOriginRefused}] = scenario{opts: opts, arrange: func(t *testing.T, e *env) *http.Request {
		return fromOrigin(beginOwn(t, e), evilOrigin)
	}}

	// finishOwn is alice's recovered enrolment finish with dev's
	// registration (newDev's, a fresh device when nil), edited, after
	// between runs.
	finishOwn := func(newDev func(t *testing.T, e *env) *accesstest.PasskeyDevice, edit func(t *testing.T, b []byte) []byte, between func(t *testing.T, e *env)) func(t *testing.T, e *env) *http.Request {
		return func(t *testing.T, e *env) *http.Request {
			ticket := e.recoveredTicket(t, "alice")
			var dev *accesstest.PasskeyDevice
			if newDev != nil {
				dev = newDev(t, e)
			}
			var ed func([]byte) []byte
			if edit != nil {
				ed = func(b []byte) []byte { return edit(t, b) }
			}
			return e.pendingPasskeyFinish(t, ticket, dev, ed, func() {
				if between != nil {
					between(t, e)
				}
			})
		}
	}
	out[scenarioKey{finishRoute, access.CodeRateLimited}] = scenario{opts: with(opts, trustLimits), arrange: finishOwn(nil, nil, func(t *testing.T, e *env) { e.spendAccount(t, "alice") })}
	out[scenarioKey{finishRoute, access.CodeBusy}] = scenario{opts: opts, arrange: finishOwn(nil, nil, func(t *testing.T, e *env) { e.holdBudget(t) })}
	out[scenarioKey{finishRoute, access.CodeUnavailable}] = scenario{opts: opts, arrange: finishOwn(nil, nil, func(t *testing.T, e *env) { e.shutdown(t) })}
	out[scenarioKey{finishRoute, access.CodeTokenInvalid}] = scenario{opts: opts, arrange: finishOwn(nil, nil, func(t *testing.T, e *env) {
		e.setUser(t, "alice", func(u *access.User) { u.Enabled = false })
	})}
	out[scenarioKey{finishRoute, access.CodeDuplicateCredential}] = scenario{opts: opts, arrange: finishOwn(func(t *testing.T, e *env) *accesstest.PasskeyDevice {
		e.createUser(t, "root", access.RoleAdmin)
		return e.enrol(t, "root")
	}, nil, nil)}
	out[scenarioKey{finishRoute, access.CodePasskeysUnavailable}] = scenario{opts: opts, arrange: finishOwn(nil, nil, func(_ *testing.T, e *env) { e.rp.Store(nil) })}
	out[scenarioKey{finishRoute, access.CodeCeremonyInvalid}] = scenario{opts: opts, arrange: func(t *testing.T, e *env) *http.Request {
		r := finishOwn(nil, nil, nil)(t, e)
		r.Header.Set(ceremonyHeader, "not-a-ceremony")
		return r
	}}
	out[scenarioKey{finishRoute, access.CodeNotDiscoverable}] = scenario{opts: opts, arrange: finishOwn(nil, func(t *testing.T, b []byte) []byte { return notDiscoverable(t, b) }, nil)}
	out[scenarioKey{finishRoute, access.CodeRegistrationFailed}] = scenario{opts: opts, arrange: finishOwn(nil, func(*testing.T, []byte) []byte { return []byte(`{}`) }, nil)}
}
