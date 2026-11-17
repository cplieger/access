package accesshttp

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// setPasskeyFinish begins the set_credential passkey registration of
// ticket through the Service and answers its finish request with dev's
// registration (a fresh device when nil), edited, after between runs.
func (e *env) setPasskeyFinish(t testing.TB, ticket string, dev *accesstest.PasskeyDevice, edit func([]byte) []byte, between func()) *http.Request {
	t.Helper()
	pc, err := e.svc.SetCredentialPasskeyBegin(t.Context(), account.Client{Secure: true}, access.NewSecret(ticket), testOriginOf(t))
	if err != nil {
		t.Fatalf("SetCredentialPasskeyBegin: %v", err)
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
	return finish(e.route(t, "authLoginSetPasskeyFinish"), pc.ID, body)
}

func setCredentialScenarios() map[scenarioKey]scenario {
	out := map[scenarioKey]scenario{}
	addSetPasswordScenarios(out)
	addSetPasskeyScenarios(out)
	return out
}

func addSetPasswordScenarios(out map[scenarioKey]scenario) {
	const route = "authLoginSetPassword"
	own := func(password string) func(t *testing.T, e *env) *http.Request {
		return func(t *testing.T, e *env) *http.Request {
			e.createUser(t, "alice", access.RoleUser)
			ticket, _ := e.temporaryTicket(t, "alice", true)
			return e.setPassword(t, testOrigin, ticket, password)
		}
	}
	// Under the rule the replacement's NextEnrol set is the
	// passkey alone, which the app then refuses.
	refused := &atomic.Bool{}
	out[scenarioKey{route, access.CodeForbidden}] = scenario{opts: with(requireRule, flag(refused, refusePasskeys)), arrange: func(t *testing.T, e *env) *http.Request {
		r := own(chosenPassword)(t, e)
		refused.Store(true)
		return r
	}}
	out[scenarioKey{route, access.CodeRateLimited}] = scenario{opts: trustLimits, arrange: func(t *testing.T, e *env) *http.Request {
		r := own(chosenPassword)(t, e)
		e.spendAccount(t, "alice")
		return r
	}}
	out[scenarioKey{route, access.CodeBusy}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		r := own(chosenPassword)(t, e)
		e.holdBudget(t)
		return r
	}}
	out[scenarioKey{route, access.CodeUnavailable}] = closing(envOptions{}, own(chosenPassword))
	out[scenarioKey{route, access.CodeTokenInvalid}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.setPassword(t, testOrigin, "not-a-ticket", chosenPassword)
	}}
	out[scenarioKey{route, access.CodePasswordLoginDisabled}] = scenario{opts: with(passkeys, envOptions{rules: func(r *account.Rules) { r.DisablePasswordLogin = true }}), arrange: own(chosenPassword)}
	out[scenarioKey{route, access.CodePasswordRejected}] = scenario{arrange: own("short")}
	out[scenarioKey{route, access.CodeBreachCheckUnavailable}] = scenario{opts: breachDown, arrange: own(chosenPassword)}
}

func addSetPasskeyScenarios(out map[scenarioKey]scenario) {
	const begin, finishRoute = "authLoginSetPasskeyBegin", "authLoginSetPasskeyFinish"
	beginOf := func(t *testing.T, e *env, ticket string) *http.Request {
		return e.post(t, begin, jsonBody(t, TicketRequest{Ticket: ticket}))
	}
	ownTicket := func(t *testing.T, e *env) string {
		e.createUser(t, "alice", access.RoleUser)
		ticket, _ := e.temporaryTicket(t, "alice", true)
		return ticket
	}
	beginOwn := func(t *testing.T, e *env) *http.Request { return beginOf(t, e, ownTicket(t, e)) }
	out[scenarioKey{begin, access.CodeRateLimited}] = scenario{opts: with(passkeys, limited), arrange: func(t *testing.T, e *env) *http.Request {
		r := beginOwn(t, e)
		e.spendRequest(t)
		return r
	}}
	out[scenarioKey{begin, access.CodeUnavailable}] = closing(passkeys, beginOwn)
	out[scenarioKey{begin, access.CodeTokenInvalid}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		return beginOf(t, e, "not-a-ticket")
	}}
	out[scenarioKey{begin, access.CodePasskeysUnavailable}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		r := beginOwn(t, e)
		e.rp.Store(nil)
		return r
	}}
	out[scenarioKey{begin, access.CodeOriginRefused}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		return fromOrigin(beginOwn(t, e), evilOrigin)
	}}

	finishOwn := func(newDev func(t *testing.T, e *env) *accesstest.PasskeyDevice, edit func([]byte) []byte, between func(t *testing.T, e *env)) func(t *testing.T, e *env) *http.Request {
		return func(t *testing.T, e *env) *http.Request {
			ticket := ownTicket(t, e)
			var dev *accesstest.PasskeyDevice
			if newDev != nil {
				dev = newDev(t, e)
			}
			return e.setPasskeyFinish(t, ticket, dev, edit, func() {
				if between != nil {
					between(t, e)
				}
			})
		}
	}
	out[scenarioKey{finishRoute, access.CodeRateLimited}] = scenario{opts: with(passkeys, trustLimits), arrange: finishOwn(nil, nil, func(t *testing.T, e *env) { e.spendAccount(t, "alice") })}
	out[scenarioKey{finishRoute, access.CodeUnavailable}] = scenario{opts: passkeys, arrange: finishOwn(nil, nil, func(t *testing.T, e *env) { e.shutdown(t) })}
	out[scenarioKey{finishRoute, access.CodeTokenInvalid}] = scenario{opts: passkeys, arrange: finishOwn(nil, nil, func(t *testing.T, e *env) {
		e.setUser(t, "alice", func(u *access.User) { u.Enabled = false })
	})}
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
	out[scenarioKey{finishRoute, access.CodeNotDiscoverable}] = scenario{opts: passkeys, arrange: func(t *testing.T, e *env) *http.Request {
		return finishOwn(nil, func(b []byte) []byte { return notDiscoverable(t, b) }, nil)(t, e)
	}}
	out[scenarioKey{finishRoute, access.CodeRegistrationFailed}] = scenario{opts: passkeys, arrange: finishOwn(nil, func([]byte) []byte { return []byte(`{}`) }, nil)}
}
