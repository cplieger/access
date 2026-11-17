package accesshttp

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// chosenPassword is a password a set_credential step accepts for alice.
const chosenPassword = "lantern orbit maple quiet 42" // gitleaks:allow (test fixture password)

// temporaryTicket issues name a temporary password out of band and answers
// it with the set_credential ticket its step 1 over the transport secure
// names mints.
func (e *env) temporaryTicket(t testing.TB, name string, secure bool) (ticket string, issued access.Secret) {
	t.Helper()
	got, err := e.svc.SetTemporaryPassword(t.Context(), account.OutOfBand("cli"), e.user(t, name).ID, account.TemporaryPasswordOptions{})
	if err != nil {
		t.Fatalf("SetTemporaryPassword: %v", err)
	}
	out, err := e.svc.PasswordLogin(t.Context(), account.Client{Secure: secure}, account.Credentials{Username: name, Password: got.Password})
	if err != nil || out.Pending == nil || out.Pending.Next != account.NextSetCredential {
		t.Fatalf("PasswordLogin with the temporary password = %+v, %v; want a set_credential ticket", out.Pending, err)
	}
	return out.Pending.Ticket.Reveal(), got.Password
}

// setPassword is authLoginSetPassword's request for ticket and password at
// origin.
func (e *env) setPassword(t *testing.T, origin, ticket, password string) *http.Request {
	t.Helper()
	rt := e.route(t, "authLoginSetPassword")
	return requestAt(origin, rt.Path, rt, jsonBody(t, SetPasswordRequest{Ticket: ticket, Password: password}))
}

// sessionCookieSet reports whether w set e's session cookie for the
// transport secure names.
func sessionCookieSet(e *env, w *httptest.ResponseRecorder, secure bool) bool {
	cfg := e.authn.Cookie()
	return slices.ContainsFunc(w.Result().Cookies(), func(c *http.Cookie) bool { return c.Name == cfg.CookieName(secure) && c.Value != "" })
}

// signInOutcome decodes w's 200 SignInOutcome strictly.
func signInOutcome(t *testing.T, e *env, w *httptest.ResponseRecorder) SignInOutcome {
	t.Helper()
	e.requireStatus(t, w, http.StatusOK)
	var out SignInOutcome
	strictDecode(t, w.Body.Bytes(), &out)
	return out
}

// TestLoginSetPassword checks authLoginSetPassword setting the credential
// on the wire, with the client's loginSetPassword answers and its
// set-password transitions.
func TestLoginSetPassword(t *testing.T) {
	t.Parallel()
	// With the rule off the chosen password is written and the answer
	// is {signed_in} with the session's cookie.
	t.Run("rule_off_signs_in", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		ticket, _ := e.temporaryTicket(t, "alice", true)
		w := do(e.route(t, "authLoginSetPassword"), e.setPassword(t, testOrigin, ticket, chosenPassword))
		out := signInOutcome(t, e, w)
		if out.Pending != nil || out.SignedIn == nil || out.SignedIn.User.Username != "alice" || out.SignedIn.SessionID == "" {
			t.Fatalf("answer %s, want {signed_in} for alice", w.Body.Bytes())
		}
		if !sessionCookieSet(e, w, true) {
			t.Errorf("Set-Cookie %v, want the secure session cookie", w.Result().Cookies())
		}
		login := do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", jsonBody(t, LoginRequest{Username: "alice", Password: chosenPassword})))
		if got := signInOutcome(t, e, login); got.SignedIn == nil {
			t.Errorf("the chosen password signs in as %s, want {signed_in}", login.Body.Bytes())
		}
	})
	// The answer is {pending} enrol with no cookie,
	// and nothing is written until the enrolment finishes.
	t.Run("rule_on_pending_enrol", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, requireRule)
		e.createUser(t, "alice", access.RoleUser)
		ticket, _ := e.temporaryTicket(t, "alice", true)
		w := do(e.route(t, "authLoginSetPassword"), e.setPassword(t, testOrigin, ticket, chosenPassword))
		out := signInOutcome(t, e, w)
		if out.SignedIn != nil || out.Pending == nil || out.Pending.Next != account.NextEnrol || !slices.Equal(out.Pending.Methods, []PendingMethod{PendingPasskey}) || out.Pending.Ticket == ticket {
			t.Fatalf("answer %s, want a new {pending} enrol [passkey]", w.Body.Bytes())
		}
		if c := w.Result().Cookies(); len(c) != 0 {
			t.Errorf("a pending answer set cookies %v, want none", c)
		}
		if !e.user(t, "alice").PasswordHash.IsZero() {
			t.Errorf("alice holds a password before the enrolment finished")
		}
	})
	// is_temporary_password, the ticket kept.
	t.Run("is_temporary_password", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		ticket, issued := e.temporaryTicket(t, "alice", true)
		got := e.requireRefused(t, do(e.route(t, "authLoginSetPassword"), e.setPassword(t, testOrigin, ticket, issued.Reveal())), access.CodePasswordRejected)
		if got.Reason != string(access.PasswordIsTemporary) {
			t.Errorf("reason %q, want %q", got.Reason, access.PasswordIsTemporary)
		}
		w := do(e.route(t, "authLoginSetPassword"), e.setPassword(t, testOrigin, ticket, chosenPassword))
		if out := signInOutcome(t, e, w); out.SignedIn == nil {
			t.Errorf("the kept ticket answers %s, want {signed_in}", w.Body.Bytes())
		}
	})
	// auth_password_login_disabled, register a
	// passkey instead; the ticket stays.
	t.Run("password_login_disabled", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, with(passkeys, envOptions{rules: func(r *account.Rules) { r.DisablePasswordLogin = true }}))
		e.createUser(t, "alice", access.RoleUser)
		ticket, _ := e.temporaryTicket(t, "alice", true)
		e.requireRefused(t, do(e.route(t, "authLoginSetPassword"), e.setPassword(t, testOrigin, ticket, chosenPassword)), access.CodePasswordLoginDisabled)
		id, options := e.begin(t, "authLoginSetPasskeyBegin", "", jsonBody(t, TicketRequest{Ticket: ticket}))
		w := do(e.route(t, "authLoginSetPasskeyFinish"), finish(e.route(t, "authLoginSetPasskeyFinish"), id, accesstest.NewPasskeyDevice(t).Register(options)))
		if out := signInOutcome(t, e, w); out.SignedIn == nil {
			t.Errorf("set-passkey on the kept ticket answers %s, want {signed_in}", w.Body.Bytes())
		}
	})
	// A plain ticket's set-password is a password
	// set, allowed with the rule off, and its session is a plain one.
	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, perRequest)
		e.createUser(t, "alice", access.RoleUser)
		ticket, _ := e.temporaryTicket(t, "alice", false)
		w := do(e.route(t, "authLoginSetPassword"), e.setPassword(t, plainOrigin, ticket, chosenPassword))
		if out := signInOutcome(t, e, w); out.SignedIn == nil {
			t.Fatalf("answer %s, want {signed_in}", w.Body.Bytes())
		}
		if !sessionCookieSet(e, w, false) {
			t.Errorf("Set-Cookie %v, want the plain session cookie", w.Result().Cookies())
		}
	})
}

// TestLoginSetPasskey checks authLoginSetPasskeyBegin and Finish, where a
// registered passkey meets the rule: the finish answers
// SignInOutcome's {signed_in} with the session's cookie under either
// setting, and the passkey is the user's.
func TestLoginSetPasskey(t *testing.T) {
	t.Parallel()
	for name, opts := range map[string]envOptions{"rule_off": passkeys, "rule_on": requireRule} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, opts)
			e.createUser(t, "alice", access.RoleUser)
			ticket, _ := e.temporaryTicket(t, "alice", true)
			id, options := e.begin(t, "authLoginSetPasskeyBegin", "", jsonBody(t, TicketRequest{Ticket: ticket}))
			rt := e.route(t, "authLoginSetPasskeyFinish")
			w := do(rt, finish(rt, id, accesstest.NewPasskeyDevice(t).Register(options)))
			out := signInOutcome(t, e, w)
			if out.Pending != nil || out.SignedIn == nil || out.SignedIn.User.Username != "alice" {
				t.Fatalf("answer %s, want {signed_in} for alice", w.Body.Bytes())
			}
			if !sessionCookieSet(e, w, true) {
				t.Errorf("Set-Cookie %v, want the secure session cookie", w.Result().Cookies())
			}
			if pks, err := e.mem.PasskeysByUserID(t.Context(), e.user(t, "alice").ID); err != nil || len(pks) != 1 {
				t.Errorf("alice's passkeys %d (%v), want the registered one", len(pks), err)
			}
		})
	}
}
