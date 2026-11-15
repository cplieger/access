package accesshttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// requireRule is an env under RequireSecondFactor with passkeys wired.
var requireRule = with(passkeys, envOptions{rules: func(r *account.Rules) { r.RequireSecondFactor = true }})

// addPasskeyFor stores a passkey of name under the env's relying party.
func (e *env) addPasskeyFor(t testing.TB, name string) {
	t.Helper()
	u := e.user(t, name)
	if err := e.mem.CreatePasskey(t.Context(), &access.PasskeyCredential{UserID: u.ID, CredentialID: []byte("cred-" + name), PublicKey: []byte("pk"), RPID: testRPID, Name: "key", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreatePasskey: %v", err)
	}
}

// strictDecode decodes body into v, refusing a field v lacks.
func strictDecode(t testing.TB, body []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}

// TestLoginOutcome is authLoginPassword's 200 answer, {signed_in} or
// {pending}, and that a pending one sets no cookie (design 4.4, 4.12).
func TestLoginOutcome(t *testing.T) {
	t.Parallel()
	t.Run("signed_in", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		w := do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", signInBody(t, "alice")))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		var out SignInOutcome
		strictDecode(t, w.Body.Bytes(), &out)
		if out.Pending != nil || out.SignedIn == nil || out.SignedIn.User.Username != "alice" || out.SignedIn.SessionID == "" {
			t.Errorf("answer = %s, want {signed_in} for alice", w.Body.Bytes())
		}
	})
	t.Run("pending", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, requireRule)
		e.createUser(t, "alice", access.RoleUser)
		e.addPasskeyFor(t, "alice")
		w := do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", signInBody(t, "alice")))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		var out SignInOutcome
		strictDecode(t, w.Body.Bytes(), &out)
		if out.SignedIn != nil || out.Pending == nil || out.Pending.Ticket == "" || out.Pending.Next != account.NextSecondFactor || !slices.Equal(out.Pending.Methods, []PendingMethod{PendingPasskey}) {
			t.Fatalf("answer = %s, want {pending} second_factor [passkey]", w.Body.Bytes())
		}
		if c := w.Result().Cookies(); len(c) != 0 {
			t.Errorf("a pending answer set cookies %v, want none: the ticket is in the body only", c)
		}
		audits := e.audits.all()
		if len(audits) != 1 || audits[0].Kind != "login.pending" || audits[0].Username != "alice" || audits[0].Success {
			t.Errorf("audit = %+v, want one login.pending for alice", audits)
		}
	})
	t.Run("enrol_needs_known_device", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, requireRule)
		e.createUser(t, "alice", access.RoleUser)
		w := do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", signInBody(t, "alice")))
		if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
			t.Fatalf("status = %d with cookies %v, want 403 and none", w.Code, w.Result().Cookies())
		}
		if got := e.errs.all(); len(got) != 1 || got[0].Code != access.CodeSecondFactorRequired || got[0].Reason != ReasonEnrolNeedsKnownDevice {
			t.Errorf("error = %+v, want auth_second_factor_required with enrol_needs_known_device", got)
		}
	})
	t.Run("no_usable_method", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, with(requireRule, envOptions{rules: refusePasskeys}))
		e.createUser(t, "alice", access.RoleUser)
		w := do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", signInBody(t, "alice")))
		if got := e.errs.all(); w.Code != http.StatusForbidden || len(got) != 1 || got[0].Code != access.CodeForbidden || got[0].Reason != ReasonNoUsableMethod {
			t.Errorf("answer = %d %+v, want 403 auth_forbidden with no_usable_method", w.Code, got)
		}
	})
}

// refusePasskeys is a Rules edit whose MethodUsable refuses passkeys.
func refusePasskeys(r *account.Rules) {
	r.MethodUsable = func(_ context.Context, _ account.Tx, _ *access.User, m access.Method) bool {
		return m != access.MethodPasskey
	}
}

// TestTicketIsNoCredential is the Termix GHSA-vx59-rf9w-9jv8 regression: a
// pending sign-in's ticket opens no route as a session cookie or a Bearer
// value.
func TestTicketIsNoCredential(t *testing.T) {
	t.Parallel()
	e := newEnv(t, requireRule)
	e.createUser(t, "alice", access.RoleUser)
	e.addPasskeyFor(t, "alice")
	w := do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", signInBody(t, "alice")))
	var out SignInOutcome
	strictDecode(t, w.Body.Bytes(), &out)
	if out.Pending == nil {
		t.Fatalf("answer = %s, want a pending sign-in", w.Body.Bytes())
	}
	ticket := out.Pending.Ticket
	cookie := e.authn.Cookie()
	for _, rt := range e.h.Routes() {
		if rt.Class == ClassPublic {
			continue
		}
		for name, present := range map[string]func(*http.Request){
			"cookie": func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: cookie.CookieName(true), Value: ticket})
			},
			"bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+ticket) },
		} {
			r := requestFor(e.route(t, rt.Name), censusPathValue(t, rt), censusBody(t, rt))
			present(r)
			if w := do(e.route(t, rt.Name), r); w.Code != http.StatusUnauthorized {
				t.Errorf("%s with the ticket as a %s = %d, want 401", rt.Name, name, w.Code)
			}
		}
	}
}

// storedInvite is invite's token, issued through a session written to the
// store, since root's password sign-in pends under the rule.
func (e *env) storedInvite(t testing.TB) access.Secret {
	t.Helper()
	e.createUser(t, "root", access.RoleAdmin)
	issued, err := e.svc.CreateInvite(t.Context(), e.principal(t, e.storedSession(t, "root", 0, 0)), access.RoleUser, 0)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	return issued.Plaintext
}

// TestDraftOutcome is design 4.52: authSetupPassword and
// authInviteAcceptPassword answer SignInOutcome, a pending enrol with no
// cookie under RequireSecondFactor (design 4.8), and signed_in without it.
func TestDraftOutcome(t *testing.T) {
	t.Parallel()
	routes := map[string]func(t *testing.T, e *env) string{
		"authSetupPassword":        func(t *testing.T, _ *env) string { return setupPasswordBody(t, "") },
		"authInviteAcceptPassword": func(t *testing.T, e *env) string { return inviteBody(t, e.storedInvite(t), "bob", testPassword) },
	}
	for name, body := range routes {
		t.Run(name+"/pending", func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, with(requireRule, totpOn))
			w := do(e.route(t, name), e.post(t, name, body(t, e)))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d %s, want 200", w.Code, w.Body.Bytes())
			}
			var out SignInOutcome
			strictDecode(t, w.Body.Bytes(), &out)
			if out.SignedIn != nil || out.Pending == nil || out.Pending.Next != account.NextEnrol || !slices.Equal(out.Pending.Methods, []PendingMethod{PendingTOTP, PendingPasskey}) {
				t.Fatalf("answer = %s, want {pending} enrol [totp passkey]", w.Body.Bytes())
			}
			if c := w.Result().Cookies(); len(c) != 0 {
				t.Errorf("a draft's answer set cookies %v, want none", c)
			}
		})
		// Design 4.17: under the rule the password routes mint a draft, and an
		// app allowing no enrolment method answers no_usable_method.
		t.Run(name+"/no_usable_method", func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, with(requireRule, envOptions{rules: refusePasskeys}))
			w := do(e.route(t, name), e.post(t, name, body(t, e)))
			if got := e.errs.all(); w.Code != http.StatusForbidden || len(got) != 1 || got[0].Code != access.CodeForbidden || got[0].Reason != ReasonNoUsableMethod {
				t.Errorf("answer = %d %+v, want 403 auth_forbidden with no_usable_method", w.Code, got)
			}
		})
		t.Run(name+"/signed_in", func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, envOptions{})
			w := do(e.route(t, name), e.post(t, name, body(t, e)))
			var out SignInOutcome
			strictDecode(t, w.Body.Bytes(), &out)
			if w.Code != http.StatusOK || out.Pending != nil || out.SignedIn == nil || out.SignedIn.SessionID == "" {
				t.Fatalf("answer = %d %s, want {signed_in}", w.Code, w.Body.Bytes())
			}
		})
	}
}
