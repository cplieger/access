package accesshttp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/failreason"
)

func TestAuditRefusalCarriesIP(t *testing.T) {
	e := newEnv(t, envOptions{})
	cases := []struct {
		name, route, kind, reason string
		edit                      func(*http.Request)
	}{
		{"guard_refusal", "authStepUpPassword", "stepup.failure", "required", func(*http.Request) {}},
		{"cross_origin", "authLoginPassword", "login.failure", "cross_origin", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(e.audits.all())
			rt := e.route(t, tc.route)
			r := request(rt, jsonBody(t, PasswordRequest{Password: testPassword}))
			tc.edit(r)
			do(rt, r)
			events := e.audits.all()[before:]
			if len(events) != 1 || events[0].Kind != tc.kind || events[0].Reason != tc.reason || events[0].IP != "192.0.2.1" {
				t.Errorf("events %+v, want one %s %s from 192.0.2.1", events, tc.kind, tc.reason)
			}
		})
	}
}

func TestAuditNoRawText(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.createUser(t, "alice", access.RoleUser)
	agent := "Agent/" + strings.Repeat("u", 1<<20)
	rt := e.route(t, "authLoginPassword")
	cases := []struct {
		name, username, wantUsername string
	}{
		{"refused_username", "bad\x00name-raw", ""},
		{"wrong_password", "Alice", "alice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(e.audits.all())
			r := request(rt, jsonBody(t, LoginRequest{Username: tc.username, Password: "wrong-password-for-alice"}))
			r.Header.Set("User-Agent", agent)
			if w := do(rt, r); w.Code == http.StatusOK {
				t.Fatalf("status 200, want a refusal")
			}
			events := e.audits.all()[before:]
			if len(events) != 1 || events[0].Kind != "login.failure" || events[0].Username != tc.wantUsername {
				t.Fatalf("events %+v, want one login.failure naming %q", events, tc.wantUsername)
			}
			printed := fmt.Sprintf("%+v", events[0])
			// A provider's error_description reaches only the OIDC callback; that route's audit test owns it.
			for _, raw := range []string{"uuuuuuuu", "Agent/", "name-raw"} {
				if strings.Contains(printed, raw) {
					t.Errorf("audit event holds raw request text %q", raw)
				}
			}
		})
	}
}

// lockedAccount answers every password check as a locked password does:
// invalid credentials carrying the internal reason method_locked.
type lockedAccount struct{ accountAPI }

var errLocked = failreason.Wrap(account.ErrInvalidCredentials, failreason.MethodLocked)

func (lockedAccount) PasswordLogin(context.Context, account.Client, account.Credentials) (account.SignedIn, error) {
	return account.SignedIn{}, errLocked
}

func (lockedAccount) StepUpPassword(context.Context, account.Client, access.Principal, access.Secret) (account.Issued, error) {
	return account.Issued{}, errLocked
}

func TestAuditInternalReason(t *testing.T) {
	e := newEnv(t, envOptions{wrap: func(_ *env, s *account.Service) accountAPI { return lockedAccount{s} }})
	e.createUser(t, "alice", access.RoleUser)
	session := e.sessionCookie(t, "alice")
	cases := []struct {
		name, route, kind, body string
		cookie                  *http.Cookie
	}{
		{"login", "authLoginPassword", "login.failure", jsonBody(t, LoginRequest{Username: "alice", Password: testPassword}), nil},
		{"step_up", "authStepUpPassword", "stepup.failure", jsonBody(t, PasswordRequest{Password: testPassword}), session},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errsBefore, auditsBefore := len(e.errs.all()), len(e.audits.all())
			rt := e.route(t, tc.route)
			var cookies []*http.Cookie
			if tc.cookie != nil {
				cookies = append(cookies, tc.cookie)
			}
			do(rt, request(rt, tc.body, cookies...))
			errs, events := e.errs.all()[errsBefore:], e.audits.all()[auditsBefore:]
			if len(errs) != 1 || errs[0].Code != CodeInvalidCredentials || errs[0].Reason != "" {
				t.Errorf("errors %+v, want one auth_invalid_credentials with no Reason", errs)
			}
			if len(events) != 1 || events[0].Kind != tc.kind || events[0].Reason != "method_locked" {
				t.Errorf("events %+v, want one %s with Reason method_locked", events, tc.kind)
			}
		})
	}
}
