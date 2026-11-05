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

// requireNoStore checks that the response w sent carries Cache-Control:
// no-store.
func requireNoStore(t *testing.T, what string, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Result().Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("%s: status %d, Cache-Control %q, want no-store", what, w.Code, got)
	}
}

// TestNoStoreEverywhere is BRIEF-8 over every route: every census cell,
// every boundary case and every sentinel its account call can answer, under
// the key scopes all empty and all set, and a success through each way a
// route writes one (a JSON body, a show-once body, no body and a redirect)
// answer with Cache-Control: no-store.
func TestNoStoreEverywhere(t *testing.T) {
	for _, set := range []bool{false, true} {
		t.Run(scopeLabel(set), func(t *testing.T) {
			c, bypass := newCensus(t, set, false), newCensus(t, set, true)
			for i, rt := range c.h.Routes() {
				t.Run(rt.Name, func(t *testing.T) {
					for _, cc := range []*census{c, bypass} {
						brt := cc.h.Routes()[i]
						for j := range cc.principals {
							p := &cc.principals[j]
							cc.stub.Store(true)
							w, _, _ := cc.serve(t, brt, p, censusBody(t, brt))
							cc.stub.Store(false)
							requireNoStore(t, p.name, w)
						}
					}
					for _, bc := range c.boundaryCases(t, rt) {
						_, brt, r := bc.build(t)
						requireNoStore(t, bc.name, do(brt, r))
					}
					pass := c.passing(t, rt)
					c.stub.Store(true)
					defer c.stub.Store(false)
					defer c.fault.Store(nil)
					for _, sentinel := range accountSentinels {
						c.fault.Store(&sentinel.err)
						r := requestFor(rt, censusPathValue(t, rt), censusBody(t, rt))
						pass.send(r)
						requireNoStore(t, sentinel.name, do(rt, r))
					}
				})
			}
		})
	}
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		e.createUser(t, "alice", access.RoleAdmin)
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		for _, tc := range []struct {
			serve  func(t *testing.T) *httptest.ResponseRecorder
			name   string
			status int
		}{
			{name: "authState", status: http.StatusOK, serve: func(t *testing.T) *httptest.ResponseRecorder {
				return do(e.route(t, "authState"), request(e.route(t, "authState"), ""))
			}},
			{name: "authLoginPassword", status: http.StatusOK, serve: func(t *testing.T) *httptest.ResponseRecorder {
				rt := e.route(t, "authLoginPassword")
				return do(rt, request(rt, signInBody(t, "alice")))
			}},
			{name: "authKeyCreate", status: http.StatusCreated, serve: func(t *testing.T) *httptest.ResponseRecorder {
				rt := e.route(t, "authKeyCreate")
				return do(rt, request(rt, jsonBody(t, NewKeyRequest{Label: "k", Scopes: []string{}}), e.sessionCookie(t, "alice")))
			}},
			{name: "authLogout", status: http.StatusNoContent, serve: func(t *testing.T) *httptest.ResponseRecorder {
				rt := e.route(t, "authLogout")
				return do(rt, request(rt, "", e.sessionCookie(t, "alice")))
			}},
			{name: "authOIDCCallback", status: http.StatusFound, serve: func(t *testing.T) *httptest.ResponseRecorder {
				return e.signInFlow(t, newBrowser(t), idp, "")
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				w := tc.serve(t)
				if w.Code != tc.status {
					t.Fatalf("status %d, errors %+v, want %d", w.Code, e.errs.all(), tc.status)
				}
				requireNoStore(t, tc.name, w)
			})
		}
	})
}

// countingAccount counts the account calls a refused request must not make.
type countingAccount struct {
	accountAPI
	calls atomic.Int32
}

func (c *countingAccount) PasswordLogin(ctx context.Context, cl account.Client, in account.Credentials) (account.SignedIn, error) {
	c.calls.Add(1)
	return c.accountAPI.PasswordLogin(ctx, cl, in)
}

func (c *countingAccount) RemovePassword(ctx context.Context, cl account.Client, p access.Principal, current access.Secret) (account.Issued, error) {
	c.calls.Add(1)
	return c.accountAPI.RemovePassword(ctx, cl, p, current)
}

func TestCrossOriginRefused(t *testing.T) {
	counting := &countingAccount{}
	e := newEnv(t, envOptions{wrap: func(_ *env, s *account.Service) accountAPI { counting.accountAPI = s; return counting }})
	e.createUser(t, "alice", access.RoleUser)
	session := e.sessionCookie(t, "alice")
	cases := []struct {
		name, route, body string
		headers           map[string]string
	}{
		{"same_site_sibling_delete", "authPasswordRemove", "", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://sibling.example.com"}},
		{"origin_only_post", "authLoginPassword", jsonBody(t, LoginRequest{Username: "alice", Password: testPassword}), map[string]string{"Sec-Fetch-Site": "", "Origin": "https://sibling.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := e.route(t, tc.route)
			r := request(rt, tc.body, session)
			for k, v := range tc.headers {
				if v == "" {
					r.Header.Del(k)
				} else {
					r.Header.Set(k, v)
				}
			}
			before := len(e.errs.all())
			w := do(rt, r)
			errs := e.errs.all()[before:]
			if w.Code != http.StatusForbidden || len(errs) != 1 || errs[0].Code != CodeCrossOrigin {
				t.Errorf("status %d errors %+v, want 403 auth_cross_origin", w.Code, errs)
			}
			if n := counting.calls.Load(); n != 0 {
				t.Errorf("%d account calls, want none", n)
			}
			if w.Header().Get("Set-Cookie") != "" {
				t.Errorf("Set-Cookie %q on a refused request", w.Header().Get("Set-Cookie"))
			}
		})
	}
}
