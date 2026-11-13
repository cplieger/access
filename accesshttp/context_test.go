package accesshttp

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// passthroughValue is the key of the value every request in
// TestContextPassthroughEveryRoute carries: the name of its route.
type passthroughValue struct{}

// storeCall is one store call a request made.
type storeCall struct {
	value       any // the call context's passthroughValue
	route, name string
	inTx        bool
}

// passthrough records the store calls, the Authenticator's included, that
// each request served through env.route makes; calls outside a request
// (the fixtures' own) are not recorded.
type passthrough struct {
	current atomic.Pointer[string]
	calls   []storeCall
	mu      sync.Mutex
}

func (p *passthrough) seen(ctx context.Context, call string, inTx bool) {
	cur := p.current.Load()
	if cur == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, storeCall{route: *cur, name: call, inTx: inTx, value: ctx.Value(passthroughValue{})})
}

func (p *passthrough) recorded() []storeCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls)
}

// around serves rt with its name as the request's passthroughValue.
func (p *passthrough) around(rt Route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.current.Store(&rt.Name)
		defer p.current.Store(nil)
		rt.Handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), passthroughValue{}, rt.Name)))
	})
}

// passthroughCase drives route through one flow and returns route's
// response; want is the code it refuses with, "" for a success.
type passthroughCase struct {
	run   func(t *testing.T, e *env) *httptest.ResponseRecorder
	name  string
	route string
	want  access.Code
	opts  envOptions
}

var createKeys = envOptions{
	rules: func(r *account.Rules) { r.Scopes = []string{scopeKeysName} },
	edit:  func(c *account.Config) { c.CreateKeysScope = scopeKeysName },
}

func passthroughCases() []passthroughCase {
	serve := func(t *testing.T, e *env, name string, r *http.Request) *httptest.ResponseRecorder {
		t.Helper()
		return do(e.route(t, name), r)
	}
	oidcFlow := func(start string, linked bool) func(t *testing.T, e *env) *httptest.ResponseRecorder {
		return func(t *testing.T, e *env) *httptest.ResponseRecorder {
			idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
			b := e.signedInBrowser(t, "alice")
			if linked {
				e.linkUser(t, "alice", idpIdentity(testIssuer))
			}
			if start == "" {
				return e.signInFlow(t, newBrowser(t), idp, "")
			}
			return e.sessionFlow(t, b, idp, start, "/settings", nil)
		}
	}
	return []passthroughCase{
		{name: "setup_password", route: "authSetupPassword", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			return serve(t, e, "authSetupPassword", e.post(t, "authSetupPassword", setupPasswordBody(t, "")))
		}},
		{name: "setup_passkey", route: "authSetupPasskeyFinish", opts: passkeys, run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			return serve(t, e, "authSetupPasskeyFinish", e.setupFinish(t, "", nil, nil))
		}},
		{name: "login_password", route: "authLoginPassword", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			e.createUser(t, "alice", access.RoleUser)
			return serve(t, e, "authLoginPassword", e.post(t, "authLoginPassword", signInBody(t, "alice")))
		}},
		{name: "login_password_counted_failure", route: "authLoginPassword", want: access.CodeInvalidCredentials, run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			e.createUser(t, "alice", access.RoleUser)
			return serve(t, e, "authLoginPassword", e.post(t, "authLoginPassword", jsonBody(t, LoginRequest{Username: "alice", Password: "not-" + testPassword})))
		}},
		{name: "login_passkey", route: "authLoginPasskeyFinish", opts: passkeys, run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			return serve(t, e, "authLoginPasskeyFinish", e.loginFinish(t, nil))
		}},
		{name: "oidc_sign_in", route: "authOIDCCallback", run: oidcFlow("", true)},
		{name: "oidc_link", route: "authOIDCCallback", run: oidcFlow("authOIDCStartLink", false)},
		{name: "oidc_step_up", route: "authOIDCCallback", run: oidcFlow("authOIDCStartStepUp", true)},
		{name: "oidc_link_pending", route: "authOIDCLinkPending", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
			b := e.signedInBrowser(t, "alice")
			e.signInFlow(t, b, idp, "")
			rt := e.route(t, "authOIDCLinkPending")
			return b.send(rt, request(rt, ""))
		}},
		{name: "recovery_start", route: "authRecoveryStart", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			e.createUser(t, "alice", access.RoleUser)
			issued, err := e.svc.IssueRecovery(t.Context(), account.OutOfBand("test"), e.user(t, "alice").ID, 0)
			if err != nil {
				t.Fatalf("IssueRecovery: %v", err)
			}
			return serve(t, e, "authRecoveryStart", e.post(t, "authRecoveryStart", jsonBody(t, TokenRequest{Token: issued.Plaintext.Reveal()})))
		}},
		{name: "invite_accept", route: "authInviteAcceptPassword", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			body := inviteBody(t, e.invite(t), "bob", testPassword)
			return serve(t, e, "authInviteAcceptPassword", e.post(t, "authInviteAcceptPassword", body))
		}},
		{name: "step_up_password", route: "authStepUpPassword", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			cookie := e.aliceSession(t)
			return serve(t, e, "authStepUpPassword", e.post(t, "authStepUpPassword", jsonBody(t, PasswordRequest{Password: testPassword}), cookie))
		}},
		{name: "step_up_passkey", route: "authStepUpPasskeyFinish", opts: passkeys, run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			cookie := e.aliceSession(t)
			return serve(t, e, "authStepUpPasskeyFinish", e.stepUpFinish(t, cookie, e.enrol(t, "alice"), nil, nil))
		}},
		{name: "password_set", route: "authPasswordSet", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			cookie := e.aliceSession(t)
			return serve(t, e, "authPasswordSet", e.post(t, "authPasswordSet", passwordSetBody(t, testPassword, newPassword), cookie))
		}},
		{name: "password_remove", route: "authPasswordRemove", opts: passkeys, run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			cookie := e.aliceSession(t)
			e.enrol(t, "alice")
			return serve(t, e, "authPasswordRemove", e.post(t, "authPasswordRemove", passwordRemoveBody(t, testPassword), cookie))
		}},
		{name: "passkey_enrol", route: "authPasskeyRegisterFinish", opts: passkeys, run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			return serve(t, e, "authPasskeyRegisterFinish", e.registerFinish(t, e.aliceSession(t), nil, nil, nil))
		}},
		{name: "key_mint_session", route: "authKeyCreate", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			cookie := e.aliceSession(t)
			return serve(t, e, "authKeyCreate", e.post(t, "authKeyCreate", jsonBody(t, NewKeyRequest{Label: "ci"}), cookie))
		}},
		{name: "key_mint_key", route: "authKeyCreate", opts: createKeys, run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			e.createUser(t, "root", access.RoleAdmin)
			parent := e.mintKey(t, "root", account.NewKey{Label: "parent", Scopes: []string{scopeKeysName}})
			r := bearer(e.post(t, "authKeyCreate", jsonBody(t, NewKeyRequest{Label: "child"})), parent.Plaintext)
			return serve(t, e, "authKeyCreate", r)
		}},
	}
}

// sessionResults are the account results that carry a new or rotated
// session.
var sessionResults = []reflect.Type{
	reflect.TypeFor[account.SignedIn](), reflect.TypeFor[account.Issued](), reflect.TypeFor[account.Recovery](),
	reflect.TypeFor[account.OIDCOutcome](), reflect.TypeFor[account.Registered](), reflect.TypeFor[account.CreatedKey](),
}

// sessionRoutes are the routes whose operation returns a session result:
// every session-minting and session-rotating route.
func sessionRoutes() []string {
	api := reflect.TypeFor[accountAPI]()
	var out []string
	for i := range specs {
		m, ok := api.MethodByName(specs[i].op)
		if !ok {
			continue
		}
		for res := range m.Type.Outs() {
			if slices.Contains(sessionResults, res) {
				out = append(out, specs[i].name)
				break
			}
		}
	}
	return out
}

// TestContextPassthroughEveryRoute is §9.5 "Context passthrough" through
// accesshttp: on every session-minting and session-rotating route, every
// store call each request of the flow makes, the Authenticator's and an
// Update's Tx calls included, carries the value the request's context
// carried.
func TestContextPassthroughEveryRoute(t *testing.T) {
	cases := passthroughCases()
	for _, route := range sessionRoutes() {
		if !slices.ContainsFunc(cases, func(c passthroughCase) bool { return c.route == route }) {
			t.Errorf("%s mints or rotates a session and has no passthrough case", route)
		}
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	t.Run("routes", func(t *testing.T) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				p := &passthrough{}
				e := newEnv(t, with(tc.opts, envOptions{store: func(m *accesstest.MemStore) account.Store {
					s := &countingStore{seen: p.seen}
					s.wrap(m)
					return s
				}}))
				e.around = p.around
				w := tc.run(t, e)
				switch errs := e.errs.all(); {
				case tc.want != "":
					if len(errs) == 0 || errs[len(errs)-1].Code != tc.want {
						t.Fatalf("status %d, errors %+v, want %s", w.Code, errs, tc.want)
					}
				case len(errs) != 0 || w.Code >= http.StatusBadRequest || (w.Code == http.StatusFound && redirectedCode(t, w) != ""):
					t.Fatalf("status %d, errors %+v, Location %q; want the flow to succeed", w.Code, errs, w.Header().Get("Location"))
				default:
				}
				calls := p.recorded()
				if !slices.ContainsFunc(calls, func(c storeCall) bool { return c.route == tc.route }) {
					t.Errorf("%s made no store call", tc.route)
				}
				for _, c := range calls {
					if c.value != c.route {
						t.Errorf("%s made store call %s (in an Update: %v) carrying %v, want its request's value", c.route, c.name, c.inTx, c.value)
					}
				}
				mu.Lock()
				defer mu.Unlock()
				for _, c := range calls {
					seen[c.name] = true
					if c.inTx {
						seen["Tx"] = true
					}
				}
			})
		}
	})
	for _, name := range []string{"Update", "Tx", "PutAuthFailure", "CreateSession", "RotateSession", "SessionByHash", "APIKeyByHash"} {
		if !seen[name] {
			t.Errorf("no request made a %s call, so the passthrough of its context is unproven; seen %v", name, slices.Sorted(maps.Keys(seen)))
		}
	}
}
