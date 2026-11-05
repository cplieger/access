package accesshttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// censusMark is the context key every census request carries, so the
// recording store counts that request's account store calls and no sweep's.
type censusMark struct{}

var errStubbed = errors.New("census: operation reached")

// credential is what a census principal presents.
type credential int

const (
	credNone credential = iota
	credStale
	credSession
	credRecovery
	credKey
	credAgent
	credBypass
)

// censusPrincipal is one row of §9.5's census matrix.
type censusPrincipal struct {
	send   func(r *http.Request)
	name   string
	scopes []string // a key's scopes
	kind   credential
	fault  Code // what the Authenticator refuses a fault principal with
	recent bool // a full session inside RecentAuth
	admin  bool // the principal's user is an admin
}

// guardAnswer is the census cell for p on d: the code the guard refuses
// with, or "" when p passes it.
func (p *censusPrincipal) guardAnswer(d *Descriptor) Code {
	if d.Class == ClassPublic {
		return ""
	}
	if p.fault != "" {
		return p.fault
	}
	keyClass := d.Class == ClassKeyScope || d.Class == ClassKeyPermission
	switch p.kind {
	case credNone:
		return CodeAuthRequired
	case credStale:
		return CodeSessionExpired
	case credRecovery:
		if d.Class == ClassRecovery {
			return ""
		}
	case credSession:
		switch d.Class {
		case ClassSession, ClassKeyScope:
			return ""
		case ClassRecentAuth, ClassKeyPermission:
			if p.recent {
				return ""
			}
			return CodeRecentAuthRequired
		default:
		}
	case credKey:
		if keyClass && slices.Contains(p.scopes, d.Scope) {
			return ""
		}
		if keyClass {
			return CodeScopeRequired
		}
	default:
		if keyClass {
			return CodeScopeRequired
		}
	}
	return CodeSessionRequired
}

// census is a handler whose operations it counts and, while stub is set,
// stubs with fault (errStubbed when nil), over a store that counts each
// census request's account calls. faults are principals the Authenticator
// refuses, outside §9.5's matrix.
type census struct {
	*env
	store      *countingStore
	fault      atomic.Pointer[error]
	lastOp     atomic.Pointer[string]
	principals []censusPrincipal
	faults     []censusPrincipal
	reached    atomic.Int64
	stub       atomic.Bool
}

// principal is the census principal named name.
func (c *census) principal(t testing.TB, name string) *censusPrincipal {
	t.Helper()
	i := slices.IndexFunc(c.principals, func(p censusPrincipal) bool { return p.name == name })
	if i < 0 {
		t.Fatalf("no census principal %s", name)
	}
	return &c.principals[i]
}

func scopeLabel(set bool) string {
	if set {
		return "scopes_set"
	}
	return "scopes_empty"
}

// agentVerifier is a custom verifier in marotte's agent-key shape: an
// X-Agent header grants root its comma-separated scopes. X-Agent-Fault
// "refused" makes it refuse the credential, and "down" fail as its store
// would.
type agentVerifier struct{ e *env }

func (v agentVerifier) Verify(ctx context.Context, r *http.Request) (access.Principal, bool, error) {
	switch r.Header.Get("X-Agent-Fault") {
	case "refused":
		return access.Principal{}, false, &access.InvalidCredentialError{Method: "agent", Err: access.ErrAccountDisabled}
	case "down":
		return access.Principal{}, false, fmt.Errorf("%w: agent store", access.ErrAuthBackend)
	default:
	}
	sent, ok := r.Header["X-Agent"]
	if !ok {
		return access.Principal{}, false, nil
	}
	u, found, err := v.e.mem.UserByUsername(ctx, "root")
	if err != nil || !found {
		return access.Principal{}, false, err
	}
	scopes := strings.FieldsFunc(sent[0], func(r rune) bool { return r == ',' })
	return access.Principal{User: u, Method: "agent", Scopes: scopes}, true, nil
}

var censusScopes = []string{scopeAdminName, scopeUsersName, scopeKeysName, "read"}

// newCensus builds a census env with the three key scopes all set or all
// empty, every scope name listed in Rules either way; bypass grants every
// request the bypass principal.
func newCensus(t *testing.T, set, bypass bool) *census {
	t.Helper()
	c := &census{store: &countingStore{mark: censusMark{}}}
	c.env = newEnv(t, envOptions{
		edit: func(cfg *account.Config) {
			if set {
				cfg.AdminScope, cfg.ManageUsersScope, cfg.CreateKeysScope = scopeAdminName, scopeUsersName, scopeKeysName
			}
			c.store.wrap(cfg.Store)
			cfg.Store = c.store
		},
		authn: func(e *env, cfg *access.Config) {
			cfg.Verifier = agentVerifier{e}
			if bypass {
				cfg.Bypass = func() bool { return true }
			}
		},
		rules: func(r *account.Rules) { r.Scopes = censusScopes },
		wrap: func(_ *env, s *account.Service) accountAPI {
			return stubAccount{accountAPI: s, answer: func(op string) (bool, error) {
				c.reached.Add(1)
				c.lastOp.Store(&op)
				if f := c.fault.Load(); f != nil {
					return c.stub.Load(), *f
				}
				return c.stub.Load(), errStubbed
			}}
		},
	})
	if bypass {
		c.principals = []censusPrincipal{{name: "bypass", kind: credBypass, admin: true, send: func(*http.Request) {}}}
		return c
	}
	c.createUser(t, "root", access.RoleAdmin)
	c.createUser(t, "alice", access.RoleUser)
	c.createUser(t, "kim", access.RoleAdmin)
	cookie := func(ck *http.Cookie) func(*http.Request) { return func(r *http.Request) { r.AddCookie(ck) } }
	key := func(owner string, scopes ...string) func(*http.Request) {
		k := c.mintKey(t, owner, account.NewKey{Label: owner, Scopes: scopes})
		return func(r *http.Request) { bearer(r, k.Plaintext) }
	}
	agent := func(scopes string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("X-Agent", scopes) }
	}
	kimKey := key("kim", scopeAdminName)
	kim := c.user(t, "kim")
	kim.Role = access.RoleUser
	if err := c.mem.UpdateUser(t.Context(), kim); err != nil {
		t.Fatalf("UpdateUser(kim): %v", err)
	}
	c.principals = []censusPrincipal{
		{name: "none", kind: credNone, send: func(*http.Request) {}},
		{name: "stale_session", kind: credStale, admin: true, send: cookie(c.storedSession(t, "root", 48*time.Hour, 48*time.Hour))},
		{name: "full_session", kind: credSession, admin: true, send: cookie(c.storedSession(t, "root", time.Hour, 0))},
		{name: "recent_session", kind: credSession, admin: true, recent: true, send: cookie(c.storedSession(t, "root", 0, 0))},
		{name: "user_recent_session", kind: credSession, recent: true, send: cookie(c.storedSession(t, "alice", 0, 0))},
		{name: "recovery_session", kind: credRecovery, send: cookie(c.recoveryCookie(t, "alice"))},
		{name: "admin_key_admin_scope", kind: credKey, admin: true, scopes: []string{scopeAdminName}, send: key("root", scopeAdminName)},
		{name: "admin_key_no_admin_scope", kind: credKey, admin: true, scopes: []string{"read"}, send: key("root", "read")},
		{name: "user_key_admin_scope", kind: credKey, scopes: []string{scopeAdminName}, send: kimKey},
		{name: "admin_key_manage_users", kind: credKey, admin: true, scopes: []string{scopeUsersName}, send: key("root", scopeUsersName)},
		{name: "admin_key_create_keys", kind: credKey, admin: true, scopes: []string{scopeKeysName}, send: key("root", scopeKeysName)},
		{name: "agent_no_scopes", kind: credAgent, admin: true, send: agent("")},
		{name: "agent_every_scope", kind: credAgent, admin: true, send: agent(strings.Join(censusScopes, ","))},
	}
	fault := func(how string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("X-Agent-Fault", how) }
	}
	c.faults = []censusPrincipal{
		{name: "unknown_key", fault: CodeKeyInvalid, send: func(r *http.Request) { bearer(r, access.NewSecret("not-a-key")) }},
		{name: "agent_refused", fault: CodeInvalidCredentials, send: fault("refused")},
		{name: "agent_store_down", fault: CodeUnavailable, send: fault("down")},
	}
	return c
}

// storedSession writes a full session for name straight into the store,
// signed in authAge ago and last active activeAge ago, and returns its
// cookie.
func (e *env) storedSession(t testing.TB, name string, authAge, activeAge time.Duration) *http.Cookie {
	t.Helper()
	token, hash := access.GenerateSessionToken()
	now := time.Now()
	s := &access.Session{
		ID: hex.EncodeToString(randomBytes(16)), UserID: e.user(t, name).ID, TokenHash: hash, AuthMethod: access.MethodPassword, Kind: access.SessionFull,
		CreatedAt: now.Add(-activeAge), LastActivity: now.Add(-activeAge), AuthTime: now.Add(-authAge),
	}
	if err := e.mem.CreateSession(t.Context(), s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return e.cookie(token)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// censusPathValue is a well-formed path value for rt that names nothing
// stored, so an admin's write past the policy finds no target.
func censusPathValue(t testing.TB, rt Route) string {
	switch specNamed(t, rt.Name).pathID {
	case pathSession:
		return strings.Repeat("ab", sessionIDLen/2)
	case pathMethod:
		return string(access.MethodPassword)
	default:
		return "999999"
	}
}

// censusBody is a body rt decodes: its request type's golden fixture, or
// an opaque credential on a WebAuthn finish.
func censusBody(t testing.TB, rt Route) string {
	t.Helper()
	if rt.Request == nil {
		if specNamed(t, rt.Name).cer != ceremonyNone {
			return `{}`
		}
		return ""
	}
	for _, f := range fixtures() {
		if f.name == rt.Request.Name() {
			return jsonBody(t, f.value)
		}
	}
	t.Fatalf("no fixture for %s", rt.Request.Name())
	return ""
}

// serve sends p's request on rt and returns the response, the Errors it
// recorded and the account store calls it made.
func (c *census) serve(t *testing.T, rt Route, p *censusPrincipal, body string) (w *httptest.ResponseRecorder, errs []Error, calls int64) {
	t.Helper()
	r := requestFor(rt, censusPathValue(t, rt), body)
	p.send(r)
	r = r.WithContext(context.WithValue(r.Context(), censusMark{}, true))
	errsBefore, callsBefore := len(c.errs.all()), c.store.calls.Load()
	w = do(rt, r)
	return w, c.errs.all()[errsBefore:], c.store.calls.Load() - callsBefore
}

// TestCensusMatrix is §9.5 "Census": every principal against every route,
// under the key scopes all empty and all set. A refused cell runs over the
// real Service and answers its guard code with no account store call and no
// operation called, so a guard that lets it through to account, which
// refuses most of them with the same code and some before any store read,
// fails. A passing cell reaches its operation, stubbed so no cell writes,
// except on the key_scope routes, whose real policy answers admin and
// non-admin apart.
func TestCensusMatrix(t *testing.T) {
	descriptors := func(t *testing.T) {
		e := newEnv(t, envOptions{})
		named := map[string]bool{}
		for _, f := range fixtures() {
			named[f.name] = true
		}
		routes := e.h.Routes()
		if len(routes) != len(specs) {
			t.Errorf("%d routes, %d specs", len(routes), len(specs))
		}
		for _, rt := range routes {
			if rt.Handler == nil || !slices.Contains([]Class{ClassPublic, ClassSession, ClassRecentAuth, ClassKeyScope, ClassKeyPermission, ClassRecovery}, rt.Class) {
				t.Errorf("%s: handler %v, class %q", rt.Name, rt.Handler != nil, rt.Class)
			}
			for _, typ := range []string{typeName(rt.Request), typeName(rt.Response)} {
				if typ != "" && !named[typ] {
					t.Errorf("%s: no fixture for %s", rt.Name, typ)
				}
			}
		}
	}
	t.Run("every_descriptor_has_a_route_fixture_and_class", descriptors)
	for _, set := range []bool{false, true} {
		t.Run(scopeLabel(set), func(t *testing.T) {
			t.Parallel()
			envs := []*census{newCensus(t, set, false), newCensus(t, set, true)}
			for i, rt := range envs[0].h.Routes() {
				t.Run(rt.Name, func(t *testing.T) {
					for _, c := range envs {
						for j := range c.principals {
							t.Run(c.principals[j].name, func(t *testing.T) { c.cell(t, c.h.Routes()[i], &c.principals[j]) })
						}
					}
				})
			}
		})
	}
}

func typeName(t reflect.Type) string {
	if t == nil {
		return ""
	}
	return t.Name()
}

// cell runs one census cell.
func (c *census) cell(t *testing.T, rt Route, p *censusPrincipal) {
	want := p.guardAnswer(&rt.Descriptor)
	viaPolicy := want == "" && rt.Class == ClassKeyScope
	c.stub.Store(want == "" && !viaPolicy)
	defer c.stub.Store(false)
	reachedBefore := c.reached.Load()
	w, errs, calls := c.serve(t, rt, p, censusBody(t, rt))
	reached := c.reached.Load() > reachedBefore
	switch {
	case want != "":
		if len(errs) != 1 || errs[0].Code != want || w.Code != codeTable[codeIndex[want]].status {
			t.Errorf("status %d, errors %+v, want %s", w.Code, errs, want)
		}
		if calls != 0 || reached {
			t.Errorf("the refused request made %d account store calls (operation called: %v)", calls, reached)
		}
	case viaPolicy && !p.admin:
		if len(errs) != 1 || errs[0].Code != CodeForbidden {
			t.Errorf("status %d, errors %+v, want auth_forbidden from the policy", w.Code, errs)
		}
	case viaPolicy && rt.Method == http.MethodDelete:
		if len(errs) != 1 || errs[0].Code != CodeNotFound {
			t.Errorf("status %d, errors %+v, want an admin's auth_not_found for a missing key", w.Code, errs)
		}
	case viaPolicy:
		if w.Code != http.StatusOK || len(errs) != 0 {
			t.Errorf("status %d, errors %+v, want an admin's data", w.Code, errs)
		}
	case rt.Name == "authOIDCPending":
		// It reads only its own cookie: past the guard, none is not found.
		if len(errs) != 1 || errs[0].Code != CodeNotFound {
			t.Errorf("status %d, errors %+v, want auth_not_found past the guard", w.Code, errs)
		}
	case !reached:
		t.Errorf("status %d, errors %+v; the request never reached its operation", w.Code, errs)
	default:
	}
}

// TestCensusUserNamingAdminRoutes is §9.5 "Census"'s policy-before-existence
// cells: a non-admin's recent session on each user-naming admin route, for
// an existing and a missing ID with the same body, and, with the scopes
// set, a manage_users key naming an admin, all answer auth_forbidden alike
// and write nothing.
func TestCensusUserNamingAdminRoutes(t *testing.T) {
	for _, set := range []bool{false, true} {
		t.Run(scopeLabel(set), func(t *testing.T) {
			t.Parallel()
			c := newCensus(t, set, false)
			root := c.user(t, "root")
			rootID := c.userID(t, "root")
			unchanged := jsonBody(t, UserUpdateRequest{Role: &root.Role, Enabled: &root.Enabled})
			bodies := map[string]string{"authAdminUserUpdate": unchanged, "authAdminUserDelete": "", "authAdminRecovery": `{}`}
			userSession := &c.principals[slices.IndexFunc(c.principals, func(p censusPrincipal) bool { return p.name == "user_recent_session" })]
			usersKey := &c.principals[slices.IndexFunc(c.principals, func(p censusPrincipal) bool { return p.name == "admin_key_manage_users" })]
			for name, body := range bodies {
				t.Run(name, func(t *testing.T) {
					rt := c.route(t, name)
					send := func(p *censusPrincipal, id string) (*httptest.ResponseRecorder, Error) {
						r := requestFor(rt, id, body)
						p.send(r)
						before := len(c.errs.all())
						w := do(rt, r)
						errs := c.errs.all()[before:]
						if len(errs) != 1 || errs[0].Code != CodeForbidden || strings.Contains(w.Body.String(), "username") {
							t.Fatalf("id %s: status %d, errors %+v, body %q; want auth_forbidden and no UserView", id, w.Code, errs, w.Body.String())
						}
						return w, Error{Code: errs[0].Code, Detail: errs[0].Detail, Reason: errs[0].Reason, Status: errs[0].Status}
					}
					existing, existingErr := send(userSession, rootID)
					missing, missingErr := send(userSession, "999999")
					if existingErr != missingErr || existing.Code != missing.Code || existing.Body.String() != missing.Body.String() {
						t.Errorf("existing %d %+v %q, missing %d %+v %q; want identical answers", existing.Code, existingErr, existing.Body, missing.Code, missingErr, missing.Body)
					}
					if set {
						send(usersKey, rootID)
					}
				})
			}
			if r := c.user(t, "root"); r.Role != access.RoleAdmin || !r.Enabled || len(c.liveTokens(t)) != 0 {
				t.Errorf("root %+v, %d live tokens; want nothing written", r, len(c.liveTokens(t)))
			}
		})
	}
}
