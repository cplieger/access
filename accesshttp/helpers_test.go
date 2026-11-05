package accesshttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/capture"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

const (
	testOrigin   = "https://app.example.com"
	testRPID     = "app.example.com"
	testPassword = "correct-horse-battery-staple-9" // gitleaks:allow (test fixture password)
)

// env is a Handler over a real Service on a MemStore, with what a test reads
// back: every Error the ErrorWriter got, every AuditEvent and the logs.
type env struct {
	mem     *accesstest.MemStore
	authn   *access.Authenticator
	svc     *account.Service
	h       *Handler
	hasher  *access.Hasher
	limiter *ratelimit.Limiter
	logs    *capture.Recorder
	errs    *recorded[Error]
	audits  *recorded[AuditEvent]
	// rp is what Config.RP returns; nil turns passkeys off mid-test.
	rp atomic.Pointer[webauthn.RelyingParty]
	// provider is what Config.OIDC returns; nil is OIDC off.
	provider atomic.Pointer[oidc.Provider]
	// around, when set, wraps the handler of every route route returns.
	around func(Route) http.Handler
}

type envOptions struct {
	edit func(*account.Config)
	// authn edits the Authenticator's config, the zero Config otherwise.
	authn func(e *env, c *access.Config)
	// rules edits the Rules every operation reads.
	rules func(*account.Rules)
	// limits edits the limiter's config, DefaultConfig otherwise.
	limits func(*ratelimit.Config)
	// writer replaces the ErrorWriter, which by default writes the status
	// and nothing else.
	writer func(e *env) ErrorWriter
	// wrap substitutes the account the Handler calls.
	wrap func(e *env, s *account.Service) accountAPI
	// store wraps the MemStore both the Authenticator and the Service use.
	store func(*accesstest.MemStore) account.Store
	// handler edits the Handler's config last, after writer.
	handler func(*Config)
	// mem is the MemStore, a new one when nil, so a rebuilt env can share
	// an earlier env's store.
	mem *accesstest.MemStore
	// passkeys sets the relying party for testOrigin.
	passkeys bool
}

// fastParams is OWASP's lightest Argon2id row, so a test hashes quickly at
// the floor NewHasher enforces.
var fastParams = access.Argon2Params{Memory: 7168, Iterations: 5, Parallelism: 1, SaltLength: 16, KeyLength: 32}

// hashWait bounds a busy hash, so holdBudget's refusals come fast.
const hashWait = 50 * time.Millisecond

type recorded[T any] struct {
	items []T
	mu    sync.Mutex
}

func (r *recorded[T]) add(v T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, v)
}

func (r *recorded[T]) all() []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.items)
}

func newEnv(t testing.TB, o envOptions) *env {
	t.Helper()
	e := &env{mem: o.mem, errs: &recorded[Error]{}, audits: &recorded[AuditEvent]{}}
	if e.mem == nil {
		e.mem = accesstest.NewMemStore()
	}
	var store account.Store = e.mem
	if o.store != nil {
		store = o.store(e.mem)
	}
	var acfg access.Config
	if o.authn != nil {
		o.authn(e, &acfg)
	}
	authn, err := access.New(store, acfg)
	if err != nil {
		t.Fatalf("access.New: %v", err)
	}
	e.authn = authn
	hasher, err := access.NewHasher(access.HasherConfig{Params: fastParams, Wait: hashWait})
	if err != nil {
		t.Fatalf("access.NewHasher: %v", err)
	}
	e.hasher = hasher
	lcfg := ratelimit.DefaultConfig()
	lcfg.Devices = access.NewEphemeralSealer()
	if o.limits != nil {
		o.limits(&lcfg)
	}
	limiter, err := ratelimit.New(t.Context(), lcfg)
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	t.Cleanup(func() { _ = limiter.Shutdown(context.Background()) })
	e.limiter = limiter
	if o.passkeys {
		rp, rpErr := webauthn.New(webauthn.RPConfig{ID: testRPID, DisplayName: "Example", Origins: []string{testOrigin}})
		if rpErr != nil {
			t.Fatalf("webauthn.New: %v", rpErr)
		}
		e.rp.Store(rp)
	}
	logger, logs := capture.New()
	e.logs = logs
	cfg := account.Config{
		Store:         store,
		Policy:        account.RolePolicy{},
		Authenticator: authn,
		Hasher:        hasher,
		Limiter:       limiter,
		RP:            e.rp.Load,
		OIDC:          e.provider.Load,
		Rules: func() account.Rules {
			r := account.Rules{SetupTokenRequired: func(context.Context, account.Client) bool { return false }}
			if o.rules != nil {
				o.rules(&r)
			}
			return r
		},
		Logger:     logger,
		FailureKey: []byte("authhttp-test-failure-key-32byte"),
	}
	if o.edit != nil {
		o.edit(&cfg)
	}
	svc, err := account.New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("account.New: %v", err)
	}
	t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
	e.svc = svc
	var acct accountAPI = svc
	if o.wrap != nil {
		acct = o.wrap(e, svc)
	}
	writer := ErrorWriter(func(w http.ResponseWriter, _ *http.Request, er Error) {
		e.errs.add(er)
		w.WriteHeader(er.Status)
	})
	if o.writer != nil {
		writer = o.writer(e)
	}
	hcfg := Config{
		Errors:     writer,
		Audit:      func(_ *http.Request, ev AuditEvent) { e.audits.add(ev) },
		Logger:     logger,
		Prefix:     "/api/auth",
		OIDCPrefix: "/api/auth/oidc",
		SignInPath: "/signin",
	}
	if o.handler != nil {
		o.handler(&hcfg)
	}
	h, err := newHandler(hcfg, acct)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	e.h = h
	return e
}

// route returns the mounted route named name, its handler wrapped in
// around when set.
func (e *env) route(t testing.TB, name string) Route {
	t.Helper()
	for _, rt := range e.h.Routes() {
		if rt.Name == name {
			if e.around != nil {
				rt.Handler = e.around(rt)
			}
			return rt
		}
	}
	t.Fatalf("no route %s", name)
	return Route{}
}

// request builds a same-origin request for rt with a JSON body (none when
// body is empty) and the given cookies, its {id} 1 and its {method}
// password.
func request(rt Route, body string, cookies ...*http.Cookie) *http.Request {
	return requestAt(testOrigin, strings.NewReplacer("{id}", "1", "{method}", "password").Replace(rt.Path), rt, body, cookies...)
}

// requestFor is request with id as rt's {id} or {method} path value.
func requestFor(rt Route, id, body string, cookies ...*http.Cookie) *http.Request {
	return requestAt(testOrigin, strings.NewReplacer("{id}", id, "{method}", id).Replace(rt.Path), rt, body, cookies...)
}

// requestAt is a same-origin request for rt to path on origin.
func requestAt(origin, path string, rt Route, body string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(rt.Method, origin+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Origin", origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

// do serves r on rt mounted at its Path on a ServeMux, as an app mounts
// it, so the handler reads its path values, and returns the response.
func do(rt Route, r *http.Request) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.Handle(rt.Path, rt.Handler)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// jsonBody marshals v or fails the test.
func jsonBody(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

// createUser stores a user with testPassword straight into the store, so
// no Rules (a breach check that is down) refuse the fixture.
func (e *env) createUser(t testing.TB, name string, role access.Role) {
	t.Helper()
	hash, err := e.hasher.Hash(t.Context(), testPassword)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	now := time.Now()
	u := &access.User{Username: name, PasswordHash: hash, Role: role, Enabled: true, WebAuthnHandle: access.GenerateWebAuthnHandle(), CreatedAt: now, UpdatedAt: now}
	if err := e.mem.CreateUser(t.Context(), u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
}

// sessionCookie signs name in directly through the Service and returns its
// session cookie.
func (e *env) sessionCookie(t testing.TB, name string) *http.Cookie {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, testOrigin+"/", nil)
	out, err := e.svc.PasswordLogin(t.Context(), account.Client{}, account.Credentials{Username: name, Password: access.NewSecret(testPassword)})
	if err != nil {
		t.Fatalf("PasswordLogin: %v", err)
	}
	cfg := e.authn.Cookie()
	return &http.Cookie{Name: cfg.CookieName(r), Value: out.Token.Reveal()}
}

// specNamed returns the spec named name.
func specNamed(t testing.TB, name string) *routeSpec {
	t.Helper()
	for i := range specs {
		if specs[i].name == name {
			return &specs[i]
		}
	}
	t.Fatalf("no spec %s", name)
	return nil
}
