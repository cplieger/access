package account_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/capture"
	"github.com/cplieger/access/ratelimit"
)

// testFailureKey is a fixed 32-byte failure key.
var testFailureKey = []byte("account-test-failure-key-32bytes")

// fixture is one Service over a MemStore, with the collaborators a test
// reads back.
type fixture struct {
	mem    *accesstest.MemStore
	authn  *access.Authenticator
	svc    *account.Service
	events *eventLog
	logs   *capture.Recorder
	cfg    account.Config
}

// options adjust a fixture before New.
type options struct {
	events   *eventLog // OnEvent's log; a new one when nil
	timeouts func() access.SessionTimeouts
	rules    func() account.Rules
	edit     func(*account.Config)
	ctx      context.Context
	hook     func(ctx context.Context) // Hooks.BetweenSessionCalls
	hooks    account.Hooks
	store    *faultStore // the Store when set, over its own MemStore
}

// newFixture builds a Service and shuts it down at cleanup. Built inside a
// synctest bubble, the Service's sweep and every clock run on the bubble's
// time.
func newFixture(t testing.TB, o options) *fixture {
	t.Helper()
	f := &fixture{mem: accesstest.NewMemStore(), events: o.events}
	var store account.Store = f.mem
	if o.store != nil {
		f.mem, store = o.store.mem, o.store
	}
	if f.events == nil {
		f.events = &eventLog{}
	}
	authn, err := access.New(f.mem, access.Config{TimeoutSource: o.timeouts})
	if err != nil {
		t.Fatalf("access.New: %v", err)
	}
	f.authn = authn
	hasher, err := access.NewHasher(access.HasherConfig{})
	if err != nil {
		t.Fatalf("access.NewHasher: %v", err)
	}
	lcfg := ratelimit.DefaultConfig()
	lcfg.Devices = access.NewEphemeralSealer()
	limiter, err := ratelimit.New(t.Context(), lcfg)
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	t.Cleanup(func() { _ = limiter.Shutdown(context.Background()) })
	var logger *slog.Logger
	logger, f.logs = capture.New()
	rules := o.rules
	if rules == nil {
		rules = func() account.Rules { return account.Rules{} }
	}
	f.cfg = account.Config{
		Store:         store,
		Policy:        account.RolePolicy{},
		Authenticator: authn,
		Hasher:        hasher,
		Limiter:       limiter,
		Rules:         rules,
		OnEvent:       f.events.record,
		Logger:        logger,
		FailureKey:    slices.Clone(testFailureKey),
	}
	if o.edit != nil {
		o.edit(&f.cfg)
	}
	ctx := o.ctx
	if ctx == nil {
		ctx = t.Context()
	}
	hooks := o.hooks
	if o.hook != nil {
		hooks.BetweenSessionCalls = o.hook
	}
	svc, err := account.NewWithHooks(ctx, f.cfg, hooks)
	if err != nil {
		t.Fatalf("account.New: %v", err)
	}
	f.svc = svc
	t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
	return f
}

// eventLog records every event OnEvent receives.
type eventLog struct {
	events []account.Event
	mu     sync.Mutex
}

func (l *eventLog) record(ev account.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, ev)
}

func (l *eventLog) all() []account.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// warnings counts the records logged at WARN.
func warnings(rec *capture.Recorder) int {
	n := 0
	for _, r := range rec.Records("") {
		if r.Level == slog.LevelWarn {
			n++
		}
	}
	return n
}

// errorLogs counts the records logged at ERROR.
func errorLogs(rec *capture.Recorder) int {
	n := 0
	for _, r := range rec.Records("") {
		if r.Level == slog.LevelError {
			n++
		}
	}
	return n
}

// mustUser stores a user.
func mustUser(t *testing.T, s account.Store, name string, role access.Role) *access.User {
	t.Helper()
	u := &access.User{Username: name, Role: role, Enabled: true, WebAuthnHandle: access.GenerateWebAuthnHandle(), CreatedAt: time.Now()}
	if err := s.CreateUser(t.Context(), u); err != nil {
		t.Fatalf("CreateUser(%s): %v", name, err)
	}
	return u
}

// sessionPrincipal stores a session of u signed in at authTime and returns
// the principal the Authenticator grants for it.
func (f *fixture) sessionPrincipal(t *testing.T, u *access.User, kind access.SessionKind, authTime time.Time) access.Principal {
	t.Helper()
	now := time.Now()
	sess := &access.Session{
		ID: newSessionID(t), UserID: u.ID, Kind: kind,
		AuthMethod: access.MethodPassword, CreatedAt: now, LastActivity: now, AuthTime: authTime,
	}
	if kind == access.SessionRecovery {
		sess.AuthMethod = access.MethodRecovery
	}
	p, _ := f.principalOf(t, sess)
	return p
}

// principalOf stores sess under a fresh token and returns the principal
// the Authenticator grants for it, and the token.
func (f *fixture) principalOf(t testing.TB, sess *access.Session) (access.Principal, access.Secret) {
	t.Helper()
	token, hash := access.GenerateSessionToken()
	sess.TokenHash = hash
	if err := f.mem.CreateSession(t.Context(), sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	p, err := f.authenticate(t.Context(), token)
	if err != nil {
		t.Fatalf("Authenticate(session): %v", err)
	}
	return p, token
}

// authenticate runs the Authenticator on a request carrying token as its
// session cookie.
func (f *fixture) authenticate(ctx context.Context, token access.Secret) (access.Principal, error) {
	req := httptest.NewRequestWithContext(access.AllowRecoverySession(ctx), http.MethodGet, "https://example.com/", http.NoBody)
	cookie := f.authn.Cookie()
	req.AddCookie(&http.Cookie{Name: cookie.CookieName(req), Value: token.Reveal()})
	return f.authn.Authenticate(req)
}

// keyPrincipal stores a key of u carrying scopes and returns the principal
// the Authenticator grants for it.
func (f *fixture) keyPrincipal(t *testing.T, u *access.User, scopes ...string) access.Principal {
	t.Helper()
	p, _ := f.keyPrincipalFor(t, f.authn, u, time.Time{}, nil, scopes...)
	return p
}

func (f *fixture) keyPrincipalFor(t *testing.T, authn *access.Authenticator, u *access.User, expires time.Time, lineage []int64, scopes ...string) (access.Principal, access.Key) {
	t.Helper()
	g, err := access.GenerateAPIKey("")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	key := &access.Key{
		UserID: u.ID, KeyHash: g.Hash, KeyPrefix: g.DisplayPrefix, KeySuffix: g.DisplaySuffix,
		Scopes: scopes, CreatedAt: time.Now(), ExpiresAt: expires, LineageIDs: slices.Clone(lineage),
	}
	if err := f.mem.CreateAPIKey(t.Context(), key); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if authn == nil {
		return access.Principal{}, *key
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+g.Plaintext.Reveal())
	p, err := authn.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate(key): %v", err)
	}
	return p, *key
}

// bypassPrincipal is the principal an Authenticator in bypass grants.
func (f *fixture) bypassPrincipal(t *testing.T) access.Principal {
	t.Helper()
	authn, err := access.New(f.mem, access.Config{Bypass: func() bool { return true }, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("access.New(bypass): %v", err)
	}
	p, err := authn.Authenticate(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", http.NoBody))
	if err != nil {
		t.Fatalf("Authenticate(bypass): %v", err)
	}
	return p
}

// customVerifier grants every request one app-synthesised principal.
type customVerifier struct{ p access.Principal }

func (v customVerifier) Verify(context.Context, *http.Request) (access.Principal, bool, error) {
	return v.p, true, nil
}

func (f *fixture) customPrincipal(t *testing.T, method access.Method, keyID int64, scopes ...string) access.Principal {
	t.Helper()
	agent := access.Principal{User: &access.User{ID: 900, Username: "agent", Role: access.RoleAdmin, Enabled: true}, Method: method, KeyID: keyID, Scopes: scopes}
	authn, err := access.New(f.mem, access.Config{Verifier: customVerifier{p: agent}})
	if err != nil {
		t.Fatalf("access.New(verifier): %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", http.NoBody)
	req.Header.Set("Authorization", "Bearer agent-credential")
	p, err := authn.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate(custom): %v", err)
	}
	return p
}

var sessionIDs struct {
	mu sync.Mutex
	n  int
}

// newSessionID is a unique 32-hex session ID, in creation order.
func newSessionID(t testing.TB) string {
	t.Helper()
	sessionIDs.mu.Lock()
	defer sessionIDs.mu.Unlock()
	sessionIDs.n++
	return sessionIDFor(sessionIDs.n)
}

func sessionIDFor(n int) string {
	const digits = "0123456789abcdef"
	b := []byte("00000000000000000000000000000000")
	for i := len(b) - 1; n > 0; i-- {
		b[i] = digits[n%16]
		n /= 16
	}
	return string(b)
}
