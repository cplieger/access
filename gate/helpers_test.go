package gate_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/gate"
)

// agentHeader carries the custom verifier's credential: "ok" grants its
// principal, "bad" is its refusal, "down" a store failure, "boom" an error
// access does not map, and "ctx" the request's own context error.
const agentHeader = "X-Agent"

const agentMethod access.Method = "agent"

type agentVerifier struct{}

func (agentVerifier) Verify(ctx context.Context, r *http.Request) (access.Principal, bool, error) {
	switch r.Header.Get(agentHeader) {
	case "ok":
		return access.Principal{User: &access.User{ID: 900, Username: "agent", Role: access.RoleAdmin, Enabled: true}, Method: agentMethod, Scopes: []string{"read"}}, true, nil
	case "bad":
		return access.Principal{}, false, &access.InvalidCredentialError{Method: agentMethod}
	case "down":
		return access.Principal{}, false, fmt.Errorf("%w: agent store down", access.ErrAuthBackend)
	case "boom":
		return access.Principal{}, false, errors.New("agent: verifier broke")
	case "ctx":
		return access.Principal{}, false, fmt.Errorf("agent: %w", ctx.Err())
	default:
		return access.Principal{}, false, nil
	}
}

// fixture is one store with every credential the gate tests present.
type fixture struct {
	store    *accesstest.MemStore
	authn    *access.Authenticator
	bypass   *access.Authenticator
	cookie   string
	session  string // a full session
	recovery string // a recovery session
	expired  string // a session past its idle timeout
	stale    string // a full session last active ten minutes ago
	keyRead  string // a key with scope "read"
	keyNone  string // a key with no scope
	// keyExpired is past its ExpiresAt, keyRetired a rotated key's previous
	// secret past its overlap, and keyDisabled and disabledSession belong
	// to a disabled user.
	keyExpired      string
	keyRetired      string
	keyDisabled     string
	disabledSession string
	logs            *syncBuffer
	userID          int64
	keyID           int64
	keyNoneID       int64
	keyExpiredID    int64
	keyRetiredID    int64
	keyDisabledID   int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := t.Context()
	f := &fixture{store: accesstest.NewMemStore(), logs: &syncBuffer{}}
	u := &access.User{Username: "alice", Role: access.RoleUser, Enabled: true}
	if err := f.store.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	f.userID = u.ID
	now := time.Now()
	f.session = f.addSession(t, &access.Session{ID: "full", AuthMethod: access.MethodPassword, CreatedAt: now, LastActivity: now, AuthTime: now})
	f.recovery = f.addSession(t, &access.Session{ID: "recovery", Kind: access.SessionRecovery, AuthMethod: access.MethodRecovery, CreatedAt: now, LastActivity: now, AuthTime: now})
	f.expired = f.addSession(t, &access.Session{ID: "expired", AuthMethod: access.MethodPassword, CreatedAt: now.Add(-3 * time.Hour), LastActivity: now.Add(-2 * time.Hour), AuthTime: now.Add(-3 * time.Hour)})
	f.stale = f.addSession(t, &access.Session{ID: "stale", AuthMethod: access.MethodPassword, CreatedAt: now.Add(-time.Hour), LastActivity: now.Add(-10 * time.Minute), AuthTime: now.Add(-time.Hour)})
	f.keyRead, f.keyID = f.addKey(t, &access.Key{Label: "reader", Scopes: []string{"read"}})
	f.keyNone, f.keyNoneID = f.addKey(t, &access.Key{Label: "plain"})
	f.keyExpired, f.keyExpiredID = f.addKey(t, &access.Key{Label: "expired", ExpiresAt: now.Add(-time.Minute)})
	f.keyRetired, f.keyRetiredID = f.addKey(t, &access.Key{Label: "rotated"})
	f.retire(t, f.keyRetiredID, f.keyRetired, now.Add(-time.Minute))
	off := &access.User{Username: "bob", Role: access.RoleUser}
	if err := f.store.CreateUser(ctx, off); err != nil {
		t.Fatal(err)
	}
	f.keyDisabled, f.keyDisabledID = f.addKey(t, &access.Key{UserID: off.ID, Label: "bob's"})
	f.disabledSession = f.addSession(t, &access.Session{ID: "bob", UserID: off.ID, AuthMethod: access.MethodPassword, CreatedAt: now, LastActivity: now, AuthTime: now})
	logger := f.logger()
	var err error
	if f.authn, err = access.New(f.store, access.Config{Verifier: agentVerifier{}, Logger: logger}); err != nil {
		t.Fatal(err)
	}
	if f.bypass, err = access.New(f.store, access.Config{Bypass: func() bool { return true }, Logger: logger}); err != nil {
		t.Fatal(err)
	}
	c := f.authn.Cookie()
	f.cookie = c.EffectiveName()
	return f
}

// logger writes every level to f.logs.
func (f *fixture) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// lastActivity is the stale session's stored LastActivity.
func (f *fixture) lastActivity(t *testing.T) time.Time {
	t.Helper()
	sess, found, err := f.store.SessionByHash(t.Context(), access.SessionHash(f.stale))
	if err != nil || !found {
		t.Fatalf("SessionByHash(stale) = %v, %t, %v", sess, found, err)
	}
	return sess.LastActivity
}

func (f *fixture) addSession(t *testing.T, s *access.Session) string {
	t.Helper()
	plaintext, hash := access.GenerateSessionToken()
	s.TokenHash = hash
	if s.UserID == 0 {
		s.UserID = f.userID
	}
	if err := f.store.CreateSession(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	return plaintext.Reveal()
}

// addKey stores k with a fresh secret, for alice when k names no user, and
// returns the plaintext and the key's ID.
func (f *fixture) addKey(t *testing.T, k *access.Key) (string, int64) {
	t.Helper()
	g, err := access.GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	k.KeyHash, k.KeyPrefix, k.KeySuffix, k.CreatedAt = g.Hash, g.DisplayPrefix, g.DisplaySuffix, time.Now()
	if k.UserID == 0 {
		k.UserID = f.userID
	}
	if err := f.store.CreateAPIKey(t.Context(), k); err != nil {
		t.Fatal(err)
	}
	return g.Plaintext.Reveal(), k.ID
}

// retire rotates alice's key id to a fresh secret, keeping old as its
// previous secret until until.
func (f *fixture) retire(t *testing.T, id int64, old string, until time.Time) {
	t.Helper()
	g, err := access.GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	sec := access.KeySecret{KeyHash: g.Hash, KeyPrefix: g.DisplayPrefix, KeySuffix: g.DisplaySuffix, PreviousHash: access.APIKeyHash(old), PreviousUntil: until}
	if err := f.store.UpdateAPIKeySecret(t.Context(), access.KeyRef{ID: id, UserID: f.userID}, sec); err != nil {
		t.Fatal(err)
	}
}

// cred is one credential a request presents.
type cred func(f *fixture, r *http.Request)

func noCred(*fixture, *http.Request) {}

func withCookie(token func(f *fixture) string) cred {
	return func(f *fixture, r *http.Request) { r.AddCookie(&http.Cookie{Name: f.cookie, Value: token(f)}) }
}

func withBearer(token func(f *fixture) string) cred {
	return func(f *fixture, r *http.Request) { r.Header.Set("Authorization", "Bearer "+token(f)) }
}

func withAgent(v string) cred {
	return func(_ *fixture, r *http.Request) { r.Header.Set(agentHeader, v) }
}

var (
	sessionCred  = withCookie(func(f *fixture) string { return f.session })
	recoveryCred = withCookie(func(f *fixture) string { return f.recovery })
	expiredCred  = withCookie(func(f *fixture) string { return f.expired })
	goneCred     = withCookie(func(*fixture) string { return "no-such-session" })
	keyReadCred  = withBearer(func(f *fixture) string { return f.keyRead })
	keyNoneCred  = withBearer(func(f *fixture) string { return f.keyNone })
	unknownKey   = withBearer(func(*fixture) string { return "ak_test-key-unknown" })
	agentCred    = withAgent("ok")
	expiredKey   = withBearer(func(f *fixture) string { return f.keyExpired })
	retiredKey   = withBearer(func(f *fixture) string { return f.keyRetired })
	disabledKey  = withBearer(func(f *fixture) string { return f.keyDisabled })
	disabledCred = withCookie(func(f *fixture) string { return f.disabledSession })
	crossSite    = cred(func(_ *fixture, r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") })
)

// answer is one response: its status, the code the ErrorWriter wrote and
// the body.
type answer struct {
	header http.Header
	code   access.Code
	body   string
	status int
}

// refusalBody is what writeError puts on the wire.
type refusalBody struct {
	Code   access.Code `json:"code"`
	Reason string      `json:"reason"`
}

// writeError is the app's ErrorWriter: the code and reason as JSON.
func writeError(w http.ResponseWriter, _ *http.Request, e access.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(refusalBody{Code: e.Code, Reason: e.Reason})
}

// served is the handler each test row runs: 200 and the row's name, with
// the principal the gate admitted recorded.
type served struct {
	mu   sync.Mutex
	p    map[string]access.Principal
	seen map[string]bool
}

func (s *served) handler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		if s.p == nil {
			s.p, s.seen = map[string]access.Principal{}, map[string]bool{}
		}
		p, ok := gate.Principal(r.Context())
		s.p[name], s.seen[name] = p, ok
		s.mu.Unlock()
		_, _ = w.Write([]byte("ok:" + name))
	})
}

func (s *served) principal(name string) (access.Principal, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.p[name], s.seen[name]
}

// handlersFor returns one served handler per row.
func handlersFor(s *served, routes []gate.Route) map[string]http.Handler {
	hs := make(map[string]http.Handler, len(routes))
	for _, r := range routes {
		hs[r.Name] = s.handler(r.Name)
	}
	return hs
}

func mustGate(t *testing.T, cfg gate.Config, routes []gate.Route, s *served) *gate.Gate {
	t.Helper()
	if cfg.Errors == nil {
		cfg.Errors = writeError
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	g, err := gate.New(cfg, routes, handlersFor(s, routes))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// do serves one request on h and decodes a refusal's code.
func do(t *testing.T, f *fixture, h http.Handler, method, target string, creds ...cred) answer {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for _, c := range creds {
		c(f, r)
	}
	return serve(t, h, r)
}

func serve(t *testing.T, h http.Handler, r *http.Request) answer {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	a := answer{status: w.Code, header: w.Header(), body: w.Body.String()}
	if w.Code != http.StatusOK && w.Header().Get("Content-Type") == "application/json" {
		var b refusalBody
		if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
			t.Fatalf("refusal body %q: %v", w.Body.String(), err)
		}
		a.code = b.Code
	}
	return a
}

// syncBuffer is a log sink safe for parallel requests.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
