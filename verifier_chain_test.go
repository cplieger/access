package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubVerifier answers every request with p, ok and err, and counts its
// calls.
type stubVerifier struct {
	err   error
	calls *atomic.Int32
	p     Principal
	ok    bool
}

func (s stubVerifier) Verify(context.Context, *http.Request) (Principal, bool, error) {
	if s.calls != nil {
		s.calls.Add(1)
	}
	return s.p, s.ok, s.err
}

// isZeroPrincipal reports whether every field of p is zero.
func isZeroPrincipal(p Principal) bool {
	return reflect.ValueOf(p).IsZero()
}

// agentVerifier grants one fixed Bearer value and answers "not mine" for
// every other request.
type agentVerifier struct {
	calls *atomic.Int32
	token string
}

func (v agentVerifier) Verify(_ context.Context, r *http.Request) (Principal, bool, error) {
	v.calls.Add(1)
	if r.Header.Get("Authorization") != "Bearer "+v.token {
		return Principal{}, false, nil
	}
	return Principal{User: &User{Username: "agent", Role: RoleAdmin, Enabled: true}, Method: "agent_key"}, true, nil
}

// recordingStore counts its reads and writes, can fail each read, and can
// answer UserByID for chosen IDs in place of the store. Set every field but
// writeFails and beforeWrite before the first request.
type recordingStore struct {
	*fakeSessionStore
	keyErr     error
	sessErr    error
	userErr    error
	users      map[int64]userAnswer
	userReads  atomic.Int32
	keyReads   atomic.Int32
	sessReads  atomic.Int32
	activities atomic.Int32
	touches    atomic.Int32
	// beforeWrite, when set, runs at the start of each activity write and
	// touch, so a test can hold a write in flight. Change it only while no
	// request is.
	beforeWrite func()
	// writeFails is how many of the next activity writes and touches fail
	// with errWriteFailed, each counted and storing nothing.
	writeFails atomic.Int32
}

var errWriteFailed = errors.New("recordingStore: write failed")

// failWrite reports whether this write fails, using up one of writeFails.
func (s *recordingStore) failWrite() bool {
	for {
		n := s.writeFails.Load()
		if n <= 0 {
			return false
		}
		if s.writeFails.CompareAndSwap(n, n-1) {
			return true
		}
	}
}

// userAnswer is a UserByID answer recordingStore gives for one ID.
type userAnswer struct {
	user  *User
	found bool
}

func newRecordingStore() *recordingStore {
	return &recordingStore{fakeSessionStore: newFakeSessionStore()}
}

func (s *recordingStore) SessionByHash(ctx context.Context, h Hash) (*Session, bool, error) {
	s.sessReads.Add(1)
	if s.sessErr != nil {
		return nil, false, s.sessErr
	}
	return s.fakeSessionStore.SessionByHash(ctx, h)
}

func (s *recordingStore) UserByID(ctx context.Context, id int64) (*User, bool, error) {
	s.userReads.Add(1)
	if s.userErr != nil {
		return nil, false, s.userErr
	}
	if a, ok := s.users[id]; ok {
		return a.user, a.found, nil
	}
	return s.fakeSessionStore.UserByID(ctx, id)
}

func (s *recordingStore) APIKeyByHash(ctx context.Context, h Hash) (*Key, bool, error) {
	s.keyReads.Add(1)
	if s.keyErr != nil {
		return nil, false, s.keyErr
	}
	return s.fakeSessionStore.APIKeyByHash(ctx, h)
}

func (s *recordingStore) UpdateSessionActivity(ctx context.Context, h Hash, act SessionActivity) error {
	s.activities.Add(1)
	if s.beforeWrite != nil {
		s.beforeWrite()
	}
	if s.failWrite() {
		return errWriteFailed
	}
	return s.fakeSessionStore.UpdateSessionActivity(ctx, h, act)
}

func (s *recordingStore) TouchAPIKey(ctx context.Context, keyID int64, hash Hash, at time.Time) error {
	s.touches.Add(1)
	if s.beforeWrite != nil {
		s.beforeWrite()
	}
	if s.failWrite() {
		return errWriteFailed
	}
	return s.fakeSessionStore.TouchAPIKey(ctx, keyID, hash, at)
}

// writes is the number of activity writes and key touches s has seen.
func (s *recordingStore) writes() int32 { return s.activities.Load() + s.touches.Load() }

// chainFixture is a store holding one enabled user with a live session and
// a persisted key.
type chainFixture struct {
	store   *recordingStore
	user    *User
	session string
	key     string
	keyID   int64
}

func newChainFixture(t *testing.T) chainFixture {
	t.Helper()
	ctx := t.Context()
	store := &recordingStore{fakeSessionStore: newFakeSessionStore()}
	user := &User{Username: "alice", Role: RoleUser, Enabled: true}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	plaintext, hash := GenerateSessionToken()
	now := time.Now()
	if err := store.CreateSession(ctx, &Session{
		ID: "sess-1", TokenHash: hash, UserID: user.ID, AuthMethod: MethodPassword,
		CreatedAt: now, LastActivity: now, AuthTime: now,
	}); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAPIKey(ctx, &Key{
		ID: 77, UserID: user.ID, KeyHash: key.Hash, KeyPrefix: key.DisplayPrefix, Scopes: []string{"read"},
	}); err != nil {
		t.Fatal(err)
	}
	return chainFixture{store: store, user: user, session: plaintext.Reveal(), key: key.Plaintext.Reveal(), keyID: 77}
}

// addSession stores s, with a new token, and returns the token.
func (f chainFixture) addSession(t *testing.T, s *Session) string {
	t.Helper()
	plaintext, hash := GenerateSessionToken()
	s.TokenHash = hash
	if err := f.store.CreateSession(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	return plaintext.Reveal()
}

// addUserKey stores a new enabled user with one key and returns the key.
func (f chainFixture) addUserKey(t *testing.T) (key string, userID int64) {
	t.Helper()
	ctx := t.Context()
	user := &User{Username: "bob", Role: RoleUser, Enabled: true}
	if err := f.store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	k, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateAPIKey(ctx, &Key{UserID: user.ID, KeyHash: k.Hash, KeyPrefix: k.DisplayPrefix}); err != nil {
		t.Fatal(err)
	}
	return k.Plaintext.Reveal(), user.ID
}

// withSession adds the default session cookie carrying token to r.
func withSession(r *http.Request, token string) *http.Request {
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: token})
	return r
}

// answer runs RequireAuth's default response on r and returns its status
// and body code.
func answer(t *testing.T, a *Authenticator, r *http.Request) (status int, code string) {
	t.Helper()
	rec := httptest.NewRecorder()
	if _, ok := a.RequireAuth(rec, r); ok {
		return http.StatusOK, ""
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("RequireAuth body %q: %v", rec.Body.String(), err)
	}
	return rec.Code, body["code"]
}

func bearerRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestVerifierChainOrder(t *testing.T) {
	t.Parallel()
	const agentToken = "agent-boot-key"

	t.Run("custom value authenticates through custom", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		var calls atomic.Int32
		a := mustAuthenticator(t, f.store, Config{Verifier: agentVerifier{token: agentToken, calls: &calls}})
		p, err := a.Authenticate(bearerRequest(agentToken))
		if err != nil {
			t.Fatalf("Authenticate(agent key) error = %v, want nil", err)
		}
		if p.Method != "agent_key" || p.User == nil || p.User.Username != "agent" {
			t.Errorf("Authenticate(agent key) = %+v, want the custom verifier's principal", p)
		}
	})
	t.Run("persisted key passes custom and reaches the API-key verifier", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		var calls atomic.Int32
		a := mustAuthenticator(t, f.store, Config{Verifier: agentVerifier{token: agentToken, calls: &calls}})
		p, err := a.Authenticate(bearerRequest(f.key))
		if err != nil {
			t.Fatalf("Authenticate(persisted key) error = %v, want nil", err)
		}
		if p.Method != MethodAPIKey || p.KeyID != f.keyID || p.User.ID != f.user.ID || !p.HasScope("read") {
			t.Errorf("Authenticate(persisted key) = %+v, want MethodAPIKey with KeyID %d, user %d and scope read", p, f.keyID, f.user.ID)
		}
		if calls.Load() != 1 {
			t.Errorf("custom verifier called %d times, want 1 (it runs before the API-key verifier)", calls.Load())
		}
	})
	t.Run("unknown Bearer value is refused", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		var calls atomic.Int32
		a := mustAuthenticator(t, f.store, Config{Verifier: agentVerifier{token: agentToken, calls: &calls}})
		unknown, err := GenerateAPIKey("ak_")
		if err != nil {
			t.Fatal(err)
		}
		p, err := a.Authenticate(bearerRequest(unknown.Plaintext.Reveal()))
		if !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("Authenticate(unknown Bearer) error = %v, want ErrInvalidCredential", err)
		}
		var ice *InvalidCredentialError
		if !errors.As(err, &ice) || *ice != (InvalidCredentialError{Err: ErrInvalidAPIKey, Method: MethodAPIKey}) {
			t.Errorf("Authenticate(unknown Bearer) detail = %+v, want Method api_key, ErrInvalidAPIKey and no KeyID", ice)
		}
		if !isZeroPrincipal(p) {
			t.Errorf("Authenticate(unknown Bearer) = %+v, want the zero Principal", p)
		}
	})
	t.Run("session runs before custom", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		var calls atomic.Int32
		a := mustAuthenticator(t, f.store, Config{Verifier: agentVerifier{token: agentToken, calls: &calls}})
		r := bearerRequest(agentToken)
		r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: f.session})
		p, err := a.Authenticate(r)
		if err != nil || !p.IsSession() {
			t.Fatalf("Authenticate(session cookie + agent key) = (%+v, %v), want the session principal", p, err)
		}
		if calls.Load() != 0 {
			t.Errorf("custom verifier called %d times after a session grant, want 0", calls.Load())
		}
	})
}

// notMineRechecker answers ok false and a nil error for every request and
// every principal, beside a principal with a user and a method.
type notMineRechecker struct{ p Principal }

var _ Rechecker = notMineRechecker{}

func (v notMineRechecker) Verify(context.Context, *http.Request) (Principal, bool, error) {
	return v.p, false, nil
}

func (v notMineRechecker) Recheck(context.Context, Principal) (Principal, bool, error) {
	return v.p, false, nil
}

// TestVerifierNotMine pins that ok, not the returned Principal, is a custom
// verifier's verdict.
func TestVerifierNotMine(t *testing.T) {
	t.Parallel()
	dressed := Principal{User: &User{Username: "agent", Role: RoleAdmin, Enabled: true}, Method: "agent_key", Scopes: []string{"all"}}

	t.Run("ok false passes the request on", func(t *testing.T) {
		t.Parallel()
		for name, p := range map[string]Principal{"zero principal": {}, "principal with a user and a method": dressed} {
			f := newChainFixture(t)
			a := mustAuthenticator(t, f.store, Config{Verifier: stubVerifier{p: p}})
			got, err := a.Authenticate(bearerRequest(f.key))
			if err != nil || got.Method != MethodAPIKey || got.KeyID != f.keyID {
				t.Errorf("%s: Authenticate = (%+v, %v), want the API-key verifier's principal", name, got, err)
			}
			if _, err := a.Authenticate(bearerRequest("")); err != ErrUnauthenticated { //nolint:errorlint // bare: nothing granted
				t.Errorf("%s: Authenticate(no credential) error = %v, want bare ErrUnauthenticated", name, err)
			}
		}
	})
	t.Run("ok true with a refusal stops the chain", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		refusal := &InvalidCredentialError{Err: ErrInvalidAPIKey, Method: "agent_key"}
		a := mustAuthenticator(t, f.store, Config{Verifier: stubVerifier{p: dressed, ok: true, err: refusal}})
		p, err := a.Authenticate(bearerRequest(f.key))
		if !errors.Is(err, refusal) || !isZeroPrincipal(p) {
			t.Errorf("Authenticate = (%+v, %v), want (zero, the verifier's refusal)", p, err)
		}
		if n := f.store.keyReads.Load(); n != 0 {
			t.Errorf("store saw %d APIKeyByHash calls after the refusal, want 0", n)
		}
	})
	t.Run("a grant with a nil user is refused", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{Verifier: stubVerifier{p: Principal{Method: "agent_key"}, ok: true}})
		p, err := a.Authenticate(bearerRequest(f.key))
		if !errors.Is(err, ErrInvalidCredential) || !errors.Is(err, ErrAccountDisabled) || !isZeroPrincipal(p) {
			t.Errorf("Authenticate = (%+v, %v), want (zero, ErrInvalidCredential wrapping ErrAccountDisabled)", p, err)
		}
	})
	t.Run("a Rechecker answering ok false", func(t *testing.T) {
		t.Parallel()
		a := mustAuthenticator(t, newFakeSessionStore(), Config{Verifier: notMineRechecker{p: dressed}})
		if q, err := a.Recheck(t.Context(), dressed); !errors.Is(err, ErrNotRecheckable) || !isZeroPrincipal(q) {
			t.Errorf("Recheck = (%+v, %v), want (zero, ErrNotRecheckable)", q, err)
		}
	})
}

func TestPresentedButUnusable(t *testing.T) {
	t.Parallel()
	expired := fmt.Errorf("%w: %w", ErrUnauthenticated, ErrSessionExpired)

	t.Run("unusable custom credential before a valid key lets the key grant", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{Verifier: stubVerifier{err: expired}})
		p, err := a.Authenticate(bearerRequest(f.key))
		if err != nil || p.KeyID != f.keyID {
			t.Errorf("Authenticate = (%+v, %v), want the key's principal", p, err)
		}
	})
	t.Run("unusable custom credential alone is the result", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{Verifier: stubVerifier{err: expired}})
		if _, err := a.Authenticate(bearerRequest("")); !errors.Is(err, ErrUnauthenticated) || !errors.Is(err, ErrSessionExpired) {
			t.Errorf("Authenticate error = %v, want ErrUnauthenticated wrapping ErrSessionExpired", err)
		}
	})
	t.Run("unusable custom credential then a refused key", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{Verifier: stubVerifier{err: expired}})
		_, err := a.Authenticate(bearerRequest("ak_unknownunknownunknown"))
		if !errors.Is(err, ErrInvalidCredential) || errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate error = %v, want ErrInvalidCredential alone", err)
		}
	})
	t.Run("unusable custom credential then a key store outage", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		f.store.keyErr = errors.New("db down")
		a := mustAuthenticator(t, f.store, Config{Verifier: stubVerifier{err: expired}})
		_, err := a.Authenticate(bearerRequest(f.key))
		if !errors.Is(err, ErrAuthBackend) || !errors.Is(err, f.store.keyErr) {
			t.Errorf("Authenticate error = %v, want ErrAuthBackend wrapping the store's error", err)
		}
	})
	stale := func(t *testing.T, f chainFixture) string {
		old := time.Now().Add(-48 * time.Hour)
		return f.addSession(t, &Session{ID: "stale", UserID: f.user.ID, CreatedAt: old, LastActivity: old})
	}
	t.Run("stale cookie alone is session expired", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{})
		token := stale(t, f)
		if _, err := a.Authenticate(withSession(bearerRequest(""), token)); !errors.Is(err, ErrUnauthenticated) || !errors.Is(err, ErrSessionExpired) {
			t.Errorf("Authenticate error = %v, want ErrUnauthenticated wrapping ErrSessionExpired", err)
		}
		if status, code := answer(t, a, withSession(bearerRequest(""), token)); status != http.StatusUnauthorized || code != "auth_session_expired" {
			t.Errorf("RequireAuth = %d %s, want 401 auth_session_expired", status, code)
		}
	})
	t.Run("revoked session cookie is session not found", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{})
		f.store.deleteUserSessions(f.user.ID)
		if _, err := a.Authenticate(withSession(bearerRequest(""), f.session)); !errors.Is(err, ErrUnauthenticated) || !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("Authenticate error = %v, want ErrUnauthenticated wrapping ErrSessionNotFound", err)
		}
		if status, code := answer(t, a, withSession(bearerRequest(""), f.session)); status != http.StatusUnauthorized || code != "auth_session_expired" {
			t.Errorf("RequireAuth = %d %s, want 401 auth_session_expired", status, code)
		}
	})
	t.Run("stale cookie and a valid key grants the key", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{})
		p, err := a.Authenticate(withSession(bearerRequest(f.key), stale(t, f)))
		if err != nil || p.KeyID != f.keyID {
			t.Errorf("Authenticate = (%+v, %v), want the key's principal", p, err)
		}
	})
	t.Run("stale cookie and a refused key", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{})
		unknown, err := GenerateAPIKey("ak_")
		if err != nil {
			t.Fatal(err)
		}
		r := func() *http.Request { return withSession(bearerRequest(unknown.Plaintext.Reveal()), stale(t, f)) }
		if _, err := a.Authenticate(r()); !errors.Is(err, ErrInvalidCredential) || errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate error = %v, want ErrInvalidCredential alone", err)
		}
		if status, code := answer(t, a, r()); status != http.StatusUnauthorized || code != "auth_required" {
			t.Errorf("RequireAuth = %d %s, want 401 auth_required", status, code)
		}
	})
	t.Run("stale cookie and a key store outage", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		f.store.keyErr = errors.New("db down")
		a := mustAuthenticator(t, f.store, Config{})
		r := func() *http.Request { return withSession(bearerRequest(f.key), stale(t, f)) }
		if _, err := a.Authenticate(r()); !errors.Is(err, ErrAuthBackend) || !errors.Is(err, f.store.keyErr) {
			t.Errorf("Authenticate error = %v, want ErrAuthBackend wrapping the store's error", err)
		}
		if status, code := answer(t, a, r()); status != http.StatusServiceUnavailable || code != "auth_unavailable" {
			t.Errorf("RequireAuth = %d %s, want 503 auth_unavailable", status, code)
		}
	})
	for name, ans := range map[string]userAnswer{
		"missing":  {},
		"nil":      {found: true},
		"disabled": {user: &User{Username: "alice", Role: RoleUser}, found: true},
	} {
		t.Run("session user "+name+" at lookup", func(t *testing.T) {
			t.Parallel()
			f := newChainFixture(t)
			f.store.users = map[int64]userAnswer{f.user.ID: ans}
			a := mustAuthenticator(t, f.store, Config{})
			if _, err := a.Authenticate(withSession(bearerRequest(""), f.session)); !errors.Is(err, ErrUnauthenticated) || !errors.Is(err, ErrSessionNotFound) {
				t.Errorf("Authenticate error = %v, want ErrUnauthenticated wrapping ErrSessionNotFound", err)
			}
			if status, code := answer(t, a, withSession(bearerRequest(""), f.session)); status != http.StatusUnauthorized || code != "auth_session_expired" {
				t.Errorf("RequireAuth = %d %s, want 401 auth_session_expired", status, code)
			}
			if n := f.store.activities.Load(); n != 0 {
				t.Errorf("store saw %d activity writes, want 0", n)
			}
			other, otherID := f.addUserKey(t)
			p, err := a.Authenticate(withSession(bearerRequest(other), f.session))
			if err != nil || p.User == nil || p.User.ID != otherID || p.Method != MethodAPIKey {
				t.Errorf("Authenticate(session + another user's key) = (%+v, %v), want the key's principal", p, err)
			}
		})
	}
	t.Run("the first unusable error is kept", func(t *testing.T) {
		t.Parallel()
		notFound := fmt.Errorf("%w: %w", ErrUnauthenticated, ErrSessionNotFound)
		a := mustAuthenticator(t, newFakeSessionStore(), Config{})
		a.chain = []CredentialVerifier{stubVerifier{err: notFound}, stubVerifier{err: expired}, stubVerifier{}}
		if _, err := a.Authenticate(bearerRequest("")); !errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
			t.Errorf("Authenticate error = %v, want the first unusable error (ErrSessionNotFound)", err)
		}
	})
	t.Run("a refusal or an outage stops the chain", func(t *testing.T) {
		t.Parallel()
		for name, stop := range map[string]error{
			"refusal": &InvalidCredentialError{Method: "custom"},
			"outage":  fmt.Errorf("%w: %w", ErrAuthBackend, errors.New("db down")),
			"other":   errors.New("custom failure"),
			// An error matching both stops: a refusal never falls through.
			"refusal wrapping unauthenticated": fmt.Errorf("%w: %w", ErrUnauthenticated, ErrInvalidCredential),
		} {
			var later atomic.Int32
			a := mustAuthenticator(t, newFakeSessionStore(), Config{})
			grant := Principal{User: &User{ID: 1, Enabled: true}, Method: "custom"}
			a.chain = []CredentialVerifier{stubVerifier{err: stop}, stubVerifier{p: grant, ok: true, calls: &later}}
			if p, err := a.Authenticate(bearerRequest("")); !errors.Is(err, stop) || !isZeroPrincipal(p) {
				t.Errorf("%s: Authenticate = (%+v, %v), want (zero, %v)", name, p, err, stop)
			}
			if later.Load() != 0 {
				t.Errorf("%s: a verifier after the stopping error ran %d times, want 0", name, later.Load())
			}
		}
	})
}

func TestCustomPrincipalRefused(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		wantErr error
		name    string
		p       Principal
	}{
		{name: "nil user", p: Principal{Method: "custom", Scopes: []string{"all"}}, wantErr: ErrAccountDisabled},
		{name: "disabled user", p: Principal{User: &User{ID: 5, Enabled: false}, Method: "custom"}, wantErr: ErrAccountDisabled},
		{name: "empty method", p: Principal{User: &User{ID: 5, Enabled: true}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newChainFixture(t)
			a := mustAuthenticator(t, f.store, Config{Verifier: stubVerifier{p: tt.p, ok: true}})
			p, err := a.Authenticate(bearerRequest(f.key))
			if !errors.Is(err, ErrInvalidCredential) || !isZeroPrincipal(p) {
				t.Fatalf("Authenticate = (%+v, %v), want (zero, ErrInvalidCredential)", p, err)
			}
			var ice *InvalidCredentialError
			if !errors.As(err, &ice) {
				t.Fatalf("Authenticate error %v carries no *InvalidCredentialError", err)
			}
			if ice.Method != tt.p.Method || !errors.Is(ice.Err, tt.wantErr) || (tt.wantErr == nil && ice.Err != nil) {
				t.Errorf("detail = {Method: %q, Err: %v}, want {Method: %q, Err: %v}", ice.Method, ice.Err, tt.p.Method, tt.wantErr)
			}
		})
	}
}

// TestBearerShapeGate pins that only a value GenerateAPIKey could return is
// looked up; every malformed row breaks one part of that shape.
func TestBearerShapeGate(t *testing.T) {
	t.Parallel()
	random := strings.Repeat("0123abcd", 8)
	for _, tt := range []struct {
		name, value string
		lookedUp    bool
	}{
		{name: "prefixed key", value: "ak_" + random, lookedUp: true},
		{name: "unprefixed key", value: random, lookedUp: true},
		{name: "one-byte prefix", value: "a" + random, lookedUp: true},
		{name: "16-byte prefix", value: "Abcd_0123456789x" + random, lookedUp: true},
		{name: "17-byte prefix", value: "Abcd_0123456789xy" + random},
		{name: "81 bytes of a", value: strings.Repeat("a", 81)},
		{name: "dash in the prefix", value: "ak-" + random},
		{name: "dot in the prefix", value: "ak." + random},
		{name: "non-ASCII prefix", value: "ключ" + random},
		{name: "random part one byte short", value: random[1:]},
		{name: "exactly 8 bytes", value: "abcdefgh"},
		{name: "non-hex g in the random part", value: strings.Repeat("a", 63) + "g"},
		{name: "uppercase hex in the random part", value: "ak_" + random[1:] + "A"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingStore{fakeSessionStore: newFakeSessionStore()}
			a := mustAuthenticator(t, store, Config{})
			_, err := a.Authenticate(bearerRequest(tt.value))
			if !errors.Is(err, ErrInvalidCredential) || !errors.Is(err, ErrInvalidAPIKey) {
				t.Fatalf("Authenticate error = %v, want ErrInvalidCredential wrapping ErrInvalidAPIKey", err)
			}
			wantReads := int32(0)
			if tt.lookedUp {
				wantReads = 1
			}
			if n := store.keyReads.Load(); n != wantReads {
				t.Errorf("store saw %d APIKeyByHash calls, want %d", n, wantReads)
			}
		})
	}
}

// TestGrantedPrincipalCopied pins that a verifier handing out one shared
// User and Scopes cannot let a handler's change reach a later request.
func TestGrantedPrincipalCopied(t *testing.T) {
	t.Parallel()
	shared := Principal{
		User:   &User{Username: "agent", Role: RoleAdmin, Enabled: true, WebAuthnHandle: []byte{1}},
		Method: "agent_key", Scopes: []string{"read"},
	}
	a := mustAuthenticator(t, newFakeSessionStore(), Config{Verifier: stubVerifier{p: shared, ok: true}})
	first, err := a.Authenticate(bearerRequest(""))
	if err != nil {
		t.Fatalf("Authenticate error = %v, want nil", err)
	}
	first.User.Role = RoleUser
	first.User.WebAuthnHandle[0] = 9
	first.Scopes[0] = "admin"

	second, err := a.Authenticate(bearerRequest(""))
	if err != nil {
		t.Fatalf("Authenticate error = %v, want nil", err)
	}
	if second.User == first.User || second.User == shared.User {
		t.Error("Authenticate returned a User pointer another caller holds")
	}
	if second.User.Role != RoleAdmin || second.User.WebAuthnHandle[0] != 1 || second.Scopes[0] != "read" {
		t.Errorf("second principal = {Role: %s, handle: %v, scopes: %v}, want the verifier's unchanged values",
			second.User.Role, second.User.WebAuthnHandle, second.Scopes)
	}
	if shared.User.Role != RoleAdmin || shared.Scopes[0] != "read" {
		t.Error("a handler's change reached the verifier's own principal")
	}
}

func TestSynthesisedPrincipal(t *testing.T) {
	t.Parallel()
	store := &recordingStore{fakeSessionStore: newFakeSessionStore()}
	var calls atomic.Int32
	a := mustAuthenticator(t, store, Config{Verifier: agentVerifier{token: "boot-key", calls: &calls}})

	p, err := a.Authenticate(bearerRequest("boot-key"))
	if err != nil {
		t.Fatalf("Authenticate(synthesised user) error = %v, want nil", err)
	}
	if p.User == nil || p.User.ID != 0 || p.Method != "agent_key" {
		t.Errorf("Authenticate = %+v, want the synthesised user with ID 0", p)
	}
	if n := store.userReads.Load(); n != 0 {
		t.Errorf("store saw %d UserByID calls, want 0 (a custom principal is never looked up)", n)
	}
	if p.IsSession() || p.IsRecoverySession() {
		t.Error("synthesised principal passes IsSession or IsRecoverySession, want neither")
	}
}

// verifierFunc, verifierMap, verifierSlice and verifierChan are the non-pointer
// nilable kinds a verifier can have; New refuses a nil value of each.
type verifierFunc func(context.Context, *http.Request) (Principal, bool, error)

func (f verifierFunc) Verify(ctx context.Context, r *http.Request) (Principal, bool, error) {
	return f(ctx, r)
}

type verifierMap map[string]Principal

func (m verifierMap) Verify(_ context.Context, r *http.Request) (Principal, bool, error) {
	p, ok := m[r.Header.Get("Authorization")]
	return p, ok, nil
}

type verifierSlice []Principal

func (s verifierSlice) Verify(context.Context, *http.Request) (Principal, bool, error) {
	return s[0], true, nil
}

type verifierChan chan Principal

func (c verifierChan) Verify(ctx context.Context, _ *http.Request) (Principal, bool, error) {
	select {
	case p := <-c:
		return p, true, nil
	case <-ctx.Done():
		return Principal{}, false, ctx.Err()
	}
}
