package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// countingStore wraps fakeSessionStore and counts UpdateSessionActivity
// calls per session ID.
type countingStore struct {
	*fakeSessionStore
	counts map[string]int
	mu     sync.Mutex
}

func newCountingStore() *countingStore {
	return &countingStore{
		fakeSessionStore: newFakeSessionStore(),
		counts:           make(map[string]int),
	}
}

func (c *countingStore) UpdateSessionActivity(ctx context.Context, tokenHash Hash, act SessionActivity) error {
	var id string
	c.fakeSessionStore.mu.Lock()
	if s, ok := c.sessions[tokenHash.Key()]; ok {
		id = s.ID
	}
	c.fakeSessionStore.mu.Unlock()
	c.mu.Lock()
	c.counts[id]++
	c.mu.Unlock()
	return c.fakeSessionStore.UpdateSessionActivity(ctx, tokenHash, act)
}

func (c *countingStore) count(id string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[id]
}

// addSession stores a live session with the given ID for user 1 and returns
// its token.
func (c *countingStore) addSession(t *testing.T, id string) string {
	t.Helper()
	plaintext, hash := GenerateSessionToken()
	now := time.Now()
	if err := c.CreateSession(t.Context(), &Session{
		ID: id, TokenHash: hash, UserID: 1, AuthMethod: MethodPassword, CreatedAt: now, LastActivity: now,
	}); err != nil {
		t.Fatal(err)
	}
	return plaintext.Reveal()
}

// setupThrottleSession stores a user and its live session "s1" and returns
// the store and the session's token.
func setupThrottleSession(t *testing.T) (*countingStore, string) {
	t.Helper()
	cs := newCountingStore()
	user := &User{Username: "u", Role: RoleUser, Enabled: true}
	if err := cs.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	return cs, cs.addSession(t, "s1")
}

var throttleCookie = CookieConfig{Posture: PostureInsecureLAN, Name: "s"}

func throttleRequest(plaintext string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: plaintext})
	return r
}

func mustAuthenticate(t *testing.T, a *Authenticator, r *http.Request) Principal {
	t.Helper()
	p, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate error = %v", err)
	}
	return p
}

func TestSessionThrottle_ZeroWritesEveryRequest(t *testing.T) {
	t.Parallel()
	cs, token := setupThrottleSession(t)
	a := mustAuthenticator(t, cs, Config{Cookie: throttleCookie})
	const n = 5
	for range n {
		mustAuthenticate(t, a, throttleRequest(token))
	}
	if got := cs.count("s1"); got != n {
		t.Fatalf("throttle=0: writes = %d, want %d (every request)", got, n)
	}
}

func TestSessionThrottle_AtMostOncePerWindow(t *testing.T) {
	t.Parallel()
	const window = 30 * time.Minute
	stale := sessionT0.Add(-window)
	a, store, _, token := clockedSession(t, &Session{ID: "s", CreatedAt: stale, LastActivity: stale}, Config{ActivityThrottle: window})
	for range 5 {
		mustAuthenticate(t, a, sessionRequest(t.Context(), token))
	}
	if n := store.activities.Load(); n != 1 {
		t.Fatalf("throttle=30m: writes = %d, want 1 within window", n)
	}
}

func TestSessionThrottle_WritesAgainAfterWindow(t *testing.T) {
	t.Parallel()
	const window = 10 * time.Minute
	stale := sessionT0.Add(-window)
	a, store, clock, token := clockedSession(t, &Session{ID: "s", CreatedAt: stale, LastActivity: stale}, Config{ActivityThrottle: window})
	mustAuthenticate(t, a, sessionRequest(t.Context(), token))
	clock.Set(sessionT0.Add(window - time.Nanosecond))
	mustAuthenticate(t, a, sessionRequest(t.Context(), token))
	if n := store.activities.Load(); n != 1 {
		t.Fatalf("within window: writes = %d, want 1", n)
	}
	clock.Set(sessionT0.Add(window))
	mustAuthenticate(t, a, sessionRequest(t.Context(), token))
	if n := store.activities.Load(); n != 2 {
		t.Fatalf("after window elapsed: writes = %d, want 2", n)
	}
}

func TestPassiveSkipsActivity(t *testing.T) {
	t.Parallel()
	t.Run("session and key", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{})
		passive := func(r *http.Request) *http.Request { return r.WithContext(Passive(r.Context())) }
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				if p, err := a.Authenticate(passive(withSession(bearerRequest(""), f.session))); err != nil || !p.IsSession() {
					t.Errorf("passive session Authenticate = (%+v, %v), want the session", p, err)
				}
				if p, err := a.Authenticate(passive(bearerRequest(f.key))); err != nil || p.KeyID != f.keyID {
					t.Errorf("passive key Authenticate = (%+v, %v), want the key", p, err)
				}
			})
		}
		wg.Wait()
		if n := f.store.writes(); n != 0 {
			t.Errorf("passive requests made %d writes, want 0", n)
		}
		mustAuthenticate(t, a, withSession(bearerRequest(""), f.session))
		mustAuthenticate(t, a, bearerRequest(f.key))
		if a, k := f.store.activities.Load(), f.store.touches.Load(); a != 1 || k != 1 {
			t.Errorf("active requests made (%d activity, %d touch) writes, want (1, 1)", a, k)
		}
	})
	t.Run("an expired session is still refused", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		old := time.Now().Add(-48 * time.Hour)
		token := f.addSession(t, &Session{ID: "old", UserID: f.user.ID, CreatedAt: old, LastActivity: old})
		r := withSession(bearerRequest(""), token)
		if _, err := mustAuthenticator(t, f.store, Config{}).Authenticate(r.WithContext(Passive(r.Context()))); err == nil {
			t.Error("passive Authenticate of an expired session error = nil, want ErrSessionExpired")
		}
	})
}

// TestThrottleClampsToSessionIdleCap pins that the write window is at most
// half the session's own idle limit, so a capped session in steady use never
// expires between two throttled writes.
func TestThrottleClampsToSessionIdleCap(t *testing.T) {
	t.Parallel()
	a, store, clock, token := clockedSession(t, &Session{ID: "c", CreatedAt: sessionT0, LastActivity: sessionT0, IdleCap: 30 * time.Minute}, Config{
		IdleTimeout:      7 * 24 * time.Hour,
		AbsTimeout:       7 * 24 * time.Hour,
		ActivityThrottle: time.Hour,
	})
	for i := 1; i <= 6; i++ {
		clock.Set(sessionT0.Add(time.Duration(i) * 20 * time.Minute))
		if _, err := a.Authenticate(sessionRequest(t.Context(), token)); err != nil {
			t.Fatalf("request %d, %d min in: Authenticate error = %v, want the session in steady use", i, i*20, err)
		}
	}
	if n := store.activities.Load(); n != 6 {
		t.Errorf("activity writes = %d, want 6 (a 15-minute window, one write per 20-minute request)", n)
	}
}

func TestKeyTouchThrottle(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	other, _ := f.addUserKey(t)
	a := mustAuthenticator(t, f.store, Config{ActivityThrottle: 30 * time.Minute})
	clock := &testClock{at: sessionT0}
	setVerifierClock(a, clock)
	for range 3 {
		mustAuthenticate(t, a, bearerRequest(f.key))
		mustAuthenticate(t, a, bearerRequest(other))
	}
	if n := f.store.touches.Load(); n != 2 {
		t.Errorf("touches within the window = %d, want 2 (one per key)", n)
	}
	clock.Set(sessionT0.Add(30 * time.Minute))
	mustAuthenticate(t, a, bearerRequest(f.key))
	if n := f.store.touches.Load(); n != 3 {
		t.Errorf("touches after the window = %d, want 3", n)
	}
	k, _, _ := f.store.APIKeyByHash(t.Context(), APIKeyHash(f.key))
	if want := sessionT0.Add(30 * time.Minute); !k.LastUsedAt.Equal(want) {
		t.Errorf("LastUsedAt = %v, want %v", k.LastUsedAt, want)
	}
}

// TestActivityDueFromStoredTime pins that a write is due from the stored
// LastActivity or LastUsedAt alone, so an Authenticator built anew over the
// same store, as after a restart, decides as the first one would.
func TestActivityDueFromStoredTime(t *testing.T) {
	t.Parallel()
	const window = 30 * time.Minute
	cfg := Config{ActivityThrottle: window}
	t.Run("session", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name   string
			age    time.Duration
			writes int32
		}{
			{name: "inside the window", age: window - time.Nanosecond, writes: 0},
			{name: "at the window", age: window, writes: 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				last := sessionT0.Add(-tc.age)
				a, store, _, token := clockedSession(t, &Session{ID: "s", CreatedAt: last, LastActivity: last}, cfg)
				for range 3 {
					mustAuthenticate(t, a, sessionRequest(t.Context(), token))
				}
				if n := store.activities.Load(); n != tc.writes {
					t.Errorf("writes = %d, want %d", n, tc.writes)
				}
			})
		}
		t.Run("a restarted Authenticator", func(t *testing.T) {
			t.Parallel()
			last := sessionT0.Add(-window)
			a, store, _, token := clockedSession(t, &Session{ID: "s", CreatedAt: last, LastActivity: last}, cfg)
			mustAuthenticate(t, a, sessionRequest(t.Context(), token))
			restarted := mustAuthenticator(t, store, cfg)
			setVerifierClock(restarted, &testClock{at: sessionT0.Add(time.Minute)})
			mustAuthenticate(t, restarted, sessionRequest(t.Context(), token))
			if n := store.activities.Load(); n != 1 {
				t.Errorf("writes = %d, want 1 (the restarted Authenticator reads the write the first made)", n)
			}
		})
	})
	t.Run("key", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name    string
			age     time.Duration
			touches int32
		}{
			{name: "inside the window", age: window - time.Nanosecond, touches: 0},
			{name: "at the window", age: window, touches: 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				a, store, _, key := clockedKey(t, &Key{ID: 9, LastUsedAt: sessionT0.Add(-tc.age)}, cfg)
				for range 3 {
					mustAuthenticate(t, a, bearerRequest(key))
				}
				if n := store.touches.Load(); n != tc.touches {
					t.Errorf("touches = %d, want %d", n, tc.touches)
				}
			})
		}
		t.Run("a restarted Authenticator", func(t *testing.T) {
			t.Parallel()
			a, store, _, key := clockedKey(t, &Key{ID: 9}, cfg)
			mustAuthenticate(t, a, bearerRequest(key))
			restarted := mustAuthenticator(t, store, cfg)
			setVerifierClock(restarted, &testClock{at: sessionT0.Add(time.Minute)})
			mustAuthenticate(t, restarted, bearerRequest(key))
			if n := store.touches.Load(); n != 1 {
				t.Errorf("touches = %d, want 1 (the restarted Authenticator reads the touch the first made)", n)
			}
		})
	})
}

// TestActivityRetriesAfterFailedWrite pins that a failed write leaves the
// stored time old, so the next request writes.
func TestActivityRetriesAfterFailedWrite(t *testing.T) {
	t.Parallel()
	const window = 30 * time.Minute
	cfg := Config{ActivityThrottle: window}
	retried := sessionT0.Add(time.Second)
	t.Run("session", func(t *testing.T) {
		t.Parallel()
		last := sessionT0.Add(-window)
		a, store, clock, token := clockedSession(t, &Session{ID: "s", CreatedAt: last, LastActivity: last}, cfg)
		store.writeFails.Store(1)
		mustAuthenticate(t, a, sessionRequest(t.Context(), token))
		clock.Set(retried)
		mustAuthenticate(t, a, sessionRequest(t.Context(), token))
		if n := store.activities.Load(); n != 2 {
			t.Errorf("writes = %d, want 2 (failed, then retried)", n)
		}
		stored, _, _ := store.SessionByHash(t.Context(), SessionHash(token))
		if !stored.LastActivity.Equal(retried) {
			t.Errorf("stored LastActivity = %v, want %v", stored.LastActivity, retried)
		}
	})
	t.Run("key", func(t *testing.T) {
		t.Parallel()
		a, store, clock, key := clockedKey(t, &Key{ID: 9}, cfg)
		store.writeFails.Store(1)
		mustAuthenticate(t, a, bearerRequest(key))
		clock.Set(retried)
		mustAuthenticate(t, a, bearerRequest(key))
		if n := store.touches.Load(); n != 2 {
			t.Errorf("touches = %d, want 2 (failed, then retried)", n)
		}
		k, _, _ := store.APIKeyByHash(t.Context(), APIKeyHash(key))
		if !k.LastUsedAt.Equal(retried) {
			t.Errorf("LastUsedAt = %v, want %v", k.LastUsedAt, retried)
		}
	})
}

// TestActivityClampToHalfIdle pins that a session's write window is at most
// half its own idle limit: a 10-minute IdleCap under a 1-hour throttle writes
// once its LastActivity is 5 minutes old.
func TestActivityClampToHalfIdle(t *testing.T) {
	t.Parallel()
	a, store, clock, token := clockedSession(t, &Session{ID: "c", CreatedAt: sessionT0, LastActivity: sessionT0, IdleCap: 10 * time.Minute}, Config{
		IdleTimeout:      7 * 24 * time.Hour,
		AbsTimeout:       7 * 24 * time.Hour,
		ActivityThrottle: time.Hour,
	})
	clock.Set(sessionT0.Add(5*time.Minute - time.Nanosecond))
	mustAuthenticate(t, a, sessionRequest(t.Context(), token))
	if n := store.activities.Load(); n != 0 {
		t.Errorf("writes 1 ns short of half the idle cap = %d, want 0", n)
	}
	clock.Set(sessionT0.Add(5 * time.Minute))
	mustAuthenticate(t, a, sessionRequest(t.Context(), token))
	if n := store.activities.Load(); n != 1 {
		t.Errorf("writes at half the idle cap = %d, want 1", n)
	}
}

// TestActivityConcurrentWindowEdge pins that concurrent verifications of a
// session due for a write are all granted and store that instant, and that a
// second wave inside the new window writes nothing. -race checks the
// verifier.
func TestActivityConcurrentWindowEdge(t *testing.T) {
	t.Parallel()
	const window = 30 * time.Minute
	last := sessionT0.Add(-window)
	a, store, clock, token := clockedSession(t, &Session{ID: "s", CreatedAt: last, LastActivity: last}, Config{ActivityThrottle: window})
	wave := func() {
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				if p, err := a.Authenticate(sessionRequest(t.Context(), token)); err != nil || !p.IsSession() {
					t.Errorf("Authenticate = (%+v, %v), want the session", p, err)
				}
			})
		}
		wg.Wait()
	}
	wave()
	first := store.activities.Load()
	if first < 1 {
		t.Fatalf("writes in the first wave = %d, want at least 1", first)
	}
	stored, _, _ := store.SessionByHash(t.Context(), SessionHash(token))
	if !stored.LastActivity.Equal(sessionT0) {
		t.Errorf("stored LastActivity = %v, want %v", stored.LastActivity, sessionT0)
	}
	clock.Set(sessionT0.Add(time.Second))
	wave()
	if n := store.activities.Load(); n != first {
		t.Errorf("writes after a second wave 1 s later = %d, want %d (none)", n, first)
	}
}
