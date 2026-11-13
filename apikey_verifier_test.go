package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access/internal/capture"
	"github.com/cplieger/access/internal/failreason"
	"pgregory.net/rapid"
)

// TestBearerHeader pins which Authorization headers the API-key verifier
// reads: one header, the Bearer scheme in any case, one or more spaces, then
// a non-empty value. Every other shape is not its credential.
func TestBearerHeader(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	a := mustAuthenticator(t, f.store, Config{})
	for _, tt := range []struct {
		name    string
		headers []string
		read    bool
	}{
		{name: "Bearer", headers: []string{"Bearer " + f.key}, read: true},
		{name: "lowercase scheme", headers: []string{"bearer " + f.key}, read: true},
		{name: "uppercase scheme", headers: []string{"BEARER " + f.key}, read: true},
		{name: "mixed-case scheme", headers: []string{"bEaReR " + f.key}, read: true},
		{name: "two spaces", headers: []string{"Bearer  " + f.key}, read: true},
		{name: "Basic", headers: []string{"Basic dXNlcjpwYXNz"}},
		{name: "another scheme", headers: []string{"Token " + f.key}},
		{name: "scheme only", headers: []string{"Bearer"}},
		{name: "scheme and space", headers: []string{"Bearer "}},
		{name: "scheme and spaces", headers: []string{"Bearer   "}},
		{name: "tab separator", headers: []string{"Bearer\t" + f.key}},
		{name: "scheme glued to the key", headers: []string{"Bearer" + f.key}},
		{name: "leading space", headers: []string{" Bearer " + f.key}},
		{name: "two headers", headers: []string{"Bearer " + f.key, "Bearer " + f.key}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/api", nil)
			for _, h := range tt.headers {
				r.Header.Add("Authorization", h)
			}
			p, err := a.Authenticate(r)
			if tt.read {
				if err != nil || p.KeyID != f.keyID {
					t.Errorf("Authenticate = (%+v, %v), want the key's principal", p, err)
				}
				return
			}
			if err != ErrUnauthenticated { //nolint:errorlint // bare: no verifier claimed the header
				t.Errorf("Authenticate error = %v, want bare ErrUnauthenticated (not the verifier's credential)", err)
			}
		})
	}
	t.Run("X-API-Key is not read", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		r.Header.Set("X-API-Key", f.key)
		if _, err := a.Authenticate(r); err != ErrUnauthenticated { //nolint:errorlint // bare: no verifier claimed the header
			t.Errorf("Authenticate(X-API-Key) error = %v, want bare ErrUnauthenticated", err)
		}
	})
}

// clockedKey stores an enabled user and k for it, builds an Authenticator
// over a recording store on a test clock, and returns them with the key.
func clockedKey(t *testing.T, k *Key, cfg Config) (*Authenticator, *recordingStore, *testClock, string) {
	t.Helper()
	store := newRecordingStore()
	user := &User{Username: "alice", Role: RoleUser, Enabled: true}
	if err := store.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	g, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	k.UserID, k.KeyHash, k.KeyPrefix = user.ID, g.Hash, g.DisplayPrefix
	if err := store.CreateAPIKey(t.Context(), k); err != nil {
		t.Fatal(err)
	}
	a := mustAuthenticator(t, store, cfg)
	clock := &testClock{at: sessionT0}
	setVerifierClock(a, clock)
	return a, store, clock, g.Plaintext.Reveal()
}

// TestAPIKeyExpiryInstant pins that a key stops authenticating at the very
// instant of its ExpiresAt, and that a refused use writes nothing.
func TestAPIKeyExpiryInstant(t *testing.T) {
	t.Parallel()
	expiry := sessionT0.Add(time.Hour)
	a, store, clock, key := clockedKey(t, &Key{ID: 9, ExpiresAt: expiry}, Config{})

	clock.Set(expiry.Add(-time.Nanosecond))
	if p, err := a.Authenticate(bearerRequest(key)); err != nil || p.KeyID != 9 {
		t.Fatalf("Authenticate 1 ns before ExpiresAt = (%+v, %v), want the key", p, err)
	}
	if n := store.touches.Load(); n != 1 {
		t.Fatalf("touches before expiry = %d, want 1", n)
	}
	for name, at := range map[string]time.Time{"at ExpiresAt": expiry, "after ExpiresAt": expiry.Add(time.Nanosecond)} {
		clock.Set(at)
		_, err := a.Authenticate(bearerRequest(key))
		var ice *InvalidCredentialError
		if !errors.As(err, &ice) || !errors.Is(err, ErrInvalidAPIKey) || ice.KeyID != 9 {
			t.Errorf("Authenticate %s error = %v, want ErrInvalidCredential wrapping ErrInvalidAPIKey with the key's KeyID", name, err)
		}
	}
	if n := store.writes(); n != 1 {
		t.Errorf("store saw %d writes in all, want 1 (none at or after ExpiresAt)", n)
	}
}

// TestKeyPrincipalDeadline pins a key principal's deadlines: AbsoluteDeadline
// is a set ExpiresAt, and every other deadline of a key or custom principal
// is zero.
func TestKeyPrincipalDeadline(t *testing.T) {
	t.Parallel()
	t.Run("key with an expiry", func(t *testing.T) {
		t.Parallel()
		expiry := sessionT0.Add(time.Hour)
		a, _, _, key := clockedKey(t, &Key{ID: 9, ExpiresAt: expiry}, Config{})
		p, err := a.Authenticate(bearerRequest(key))
		if err != nil {
			t.Fatalf("Authenticate error = %v", err)
		}
		q, err := a.Recheck(t.Context(), p)
		if err != nil {
			t.Fatalf("Recheck error = %v", err)
		}
		for name, got := range map[string]Principal{"Authenticate": p, "Recheck": q} {
			if !got.AbsoluteDeadline.Equal(expiry) || !got.IdleDeadline.IsZero() {
				t.Errorf("%s deadlines = (idle %v, absolute %v), want (zero, %v)", name, got.IdleDeadline, got.AbsoluteDeadline, expiry)
			}
		}
	})
	t.Run("key with no expiry", func(t *testing.T) {
		t.Parallel()
		a, _, _, key := clockedKey(t, &Key{ID: 9}, Config{})
		p, err := a.Authenticate(bearerRequest(key))
		if err != nil || !p.AbsoluteDeadline.IsZero() || !p.IdleDeadline.IsZero() {
			t.Errorf("Authenticate = (%+v, %v), want both deadlines zero", p, err)
		}
	})
	t.Run("custom verifier", func(t *testing.T) {
		t.Parallel()
		a := mustAuthenticator(t, newFakeSessionStore(), Config{Verifier: stubVerifier{p: Principal{User: &User{Enabled: true}, Method: "custom"}, ok: true}})
		p, err := a.Authenticate(bearerRequest(""))
		if err != nil || !p.AbsoluteDeadline.IsZero() || !p.IdleDeadline.IsZero() {
			t.Errorf("Authenticate = (%+v, %v), want both deadlines zero", p, err)
		}
	})
}

// TestPrincipalIdentity pins what names the actor of a key principal and of
// a session principal, and that the two are told apart.
func TestPrincipalIdentity(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	a := mustAuthenticator(t, f.store, Config{})
	key, err := a.Authenticate(bearerRequest(f.key))
	if err != nil {
		t.Fatalf("Authenticate(key) error = %v", err)
	}
	if key.Method != MethodAPIKey || key.KeyID != f.keyID || key.User.ID != f.user.ID || !key.HasScope("read") || len(key.Scopes) != 1 {
		t.Errorf("key principal = {Method %q, KeyID %d, user %d, Scopes %v}, want {%q, %d, %d, [read]}",
			key.Method, key.KeyID, key.User.ID, key.Scopes, MethodAPIKey, f.keyID, f.user.ID)
	}
	if key.IsSession() || key.SessionID != "" || !key.SessionTokenHash().IsZero() {
		t.Error("key principal carries session identity")
	}
	sess, err := a.Authenticate(withSession(bearerRequest(""), f.session))
	if err != nil {
		t.Fatalf("Authenticate(session) error = %v", err)
	}
	stored, _, _ := f.store.SessionByHash(t.Context(), SessionHash(f.session))
	if !sess.IsSession() || sess.SessionID != "sess-1" || !sess.AuthTime.Equal(stored.AuthTime) || sess.Method != MethodPassword {
		t.Errorf("session principal = {IsSession %v, SessionID %q, AuthTime %v, Method %q}, want {true, sess-1, %v, password}",
			sess.IsSession(), sess.SessionID, sess.AuthTime, sess.Method, stored.AuthTime)
	}
	if sess.KeyID != 0 || sess.HasScope("read") {
		t.Error("session principal carries the key's identity")
	}
}

// keyStoreStub answers APIKeyByHash with key and found.
type keyStoreStub struct {
	*recordingStore
	key   *Key
	found bool
}

func (s keyStoreStub) APIKeyByHash(context.Context, Hash) (*Key, bool, error) {
	return s.key, s.found, nil
}

func TestAPIKeyStoreGuards(t *testing.T) {
	t.Parallel()
	key, hash, _, _ := mustAPIKey(t)
	other, _, _, _ := mustAPIKey(t)
	for _, tt := range []struct {
		want  error
		key   *Key
		users map[int64]userAnswer
		name  string
		keyID int64
		found bool
	}{
		{name: "found with a nil key", found: true, want: ErrInvalidAPIKey},
		// The store's answer names another key, which the refusal must not.
		{name: "another key's hash", key: &Key{ID: 1, UserID: 1, KeyHash: APIKeyHash(other)}, found: true, want: ErrInvalidAPIKey},
		{
			name: "nil user", key: &Key{ID: 1, UserID: 1, KeyHash: hash}, found: true, want: ErrAccountDisabled, keyID: 1,
			users: map[int64]userAnswer{1: {found: true}},
		},
		{
			name: "missing user", key: &Key{ID: 1, UserID: 1, KeyHash: hash}, found: true, want: ErrAccountDisabled, keyID: 1,
			users: map[int64]userAnswer{1: {}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingStore{users: tt.users, fakeSessionStore: newFakeSessionStore()}
			a := mustAuthenticator(t, keyStoreStub{recordingStore: store, key: tt.key, found: tt.found}, Config{})
			_, err := a.Authenticate(bearerRequest(key))
			var ice *InvalidCredentialError
			if !errors.As(err, &ice) || !errors.Is(err, tt.want) || ice.KeyID != tt.keyID {
				t.Errorf("Authenticate error = %v, want ErrInvalidCredential wrapping %v with KeyID %d", err, tt.want, tt.keyID)
			}
			if n := store.writes(); n != 0 {
				t.Errorf("store saw %d writes, want 0", n)
			}
		})
	}
	t.Run("user lookup error", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		f.store.userErr = errors.New("db down")
		if _, err := mustAuthenticator(t, f.store, Config{}).Authenticate(bearerRequest(f.key)); !errors.Is(err, ErrAuthBackend) || !errors.Is(err, f.store.userErr) {
			t.Errorf("Authenticate error = %v, want ErrAuthBackend wrapping the store's error", err)
		}
	})
}

// failingTouchStore fails every key touch.
type failingTouchStore struct{ *recordingStore }

func (failingTouchStore) TouchAPIKey(context.Context, int64, Hash, time.Time) error {
	return context.DeadlineExceeded
}

// TestGuardNeverRotatedTouchFailureGrants pins that a key with no previous
// secret is granted when its touch fails, its first use included: the
// failure is logged and the next request retries it.
func TestGuardNeverRotatedTouchFailureGrants(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	if k := f.store.apiKey(f.keyID); !k.LastUsedAt.IsZero() || !k.PreviousHash.IsZero() {
		t.Fatalf("fixture key = %+v, want a never-used, never-rotated key", k)
	}
	logger, h := capture.New()
	a := mustAuthenticator(t, failingTouchStore{f.store}, Config{Logger: logger})
	if p, err := a.Authenticate(bearerRequest(f.key)); err != nil || p.KeyID != f.keyID {
		t.Fatalf("Authenticate = (%+v, %v), want the key despite the failed touch", p, err)
	}
	if n := h.CountMsg("API key touch failed"); n != 1 {
		t.Errorf("logged %d touch warnings, want 1", n)
	}
}

// TestRefusalCarriesNoPresentedBytes pins that a refused Bearer value the
// store does not hold leaves nothing of itself in the refusal, and that a
// refusal names a key, by its KeyID, only when the store found one.
func TestRefusalCarriesNoPresentedBytes(t *testing.T) {
	t.Parallel()
	want := InvalidCredentialError{Err: ErrInvalidAPIKey, Method: MethodAPIKey}
	t.Run("unknown values", func(t *testing.T) {
		t.Parallel()
		a := mustAuthenticator(t, newRecordingStore(), Config{})
		generated := rapid.Custom(func(rt *rapid.T) string {
			return rapid.StringMatching(`[A-Za-z0-9_]{0,16}`).Draw(rt, "prefix") + rapid.StringMatching(`[0-9a-f]{64}`).Draw(rt, "random")
		})
		arbitrary := rapid.String().Filter(func(s string) bool { return strings.TrimLeft(s, " ") != "" })
		value := rapid.OneOf(generated, arbitrary)
		rapid.Check(t, func(rt *rapid.T) {
			for _, v := range []string{value.Draw(rt, "first"), value.Draw(rt, "second")} {
				_, err := a.Authenticate(bearerRequest(v))
				var ice *InvalidCredentialError
				if !errors.As(err, &ice) {
					rt.Fatalf("Authenticate(%q) error = %v, want an *InvalidCredentialError", v, err)
				}
				if *ice != want || err.Error() != want.Error() {
					rt.Fatalf("Authenticate(%q) refusal = %+v %q, want %+v %q", v, *ice, err.Error(), want, want.Error())
				}
			}
		})
	})
	t.Run("a held key is named by its KeyID", func(t *testing.T) {
		t.Parallel()
		expired, _, _, key := clockedKey(t, &Key{ID: 9, ExpiresAt: sessionT0}, Config{})
		f := newChainFixture(t)
		f.store.users = map[int64]userAnswer{f.user.ID: {user: &User{ID: f.user.ID}, found: true}}
		disabled := mustAuthenticator(t, f.store, Config{})
		for name, tt := range map[string]struct {
			a     *Authenticator
			key   string
			keyID int64
		}{
			"expired":        {a: expired, key: key, keyID: 9},
			"owner disabled": {a: disabled, key: f.key, keyID: f.keyID},
		} {
			_, err := tt.a.Authenticate(bearerRequest(tt.key))
			var ice *InvalidCredentialError
			if !errors.As(err, &ice) || ice.KeyID != tt.keyID {
				t.Errorf("%s: Authenticate error = %v, want an *InvalidCredentialError with KeyID %d", name, err, tt.keyID)
			}
		}
	})
}

// rotateKey gives the stored key id a new secret, keeping old (its current
// one) as the previous secret until until, and returns the new plaintext.
func rotateKey(t *testing.T, store *recordingStore, id int64, old string, until time.Time) string {
	t.Helper()
	g, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	store.updateAPIKeySecret(id, KeySecret{
		KeyHash: g.Hash, KeyPrefix: g.DisplayPrefix, KeySuffix: g.DisplaySuffix,
		PreviousHash: APIKeyHash(old), PreviousUntil: until,
	})
	return g.Plaintext.Reveal()
}

// passive marks r as access.Passive.
func passive(r *http.Request) *http.Request { return r.WithContext(Passive(r.Context())) }

// wantRetired checks err is the key refusal a retired previous secret gets:
// the sentinel a client sees, the stored key named, and key_retired for the
// audit.
func wantRetired(t *testing.T, name string, err error, keyID int64) {
	t.Helper()
	var ice *InvalidCredentialError
	if !errors.As(err, &ice) || !errors.Is(err, ErrInvalidAPIKey) || ice.KeyID != keyID || failreason.Of(err) != failreason.KeyRetired {
		t.Errorf("%s: error = %v (reason %q), want ErrInvalidAPIKey for key %d with reason key_retired", name, err, failreason.Of(err), keyID)
	}
}

// TestPreviousSecret pins design 2.4 "Verification": a rotated key's
// previous secret verifies while PreviousUntil is ahead and the new secret
// is unused, and never touches; the new secret's first use is always
// written and ends the overlap.
func TestPreviousSecret(t *testing.T) {
	t.Parallel()
	until := sessionT0.Add(time.Hour)
	for _, throttle := range []time.Duration{0, 10 * time.Minute} {
		t.Run("usable before first use, untouched, throttle "+throttle.String(), func(t *testing.T) {
			t.Parallel()
			a, store, clock, old := clockedKey(t, &Key{ID: 9}, Config{ActivityThrottle: throttle})
			rotateKey(t, store, 9, old, until)
			clock.Set(until.Add(-time.Nanosecond))
			p, err := a.Authenticate(bearerRequest(old))
			if err != nil || p.KeyID != 9 || !p.KeyHash().Equal(APIKeyHash(old)) {
				t.Fatalf("Authenticate(previous) = (%+v, %v), want key 9 with the previous secret's hash", p, err)
			}
			if n := store.touches.Load(); n != 0 {
				t.Errorf("previous-secret use made %d touches, want 0", n)
			}
			if k := store.apiKey(9); !k.LastUsedAt.IsZero() {
				t.Errorf("LastUsedAt after a previous-secret use = %v, want zero", k.LastUsedAt)
			}
		})
	}
	t.Run("refused after the new secret's first use", func(t *testing.T) {
		t.Parallel()
		a, store, _, old := clockedKey(t, &Key{ID: 9}, Config{})
		current := rotateKey(t, store, 9, old, until)
		if _, err := a.Authenticate(bearerRequest(current)); err != nil {
			t.Fatalf("Authenticate(current) error = %v", err)
		}
		_, err := a.Authenticate(bearerRequest(old))
		wantRetired(t, "previous after first use", err, 9)
	})
	t.Run("refused at and after the bound", func(t *testing.T) {
		t.Parallel()
		a, store, clock, old := clockedKey(t, &Key{ID: 9}, Config{})
		current := rotateKey(t, store, 9, old, until)
		for name, at := range map[string]time.Time{"at PreviousUntil": until, "after PreviousUntil": until.Add(time.Nanosecond)} {
			clock.Set(at)
			_, err := a.Authenticate(bearerRequest(old))
			wantRetired(t, name, err, 9)
		}
		if p, err := a.Authenticate(bearerRequest(current)); err != nil || p.KeyID != 9 {
			t.Errorf("Authenticate(current) after the bound = (%+v, %v), want key 9", p, err)
		}
	})
	t.Run("first current use is written inside the throttle and under Passive", func(t *testing.T) {
		t.Parallel()
		a, store, clock, old := clockedKey(t, &Key{ID: 9, LastUsedAt: sessionT0.Add(-time.Minute)}, Config{ActivityThrottle: 10 * time.Minute})
		current := rotateKey(t, store, 9, old, until)
		clock.Set(sessionT0.Add(time.Minute))
		mustAuthenticate(t, a, passive(bearerRequest(current)))
		if k := store.apiKey(9); store.touches.Load() != 1 || !k.LastUsedAt.Equal(sessionT0.Add(time.Minute)) {
			t.Errorf("first use: %d touches, LastUsedAt %v, want 1 touch writing %v", store.touches.Load(), k.LastUsedAt, sessionT0.Add(time.Minute))
		}
		clock.Set(sessionT0.Add(2 * time.Minute))
		mustAuthenticate(t, a, bearerRequest(current))
		mustAuthenticate(t, a, passive(bearerRequest(current)))
		if n := store.touches.Load(); n != 1 {
			t.Errorf("touches after two later uses inside the throttle = %d, want 1", n)
		}
		_, err := a.Authenticate(bearerRequest(old))
		wantRetired(t, "previous after a passive first use", err, 9)
	})
	t.Run("a never-used key's first use is written under Passive", func(t *testing.T) {
		t.Parallel()
		a, store, _, key := clockedKey(t, &Key{ID: 9}, Config{ActivityThrottle: 10 * time.Minute})
		mustAuthenticate(t, a, passive(bearerRequest(key)))
		if k := store.apiKey(9); !k.LastUsedAt.Equal(sessionT0) {
			t.Errorf("LastUsedAt after a passive first use = %v, want %v", k.LastUsedAt, sessionT0)
		}
	})
	t.Run("a touch sampled before a rotation writes nothing after it", func(t *testing.T) {
		t.Parallel()
		a, store, _, old := clockedKey(t, &Key{ID: 9}, Config{})
		var current string
		store.beforeWrite = func() { current = rotateKey(t, store, 9, old, until) }
		mustAuthenticate(t, a, bearerRequest(old))
		store.beforeWrite = nil
		if k := store.apiKey(9); !k.LastUsedAt.IsZero() || !k.KeyHash.Equal(APIKeyHash(current)) {
			t.Fatalf("after the late touch: LastUsedAt %v, want zero on the rotated key", k.LastUsedAt)
		}
		if p, err := a.Authenticate(bearerRequest(old)); err != nil || p.KeyID != 9 {
			t.Errorf("Authenticate(previous) after the late touch = (%+v, %v), want key 9: its overlap is still open", p, err)
		}
	})
}

// TestPreviousSecretDeadline pins a previous-secret principal's
// AbsoluteDeadline, the earlier non-zero of ExpiresAt and PreviousUntil, and
// that Recheck re-resolves it by the presented hash.
func TestPreviousSecretDeadline(t *testing.T) {
	t.Parallel()
	until := sessionT0.Add(time.Hour)
	for name, tt := range map[string]struct{ expires, want time.Time }{
		"no expiry":         {want: until},
		"expiry later":      {expires: until.Add(time.Minute), want: until},
		"expiry earlier":    {expires: until.Add(-time.Minute), want: until.Add(-time.Minute)},
		"expiry at the end": {expires: until, want: until},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, store, _, old := clockedKey(t, &Key{ID: 9, ExpiresAt: tt.expires}, Config{})
			current := rotateKey(t, store, 9, old, until)
			p := mustAuthenticate(t, a, bearerRequest(old))
			q, err := a.Recheck(t.Context(), p)
			if err != nil {
				t.Fatalf("Recheck error = %v", err)
			}
			for name, got := range map[string]Principal{"Authenticate": p, "Recheck": q} {
				if !got.AbsoluteDeadline.Equal(tt.want) || !got.KeyHash().Equal(APIKeyHash(old)) {
					t.Errorf("%s AbsoluteDeadline = %v, want %v on the previous secret", name, got.AbsoluteDeadline, tt.want)
				}
			}
			c := mustAuthenticate(t, a, bearerRequest(current))
			if !c.AbsoluteDeadline.Equal(tt.expires) {
				t.Errorf("current-secret AbsoluteDeadline = %v, want ExpiresAt %v", c.AbsoluteDeadline, tt.expires)
			}
		})
	}
	t.Run("Recheck refuses once the new secret is used", func(t *testing.T) {
		t.Parallel()
		a, store, _, old := clockedKey(t, &Key{ID: 9}, Config{})
		current := rotateKey(t, store, 9, old, until)
		p := mustAuthenticate(t, a, bearerRequest(old))
		c := mustAuthenticate(t, a, bearerRequest(current))
		_, err := a.Recheck(t.Context(), p)
		wantRetired(t, "Recheck(previous)", err, 9)
		if q, err := a.Recheck(t.Context(), c); err != nil || q.KeyID != 9 {
			t.Errorf("Recheck(current) = (%+v, %v), want key 9", q, err)
		}
	})
	t.Run("Recheck refuses at the bound", func(t *testing.T) {
		t.Parallel()
		a, store, clock, old := clockedKey(t, &Key{ID: 9}, Config{})
		rotateKey(t, store, 9, old, until)
		p := mustAuthenticate(t, a, bearerRequest(old))
		clock.Set(until)
		_, err := a.Recheck(t.Context(), p)
		wantRetired(t, "Recheck(previous) at PreviousUntil", err, 9)
	})
}

// TestFirstUseTouchFailure pins design 2.4 "A failed touch": while the
// previous secret still verifies, the new secret's first use is granted
// only once its touch is written, so no client sees the new secret work
// while the old one still does.
func TestFirstUseTouchFailure(t *testing.T) {
	t.Parallel()
	until := sessionT0.Add(time.Hour)
	t.Run("inside the overlap", func(t *testing.T) {
		t.Parallel()
		a, store, _, old := clockedKey(t, &Key{ID: 9}, Config{})
		current := rotateKey(t, store, 9, old, until)
		store.writeFails.Store(1)
		p, err := a.Authenticate(bearerRequest(current))
		if !errors.Is(err, ErrAuthBackend) || !errors.Is(err, errWriteFailed) || !isZeroPrincipal(p) {
			t.Fatalf("Authenticate(current) with a failing first touch = (%+v, %v), want (zero, ErrAuthBackend wrapping the store's error)", p, err)
		}
		if p, err := a.Authenticate(bearerRequest(old)); err != nil || p.KeyID != 9 {
			t.Errorf("Authenticate(previous) after the failed touch = (%+v, %v), want key 9", p, err)
		}
		mustAuthenticate(t, a, bearerRequest(current))
		_, err = a.Authenticate(bearerRequest(old))
		wantRetired(t, "previous after the retried first use", err, 9)
	})
	t.Run("past the bound", func(t *testing.T) {
		t.Parallel()
		a, store, clock, old := clockedKey(t, &Key{ID: 9}, Config{})
		current := rotateKey(t, store, 9, old, until)
		clock.Set(until)
		store.writeFails.Store(1)
		if p, err := a.Authenticate(bearerRequest(current)); err != nil || p.KeyID != 9 {
			t.Errorf("Authenticate(current) with a failing touch once the previous secret is dead = (%+v, %v), want key 9", p, err)
		}
	})
}

// TestKeyVerifierFailReasons pins the audit reason each key refusal
// carries, and that ErrorFor hides it from the client.
func TestKeyVerifierFailReasons(t *testing.T) {
	t.Parallel()
	until := sessionT0.Add(time.Hour)
	unknown, _, _, _ := mustAPIKey(t)
	expired, _, _, expiredKey := clockedKey(t, &Key{ID: 9, ExpiresAt: sessionT0}, Config{})
	retired, store, _, old := clockedKey(t, &Key{ID: 9}, Config{})
	current := rotateKey(t, store, 9, old, until)
	mustAuthenticate(t, retired, bearerRequest(current))
	f := newChainFixture(t)
	f.store.users = map[int64]userAnswer{f.user.ID: {user: &User{ID: f.user.ID}, found: true}}
	disabled := mustAuthenticator(t, f.store, Config{})
	g := newChainFixture(t)
	g.store.users = map[int64]userAnswer{g.user.ID: {}}
	missing := mustAuthenticator(t, g.store, Config{})
	plain := mustAuthenticator(t, newRecordingStore(), Config{})
	for name, tt := range map[string]struct {
		a      *Authenticator
		key    string
		reason string
	}{
		"not a key's shape": {a: plain, key: "not-a-key", reason: failreason.KeyUnknown},
		"unknown key":       {a: plain, key: unknown, reason: failreason.KeyUnknown},
		"expired key":       {a: expired, key: expiredKey, reason: failreason.KeyExpired},
		"retired secret":    {a: retired, key: old, reason: failreason.KeyRetired},
		"owner disabled":    {a: disabled, key: f.key, reason: failreason.AccountDisabled},
		"owner missing":     {a: missing, key: g.key, reason: failreason.AccountDisabled},
	} {
		_, err := tt.a.Authenticate(bearerRequest(tt.key))
		if got := failreason.Of(err); got != tt.reason {
			t.Errorf("%s: reason = %q (error %v), want %q", name, got, err, tt.reason)
		}
		if e, ok := ErrorFor(err); !ok || e.Code != CodeKeyInvalid || e.Reason != "" {
			t.Errorf("%s: ErrorFor = (%+v, %v), want auth_key_invalid with no reason", name, e, ok)
		}
	}
}
