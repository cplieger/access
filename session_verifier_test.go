package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/cplieger/access/internal/capture"
	"github.com/cplieger/access/internal/failreason"
)

// sessionT0 is the fixed instant the clocked session tests start from.
var sessionT0 = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

// clockedSession stores an enabled user and s for it (signed in by password
// unless s names a method), builds an Authenticator over the store with cfg
// on a test clock set to sessionT0, and returns them with the session's
// cookie value.
func clockedSession(t *testing.T, s *Session, cfg Config) (*Authenticator, *recordingStore, *testClock, string) {
	t.Helper()
	store := newRecordingStore()
	user := &User{Username: "alice", Role: RoleUser, Enabled: true}
	if err := store.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	plaintext, hash := GenerateSessionToken()
	s.TokenHash, s.UserID = hash, user.ID
	if s.AuthMethod == "" {
		s.AuthMethod = MethodPassword
	}
	if err := store.CreateSession(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	a := mustAuthenticator(t, store, cfg)
	clock := &testClock{at: sessionT0}
	setVerifierClock(a, clock)
	return a, store, clock, plaintext.Reveal()
}

func sessionRequest(ctx context.Context, token string) *http.Request {
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	return withSession(r, token)
}

// TestSessionVerifierRefusals pins each refusal of a presented session
// cookie: the sentinel a client sees, and the audit reason it carries.
func TestSessionVerifierRefusals(t *testing.T) {
	t.Parallel()
	live := Session{ID: "s", CreatedAt: sessionT0, LastActivity: sessionT0}
	for _, tt := range []struct {
		want     error
		session  Session
		name     string
		token    string
		reason   string
		disabled bool
	}{
		{name: "unknown cookie", token: "no-such-session", want: ErrSessionNotFound, reason: failreason.SessionUnknown, session: live},
		{
			name: "past idle", want: ErrSessionExpired, reason: failreason.SessionExpired,
			session: Session{ID: "s", CreatedAt: sessionT0.Add(-2 * time.Hour), LastActivity: sessionT0.Add(-time.Hour - time.Nanosecond)},
		},
		{
			name: "past absolute", want: ErrSessionExpired, reason: failreason.SessionExpired,
			session: Session{ID: "s", CreatedAt: sessionT0.Add(-24*time.Hour - time.Nanosecond), LastActivity: sessionT0},
		},
		{name: "owner disabled", want: ErrSessionNotFound, reason: failreason.AccountDisabled, session: live, disabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, store, _, token := clockedSession(t, &tt.session, Config{})
			if tt.token != "" {
				token = tt.token
			}
			if tt.disabled {
				store.users = map[int64]userAnswer{tt.session.UserID: {user: &User{ID: tt.session.UserID}, found: true}}
			}
			p, err := a.Authenticate(sessionRequest(t.Context(), token))
			if !errors.Is(err, ErrUnauthenticated) || !errors.Is(err, tt.want) || !isZeroPrincipal(p) {
				t.Errorf("Authenticate = (%+v, %v), want ErrUnauthenticated wrapping %v", p, err, tt.want)
			}
			if got := failreason.Of(err); got != tt.reason {
				t.Errorf("reason = %q, want %q", got, tt.reason)
			}
			if e, ok := ErrorFor(err); !ok || e.Code != CodeSessionExpired || e.Reason != "" {
				t.Errorf("ErrorFor = (%+v, %v), want auth_session_expired with no reason", e, ok)
			}
			if n := store.activities.Load(); n != 0 {
				t.Errorf("store saw %d activity writes, want 0", n)
			}
		})
	}
}

// TestSessionAheadOfClockVerifies pins that a session whose stored times lie
// after the verifier's clock lives exactly as long as SessionDeadlines says.
func TestSessionAheadOfClockVerifies(t *testing.T) {
	t.Parallel()
	week := 7 * 24 * time.Hour
	ahead := sessionT0.Add(2 * time.Minute)
	a, store, clock, token := clockedSession(t, &Session{ID: "s", CreatedAt: ahead, LastActivity: ahead}, Config{IdleTimeout: week, AbsTimeout: week})
	stored, _, _ := store.SessionByHash(t.Context(), SessionHash(token))
	wantIdle, wantAbsolute := SessionDeadlines(stored, a.Timeouts())

	if err := ValidateSession(stored, a.Timeouts(), sessionT0); err != nil {
		t.Fatalf("ValidateSession at the clock error = %v, want nil", err)
	}
	p, err := a.Authenticate(sessionRequest(Passive(t.Context()), token))
	if err != nil || !p.IsSession() {
		t.Fatalf("Authenticate = (%+v, %v), want the session principal", p, err)
	}
	if !p.IdleDeadline.Equal(wantIdle) || !p.AbsoluteDeadline.Equal(wantAbsolute) {
		t.Errorf("deadlines = (%v, %v), want SessionDeadlines' (%v, %v)", p.IdleDeadline, p.AbsoluteDeadline, wantIdle, wantAbsolute)
	}
	if _, err := a.Recheck(t.Context(), p); err != nil {
		t.Errorf("Recheck error = %v, want nil", err)
	}

	clock.Set(wantIdle.Add(time.Nanosecond))
	if _, err := a.Authenticate(sessionRequest(t.Context(), token)); !errors.Is(err, ErrUnauthenticated) || !errors.Is(err, ErrSessionExpired) {
		t.Errorf("Authenticate 1 ns past the idle deadline error = %v, want ErrUnauthenticated wrapping ErrSessionExpired", err)
	}
	if _, err := a.Recheck(t.Context(), p); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("Recheck 1 ns past the idle deadline error = %v, want ErrSessionExpired", err)
	}
}

func TestSessionStoreErrorIs503(t *testing.T) {
	t.Parallel()
	down := errors.New("db down")
	for _, tt := range []struct {
		fail func(*recordingStore)
		name string
	}{
		{name: "session lookup", fail: func(s *recordingStore) { s.sessErr = down }},
		{name: "user lookup", fail: func(s *recordingStore) { s.userErr = down }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newChainFixture(t)
			tt.fail(f.store)
			a := mustAuthenticator(t, f.store, Config{})
			r := func() *http.Request { return withSession(bearerRequest(f.key), f.session) }
			_, err := a.Authenticate(r())
			if !errors.Is(err, ErrAuthBackend) || !errors.Is(err, down) || errors.Is(err, ErrUnauthenticated) {
				t.Errorf("Authenticate error = %v, want ErrAuthBackend wrapping the store's error", err)
			}
			if n := f.store.keyReads.Load(); n != 0 {
				t.Errorf("store saw %d key reads after the outage, want 0 (the chain stops)", n)
			}
			rec := httptest.NewRecorder()
			if _, ok := a.RequireAuth(rec, r()); ok {
				t.Fatal("RequireAuth ok = true, want false")
			}
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "5" {
				t.Errorf("RequireAuth = %d with Retry-After %q, want 503 with Retry-After 5", rec.Code, rec.Header().Get("Retry-After"))
			}
		})
	}
}

func TestSessionActivityWrite(t *testing.T) {
	t.Parallel()
	client := netip.MustParseAddr("192.0.2.7")
	a, store, clock, token := clockedSession(t, &Session{ID: "s", CreatedAt: sessionT0, LastActivity: sessionT0}, Config{ClientAddr: func(*http.Request) ClientAddr { return ClientAddr{Peer: client, Via: ViaDirect} }})
	now := sessionT0.Add(10 * time.Minute)
	clock.Set(now)
	p, err := a.Authenticate(sessionRequest(t.Context(), token))
	if err != nil {
		t.Fatalf("Authenticate error = %v", err)
	}
	stored, _, _ := store.SessionByHash(t.Context(), SessionHash(token))
	if !stored.LastActivity.Equal(now) || stored.LastIP != client.String() {
		t.Errorf("stored activity = (%v, %q), want (%v, %q)", stored.LastActivity, stored.LastIP, now, client)
	}
	if want := now.Add(DefaultIdleTimeout); !p.IdleDeadline.Equal(want) {
		t.Errorf("IdleDeadline = %v, want %v, from the activity just written", p.IdleDeadline, want)
	}
}

func TestSessionActivityFailureWarns(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	f.store.writeFails.Store(1)
	logger, h := capture.New()
	a := mustAuthenticator(t, f.store, Config{Logger: logger})
	p, err := a.Authenticate(withSession(bearerRequest(""), f.session))
	if err != nil || !p.IsSession() {
		t.Fatalf("Authenticate = (%+v, %v), want the session principal despite the failed write", p, err)
	}
	if n := h.CountMsg("session activity update failed"); n != 1 {
		t.Errorf("logged %d activity-update warnings, want 1", n)
	}
}

func TestDuplicateSessionCookie(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	a := mustAuthenticator(t, f.store, Config{})
	twice := func(r *http.Request) *http.Request { return withSession(withSession(r, f.session), f.session) }

	_, err := a.Authenticate(twice(bearerRequest("")))
	if !errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
		t.Errorf("Authenticate(two session cookies) error = %v, want bare ErrUnauthenticated", err)
	}
	if n := f.store.sessReads.Load(); n != 0 {
		t.Errorf("store saw %d session reads, want 0 (two cookies are not the verifier's credential)", n)
	}
	p, err := a.Authenticate(twice(bearerRequest(f.key)))
	if err != nil || p.KeyID != f.keyID {
		t.Errorf("Authenticate(two session cookies + key) = (%+v, %v), want the key's principal", p, err)
	}
}

func TestRecoverySessionRestricted(t *testing.T) {
	t.Parallel()
	week := 7 * 24 * time.Hour
	recovery := func() *Session {
		return &Session{ID: "r", Kind: SessionRecovery, AuthMethod: MethodRecovery, CreatedAt: sessionT0, LastActivity: sessionT0}
	}
	cfg := Config{IdleTimeout: week, AbsTimeout: week}

	t.Run("refused without the mark", func(t *testing.T) {
		t.Parallel()
		a, store, _, token := clockedSession(t, recovery(), cfg)
		_, err := a.Authenticate(sessionRequest(t.Context(), token))
		var ice *InvalidCredentialError
		if !errors.As(err, &ice) || !errors.Is(err, ErrRestrictedSession) || errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("Authenticate error = %v, want ErrInvalidCredential wrapping ErrRestrictedSession", err)
		}
		if ice.Method != MethodRecovery {
			t.Errorf("refusal Method = %q, want %q", ice.Method, MethodRecovery)
		}
		if n := store.activities.Load(); n != 0 {
			t.Errorf("store saw %d activity writes, want 0", n)
		}
	})
	t.Run("granted with the mark and capped at 15 minutes", func(t *testing.T) {
		t.Parallel()
		a, store, clock, token := clockedSession(t, recovery(), cfg)
		ctx := AllowRecoverySession(t.Context())
		p, err := a.Authenticate(sessionRequest(ctx, token))
		if err != nil || !p.IsRecoverySession() || p.IsSession() {
			t.Fatalf("Authenticate = (%+v, %v), want a recovery principal", p, err)
		}
		want := sessionT0.Add(RecoverySessionLifetime)
		if !p.IdleDeadline.Equal(want) || !p.AbsoluteDeadline.Equal(want) {
			t.Errorf("deadlines = (%v, %v), want both %v", p.IdleDeadline, p.AbsoluteDeadline, want)
		}
		writes := store.activities.Load()
		clock.Set(want.Add(time.Nanosecond))
		if _, err := a.Authenticate(sessionRequest(ctx, token)); !errors.Is(err, ErrSessionExpired) {
			t.Errorf("Authenticate 15 min + 1 ns after creation error = %v, want ErrSessionExpired", err)
		}
		if n := store.activities.Load(); n != writes {
			t.Errorf("the refused request wrote activity (%d writes, want %d)", n, writes)
		}
	})
	t.Run("the mark does not restrict a full session", func(t *testing.T) {
		t.Parallel()
		a, _, _, token := clockedSession(t, &Session{ID: "f", CreatedAt: sessionT0, LastActivity: sessionT0}, cfg)
		if p, err := a.Authenticate(sessionRequest(AllowRecoverySession(t.Context()), token)); err != nil || !p.IsSession() {
			t.Errorf("Authenticate = (%+v, %v), want the full session principal", p, err)
		}
	})
}

// TestSessionCapsEnforced pins that a session's own IdleCap and AbsoluteCap
// bound its life and its principal's deadlines under far longer timeouts.
func TestSessionCapsEnforced(t *testing.T) {
	t.Parallel()
	week := 7 * 24 * time.Hour
	cfg := Config{IdleTimeout: week, AbsTimeout: week}
	for _, tt := range []struct {
		name         string
		lastActivity time.Time
		expires      time.Time
	}{
		{name: "idle cap", lastActivity: sessionT0, expires: sessionT0.Add(30 * time.Minute)},
		{name: "absolute cap", lastActivity: sessionT0.Add(12*time.Hour - 10*time.Minute), expires: sessionT0.Add(12 * time.Hour)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, store, clock, token := clockedSession(t, &Session{
				ID: "c", CreatedAt: sessionT0, LastActivity: tt.lastActivity,
				IdleCap: 30 * time.Minute, AbsoluteCap: 12 * time.Hour,
			}, cfg)
			wantIdle, wantAbsolute := tt.lastActivity.Add(30*time.Minute), sessionT0.Add(12*time.Hour)

			clock.Set(tt.expires)
			p, err := a.Authenticate(sessionRequest(Passive(t.Context()), token))
			if err != nil {
				t.Fatalf("Authenticate at the deadline error = %v, want the session", err)
			}
			if !p.IdleDeadline.Equal(wantIdle) || !p.AbsoluteDeadline.Equal(wantAbsolute) {
				t.Errorf("deadlines = (%v, %v), want the capped (%v, %v)", p.IdleDeadline, p.AbsoluteDeadline, wantIdle, wantAbsolute)
			}
			q, err := a.Recheck(t.Context(), p)
			if err != nil || !q.IdleDeadline.Equal(wantIdle) || !q.AbsoluteDeadline.Equal(wantAbsolute) {
				t.Errorf("Recheck = (%v, %v, %v), want the capped (%v, %v)", q.IdleDeadline, q.AbsoluteDeadline, err, wantIdle, wantAbsolute)
			}

			clock.Set(tt.expires.Add(time.Nanosecond))
			if _, err := a.Authenticate(sessionRequest(t.Context(), token)); !errors.Is(err, ErrUnauthenticated) || !errors.Is(err, ErrSessionExpired) {
				t.Errorf("Authenticate 1 ns past the cap error = %v, want ErrUnauthenticated wrapping ErrSessionExpired", err)
			}
			if _, err := a.Recheck(t.Context(), p); !errors.Is(err, ErrSessionExpired) {
				t.Errorf("Recheck 1 ns past the cap error = %v, want ErrSessionExpired", err)
			}
			if n := store.activities.Load(); n != 0 {
				t.Errorf("store saw %d activity writes, want 0", n)
			}
		})
	}
}
