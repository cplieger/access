package access

import (
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// setupAgedSession stores a valid user and a session whose CreatedAt and
// LastActivity are age in the past, returning the store and the token.
func setupAgedSession(t *testing.T, age time.Duration) (*countingStore, string) {
	t.Helper()
	cs, _ := setupThrottleSession(t)
	plaintext, hash := GenerateSessionToken()
	then := time.Now().Add(-age)
	if err := cs.CreateSession(t.Context(), &Session{
		ID: "aged", TokenHash: hash, UserID: 1, AuthMethod: MethodPassword, CreatedAt: then, LastActivity: then,
	}); err != nil {
		t.Fatal(err)
	}
	return cs, plaintext.Reveal()
}

// TestTimeoutSource_ResolvedPerVerify confirms the source is consulted on
// every verification, so a changed value takes effect immediately: the same
// 30-minute-old session is refused under a 10-minute source idle and accepted
// once the source grows it to 1h. The refusal writes no activity, so it
// cannot refresh the session and mask the second assertion.
func TestTimeoutSource_ResolvedPerVerify(t *testing.T) {
	t.Parallel()
	cs, token := setupAgedSession(t, 30*time.Minute)
	var idle atomic.Int64
	idle.Store(int64(10 * time.Minute))
	a := mustAuthenticator(t, cs, Config{Cookie: throttleCookie, TimeoutSource: func() SessionTimeouts {
		return SessionTimeouts{Idle: time.Duration(idle.Load()), Absolute: 24 * time.Hour}
	}})

	if _, err := a.Authenticate(throttleRequest(token)); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Authenticate under a 10m source idle error = %v, want ErrSessionExpired", err)
	}
	idle.Store(int64(time.Hour))
	if p, err := a.Authenticate(throttleRequest(token)); err != nil || !p.IsSession() {
		t.Fatalf("Authenticate under a 1h source idle = (%+v, %v), want the session", p, err)
	}
}

// TestTimeoutSource_NonPositiveFallsBackToStatic confirms a source returning
// non-positive values falls back to the static configured values, each field
// on its own, rather than expiring every session.
func TestTimeoutSource_NonPositiveFallsBackToStatic(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		src  SessionTimeouts
	}{
		{"zero idle, negative absolute", SessionTimeouts{Idle: 0, Absolute: -time.Hour}},
		{"negative idle, zero absolute", SessionTimeouts{Idle: -time.Hour, Absolute: 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cs, token := setupAgedSession(t, 30*time.Minute)
			a := mustAuthenticator(t, cs, Config{
				Cookie:        throttleCookie,
				IdleTimeout:   time.Hour,
				AbsTimeout:    24 * time.Hour,
				TimeoutSource: func() SessionTimeouts { return tt.src },
			})
			if p, err := a.Authenticate(throttleRequest(token)); err != nil || !p.IsSession() {
				t.Fatalf("Authenticate with source %+v = (%+v, %v), want the session via the static fallback", tt.src, p, err)
			}
		})
	}
}

// TestTimeoutSource_ClampsThrottleToHalfIdle confirms the per-resolution
// clamp: with a configured throttle above half the resolved idle timeout,
// activity writes recur at idle/2, so an active session never idle-expires
// from throttling alone.
func TestTimeoutSource_ClampsThrottleToHalfIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cs, token := setupThrottleSession(t)
		// The static idle of 1h passes construction (throttle 80ms < 1h); the
		// source resolves 100ms, clamping the window to 50ms.
		a := mustAuthenticator(t, cs, Config{
			Cookie:           throttleCookie,
			IdleTimeout:      time.Hour,
			AbsTimeout:       24 * time.Hour,
			ActivityThrottle: 80 * time.Millisecond,
			TimeoutSource: func() SessionTimeouts {
				return SessionTimeouts{Idle: 100 * time.Millisecond, Absolute: 24 * time.Hour}
			},
		})

		mustAuthenticate(t, a, throttleRequest(token))
		if got := cs.count("s1"); got != 0 {
			t.Fatalf("writes at the session's own LastActivity = %d, want 0", got)
		}
		synctest.Sleep(30 * time.Millisecond) // inside the clamped 50ms window
		mustAuthenticate(t, a, throttleRequest(token))
		if got := cs.count("s1"); got != 0 {
			t.Fatalf("writes after 30ms = %d, want 0 (inside the clamped 50ms window)", got)
		}
		// 60ms is past the 50ms clamp but inside the raw 80ms window.
		synctest.Sleep(30 * time.Millisecond)
		mustAuthenticate(t, a, throttleRequest(token))
		if got := cs.count("s1"); got != 1 {
			t.Fatalf("writes after 60ms = %d, want 1 (clamped window 50ms elapsed)", got)
		}
	})
}

// TestTimeoutSource_SubWindowIdleWritesEveryRequest covers the degenerate
// end of the clamp: a resolved idle of 1ns halves to zero, so every request
// writes, and once a usable idle is restored the fresh stored time throttles
// the next request.
func TestTimeoutSource_SubWindowIdleWritesEveryRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cs, token := setupThrottleSession(t)
		var idle atomic.Int64
		idle.Store(1)
		a := mustAuthenticator(t, cs, Config{
			Cookie:           throttleCookie,
			IdleTimeout:      time.Hour,
			AbsTimeout:       24 * time.Hour,
			ActivityThrottle: 30 * time.Minute,
			TimeoutSource: func() SessionTimeouts {
				return SessionTimeouts{Idle: time.Duration(idle.Load()), Absolute: 24 * time.Hour}
			},
		})

		// The session was created at this virtual instant, so a 1ns idle
		// still accepts it.
		mustAuthenticate(t, a, throttleRequest(token))
		mustAuthenticate(t, a, throttleRequest(token))
		if got := cs.count("s1"); got != 2 {
			t.Fatalf("writes under a 1ns resolved idle = %d, want 2", got)
		}
		idle.Store(int64(time.Hour))
		mustAuthenticate(t, a, throttleRequest(token))
		if got := cs.count("s1"); got != 2 {
			t.Fatalf("writes after the idle timeout was restored = %d, want 2 (the stored time is fresh)", got)
		}
	})
}
