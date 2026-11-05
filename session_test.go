package access

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestProperty_SessionTokenUniquenessAndEntropy(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 20).Draw(t, "n")
		tokens := make(map[string]struct{}, n)
		hashes := make(map[string]struct{}, n)

		for i := range n {
			tok, hash := GenerateSessionToken()
			plaintext := tok.Reveal()
			if !SessionHash(plaintext).Equal(hash) {
				t.Fatalf("SessionHash(plaintext) differs from the returned hash")
			}

			raw, err := hex.DecodeString(plaintext)
			if err != nil {
				t.Fatalf("token is not valid hex: %v", err)
			}
			if len(raw) < 32 {
				t.Fatalf("token raw length %d < 32", len(raw))
			}
			if plaintext == hash.Reveal() {
				t.Fatalf("hash equals plaintext")
			}
			if _, dup := tokens[plaintext]; dup {
				t.Fatalf("duplicate token at index %d", i)
			}
			tokens[plaintext] = struct{}{}
			if _, dup := hashes[hash.Reveal()]; dup {
				t.Fatalf("duplicate hash at index %d", i)
			}
			hashes[hash.Reveal()] = struct{}{}
		}
	})
}

func TestProperty_SessionExpiryEnforcement(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		idleTimeout := time.Duration(rapid.Int64Range(int64(time.Minute), int64(30*24*time.Hour)).Draw(t, "idleTimeout"))
		absTimeout := time.Duration(rapid.Int64Range(int64(time.Minute), int64(30*24*time.Hour)).Draw(t, "absTimeout"))

		now := time.Now()
		lastActivityAge := time.Duration(rapid.Int64Range(0, int64(60*24*time.Hour)).Draw(t, "lastActivityAge"))
		createdAge := time.Duration(rapid.Int64Range(0, int64(60*24*time.Hour)).Draw(t, "createdAge"))

		if createdAge < lastActivityAge {
			createdAge, lastActivityAge = lastActivityAge, createdAge
		}

		sess := &Session{
			CreatedAt:    now.Add(-createdAge),
			LastActivity: now.Add(-lastActivityAge),
		}

		idleExpired := lastActivityAge > idleTimeout
		absExpired := createdAge > absTimeout

		err := ValidateSession(sess, SessionTimeouts{Idle: idleTimeout, Absolute: absTimeout}, now)

		if idleExpired || absExpired {
			if err == nil {
				t.Fatalf("expected ErrSessionExpired")
			}
		} else {
			if err != nil {
				t.Fatalf("expected valid session, got: %v", err)
			}
		}
	})
}

// TestValidateSession_timeoutBoundaries pins the idle and absolute expiry
// boundaries: expiry triggers strictly past the timeout, so a session aged
// exactly at the limit is still valid, and a zero timeout expires immediately.
func TestValidateSession_timeoutBoundaries(t *testing.T) {
	t.Parallel()
	const (
		idle = time.Hour
		abs  = 24 * time.Hour
	)
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name         string
		idle, abs    time.Duration
		lastActivity time.Time
		createdAt    time.Time
		wantErr      bool
	}{
		{"idle exactly at timeout", idle, abs, now.Add(-idle), now, false},
		{"idle just past timeout", idle, abs, now.Add(-idle - time.Nanosecond), now, true},
		{"idle just under timeout", idle, abs, now.Add(-idle + time.Nanosecond), now, false},
		{"absolute exactly at timeout", idle, abs, now, now.Add(-abs), false},
		{"absolute just past timeout", idle, abs, now, now.Add(-abs - time.Nanosecond), true},
		{"zero idle expires immediately", 0, abs, now.Add(-time.Nanosecond), now, true},
		{"zero absolute expires immediately", idle, 0, now, now.Add(-time.Nanosecond), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sess := &Session{LastActivity: tc.lastActivity, CreatedAt: tc.createdAt}
			err := ValidateSession(sess, SessionTimeouts{Idle: tc.idle, Absolute: tc.abs}, now)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateSession(idle=%v, abs=%v, lastActivity %v ago, created %v ago) = %v, wantErr=%v",
					tc.idle, tc.abs, now.Sub(tc.lastActivity), now.Sub(tc.createdAt), err, tc.wantErr)
			}
		})
	}
}

func TestSessionDeadlines(t *testing.T) {
	t.Parallel()
	const week = 7 * 24 * time.Hour
	created := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	active := created.Add(3 * time.Hour)
	policy := SessionTimeouts{Idle: week, Absolute: week}
	tests := []struct {
		name              string
		kind              SessionKind
		idleCap, absCap   time.Duration
		wantIdle, wantAbs time.Time
	}{
		{name: "uncapped full session", wantIdle: active.Add(week), wantAbs: created.Add(week)},
		{
			name: "caps below the policy", idleCap: 30 * time.Minute, absCap: 12 * time.Hour,
			wantIdle: active.Add(30 * time.Minute), wantAbs: created.Add(12 * time.Hour),
		},
		{name: "caps above the policy", idleCap: 2 * week, absCap: 3 * week, wantIdle: active.Add(week), wantAbs: created.Add(week)},
		{name: "zero caps", wantIdle: active.Add(week), wantAbs: created.Add(week)},
		{name: "negative caps", idleCap: -time.Hour, absCap: -time.Nanosecond, wantIdle: active.Add(week), wantAbs: created.Add(week)},
		{
			name: "recovery session", kind: SessionRecovery,
			wantIdle: active.Add(15 * time.Minute), wantAbs: created.Add(15 * time.Minute),
		},
		{
			name: "recovery session with lower caps", kind: SessionRecovery, idleCap: 5 * time.Minute, absCap: 10 * time.Minute,
			wantIdle: active.Add(5 * time.Minute), wantAbs: created.Add(10 * time.Minute),
		},
		{
			name: "recovery session with higher caps", kind: SessionRecovery, idleCap: time.Hour, absCap: time.Hour,
			wantIdle: active.Add(15 * time.Minute), wantAbs: created.Add(15 * time.Minute),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &Session{CreatedAt: created, LastActivity: active, Kind: tc.kind, IdleCap: tc.idleCap, AbsoluteCap: tc.absCap}
			idle, absolute := SessionDeadlines(s, policy)
			if !idle.Equal(tc.wantIdle) {
				t.Errorf("idle deadline = %v, want %v", idle, tc.wantIdle)
			}
			if !absolute.Equal(tc.wantAbs) {
				t.Errorf("absolute deadline = %v, want %v", absolute, tc.wantAbs)
			}
		})
	}
}

func TestValidateSessionCaps(t *testing.T) {
	t.Parallel()
	const week = 7 * 24 * time.Hour
	created := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	policy := SessionTimeouts{Idle: week, Absolute: week}
	// The absolute cases stay active until a second before the instant, so
	// only the 12 h cap can lapse there.
	idleCapped := &Session{CreatedAt: created, LastActivity: created, IdleCap: 30 * time.Minute}
	recovery := &Session{CreatedAt: created, LastActivity: created, Kind: SessionRecovery}
	absAt := created.Add(12 * time.Hour)
	tests := []struct {
		s       *Session
		now     time.Time
		wantErr error
		name    string
	}{
		{name: "idle cap exactly at its deadline", s: idleCapped, now: created.Add(30 * time.Minute)},
		{name: "idle cap 1ns after its deadline", s: idleCapped, now: created.Add(30*time.Minute + 1), wantErr: ErrSessionExpired},
		{
			name: "absolute cap exactly at its deadline", now: absAt,
			s: &Session{CreatedAt: created, LastActivity: absAt.Add(-time.Second), AbsoluteCap: 12 * time.Hour},
		},
		{
			name: "absolute cap 1ns after its deadline", now: absAt.Add(1), wantErr: ErrSessionExpired,
			s: &Session{CreatedAt: created, LastActivity: absAt.Add(-time.Second), AbsoluteCap: 12 * time.Hour},
		},
		{name: "uncapped full session a day old", s: &Session{CreatedAt: created, LastActivity: created.Add(23 * time.Hour)}, now: created.Add(24 * time.Hour)},
		{name: "recovery session idle 15 min", s: recovery, now: created.Add(15 * time.Minute)},
		{name: "recovery session idle 15 min and 1ns", s: recovery, now: created.Add(15*time.Minute + 1), wantErr: ErrSessionExpired},
		{
			name: "recovery session created 15 min and 1ns ago, active a minute ago", now: created.Add(15*time.Minute + 1), wantErr: ErrSessionExpired,
			s: &Session{CreatedAt: created, LastActivity: created.Add(14*time.Minute + 1), Kind: SessionRecovery},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateSession(tc.s, policy, tc.now); !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidateSession(%v after creation) = %v, want %v", tc.now.Sub(created), err, tc.wantErr)
			}
		})
	}
}

// TestValidateSessionIgnoresOIDCExpiry pins that an OIDC session is bounded by
// its idle and absolute deadlines only, never by its ID token's expiry: one
// signed in 3 h ago, active a minute ago, stays valid while those admit it.
func TestValidateSessionIgnoresOIDCExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	sess := &Session{
		CreatedAt:    now.Add(-3 * time.Hour),
		AuthTime:     now.Add(-3 * time.Hour),
		LastActivity: now.Add(-time.Minute),
		AuthMethod:   MethodOIDC,
	}
	if err := ValidateSession(sess, SessionTimeouts{Idle: time.Hour, Absolute: 24 * time.Hour}, now); err != nil {
		t.Errorf("ValidateSession(created 3h ago, idle 1m) = %v, want nil", err)
	}
}
