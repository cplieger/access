package access

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// Sentinel errors for session operations.
var (
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionNotFound = errors.New("session not found")
)

// generateRandomHex returns n cryptographically random bytes, hex-encoded.
//
// It cannot fail, and so returns no error: since Go 1.24 [crypto/rand.Read] is
// documented never to return an error — it fills its argument entirely and
// crashes the program irrecoverably rather than reporting a failure a caller
// could mishandle. An always-nil error here would propagate to every token
// constructor below and invite the one fallback that must never exist in an
// auth library: degrading to a weaker source when "randomness failed".
func generateRandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b) // never returns an error (Go 1.24+); it crashes instead
	return hex.EncodeToString(b)
}

// GenerateSessionToken generates a cryptographically random session token
// (256 bits / 32 bytes). It returns the hex-encoded plaintext token, to
// Reveal only into the cookie, and its [SessionHash], to store. It cannot
// fail; see [generateRandomHex].
func GenerateSessionToken() (plaintext Secret, hash Hash) {
	tok := generateRandomHex(32)
	return NewSecret(tok), SessionHash(tok)
}

// SessionTimeouts groups the idle and absolute session timeouts, so a swap of
// two adjacent durations cannot leave the idle timeout unbounded. Both fields
// are required: a zero field, a partial literal included, expires every
// session instantly, and a zero pair passed to a store's
// CleanupExpiredSessions would delete every session, which account never
// passes and a store may refuse. It fails closed (lockout, never a bypass).
type SessionTimeouts struct {
	// Idle is the maximum time since the session's last activity.
	Idle time.Duration
	// Absolute is the maximum time since the session was created.
	Absolute time.Duration
}

// RecoverySessionLifetime bounds a [SessionRecovery] session's idle and
// absolute life, whatever the policy timeouts.
const RecoverySessionLifetime = 15 * time.Minute

// SessionDeadlines returns the instants after which s is expired: its last
// activity plus the idle limit, and its creation plus the absolute limit.
// Each limit is the policy's in t, lowered to [RecoverySessionLifetime] for a
// [SessionRecovery] session and to the session's positive IdleCap or
// AbsoluteCap. s must not be nil.
func SessionDeadlines(s *Session, t SessionTimeouts) (idle, absolute time.Time) {
	idleLimit, absoluteLimit := t.Idle, t.Absolute
	if s.Kind == SessionRecovery {
		idleLimit = min(idleLimit, RecoverySessionLifetime)
		absoluteLimit = min(absoluteLimit, RecoverySessionLifetime)
	}
	if s.IdleCap > 0 {
		idleLimit = min(idleLimit, s.IdleCap)
	}
	if s.AbsoluteCap > 0 {
		absoluteLimit = min(absoluteLimit, s.AbsoluteCap)
	}
	return s.LastActivity.Add(idleLimit), s.CreatedAt.Add(absoluteLimit)
}

// ValidateSession returns [ErrSessionExpired] when now is after either of the
// session's [SessionDeadlines], and [ErrSessionNotFound] for a nil session.
func ValidateSession(sess *Session, timeouts SessionTimeouts, now time.Time) error {
	if sess == nil {
		return ErrSessionNotFound
	}
	idle, absolute := SessionDeadlines(sess, timeouts)
	if now.After(idle) || now.After(absolute) {
		return ErrSessionExpired
	}
	return nil
}

// HexSHA256 returns the hex-encoded SHA-256 hash of s.
func HexSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// SessionHash returns the hex-encoded SHA-256 hash of a plaintext token.
func SessionHash(token string) Hash {
	return NewHash(HexSHA256(token))
}
