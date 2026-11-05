package access

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// The session verifier's "presented but unusable" answers.
var (
	errSessionGone    = fmt.Errorf("%w: %w", ErrUnauthenticated, ErrSessionNotFound)
	errSessionExpired = fmt.Errorf("%w: %w", ErrUnauthenticated, ErrSessionExpired)
)

// sessionVerifier authenticates a request by its one session cookie. [New]
// builds it over the Authenticator's own configuration.
type sessionVerifier struct {
	store AuthenticatorStore
	cfg   *Config
	// now is the verifier's only clock.
	now  func() time.Time
	warn warnLimiter
}

// Verify grants the session the request's one session cookie names. No
// cookie, or more than one, is not its credential.
func (v *sessionVerifier) Verify(ctx context.Context, r *http.Request) (Principal, bool, error) {
	token := v.cfg.Cookie.ReadCookie(r)
	if token == "" {
		return Principal{}, false, nil
	}
	hash := SessionHash(token)
	now := v.now()
	sess, user, ts, err := v.resolve(ctx, hash, now)
	if err != nil {
		return Principal{}, false, err
	}
	if !IsPassive(ctx) && v.activityDue(sess, ts, now) {
		act := SessionActivity{At: now, IP: activityIP(v.cfg.ClientAddr(r).IP)}
		if err := v.store.UpdateSessionActivity(ctx, hash, act); err != nil {
			v.warn.log(v.cfg.log(), "access: session activity update failed", "session_id", sess.ID, "error", err)
		} else {
			sess.LastActivity = now
		}
	}
	return sessionPrincipal(sess, user, hash, ts), true, nil
}

// recheck re-reads p's session and user and returns its principal anew,
// writing nothing.
func (v *sessionVerifier) recheck(ctx context.Context, p *Principal) (Principal, error) {
	sess, user, ts, err := v.resolve(ctx, p.credential, v.now())
	if err != nil {
		return Principal{}, err
	}
	return sessionPrincipal(sess, user, p.credential, ts), nil
}

// resolve reads the session stored under hash and its user, and refuses
// either at now. Every check runs before the caller writes any activity.
func (v *sessionVerifier) resolve(ctx context.Context, hash Hash, now time.Time) (*Session, *User, SessionTimeouts, error) {
	ts := v.cfg.timeouts()
	sess, found, err := v.store.SessionByHash(ctx, hash)
	if err != nil {
		return nil, nil, ts, fmt.Errorf("%w: %w", ErrAuthBackend, err)
	}
	if !found || sess == nil {
		return nil, nil, ts, errSessionGone
	}
	if ValidateSession(sess, ts, now) != nil {
		return nil, nil, ts, errSessionExpired
	}
	user, found, err := v.store.UserByID(ctx, sess.UserID)
	if err != nil {
		return nil, nil, ts, fmt.Errorf("%w: %w", ErrAuthBackend, err)
	}
	if !found || user == nil || !user.Enabled {
		v.cfg.log().Debug("access: session user missing or disabled", "session_id", sess.ID, "user_id", sess.UserID)
		return nil, nil, ts, errSessionGone
	}
	if sess.Kind == SessionRecovery && !allowsRecoverySession(ctx) {
		return nil, nil, ts, &InvalidCredentialError{Method: sess.AuthMethod, Err: ErrRestrictedSession}
	}
	return sess, user, ts, nil
}

// activityDue reports whether this request writes sess's activity: once the
// stored LastActivity is the throttle old, the window clamped to half the
// session's own idle limit, its cap and the recovery lifetime included. A
// window at or above that limit would let an active session expire between
// two writes. The stored time is the throttle's only state, so a failed
// write is retried by the next request.
func (v *sessionVerifier) activityDue(sess *Session, ts SessionTimeouts, now time.Time) bool {
	idle, _ := SessionDeadlines(sess, ts)
	return now.Sub(sess.LastActivity) >= min(v.cfg.ActivityThrottle, idle.Sub(sess.LastActivity)/2)
}

func sessionPrincipal(sess *Session, user *User, hash Hash, ts SessionTimeouts) Principal {
	idle, absolute := SessionDeadlines(sess, ts)
	return Principal{
		User:             user,
		Method:           sess.AuthMethod,
		SessionID:        sess.ID,
		SessionKind:      sess.Kind,
		AuthTime:         sess.AuthTime,
		IdleDeadline:     idle,
		AbsoluteDeadline: absolute,
		credential:       hash,
		source:           sourceSession,
	}
}

// activityWarnInterval is how long after a failed-write WARN further
// failures are only counted: a store failing every write would otherwise log
// once per request.
const activityWarnInterval = time.Minute

// warnLimiter rate-limits one verifier's failed-write WARN; it is the
// verifiers' only mutable state.
type warnLimiter struct {
	last time.Time
	// now is read only under mu, so the times allow compares never run
	// backwards: a time read before the lock lets a later failure log first
	// and date the interval from the later instant.
	now        func() time.Time
	mu         sync.Mutex
	suppressed int
}

// allow reports whether a failure now logs and, when it does, the failures
// counted since the last WARN, resetting the count.
func (l *warnLimiter) allow() (ok bool, suppressed int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.last) < activityWarnInterval {
		l.suppressed++
		return false, 0
	}
	suppressed, l.last, l.suppressed = l.suppressed, now, 0
	return true, suppressed
}

// log writes msg with args at WARN unless allow refuses, adding the
// suppressed count when it is not zero.
func (l *warnLimiter) log(logger *slog.Logger, msg string, args ...any) {
	ok, n := l.allow()
	if !ok {
		return
	}
	if n > 0 {
		args = append(args, "suppressed", n)
	}
	logger.Warn(msg, args...)
}
