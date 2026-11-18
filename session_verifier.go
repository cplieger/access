package access

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/cplieger/access/internal/failreason"
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
	now     func() time.Time
	revoker atomic.Pointer[SessionRevoker]
	warn    warnLimiter
	// mismatchWarn limits the WARN for a transport mismatch left unrevoked.
	mismatchWarn warnLimiter
}

// revokeTimeout bounds one transport-mismatch revoke. It runs detached
// from the request's cancellation, so a client that hangs up cannot keep
// its token alive.
const revokeTimeout = 5 * time.Second

// SessionRevoker ends a session the session verifier refused for its
// transport (see [Session.Secure]).
type SessionRevoker interface {
	// RevokeTransportMismatch deletes the session ref names, answering nil
	// when it is already gone.
	RevokeTransportMismatch(ctx context.Context, ref SessionRef) error
}

// UseSessionRevoker registers r as the revoker of every session refused
// for its transport. It refuses a nil r and a second registration; with
// none registered, such a session is refused but left in the store.
func (a *Authenticator) UseSessionRevoker(r SessionRevoker) error {
	if isNilInterface(r) {
		return errors.New("access: UseSessionRevoker: nil SessionRevoker")
	}
	if !a.sessions.revoker.CompareAndSwap(nil, &r) {
		return errors.New("access: UseSessionRevoker: a revoker is already registered")
	}
	return nil
}

// verify grants the session the request's one session cookie names, read
// for ca's transport. No cookie, or more than one, is not its credential. A
// session whose Secure differs from ca's is refused with
// [ErrSessionTransport]; revokeMismatch owns whether it is revoked.
func (v *sessionVerifier) verify(ctx context.Context, r *http.Request, ca ClientAddr) (Principal, bool, error) {
	token := v.cfg.Cookie.ReadCookie(r, ca.Secure)
	if token == "" {
		return Principal{}, false, nil
	}
	hash := SessionHash(token)
	now := v.now()
	sess, user, ts, err := v.resolve(ctx, hash, now)
	if err != nil {
		return Principal{}, false, err
	}
	if sess.Secure != ca.Secure {
		v.revokeMismatch(ctx, sess)
		return Principal{}, false, failreason.Wrap(&InvalidCredentialError{Method: sess.AuthMethod, Err: ErrSessionTransport}, failreason.TransportChanged)
	}
	if !IsPassive(ctx) && v.activityDue(sess, ts, now) {
		act := SessionActivity{At: now, IP: activityIP(ca.IP())}
		if err := v.store.UpdateSessionActivity(ctx, hash, act); err != nil {
			v.warn.log(v.cfg.log(), "access: session activity update failed", "session_id", sess.ID, "error", err)
		} else {
			sess.LastActivity = now
		}
	}
	return sessionPrincipal(sess, user, hash, ts), true, nil
}

// revokeMismatch ends sess, refused for its transport, through the
// registered revoker. With none, or when the revoke fails, the session
// stays stored and a WARN says so; the refusal stands either way.
func (v *sessionVerifier) revokeMismatch(ctx context.Context, sess *Session) {
	const msg = "access: a session presented on the other transport was refused but not revoked"
	r := v.revoker.Load()
	if r == nil {
		v.mismatchWarn.log(v.cfg.log(), msg, "session_id", sess.ID)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	if err := (*r).RevokeTransportMismatch(ctx, SessionRef{ID: sess.ID, UserID: sess.UserID}); err != nil {
		v.mismatchWarn.log(v.cfg.log(), msg, "session_id", sess.ID, "error", err)
	}
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
		return nil, nil, ts, failreason.Wrap(errSessionGone, failreason.SessionUnknown)
	}
	if ValidateSession(sess, ts, now) != nil {
		return nil, nil, ts, failreason.Wrap(errSessionExpired, failreason.SessionExpired)
	}
	user, found, err := v.store.UserByID(ctx, sess.UserID)
	if err != nil {
		return nil, nil, ts, fmt.Errorf("%w: %w", ErrAuthBackend, err)
	}
	if !found || user == nil || !user.Enabled {
		v.cfg.log().Debug("access: session user missing or disabled", "session_id", sess.ID, "user_id", sess.UserID)
		return nil, nil, ts, failreason.Wrap(errSessionGone, failreason.AccountDisabled)
	}
	return sess, user, ts, nil
}

// activityDue reports whether this request writes sess's activity: once the
// stored LastActivity is the throttle old, the window clamped to half the
// session's own idle limit, its cap included. A
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
		AuthTime:         sess.AuthTime,
		IdleDeadline:     idle,
		AbsoluteDeadline: absolute,
		credential:       hash,
		source:           sourceSession,
	}
}
