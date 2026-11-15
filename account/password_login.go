package account

import (
	"context"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
)

// Credentials is the input of PasswordLogin.
type Credentials struct {
	Password access.Secret
	Username string
}

// PasswordLogin is a password sign-in's step 1. It refuses before any store
// call a plain c under PostureSecure, ErrPasswordLoginDisabled, a bad name,
// a *ratelimit.RefusedError and access.ErrHashBusy; every later attempt is
// counted before the compare, locking at FailureCap, and a stored hash
// costlier than the hasher's may still be access.ErrHashBusy. A wrong,
// unknown, disabled, locked or dormant arm is one ErrInvalidCredentials after
// the same work. A correct password resets the failure records and rehashes
// an old hash, then signs in or answers pendAt's Pending or refusal.
func (s *Service) PasswordLogin(ctx context.Context, c Client, in Credentials) (LoginResult, error) { //nolint:gocritic // hugeParam: the request's Client and input, read once
	r, err := s.beginOver(plainPerRequest, c.Secure)
	if err != nil {
		return LoginResult{}, err
	}
	var (
		canonical string
		a         *passwordAttempt
		reenabled bool
	)
	return s.signIn(ctx, r, c, &sessionOp{
		method: access.MethodPassword,
		gate: admission{
			refusals: func() error {
				if r.DisablePasswordLogin {
					return ErrPasswordLoginDisabled
				}
				var nameErr error
				canonical, nameErr = canonicalUsername(in.Username)
				return nameErr
			},
			limit: func() (*ratelimit.Reservation, error) {
				return s.limiter.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(c.IP()), Account: ratelimit.AccountKey(canonical), Device: c.Device})
			},
		},
		prepare: func(res *ratelimit.Reservation) error {
			a = s.newAttempt(res, canonical)
			return s.verifyCounted(ctx, a, canonical, in.Password, !res.Trusted())
		},
		in: func(tx Tx) (*access.User, error) {
			u, cleared, err := commitVerified(ctx, tx, a)
			if err != nil {
				return nil, err
			}
			reenabled = cleared
			return u, requireLocal(ctx, tx, u, ErrInvalidCredentials)
		},
		pend: func(tx Tx, u *access.User) (*pending, error, error) {
			return s.pendAt(ctx, tx, r, c, u, a.res.KnownDevice())
		},
		announce: func(j *journal, u *access.User, sess *access.Session) {
			if !reenabled {
				return
			}
			ev := Event{Kind: EventMethodReenabled, At: s.now(), UserID: u.ID, Method: access.MethodPassword, Trusted: a.ref.Trusted, Actor: EventActor{UserID: u.ID}}
			if sess != nil {
				ev.At, ev.Actor.SessionID = sess.CreatedAt, sess.ID
			}
			j.add(ev)
		},
	})
}
