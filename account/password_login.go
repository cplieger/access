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
// call a plain c under PostureSecure, a bad name, a *ratelimit.RefusedError
// and access.ErrHashBusy (a wait for the name's lock that ctx ended
// included). It compares one hash, counted, locking at FailureCap: the
// user's live temporary password, else PasswordHash unless
// Rules.DisablePasswordLogin; every other arm is one ErrInvalidCredentials
// after the same work. A temporary password answers pendTemporary's ticket
// or refusal; a password signs in or answers pendAt's.
func (s *Service) PasswordLogin(ctx context.Context, c Client, in Credentials) (LoginResult, error) { //nolint:gocritic // hugeParam: the request's Client and input, read once
	r, err := s.beginOver(plainPerRequest, c.Secure)
	if err != nil {
		return LoginResult{}, err
	}
	var (
		canonical string
		a         *passwordAttempt
		reenabled bool
		temporary access.TemporaryPassword
		unlock    func()
	)
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	return s.signIn(ctx, r, c, &sessionOp{
		method: access.MethodPassword,
		gate: admission{
			refusals: func() error {
				var nameErr error
				canonical, nameErr = canonicalUsername(in.Username)
				return nameErr
			},
			limit: func() (*ratelimit.Reservation, error) {
				return s.limiter.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(c.IP()), Account: ratelimit.AccountKey(canonical), Device: c.Device})
			},
		},
		prepare: func(res *ratelimit.Reservation) error {
			var lockErr error
			if unlock, lockErr = s.lockName(ctx, canonical); lockErr != nil {
				return busy(lockErr)
			}
			a = s.newAttempt(res, canonical)
			a.signIn, a.passwordOff = true, r.DisablePasswordLogin
			return s.verifyCounted(ctx, a, canonical, in.Password, !res.Trusted())
		},
		in: func(tx Tx) (*access.User, error) {
			reenabled = false
			if a.viaTemporary {
				u, rec, err := s.liveTemporaryIn(ctx, tx, a.user.ID, a.verified)
				temporary = rec
				return u, err
			}
			u, cleared, err := commitVerified(ctx, tx, a)
			if err != nil {
				return nil, err
			}
			reenabled = cleared
			return u, requireLocal(ctx, tx, u, ErrInvalidCredentials)
		},
		pend: func(tx Tx, j *journal, u *access.User) (*pending, error, error) {
			if !a.viaTemporary {
				return s.pendAt(ctx, tx, r, c, u, a.res.KnownDevice())
			}
			entry, refused, cleared, err := s.pendTemporary(ctx, tx, j, r, c, a, u, &temporary)
			reenabled = cleared
			return entry, refused, err
		},
		announce: func(j *journal, u *access.User, sess *access.Session) {
			at, actor := s.signInActor(u, sess)
			j.addReenabled(reenabled, a.ref, at, actor)
		},
	})
}
