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

// PasswordLogin signs a user in with a password. Before any store call it answers
// ErrPasswordLoginDisabled, a *UsernameError, a *ratelimit.RefusedError (the limiter's,
// or Dimension "untrusted" once the untrusted allowance is spent) or access.ErrHashBusy.
// Each later attempt is counted before it is compared, and FailureCap failures lock the
// password in their trust context. An unknown, disabled, passwordless, locked or
// wrong-password arm is one ErrInvalidCredentials after the same work; a stored hash
// costlier than the hasher's can be access.ErrHashBusy after the count. A success returns
// the device cookie, resets the failure records and rehashes an old hash.
func (s *Service) PasswordLogin(ctx context.Context, c Client, in Credentials) (SignedIn, error) { //nolint:gocritic // hugeParam: the request's Client and input, read once
	r, err := s.begin()
	if err != nil {
		return SignedIn{}, err
	}
	var (
		canonical string
		a         *passwordAttempt
		reenabled bool
	)
	return s.createSession(ctx, r, c, &sessionOp{
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
				return s.limiter.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(c.IP), Account: ratelimit.AccountKey(canonical), Device: c.Device})
			},
		},
		prepare: func(res *ratelimit.Reservation) error {
			a = s.newAttempt(res, canonical)
			return s.verifyCounted(ctx, a, canonical, in.Password, !res.Trusted())
		},
		in: func(tx Tx) (*access.User, error) {
			u, cleared, err := commitVerified(ctx, tx, a)
			reenabled = cleared
			return u, err
		},
		announce: func(u *access.User, sess *access.Session) {
			if reenabled {
				s.emit(Event{
					Kind: EventMethodReenabled, At: sess.CreatedAt, UserID: u.ID, Method: access.MethodPassword, Trusted: a.ref.Trusted,
					Actor: EventActor{SessionID: sess.ID, UserID: u.ID},
				})
			}
		},
	})
}
