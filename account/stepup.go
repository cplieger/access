package account

import (
	"context"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
)

// StepUpPassword re-proves p's user with password and rotates p's session
// to AuthTime now and AuthMethod MethodPassword, returning the device cookie
// in Issued. It needs a full session (ErrSessionRequired) and is refused
// under Rules.DisablePasswordLogin (ErrPasswordLoginDisabled). The attempt is
// limited on the account and device dimensions, never the client's IP, and
// counted like PasswordLogin's on the user's name, without an untrusted
// allowance slot. A wrong or locked password is ErrInvalidCredentials, and a
// session rotated or ended meanwhile ErrSessionGone.
func (s *Service) StepUpPassword(ctx context.Context, c Client, p access.Principal, password access.Secret) (Issued, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	r, err := s.begin()
	if err != nil {
		return Issued{}, err
	}
	if sessErr := requireSession(p); sessErr != nil {
		return Issued{}, sessErr
	}
	if r.DisablePasswordLogin {
		return Issued{}, ErrPasswordLoginDisabled
	}
	canonical := p.User.Username
	res, err := s.limiter.Attempt(ratelimit.Attempt{OmitIP: true, Account: ratelimit.AccountKey(canonical), Device: c.Device})
	if err != nil {
		return Issued{}, err
	}
	a := s.newAttempt(res, canonical)
	if verifyErr := s.verifyCounted(ctx, a, canonical, password, false); verifyErr != nil {
		return Issued{}, verifyErr
	}
	var (
		rot       rotated
		reenabled bool
	)
	err = s.update(ctx, func(tx Tx) error {
		u, cleared, commitErr := commitVerified(ctx, tx, a)
		if commitErr != nil {
			return commitErr
		}
		reenabled = cleared
		var rotErr error
		rot, rotErr = s.rotate(ctx, tx, p, u.ID, access.MethodPassword)
		return rotErr
	})
	if err != nil {
		a.res.Fail()
		return Issued{}, err
	}
	device := a.res.Succeed()
	actor := EventActor{SessionID: rot.session.ID, UserID: rot.session.UserID}
	at := rot.session.AuthTime
	if reenabled {
		s.emit(Event{Kind: EventMethodReenabled, At: at, UserID: actor.UserID, Method: access.MethodPassword, Trusted: a.ref.Trusted, Actor: actor})
	}
	s.emit(Event{Kind: EventSteppedUp, At: at, UserID: actor.UserID, Method: access.MethodPassword, SessionIDs: []string{rot.session.ID}, Actor: actor})
	return Issued{Token: rot.token, DeviceCookie: device, Session: rot.session}, nil
}
