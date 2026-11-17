package account

import (
	"context"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
)

// StepUpPassword re-proves p's user with password and rotates p's session to
// AuthTime now and AuthMethod MethodPassword, with the device cookie in Issued.
// Before the limiter: a plain c or p is access.ErrHTTPSRequired, any but a full
// session ErrSessionRequired, Rules.DisablePasswordLogin ErrPasswordLoginDisabled,
// a dormant user ErrSSOOnly and one holding a second factor ErrSecondFactorHeld.
// The attempt is limited on the account and device and counted like
// PasswordLogin's without an allowance slot. A wrong or locked password is
// ErrInvalidCredentials, a session rotated or ended meanwhile ErrSessionGone.
func (s *Service) StepUpPassword(ctx context.Context, c Client, p access.Principal, password access.Secret) (Issued, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	r, err := s.passwordStepUpAdmitted(ctx, c, p)
	if err != nil {
		return Issued{}, err
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
	var rot rotated
	err = s.change(ctx, byClient(As(p), c), func(tx Tx, j *journal) error {
		u, cleared, commitErr := commitVerified(ctx, tx, a)
		if commitErr != nil {
			return commitErr
		}
		if modeErr := requireLocal(ctx, tx, u, ErrSSOOnly); modeErr != nil {
			return modeErr
		}
		if heldErr := s.refuseHeld(ctx, tx, r, u); heldErr != nil {
			return heldErr
		}
		var rotErr error
		if rot, rotErr = s.rotate(ctx, tx, p, u.ID, access.MethodPassword); rotErr != nil {
			return rotErr
		}
		actor := EventActor{SessionID: rot.session.ID, UserID: rot.session.UserID}
		at := rot.session.AuthTime
		j.addReenabled(cleared, a.ref, at, actor)
		j.add(Event{Kind: EventSteppedUp, At: at, UserID: actor.UserID, Method: access.MethodPassword, SessionIDs: []string{rot.session.ID}, Actor: actor})
		return nil
	})
	if err != nil {
		a.res.Fail()
		return Issued{}, err
	}
	a.res.Succeed()
	device := s.deviceCookie(p.User.Username, c)
	return Issued{Token: rot.token, DeviceCookie: device, Session: rot.session}, nil
}

// passwordStepUpAdmitted is StepUpPassword's refusals before any limiter
// charge, in its godoc's order, and the operation's Rules.
func (s *Service) passwordStepUpAdmitted(ctx context.Context, c Client, p access.Principal) (Rules, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	r, err := s.beginOver(plainRefused, c.Secure && p.Secure)
	if err != nil {
		return Rules{}, err
	}
	if sessErr := requireSession(p); sessErr != nil {
		return Rules{}, sessErr
	}
	if r.DisablePasswordLogin {
		return Rules{}, ErrPasswordLoginDisabled
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return Rules{}, err
	}
	if modeErr := s.localAllowed(ctx, u); modeErr != nil {
		return Rules{}, modeErr
	}
	return r, answer(s.refuseHeld(ctx, s.store, r, u))
}

// refuseHeld is a refused ErrSecondFactorHeld, read through tx, for a user
// holding a second factor: a password alone never steps them up.
func (s *Service) refuseHeld(ctx context.Context, tx Tx, r Rules, u *access.User) error { //nolint:gocritic // hugeParam: the operation's one Rules value
	held, err := s.secondFactorHeld(ctx, tx, r, u)
	switch {
	case err != nil:
		return err
	case held:
		return refuse(ErrSecondFactorHeld)
	}
	return nil
}
