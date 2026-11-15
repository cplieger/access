package account

import (
	"context"

	"github.com/cplieger/access"
)

// CheckSecondFactorReady is the check an app runs before it saves
// Rules.RequireSecondFactor on (design 4.8): it answers nil only for a full
// session p on a secure c whose user holds a usable TOTP or a usable
// passkey by the current Rules, and ErrEnableWithoutSecondFactor for any
// other p, a dormant factor counting for nothing. It writes nothing.
func (s *Service) CheckSecondFactorReady(ctx context.Context, c Client, p access.Principal) error { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	r, err := s.begin()
	if err != nil {
		return err
	}
	if requireSession(p) != nil || !c.Secure || !p.Secure {
		return ErrEnableWithoutSecondFactor
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return err
	}
	ready, err := s.usableFactorHeld(ctx, s.store, r, u)
	switch {
	case err != nil:
		return storeErr(err)
	case !ready:
		return ErrEnableWithoutSecondFactor
	}
	return nil
}

// usableFactorHeld reports whether u, read through tx under r, holds a
// second factor that signs in now, whatever Rules.RequireSecondFactor says:
// a usable TOTP or a usable passkey, neither while the stored mode keeps u
// dormant.
func (s *Service) usableFactorHeld(ctx context.Context, tx Tx, r Rules, u *access.User) (bool, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	mode, err := storedMode(ctx, tx)
	if err != nil || mode.dormantFor(u) {
		return false, err
	}
	if held, totpErr := s.usableTOTP(ctx, tx, r, u); totpErr != nil || held {
		return held, totpErr
	}
	n, err := usablePasskeys(ctx, tx, r, s.rpID(), u, credential{})
	return n > 0, err
}
