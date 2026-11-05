package account

import (
	"context"

	"github.com/cplieger/access"
)

// maxDisplayRunes bounds a display name, a key label and a passkey name.
const maxDisplayRunes = 128

// UpdateProfile sets p's own display name: at most 128 runes on one line
// (*TextError), the empty name clearing it. p must be a full session
// (ErrSessionRequired); a user deleted since p was verified is
// ErrSessionGone. It returns p's Me view as committed, read inside the same
// Update, so a failed read rolls the name back.
func (s *Service) UpdateProfile(ctx context.Context, p access.Principal, displayName string) (Me, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, beginErr := s.begin()
	if beginErr != nil {
		return Me{}, beginErr
	}
	if err := requireSession(p); err != nil {
		return Me{}, err
	}
	if err := checkLine(TextFieldDisplayName, displayName, maxDisplayRunes); err != nil {
		return Me{}, err
	}
	var me Me
	err := s.update(ctx, func(tx Tx) error {
		u, found, err := tx.UserByID(ctx, p.User.ID)
		switch {
		case err != nil:
			return err
		case !found:
			return refuse(ErrSessionGone)
		}
		u.DisplayName, u.UpdatedAt = displayName, s.now()
		if updErr := tx.UpdateUser(ctx, u); updErr != nil {
			return updErr
		}
		me, err = s.meIn(ctx, tx, r, u.Clone(), p)
		return err
	})
	if err != nil {
		return Me{}, err
	}
	return me, nil
}
