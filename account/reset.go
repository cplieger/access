package account

import (
	"context"
	"slices"

	"github.com/cplieger/access"
)

// ResetSecondFactor deletes userID's TOTP record and recovery code, with
// their failure records, sessions and pending sign-ins, for an admin
// principal, a ManageUsersScope key on a RoleUser (admin_target) or an
// out-of-band actor, under OpResetSecondFactor and the owner protections;
// the password, passkeys and keys stay. A principal's own user is
// ReasonSelfRecovery. A refusal answers before existence, and a missing
// user or one holding neither record is ErrNotFound, writing nothing.
func (s *Service) ResetSecondFactor(ctx context.Context, a Actor, userID int64) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.begin()
	if err != nil {
		return err
	}
	if admitErr := s.admitUserAdmin(r, a); admitErr != nil {
		return admitErr
	}
	if p, ok := a.Principal(); ok && p.User != nil && p.User.ID == userID {
		return &PolicyError{Op: OpResetSecondFactor, Reason: ReasonSelfRecovery}
	}
	err = s.change(ctx, by(a), func(tx Tx, j *journal) error { return s.resetIn(ctx, tx, j, a, userID) })
	if err == nil {
		s.pending.dropUser(userID)
	}
	return err
}

// resetIn is ResetSecondFactor's change: the actor's authority, the Policy
// and owner protections, existence and admin_target, then the deletions. A
// record kept dormant, by TOTP unwired or off or by the SSO mode, is
// deleted like a usable one.
func (s *Service) resetIn(ctx context.Context, tx Tx, j *journal, a Actor, userID int64) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	ua, err := s.userAdminIn(ctx, tx, j, OpResetSecondFactor, a)
	if err != nil {
		return err
	}
	target, found, users, err := targetIn(ctx, tx, userID)
	if err != nil {
		return err
	}
	if polErr := s.authorizeOwned(ctx, &Decision{Op: OpResetSecondFactor, Actor: ua.actor, Target: target, Users: users}); polErr != nil {
		return refuse(polErr)
	}
	if !found {
		return refuse(ErrNotFound)
	}
	if ruleErr := ua.target(OpResetSecondFactor, target.Role); ruleErr != nil {
		return ruleErr
	}
	held, err := secondFactorStoredIn(ctx, tx, userID)
	if err != nil {
		return err
	}
	if !held {
		return refuse(ErrNotFound)
	}
	if delErr := s.deleteSecondFactorIn(ctx, tx, target); delErr != nil {
		return delErr
	}
	sessions, err := tx.DeleteUserSessions(ctx, userID, "")
	if err != nil {
		return err
	}
	slices.Sort(sessions)
	actor := eventActor(a)
	j.add(Event{Kind: EventSecondFactorReset, At: s.now(), UserID: userID, Actor: actor})
	s.addRevoked(j, userID, sessions, actor)
	return nil
}

// deleteSecondFactorIn deletes u's TOTP record and recovery code with their
// failure records inside tx.
func (s *Service) deleteSecondFactorIn(ctx context.Context, tx Tx, u *access.User) error {
	if err := tx.DeleteTOTP(ctx, u.ID); err != nil {
		return err
	}
	if err := tx.DeleteRecoveryCode(ctx, u.ID); err != nil {
		return err
	}
	return tx.DeleteAuthFailures(ctx, failureName(s.failureMAC(), u.Username), []access.Method{access.MethodTOTP, access.MethodRecoveryCode})
}

// secondFactorStoredIn reports whether userID holds a TOTP record or a
// recovery code, whether or not either is usable now.
func secondFactorStoredIn(ctx context.Context, tx Tx, userID int64) (bool, error) {
	_, found, err := tx.TOTPByUserID(ctx, userID)
	if err != nil || found {
		return found, err
	}
	_, found, err = tx.RecoveryCodeByUserID(ctx, userID)
	return found, err
}
