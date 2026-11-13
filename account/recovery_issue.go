package account

import (
	"context"
	"time"

	"github.com/cplieger/access"
)

const (
	defaultOutOfBandRecoveryTTL = 15 * time.Minute
	defaultAdminRecoveryTTL     = 24 * time.Hour
)

// IssueRecovery mints a recovery token for userID and voids the user's
// earlier ones, for an out-of-band actor (ttl 0: 15 min) or an admin
// principal or ManageUsersScope key (ttl 0: 24 h); above 7 × that default is
// ErrTTLTooLong. A principal naming its own ID is self_recovery before any
// Policy call or store read. Policy (OpIssueRecovery) answers before
// existence (ErrNotFound after). A key is re-read inside the Update
// (key_not_current), issues for a RoleUser only (admin_target), and its
// token records IssuedByKey and expires no later than the key.
func (s *Service) IssueRecovery(ctx context.Context, a Actor, userID int64, ttl time.Duration) (IssuedToken, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.begin()
	if err != nil {
		return IssuedToken{}, err
	}
	if admitErr := s.admitUserAdmin(r, a); admitErr != nil {
		return IssuedToken{}, admitErr
	}
	def := defaultOutOfBandRecoveryTTL
	if p, ok := a.Principal(); ok {
		if p.User.ID == userID {
			return IssuedToken{}, &PolicyError{Op: OpIssueRecovery, Reason: ReasonSelfRecovery}
		}
		def = defaultAdminRecoveryTTL
	}
	if ttl, err = tokenTTL(ttl, def); err != nil {
		return IssuedToken{}, err
	}
	plaintext, base := access.NewOneTimeToken(access.PurposeRecovery, userID, ttl, s.now())
	var rec access.OneTimeToken
	err = s.change(ctx, by(a), func(tx Tx, j *journal) error {
		rec = base
		if issueErr := s.issueRecoveryIn(ctx, tx, j, a, &rec); issueErr != nil {
			return issueErr
		}
		j.add(Event{Kind: EventRecoveryIssued, At: rec.CreatedAt, UserID: userID, Actor: eventActor(a)})
		return nil
	})
	if err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{Plaintext: plaintext, ExpiresAt: rec.ExpiresAt}, nil
}

// issueRecoveryIn is IssueRecovery's Update: a's authority, the subject read
// in tx for the Policy, then existence and the admin-target rule, the
// earlier tokens voided and rec stored with a key's mark.
func (s *Service) issueRecoveryIn(ctx context.Context, tx Tx, j *journal, a Actor, rec *access.OneTimeToken) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	ua, err := s.userAdminIn(ctx, tx, j, OpIssueRecovery, a)
	if err != nil {
		return err
	}
	target, found, err := tx.UserByID(ctx, rec.Subject)
	if err != nil {
		return err
	}
	if !found {
		target = nil
	}
	if polErr := s.policy.Authorize(ctx, Decision{Op: OpIssueRecovery, Actor: ua.actor, Target: target}); polErr != nil {
		return refuse(polErr)
	}
	if !found {
		return refuse(ErrNotFound)
	}
	if ruleErr := ua.target(OpIssueRecovery, target.Role); ruleErr != nil {
		return ruleErr
	}
	if _, err := tx.DeleteOneTimeTokens(ctx, access.PurposeRecovery, rec.Subject); err != nil {
		return err
	}
	ua.issue(rec)
	return tx.CreateOneTimeToken(ctx, *rec)
}
