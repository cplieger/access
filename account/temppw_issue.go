package account

import (
	"context"
	"slices"
	"time"

	"github.com/cplieger/access"
)

// defaultTemporaryPasswordTTL is a temporary password's lifetime when
// TemporaryPasswordOptions.TTL is zero; tokenTTL caps a set one at seven
// times it.
const defaultTemporaryPasswordTTL = 24 * time.Hour

// TemporaryPasswordOptions are an issue's choices.
type TemporaryPasswordOptions struct {
	// TTL is the password's lifetime: 0 is 24 hours, a negative one
	// ErrTTLNegative and one above 7 days ErrTTLTooLong. A key's expiry caps
	// it.
	TTL time.Duration
	// RevokePasskeys deletes the user's passkeys, for a lost device that
	// held them.
	RevokePasskeys bool
	// KeepKeys keeps the user's API keys and the tokens they issued, which
	// the issue otherwise deletes.
	KeepKeys bool
}

// IssuedTemporaryPassword is what an issue decided, to show its holder's
// admin once.
type IssuedTemporaryPassword struct {
	ExpiresAt time.Time
	// Password is the secret in its displayed form, XXXX-XXXX-XXXX-XXXX.
	Password access.Secret
	// HTTPSOrigin is Rules.HTTPSOrigin as the issue read it.
	HTTPSOrigin string
	// mode is the stored SSO mode the issue decided under, which
	// TemporaryPasswordHTTPSOnly reads.
	mode SSOMode
	// Dormant is the record's Dormant: the stored mode keeps the user's
	// local methods dormant, so the issue kept them and the secret's one
	// use is the admin link.
	Dormant bool
	// PasswordKept is a Dormant issue that kept a password the user holds.
	PasswordKept bool
}

// SetTemporaryPassword issues userID a temporary password, returned to show
// once, for an admin principal, a ManageUsersScope key on a RoleUser
// (admin_target) or an out-of-band actor, under OpSetTemporaryPassword and
// the owner protections, on a secure request; a principal's own user is
// ReasonSelfRecovery and a linked dormant user ErrSSOLinked. Its one Update
// replaces any record, clears the password, TOTP and recovery code (keeps
// them, marking the record Dormant, for a dormant user), deletes passkeys
// under RevokePasskeys and keys unless KeepKeys, and ends sessions and locks.
func (s *Service) SetTemporaryPassword(ctx context.Context, a Actor, userID int64, in TemporaryPasswordOptions) (IssuedTemporaryPassword, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, iss, err := s.prepareIssue(ctx, a, userID, in)
	if err != nil {
		return IssuedTemporaryPassword{}, err
	}
	err = s.change(ctx, by(a), func(tx Tx, j *journal) error { return s.issueTemporaryIn(ctx, tx, j, a, userID, iss) })
	if err != nil {
		return IssuedTemporaryPassword{}, err
	}
	return s.issuedTo(&r, userID, iss), nil
}

// prepareIssue is an issue's checks before its Update, in order: the
// transport, the actor's admission, ReasonSelfRecovery and the lifetime;
// then the secret, drawn and hashed.
func (s *Service) prepareIssue(ctx context.Context, a Actor, userID int64, in TemporaryPasswordOptions) (Rules, *tempIssue, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.begin()
	if err != nil {
		return Rules{}, nil, err
	}
	p, isPrincipal := a.Principal()
	if isPrincipal && !p.Secure {
		return Rules{}, nil, access.ErrHTTPSRequired
	}
	if admitErr := s.admitUserAdmin(r, a); admitErr != nil {
		return Rules{}, nil, admitErr
	}
	if isPrincipal && p.User != nil && p.User.ID == userID {
		return Rules{}, nil, &PolicyError{Op: OpSetTemporaryPassword, Reason: ReasonSelfRecovery}
	}
	ttl, err := tokenTTL(in.TTL, defaultTemporaryPasswordTTL)
	if err != nil {
		return Rules{}, nil, err
	}
	shown, canonical := newTemporaryPassword()
	hash, err := s.hasher.Hash(ctx, canonical)
	if err != nil {
		return Rules{}, nil, err
	}
	return r, &tempIssue{opts: in, ttl: ttl, shown: shown, hash: hash}, nil
}

// issuedTo is a committed issue's answer for userID, whose pending
// sign-ins it drops.
func (s *Service) issuedTo(r *Rules, userID int64, iss *tempIssue) IssuedTemporaryPassword {
	s.pending.dropUser(userID)
	iss.out.Password, iss.out.HTTPSOrigin = iss.shown, r.HTTPSOrigin
	return iss.out
}

// tempIssue is one SetTemporaryPassword: its options, the secret drawn and
// hashed before the Update, and what the committed Update decided.
type tempIssue struct {
	hash  access.Hash
	shown access.Secret
	out   IssuedTemporaryPassword
	opts  TemporaryPasswordOptions
	ttl   time.Duration
}

// issueTemporaryIn is SetTemporaryPassword's change: issueTargetIn, the
// mode's refusal of a linked dormant user, then issueWriteIn.
func (s *Service) issueTemporaryIn(ctx context.Context, tx Tx, j *journal, a Actor, userID int64, iss *tempIssue) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	ua, target, err := s.issueTargetIn(ctx, tx, j, a, userID)
	if err != nil {
		return err
	}
	mode, err := storedMode(ctx, tx)
	if err != nil {
		return err
	}
	if mode.dormantFor(target) && !target.OIDC.IsZero() {
		return refuse(ErrSSOLinked)
	}
	return s.issueWriteIn(ctx, tx, j, a, &ua, target, iss, mode)
}

// issueTargetIn is an issue's authority inside tx, before any write: the
// actor's, the Policy and owner protections, existence and admin_target.
// It returns the actor's authority and the target.
func (s *Service) issueTargetIn(ctx context.Context, tx Tx, j *journal, a Actor, userID int64) (userAdmin, *access.User, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	ua, err := s.userAdminIn(ctx, tx, j, OpSetTemporaryPassword, a)
	if err != nil {
		return userAdmin{}, nil, err
	}
	target, found, users, err := targetIn(ctx, tx, userID)
	if err != nil {
		return userAdmin{}, nil, err
	}
	if polErr := s.authorizeOwned(ctx, &Decision{Op: OpSetTemporaryPassword, Actor: ua.actor, Target: target, Users: users}); polErr != nil {
		return userAdmin{}, nil, refuse(polErr)
	}
	if !found {
		return userAdmin{}, nil, refuse(ErrNotFound)
	}
	if ruleErr := ua.target(OpSetTemporaryPassword, target.Role); ruleErr != nil {
		return userAdmin{}, nil, ruleErr
	}
	return ua, target, nil
}

// issueWriteIn is an issue's writes for target as tx holds it under the
// stored mode: the record and its arm's writes.
func (s *Service) issueWriteIn(ctx context.Context, tx Tx, j *journal, a Actor, ua *userAdmin, target *access.User, iss *tempIssue, mode SSOMode) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	dormant := mode.dormantFor(target)
	rec := s.temporaryRecord(ua, a, target.ID, iss, dormant)
	if err := tx.SetTemporaryPassword(ctx, rec); err != nil {
		return err
	}
	iss.out = IssuedTemporaryPassword{ExpiresAt: rec.ExpiresAt, mode: mode, Dormant: dormant, PasswordKept: dormant && !target.PasswordHash.IsZero()}
	actor := eventActor(a)
	j.add(Event{Kind: EventTemporaryPasswordSet, At: s.now(), UserID: target.ID, Actor: actor})
	if !dormant {
		if err := s.clearLocalIn(ctx, tx, target); err != nil {
			return err
		}
	}
	if err := s.revokeForIssueIn(ctx, tx, j, target, iss.opts, actor); err != nil {
		return err
	}
	if ua.key == nil {
		return nil
	}
	return s.attribute(ctx, tx, target.ID, access.AttributionTemporaryPasswordSet, ua.key)
}

// temporaryRecord is the record an issue stores: its issuer from the actor,
// and an expiry no later than an issuing key's.
func (s *Service) temporaryRecord(ua *userAdmin, a Actor, userID int64, iss *tempIssue, dormant bool) access.TemporaryPassword { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	now := s.stamp()
	rec := access.TemporaryPassword{UserID: userID, Hash: iss.hash, CreatedAt: now, ExpiresAt: now.Add(iss.ttl), Dormant: dormant}
	switch p, ok := a.Principal(); {
	case ua.key != nil:
		rec.IssuedByKey = ua.key.ID
		if exp := ua.key.ExpiresAt; !exp.IsZero() && exp.Before(rec.ExpiresAt) {
			rec.ExpiresAt = exp
		}
	case ok && p.User != nil:
		rec.IssuedByUser = p.User.ID
	}
	return rec
}

// clearLocalIn deletes u's password, TOTP and recovery code inside tx, so a
// password an attacker knew stops working.
func (s *Service) clearLocalIn(ctx context.Context, tx Tx, u *access.User) error {
	if !u.PasswordHash.IsZero() {
		u.PasswordHash, u.UpdatedAt = access.Hash{}, s.now()
		if err := tx.UpdateUser(ctx, u); err != nil {
			return err
		}
	}
	if err := tx.DeleteTOTP(ctx, u.ID); err != nil {
		return err
	}
	return tx.DeleteRecoveryCode(ctx, u.ID)
}

// revokeForIssueIn is an issue's revocations inside tx: the passkeys under
// RevokePasskeys, the keys and their tokens unless KeepKeys, then every
// session and lock, each journalled.
func (s *Service) revokeForIssueIn(ctx context.Context, tx Tx, j *journal, u *access.User, in TemporaryPasswordOptions, actor EventActor) error {
	if in.RevokePasskeys {
		ids, err := tx.DeleteUserPasskeys(ctx, u.ID)
		if err != nil {
			return err
		}
		slices.Sort(ids)
		for _, id := range ids {
			j.add(Event{Kind: EventPasskeyRemoved, At: s.now(), UserID: u.ID, PasskeyID: id, Actor: actor})
		}
	}
	if !in.KeepKeys {
		keys, err := deleteUserKeys(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		s.addKeysRevoked(j, u.ID, keys, actor)
	}
	sessions, err := tx.DeleteUserSessions(ctx, u.ID, "")
	if err != nil {
		return err
	}
	slices.Sort(sessions)
	s.addRevoked(j, u.ID, sessions, actor)
	return tx.DeleteAuthFailures(ctx, failureName(s.failureMAC(), u.Username), countedMethods)
}

// TemporaryPasswordHTTPSOnly reports whether issued works only over HTTPS
// now: under access.PosturePerRequest, while the current Rules hold
// RequireSecondFactor or DisablePasswordLogin, or when the issue decided
// under SSOOnly. It reads no store and cannot fail, so a route calls it
// after the issue commits.
func (s *Service) TemporaryPasswordHTTPSOnly(issued IssuedTemporaryPassword) bool {
	if s.authn.Cookie().Posture != access.PosturePerRequest {
		return false
	}
	r := s.rulesFn()
	return r.RequireSecondFactor || r.DisablePasswordLogin || issued.mode == SSOOnly
}
