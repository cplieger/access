package account

import (
	"context"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
)

// SetPassword sets p's own password, for a full session within RecentAuth;
// a linked user under Rules.SSOGoverned is ErrSSOGoverned. A user holding a
// password must give it as current (zero: ErrCurrentPasswordRequired before
// any limiter call), counted like StepUpPassword's attempt. A user holding
// none has current ignored and commits only while still holding none. One
// Update writes the hash, rotates p's session into Issued (with the device
// cookie after a verified current), revokes the other sessions and, under
// Rules.RevokeKeysOnCredentialChange, the user's keys and their tokens.
func (s *Service) SetPassword(ctx context.Context, c Client, p access.Principal, current, password access.Secret) (Issued, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	r, err := s.beginRecentSession(p)
	if err != nil {
		return Issued{}, err
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return Issued{}, err
	}
	if r.SSOGoverned && !u.OIDC.IsZero() {
		return Issued{}, ErrSSOGoverned
	}
	held, err := holds(ctx, s.store, u, credential{method: access.MethodPassword})
	if err != nil {
		return Issued{}, storeErr(err)
	}
	if held && current.IsZero() {
		return Issued{}, ErrCurrentPasswordRequired
	}
	if err := s.checkPassword(ctx, r, u.Username, password); err != nil {
		return Issued{}, err
	}
	if !held {
		return s.firstPassword(ctx, r, c, p, password)
	}
	return s.changePassword(ctx, r, c, p, current, password)
}

func (s *Service) firstPassword(ctx context.Context, r Rules, c Client, p access.Principal, password access.Secret) (Issued, error) { //nolint:gocritic // hugeParam: the operation's one Rules value, Client and Principal
	hash, err := s.hasher.Hash(ctx, password.Reveal())
	if err != nil {
		return Issued{}, err
	}
	var ch credentialChange
	err = s.change(ctx, byClient(As(p), c), func(tx Tx, j *journal) error {
		u, found, readErr := tx.UserByID(ctx, p.User.ID)
		switch {
		case readErr != nil:
			return readErr
		case !found:
			return refuse(ErrSessionGone)
		case !u.PasswordHash.IsZero():
			return refuse(ErrCurrentPasswordRequired)
		}
		u.PasswordHash = hash
		if chErr := s.changeCredential(ctx, tx, r, p, u, &ch); chErr != nil {
			return chErr
		}
		s.addCredentialChange(j, EventPasswordSet, p, &ch)
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	return Issued{Token: ch.rot.token, Session: ch.rot.session}, nil
}

func (s *Service) changePassword(ctx context.Context, r Rules, c Client, p access.Principal, current, password access.Secret) (Issued, error) { //nolint:gocritic // hugeParam: the operation's one Rules value, Client and Principal
	a, err := s.ownAttempt(c, p)
	if err != nil {
		return Issued{}, err
	}
	next, err := s.hasher.Hash(ctx, password.Reveal())
	if err != nil {
		a.res.Cancel()
		return Issued{}, err
	}
	if verifyErr := s.verifyCounted(ctx, a, p.User.Username, current, false); verifyErr != nil {
		return Issued{}, verifyErr
	}
	var ch credentialChange
	err = s.change(ctx, byClient(As(p), c), func(tx Tx, j *journal) error {
		u, cleared, commitErr := commitVerified(ctx, tx, a)
		if commitErr != nil {
			return commitErr
		}
		u.PasswordHash = next
		if chErr := s.changeCredential(ctx, tx, r, p, u, &ch); chErr != nil {
			return chErr
		}
		s.addReenabled(j, cleared, p, a.ref.Trusted)
		s.addCredentialChange(j, EventPasswordChanged, p, &ch)
		return nil
	})
	if err != nil {
		a.res.Fail()
		return Issued{}, err
	}
	device := a.res.Succeed()
	return Issued{Token: ch.rot.token, DeviceCookie: device, Session: ch.rot.session}, nil
}

// RemovePassword removes p's own password, for a full session within
// RecentAuth. current is that password: zero is ErrCurrentPasswordRequired
// before any limiter call. A user holding no password is ErrNotFound, and
// the last-method guard (ErrLastMethod) runs next, both before the count,
// so neither refusal charges or counts anything. current is then counted
// as SetPassword's. The removal commits only while the guard passes and the
// verified hash is still stored, resets the password's failure records, and
// rotates p's session into Issued with the device cookie.
func (s *Service) RemovePassword(ctx context.Context, c Client, p access.Principal, current access.Secret) (Issued, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	r, err := s.beginRecentSession(p)
	if err != nil {
		return Issued{}, err
	}
	if current.IsZero() {
		return Issued{}, ErrCurrentPasswordRequired
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return Issued{}, err
	}
	gone := credential{method: access.MethodPassword}
	if heldErr := answer(requireHeld(ctx, s.store, u, gone)); heldErr != nil {
		return Issued{}, heldErr
	}
	if guardErr := answer(s.guardLastMethod(ctx, s.store, r, u, gone)); guardErr != nil {
		return Issued{}, guardErr
	}
	a, err := s.ownAttempt(c, p)
	if err != nil {
		return Issued{}, err
	}
	if verifyErr := s.verifyCounted(ctx, a, p.User.Username, current, false); verifyErr != nil {
		return Issued{}, verifyErr
	}
	var rot rotated
	err = s.change(ctx, byClient(As(p), c), func(tx Tx, j *journal) error {
		var removeErr error
		rot, removeErr = s.removePasswordIn(ctx, tx, j, r, a, p)
		return removeErr
	})
	if err != nil {
		a.res.Fail()
		return Issued{}, err
	}
	device := a.res.Succeed()
	return Issued{Token: rot.token, DeviceCookie: device, Session: rot.session}, nil
}

// removePasswordIn is RemovePassword's change: the verified hash still
// stored and the last-method guard re-run in tx, then the removal, the
// rotation and the entries.
func (s *Service) removePasswordIn(ctx context.Context, tx Tx, j *journal, r Rules, a *passwordAttempt, p access.Principal) (rotated, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and its Principal
	stored, cleared, err := commitVerified(ctx, tx, a)
	if err != nil {
		return rotated{}, err
	}
	if guardErr := s.guardLastMethod(ctx, tx, r, stored, credential{method: access.MethodPassword}); guardErr != nil {
		return rotated{}, guardErr
	}
	stored.PasswordHash, stored.UpdatedAt = access.Hash{}, s.now()
	if writeErr := tx.UpdateUser(ctx, stored); writeErr != nil {
		return rotated{}, writeErr
	}
	rot, err := s.rotate(ctx, tx, p, stored.ID, "")
	if err != nil {
		return rotated{}, err
	}
	s.addReenabled(j, cleared, p, a.ref.Trusted)
	j.add(Event{Kind: EventPasswordRemoved, At: s.now(), UserID: p.User.ID, Method: access.MethodPassword, Actor: eventActor(As(p))})
	return rot, nil
}

// beginRecentSession is the head of a change to p's own credential: the
// operation's Rules, then a full session within Rules().RecentAuth.
func (s *Service) beginRecentSession(p access.Principal) (Rules, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.begin()
	if err != nil {
		return Rules{}, err
	}
	if sessErr := requireSession(p); sessErr != nil {
		return Rules{}, sessErr
	}
	return r, s.recentAuth(r, p)
}

// ownUser reads p's user as stored; one deleted since p was verified is
// ErrSessionGone.
func (s *Service) ownUser(ctx context.Context, p access.Principal) (*access.User, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	u, found, err := s.store.UserByID(ctx, p.User.ID)
	switch {
	case err != nil:
		return nil, storeErr(err)
	case !found:
		return nil, ErrSessionGone
	}
	return u, nil
}

// ownAttempt admits a check of p's own current password to the limiter, on
// the account and device dimensions only: the caller already holds a full
// session for that account. The attempt replaces or removes the hash, so it
// skips the rehash.
func (s *Service) ownAttempt(c Client, p access.Principal) (*passwordAttempt, error) { //nolint:gocritic // hugeParam: the request's Client and Principal
	canonical := p.User.Username
	res, err := s.limiter.Attempt(ratelimit.Attempt{OmitIP: true, Account: ratelimit.AccountKey(canonical), Device: c.Device})
	if err != nil {
		return nil, err
	}
	a := s.newAttempt(res, canonical)
	a.replaces = true
	return a, nil
}

// credentialChange is what a password set or change wrote besides the hash.
type credentialChange struct {
	sessions []string // the other sessions revoked
	keys     []int64  // the keys deleted under RevokeKeysOnCredentialChange
	rot      rotated
}

// changeCredential writes u's new credential inside tx, then rotates p's
// session, revokes every other session of the user and, under
// Rules.RevokeKeysOnCredentialChange, deletes the user's keys and their
// tokens, all in the caller's Update.
func (s *Service) changeCredential(ctx context.Context, tx Tx, r Rules, p access.Principal, u *access.User, ch *credentialChange) error { //nolint:gocritic // hugeParam: the operation's one Rules value and its Principal
	*ch = credentialChange{}
	u.UpdatedAt = s.now()
	if err := tx.UpdateUser(ctx, u); err != nil {
		return err
	}
	var err error
	if ch.rot, err = s.rotate(ctx, tx, p, u.ID, ""); err != nil {
		return err
	}
	if ch.sessions, err = tx.DeleteUserSessions(ctx, u.ID, ch.rot.session.ID); err != nil {
		return err
	}
	if r.RevokeKeysOnCredentialChange {
		ch.keys, err = deleteUserKeys(ctx, tx, u.ID)
	}
	return err
}

// addCredentialChange adds a credential change's entries: kind, the
// revoked sessions, then one EventKeyRevoked per deleted key.
func (s *Service) addCredentialChange(j *journal, kind EventKind, p access.Principal, ch *credentialChange) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	actor, userID := eventActor(As(p)), p.User.ID
	j.add(Event{Kind: kind, At: s.now(), UserID: userID, Method: access.MethodPassword, Actor: actor})
	s.addRevoked(j, userID, ch.sessions, actor)
	s.addKeysRevoked(j, userID, ch.keys, actor)
}

// addReenabled adds the EventMethodReenabled of a reported lock a verified
// password's reset cleared.
func (s *Service) addReenabled(j *journal, reenabled bool, p access.Principal, trusted bool) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if reenabled {
		j.add(Event{Kind: EventMethodReenabled, At: s.now(), UserID: p.User.ID, Method: access.MethodPassword, Trusted: trusted, Actor: eventActor(As(p))})
	}
}
