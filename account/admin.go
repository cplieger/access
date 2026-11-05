package account

import (
	"cmp"
	"context"
	"slices"

	"github.com/cplieger/access"
)

// UserChange is an admin's change to a user; a nil field is left as it
// is, and at least one must be set (ErrNoChange).
type UserChange struct {
	Role    *access.Role // empty is access.RoleUser
	Enabled *bool
}

// UserFilter narrows Users; the zero value lists every user.
type UserFilter struct {
	// AttributedToKey, when non-zero, keeps only the users with a
	// KeyAttribution whose KeyLineage contains it, for a live, expired,
	// revoked or deleted key alike.
	AttributedToKey int64
}

// userAdmin is who performs a user-management write, as its Update decided
// it: the Actor the Policy sees and, for a key principal, the key as
// currentKeyActor re-read it.
type userAdmin struct {
	key   *access.Key
	actor Actor
}

// admitUserAdmin is the head of every user-management write, before any
// store call: RequireKeyPermission under ManageUsersScope for a principal,
// which refuses a bypass principal. An out-of-band actor passes; the zero
// Actor is ErrSessionRequired.
func (s *Service) admitUserAdmin(r Rules, a Actor) error { //nolint:gocritic // hugeParam: the operation's one Rules value and its Actor
	if a.isOutOfBand() {
		return nil
	}
	_, err := s.admitPermission(r, a, s.usersScope)
	return err
}

// userAdminIn decides a's authority first inside the write's Update: a key
// principal's from its stored key and owner under ManageUsersScope
// (key_not_current), any other actor as it is.
func (s *Service) userAdminIn(ctx context.Context, tx Tx, op Operation, a Actor) (userAdmin, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	p, ok := a.Principal()
	if !ok || !p.IsAPIKey() {
		return userAdmin{actor: a}, nil
	}
	actor, key, err := s.currentKeyActor(ctx, tx, op, access.KeyRef{ID: p.KeyID, UserID: p.User.ID}, s.usersScope)
	if err != nil {
		return userAdmin{}, err
	}
	return userAdmin{actor: actor, key: key}, nil
}

// target is the admin-target rule, run after the Policy call so a refusal
// still answers before existence: a key actor sets and acts on RoleUser
// only. Any other actor passes.
func (ua *userAdmin) target(op Operation, roles ...access.Role) error {
	if ua.key == nil {
		return nil
	}
	return requireUserTarget(op, roles...)
}

// issue marks a token a key actor mints: IssuedByKey, and an expiry no
// later than the key's.
func (ua *userAdmin) issue(tok *access.OneTimeToken) {
	if ua.key == nil {
		return
	}
	tok.IssuedByKey = ua.key.ID
	if exp := ua.key.ExpiresAt; !exp.IsZero() && exp.Before(tok.ExpiresAt) {
		tok.ExpiresAt = exp
	}
}

// Users lists every user by ID with its passkey count, for a principal
// RequireAdminScope admits and Policy allows OpListUsers. With
// f.AttributedToKey set it keeps the users holding a KeyAttribution whose
// KeyLineage contains that key, whether the key is live or gone. Each row
// carries the KeyLineage of the user's most recent record the filter
// matched. It writes nothing.
func (s *Service) Users(ctx context.Context, p access.Principal, f UserFilter) ([]ListedUser, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if err := s.admitAdminScope(p); err != nil {
		return nil, err
	}
	if err := s.policy.Authorize(ctx, Decision{Op: OpListUsers, Actor: As(p)}); err != nil {
		return nil, err
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	records, err := s.store.ListKeyAttributions(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	// records ascend by ID, so the last one kept per user is its most
	// recent.
	lineage := make(map[int64][]int64)
	for i := range records {
		if f.AttributedToKey == 0 || slices.Contains(records[i].KeyLineage, f.AttributedToKey) {
			lineage[records[i].UserID] = records[i].KeyLineage
		}
	}
	slices.SortFunc(users, func(a, b access.User) int { return cmp.Compare(a.ID, b.ID) })
	listed := make([]ListedUser, 0, len(users))
	for i := range users {
		path, attributed := lineage[users[i].ID]
		if f.AttributedToKey != 0 && !attributed {
			continue
		}
		passkeys, err := s.store.PasskeysByUserID(ctx, users[i].ID)
		if err != nil {
			return nil, storeErr(err)
		}
		listed = append(listed, ListedUser{User: users[i], KeyLineage: slices.Clone(path), PasskeyCount: len(passkeys)})
	}
	return listed, nil
}

// UpdateUser changes a user's role, enabled state or both (neither is
// ErrNoChange; the Policy decides self-changes), for an admin principal or
// a ManageUsersScope key. One Update asks OpSetRole, then OpSetEnabled on
// the user set with the role applied, for every set field even when
// unchanged, so a refusal answers before existence (ErrNotFound after). A
// key sets and acts on RoleUser only (admin_target). A role change revokes
// the sessions; a disable revokes every session, key and token those keys
// issued, and re-enabling restores none. It returns the user as committed.
func (s *Service) UpdateUser(ctx context.Context, p access.Principal, userID int64, ch UserChange) (*access.User, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.begin()
	if err != nil {
		return nil, err
	}
	op := OpSetEnabled
	if ch.Role != nil {
		op = OpSetRole
	}
	if admitErr := s.admitUserAdmin(r, As(p)); admitErr != nil {
		return nil, admitErr
	}
	if ch.Role == nil && ch.Enabled == nil {
		return nil, ErrNoChange
	}
	var res userUpdate
	err = s.update(ctx, func(tx Tx) error {
		res = userUpdate{}
		return s.updateUser(ctx, tx, op, As(p), userID, ch, &res)
	})
	if err != nil {
		return nil, err
	}
	s.emitUserUpdate(userID, eventActor(As(p)), &res)
	return res.user, nil
}

// userUpdate is what one UpdateUser's Update committed.
type userUpdate struct {
	user                      *access.User
	sessions                  []string
	keys                      []int64
	roleChanged, enabledMoved bool
}

func (s *Service) updateUser(ctx context.Context, tx Tx, op Operation, a Actor, userID int64, ch UserChange, res *userUpdate) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	ua, err := s.userAdminIn(ctx, tx, op, a)
	if err != nil {
		return err
	}
	target, found, users, err := targetIn(ctx, tx, userID)
	if err != nil {
		return err
	}
	if polErr := s.authorizeChange(ctx, ua.actor, target, users, userID, ch); polErr != nil {
		return refuse(polErr)
	}
	var roles []access.Role
	if ch.Role != nil {
		roles = append(roles, cmp.Or(*ch.Role, access.RoleUser))
	}
	if found {
		roles = append(roles, target.Role)
	}
	if ruleErr := ua.target(op, roles...); ruleErr != nil {
		return ruleErr
	}
	if !found {
		return refuse(ErrNotFound)
	}
	return s.applyUserChange(ctx, tx, &ua, target, ch, res)
}

// authorizeChange asks OpSetRole for a set role, then OpSetEnabled for a
// set enabled state on users with that role applied.
func (s *Service) authorizeChange(ctx context.Context, actor Actor, target *access.User, users []access.User, userID int64, ch UserChange) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	if ch.Role != nil {
		role := cmp.Or(*ch.Role, access.RoleUser)
		if err := s.policy.Authorize(ctx, Decision{Op: OpSetRole, Actor: actor, Target: target, Role: role, Users: users}); err != nil {
			return err
		}
		for i := range users {
			if users[i].ID == userID {
				users[i].Role = role
			}
		}
	}
	if ch.Enabled == nil {
		return nil
	}
	return s.policy.Authorize(ctx, Decision{Op: OpSetEnabled, Actor: actor, Target: target, Enabled: *ch.Enabled, Users: users})
}

// applyUserChange writes the fields that differ from target's stored
// values, with their revocations and a key's attribution, inside tx.
func (s *Service) applyUserChange(ctx context.Context, tx Tx, ua *userAdmin, target *access.User, ch UserChange, res *userUpdate) error {
	res.roleChanged = ch.Role != nil && cmp.Or(*ch.Role, access.RoleUser) != target.Role
	res.enabledMoved = ch.Enabled != nil && *ch.Enabled != target.Enabled
	res.user = target.Clone()
	if !res.roleChanged && !res.enabledMoved {
		return nil
	}
	if res.roleChanged {
		target.Role = cmp.Or(*ch.Role, access.RoleUser)
	}
	if res.enabledMoved {
		target.Enabled = *ch.Enabled
	}
	target.UpdatedAt = s.now()
	if err := tx.UpdateUser(ctx, target); err != nil {
		return err
	}
	res.user = target.Clone()
	disabled := res.enabledMoved && !target.Enabled
	if err := revokeForChange(ctx, tx, target.ID, disabled, res); err != nil {
		return err
	}
	if !res.enabledMoved || ua.key == nil {
		return nil
	}
	action := access.AttributionEnabled
	if disabled {
		action = access.AttributionDisabled
	}
	return s.attribute(ctx, tx, target.ID, action, ua.key)
}

// revokeForChange deletes userID's sessions after a role change or a
// disable, and on a disable every key and the tokens those keys issued.
func revokeForChange(ctx context.Context, tx Tx, userID int64, disabled bool, res *userUpdate) error {
	var err error
	if res.roleChanged || disabled {
		if res.sessions, err = tx.DeleteUserSessions(ctx, userID, ""); err != nil {
			return err
		}
		slices.Sort(res.sessions)
	}
	if disabled {
		res.keys, err = deleteUserKeys(ctx, tx, userID)
	}
	return err
}

// emitUserUpdate reports a committed UpdateUser: the role change, then the
// disable with its sessions and one EventKeyRevoked per key, or the
// re-enable. A role change alone carries the sessions it revoked.
func (s *Service) emitUserUpdate(userID int64, actor EventActor, res *userUpdate) {
	at := s.now()
	disabled := res.enabledMoved && !res.user.Enabled
	if res.roleChanged {
		ev := Event{Kind: EventRoleChanged, At: at, UserID: userID, Actor: actor}
		if !disabled {
			ev.SessionIDs = res.sessions
		}
		s.emit(ev)
	}
	switch {
	case disabled:
		s.emit(Event{Kind: EventUserDisabled, At: at, UserID: userID, SessionIDs: res.sessions, Actor: actor})
		s.emitKeysRevoked(userID, res.keys, actor)
	case res.enabledMoved:
		s.emit(Event{Kind: EventUserEnabled, At: at, UserID: userID, Actor: actor})
	}
}

// DeleteUser deletes a user (the Policy decides self-deletion) with every
// session, passkey, key, attribution record and token of theirs, and every
// token their keys issued, in one Update, for an admin principal or a
// ManageUsersScope key. The Policy (OpDeleteUser) answers before existence:
// a refusal is ErrPolicyRefused whether or not userID exists, and an
// allowed call on a missing user is ErrNotFound. A key deletes RoleUser
// targets only (admin_target). EventUserDeleted names the deleted
// sessions; one EventKeyRevoked per key follows.
func (s *Service) DeleteUser(ctx context.Context, p access.Principal, userID int64) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.begin()
	if err != nil {
		return err
	}
	if admitErr := s.admitUserAdmin(r, As(p)); admitErr != nil {
		return admitErr
	}
	var (
		sessions []string
		keys     []int64
	)
	err = s.update(ctx, func(tx Tx) error {
		sessions, keys = nil, nil
		ua, uaErr := s.userAdminIn(ctx, tx, OpDeleteUser, As(p))
		if uaErr != nil {
			return uaErr
		}
		target, found, users, readErr := targetIn(ctx, tx, userID)
		if readErr != nil {
			return readErr
		}
		if polErr := s.policy.Authorize(ctx, Decision{Op: OpDeleteUser, Actor: ua.actor, Target: target, Users: users}); polErr != nil {
			return refuse(polErr)
		}
		if !found {
			return refuse(ErrNotFound)
		}
		if ruleErr := ua.target(OpDeleteUser, target.Role); ruleErr != nil {
			return ruleErr
		}
		var cascadeErr error
		sessions, keys, cascadeErr = deleteUserCascade(ctx, tx, userID)
		return cascadeErr
	})
	if err != nil {
		return err
	}
	actor := eventActor(As(p))
	s.emit(Event{Kind: EventUserDeleted, At: s.now(), UserID: userID, SessionIDs: sessions, Actor: actor})
	s.emitKeysRevoked(userID, keys, actor)
	return nil
}

// deleteUserCascade reads userID's session and key IDs for the events,
// deletes the tokens those keys issued, then the user with the store's
// cascade, inside tx.
func deleteUserCascade(ctx context.Context, tx Tx, userID int64) (sessions []string, keys []int64, err error) {
	ss, err := tx.SessionsByUserID(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	for i := range ss {
		sessions = append(sessions, ss[i].ID)
	}
	slices.Sort(sessions)
	ks, err := tx.ListAPIKeysByUserID(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	keys = keyIDsOf(ks)
	if err := deleteIssuedTokens(ctx, tx, keys); err != nil {
		return nil, nil, err
	}
	return sessions, keys, tx.DeleteUser(ctx, userID)
}

// targetIn reads a target user and the user set inside tx; a missing target
// is a nil user and found false, for the Policy's nil Target.
func targetIn(ctx context.Context, tx Tx, userID int64) (target *access.User, found bool, users []access.User, err error) {
	target, found, err = tx.UserByID(ctx, userID)
	if err != nil {
		return nil, false, nil, err
	}
	if !found {
		target = nil
	}
	users, err = tx.ListUsers(ctx)
	if err != nil {
		return nil, false, nil, err
	}
	return target, found, users, nil
}

// keyIDsOf is the IDs of keys, ascending.
func keyIDsOf(keys []access.Key) []int64 {
	ids := make([]int64, 0, len(keys))
	for i := range keys {
		ids = append(ids, keys[i].ID)
	}
	slices.Sort(ids)
	return ids
}
