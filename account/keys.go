package account

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/cplieger/access"
)

// NewKey is the input of CreateAPIKey.
type NewKey struct {
	Label     string
	Scopes    []string
	ExpiresIn time.Duration // 0 = never; a negative value is ErrKeyExpiryInvalid
}

// minter is who mints a key: an out-of-band actor, a full session of the
// key's own user, or a built-in key principal of that user.
type minter struct {
	op    Operation
	actor Actor
	key   bool
}

// principal is a principal minter's principal, and the zero Principal for
// an out-of-band one.
func (m *minter) principal() access.Principal {
	p, _ := m.actor.Principal()
	return p
}

// CreateAPIKey mints a key for userID and returns its plaintext once, for
// OutOfBand (OpCreateKeyFor) or a principal of userID's own user that
// RequireKeyPermission admits under CreateKeysScope (OpCreateOwnKey; another
// user is other_user). Scopes come from Rules().Scopes (ErrUnknownScope), a
// permission scope only on a RoleAdmin owner (permission_not_admin); the
// label is one line of at most 128 runes and ExpiresIn not negative. A key
// actor's parent is re-read in the Update and bounds the child's scopes,
// expiry and depth. Only a session actor's session rotates into Issued.
func (s *Service) CreateAPIKey(ctx context.Context, a Actor, userID int64, in NewKey) (CreatedKey, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.begin()
	if err != nil {
		return CreatedKey{}, err
	}
	m, err := s.admitMinter(r, a, userID)
	if err != nil {
		return CreatedKey{}, err
	}
	if inputErr := checkKeyInput(r, in); inputErr != nil {
		return CreatedKey{}, inputErr
	}
	gen, err := access.GenerateAPIKey(r.KeyPrefix)
	if err != nil {
		return CreatedKey{}, err
	}
	now := s.now()
	draft := access.Key{
		UserID: userID, KeyHash: gen.Hash, KeyPrefix: gen.DisplayPrefix, KeySuffix: gen.DisplaySuffix,
		Label: in.Label, Scopes: slices.Clone(in.Scopes), CreatedAt: now,
	}
	if in.ExpiresIn > 0 {
		draft.ExpiresAt = now.Add(in.ExpiresIn)
	}
	var (
		key access.Key
		rot rotated
	)
	session := m.principal()
	err = s.change(ctx, by(a), func(tx Tx, j *journal) error {
		key, rot = *draft.Clone(), rotated{}
		owner, mintErr := s.authorizeMint(ctx, tx, j, m, &key)
		if mintErr != nil {
			return mintErr
		}
		if scopeErr := s.permissionScopes(m.op, owner, key.Scopes); scopeErr != nil {
			return scopeErr
		}
		if createErr := tx.CreateAPIKey(ctx, &key); createErr != nil {
			return createErr
		}
		j.add(Event{Kind: EventKeyMinted, At: now, UserID: userID, KeyID: key.ID, Actor: eventActor(a)})
		if !session.IsSession() {
			return nil
		}
		var rotErr error
		rot, rotErr = s.rotate(ctx, tx, session, userID, "")
		return rotErr
	})
	if err != nil {
		return CreatedKey{}, err
	}
	created := CreatedKey{Plaintext: gen.Plaintext, Key: key}
	if session.IsSession() {
		created.Issued = Issued{Token: rot.token, Session: rot.session}
	}
	return created, nil
}

// admitMinter is CreateAPIKey's actor check, before any store call:
// RequireKeyPermission's answer for a principal, which refuses a bypass
// principal, and the own-user rule.
func (s *Service) admitMinter(r Rules, a Actor, userID int64) (minter, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and its Actor
	if a.isOutOfBand() {
		return minter{actor: a, op: OpCreateKeyFor}, nil
	}
	p, err := s.admitPermission(r, a, s.keysScope)
	if err != nil {
		return minter{}, err
	}
	if p.User.ID != userID {
		return minter{}, &PolicyError{Op: OpCreateOwnKey, Reason: ReasonOtherUser}
	}
	return minter{actor: a, op: OpCreateOwnKey, key: p.IsAPIKey()}, nil
}

// checkKeyInput is the shared rule on a minted key's request: known scopes,
// a one-line label, a non-negative expiry.
func checkKeyInput(r Rules, in NewKey) error { //nolint:gocritic // hugeParam: the operation's one Rules value
	for _, scope := range in.Scopes {
		if !slices.Contains(r.Scopes, scope) {
			return ErrUnknownScope
		}
	}
	if err := checkLine(TextFieldLabel, in.Label, maxDisplayRunes); err != nil {
		return err
	}
	if in.ExpiresIn < 0 {
		return ErrKeyExpiryInvalid
	}
	return nil
}

// authorizeMint decides a mint inside its Update and returns the key's
// owner as tx read it. A key minter's parent is re-read first, and key
// takes its path; then the Policy, then the owner must be enabled.
func (s *Service) authorizeMint(ctx context.Context, tx Tx, j *journal, m minter, key *access.Key) (*access.User, error) { //nolint:gocritic // hugeParam: the minter admitMinter built
	actor := m.actor
	if m.key {
		var (
			parent *access.Key
			err    error
		)
		p := m.principal()
		actor, parent, err = s.currentKeyActor(ctx, tx, j, m.op, access.KeyRef{ID: p.KeyID, UserID: p.User.ID}, s.keysScope)
		if err != nil {
			return nil, err
		}
		if err := childOf(m.op, parent, key); err != nil {
			return nil, err
		}
		key.LineageIDs = slices.Clone(parent.LineageIDs)
	}
	owner, found, err := tx.UserByID(ctx, key.UserID)
	if err != nil {
		return nil, err
	}
	var target *access.User
	if found {
		target = owner
	}
	if polErr := s.policy.Authorize(ctx, Decision{Op: m.op, Actor: actor, Target: target}); polErr != nil {
		return nil, refuse(polErr)
	}
	switch {
	case !found && m.op == OpCreateKeyFor:
		return nil, refuse(ErrNotFound)
	case !found:
		return nil, refuse(ErrSessionGone)
	case !owner.Enabled:
		return nil, refuse(&PolicyError{Op: m.op, Reason: ReasonTargetNotEligible})
	}
	return owner, nil
}

// childOf is the rule on a key a key mints: no scope its parent lacks, no
// expiry later than an expiring parent's, and room below the parent's path.
func childOf(op Operation, parent, child *access.Key) error {
	for _, scope := range child.Scopes {
		if !slices.Contains(parent.Scopes, scope) {
			return refuse(&PolicyError{Op: op, Reason: ReasonScopesNotSubset})
		}
	}
	if !parent.ExpiresAt.IsZero() && (child.ExpiresAt.IsZero() || child.ExpiresAt.After(parent.ExpiresAt)) {
		return refuse(&PolicyError{Op: op, Reason: ReasonExpiryAfterParent})
	}
	if len(parent.LineageIDs) >= MaxKeyLineage {
		return refuse(&PolicyError{Op: op, Reason: ReasonLineageTooDeep})
	}
	return nil
}

// permissionScopes refuses a configured permission scope on a key whose
// owner is not RoleAdmin: the permissions are an admin's grant alone.
func (s *Service) permissionScopes(op Operation, owner *access.User, scopes []string) error {
	if owner.Role == access.RoleAdmin {
		return nil
	}
	for _, permission := range []string{s.adminScope, s.usersScope, s.keysScope} {
		if permission != "" && slices.Contains(scopes, permission) {
			return refuse(&PolicyError{Op: op, Reason: ReasonPermissionNotAdmin})
		}
	}
	return nil
}

// APIKeys returns p's own keys, expired ones included, by ID. p must be a
// full session (ErrSessionRequired).
func (s *Service) APIKeys(ctx context.Context, p access.Principal) ([]access.Key, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return nil, err
	}
	if err := requireSession(p); err != nil {
		return nil, err
	}
	keys, err := s.store.ListAPIKeysByUserID(ctx, p.User.ID)
	if err != nil {
		return nil, storeErr(err)
	}
	return byID(keys), nil
}

// RevokeAPIKey deletes one of p's own keys with its subtree, every key whose
// LineageIDs holds it, and every token those keys issued, in one Update;
// one EventKeyRevoked per key follows the commit. p must be a full session
// (ErrSessionRequired); a key of another user, or none, is ErrNotFound.
func (s *Service) RevokeAPIKey(ctx context.Context, p access.Principal, id int64) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return err
	}
	if err := requireSession(p); err != nil {
		return err
	}
	userID := p.User.ID
	return s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		revoked, err := revokeSubtree(ctx, tx, userID, id)
		if err != nil {
			return err
		}
		s.addKeysRevoked(j, userID, revoked, eventActor(As(p)))
		return nil
	})
}

// AllAPIKeys returns every user's keys by ID, each with its owner's
// username, for a principal RequireAdminScope admits and Policy allows
// OpManageAllKeys. The keys and the users are read in one transaction, so
// each Owner is the name the key's own snapshot holds; a key whose owner
// that snapshot lacks lists an empty Owner.
func (s *Service) AllAPIKeys(ctx context.Context, p access.Principal) ([]ListedKey, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if err := s.admitAdminScope(p); err != nil {
		return nil, err
	}
	if err := s.policy.Authorize(ctx, Decision{Op: OpManageAllKeys, Actor: As(p)}); err != nil {
		return nil, err
	}
	var listed []ListedKey
	err := s.update(ctx, func(tx Tx) error {
		keys, err := tx.ListAPIKeys(ctx)
		if err != nil {
			return err
		}
		users, err := tx.ListUsers(ctx)
		if err != nil {
			return err
		}
		owners := make(map[int64]string, len(users))
		for i := range users {
			owners[users[i].ID] = users[i].Username
		}
		keys = byID(keys)
		listed = make([]ListedKey, len(keys))
		for i := range keys {
			listed[i] = ListedKey{Key: keys[i], Owner: owners[keys[i].UserID]}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return listed, nil
}

// RevokeAnyAPIKey deletes any user's key with its subtree and their tokens,
// as RevokeAPIKey does, for a principal RequireAdminScope admits. A key
// principal's authority is re-read inside the Update with AdminScope
// (key_not_current), and that actor meets Policy (OpManageAllKeys) before
// the key is looked up, so a refusal says nothing of which keys exist; an
// unknown key is ErrNotFound.
func (s *Service) RevokeAnyAPIKey(ctx context.Context, p access.Principal, id int64) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if err := s.admitAdminScope(p); err != nil {
		return err
	}
	return s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		actor := As(p)
		if p.IsAPIKey() {
			var keyErr error
			if actor, _, keyErr = s.currentKeyActor(ctx, tx, j, OpManageAllKeys, access.KeyRef{ID: p.KeyID, UserID: p.User.ID}, s.adminScope); keyErr != nil {
				return keyErr
			}
		}
		if polErr := s.policy.Authorize(ctx, Decision{Op: OpManageAllKeys, Actor: actor}); polErr != nil {
			return refuse(polErr)
		}
		keys, err := tx.ListAPIKeys(ctx)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(keys, func(k access.Key) bool { return k.ID == id })
		if i < 0 {
			return refuse(ErrNotFound)
		}
		owner := keys[i].UserID
		revoked, err := revokeSubtree(ctx, tx, owner, id)
		if err != nil {
			return err
		}
		s.addKeysRevoked(j, owner, revoked, eventActor(As(p)))
		return nil
	})
}

// revokeSubtree deletes userID's key id and every key of that user whose
// LineageIDs holds it, then every token they issued, inside tx, and
// returns the deleted IDs ascending. No such key is a refused ErrNotFound.
func revokeSubtree(ctx context.Context, tx Tx, userID, id int64) ([]int64, error) {
	keys, err := tx.ListAPIKeysByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for i := range keys {
		if keys[i].ID == id || slices.Contains(keys[i].LineageIDs, id) {
			ids = append(ids, keys[i].ID)
		}
	}
	if !slices.Contains(ids, id) {
		return nil, refuse(ErrNotFound)
	}
	slices.Sort(ids)
	for _, kid := range ids {
		if err := tx.DeleteAPIKey(ctx, access.KeyRef{ID: kid, UserID: userID}); err != nil {
			return nil, err
		}
	}
	return ids, deleteIssuedTokens(ctx, tx, ids)
}

// deleteUserKeys deletes every key of userID and every token they issued,
// inside tx, and returns the deleted IDs ascending.
func deleteUserKeys(ctx context.Context, tx Tx, userID int64) ([]int64, error) {
	ids, err := tx.DeleteUserAPIKeys(ctx, userID)
	if err != nil {
		return nil, err
	}
	slices.Sort(ids)
	return ids, deleteIssuedTokens(ctx, tx, ids)
}

// deleteIssuedTokens is the half of every key deletion that shares its
// Update, so no committed state holds a deleted key's live link.
func deleteIssuedTokens(ctx context.Context, tx Tx, keyIDs []int64) error {
	if len(keyIDs) == 0 {
		return nil
	}
	_, err := tx.DeleteOneTimeTokensIssuedBy(ctx, keyIDs)
	return err
}

// addKeysRevoked adds one EventKeyRevoked per deleted key.
func (s *Service) addKeysRevoked(j *journal, userID int64, ids []int64, actor EventActor) {
	at := s.now()
	for _, id := range ids {
		j.add(Event{Kind: EventKeyRevoked, At: at, UserID: userID, KeyID: id, Actor: actor})
	}
}

// admitAdminScope is RequireAdminScope as an operation's first check,
// reading Rules() once like every operation.
func (s *Service) admitAdminScope(p access.Principal) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return err
	}
	return s.admitKey(p, s.adminScope, func() error { return nil })
}

// byID sorts keys by ascending ID.
func byID(keys []access.Key) []access.Key {
	slices.SortFunc(keys, func(a, b access.Key) int { return cmp.Compare(a.ID, b.ID) })
	return keys
}
