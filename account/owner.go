package account

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cplieger/access"
)

// actorMigration is the out-of-band channel New's owner marking journals.
const actorMigration = "migration"

// isOwner is the owner every rule counts: the stored flag on an enabled
// admin. A flag on a disabled account or a RoleUser counts for no rule.
func isOwner(u *access.User) bool { return u.Owner && u.Enabled && u.Role == access.RoleAdmin }

// errNoEnabledAdmin is New's refusal of a multi-user store with users and no
// enabled admin.
var errNoEnabledAdmin = fmt.Errorf("%w: the store holds users and no enabled admin; while the app is stopped, enable an admin or make an enabled account an admin in the store, or restore a backup", ErrNoOwner)

// errOwnerFlag is Service.Owner on a single-user store that fits but whose
// owner flag is not on its one enabled admin alone.
var errOwnerFlag = fmt.Errorf("%w: the owner flag is not on the one enabled admin alone; restart the app, and account.New marks it again", ErrNoOwner)

// singleUserFit is the one enabled admin of a single-user store with users,
// or the one error naming what the store holds and its one repair. The
// error matches ErrNoOwner when no enabled account is an admin.
func singleUserFit(users []access.User) (*access.User, error) {
	var enabled, admins []*access.User
	for i := range users {
		if users[i].Enabled {
			enabled = append(enabled, &users[i])
			if users[i].Role == access.RoleAdmin {
				admins = append(admins, &users[i])
			}
		}
	}
	if len(enabled) == 1 && len(admins) == 1 {
		return admins[0], nil
	}
	held := fmt.Sprintf("%d enabled accounts", len(enabled))
	if len(enabled) == 1 {
		held = "1 enabled account"
	}
	found := "none of them an admin"
	switch {
	case len(admins) == 1:
		found = "one of them an admin"
	case len(admins) > 1:
		found = fmt.Sprintf("%d of them admins", len(admins))
	}
	msg := fmt.Sprintf("a single-user Policy needs exactly one enabled account, an admin, and the store holds %s, %s; "+
		"while the app is stopped, keep one account, enable it if it is disabled, delete or disable the others and make it an admin, "+
		"in the store, or restore a single-user backup", held, found)
	if len(admins) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoOwner, msg)
	}
	return nil, errors.New("account: " + msg)
}

// markOwners is New's owner marking. A single-user store must fit
// (singleUserFit), and its one enabled admin alone keeps the flag. A
// multi-user store with users and no owner marks its earliest enabled admin,
// preferring one with a local method. Each flag written is journalled by
// actorMigration, and a flag that already holds is not written.
func (s *Service) markOwners(ctx context.Context, r Rules) error { //nolint:gocritic // hugeParam: New's one Rules value
	var bare *access.User
	err := s.change(ctx, by(OutOfBand(actorMigration)), func(tx Tx, j *journal) error {
		var err error
		bare, err = s.markOwnersIn(ctx, tx, j, r)
		return err
	})
	if err == nil && bare != nil {
		s.logger().Warn("account: the owner holds no password or passkey; add one from a single sign-on session, or, if admission refuses it, issue it a temporary password at the admin socket",
			"user_id", bare.ID)
	}
	return err
}

// markOwnersIn is markOwners inside tx. bare is the owner it marked when
// that owner holds no local method.
func (s *Service) markOwnersIn(ctx context.Context, tx Tx, j *journal, r Rules) (bare *access.User, err error) { //nolint:gocritic // hugeParam: New's one Rules value
	users, err := tx.ListUsers(ctx)
	if err != nil || len(users) == 0 {
		return nil, err
	}
	if s.singleUser {
		owner, fitErr := singleUserFit(users)
		if fitErr != nil {
			return nil, refuse(fitErr)
		}
		return nil, s.leaveOneFlag(ctx, tx, j, users, owner.ID)
	}
	if slices.ContainsFunc(users, func(u access.User) bool { return isOwner(&u) }) {
		return nil, nil
	}
	pick, local, err := s.pickOwner(ctx, tx, r, users)
	if err != nil {
		return nil, err
	}
	if !local {
		bare = pick
	}
	return bare, s.writeOwner(ctx, tx, j, pick, true, OutOfBand(actorMigration), local)
}

// leaveOneFlag sets the owner flag on ownerID and clears it on every other
// user, writing only the flags that differ.
func (s *Service) leaveOneFlag(ctx context.Context, tx Tx, j *journal, users []access.User, ownerID int64) error {
	for i := range users {
		if want := users[i].ID == ownerID; users[i].Owner != want {
			if err := s.writeOwner(ctx, tx, j, &users[i], want, OutOfBand(actorMigration), true); err != nil {
				return err
			}
		}
	}
	return nil
}

// pickOwner is the enabled admin with the earliest CreatedAt, ties by
// username, preferring one that holds a local method; local reports
// whether the pick holds one. IDs are never read: a store may reuse them.
func (s *Service) pickOwner(ctx context.Context, tx Tx, r Rules, users []access.User) (pick *access.User, local bool, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	var admins []*access.User
	for i := range users {
		if users[i].Enabled && users[i].Role == access.RoleAdmin {
			admins = append(admins, &users[i])
		}
	}
	if len(admins) == 0 {
		return nil, false, refuse(errNoEnabledAdmin)
	}
	slices.SortFunc(admins, func(a, b *access.User) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.Username, b.Username))
	})
	for _, u := range admins {
		ok, err := s.holdsLocalMethod(ctx, tx, r, u)
		if err != nil || ok {
			return u, ok, err
		}
	}
	return admins[0], false, nil
}

// holdsLocalMethod reports whether u holds a password or a passkey it signs
// in with as an owner: held, allowed by r and unlocked, OIDC left out.
func (s *Service) holdsLocalMethod(ctx context.Context, tx Tx, r Rules, u *access.User) (bool, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	st := MethodState{Rules: r}
	if rp := s.relyingParty(); rp != nil {
		st.RPID = rp.ID()
	}
	avail, err := s.availability(ctx, tx, st, u, credential{})
	if err != nil {
		return false, err
	}
	return avail.HasPassword || avail.PasskeyCount > 0, nil
}

// writeOwner stores u with its owner flag set to owner and journals
// owner_set or owner_removed by a. An owner_set whose owner holds no local
// method carries LogDetailOwnerNeedsLocalMethod.
func (s *Service) writeOwner(ctx context.Context, tx Tx, j *journal, u *access.User, owner bool, a Actor, local bool) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	u.Owner = owner
	u.UpdatedAt = s.now()
	if err := tx.UpdateUser(ctx, u); err != nil {
		return err
	}
	ev := Event{Kind: EventOwnerRemoved, At: u.UpdatedAt, UserID: u.ID, Actor: eventActor(a)}
	if !owner {
		j.add(ev)
		return nil
	}
	ev.Kind = EventOwnerSet
	if !local {
		j.addDetail(ev, LogDetailOwnerNeedsLocalMethod)
		return nil
	}
	j.add(ev)
	return nil
}

// Owner returns the owner of a single-user app: the one enabled admin when
// it alone carries access.User.Owner. An empty store is ErrNotFound and a
// nil user, since setup has not run. A store changed under the running
// Service answers no user: one that no longer fits answers the error New
// would refuse it with, and one whose flag is not on its one enabled admin
// alone an error matching ErrNoOwner whose repair is a restart. Under a
// multi-user Policy it is ErrNotSingleUser whatever the store holds.
func (s *Service) Owner(ctx context.Context) (*access.User, error) {
	if s.closed.Load() {
		return nil, ErrServiceClosed
	}
	if !s.singleUser {
		return nil, ErrNotSingleUser
	}
	users, err := s.store.ListUsers(ctx)
	switch {
	case err != nil:
		return nil, storeErr(err)
	case len(users) == 0:
		return nil, ErrNotFound
	}
	owner, err := singleUserFit(users)
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].Owner != (users[i].ID == owner.ID) {
			return nil, errOwnerFlag
		}
	}
	return owner.Clone(), nil
}

// SetOwner sets userID's owner flag for an owner's full session within
// Rules().RecentAuth, or an out-of-band actor, under Policy (OpSetOwner),
// and returns the user as committed. An owner needs an enabled admin with a
// password or passkey it signs in with (owner_needs_local_method), and the
// last enabled owner stays (last_owner). A refusal answers before existence
// and writes nothing, as does the flag it already has. A new owner's
// dormant temporary password is withdrawn, and an ex-owner now a dormant
// user loses its sessions of a local method.
func (s *Service) SetOwner(ctx context.Context, a Actor, userID int64, owner bool) (*access.User, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.begin()
	if err != nil {
		return nil, err
	}
	if !a.isOutOfBand() {
		p, _ := a.Principal()
		if sessErr := requireSession(p); sessErr != nil {
			return nil, sessErr
		}
		if authErr := s.recentAuth(r, p); authErr != nil {
			return nil, authErr
		}
	}
	var out *access.User
	err = s.change(ctx, by(a), func(tx Tx, j *journal) error {
		var setErr error
		out, setErr = s.setOwnerIn(ctx, tx, j, r, a, userID, owner)
		return setErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// setOwnerIn is SetOwner's Update: the Policy and the owner protections on
// the rows read in tx, then the flag when it differs.
func (s *Service) setOwnerIn(ctx context.Context, tx Tx, j *journal, r Rules, a Actor, userID int64, owner bool) (*access.User, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and its Actor
	target, found, users, err := targetIn(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	d := Decision{Op: OpSetOwner, Actor: storedActor(a, users), Target: target, Owner: owner, Users: users}
	if polErr := s.authorizeOwned(ctx, &d); polErr != nil {
		return nil, refuse(polErr)
	}
	if !found {
		return nil, refuse(ErrNotFound)
	}
	if target.Owner == owner {
		return target.Clone(), nil
	}
	if owner {
		local, localErr := s.holdsLocalMethod(ctx, tx, r, target)
		switch {
		case localErr != nil:
			return nil, localErr
		case !local || !target.Enabled || target.Role != access.RoleAdmin:
			return nil, refuse(&PolicyError{Op: OpSetOwner, Reason: ReasonOwnerNeedsLocalMethod})
		}
	}
	if err := s.writeOwner(ctx, tx, j, target, owner, a, true); err != nil {
		return nil, err
	}
	if err := s.ownerModeIn(ctx, tx, j, target, eventActor(a)); err != nil {
		return nil, err
	}
	return target.Clone(), nil
}

// ownerModeIn is the stored mode's effect of u's new owner flag, inside
// tx: an owner's methods are usable, so its dormant temporary password is
// withdrawn; an ex-owner the mode keeps dormant loses its sessions of a
// local method.
func (s *Service) ownerModeIn(ctx context.Context, tx Tx, j *journal, u *access.User, actor EventActor) error {
	if u.Owner {
		return s.withdrawDormant(ctx, tx, j, u.ID, actor)
	}
	mode, err := storedMode(ctx, tx)
	if err != nil || !mode.dormantFor(u) {
		return err
	}
	ended, err := endForbiddenSessions(ctx, tx, u)
	if err != nil {
		return err
	}
	s.addRevoked(j, u.ID, ended, actor)
	return nil
}

// storedActor is a with a principal's user replaced by its row in users,
// read inside the Update: an owner flag changes without ending sessions,
// so the principal's copy can be stale. A principal whose user is gone
// keeps its copy, which the Policy refuses as any other.
func storedActor(a Actor, users []access.User) Actor { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	u, ok := a.user()
	if !ok {
		return a
	}
	if i := slices.IndexFunc(users, func(s access.User) bool { return s.ID == u.ID }); i >= 0 {
		a.principal.User = users[i].Clone()
	}
	return a
}

// ownerGuard is the owner protections account applies to an allowed d, for
// every Policy, before any write: a principal that is no owner never acts
// on an owner (owner_target), an owner's role never changes (owner_role),
// and no change leaves no enabled owner (last_owner). An out-of-band actor
// passes owner_target. A nil Target passes, so existence is answered after.
func ownerGuard(d *Decision) error {
	t := d.Target
	switch {
	case t == nil:
		return nil
	case t.Owner && !d.Actor.isOutOfBand() && !actsAsOwner(d):
		return &PolicyError{Op: d.Op, Reason: ReasonOwnerTarget}
	case d.Op == OpSetRole && t.Owner && d.Role != t.Role:
		return &PolicyError{Op: d.Op, Reason: ReasonOwnerRole}
	case removesOwner(d) && isOwner(t) && !otherOwner(d.Users, t.ID):
		return &PolicyError{Op: d.Op, Reason: ReasonLastOwner}
	}
	return nil
}

// actsAsOwner reports whether d's actor is an owner as d.Users stores it.
func actsAsOwner(d *Decision) bool {
	actor, ok := storedActor(d.Actor, d.Users).user()
	return ok && isOwner(actor)
}

// removesOwner reports whether d takes its target out of the enabled
// owners: a delete, a disable or an un-owner.
func removesOwner(d *Decision) bool {
	switch d.Op {
	case OpDeleteUser:
		return true
	case OpSetEnabled:
		return !d.Enabled
	case OpSetOwner:
		return !d.Owner
	default:
		return false
	}
}

// otherOwner reports whether users holds an owner other than id.
func otherOwner(users []access.User, id int64) bool {
	return slices.ContainsFunc(users, func(u access.User) bool { return u.ID != id && isOwner(&u) })
}
