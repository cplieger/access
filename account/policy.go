package account

import (
	"context"

	"github.com/cplieger/access"
)

// Operation names what a Decision asks the Policy to allow.
type Operation string

// The operations a Policy decides.
const (
	OpCreateUser    Operation = "create_user" // admin create, invite accept, JIT provisioning
	OpDeleteUser    Operation = "delete_user"
	OpSetRole       Operation = "set_role"
	OpSetEnabled    Operation = "set_enabled"
	OpInvite        Operation = "invite"
	OpIssueRecovery Operation = "issue_recovery"
	OpListUsers     Operation = "list_users"      // the admin user list, the live invite and recovery tokens, and the security log
	OpManageAllKeys Operation = "manage_all_keys" // list and revoke every user's keys
	OpMigrateToSSO  Operation = "migrate_to_sso"  // an OIDC link under Rules.SSOGoverned
	OpCreateKeyFor  Operation = "create_key_for"  // an out-of-band actor mints a key for Target
	OpCreateOwnKey  Operation = "create_own_key"  // a session or a key mints a key for its own user
)

// CreateVia names what authorises an OpCreateUser. account alone sets it,
// from the code path; a caller cannot choose it.
type CreateVia string

// The creation paths.
const (
	ViaActor        CreateVia = ""             // the Decision's Actor: an admin principal or OutOfBand
	ViaSetup        CreateVia = "setup"        // first-account setup; account sets it only while UserCount == 0
	ViaInvite       CreateVia = "invite"       // a consumed invite, minted earlier under OpInvite
	ViaProvisioning CreateVia = "provisioning" // an OIDC identity Rules.Provisioning admitted
)

// Decision is one question to the Policy. A write that decides on stored
// rows asks it inside its Update, with the rows read there; a list read,
// and an invite acceptance's OpCreateUser, which no row decides, ask it
// before.
type Decision struct {
	// Target is nil for OpCreateUser, OpInvite and the list operations, and
	// for a user operation whose target does not exist; the policy then
	// decides on the actor alone.
	Target *access.User
	Op     Operation
	Role   access.Role // OpCreateUser, OpSetRole, OpInvite
	Via    CreateVia   // OpCreateUser only
	// Users is the user set read inside the operation's Update, with any
	// earlier change of the same UpdateUser call applied.
	Users   []access.User
	Actor   Actor // the zero Actor for every Via other than ViaActor
	Enabled bool  // OpSetEnabled: the value being set
}

// Policy decides who may change the user set and mint credentials.
type Policy interface {
	// Authorize returns nil, or a *PolicyError.
	Authorize(ctx context.Context, d Decision) error
}

// RolePolicy is the two-role policy: an admin manages the user set, and the
// last enabled admin cannot be removed, demoted or disabled.
type RolePolicy struct {
	// KeepLocalAdmin refuses removing, demoting, disabling or migrating to
	// SSO the last enabled admin who holds a password.
	KeepLocalAdmin bool
	// KeysAdminOnly lets only an admin mint keys for itself
	// (OpCreateOwnKey); false lets any enabled user.
	KeysAdminOnly bool
}

var (
	_ Policy = RolePolicy{}
	_ Policy = SingleOwnerPolicy{}
)

// Authorize applies the two-role rules to d.
func (p RolePolicy) Authorize(_ context.Context, d Decision) error { //nolint:gocritic // hugeParam: Policy's signature passes the Decision by value
	actor, isPrincipal := d.Actor.user()
	switch d.Op {
	case OpCreateUser:
		switch {
		case d.Via != ViaActor:
			return createViaZeroActor(d)
		case d.Actor.isOutOfBand():
			return nil
		}
		return requireAdmin(d, actor, isPrincipal)
	case OpCreateOwnKey:
		return p.createOwnKey(d, actor, isPrincipal)
	case OpCreateKeyFor:
		return createKeyFor(d, func(u *access.User) bool { return u.Enabled })
	case OpIssueRecovery:
		if d.Actor.isOutOfBand() {
			return nil
		}
		return requireAdmin(d, actor, isPrincipal)
	case OpMigrateToSSO:
		if !isPrincipal {
			return &PolicyError{Op: d.Op, Reason: ReasonNotPrincipal}
		}
		return p.keepLocalAdmin(d)
	case OpDeleteUser, OpSetRole, OpSetEnabled:
		return p.changeUser(d, actor, isPrincipal)
	case OpInvite, OpListUsers, OpManageAllKeys:
		return requireAdmin(d, actor, isPrincipal)
	default:
		return &PolicyError{Op: d.Op, Reason: ReasonUnknownOperation}
	}
}

func (p RolePolicy) createOwnKey(d Decision, actor *access.User, isPrincipal bool) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	if !isPrincipal || !actor.Enabled {
		return &PolicyError{Op: d.Op, Reason: ReasonNotEnabledUser}
	}
	if p.KeysAdminOnly && actor.Role != access.RoleAdmin {
		return &PolicyError{Op: d.Op, Reason: ReasonNotAdmin}
	}
	return nil
}

// changeUser decides a delete, role change or enable change: an admin
// actor, no self-delete, and no change that leaves no enabled admin.
func (p RolePolicy) changeUser(d Decision, actor *access.User, isPrincipal bool) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	if err := requireAdmin(d, actor, isPrincipal); err != nil {
		return err
	}
	if d.Op == OpDeleteUser && d.Target != nil && actor.ID == d.Target.ID {
		return &PolicyError{Op: d.Op, Reason: ReasonSelfDelete}
	}
	if removesLast(d, func(u *access.User) bool { return u.Role == access.RoleAdmin }) {
		return &PolicyError{Op: d.Op, Reason: ReasonLastAdmin}
	}
	return p.keepLocalAdmin(d)
}

// createKeyFor allows an out-of-band mint for a target eligible holds for.
func createKeyFor(d Decision, eligible func(*access.User) bool) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	if !d.Actor.isOutOfBand() {
		return &PolicyError{Op: d.Op, Reason: ReasonOutOfBandOnly}
	}
	if d.Target == nil || !eligible(d.Target) {
		return &PolicyError{Op: d.Op, Reason: ReasonTargetNotEligible}
	}
	return nil
}

func (p RolePolicy) keepLocalAdmin(d Decision) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	if p.KeepLocalAdmin && removesLast(d, func(u *access.User) bool {
		return u.Role == access.RoleAdmin && !u.PasswordHash.IsZero()
	}) {
		return &PolicyError{Op: d.Op, Reason: ReasonLastLocalAdmin}
	}
	return nil
}

// SingleOwnerPolicy is the one-user policy: the account setup creates is
// the owner, and nothing adds, removes or changes a user.
type SingleOwnerPolicy struct{}

// Authorize applies the single-owner rules to d.
func (SingleOwnerPolicy) Authorize(_ context.Context, d Decision) error { //nolint:gocritic // hugeParam: Policy's signature passes the Decision by value
	refuse := func(reason string) error { return &PolicyError{Op: d.Op, Reason: reason} }
	actor, isPrincipal := d.Actor.user()
	isOwner := func(u *access.User) bool { return u.Enabled && u.Role == access.RoleAdmin }
	switch d.Op {
	case OpCreateUser:
		if d.Via != ViaSetup {
			return refuse(ReasonSingleOwner)
		}
		return createViaZeroActor(d)
	case OpIssueRecovery:
		if !d.Actor.isOutOfBand() {
			return refuse(ReasonOutOfBandOnly)
		}
		return nil
	case OpCreateOwnKey, OpListUsers, OpManageAllKeys:
		if !isPrincipal || !isOwner(actor) {
			return refuse(ReasonNotOwner)
		}
		return nil
	case OpCreateKeyFor:
		return createKeyFor(d, isOwner)
	default:
		return refuse(ReasonSingleOwner)
	}
}

// createViaZeroActor allows a creation that a consumed setup, invite or
// provisioning step authorises, and only from the zero Actor.
func createViaZeroActor(d Decision) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	switch d.Via {
	case ViaSetup, ViaInvite, ViaProvisioning:
	default:
		return &PolicyError{Op: d.Op, Reason: ReasonUnknownVia}
	}
	if !d.Actor.isZero() {
		return &PolicyError{Op: d.Op, Reason: ReasonViaWithActor}
	}
	return nil
}

// changed is target after d's change: a delete leaves it disabled, a role
// change sets d.Role, an enable change sets d.Enabled, and an SSO migration
// drops the password.
func changed(d Decision, target access.User) access.User { //nolint:gocritic // hugeParam: the Decision Authorize received
	switch d.Op {
	case OpDeleteUser:
		target.Enabled = false
	case OpSetRole:
		target.Role = d.Role
	case OpSetEnabled:
		target.Enabled = d.Enabled
	case OpMigrateToSSO:
		target.PasswordHash = access.Hash{}
	default:
	}
	return target
}

func requireAdmin(d Decision, actor *access.User, isPrincipal bool) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	if !isPrincipal || !actor.Enabled || actor.Role != access.RoleAdmin {
		return &PolicyError{Op: d.Op, Reason: ReasonNotAdmin}
	}
	return nil
}

// removesLast reports whether d leaves no enabled user that counts, where
// its target was one. The target is read from d.Users, which carries any
// earlier change of the same call.
func removesLast(d Decision, counts func(*access.User) bool) bool { //nolint:gocritic // hugeParam: the Decision Authorize received
	if d.Target == nil {
		return false
	}
	target := *d.Target
	for i := range d.Users {
		if d.Users[i].ID == target.ID {
			target = d.Users[i]
		}
	}
	if !target.Enabled || !counts(&target) {
		return false
	}
	after := changed(d, target)
	if after.Enabled && counts(&after) {
		return false
	}
	for i := range d.Users {
		u := &d.Users[i]
		if u.ID != target.ID && u.Enabled && counts(u) {
			return false
		}
	}
	return true
}
