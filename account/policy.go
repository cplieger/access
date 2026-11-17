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
	OpListUsers     Operation = "list_users"      // the admin user list, the live invite tokens and the security log
	OpManageAllKeys Operation = "manage_all_keys" // list and revoke every user's keys
	OpCreateKeyFor  Operation = "create_key_for"  // an out-of-band actor mints a key for Target
	OpCreateOwnKey  Operation = "create_own_key"  // a session or a key mints a key for its own user
	OpRotateKey     Operation = "rotate_key"      // a new secret for Target's key, by OutOfBand or Target's own session
	OpSetOwner      Operation = "set_owner"       // Target's owner flag, to Decision.Owner
	// OpSetTemporaryPassword issues Target a temporary password.
	OpSetTemporaryPassword Operation = "set_temporary_password"
	OpResetSecondFactor    Operation = "reset_second_factor" // delete Target's TOTP and recovery code
	OpUnlinkOIDC           Operation = "unlink_oidc"         // remove Target's identity-provider link for them
	// OpApplySSO is a change of the stored SSO mode. account decides it
	// itself, owners and out-of-band actors only, and asks no Policy; it
	// names the operation of its PolicyErrors.
	OpApplySSO Operation = "apply_sso"
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
	ViaRegistration CreateVia = "registration" // an anonymous sign-up under open registration
)

// Decision is one question to the Policy. A write that decides on stored
// rows asks it inside its Update, with the rows read there, and so does
// AllAPIKeys, whose key actor is re-read there; the other list reads, and
// an invite acceptance's OpCreateUser, which no row decides, ask it before.
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
	Owner   bool  // OpSetOwner: the value being set
}

// Policy decides who may change the user set and mint credentials. An
// OutOfBand actor reaches it for OpCreateUser, OpCreateKeyFor,
// OpManageAllKeys, OpRotateKey, OpSetOwner, OpSetTemporaryPassword,
// OpResetSecondFactor and OpUnlinkOIDC, so an app's own Policy decides each.
// OpRotateKey's Target is the key's user as stored. account applies the
// owner protections itself, after Authorize allows, whatever the Policy.
type Policy interface {
	// Authorize returns nil, or a *PolicyError.
	Authorize(ctx context.Context, d Decision) error
	// SingleUser reports whether the Policy admits one account only. It
	// must be constant for a Policy value: New reads it once, and under a
	// true answer account itself refuses every creation but setup, every
	// invite and every enable before Authorize is asked.
	SingleUser() bool
}

// RolePolicy is the two-role policy: an admin manages the user set, and an
// owner manages the owners.
type RolePolicy struct {
	// KeysAdminOnly lets only an admin mint keys for itself
	// (OpCreateOwnKey) and rotate its own (OpRotateKey); false lets any
	// enabled user.
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
		return createUser(d, actor, isPrincipal)
	case OpCreateOwnKey:
		return p.ownKey(d, actor, isPrincipal)
	case OpCreateKeyFor:
		return outOfBandOn(d, enabled)
	case OpRotateKey:
		return p.rotateKey(d, actor, isPrincipal)
	case OpManageAllKeys, OpSetTemporaryPassword, OpResetSecondFactor, OpUnlinkOIDC:
		if d.Actor.isOutOfBand() {
			return nil
		}
		return requireAdmin(d, actor, isPrincipal)
	case OpSetOwner:
		if d.Actor.isOutOfBand() || (isPrincipal && isOwner(actor)) {
			return nil
		}
		return &PolicyError{Op: d.Op, Reason: ReasonNotOwner}
	case OpDeleteUser, OpSetRole, OpSetEnabled:
		return changeUser(d, actor, isPrincipal)
	case OpInvite, OpListUsers:
		return requireAdmin(d, actor, isPrincipal)
	default:
		return &PolicyError{Op: d.Op, Reason: ReasonUnknownOperation}
	}
}

// createUser allows a creation through a consumed setup, invite,
// provisioning or registration step, and an admin's or an out-of-band one.
func createUser(d Decision, actor *access.User, isPrincipal bool) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	switch {
	case d.Via != ViaActor:
		return createViaZeroActor(d)
	case d.Actor.isOutOfBand():
		return nil
	}
	return requireAdmin(d, actor, isPrincipal)
}

// ownKey is the rule on a principal acting on a key of its own user: an
// enabled user, and an admin under KeysAdminOnly.
func (p RolePolicy) ownKey(d Decision, actor *access.User, isPrincipal bool) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	if !isPrincipal || !actor.Enabled {
		return &PolicyError{Op: d.Op, Reason: ReasonNotEnabledUser}
	}
	if p.KeysAdminOnly && actor.Role != access.RoleAdmin {
		return &PolicyError{Op: d.Op, Reason: ReasonNotAdmin}
	}
	return nil
}

// rotateKey allows an out-of-band actor on an enabled target, and a
// principal on its own enabled user under ownKey's rule.
func (p RolePolicy) rotateKey(d Decision, actor *access.User, isPrincipal bool) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	if d.Actor.isOutOfBand() {
		return outOfBandOn(d, enabled)
	}
	if err := p.ownKey(d, actor, isPrincipal); err != nil {
		return err
	}
	switch {
	case d.Target == nil || d.Target.ID != actor.ID:
		return &PolicyError{Op: d.Op, Reason: ReasonOtherUser}
	case !d.Target.Enabled:
		return &PolicyError{Op: d.Op, Reason: ReasonNotEnabledUser}
	}
	return nil
}

// SingleUser reports false: RolePolicy admits many accounts.
func (RolePolicy) SingleUser() bool { return false }

// changeUser decides a delete, role change or enable change: an admin
// actor and no self-delete. The owner rules keep an enabled admin.
func changeUser(d Decision, actor *access.User, isPrincipal bool) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	if err := requireAdmin(d, actor, isPrincipal); err != nil {
		return err
	}
	if d.Op == OpDeleteUser && d.Target != nil && actor.ID == d.Target.ID {
		return &PolicyError{Op: d.Op, Reason: ReasonSelfDelete}
	}
	return nil
}

// outOfBandOn allows only an out-of-band actor, on a target eligible holds
// for.
func outOfBandOn(d Decision, eligible func(*access.User) bool) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	if !d.Actor.isOutOfBand() {
		return &PolicyError{Op: d.Op, Reason: ReasonOutOfBandOnly}
	}
	if d.Target == nil || !eligible(d.Target) {
		return &PolicyError{Op: d.Op, Reason: ReasonTargetNotEligible}
	}
	return nil
}

// SingleOwnerPolicy is the one-user policy: its owner is the account that
// carries access.User.Owner, which setup and New set, and nothing adds,
// removes or changes a user.
type SingleOwnerPolicy struct{}

// SingleUser reports true.
func (SingleOwnerPolicy) SingleUser() bool { return true }

// Authorize applies the single-owner rules to d.
func (SingleOwnerPolicy) Authorize(_ context.Context, d Decision) error { //nolint:gocritic // hugeParam: Policy's signature passes the Decision by value
	refuse := func(reason string) error { return &PolicyError{Op: d.Op, Reason: reason} }
	actor, isPrincipal := d.Actor.user()
	requireOwner := func() error {
		if !isPrincipal || !isOwner(actor) {
			return refuse(ReasonNotOwner)
		}
		return nil
	}
	switch d.Op {
	case OpCreateUser:
		if d.Via != ViaSetup {
			return refuse(ReasonSingleOwner)
		}
		return createViaZeroActor(d)
	case OpManageAllKeys, OpRotateKey:
		if d.Actor.isOutOfBand() {
			return nil
		}
		return requireOwner()
	case OpCreateOwnKey, OpListUsers:
		return requireOwner()
	case OpCreateKeyFor, OpSetTemporaryPassword, OpResetSecondFactor, OpUnlinkOIDC:
		return outOfBandOn(d, isOwner)
	default:
		return refuse(ReasonSingleOwner)
	}
}

// createViaZeroActor allows a creation that a consumed setup, invite or
// provisioning step authorises, and only from the zero Actor.
func createViaZeroActor(d Decision) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	switch d.Via {
	case ViaSetup, ViaInvite, ViaProvisioning, ViaRegistration:
	default:
		return &PolicyError{Op: d.Op, Reason: ReasonUnknownVia}
	}
	if !d.Actor.isZero() {
		return &PolicyError{Op: d.Op, Reason: ReasonViaWithActor}
	}
	return nil
}

func enabled(u *access.User) bool { return u.Enabled }

func requireAdmin(d Decision, actor *access.User, isPrincipal bool) error { //nolint:gocritic // hugeParam: the Decision Authorize received
	if !isPrincipal || !actor.Enabled || actor.Role != access.RoleAdmin {
		return &PolicyError{Op: d.Op, Reason: ReasonNotAdmin}
	}
	return nil
}

// authorize is the one place account asks the Policy. Under the kept
// single-user declaration it first refuses every creation but setup, every
// invite and every enable (ReasonSingleOwner), so no path adds an enabled
// account whatever the Policy would answer.
func (s *Service) authorize(ctx context.Context, d Decision) error { //nolint:gocritic // hugeParam: the Decision is built for this one call
	if s.singleUser && addsAccount(d) {
		return &PolicyError{Op: d.Op, Reason: ReasonSingleOwner}
	}
	return s.policy.Authorize(ctx, d)
}

// addsAccount reports whether d could raise the count of enabled accounts.
func addsAccount(d Decision) bool { //nolint:gocritic // hugeParam: as authorize
	switch d.Op {
	case OpCreateUser:
		return d.Via != ViaSetup
	case OpInvite:
		return true
	case OpSetEnabled:
		return d.Enabled && (d.Target == nil || !d.Target.Enabled)
	default:
		return false
	}
}
