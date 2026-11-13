package account_test

import (
	"errors"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// policyUsers are the stored users the policy tables decide over.
var (
	adminA = access.User{ID: 1, Username: "a", Role: access.RoleAdmin, Enabled: true, PasswordHash: access.NewHash("$argon2id$a")}
	adminB = access.User{ID: 2, Username: "b", Role: access.RoleAdmin, Enabled: true}
	userU  = access.User{ID: 3, Username: "u", Role: access.RoleUser, Enabled: true}
	userV  = access.User{ID: 4, Username: "v", Role: access.RoleUser, Enabled: false}
)

// actorKinds are the kinds of actor every operation is tried with.
func actorKinds() map[string]account.Actor {
	a, u := adminA, userU
	return map[string]account.Actor{
		"zero":        {},
		"out_of_band": account.OutOfBand("socket"),
		"admin":       account.As(access.Principal{User: &a, Method: access.MethodPassword}),
		"user":        account.As(access.Principal{User: &u, Method: access.MethodPassword}),
		"no_user":     account.As(access.Principal{Method: access.MethodPassword}),
	}
}

type policyRow struct {
	allowed map[string]bool // actor kind -> allowed; absent kinds are refused
	op      account.Operation
	via     account.CreateVia
	target  *access.User
	role    access.Role
	enabled bool
}

func (r policyRow) name() string {
	n := string(r.op)
	if r.via != "" {
		n += "_via_" + string(r.via)
	}
	return n
}

// runPolicyTable asks p every row with every actor kind.
func runPolicyTable(t *testing.T, p account.Policy, rows []policyRow) {
	t.Helper()
	users := []access.User{adminA, adminB, userU, userV}
	for _, r := range rows {
		for kind, actor := range actorKinds() {
			d := account.Decision{Op: r.op, Via: r.via, Actor: actor, Target: r.target, Role: r.role, Enabled: r.enabled, Users: users}
			err := p.Authorize(t.Context(), d)
			want := r.allowed[kind]
			switch {
			case want && err != nil:
				t.Errorf("%s from %s = %v, want allowed", r.name(), kind, err)
			case !want && !isPolicyRefusal(err, r.op):
				t.Errorf("%s from %s = %v, want a *PolicyError for %s", r.name(), kind, err, r.op)
			}
		}
	}
}

func isPolicyRefusal(err error, op account.Operation) bool {
	var pe *account.PolicyError
	return errors.As(err, &pe) && pe.Op == op && pe.Reason != "" && errors.Is(err, account.ErrPolicyRefused)
}

func TestRolePolicyTable(t *testing.T) {
	t.Parallel()
	adminOnly := map[string]bool{"admin": true}
	adminOrOOB := map[string]bool{"admin": true, "out_of_band": true}
	zeroOnly := map[string]bool{"zero": true}
	rows := []policyRow{
		{op: account.OpCreateUser, via: account.ViaActor, role: access.RoleUser, allowed: adminOrOOB},
		{op: account.OpCreateUser, via: account.ViaActor, role: access.RoleAdmin, allowed: adminOrOOB},
		{op: account.OpCreateUser, via: account.ViaSetup, role: access.RoleAdmin, allowed: zeroOnly},
		{op: account.OpCreateUser, via: account.ViaInvite, role: access.RoleUser, allowed: zeroOnly},
		{op: account.OpCreateUser, via: account.ViaProvisioning, role: access.RoleUser, allowed: zeroOnly},
		{op: account.OpCreateUser, via: "unknown", role: access.RoleUser},
		{op: account.OpDeleteUser, target: new(userU), allowed: adminOnly},
		{op: account.OpDeleteUser, allowed: adminOnly},
		{op: account.OpSetRole, target: new(userU), role: access.RoleAdmin, allowed: adminOnly},
		{op: account.OpSetEnabled, target: new(userU), enabled: false, allowed: adminOnly},
		{op: account.OpSetEnabled, target: new(userV), enabled: true, allowed: adminOnly},
		{op: account.OpInvite, role: access.RoleUser, allowed: adminOnly},
		{op: account.OpIssueRecovery, target: new(userU), allowed: adminOrOOB},
		{op: account.OpListUsers, allowed: adminOnly},
		{op: account.OpManageAllKeys, allowed: adminOrOOB},
		{op: account.OpMigrateToSSO, target: new(userU), allowed: map[string]bool{"admin": true, "user": true}},
		{op: account.OpCreateKeyFor, target: new(userU), allowed: map[string]bool{"out_of_band": true}},
		{op: account.OpCreateKeyFor, target: new(userV)},
		{op: account.OpCreateOwnKey, allowed: map[string]bool{"admin": true, "user": true}},
		{op: "unknown"},
	}
	t.Run("operations", func(t *testing.T) {
		t.Parallel()
		runPolicyTable(t, account.RolePolicy{}, rows)
	})
	t.Run("keys_admin_only", func(t *testing.T) {
		t.Parallel()
		runPolicyTable(t, account.RolePolicy{KeysAdminOnly: true}, []policyRow{
			{op: account.OpCreateOwnKey, allowed: adminOnly},
		})
	})
	t.Run("disabled_admin_actor", func(t *testing.T) {
		t.Parallel()
		a := adminA
		a.Enabled = false
		d := account.Decision{Op: account.OpListUsers, Actor: account.As(access.Principal{User: &a, Method: access.MethodAPIKey})}
		if err := (account.RolePolicy{}).Authorize(t.Context(), d); !isPolicyRefusal(err, account.OpListUsers) {
			t.Errorf("a disabled admin's list_users = %v, want refused", err)
		}
	})
	t.Run("last_admin", func(t *testing.T) {
		t.Parallel()
		a, b, u := adminA, adminB, userU
		bDisabled := adminB
		bDisabled.Enabled = false
		aDemoted := adminA
		aDemoted.Role = access.RoleUser
		actorA := account.As(access.Principal{User: &a, Method: access.MethodPassword})
		actorB := account.As(access.Principal{User: &b, Method: access.MethodPassword})
		for _, tc := range []struct {
			d      account.Decision
			name   string
			reason string
		}{
			{name: "delete_other_admin", d: account.Decision{Op: account.OpDeleteUser, Actor: actorA, Target: &b, Users: []access.User{a, b, u}}},
			{name: "delete_self", reason: "self_delete", d: account.Decision{Op: account.OpDeleteUser, Actor: actorA, Target: &a, Users: []access.User{a, b, u}}},
			{name: "delete_last_enabled_admin", reason: "last_admin", d: account.Decision{Op: account.OpDeleteUser, Actor: actorA, Target: &b, Users: []access.User{aDemoted, b, u}}},
			{name: "demote_other_admin", d: account.Decision{Op: account.OpSetRole, Role: access.RoleUser, Actor: actorA, Target: &b, Users: []access.User{a, b}}},
			{name: "demote_last_admin", reason: "last_admin", d: account.Decision{Op: account.OpSetRole, Role: access.RoleUser, Actor: actorA, Target: &a, Users: []access.User{a, bDisabled, u}}},
			{name: "promote_keeps_admin", d: account.Decision{Op: account.OpSetRole, Role: access.RoleAdmin, Actor: actorA, Target: &a, Users: []access.User{a, u}}},
			{name: "disable_last_admin", reason: "last_admin", d: account.Decision{Op: account.OpSetEnabled, Enabled: false, Actor: actorA, Target: &a, Users: []access.User{a, bDisabled, u}}},
			{name: "disable_admin_two_left", d: account.Decision{Op: account.OpSetEnabled, Enabled: false, Actor: actorA, Target: &b, Users: []access.User{a, b}}},
			// The second question of one UpdateUser call sees the first
			// change applied in Users: A's demotion leaves B the last admin.
			{name: "disable_after_demote_in_same_call", reason: "last_admin", d: account.Decision{Op: account.OpSetEnabled, Enabled: false, Actor: actorB, Target: &b, Users: []access.User{aDemoted, b}}},
			{name: "disable_reads_target_from_users", reason: "last_admin", d: account.Decision{Op: account.OpSetEnabled, Enabled: false, Actor: actorB, Target: &aDemoted, Users: []access.User{a, bDisabled}}},
		} {
			err := (account.RolePolicy{}).Authorize(t.Context(), tc.d)
			var pe *account.PolicyError
			switch {
			case tc.reason == "" && err != nil:
				t.Errorf("%s = %v, want allowed", tc.name, err)
			case tc.reason != "" && (!errors.As(err, &pe) || pe.Reason != tc.reason):
				t.Errorf("%s = %v, want reason %s", tc.name, err, tc.reason)
			}
		}
	})
	t.Run("last_local_admin", func(t *testing.T) {
		t.Parallel()
		a, b := adminA, adminB
		c := adminB
		c.ID, c.PasswordHash = 5, access.NewHash("$argon2id$c")
		aDisabled, u := adminA, userU
		aDisabled.Enabled = false
		actorA := account.As(access.Principal{User: &a, Method: access.MethodOIDC})
		actorB := account.As(access.Principal{User: &b, Method: access.MethodOIDC})
		for _, tc := range []struct {
			d    account.Decision
			name string
			keep bool
		}{
			{name: "delete", d: account.Decision{Op: account.OpDeleteUser, Actor: actorB, Target: &a, Users: []access.User{a, b}}},
			{name: "demote", d: account.Decision{Op: account.OpSetRole, Role: access.RoleUser, Actor: actorB, Target: &a, Users: []access.User{a, b}}},
			{name: "disable", d: account.Decision{Op: account.OpSetEnabled, Actor: actorB, Target: &a, Users: []access.User{a, b}}},
			{name: "migrate", d: account.Decision{Op: account.OpMigrateToSSO, Actor: actorA, Target: &a, Users: []access.User{a, b}}},
			{name: "migrate_another_local_left", keep: true, d: account.Decision{Op: account.OpMigrateToSSO, Actor: actorA, Target: &a, Users: []access.User{a, b, c}}},
			{name: "delete_disabled_local_admin", keep: true, d: account.Decision{Op: account.OpDeleteUser, Actor: actorB, Target: &aDisabled, Users: []access.User{aDisabled, b}}},
			{name: "delete_user_with_no_local_admin", keep: true, d: account.Decision{Op: account.OpDeleteUser, Actor: actorB, Target: &u, Users: []access.User{b, u}}},
		} {
			if err := (account.RolePolicy{}).Authorize(t.Context(), tc.d); err != nil {
				t.Errorf("%s without KeepLocalAdmin = %v, want allowed", tc.name, err)
			}
			err := (account.RolePolicy{KeepLocalAdmin: true}).Authorize(t.Context(), tc.d)
			var pe *account.PolicyError
			switch {
			case tc.keep && err != nil:
				t.Errorf("%s with KeepLocalAdmin = %v, want allowed", tc.name, err)
			case !tc.keep && (!errors.As(err, &pe) || pe.Reason != "last_local_admin"):
				t.Errorf("%s with KeepLocalAdmin = %v, want last_local_admin", tc.name, err)
			}
		}
	})
}

func TestSingleOwnerPolicyTable(t *testing.T) {
	t.Parallel()
	ownerOnly := map[string]bool{"admin": true}
	rows := []policyRow{
		{op: account.OpCreateUser, via: account.ViaSetup, role: access.RoleAdmin, allowed: map[string]bool{"zero": true}},
		{op: account.OpCreateUser, via: account.ViaActor, role: access.RoleUser},
		{op: account.OpCreateUser, via: account.ViaInvite, role: access.RoleUser},
		{op: account.OpCreateUser, via: account.ViaProvisioning, role: access.RoleUser},
		{op: account.OpInvite, role: access.RoleUser},
		{op: account.OpSetRole, target: new(userU), role: access.RoleAdmin},
		{op: account.OpDeleteUser, target: new(userU)},
		{op: account.OpSetEnabled, target: new(userU)},
		{op: account.OpMigrateToSSO, target: new(adminA)},
		{op: account.OpIssueRecovery, target: new(adminA), allowed: map[string]bool{"out_of_band": true}},
		{op: account.OpCreateOwnKey, allowed: ownerOnly},
		{op: account.OpCreateKeyFor, target: new(adminA), allowed: map[string]bool{"out_of_band": true}},
		{op: account.OpCreateKeyFor, target: new(userU)},
		{op: account.OpListUsers, allowed: ownerOnly},
		{op: account.OpManageAllKeys, allowed: map[string]bool{"admin": true, "out_of_band": true}},
		{op: "unknown"},
	}
	runPolicyTable(t, account.SingleOwnerPolicy{}, rows)
}
