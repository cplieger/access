package account_test

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// testClock is a Config.Now a test moves.
type testClock struct{ t atomic.Pointer[time.Time] }

func newTestClock(at time.Time) *testClock {
	c := &testClock{}
	c.set(at)
	return c
}

func (c *testClock) now() time.Time      { return *c.t.Load() }
func (c *testClock) set(at time.Time)    { c.t.Store(&at) }
func (c *testClock) add(d time.Duration) { c.set(c.now().Add(d)) }

// ownerHidden is a Tx whose UserByID finds no user, for a key whose owner
// row is gone while the key row stays.
type ownerHidden struct{ account.Tx }

func (ownerHidden) UserByID(context.Context, int64) (*access.User, bool, error) {
	return nil, false, nil
}

func TestCurrentKeyActor(t *testing.T) {
	t.Parallel()
	start := time.Now()
	clock := newTestClock(start)
	f := newFixture(t, options{edit: func(c *account.Config) { c.Now = clock.now }})
	ctx := t.Context()
	// run calls the helper inside one Update, through wrap's view of tx
	// when wrap is set.
	run := func(wrap func(account.Tx) account.Tx, ref access.KeyRef, scope string) (account.Actor, *access.Key, error) {
		var actor account.Actor
		var key *access.Key
		var opErr error
		err := f.mem.Update(ctx, func(tx account.Tx) error {
			if wrap != nil {
				tx = wrap(tx)
			}
			actor, key, opErr = account.CurrentKeyActor(ctx, f.svc, tx, account.OpCreateUser, ref, scope)
			return nil
		})
		return actor, key, errors.Join(err, opErr)
	}
	notCurrent := func(name string, err error) {
		t.Helper()
		var pe *account.PolicyError
		if !errors.As(err, &pe) || pe.Reason != "key_not_current" || pe.Op != account.OpCreateUser {
			t.Errorf("%s: error = %v, want *PolicyError{create_user, key_not_current}", name, err)
		}
	}

	admin := mustUser(t, f.mem, "admin", access.RoleAdmin)
	_, parent := f.keyPrincipalFor(t, nil, admin, time.Time{}, nil, usersScope)
	_, child := f.keyPrincipalFor(t, nil, admin, start.Add(time.Hour), parent.LineageIDs, usersScope, keysScope)

	if err := f.mem.Update(ctx, func(tx account.Tx) error {
		return tx.UpdateAPIKeyLabel(ctx, access.KeyRef{ID: child.ID, UserID: admin.ID}, "deploy")
	}); err != nil {
		t.Fatalf("UpdateAPIKeyLabel: %v", err)
	}

	t.Run("current", func(t *testing.T) {
		for name, ref := range map[string]access.KeyRef{
			"principal_ref": {ID: child.ID, UserID: admin.ID},
			"issuer_ref":    {ID: child.ID},
		} {
			actor, key, err := run(nil, ref, usersScope)
			if err != nil {
				t.Fatalf("%s: error = %v, want nil", name, err)
			}
			p, ok := actor.Principal()
			if !ok || p.User == nil || p.User.ID != admin.ID || p.User.Role != access.RoleAdmin || p.KeyID != child.ID || p.Method != access.MethodAPIKey {
				t.Errorf("%s: actor = %+v, want the stored admin owner acting through key %d", name, p, child.ID)
			}
			if p.KeyLabel != "deploy" || !p.KeyHash().IsZero() {
				t.Errorf("%s: actor KeyLabel %q, KeyHash zero %v, want the stored label and no credential", name, p.KeyLabel, p.KeyHash().IsZero())
			}
			if want := []int64{parent.ID, child.ID}; key == nil || !slices.Equal(key.LineageIDs, want) {
				t.Errorf("%s: key lineage = %v, want %v", name, key, want)
			}
		}
	})
	t.Run("refusals", func(t *testing.T) {
		for name, tc := range map[string]struct {
			ref   access.KeyRef
			scope string
		}{
			"never_assigned_by_principal": {ref: access.KeyRef{ID: 9999, UserID: admin.ID}, scope: usersScope},
			"never_assigned_by_issuer":    {ref: access.KeyRef{ID: 9999}, scope: usersScope},
			"zero_ref":                    {scope: usersScope},
			"lacks_scope":                 {ref: access.KeyRef{ID: parent.ID, UserID: admin.ID}, scope: keysScope},
			"empty_scope":                 {ref: access.KeyRef{ID: child.ID, UserID: admin.ID}},
			"other_owner":                 {ref: access.KeyRef{ID: child.ID, UserID: admin.ID + 1000}, scope: usersScope},
		} {
			_, _, err := run(nil, tc.ref, tc.scope)
			notCurrent(name, err)
		}
		_, _, err := run(func(tx account.Tx) account.Tx { return ownerHidden{tx} }, access.KeyRef{ID: child.ID, UserID: admin.ID}, usersScope)
		notCurrent("deleted_owner", err)
	})
	t.Run("expiry", func(t *testing.T) {
		clock.set(start.Add(time.Hour - time.Nanosecond))
		if _, _, err := run(nil, access.KeyRef{ID: child.ID}, usersScope); err != nil {
			t.Errorf("before ExpiresAt: error = %v, want nil", err)
		}
		clock.set(start.Add(time.Hour))
		_, _, err := run(nil, access.KeyRef{ID: child.ID}, usersScope)
		notCurrent("at_expires_at", err)
		clock.add(time.Hour)
		_, _, err = run(nil, access.KeyRef{ID: child.ID, UserID: admin.ID}, usersScope)
		notCurrent("past_expires_at", err)
		clock.set(start)
	})
	t.Run("demoted_owner", func(t *testing.T) {
		demoted := mustUser(t, f.mem, "demoted", access.RoleAdmin)
		_, k := f.keyPrincipalFor(t, nil, demoted, time.Time{}, nil, usersScope)
		demoted.Role = access.RoleUser
		if err := f.mem.UpdateUser(ctx, demoted); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		actor, _, err := run(nil, access.KeyRef{ID: k.ID, UserID: demoted.ID}, usersScope)
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if p, _ := actor.Principal(); p.User == nil || p.User.Role != access.RoleUser {
			t.Errorf("actor of a key whose owner was demoted = %+v, want RoleUser", p.User)
		}
	})
	t.Run("disabled_owner", func(t *testing.T) {
		u := mustUser(t, f.mem, "disabled", access.RoleAdmin)
		_, k := f.keyPrincipalFor(t, nil, u, time.Time{}, nil, usersScope)
		u.Enabled = false
		if err := f.mem.UpdateUser(ctx, u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		_, _, err := run(nil, access.KeyRef{ID: k.ID, UserID: u.ID}, usersScope)
		notCurrent("disabled_owner", err)
	})
	t.Run("deleted_key", func(t *testing.T) {
		u := mustUser(t, f.mem, "revoked", access.RoleAdmin)
		_, k := f.keyPrincipalFor(t, nil, u, time.Time{}, nil, usersScope)
		if err := f.mem.DeleteAPIKey(ctx, access.KeyRef{ID: k.ID, UserID: u.ID}); err != nil {
			t.Fatalf("DeleteAPIKey: %v", err)
		}
		_, _, err := run(nil, access.KeyRef{ID: k.ID, UserID: u.ID}, usersScope)
		notCurrent("deleted_by_principal_ref", err)
		_, _, err = run(nil, access.KeyRef{ID: k.ID}, usersScope)
		notCurrent("deleted_by_issuer_ref", err)
	})
}

func TestAttribute(t *testing.T) {
	t.Parallel()
	at := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	f := newFixture(t, options{edit: func(c *account.Config) { c.Now = func() time.Time { return at } }})
	ctx := t.Context()
	u := mustUser(t, f.mem, "target", access.RoleUser)
	key := &access.Key{ID: 7, UserID: u.ID, LineageIDs: []int64{3, 7}}
	records := func() []access.KeyAttribution {
		t.Helper()
		got, err := f.mem.ListKeyAttributions(ctx)
		if err != nil {
			t.Fatalf("ListKeyAttributions: %v", err)
		}
		return got
	}
	if err := f.mem.Update(ctx, func(tx account.Tx) error {
		return account.Attribute(ctx, f.svc, tx, u.ID, access.AttributionCreated, key)
	}); err != nil {
		t.Fatalf("Update(attribute): %v", err)
	}
	key.LineageIDs[0] = 99
	got := records()
	if len(got) != 1 {
		t.Fatalf("records = %v, want one", got)
	}
	first := got[0]
	if first.UserID != u.ID || first.Action != access.AttributionCreated || !first.At.Equal(at) || !slices.Equal(first.KeyLineage, []int64{3, 7}) {
		t.Errorf("record = %+v, want user %d, created, %v, lineage [3 7]", first, u.ID, at)
	}
	rollback := errors.New("rollback")
	if err := f.mem.Update(ctx, func(tx account.Tx) error {
		if err := account.Attribute(ctx, f.svc, tx, u.ID, access.AttributionDisabled, key); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("Update(attribute, error) = %v, want the callback's error", err)
	}
	if got := records(); len(got) != 1 {
		t.Errorf("records after a rolled-back Update = %v, want only the first", got)
	}
	if err := f.mem.Update(ctx, func(tx account.Tx) error {
		return account.Attribute(ctx, f.svc, tx, u.ID, access.AttributionDisabled, key)
	}); err != nil {
		t.Fatalf("Update(second attribute): %v", err)
	}
	got = records()
	if len(got) != 2 || !slices.Equal(got[0].KeyLineage, first.KeyLineage) || got[0].Action != first.Action || !slices.Equal(got[1].KeyLineage, []int64{99, 7}) {
		t.Errorf("records after a second call = %+v, want the first unchanged and a second with [99 7]", got)
	}
}

func TestRequireUserTarget(t *testing.T) {
	t.Parallel()
	if err := account.RequireUserTarget(account.OpSetRole, access.RoleUser, access.RoleUser); err != nil {
		t.Errorf("RequireUserTarget(user, user) = %v, want nil", err)
	}
	for name, roles := range map[string][]access.Role{
		"admin":       {access.RoleAdmin},
		"app_defined": {"auditor"},
		"empty":       {""},
		"second_role": {access.RoleUser, access.RoleAdmin},
	} {
		err := account.RequireUserTarget(account.OpSetRole, roles...)
		var pe *account.PolicyError
		if !errors.As(err, &pe) || pe.Reason != "admin_target" || pe.Op != account.OpSetRole {
			t.Errorf("%s: RequireUserTarget = %v, want *PolicyError{set_role, admin_target}", name, err)
		}
	}
}
