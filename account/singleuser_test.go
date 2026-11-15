package account_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// singleAllowAll declares one account and allows every decision, so only
// account's own single-user refusals stand.
type singleAllowAll struct{}

func (singleAllowAll) SingleUser() bool { return true }

func (singleAllowAll) Authorize(context.Context, account.Decision) error { return nil }

// singleRefusingAdds declares one account, refuses every user-adding
// operation, and is RolePolicy otherwise.
type singleRefusingAdds struct{}

func (singleRefusingAdds) SingleUser() bool { return true }

func (singleRefusingAdds) Authorize(ctx context.Context, d account.Decision) error {
	if (d.Op == account.OpCreateUser && d.Via != account.ViaSetup) || d.Op == account.OpInvite {
		return &account.PolicyError{Op: d.Op, Reason: "custom_refused"}
	}
	return account.RolePolicy{}.Authorize(ctx, d)
}

// flippingPolicy is RolePolicy whose declaration is whatever single holds
// when asked.
type flippingPolicy struct{ single *atomic.Bool }

func (p flippingPolicy) SingleUser() bool { return p.single.Load() }

func (flippingPolicy) Authorize(ctx context.Context, d account.Decision) error {
	return account.RolePolicy{}.Authorize(ctx, d)
}

func singleUserPolicies() map[string]account.Policy {
	return map[string]account.Policy{
		"single_owner_policy": account.SingleOwnerPolicy{},
		"custom_allow_all":    singleAllowAll{},
		"custom_refusing":     singleRefusingAdds{},
	}
}

// TestSingleUserRefusals: "Across the parts", under a single-user Policy
// account refuses, before the Policy, every creation but setup, every
// invite, every invite acceptance and every enable, whatever the Policy
// answers, and writes nothing.
func TestSingleUserRefusals(t *testing.T) {
	t.Parallel()
	for name, pol := range singleUserPolicies() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fs := newFaultStore()
			f := newFixture(t, options{store: fs, edit: func(c *account.Config) { c.Policy = pol }})
			owner := mustOwner(t, f.mem, "owner")
			extra := storeUser(t, f.mem, access.User{Username: "extra", Role: access.RoleUser, PasswordHash: someHash, CreatedAt: t0})
			plaintext, invite := access.NewOneTimeToken(access.PurposeInvite, time.Hour, time.Now())
			invite.Role = access.RoleUser
			if err := f.mem.CreateOneTimeToken(t.Context(), invite); err != nil {
				t.Fatalf("CreateOneTimeToken: %v", err)
			}
			pr := f.sessionPrincipal(t, owner, time.Now())
			for _, tc := range []struct {
				run  func() error
				name string
			}{
				{name: "create_by_owner", run: func() error {
					_, err := f.svc.CreateUser(t.Context(), account.As(pr), account.NewUser{Username: "second"})
					return err
				}},
				{name: "create_out_of_band", run: func() error {
					_, err := f.svc.CreateUser(t.Context(), account.OutOfBand("socket"), account.NewUser{Username: "second"})
					return err
				}},
				{name: "invite", run: func() error {
					_, err := f.svc.CreateInvite(t.Context(), pr, access.RoleUser, 0)
					return err
				}},
				{name: "accept_a_stored_invite", run: func() error {
					_, err := f.svc.AcceptInvitePassword(t.Context(), localClient, account.AcceptInvite{Token: plaintext, Username: "newbie", Password: access.NewSecret(goodPassword)})
					return err
				}},
				{name: "enable_a_disabled_account", run: func() error {
					_, err := f.svc.UpdateUser(t.Context(), pr, extra.ID, account.UserChange{Enabled: new(true)})
					return err
				}},
			} {
				fs.resetRecord()
				if err := tc.run(); reason(err) != account.ReasonSingleOwner {
					t.Errorf("%s = %v, want single_owner", tc.name, err)
				}
				if ws := writesOf(fs); len(ws) != 0 {
					t.Errorf("%s wrote %v", tc.name, ws)
				}
			}
			if n, err := f.mem.UserCount(t.Context()); err != nil || n != 2 {
				t.Errorf("UserCount = %d, %v; want the owner and the disabled account alone", n, err)
			}
			if u := stored(t, f, extra.ID); u.Enabled {
				t.Error("the disabled account was enabled")
			}
		})
	}
}

// TestSingleUserDeclarationReadOnce: "Across the parts", New reads
// SingleUser once; a Policy whose answer flips after New changes no row.
func TestSingleUserDeclarationReadOnce(t *testing.T) {
	t.Parallel()
	for _, start := range []bool{true, false} {
		t.Run(map[bool]string{true: "single_then_multi", false: "multi_then_single"}[start], func(t *testing.T) {
			t.Parallel()
			single := &atomic.Bool{}
			single.Store(start)
			f := newFixture(t, options{edit: func(c *account.Config) { c.Policy = flippingPolicy{single: single} }})
			single.Store(!start)
			owner := mustOwner(t, f.mem, "owner")
			_, err := f.svc.CreateUser(t.Context(), account.As(f.sessionPrincipal(t, owner, time.Now())), account.NewUser{Username: "second"})
			switch {
			case start && reason(err) != account.ReasonSingleOwner:
				t.Errorf("CreateUser after the answer flipped to multi-user = %v, want single_owner", err)
			case !start && err != nil:
				t.Errorf("CreateUser after the answer flipped to single-user = %v, want a user", err)
			}
			if _, err := f.svc.Owner(t.Context()); start == errors.Is(err, account.ErrNotSingleUser) {
				t.Errorf("Owner = %v, want the declaration New kept", err)
			}
		})
	}
}

// TestNewSingleUserStore: "Across the parts" and design 5.2, a single-user
// store with users fits only with exactly one enabled account, an admin;
// otherwise New refuses with one error naming what it found and one
// repair, matching ErrNoOwner when no enabled account is an admin. A
// fitting store leaves one owner flag, journalled by "migration".
func TestNewSingleUserStore(t *testing.T) {
	t.Parallel()
	admin := func(name string, enabled bool) access.User {
		return access.User{Username: name, Role: access.RoleAdmin, Enabled: enabled, CreatedAt: t0}
	}
	user := func(name string, enabled bool) access.User {
		return access.User{Username: name, Role: access.RoleUser, Enabled: enabled, PasswordHash: someHash, CreatedAt: t0}
	}
	for _, tc := range []struct {
		name    string
		users   []access.User
		found   string // what the error names; empty: New starts
		noOwner bool
	}{
		{name: "two_enabled_admins", users: []access.User{admin("a", true), admin("b", true)}, found: "2 enabled accounts, 2 of them admins"},
		{name: "admin_and_user", users: []access.User{admin("a", true), user("u", true)}, found: "2 enabled accounts, one of them an admin"},
		{name: "two_enabled_users", users: []access.User{user("u", true), user("v", true)}, found: "2 enabled accounts, none of them an admin", noOwner: true},
		{name: "one_enabled_user", users: []access.User{user("u", true), admin("a", false)}, found: "1 enabled account, none of them an admin", noOwner: true},
		{name: "all_disabled", users: []access.User{admin("a", false), user("u", false)}, found: "0 enabled accounts, none of them an admin", noOwner: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, options{edit: func(c *account.Config) { c.Policy = account.SingleOwnerPolicy{} }})
			for i := range tc.users {
				storeUser(t, f.mem, tc.users[i])
			}
			_, err := restart(t, f)
			if err == nil || !strings.Contains(err.Error(), tc.found) || !strings.Contains(err.Error(), "keep one account") || errors.Is(err, account.ErrNoOwner) != tc.noOwner {
				t.Errorf("New = %v, want one error naming %q and the repair, ErrNoOwner %t", err, tc.found, tc.noOwner)
			}
			if got := ownerNames(t, f.mem); len(got) != 0 || len(ownerEntries(t, f.mem)) != 0 {
				t.Errorf("a refused New marked %v", got)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		owner access.User
	}{
		{name: "oidc_only_admin", owner: access.User{Username: "a", Role: access.RoleAdmin, Enabled: true, CreatedAt: t0, OIDC: access.OIDCIdentity{Issuer: "https://idp.example", Subject: "s"}}},
		{name: "password_admin", owner: access.User{Username: "a", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash, CreatedAt: t0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, options{edit: func(c *account.Config) { c.Policy = account.SingleOwnerPolicy{} }})
			storeUser(t, f.mem, tc.owner)
			if _, err := restart(t, f); err != nil {
				t.Fatalf("New = %v", err)
			}
			entries := ownerEntries(t, f.mem)
			if got := ownerNames(t, f.mem); !slices.Equal(got, []string{"a"}) || len(entries) != 1 || entries[0].Detail != "" {
				t.Errorf("owners %v, entries %+v; want a marked with one plain owner_set", got, entries)
			}
		})
	}
	t.Run("disabled_owner_flag", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newFixture(t, options{store: fs, edit: func(c *account.Config) { c.Policy = account.SingleOwnerPolicy{} }})
		old := storeUser(t, f.mem, access.User{Username: "old", Role: access.RoleAdmin, Owner: true, PasswordHash: someHash, CreatedAt: t0})
		now := storeUser(t, f.mem, access.User{Username: "now", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash, CreatedAt: t0.Add(time.Hour)})
		svc, err := restart(t, f)
		if err != nil {
			t.Fatalf("New = %v", err)
		}
		if got := ownerNames(t, f.mem); !slices.Equal(got, []string{"now"}) {
			t.Errorf("owners = %v, want the enabled admin alone", got)
		}
		var got []string
		for _, e := range ownerEntries(t, f.mem) {
			if e.Event.Actor.OutOfBand == "migration" {
				got = append(got, string(e.Event.Kind)+":"+map[int64]string{old.ID: "old", now.ID: "now"}[e.Event.UserID])
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, []string{"owner_removed:old", "owner_set:now"}) {
			t.Errorf("migration entries = %v, want owner_removed for old and owner_set for now", got)
		}
		if u, err := svc.Owner(t.Context()); err != nil || u.ID != now.ID {
			t.Errorf("Owner = %v, %v; want now", u, err)
		}
		fs.resetRecord()
		before := len(logOf(t, f.mem))
		if _, err := restart(t, f); err != nil {
			t.Fatalf("second New = %v", err)
		}
		// New's failure-record sweep writes on every start; no user row may.
		if ws := writesOf(fs); slices.Contains(ws, "UpdateUser") || len(logOf(t, f.mem)) != before {
			t.Errorf("a second start wrote %v and journalled %d entries, want no user write and no entry", ws, len(logOf(t, f.mem))-before)
		}
	})
}

// TestServiceOwner: "Across the parts", Owner answers the one enabled
// admin when it alone carries the flag, ErrNotFound before setup, New's
// error or the restart error on a store changed under it, and
// ErrNotSingleUser under a multi-user Policy.
func TestServiceOwner(t *testing.T) {
	t.Parallel()
	setUp := func(t *testing.T) (*fixture, *access.User) {
		t.Helper()
		f := newFixture(t, options{rules: noSetupToken, edit: func(c *account.Config) { c.Policy = account.SingleOwnerPolicy{} }})
		if u, err := f.svc.Owner(t.Context()); !errors.Is(err, account.ErrNotFound) || u != nil {
			t.Errorf("Owner before setup = %v, %v; want ErrNotFound and no user", u, err)
		}
		in, err := f.svc.SetupWithPassword(t.Context(), localClient, account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)})
		if err != nil {
			t.Fatalf("SetupWithPassword = %v", err)
		}
		if u, err := f.svc.Owner(t.Context()); err != nil || u.ID != in.User.ID {
			t.Errorf("Owner after setup = %v, %v; want the setup account", u, err)
		}
		return f, in.User
	}
	t.Run("edited_to_two_enabled", func(t *testing.T) {
		t.Parallel()
		f, _ := setUp(t)
		storeUser(t, f.mem, access.User{Username: "second", Role: access.RoleUser, Enabled: true, CreatedAt: t0})
		u, err := f.svc.Owner(t.Context())
		if u != nil || err == nil || !strings.Contains(err.Error(), "2 enabled accounts") || errors.Is(err, account.ErrNoOwner) {
			t.Errorf("Owner = %v, %v; want New's error naming two enabled accounts", u, err)
		}
	})
	t.Run("edited_to_move_the_admin", func(t *testing.T) {
		t.Parallel()
		f, first := setUp(t)
		first.Enabled = false
		if err := f.mem.UpdateUser(t.Context(), first); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		second := storeUser(t, f.mem, access.User{Username: "second", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash, CreatedAt: t0})
		u, err := f.svc.Owner(t.Context())
		if u != nil || !errors.Is(err, account.ErrNoOwner) || !strings.Contains(err.Error(), "restart") {
			t.Errorf("Owner = %v, %v; want the restart error matching ErrNoOwner", u, err)
		}
		if got := ownerNames(t, f.mem); !slices.Equal(got, []string{"owner"}) {
			t.Errorf("Owner wrote: owners are %v", got)
		}
		svc, err := restart(t, f)
		if err != nil {
			t.Fatalf("New = %v", err)
		}
		if u, err := svc.Owner(t.Context()); err != nil || u.ID != second.ID {
			t.Errorf("Owner after a restart = %v, %v; want the second admin", u, err)
		}
	})
	t.Run("multi_user", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		mustOwner(t, f.mem, "one")
		if _, err := f.svc.Owner(t.Context()); !errors.Is(err, account.ErrNotSingleUser) {
			t.Errorf("Owner with one owner = %v, want ErrNotSingleUser", err)
		}
		mustOwner(t, f.mem, "two")
		if _, err := f.svc.Owner(t.Context()); !errors.Is(err, account.ErrNotSingleUser) {
			t.Errorf("Owner with two owners = %v, want ErrNotSingleUser", err)
		}
	})
}

// TestSingleUserSetOwner: design 5.2, SingleOwnerPolicy refuses SetOwner
// for every actor, since its one account is the owner New marks.
func TestSingleUserSetOwner(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{edit: func(c *account.Config) { c.Policy = account.SingleOwnerPolicy{} }})
	owner := mustOwner(t, f.mem, "owner")
	for name, a := range map[string]account.Actor{"owner": account.As(f.sessionPrincipal(t, owner, time.Now())), "out_of_band": account.OutOfBand("socket")} {
		if _, err := f.svc.SetOwner(t.Context(), a, owner.ID, false); reason(err) != account.ReasonSingleOwner {
			t.Errorf("%s: SetOwner = %v, want single_owner", name, err)
		}
	}
}
