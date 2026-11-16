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
		in, err := completed(f.svc.SetupWithPassword(t.Context(), localClient, account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)}))
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

// appPolicy is one Policy a row runs under, with the declaration New keeps
// from it.
type appPolicy struct {
	policy account.Policy
	name   string
	single bool
}

// appPolicies are RolePolicy, SingleOwnerPolicy and the two custom
// single-user Policies "Across the parts" names: one refusing every
// user-adding operation, one allowing admin create and invites.
func appPolicies() []appPolicy {
	ps := []appPolicy{{name: "role_policy", policy: account.RolePolicy{}}}
	for name, pol := range singleUserPolicies() {
		ps = append(ps, appPolicy{name: name, policy: pol, single: true})
	}
	return ps
}

// appWorld is one app under a Policy, with password, passkeys and OIDC
// wired: an owner holding a password and linked to the rig's identity, and
// a disabled regular account, which a single-user store admits.
type appWorld struct {
	*oidcFixture
	fs     *faultStore
	owner  *access.User
	extra  *access.User
	ownerP access.Principal
	rules  atomic.Pointer[account.Rules]
}

func newAppWorld(t *testing.T, pol account.Policy) *appWorld {
	t.Helper()
	w := &appWorld{fs: newFaultStore()}
	w.rules.Store(&account.Rules{})
	w.oidcFixture = newOIDCFixture(t, rigFor(t, "owner-subject"), pwOptions{
		store: w.fs,
		rules: func() account.Rules { return *w.rules.Load() },
		edit:  func(c *account.Config) { c.Policy = pol },
	})
	w.owner = passwordOwner(t, w.pwFixture, "root")
	linkIdentity(t, w.mem, w.owner, w.rig.identity())
	w.extra = passwordUser(t, w.mem, w.hasher, "extra", goodPassword)
	w.extra.Enabled = false
	if err := w.mem.UpdateUser(t.Context(), w.extra); err != nil {
		t.Fatalf("UpdateUser(extra): %v", err)
	}
	w.ownerP = w.sessionPrincipal(t, w.owner, time.Now())
	return w
}

// multiWorld is an appWorld under RolePolicy with an enabled regular
// account bob and an enabled admin carol who is no owner, each holding a
// password, and their sessions.
func multiWorld(t *testing.T) (w *appWorld, bob, carol access.Principal) {
	t.Helper()
	w = newAppWorld(t, account.RolePolicy{})
	b := passwordUser(t, w.mem, w.hasher, "bob", goodPassword)
	c := passwordUser(t, w.mem, w.hasher, "carol", goodPassword)
	c.Role = access.RoleAdmin
	if err := w.mem.UpdateUser(t.Context(), c); err != nil {
		t.Fatalf("UpdateUser(carol): %v", err)
	}
	return w, w.sessionPrincipal(t, b, time.Now()), w.sessionPrincipal(t, c, time.Now())
}

// declarationRows are the rows of "Across the parts" the library enforces
// from the kept declaration, each run under every appPolicy.
var declarationRows = []struct {
	run  func(*testing.T, appPolicy)
	name string
}{
	{name: "creating_accounts", run: rowCreatingAccounts},
	{name: "setup", run: rowSetup},
	{name: "reading_the_owner", run: rowReadingTheOwner},
	{name: "owner_marking", run: rowOwnerMarking},
	{name: "unknown_identity", run: rowUnknownIdentity},
	{name: "provisioning", run: rowProvisioning},
	{name: "registration", run: rowRegistration},
	{name: "sso_mode", run: rowSSOMode},
	{name: "single_user", run: rowSingleUser},
	{name: "anonymous_bounds", run: rowAnonymousBounds},
	{name: "same_everywhere", run: rowSameEverywhere},
}

// TestSingleAndMultiUser is "Across the parts"' Tests bullet: each row
// account enforces from the declaration answers by the declaration alone,
// so the two custom single-user Policies answer as SingleOwnerPolicy does,
// and RolePolicy answers as a multi-user app.
func TestSingleAndMultiUser(t *testing.T) {
	t.Parallel()
	for _, ap := range appPolicies() {
		t.Run(ap.name, func(t *testing.T) {
			t.Parallel()
			for _, row := range declarationRows {
				t.Run(row.name, func(t *testing.T) {
					t.Parallel()
					row.run(t, ap)
				})
			}
		})
	}
}

// rowCreatingAccounts: a single-user app refuses, before the Policy and
// writing nothing, every creation but setup, every invite, the acceptance
// of an invite stored earlier and every enable; a multi-user app adds the
// account each time.
func rowCreatingAccounts(t *testing.T, ap appPolicy) {
	w := newAppWorld(t, ap.policy)
	plaintext, invite := access.NewOneTimeToken(access.PurposeInvite, time.Hour, time.Now())
	invite.Role = access.RoleUser
	if err := w.mem.CreateOneTimeToken(t.Context(), invite); err != nil {
		t.Fatalf("CreateOneTimeToken: %v", err)
	}
	for _, tc := range []struct {
		run  func() error
		name string
	}{
		{name: "create_by_owner", run: func() error {
			_, err := w.svc.CreateUser(t.Context(), account.As(w.ownerP), account.NewUser{Username: "second"})
			return err
		}},
		{name: "create_out_of_band", run: func() error {
			_, err := w.svc.CreateUser(t.Context(), socket, account.NewUser{Username: "third"})
			return err
		}},
		{name: "invite", run: func() error {
			_, err := w.svc.CreateInvite(t.Context(), w.ownerP, access.RoleUser, 0)
			return err
		}},
		{name: "accept_a_stored_invite", run: func() error {
			_, err := w.svc.AcceptInvitePassword(t.Context(), localClient, account.AcceptInvite{Token: plaintext, Username: "newbie", Password: access.NewSecret(goodPassword)})
			return err
		}},
		{name: "enable_a_disabled_account", run: func() error {
			_, err := w.svc.UpdateUser(t.Context(), w.ownerP, w.extra.ID, account.UserChange{Enabled: new(true)})
			return err
		}},
	} {
		w.fs.resetRecord()
		err := tc.run()
		switch {
		case ap.single && reason(err) != account.ReasonSingleOwner:
			t.Errorf("%s = %v, want single_owner", tc.name, err)
		case ap.single && len(writesOf(w.fs)) != 0:
			t.Errorf("%s wrote %v", tc.name, writesOf(w.fs))
		case !ap.single && err != nil:
			t.Errorf("%s = %v, want it allowed", tc.name, err)
		}
	}
	enabled := 0
	users, err := w.mem.ListUsers(t.Context())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for i := range users {
		if users[i].Enabled {
			enabled++
		}
	}
	// single: the owner; multi: the owner, second, third, newbie and extra.
	if want := map[bool]int{true: 1, false: 5}[ap.single]; enabled != want {
		t.Errorf("enabled accounts = %d, want %d", enabled, want)
	}
}

// rowSetup: first setup creates the owner under every Policy.
func rowSetup(t *testing.T, ap appPolicy) {
	f := newFixture(t, options{rules: noSetupToken, edit: func(c *account.Config) { c.Policy = ap.policy }})
	in, err := completed(f.svc.SetupWithPassword(t.Context(), localClient, account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)}))
	if err != nil {
		t.Fatalf("SetupWithPassword = %v", err)
	}
	if got := ownerNames(t, f.mem); !slices.Equal(got, []string{"owner"}) || in.User.Role != access.RoleAdmin {
		t.Errorf("owners %v, role %s; want the setup account an owning admin", got, in.User.Role)
	}
}

// rowReadingTheOwner: Service.Owner answers the owner in a single-user app
// and ErrNotSingleUser in a multi-user one.
func rowReadingTheOwner(t *testing.T, ap appPolicy) {
	w := newAppWorld(t, ap.policy)
	u, err := w.svc.Owner(t.Context())
	switch {
	case ap.single && (err != nil || u.ID != w.owner.ID):
		t.Errorf("Owner = %v, %v; want root", u, err)
	case !ap.single && (u != nil || !errors.Is(err, account.ErrNotSingleUser)):
		t.Errorf("Owner = %v, %v; want ErrNotSingleUser and no user", u, err)
	}
}

// rowOwnerMarking: over two enabled admins and no flag, New refuses a
// single-user store and marks a multi-user store's earliest admin.
func rowOwnerMarking(t *testing.T, ap appPolicy) {
	f := newFixture(t, options{edit: func(c *account.Config) { c.Policy = ap.policy }})
	storeUser(t, f.mem, access.User{Username: "a", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash, CreatedAt: t0})
	storeUser(t, f.mem, access.User{Username: "b", Role: access.RoleAdmin, Enabled: true, PasswordHash: someHash, CreatedAt: t0.Add(time.Hour)})
	_, err := restart(t, f)
	owners := ownerNames(t, f.mem)
	switch {
	case ap.single && (err == nil || !strings.Contains(err.Error(), "2 enabled accounts") || len(owners) != 0):
		t.Errorf("New = %v, owners %v; want the store refused and nobody marked", err, owners)
	case !ap.single && (err != nil || !slices.Equal(owners, []string{"a"})):
		t.Errorf("New = %v, owners %v; want a marked", err, owners)
	}
}

// rowUnknownIdentity: design 5.4, an identity no account links is refused
// as invalid credentials in a single-user app, with no pending link and
// nothing journalled, and answers a pending link in a multi-user one.
func rowUnknownIdentity(t *testing.T, ap appPolicy) {
	w := newAppWorld(t, ap.policy)
	flow, claims := rigFor(t, "other-subject").signInFlow(t)
	out, err := w.complete(t, localClient, flow, claims)
	switch {
	case ap.single && (!errors.Is(err, account.ErrInvalidCredentials) || out.Kind == account.OutcomeNotLinked || len(w.events.all()) != 0):
		t.Errorf("OIDCComplete = %+v, %v, events %v; want ErrInvalidCredentials, no pending link, nothing journalled", out, err, w.events.all())
	case !ap.single && (err != nil || out.Kind != account.OutcomeNotLinked):
		t.Errorf("OIDCComplete = %+v, %v; want a pending link", out, err)
	}
}

// requireRulesRefused is the single-user answer of a setting the kept
// declaration refuses: CheckRules refuses field, and so does every
// operation once a reload publishes it; a multi-user app takes it.
func requireRulesRefused(t *testing.T, ap appPolicy, r account.Rules, field string) {
	t.Helper()
	w := newAppWorld(t, ap.policy)
	var re *account.RulesError
	checked := w.svc.CheckRules(t.Context(), r)
	w.rules.Store(&r)
	_, used := w.svc.State(t.Context(), localClient)
	switch {
	case ap.single && (!errors.As(checked, &re) || re.Field != field || !errors.As(used, &re) || re.Field != field):
		t.Errorf("CheckRules = %v, State after the reload = %v; want a RulesError on %s from both", checked, used, field)
	case !ap.single && (checked != nil || used != nil):
		t.Errorf("CheckRules = %v, State after the reload = %v; want both nil", checked, used)
	}
}

// rowProvisioning: provisioning is refused by the kept declaration.
func rowProvisioning(t *testing.T, ap appPolicy) {
	requireRulesRefused(t, ap, account.Rules{Provisioning: account.Provisioning{Enabled: true}}, "Provisioning")
}

// rowRegistration: design 4.17, either registration mode is refused by
// the kept declaration.
func rowRegistration(t *testing.T, ap appPolicy) {
	for _, mode := range []account.RegistrationMode{account.RegistrationOpen, account.RegistrationApproval} {
		requireRulesRefused(t, ap, account.Rules{Registration: mode}, "Registration")
	}
}

// rowSSOMode: design 5.3, a single-user app keeps SSOAlongside, refusing a
// change with single_owner and a stored contradiction at New; a
// multi-user app takes any mode.
func rowSSOMode(t *testing.T, ap appPolicy) {
	w := newAppWorld(t, ap.policy)
	err := w.svc.ApplySSO(t.Context(), socket, account.SSOForLinked)
	mode, _ := modeOf(t, w.mem)
	switch {
	case ap.single && (reason(err) != account.ReasonSingleOwner || mode != account.SSOAlongside):
		t.Errorf("ApplySSO(for_linked) = %v, stored %s; want single_owner and alongside kept", err, mode)
	case !ap.single && (err != nil || mode != account.SSOForLinked):
		t.Errorf("ApplySSO(for_linked) = %v, stored %s; want for_linked", err, mode)
	}
	storeMode(t, w.mem, account.SSOForLinked)
	_, err = restart(t, w.fixture)
	switch {
	case ap.single && (err == nil || !strings.Contains(err.Error(), "single-user Policy admits only alongside")):
		t.Errorf("New over a stored for_linked = %v, want the stored mode named", err)
	case !ap.single && err != nil:
		t.Errorf("New over a stored for_linked = %v, want it to start", err)
	}
}

// rowSingleUser: Me.SingleUser, MeResponse.single_user on the wire, is
// the kept declaration.
func rowSingleUser(t *testing.T, ap appPolicy) {
	w := newAppWorld(t, ap.policy)
	if me, err := w.svc.Me(t.Context(), w.ownerP); err != nil || me.SingleUser != ap.single {
		t.Errorf("Me.SingleUser = %t, %v; want %t", me.SingleUser, err, ap.single)
	}
}

// rowAnonymousBounds: a single-user app's anonymous state stays within the
// bounds the declaration sets, registration off, sso alongside and no
// temporary_password_https_only from SSOOnly, each a value a multi-user
// app also gives; a multi-user app reaches the values past them.
func rowAnonymousBounds(t *testing.T, ap appPolicy) {
	w := newAppWorld(t, ap.policy)
	plain := plainClientOf()
	w.rules.Store(&account.Rules{Registration: account.RegistrationOpen})
	st, err := w.svc.State(t.Context(), plain)
	switch {
	case ap.single && err == nil:
		t.Errorf("State under a published registration mode = %+v, want no answer", st)
	case !ap.single && (err != nil || st.Registration != account.RegistrationOpen):
		t.Errorf("State.Registration = %s, %v; want open", st.Registration, err)
	}
	w.rules.Store(&account.Rules{})
	applied := w.svc.ApplySSO(t.Context(), socket, account.SSOOnly)
	st, err = w.svc.State(t.Context(), plain)
	if err != nil {
		t.Fatalf("State = %v", err)
	}
	switch {
	case ap.single && (applied == nil || st.SSO != account.SSOAlongside || st.Registration != account.RegistrationOff || st.TemporaryPasswordHTTPSOnly):
		t.Errorf("ApplySSO(only) = %v, then plain State %+v; want the change refused and alongside, off, no https_only", applied, st)
	case !ap.single && (applied != nil || st.SSO != account.SSOOnly || !st.TemporaryPasswordHTTPSOnly):
		t.Errorf("ApplySSO(only) = %v, then plain State %+v; want only and https_only", applied, st)
	}
}

// rowSameEverywhere: the rows the table marks the same answer alike under
// every Policy: RequireSecondFactor and OIDCAdmission are valid settings,
// TOTP stays an owner's choice, and the owner mints its own key.
func rowSameEverywhere(t *testing.T, ap appPolicy) {
	w := newAppWorld(t, ap.policy)
	for name, r := range map[string]account.Rules{
		"require_second_factor": {RequireSecondFactor: true},
		"oidc_admission":        {OIDCAdmission: account.OIDCAdmission{Claim: "groups", AllowedValues: []string{"staff"}}},
	} {
		if err := w.svc.CheckRules(t.Context(), r); err != nil {
			t.Errorf("CheckRules(%s) = %v, want nil", name, err)
		}
	}
	if _, err := w.svc.CreateAPIKey(t.Context(), account.As(w.ownerP), w.owner.ID, account.NewKey{Label: "own"}); err != nil {
		t.Errorf("the owner's own key = %v, want a key", err)
	}
}

// TestPolicyRowsSingleAndMulti is "Across the parts"' rows the Policy
// decides, each cell checked under SingleOwnerPolicy (single-user) and
// RolePolicy (multi-user).
func TestPolicyRowsSingleAndMulti(t *testing.T) {
	t.Parallel()
	refusedFor := func(t *testing.T, what string, err error, want string) {
		t.Helper()
		if reason(err) != want {
			t.Errorf("%s = %v, want %s", what, err, want)
		}
	}
	allowed := func(t *testing.T, what string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s = %v, want it allowed", what, err)
		}
	}
	t.Run("set_owner", func(t *testing.T) {
		t.Parallel()
		s := newAppWorld(t, account.SingleOwnerPolicy{})
		_, err := s.svc.SetOwner(t.Context(), account.As(s.ownerP), s.owner.ID, false)
		refusedFor(t, "single: the owner's SetOwner", err, account.ReasonSingleOwner)
		_, err = s.svc.SetOwner(t.Context(), socket, s.owner.ID, false)
		refusedFor(t, "single: an out-of-band SetOwner", err, account.ReasonSingleOwner)
		m, _, carol := multiWorld(t)
		_, err = m.svc.SetOwner(t.Context(), account.As(carol), m.owner.ID, false)
		refusedFor(t, "multi: SetOwner by an admin who is no owner", err, account.ReasonNotOwner)
		_, err = m.svc.SetOwner(t.Context(), account.As(m.ownerP), carol.User.ID, true)
		allowed(t, "multi: the owner making carol an owner", err)
	})
	t.Run("temporary_password", func(t *testing.T) {
		t.Parallel()
		s := newAppWorld(t, account.SingleOwnerPolicy{})
		_, err := s.svc.SetTemporaryPassword(t.Context(), account.As(s.ownerP), s.extra.ID, account.TemporaryPasswordOptions{})
		refusedFor(t, "single: the owner's issue", err, account.ReasonOutOfBandOnly)
		_, err = s.svc.SetTemporaryPassword(t.Context(), socket, s.owner.ID, account.TemporaryPasswordOptions{})
		allowed(t, "single: an out-of-band issue for the owner", err)
		m, bob, carol := multiWorld(t)
		_, err = m.svc.SetTemporaryPassword(t.Context(), account.As(m.ownerP), bob.User.ID, account.TemporaryPasswordOptions{})
		allowed(t, "multi: an admin's issue for bob", err)
		_, err = m.svc.SetTemporaryPassword(t.Context(), account.As(carol), m.owner.ID, account.TemporaryPasswordOptions{})
		refusedFor(t, "multi: an issue for the owner by an admin who is no owner", err, account.ReasonOwnerTarget)
		_, err = m.svc.SetTemporaryPassword(t.Context(), socket, m.owner.ID, account.TemporaryPasswordOptions{})
		allowed(t, "multi: an out-of-band issue for the owner", err)
	})
	t.Run("reset_second_factor", func(t *testing.T) {
		t.Parallel()
		s := newAppWorld(t, account.SingleOwnerPolicy{})
		storeTOTP(t, s.mem, s.owner)
		refusedFor(t, "single: the owner's reset", s.svc.ResetSecondFactor(t.Context(), account.As(s.ownerP), s.extra.ID), account.ReasonOutOfBandOnly)
		allowed(t, "single: an out-of-band reset of the owner", s.svc.ResetSecondFactor(t.Context(), socket, s.owner.ID))
		m, bob, carol := multiWorld(t)
		storeTOTP(t, m.mem, bob.User)
		storeTOTP(t, m.mem, m.owner)
		allowed(t, "multi: an admin's reset of bob", m.svc.ResetSecondFactor(t.Context(), account.As(m.ownerP), bob.User.ID))
		refusedFor(t, "multi: a reset of the owner by an admin who is no owner", m.svc.ResetSecondFactor(t.Context(), account.As(carol), m.owner.ID), account.ReasonOwnerTarget)
		allowed(t, "multi: an out-of-band reset of the owner", m.svc.ResetSecondFactor(t.Context(), socket, m.owner.ID))
	})
	t.Run("delete_disable_demote", func(t *testing.T) {
		t.Parallel()
		admin := access.RoleAdmin
		s := newAppWorld(t, account.SingleOwnerPolicy{})
		refusedFor(t, "single: deleting an account", s.svc.DeleteUser(t.Context(), s.ownerP, s.extra.ID), account.ReasonSingleOwner)
		_, err := s.svc.UpdateUser(t.Context(), s.ownerP, s.extra.ID, account.UserChange{Role: &admin})
		refusedFor(t, "single: a role change", err, account.ReasonSingleOwner)
		m, bob, carol := multiWorld(t)
		_, err = m.svc.UpdateUser(t.Context(), m.ownerP, bob.User.ID, account.UserChange{Role: &admin})
		allowed(t, "multi: the owner promoting bob", err)
		_, err = m.svc.UpdateUser(t.Context(), carol, m.owner.ID, account.UserChange{Enabled: new(false)})
		refusedFor(t, "multi: disabling the owner by an admin who is no owner", err, account.ReasonOwnerTarget)
		refusedFor(t, "multi: deleting the owner by an admin who is no owner", m.svc.DeleteUser(t.Context(), carol, m.owner.ID), account.ReasonOwnerTarget)
		allowed(t, "multi: the owner deleting an account", m.svc.DeleteUser(t.Context(), m.ownerP, m.extra.ID))
	})
	t.Run("every_users_keys", func(t *testing.T) {
		t.Parallel()
		s := newAppWorld(t, account.SingleOwnerPolicy{})
		_, err := s.svc.AllAPIKeys(t.Context(), account.As(s.ownerP))
		allowed(t, "single: the owner listing every key", err)
		_, err = s.svc.AllAPIKeys(t.Context(), socket)
		allowed(t, "single: listing every key out of band", err)
		m, bob, carol := multiWorld(t)
		_, err = m.svc.AllAPIKeys(t.Context(), account.As(carol))
		allowed(t, "multi: an admin listing every key", err)
		_, err = m.svc.AllAPIKeys(t.Context(), account.As(bob))
		refusedFor(t, "multi: a regular user listing every key", err, account.ReasonNotAdmin)
	})
	t.Run("key_for_another_user", func(t *testing.T) {
		t.Parallel()
		s := newAppWorld(t, account.SingleOwnerPolicy{})
		_, err := s.svc.CreateAPIKey(t.Context(), socket, s.owner.ID, account.NewKey{Label: "socket"})
		allowed(t, "single: an out-of-band key for the owner", err)
		_, err = s.svc.CreateAPIKey(t.Context(), socket, s.extra.ID, account.NewKey{Label: "socket"})
		refusedFor(t, "single: an out-of-band key for another account", err, account.ReasonTargetNotEligible)
		m, bob, _ := multiWorld(t)
		_, err = m.svc.CreateAPIKey(t.Context(), socket, bob.User.ID, account.NewKey{Label: "socket"})
		allowed(t, "multi: an out-of-band key for bob", err)
	})
	t.Run("unlink_for_someone_else", func(t *testing.T) {
		t.Parallel()
		s := newAppWorld(t, account.SingleOwnerPolicy{})
		refusedFor(t, "single: the owner unlinking another account", s.svc.AdminUnlinkOIDC(t.Context(), account.As(s.ownerP), s.extra.ID), account.ReasonOutOfBandOnly)
		allowed(t, "single: an out-of-band unlink of the owner", s.svc.AdminUnlinkOIDC(t.Context(), socket, s.owner.ID))
		m, bob, carol := multiWorld(t)
		linkIdentity(t, m.mem, storedUser(t, m.mem, bob.User.ID), access.OIDCIdentity{Issuer: oidcIssuer, Subject: "bob-subject"})
		refusedFor(t, "multi: an unlink of the owner by an admin who is no owner", m.svc.AdminUnlinkOIDC(t.Context(), account.As(carol), m.owner.ID), account.ReasonOwnerTarget)
		allowed(t, "multi: an admin unlinking bob", m.svc.AdminUnlinkOIDC(t.Context(), account.As(m.ownerP), bob.User.ID))
		allowed(t, "multi: an out-of-band unlink of the owner", m.svc.AdminUnlinkOIDC(t.Context(), socket, m.owner.ID))
	})
}
