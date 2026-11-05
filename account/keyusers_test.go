package account_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// attributionsOf is userID's stored records, oldest first.
func attributionsOf(t testing.TB, f *fixture, userID int64) []access.KeyAttribution {
	t.Helper()
	all, err := f.mem.ListKeyAttributions(t.Context())
	if err != nil {
		t.Fatalf("ListKeyAttributions: %v", err)
	}
	return slices.DeleteFunc(all, func(a access.KeyAttribution) bool { return a.UserID != userID })
}

// key mints a root key of root's from its session with scopes, then
// replaces pr with a fresh session, since the mint rotated it.
func (w *adminWorld) key(t *testing.T, in account.NewKey) minted {
	t.Helper()
	m := w.f.mint(t, account.As(w.pr), w.root.ID, in)
	w.pr = w.f.sessionPrincipal(t, w.root, access.SessionFull, time.Now())
	return m
}

func userIDs(rows []account.ListedUser) []int64 {
	ids := make([]int64, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.User.ID)
	}
	return ids
}

func TestKeyManagesUsers(t *testing.T) {
	t.Parallel()
	w := newAdminWorld(t, options{}, account.RolePolicy{})
	k := w.key(t, account.NewKey{Scopes: []string{scopeUsers}})
	ctx := t.Context()
	u1, err := w.f.svc.CreateUser(ctx, account.As(k.p), account.NewUser{Username: "Una", Password: access.NewSecret(goodPassword)})
	if err != nil || u1.Role != access.RoleUser || u1.Username != "una" {
		t.Fatalf("CreateUser from the key = %+v, %v; want RoleUser una", u1, err)
	}
	created := eventsOf(w.f.events, account.EventUserCreated)
	if len(created) != 1 || created[0].Actor.KeyID != k.key.ID || created[0].UserID != u1.ID {
		t.Errorf("EventUserCreated = %+v, want one naming the key", created)
	}
	if _, err := w.f.svc.CreateUser(ctx, account.As(k.p), account.NewUser{Username: "two words"}); !errors.As(err, new(*account.UsernameError)) {
		t.Errorf("an invalid name from the key = %v, want *UsernameError", err)
	}
	if _, err := w.f.svc.CreateUser(ctx, account.As(k.p), account.NewUser{Username: "pw", Password: access.NewSecret("password")}); !errors.As(err, new(*access.PasswordError)) {
		t.Errorf("a weak password from the key = %v, want *access.PasswordError", err)
	}
	u2, err := w.f.svc.CreateUser(ctx, account.As(k.p), account.NewUser{Username: "victor"})
	if err != nil {
		t.Fatalf("CreateUser(victor) = %v", err)
	}
	if got, err := w.f.svc.UpdateUser(ctx, k.p, u1.ID, account.UserChange{Enabled: new(false)}); err != nil || got.Enabled {
		t.Errorf("UpdateUser from the key = %+v, %v; want una disabled", got, err)
	}
	if err := w.f.svc.DeleteUser(ctx, k.p, u2.ID); err != nil {
		t.Errorf("DeleteUser from the key = %v", err)
	}
	if _, err := w.f.svc.CreateInvite(ctx, k.p, access.RoleUser, 0); err != nil {
		t.Errorf("CreateInvite from the key = %v", err)
	}
	if _, err := w.f.svc.IssueRecovery(ctx, account.As(k.p), w.alice.ID, 0); err != nil {
		t.Errorf("IssueRecovery from the key = %v", err)
	}
	if err := w.f.svc.RevokeAPIKey(ctx, w.pr, k.key.ID); err != nil {
		t.Fatalf("RevokeAPIKey = %v", err)
	}
	recs := attributionsOf(t, w.f, u1.ID)
	if len(recs) != 2 || recs[0].Action != access.AttributionCreated || !slices.Equal(recs[0].KeyLineage, []int64{k.key.ID}) {
		t.Errorf("una's records after the revocation = %+v, want created then disabled, with the key's path", recs)
	}
	rows, err := w.f.svc.Users(ctx, w.pr, account.UserFilter{AttributedToKey: k.key.ID})
	if err != nil || !slices.Equal(userIDs(rows), []int64{u1.ID}) {
		t.Errorf("Users attributed to the key = %v, %v; want una alone (victor is deleted)", userIDs(rows), err)
	}
	t.Run("scope_empty", func(t *testing.T) {
		f := newFixture(t, options{})
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		target := mustUser(t, f.mem, "alice", access.RoleUser)
		kp := f.keyPrincipal(t, admin, scopeUsers)
		for name, op := range map[string]func() error{
			"CreateUser": func() error {
				_, err := f.svc.CreateUser(t.Context(), account.As(kp), account.NewUser{Username: "x"})
				return err
			},
			"UpdateUser": func() error {
				_, err := f.svc.UpdateUser(t.Context(), kp, target.ID, account.UserChange{Enabled: new(false)})
				return err
			},
			"DeleteUser": func() error { return f.svc.DeleteUser(t.Context(), kp, target.ID) },
			"CreateInvite": func() error {
				_, err := f.svc.CreateInvite(t.Context(), kp, access.RoleUser, 0)
				return err
			},
			"IssueRecovery": func() error {
				_, err := f.svc.IssueRecovery(t.Context(), account.As(kp), target.ID, 0)
				return err
			},
		} {
			if err := op(); !errors.Is(err, account.ErrSessionRequired) {
				t.Errorf("%s from a key with ManageUsersScope empty = %v, want ErrSessionRequired", name, err)
			}
		}
	})
	t.Run("single_owner", func(t *testing.T) {
		g := newAdminWorld(t, options{}, account.SingleOwnerPolicy{})
		gk := g.key(t, account.NewKey{Scopes: []string{scopeUsers}})
		if _, err := g.f.svc.CreateUser(t.Context(), account.As(gk.p), account.NewUser{Username: "second"}); !errors.Is(err, account.ErrPolicyRefused) {
			t.Errorf("CreateUser from the owner's key under SingleOwnerPolicy = %v, want ErrPolicyRefused", err)
		}
	})
}

// allowAll is a Policy that allows every decision.
type allowAll struct{}

func (allowAll) Authorize(context.Context, account.Decision) error { return nil }

// refuseAll is a Policy that refuses every decision.
type refuseAll struct{}

func (refuseAll) Authorize(_ context.Context, d account.Decision) error {
	return &account.PolicyError{Op: d.Op, Reason: "refuse_all"}
}

func TestKeyNoAdminTarget(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		policy account.Policy
		name   string
		role   access.Role
	}{
		{name: "role_policy", policy: account.RolePolicy{}, role: access.RoleAdmin},
		{name: "allow_all", policy: allowAll{}, role: access.RoleAdmin},
		{name: "app_role", policy: allowAll{}, role: "editor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newAdminWorld(t, options{}, tc.policy)
			k := w.key(t, account.NewKey{Scopes: []string{scopeUsers}})
			high := mustUser(t, w.f.mem, "high", tc.role)
			off := mustUser(t, w.f.mem, "off", tc.role)
			off.Enabled = false
			if err := w.f.mem.UpdateUser(t.Context(), off); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
			ctx := t.Context()
			ops := map[string]func() error{
				"CreateUser": func() error {
					_, err := w.f.svc.CreateUser(ctx, account.As(k.p), account.NewUser{Username: "made", Role: tc.role})
					return err
				},
				"UpdateUser_promote": func() error {
					_, err := w.f.svc.UpdateUser(ctx, k.p, w.alice.ID, account.UserChange{Role: new(tc.role)})
					return err
				},
				"UpdateUser_demote": func() error {
					_, err := w.f.svc.UpdateUser(ctx, k.p, high.ID, account.UserChange{Role: new(access.RoleUser)})
					return err
				},
				"UpdateUser_disable": func() error {
					_, err := w.f.svc.UpdateUser(ctx, k.p, high.ID, account.UserChange{Enabled: new(false)})
					return err
				},
				"UpdateUser_enable": func() error {
					_, err := w.f.svc.UpdateUser(ctx, k.p, off.ID, account.UserChange{Enabled: new(true)})
					return err
				},
				"DeleteUser": func() error { return w.f.svc.DeleteUser(ctx, k.p, high.ID) },
				"CreateInvite": func() error {
					_, err := w.f.svc.CreateInvite(ctx, k.p, tc.role, 0)
					return err
				},
				"IssueRecovery": func() error {
					_, err := w.f.svc.IssueRecovery(ctx, account.As(k.p), high.ID, 0)
					return err
				},
			}
			for name, op := range ops {
				w.fs.resetRecord()
				events := len(w.f.events.all())
				if err := op(); reason(err) != "admin_target" {
					t.Errorf("%s = %v, want admin_target", name, err)
				}
				if ws := writesOf(w.fs); len(ws) != 0 {
					t.Errorf("%s wrote %v", name, ws)
				}
				if n := len(w.f.events.all()); n != events {
					t.Errorf("%s emitted %d events", name, n-events)
				}
			}
			if u := stored(t, w.f, high.ID); u == nil || u.Role != tc.role || !u.Enabled {
				t.Errorf("high changed: %+v", u)
			}
			ok := map[string]func() error{
				"CreateUser": func() error {
					_, err := w.f.svc.CreateUser(ctx, account.As(k.p), account.NewUser{Username: "plain"})
					return err
				},
				"UpdateUser": func() error {
					_, err := w.f.svc.UpdateUser(ctx, k.p, w.alice.ID, account.UserChange{Role: new(access.RoleUser), Enabled: new(false)})
					return err
				},
				"CreateInvite": func() error {
					_, err := w.f.svc.CreateInvite(ctx, k.p, access.RoleUser, 0)
					return err
				},
				"IssueRecovery": func() error {
					_, err := w.f.svc.IssueRecovery(ctx, account.As(k.p), w.alice.ID, 0)
					return err
				},
				"DeleteUser": func() error { return w.f.svc.DeleteUser(ctx, k.p, w.alice.ID) },
			}
			for _, name := range []string{"CreateUser", "UpdateUser", "CreateInvite", "IssueRecovery", "DeleteUser"} {
				if err := ok[name](); err != nil {
					t.Errorf("%s on a RoleUser = %v, want nil", name, err)
				}
			}
		})
	}
	t.Run("policy_first", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			policy         account.Policy
			name           string
			existing, gone string
		}{
			{name: "refused", policy: refuseAll{}, existing: "refuse_all", gone: "refuse_all"},
			{name: "allowed", policy: allowAll{}, existing: "admin_target", gone: ""},
		} {
			w := newAdminWorld(t, options{}, account.RolePolicy{})
			k := w.key(t, account.NewKey{Scopes: []string{scopeUsers}})
			high := mustUser(t, w.f.mem, "high", access.RoleAdmin)
			cfg := w.f.cfg
			cfg.Policy = tc.policy
			svc, err := account.New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("account.New: %v", err)
			}
			t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
			for name, op := range map[string]func(id int64) error{
				"UpdateUser": func(id int64) error {
					_, err := svc.UpdateUser(t.Context(), k.p, id, account.UserChange{Enabled: new(false)})
					return err
				},
				"DeleteUser": func(id int64) error { return svc.DeleteUser(t.Context(), k.p, id) },
				"IssueRecovery": func(id int64) error {
					_, err := svc.IssueRecovery(t.Context(), account.As(k.p), id, 0)
					return err
				},
			} {
				existing, gone := op(high.ID), op(9999)
				if reason(existing) != tc.existing || reason(gone) != tc.gone {
					t.Errorf("%s/%s: existing admin = %v, missing = %v; want %q and %q", tc.name, name, existing, gone, tc.existing, tc.gone)
				}
				if tc.gone == "" && !errors.Is(gone, account.ErrNotFound) {
					t.Errorf("%s/%s: missing ID allowed = %v, want ErrNotFound", tc.name, name, gone)
				}
			}
		}
	})
}

func TestKeyChainStaysUser(t *testing.T) {
	t.Parallel()
	for _, keysAdminOnly := range []bool{false, true} {
		w := newAdminWorld(t, options{}, account.RolePolicy{KeysAdminOnly: keysAdminOnly})
		k := w.key(t, account.NewKey{Scopes: []string{scopeUsers}})
		u, err := w.f.svc.CreateUser(t.Context(), account.As(k.p), account.NewUser{Username: "uma", Password: access.NewSecret(goodPassword)})
		if err != nil {
			t.Fatalf("CreateUser from the key = %v", err)
		}
		in, err := w.f.svc.PasswordLogin(t.Context(), localClient, account.Credentials{Username: "uma", Password: access.NewSecret(goodPassword)})
		if err != nil {
			t.Fatalf("PasswordLogin(uma) = %v", err)
		}
		up, err := w.f.authenticate(t.Context(), in.Token)
		if err != nil {
			t.Fatalf("Authenticate(uma) = %v", err)
		}
		created, err := w.f.svc.CreateAPIKey(t.Context(), account.As(up), u.ID, account.NewKey{Scopes: []string{"read"}})
		if keysAdminOnly {
			if !errors.Is(err, account.ErrPolicyRefused) {
				t.Errorf("uma's mint under KeysAdminOnly = %v, want ErrPolicyRefused", err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("uma's mint = %v", err)
		}
		if created.Key.UserID != u.ID || !slices.Equal(created.Key.LineageIDs, []int64{created.Key.ID}) {
			t.Errorf("uma's key = %+v, want owned by uma with its own ID as path", created.Key)
		}
		up, err = w.f.authenticate(t.Context(), created.Issued.Token)
		if err != nil {
			t.Fatalf("Authenticate(uma rotated) = %v", err)
		}
		for _, scope := range []string{scopeUsers, scopeAdmin, scopeKeys} {
			if _, err := w.f.svc.CreateAPIKey(t.Context(), account.As(up), u.ID, account.NewKey{Scopes: []string{scope}}); reason(err) != "permission_not_admin" {
				t.Errorf("uma minting %s = %v, want permission_not_admin", scope, err)
			}
		}
		k2, err := w.f.bearer(t, created.Plaintext)
		if err != nil {
			t.Fatalf("Authenticate(K2) = %v", err)
		}
		refusals := map[string]error{}
		_, refusals["Users"] = w.f.svc.Users(t.Context(), k2, account.UserFilter{})
		_, refusals["CreateUser"] = w.f.svc.CreateUser(t.Context(), account.As(k2), account.NewUser{Username: "more"})
		_, refusals["UpdateUser"] = w.f.svc.UpdateUser(t.Context(), k2, w.alice.ID, account.UserChange{Enabled: new(false)})
		refusals["RevokeAnyAPIKey"] = w.f.svc.RevokeAnyAPIKey(t.Context(), k2, k.key.ID)
		refusals["RequireAdminScope"] = w.f.svc.RequireAdminScope(k2)
		for name, err := range refusals {
			if !errors.Is(err, account.ErrScopeRequired) {
				t.Errorf("%s from uma's key = %v, want ErrScopeRequired: a RoleUser's key carries no permission", name, err)
			}
		}
		if _, err := w.f.svc.UpdateUser(t.Context(), w.pr, u.ID, account.UserChange{Enabled: new(false)}); err != nil {
			t.Fatalf("disable uma = %v", err)
		}
		if keys := keysOf(t, w.f.mem, u.ID); len(keys) != 0 {
			t.Errorf("disabling uma left her keys %v", keyIDs(keys))
		}
		recs := attributionsOf(t, w.f, u.ID)
		if len(recs) != 1 || recs[0].Action != access.AttributionCreated || !slices.Equal(recs[0].KeyLineage, k.key.LineageIDs) {
			t.Errorf("uma's records = %+v, want one created with the creating key's path", recs)
		}
	}
}

func TestKeyAttributionWrites(t *testing.T) {
	t.Parallel()
	clock := laterClock()
	w := newAdminWorld(t, options{edit: func(c *account.Config) { c.Now = clock.now }}, nil)
	root := w.key(t, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}})
	k := w.f.mint(t, account.As(root.p), w.root.ID, account.NewKey{Scopes: []string{scopeUsers}})
	ctx := t.Context()
	want := func(userID int64, action access.AttributionAction) access.KeyAttribution {
		return access.KeyAttribution{UserID: userID, Action: action, KeyLineage: k.key.LineageIDs, At: clock.now()}
	}
	same := func(got []access.KeyAttribution, exp ...access.KeyAttribution) bool {
		if len(got) != len(exp) {
			return false
		}
		for i := range got {
			if got[i].UserID != exp[i].UserID || got[i].Action != exp[i].Action || !slices.Equal(got[i].KeyLineage, exp[i].KeyLineage) || !got[i].At.Equal(exp[i].At) {
				return false
			}
		}
		return true
	}
	u, err := w.f.svc.CreateUser(ctx, account.As(k.p), account.NewUser{Username: "made"})
	if err != nil {
		t.Fatalf("CreateUser from K = %v", err)
	}
	if got := attributionsOf(t, w.f, u.ID); !same(got, want(u.ID, access.AttributionCreated)) {
		t.Errorf("after CreateUser: %+v, want one created", got)
	}
	inv, err := w.f.svc.CreateInvite(ctx, k.p, access.RoleUser, 0)
	if err != nil {
		t.Fatalf("CreateInvite from K = %v", err)
	}
	in, err := w.f.accept(t, inv.Plaintext, "joined")
	if err != nil {
		t.Fatalf("accept K's invite = %v", err)
	}
	if got := attributionsOf(t, w.f, in.User.ID); !same(got, want(in.User.ID, access.AttributionInviteAccepted)) {
		t.Errorf("after the acceptance: %+v, want one invite_accepted", got)
	}
	clock.add(time.Second)
	if _, err := w.f.svc.UpdateUser(ctx, k.p, u.ID, account.UserChange{Enabled: new(false)}); err != nil {
		t.Fatalf("disable from K = %v", err)
	}
	disabled := want(u.ID, access.AttributionDisabled)
	clock.add(time.Second)
	if _, err := w.f.svc.UpdateUser(ctx, k.p, u.ID, account.UserChange{Enabled: new(true)}); err != nil {
		t.Fatalf("enable from K = %v", err)
	}
	enabled := want(u.ID, access.AttributionEnabled)
	created := want(u.ID, access.AttributionCreated)
	created.At = clock.now().Add(-2 * time.Second)
	if got := attributionsOf(t, w.f, u.ID); !same(got, created, disabled, enabled) {
		t.Errorf("after disable and enable: %+v, want created, disabled, enabled", got)
	}
	snapshot, err := w.f.mem.ListKeyAttributions(ctx)
	if err != nil {
		t.Fatalf("ListKeyAttributions: %v", err)
	}
	w.fs.resetRecord()
	none := map[string]func() error{
		"UpdateUser_same_role_from_K": func() error {
			_, err := w.f.svc.UpdateUser(ctx, k.p, u.ID, account.UserChange{Role: new(access.RoleUser)})
			return err
		},
		"UpdateUser_from_session": func() error {
			if _, err := w.f.svc.UpdateUser(ctx, w.pr, u.ID, account.UserChange{Enabled: new(false)}); err != nil {
				return err
			}
			_, err := w.f.svc.UpdateUser(ctx, w.pr, u.ID, account.UserChange{Enabled: new(true)})
			return err
		},
		"CreateUser_from_session": func() error {
			_, err := w.f.svc.CreateUser(ctx, account.As(w.pr), account.NewUser{Username: "bysession"})
			return err
		},
		"CreateUser_out_of_band": func() error {
			_, err := w.f.svc.CreateUser(ctx, account.OutOfBand("socket"), account.NewUser{Username: "byband"})
			return err
		},
		"CreateInvite_from_K": func() error {
			_, err := w.f.svc.CreateInvite(ctx, k.p, access.RoleUser, 0)
			return err
		},
		"IssueRecovery_from_K": func() error {
			_, err := w.f.svc.IssueRecovery(ctx, account.As(k.p), u.ID, 0)
			return err
		},
		"CreateAPIKey_from_root": func() error {
			_, err := w.f.svc.CreateAPIKey(ctx, account.As(root.p), w.root.ID, account.NewKey{Scopes: []string{scopeUsers}})
			return err
		},
	}
	for name, op := range none {
		if err := op(); err != nil {
			t.Fatalf("%s = %v", name, err)
		}
		if after, _ := w.f.mem.ListKeyAttributions(ctx); !reflect.DeepEqual(after, snapshot) {
			t.Errorf("%s changed the records: %+v, want %+v", name, after, snapshot)
		}
	}
	for _, c := range w.fs.recorded() {
		if c.name == "CreateKeyAttribution" {
			t.Errorf("an unattributed operation wrote a record (Update %d)", c.update)
		}
	}
	t.Run("rollback", func(t *testing.T) {
		for _, op := range []struct {
			run  func() error
			name string
		}{
			{name: "CreateUser", run: func() error {
				_, err := w.f.svc.CreateUser(ctx, account.As(k.p), account.NewUser{Username: "rolled"})
				return err
			}},
			{name: "UpdateUser_disable", run: func() error {
				_, err := w.f.svc.UpdateUser(ctx, k.p, u.ID, account.UserChange{Enabled: new(false)})
				return err
			}},
		} {
			check := func(how string, n int) {
				if after, _ := w.f.mem.ListKeyAttributions(ctx); !reflect.DeepEqual(after, snapshot) {
					t.Errorf("%s %s at write %d left a record", op.name, how, n)
				}
				if _, found, _ := w.f.mem.UserByUsername(ctx, "rolled"); found {
					t.Errorf("%s %s at write %d left the user", op.name, how, n)
				}
				if got := stored(t, w.f, u.ID); !got.Enabled {
					t.Errorf("%s %s at write %d left the disable", op.name, how, n)
				}
			}
			n := 1
			for ; ; n++ {
				w.fs.failWrite(n)
				err := op.run()
				w.fs.failWrite(0)
				if err == nil {
					break
				}
				if !errors.Is(err, access.ErrAuthBackend) {
					t.Fatalf("%s failing write %d = %v, want ErrAuthBackend", op.name, n, err)
				}
				check("failing", n)
				w.fs.panicWrite(n)
				panicked := crash(func() { _ = op.run() })
				w.fs.panicWrite(0)
				if !panicked {
					t.Fatalf("%s did not panic at write %d", op.name, n)
				}
				check("panicking", n)
			}
			if n < 3 {
				t.Errorf("%s committed at write %d, want its user write, attribution and more each failed first", op.name, n)
			}
			snapshot, _ = w.f.mem.ListKeyAttributions(ctx)
			if op.name == "CreateUser" {
				if u2, found, _ := w.f.mem.UserByUsername(ctx, "rolled"); found {
					if err := w.f.mem.DeleteUser(ctx, u2.ID); err != nil {
						t.Fatalf("DeleteUser: %v", err)
					}
				}
				snapshot, _ = w.f.mem.ListKeyAttributions(ctx)
			}
		}
	})
}

func TestUsersAttributedToKey(t *testing.T) {
	t.Parallel()
	w := newAdminWorld(t, options{}, nil)
	boss := mustUser(t, w.f.mem, "boss", access.RoleAdmin)
	bp := w.f.sessionPrincipal(t, boss, access.SessionFull, time.Now())
	k := w.key(t, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}})
	k2 := w.f.mint(t, account.As(k.p), w.root.ID, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}})
	k3 := w.f.mint(t, account.As(k2.p), w.root.ID, account.NewKey{Scopes: []string{scopeUsers}})
	other := w.key(t, account.NewKey{Scopes: []string{scopeUsers}})
	ctx := t.Context()
	u1, err := w.f.svc.CreateUser(ctx, account.As(k3.p), account.NewUser{Username: "u1"})
	if err != nil {
		t.Fatalf("CreateUser from K3 = %v", err)
	}
	inv, err := w.f.svc.CreateInvite(ctx, k3.p, access.RoleUser, 0)
	if err != nil {
		t.Fatalf("CreateInvite from K3 = %v", err)
	}
	in, err := w.f.accept(t, inv.Plaintext, "u2")
	if err != nil {
		t.Fatalf("accept = %v", err)
	}
	u2 := in.User
	if err := w.f.svc.RevokeAPIKey(ctx, w.pr, k.key.ID); err != nil {
		t.Fatalf("RevokeAPIKey(K) = %v", err)
	}
	path := []int64{k.key.ID, k2.key.ID, k3.key.ID}
	filters := func(when string) {
		t.Helper()
		for _, id := range path {
			rows, err := w.f.svc.Users(ctx, bp, account.UserFilter{AttributedToKey: id})
			if err != nil || !slices.Equal(userIDs(rows), []int64{u1.ID, u2.ID}) {
				t.Errorf("%s: Users attributed to %d = %v, %v; want u1 and u2", when, id, userIDs(rows), err)
				continue
			}
			for _, r := range rows {
				if !slices.Equal(r.KeyLineage, path) {
					t.Errorf("%s: %s lists lineage %v, want %v", when, r.User.Username, r.KeyLineage, path)
				}
			}
		}
		for _, id := range []int64{other.key.ID, 99999} {
			if rows, err := w.f.svc.Users(ctx, bp, account.UserFilter{AttributedToKey: id}); err != nil || len(rows) != 0 {
				t.Errorf("%s: Users attributed to %d = %v, %v; want none", when, id, userIDs(rows), err)
			}
		}
	}
	filters("after the revocation")
	all, err := w.f.svc.Users(ctx, bp, account.UserFilter{})
	if err != nil {
		t.Fatalf("Users = %v", err)
	}
	for _, r := range all {
		attributed := r.User.ID == u1.ID || r.User.ID == u2.ID
		if attributed != (r.KeyLineage != nil) || (attributed && !slices.Equal(r.KeyLineage, path)) {
			t.Errorf("unfiltered, %s lists lineage %v", r.User.Username, r.KeyLineage)
		}
	}
	if len(all) != 5 {
		t.Errorf("unfiltered Users = %d rows, want every user", len(all))
	}
	if err := w.f.svc.DeleteUser(ctx, bp, w.root.ID); err != nil {
		t.Fatalf("DeleteUser(K's owner) = %v", err)
	}
	if _, err := w.f.svc.UpdateUser(ctx, bp, u1.ID, account.UserChange{Enabled: new(false)}); err != nil {
		t.Fatalf("disable u1 = %v", err)
	}
	filters("after the owner's deletion and u1's disable")
	before := len(attributionsOf(t, w.f, u1.ID))
	if err := w.f.svc.DeleteUser(ctx, bp, u2.ID); err != nil {
		t.Fatalf("DeleteUser(u2) = %v", err)
	}
	if n := len(attributionsOf(t, w.f, u2.ID)); n != 0 {
		t.Errorf("u2's %d records survive u2", n)
	}
	if n := len(attributionsOf(t, w.f, u1.ID)); n != before {
		t.Errorf("deleting u2 changed u1's records: %d, want %d", n, before)
	}
	k4 := w.f.mint(t, account.As(bp), boss.ID, account.NewKey{Scopes: []string{scopeUsers}})
	if _, err := w.f.svc.UpdateUser(ctx, k4.p, u1.ID, account.UserChange{Enabled: new(true)}); err != nil {
		t.Fatalf("re-enable u1 from K4 = %v", err)
	}
	lineageOf := func(f account.UserFilter) map[int64][]int64 {
		t.Helper()
		rows, err := w.f.svc.Users(ctx, bp, f)
		if err != nil {
			t.Fatalf("Users(%+v) = %v", f, err)
		}
		m := make(map[int64][]int64, len(rows))
		for _, r := range rows {
			m[r.User.ID] = r.KeyLineage
		}
		return m
	}
	k4Path := []int64{k4.key.ID}
	if got := lineageOf(account.UserFilter{})[u1.ID]; !slices.Equal(got, k4Path) {
		t.Errorf("unfiltered, u1 lists lineage %v, want K4's %v, its most recent record", got, k4Path)
	}
	if got := lineageOf(account.UserFilter{AttributedToKey: k4.key.ID}); len(got) != 1 || !slices.Equal(got[u1.ID], k4Path) {
		t.Errorf("Users attributed to K4 = %v, want only u1 with %v", got, k4Path)
	}
	for _, id := range path {
		if got := lineageOf(account.UserFilter{AttributedToKey: id}); len(got) != 1 || !slices.Equal(got[u1.ID], path) {
			t.Errorf("Users attributed to %d after K4's write = %v, want only u1 with %v", id, got, path)
		}
	}
}
