package account_test

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// writeCalls names every faultStore call that writes.
var writeCalls = []string{
	"CreateUser", "CreateInitialUser", "UpdateUser", "DeleteUser", "CreateSession", "UpdateSessionActivity",
	"RotateSession", "UpdateSessionLabel", "DeleteSession", "DeleteSessionByHash", "DeleteUserSessions",
	"CreatePasskey", "UpdatePasskeyAfterLogin", "RenamePasskey", "DeletePasskey", "DeleteUserPasskeys",
	"CreateAPIKey", "DeleteAPIKey", "DeleteUserAPIKeys", "TouchAPIKey", "UpdateAPIKeySecret", "UpdateAPIKeyLabel",
	"CreateOneTimeToken",
	"ConsumeOneTimeToken", "DeleteOneTimeTokens", "DeleteOneTimeTokensIssuedBy", "CreateKeyAttribution",
	"PutAuthFailure", "DeleteAuthFailures", "PruneAuthFailures", "Descope",
}

// writesOf is the recorded write calls, by name, in order.
func writesOf(fs *faultStore) []string {
	var names []string
	for _, c := range fs.recorded() {
		if slices.Contains(writeCalls, c.name) {
			names = append(names, c.name)
		}
	}
	return names
}

// adminWorld is a key-scoped fixture over a faultStore with an admin root,
// root's recent full session pr, and a RoleUser alice.
type adminWorld struct {
	f     *fixture
	fs    *faultStore
	root  *access.User
	alice *access.User
	pr    access.Principal
}

func newAdminWorld(t *testing.T, o options, policy account.Policy) *adminWorld {
	t.Helper()
	fs := newFaultStore()
	o.store = fs
	f := newFixture(t, keyOptions(o, policy))
	w := &adminWorld{f: f, fs: fs, root: mustUser(t, f.mem, "root", access.RoleAdmin), alice: mustUser(t, f.mem, "alice", access.RoleUser)}
	w.pr = f.sessionPrincipal(t, w.root, access.SessionFull, time.Now())
	return w
}

// stored reads user id from the store, nil when it is gone.
func stored(t *testing.T, f *fixture, id int64) *access.User {
	t.Helper()
	u, found, err := f.mem.UserByID(t.Context(), id)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if !found {
		return nil
	}
	return u
}

// fastHasher hashes at fastParams, for users a test seeds with a password.
func fastHasher(t testing.TB) *access.Hasher {
	t.Helper()
	h, err := access.NewHasher(access.HasherConfig{Params: fastParams})
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	return h
}

// accept redeems an invite for name with goodPassword.
func (f *fixture) accept(t testing.TB, token access.Secret, name string) (account.SignedIn, error) {
	t.Helper()
	return f.svc.AcceptInvitePassword(t.Context(), localClient, account.AcceptInvite{Token: token, Username: name, Password: access.NewSecret(goodPassword)})
}

func TestUpdateUser(t *testing.T) {
	t.Parallel()
	t.Run("both_or_neither", func(t *testing.T) {
		t.Parallel()
		for n := 1; n <= 4; n++ {
			w := newAdminWorld(t, options{}, nil)
			w.f.sessionPrincipal(t, w.alice, access.SessionFull, time.Now())
			w.f.mint(t, account.OutOfBand("socket"), w.alice.ID, account.NewKey{Scopes: []string{"read"}})
			before := w.f.events.all()
			w.fs.failWrite(n)
			got, err := w.f.svc.UpdateUser(t.Context(), w.pr, w.alice.ID, account.UserChange{Role: new(access.RoleAdmin), Enabled: new(false)})
			w.fs.failWrite(0)
			if !errors.Is(err, access.ErrAuthBackend) || got != nil {
				t.Errorf("write %d failing: UpdateUser = %v, %v; want ErrAuthBackend and no user", n, got, err)
			}
			if u := stored(t, w.f, w.alice.ID); u.Role != access.RoleUser || !u.Enabled {
				t.Errorf("write %d failing: alice is %s, enabled %t; want both old values", n, u.Role, u.Enabled)
			}
			if len(sessionsOf(t, w.f.mem, w.alice.ID)) != 1 || len(keysOf(t, w.f.mem, w.alice.ID)) != 1 {
				t.Errorf("write %d failing: alice's session or key is gone", n)
			}
			if after := w.f.events.all(); len(after) != len(before) {
				t.Errorf("write %d failing: %d events fired", n, len(after)-len(before))
			}
		}
	})
	t.Run("combined_user_set", func(t *testing.T) {
		t.Parallel()
		pol := &recordingPolicy{inner: account.RolePolicy{}}
		w := newAdminWorld(t, options{}, pol)
		ann := mustUser(t, w.f.mem, "ann", access.RoleAdmin)
		if _, err := w.f.svc.UpdateUser(t.Context(), w.pr, ann.ID, account.UserChange{Role: new(access.RoleUser), Enabled: new(false)}); err != nil {
			t.Fatalf("demote and disable ann = %v", err)
		}
		ds := pol.taken()
		if len(ds) != 2 || ds[0].Op != account.OpSetRole || ds[1].Op != account.OpSetEnabled {
			t.Fatalf("decisions = %+v, want OpSetRole then OpSetEnabled", ds)
		}
		for _, u := range ds[1].Users {
			if u.ID == ann.ID && u.Role != access.RoleUser {
				t.Errorf("OpSetEnabled saw ann as %s, want the demotion applied", u.Role)
			}
		}
		g := newAdminWorld(t, options{}, account.RolePolicy{KeepLocalAdmin: true})
		local := passwordUser(t, g.f.mem, fastHasher(t), "local", goodPassword)
		local.Role = access.RoleAdmin
		if err := g.f.mem.UpdateUser(t.Context(), local); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		_, err := g.f.svc.UpdateUser(t.Context(), g.pr, local.ID, account.UserChange{Role: new(access.RoleUser), Enabled: new(false)})
		if reason(err) != "last_local_admin" {
			t.Errorf("demoting and disabling the last local admin = %v, want last_local_admin", err)
		}
		if u := stored(t, g.f, local.ID); u.Role != access.RoleAdmin || !u.Enabled {
			t.Errorf("after the refusal local is %s, enabled %t", u.Role, u.Enabled)
		}
	})
	t.Run("no_change", func(t *testing.T) {
		t.Parallel()
		w := newAdminWorld(t, options{}, nil)
		if _, err := w.f.svc.UpdateUser(t.Context(), w.pr, w.alice.ID, account.UserChange{}); !errors.Is(err, account.ErrNoChange) {
			t.Errorf("UpdateUser with no field = %v, want ErrNoChange", err)
		}
	})
	t.Run("returns_the_committed_user", func(t *testing.T) {
		t.Parallel()
		w := newAdminWorld(t, options{}, nil)
		got, err := w.f.svc.UpdateUser(t.Context(), w.pr, w.alice.ID, account.UserChange{Enabled: new(false)})
		if err != nil {
			t.Fatalf("UpdateUser = %v", err)
		}
		rows, err := w.f.svc.Users(t.Context(), w.pr, account.UserFilter{})
		if err != nil {
			t.Fatalf("Users = %v", err)
		}
		i := slices.IndexFunc(rows, func(r account.ListedUser) bool { return r.User.ID == w.alice.ID })
		if i < 0 || !rows[i].User.UpdatedAt.Equal(got.UpdatedAt) || rows[i].User.Enabled || got.Enabled || rows[i].User.Role != got.Role {
			t.Errorf("returned %+v, want the Users row %+v", got, rows)
		}
	})
	t.Run("policy_before_existence", func(t *testing.T) {
		t.Parallel()
		pol := &recordingPolicy{inner: account.RolePolicy{}}
		w := newAdminWorld(t, options{}, pol)
		up := w.f.sessionPrincipal(t, w.alice, access.SessionFull, time.Now())
		same := account.UserChange{Role: new(access.RoleAdmin), Enabled: new(true)}
		for name, id := range map[string]int64{"existing": w.root.ID, "missing": 9999} {
			got, err := w.f.svc.UpdateUser(t.Context(), up, id, same)
			if !errors.Is(err, account.ErrPolicyRefused) || got != nil {
				t.Errorf("%s: a RoleUser's all-equal UpdateUser = %v, %v; want ErrPolicyRefused and no user", name, got, err)
			}
		}
		if ds := pol.taken(); len(ds) != 2 || ds[0].Op != account.OpSetRole || ds[1].Op != account.OpSetRole || (ds[0].Target == nil) == (ds[1].Target == nil) {
			t.Errorf("decisions = %d, want one OpSetRole with the admin and one with a nil Target", len(ds))
		}
		w.fs.resetRecord()
		events := len(w.f.events.all())
		got, err := w.f.svc.UpdateUser(t.Context(), w.pr, w.alice.ID, account.UserChange{Role: new(access.RoleUser), Enabled: new(true)})
		if err != nil || got.ID != w.alice.ID {
			t.Errorf("an admin's all-equal UpdateUser = %v, %v; want alice", got, err)
		}
		if ws := writesOf(w.fs); len(ws) != 0 {
			t.Errorf("an all-equal UpdateUser wrote %v", ws)
		}
		if ds := pol.taken()[2:]; len(ds) != 2 || ds[0].Op != account.OpSetRole || ds[1].Op != account.OpSetEnabled {
			t.Errorf("the all-equal call asked %+v, want OpSetRole and OpSetEnabled", ds)
		}
		if n := len(w.f.events.all()); n != events {
			t.Errorf("an all-equal UpdateUser emitted %d events", n-events)
		}
		if _, err := w.f.svc.UpdateUser(t.Context(), w.pr, 9999, same); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("an admin's UpdateUser on a missing ID = %v, want ErrNotFound", err)
		}
	})
	t.Run("role_change_revokes_sessions", func(t *testing.T) {
		t.Parallel()
		w := newAdminWorld(t, options{}, nil)
		sp := w.f.sessionPrincipal(t, w.alice, access.SessionFull, time.Now())
		key := w.f.mint(t, account.OutOfBand("socket"), w.alice.ID, account.NewKey{Scopes: []string{"read"}})
		if _, err := w.f.svc.UpdateUser(t.Context(), w.pr, w.alice.ID, account.UserChange{Role: new(access.RoleAdmin)}); err != nil {
			t.Fatalf("promote alice = %v", err)
		}
		if n := len(sessionsOf(t, w.f.mem, w.alice.ID)); n != 0 {
			t.Errorf("alice keeps %d sessions after her role change", n)
		}
		if !slices.Contains(keyIDs(keysOf(t, w.f.mem, w.alice.ID)), key.key.ID) {
			t.Error("a role change deleted alice's key")
		}
		evs := eventsOf(w.f.events, account.EventRoleChanged)
		if len(evs) != 1 || evs[0].UserID != w.alice.ID || !slices.Equal(evs[0].SessionIDs, []string{sp.SessionID}) || evs[0].Actor.SessionID != w.pr.SessionID {
			t.Errorf("EventRoleChanged = %+v, want one for alice naming her session and the admin", evs)
		}
	})
}

func TestLastAdminConcurrent(t *testing.T) {
	t.Parallel()
	for round := range 20 {
		f := newFixture(t, options{})
		a := mustUser(t, f.mem, "ann", access.RoleAdmin)
		b := mustUser(t, f.mem, "ben", access.RoleAdmin)
		pa := f.sessionPrincipal(t, a, access.SessionFull, time.Now())
		pb := f.sessionPrincipal(t, b, access.SessionFull, time.Now())
		var wg sync.WaitGroup
		errs := make([]error, 2)
		start := make(chan struct{})
		wg.Go(func() {
			<-start
			_, errs[0] = f.svc.UpdateUser(t.Context(), pa, b.ID, account.UserChange{Role: new(access.RoleUser)})
		})
		wg.Go(func() {
			<-start
			_, errs[1] = f.svc.UpdateUser(t.Context(), pb, a.ID, account.UserChange{Role: new(access.RoleUser)})
		})
		close(start)
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case reason(err) != "last_admin" && reason(err) != "not_admin":
				t.Errorf("round %d: the losing demotion = %v, want last_admin or not_admin", round, err)
			}
		}
		admins := 0
		for _, id := range []int64{a.ID, b.ID} {
			if stored(t, f, id).Role == access.RoleAdmin {
				admins++
			}
		}
		if ok != 1 || admins != 1 {
			t.Errorf("round %d: %d demotions succeeded and %d admins remain, want exactly one of each", round, ok, admins)
		}
	}
}

func TestPolicyBeforeExistence(t *testing.T) {
	t.Parallel()
	w := newAdminWorld(t, options{}, nil)
	up := w.f.sessionPrincipal(t, w.alice, access.SessionFull, time.Now())
	ops := map[string]func(id int64) (any, error){
		"UpdateUser": func(id int64) (any, error) {
			u, err := w.f.svc.UpdateUser(t.Context(), up, id, account.UserChange{Enabled: new(true)})
			return u, err
		},
		"DeleteUser": func(id int64) (any, error) { return nil, w.f.svc.DeleteUser(t.Context(), up, id) },
		"IssueRecovery": func(id int64) (any, error) {
			tok, err := w.f.svc.IssueRecovery(t.Context(), account.As(up), id, 0)
			return tok.Plaintext.IsZero(), err
		},
	}
	for name, op := range ops {
		w.fs.resetRecord()
		got, existing := op(w.root.ID)
		_, missing := op(9999)
		if !errors.Is(existing, account.ErrPolicyRefused) || existing.Error() != missing.Error() {
			t.Errorf("%s: existing = %v, missing = %v; want one identical ErrPolicyRefused", name, existing, missing)
		}
		if u, isUser := got.(*access.User); isUser && u != nil {
			t.Errorf("%s returned user data %+v with its refusal", name, u)
		}
		if ws := writesOf(w.fs); len(ws) != 0 {
			t.Errorf("%s wrote %v", name, ws)
		}
	}
}

func TestDisableDeletesKeysAndSessions(t *testing.T) {
	t.Parallel()
	w := newAdminWorld(t, options{}, account.RolePolicy{})
	s1 := w.f.sessionPrincipal(t, w.alice, access.SessionFull, time.Now())
	s2 := w.f.sessionPrincipal(t, w.alice, access.SessionFull, time.Now())
	k1 := w.f.mint(t, account.As(s1), w.alice.ID, account.NewKey{Scopes: []string{"read"}})
	k2 := w.f.mint(t, account.OutOfBand("socket"), w.alice.ID, account.NewKey{Scopes: []string{"read"}})
	if _, err := w.f.svc.UpdateUser(t.Context(), w.pr, w.alice.ID, account.UserChange{Enabled: new(false)}); err != nil {
		t.Fatalf("disable alice = %v", err)
	}
	if n, k := len(sessionsOf(t, w.f.mem, w.alice.ID)), len(keysOf(t, w.f.mem, w.alice.ID)); n != 0 || k != 0 {
		t.Errorf("after the disable alice holds %d sessions and %d keys, want none", n, k)
	}
	dis := eventsOf(w.f.events, account.EventUserDisabled)
	if len(dis) != 1 || len(dis[0].SessionIDs) != 2 || !slices.Contains(dis[0].SessionIDs, s2.SessionID) {
		t.Errorf("EventUserDisabled = %+v, want alice's two sessions", dis)
	}
	revoked := eventsOf(w.f.events, account.EventKeyRevoked)
	ids := []int64{}
	for _, ev := range revoked {
		ids = append(ids, ev.KeyID)
	}
	if !slices.Equal(ids, []int64{k1.key.ID, k2.key.ID}) {
		t.Errorf("EventKeyRevoked for keys %v, want %v", ids, []int64{k1.key.ID, k2.key.ID})
	}
	if _, err := w.f.svc.UpdateUser(t.Context(), w.pr, w.alice.ID, account.UserChange{Enabled: new(true)}); err != nil {
		t.Fatalf("re-enable alice = %v", err)
	}
	if n, k := len(sessionsOf(t, w.f.mem, w.alice.ID)), len(keysOf(t, w.f.mem, w.alice.ID)); n != 0 || k != 0 {
		t.Errorf("re-enabling restored %d sessions and %d keys", n, k)
	}
	if evs := eventsOf(w.f.events, account.EventUserEnabled); len(evs) != 1 || evs[0].UserID != w.alice.ID {
		t.Errorf("EventUserEnabled = %+v, want one for alice", evs)
	}
}

func TestDisableOwnerRevokesMintedKeys(t *testing.T) {
	t.Parallel()
	for _, op := range []string{"disable", "delete"} {
		t.Run(op, func(t *testing.T) {
			t.Parallel()
			w := newAdminWorld(t, options{}, nil)
			owner := mustUser(t, w.f.mem, "owner", access.RoleAdmin)
			op1 := w.f.sessionPrincipal(t, owner, access.SessionFull, time.Now())
			root := w.f.mint(t, account.As(op1), owner.ID, account.NewKey{Scopes: []string{scopeUsers, scopeKeys}})
			child := w.f.mint(t, account.As(root.p), owner.ID, account.NewKey{Scopes: []string{scopeUsers}})
			invite, err := w.f.svc.CreateInvite(t.Context(), child.p, access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite from the child = %v", err)
			}
			if _, err := w.f.svc.IssueRecovery(t.Context(), account.As(root.p), w.alice.ID, 0); err != nil {
				t.Fatalf("IssueRecovery from the root = %v", err)
			}
			session := seedToken(t, w.f.mem, access.PurposeInvite, 0, 0, time.Hour)
			w.fs.resetRecord()
			switch op {
			case "disable":
				_, err = w.f.svc.UpdateUser(t.Context(), w.pr, owner.ID, account.UserChange{Enabled: new(false)})
			default:
				err = w.f.svc.DeleteUser(t.Context(), w.pr, owner.ID)
			}
			if err != nil {
				t.Fatalf("%s the owner = %v", op, err)
			}
			if k := keysOf(t, w.f.mem, owner.ID); len(k) != 0 {
				t.Errorf("after the %s the owner keeps keys %v", op, keyIDs(k))
			}
			live, err := w.f.mem.LiveOneTimeTokens(t.Context(), []access.TokenPurpose{access.PurposeInvite, access.PurposeRecovery}, time.Now())
			if err != nil {
				t.Fatalf("LiveOneTimeTokens: %v", err)
			}
			if len(live) != 1 || !live[0].Hash.Equal(session.Hash) {
				t.Errorf("after the %s %d tokens live, want only the session-issued invite", op, len(live))
			}
			if _, err := w.f.accept(t, invite.Plaintext, "invited"); !errors.Is(err, access.ErrTokenInvalid) {
				t.Errorf("the child's invite after the %s = %v, want access.ErrTokenInvalid", op, err)
			}
			updates := map[int]bool{}
			for _, c := range w.fs.recorded() {
				if c.name == "DeleteOneTimeTokensIssuedBy" || c.name == "DeleteUserAPIKeys" || c.name == "DeleteUser" {
					updates[c.update] = true
				}
			}
			if len(updates) != 1 || updates[0] {
				t.Errorf("the key and token deletions ran in Updates %v, want one", updates)
			}
		})
	}
}

func TestSingleOwnerRefusesAdminOps(t *testing.T) {
	t.Parallel()
	w := newAdminWorld(t, options{}, account.SingleOwnerPolicy{})
	ops := map[string]func() error{
		"CreateUser": func() error {
			_, err := w.f.svc.CreateUser(t.Context(), account.As(w.pr), account.NewUser{Username: "second"})
			return err
		},
		"UpdateUser": func() error {
			_, err := w.f.svc.UpdateUser(t.Context(), w.pr, w.alice.ID, account.UserChange{Enabled: new(false)})
			return err
		},
		"DeleteUser": func() error { return w.f.svc.DeleteUser(t.Context(), w.pr, w.alice.ID) },
		"CreateInvite": func() error {
			_, err := w.f.svc.CreateInvite(t.Context(), w.pr, access.RoleUser, 0)
			return err
		},
		"IssueRecovery": func() error {
			_, err := w.f.svc.IssueRecovery(t.Context(), account.As(w.pr), w.alice.ID, 0)
			return err
		},
	}
	for name, op := range ops {
		w.fs.resetRecord()
		if err := op(); !errors.Is(err, account.ErrPolicyRefused) {
			t.Errorf("%s from the owner's session = %v, want ErrPolicyRefused", name, err)
		}
		if ws := writesOf(w.fs); len(ws) != 0 {
			t.Errorf("%s wrote %v", name, ws)
		}
	}
	if u := stored(t, w.f, w.alice.ID); u == nil || !u.Enabled {
		t.Error("alice changed under SingleOwnerPolicy")
	}
	if _, err := w.f.svc.IssueRecovery(t.Context(), account.OutOfBand("socket"), w.root.ID, 0); err != nil {
		t.Errorf("IssueRecovery out of band for the owner = %v, want nil", err)
	}
	if _, err := w.f.svc.Users(t.Context(), w.pr, account.UserFilter{}); err != nil {
		t.Errorf("Users from the owner = %v, want nil", err)
	}
}

func TestUsersMethods(t *testing.T) {
	t.Parallel()
	w := newAdminWorld(t, options{}, nil)
	pw := passwordUser(t, w.f.mem, fastHasher(t), "pat", goodPassword)
	addPasskey(t, w.f.mem, pw, "example.com")
	addPasskey(t, w.f.mem, pw, "example.com")
	rows, err := w.f.svc.Users(t.Context(), w.pr, account.UserFilter{})
	if err != nil {
		t.Fatalf("Users = %v", err)
	}
	if !slices.IsSortedFunc(rows, func(a, b account.ListedUser) int { return int(a.User.ID - b.User.ID) }) || len(rows) != 3 {
		t.Fatalf("Users = %d rows, want three by ID", len(rows))
	}
	for _, r := range rows {
		switch r.User.ID {
		case pw.ID:
			if r.PasskeyCount != 2 || r.User.PasswordHash.IsZero() {
				t.Errorf("pat lists %d passkeys and password %t, want 2 and a password", r.PasskeyCount, !r.User.PasswordHash.IsZero())
			}
		case w.alice.ID:
			if r.PasskeyCount != 0 || !r.User.PasswordHash.IsZero() || r.KeyLineage != nil {
				t.Errorf("alice lists %+v, want no method and no lineage", r)
			}
		}
	}
}
