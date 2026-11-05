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

// censusPrincipal is one principal of the census matrix, built fresh for
// each cell.
type censusPrincipal struct {
	make func(t *testing.T, w *opWorld) access.Principal
	name string
}

func censusPrincipals() []censusPrincipal {
	key := func(user func(w *opWorld) *access.User, scopes ...string) func(t *testing.T, w *opWorld) access.Principal {
		return func(t *testing.T, w *opWorld) access.Principal {
			p, _ := w.keyPrincipalFor(t, w.authn, user(w), time.Time{}, nil, scopes...)
			return p
		}
	}
	root := func(w *opWorld) *access.User { return w.root }
	alice := func(w *opWorld) *access.User { return w.alice }
	return []censusPrincipal{
		{name: "zero", make: func(*testing.T, *opWorld) access.Principal { return access.Principal{} }},
		{name: "full", make: func(t *testing.T, w *opWorld) access.Principal {
			return w.sessionPrincipal(t, w.root, access.SessionFull, time.Now().Add(-time.Hour))
		}},
		{name: "recent", make: func(t *testing.T, w *opWorld) access.Principal { return w.recent(t, w.root) }},
		{name: "recent_user", make: func(t *testing.T, w *opWorld) access.Principal { return w.recent(t, w.alice) }},
		{name: "recovery", make: func(t *testing.T, w *opWorld) access.Principal {
			return w.sessionPrincipal(t, w.root, access.SessionRecovery, time.Now())
		}},
		{name: "admin_key", make: key(root, scopeAdmin)},
		{name: "unscoped_key", make: key(root)},
		{name: "user_admin_key", make: key(alice, scopeAdmin)},
		{name: "users_key", make: key(root, scopeUsers)},
		{name: "keys_key", make: key(root, scopeKeys)},
		{name: "custom_none", make: func(t *testing.T, w *opWorld) access.Principal { return w.customPrincipal(t, "agent", 0) }},
		{name: "custom_every", make: func(t *testing.T, w *opWorld) access.Principal {
			return w.customPrincipal(t, "agent", 0, scopeAdmin, scopeUsers, scopeKeys)
		}},
		{name: "bypass", make: func(t *testing.T, w *opWorld) access.Principal { return w.bypassPrincipal(t) }},
	}
}

// censusAnswer is the census cell for a principal calling an operation of
// class directly, with the three scopes set or empty: nil where the call
// goes through.
func censusAnswer(class opClass, scoped bool, who string) error {
	sessionAnswer := func(passes ...string) error {
		switch {
		case slices.Contains(passes, who):
			return nil
		case who == "full":
			return access.ErrRecentAuthRequired
		}
		return account.ErrSessionRequired
	}
	keyAnswer := func(key string, session error) error {
		switch who {
		case key:
			return nil
		case "recovery":
			return account.ErrSessionRequired
		case "zero", "unscoped_key", "admin_key", "user_admin_key", "users_key", "keys_key", "custom_none", "custom_every", "bypass":
			return account.ErrScopeRequired
		}
		return session
	}
	switch class {
	case classSession:
		return sessionAnswer("full", "recent", "recent_user")
	case classRecentAuth:
		return sessionAnswer("recent", "recent_user")
	case classRecovery:
		if who == "recovery" {
			return nil
		}
		return account.ErrSessionRequired
	case classAdminScope:
		session := sessionAnswer("full", "recent", "recent_user")
		if who == "recent_user" {
			session = account.ErrPolicyRefused
		}
		if !scoped {
			return session
		}
		if who == "user_admin_key" {
			return account.ErrPolicyRefused
		}
		return keyAnswer("admin_key", session)
	case classManageUsers:
		session := sessionAnswer("recent", "recent_user")
		if who == "recent_user" {
			session = account.ErrPolicyRefused
		}
		if !scoped {
			return session
		}
		return keyAnswer("users_key", session)
	case classCreateKeys:
		session := sessionAnswer("recent", "recent_user")
		if !scoped {
			return session
		}
		return keyAnswer("keys_key", session)
	case classOutOfBand:
		return account.ErrPolicyRefused
	}
	return nil
}

// scopedName names a census world.
func scopedName(scoped bool) string {
	if scoped {
		return "scopes_set"
	}
	return "scopes_empty"
}

func TestDirectCensusMatrix(t *testing.T) {
	t.Parallel()
	for _, scoped := range []bool{true, false} {
		t.Run(scopedName(scoped), func(t *testing.T) {
			t.Parallel()
			for _, op := range operations() {
				if op.class == classPublic {
					continue
				}
				t.Run(op.name, func(t *testing.T) {
					t.Parallel()
					w := newOpWorld(t, worldOptions{scoped: scoped})
					w.census = true
					for _, who := range censusPrincipals() {
						p := who.make(t, w)
						call := op.prep(t, w, p)
						want := censusAnswer(op.class, scoped, who.name)
						err := call.run(t.Context())
						switch {
						case want == nil && err != nil:
							t.Errorf("%s: %s = %v, want it to go through", who.name, op.name, err)
						case want != nil && !errors.Is(err, want):
							t.Errorf("%s: %s = %v, want %v", who.name, op.name, err, want)
						}
					}
				})
			}
		})
	}
	t.Run("user_naming", censusUserNaming)
}

// censusUserNaming holds the cells of the three operations that name a
// user: a non-admin's recent session is refused alike for an existing and
// a missing user, and a manage_users key acts on a RoleUser target only.
func censusUserNaming(t *testing.T) {
	t.Parallel()
	const missing = int64(1) << 40
	for _, tc := range []struct {
		call func(t *testing.T, w *opWorld, p access.Principal, id int64) error
		name string
	}{
		{name: "UpdateUser", call: func(t *testing.T, w *opWorld, p access.Principal, id int64) error {
			u, found, err := w.mem.UserByID(t.Context(), id)
			change := account.UserChange{Role: new(access.RoleUser), Enabled: new(true)}
			if err == nil && found {
				change = account.UserChange{Role: new(u.Role), Enabled: new(u.Enabled)}
			}
			_, err = w.svc.UpdateUser(t.Context(), p, id, change)
			return err
		}},
		{name: "DeleteUser", call: func(t *testing.T, w *opWorld, p access.Principal, id int64) error {
			return w.svc.DeleteUser(t.Context(), p, id)
		}},
		{name: "IssueRecovery", call: func(t *testing.T, w *opWorld, p access.Principal, id int64) error {
			_, err := w.svc.IssueRecovery(t.Context(), account.As(p), id, 0)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, scoped := range []bool{true, false} {
				w := newOpWorld(t, worldOptions{scoped: scoped})
				target := w.user(t)
				existing := tc.call(t, w, w.recent(t, w.alice), target.ID)
				absent := tc.call(t, w, w.recent(t, w.alice), missing)
				if !errors.Is(existing, account.ErrPolicyRefused) || !errors.Is(absent, account.ErrPolicyRefused) || existing.Error() != absent.Error() {
					t.Errorf("%s: a non-admin's recent session on an existing user = %v and on a missing one = %v, want one ErrPolicyRefused for both", scopedName(scoped), existing, absent)
				}
				if storedUser(t, w.mem, target.ID) == nil {
					t.Errorf("%s: the refused call changed the target", scopedName(scoped))
				}
				if !scoped {
					continue
				}
				admin := w.user(t)
				admin.Role = access.RoleAdmin
				if err := w.mem.UpdateUser(t.Context(), admin); err != nil {
					t.Fatalf("UpdateUser: %v", err)
				}
				key, _ := w.keyPrincipalFor(t, w.authn, w.root, time.Time{}, nil, scopeUsers)
				if err := tc.call(t, w, key, admin.ID); reason(err) != "admin_target" {
					t.Errorf("a manage_users key on an admin target = %v, want admin_target", err)
				}
				if err := tc.call(t, w, key, w.user(t).ID); err != nil {
					t.Errorf("a manage_users key on a RoleUser target = %v, want it to go through", err)
				}
			}
		})
	}
}

func TestKeyAuthorityEveryWrite(t *testing.T) {
	t.Parallel()
	want := []string{"CreateAPIKey", "CreateInvite", "CreateUser", "DeleteUser", "IssueRecovery", "RevokeAnyAPIKey", "UpdateUser"}
	var (
		mu      sync.Mutex
		reached []string
	)
	for _, op := range operations() {
		if op.class == classPublic {
			continue
		}
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			w := newOpWorld(t, worldOptions{scoped: true})
			p, _ := w.keyPrincipalFor(t, w.authn, w.root, time.Time{}, nil, scopeAdmin, scopeUsers, scopeKeys)
			call := op.prep(t, w, p)
			w.fs.resetRecord()
			err := call.run(t.Context())
			if errors.Is(err, account.ErrSessionRequired) || reason(err) == "out_of_band_only" {
				return
			}
			if err != nil {
				t.Fatalf("%s by a key carrying every scope = %v", op.name, err)
			}
			calls := w.fs.recorded()
			for _, n := range mutatingUpdates(calls) {
				mu.Lock()
				reached = append(reached, op.name)
				mu.Unlock()
				var first []string
				for _, c := range calls {
					if c.update == n && c.name != "Update" && len(first) < 2 {
						first = append(first, c.name)
					}
				}
				if !slices.Equal(first, []string{"ListAPIKeysByUserID", "UserByID"}) {
					t.Errorf("%s's writing Update %d first read %v, want the key's ListAPIKeysByUserID and its owner's UserByID", op.name, n, first)
				}
			}
		})
	}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		slices.Sort(reached)
		if got := slices.Compact(reached); !slices.Equal(got, want) {
			t.Errorf("writes a key reached = %v, want %v", got, want)
		}
	})
}

// mutatingUpdates are the ordinals of the Updates in calls that wrote.
func mutatingUpdates(calls []storeCall) []int {
	var out []int
	for _, c := range calls {
		if c.update > 0 && c.name != "Update" && isWrite(c.name) && !slices.Contains(out, c.update) {
			out = append(out, c.update)
		}
	}
	return out
}
