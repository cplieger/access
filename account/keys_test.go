package account_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// unrotated reports whether pr's stored session still has pr's token.
func unrotated(t *testing.T, s account.Store, pr access.Principal) bool {
	t.Helper()
	return storedSession(t, s, pr.User.ID, pr.SessionID).TokenHash.Equal(pr.SessionTokenHash())
}

func TestKeyPermissionScopesAdminOnly(t *testing.T) {
	t.Parallel()
	permissions := []string{scopeUsers, scopeKeys, scopeAdmin}
	t.Run("role_user_refused", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
		for _, scope := range permissions {
			for name, a := range map[string]account.Actor{"session": account.As(pr), "out_of_band": account.OutOfBand("admin-socket")} {
				_, err := f.svc.CreateAPIKey(t.Context(), a, u.ID, account.NewKey{Scopes: []string{"read", scope}})
				if reason(err) != "permission_not_admin" {
					t.Errorf("%s minting %s for a RoleUser = %v, want permission_not_admin", name, scope, err)
				}
			}
		}
		if n := len(keysOf(t, f.mem, u.ID)); n != 0 {
			t.Errorf("keys = %d, want none", n)
		}
		if n := len(eventsOf(f.events, account.EventKeyMinted)); n != 0 {
			t.Errorf("EventKeyMinted = %d, want none", n)
		}
		if !unrotated(t, f.mem, pr) {
			t.Error("a refused mint rotated the session")
		}
		if _, err := f.svc.CreateAPIKey(t.Context(), account.As(pr), u.ID, account.NewKey{Scopes: []string{"read"}}); err != nil {
			t.Errorf("the RoleUser minting read only = %v, want a key", err)
		}
	})
	t.Run("admin_mints_each", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		for _, scope := range permissions {
			pr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
			if _, err := f.svc.CreateAPIKey(t.Context(), account.As(pr), admin.ID, account.NewKey{Scopes: []string{scope}}); err != nil {
				t.Errorf("an admin session minting %s = %v", scope, err)
			}
			if _, err := f.svc.CreateAPIKey(t.Context(), account.OutOfBand("admin-socket"), admin.ID, account.NewKey{Scopes: []string{scope}}); err != nil {
				t.Errorf("out of band minting %s for an admin = %v", scope, err)
			}
		}
		pr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		parent := f.mint(t, account.As(pr), admin.ID, account.NewKey{Scopes: permissions})
		child, err := f.svc.CreateAPIKey(t.Context(), account.As(parent.p), admin.ID, account.NewKey{Scopes: []string{scopeUsers, scopeAdmin}})
		if err != nil {
			t.Fatalf("an admin's create_keys key minting the permissions it holds = %v", err)
		}
		if !slices.Equal(child.Key.Scopes, []string{scopeUsers, scopeAdmin}) {
			t.Errorf("child scopes = %v", child.Key.Scopes)
		}
	})
	t.Run("demoted_inside_the_update", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newFixture(t, keyOptions(options{store: fs}, nil))
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		pr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		entered, release := fs.holdUpdate()
		done := make(chan error, 1)
		go func() {
			_, err := f.svc.CreateAPIKey(t.Context(), account.As(pr), admin.ID, account.NewKey{Scopes: []string{scopeUsers}})
			done <- err
		}()
		<-entered
		demoted := storedUser(t, f.mem, admin.ID)
		demoted.Role = access.RoleUser
		if err := f.mem.UpdateUser(t.Context(), demoted); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		release()
		if err := <-done; reason(err) != "permission_not_admin" {
			t.Errorf("a mint held across its owner's demotion = %v, want permission_not_admin", err)
		}
		if n := len(keysOf(t, f.mem, admin.ID)); n != 0 {
			t.Errorf("keys = %d, want none", n)
		}
	})
}

func TestKeyMintingPolicy(t *testing.T) {
	t.Parallel()
	t.Run("keys_admin_only", func(t *testing.T) {
		t.Parallel()
		rec := &recordingPolicy{inner: account.RolePolicy{KeysAdminOnly: true}}
		f := newFixture(t, keyOptions(options{}, rec))
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
		if _, err := f.svc.CreateAPIKey(t.Context(), account.As(pr), u.ID, account.NewKey{Scopes: []string{"read"}}); !errors.Is(err, account.ErrPolicyRefused) {
			t.Errorf("a RoleUser session under KeysAdminOnly = %v, want ErrPolicyRefused", err)
		}
		decisions := rec.taken()
		if len(decisions) != 1 || decisions[0].Op != account.OpCreateOwnKey || decisions[0].Target == nil || decisions[0].Target.ID != u.ID {
			t.Fatalf("decisions = %+v, want one OpCreateOwnKey targeting the caller", decisions)
		}
		if got, _ := decisions[0].Actor.Principal(); got.SessionID != pr.SessionID {
			t.Errorf("decision actor = %+v, want the caller's session", got)
		}
		if len(keysOf(t, f.mem, u.ID)) != 0 || !unrotated(t, f.mem, pr) {
			t.Error("the refused mint wrote a key or rotated the session")
		}
		apr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		if _, err := f.svc.CreateAPIKey(t.Context(), account.As(apr), admin.ID, account.NewKey{Scopes: []string{"read"}}); err != nil {
			t.Errorf("an admin session = %v, want a key", err)
		}
		oob, err := f.svc.CreateAPIKey(t.Context(), account.OutOfBand("admin-socket"), u.ID, account.NewKey{Scopes: []string{"read"}})
		if err != nil {
			t.Fatalf("out of band for the RoleUser = %v, want a key", err)
		}
		keys, err := f.svc.APIKeys(t.Context(), pr)
		if err != nil || !slices.Equal(keyIDs(keys), []int64{oob.Key.ID}) {
			t.Errorf("APIKeys = %v, %v; want the out-of-band key", keyIDs(keys), err)
		}
		if err := f.svc.RevokeAPIKey(t.Context(), pr, oob.Key.ID); err != nil {
			t.Errorf("RevokeAPIKey of the out-of-band key = %v", err)
		}
	})
	t.Run("role_policy_default", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		other := mustUser(t, f.mem, "bob", access.RoleUser)
		pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
		created, err := f.svc.CreateAPIKey(t.Context(), account.As(pr), u.ID, account.NewKey{Scopes: []string{"read"}})
		if err != nil {
			t.Fatalf("a RoleUser session under RolePolicy{} = %v, want a key", err)
		}
		if created.Issued.Token.IsZero() || created.Issued.Session.ID != pr.SessionID {
			t.Error("a session mint did not rotate the session into Issued")
		}
		pr2 := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
		if _, err := f.svc.CreateAPIKey(t.Context(), account.As(pr2), other.ID, account.NewKey{Scopes: []string{"read"}}); reason(err) != "other_user" {
			t.Errorf("a session naming another user = %v, want other_user", err)
		}
		if n := len(keysOf(t, f.mem, other.ID)); n != 0 {
			t.Errorf("the other user's keys = %d, want none", n)
		}
	})
	t.Run("stale_session", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		stale := f.sessionPrincipal(t, u, access.SessionFull, time.Now().Add(-time.Hour))
		if _, err := f.svc.CreateAPIKey(t.Context(), account.As(stale), u.ID, account.NewKey{}); !errors.Is(err, access.ErrRecentAuthRequired) {
			t.Errorf("a stale session = %v, want ErrRecentAuthRequired", err)
		}
		if _, err := f.svc.CreateAPIKey(t.Context(), account.As(f.bypassPrincipal(t)), u.ID, account.NewKey{}); !errors.Is(err, account.ErrScopeRequired) {
			t.Errorf("the bypass principal with CreateKeysScope set = %v, want ErrScopeRequired", err)
		}
		if _, err := f.svc.CreateAPIKey(t.Context(), account.Actor{}, u.ID, account.NewKey{}); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("the zero Actor = %v, want ErrSessionRequired", err)
		}
	})
}

func TestOutOfBandMinting(t *testing.T) {
	t.Parallel()
	f := newFixture(t, keyOptions(options{}, nil))
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	oob := account.OutOfBand("admin-socket")
	var textErr *account.TextError
	if _, err := f.svc.CreateAPIKey(t.Context(), oob, u.ID, account.NewKey{Scopes: []string{"delete_everything"}}); !errors.Is(err, account.ErrUnknownScope) {
		t.Errorf("an unknown scope = %v, want ErrUnknownScope", err)
	}
	if _, err := f.svc.CreateAPIKey(t.Context(), oob, u.ID, account.NewKey{Label: strings.Repeat("a", 129)}); !errors.As(err, &textErr) || textErr.Reason != "too_long" {
		t.Errorf("a 129-rune label = %v, want label too_long", err)
	}
	if _, err := f.svc.CreateAPIKey(t.Context(), oob, u.ID, account.NewKey{Label: "a\nb"}); !errors.As(err, &textErr) || textErr.Reason != "disallowed_character" {
		t.Errorf("a two-line label = %v, want label disallowed_character", err)
	}
	if _, err := f.svc.CreateAPIKey(t.Context(), oob, u.ID, account.NewKey{ExpiresIn: -time.Second}); !errors.Is(err, account.ErrKeyExpiryInvalid) {
		t.Errorf("a negative expiry = %v, want ErrKeyExpiryInvalid", err)
	}
	if _, err := f.svc.CreateAPIKey(t.Context(), oob, 9999, account.NewKey{}); !errors.Is(err, account.ErrPolicyRefused) {
		t.Errorf("a missing target = %v, want ErrPolicyRefused", err)
	}
	created, err := f.svc.CreateAPIKey(t.Context(), oob, u.ID, account.NewKey{Label: strings.Repeat("ß", 128), Scopes: []string{"read"}, ExpiresIn: time.Hour})
	if err != nil {
		t.Fatalf("out of band = %v", err)
	}
	if !created.Issued.Token.IsZero() || len(created.Key.LineageIDs) != 1 || created.Key.LineageIDs[0] != created.Key.ID {
		t.Errorf("out-of-band key = issued token zero %t, lineage %v; want no rotation and its own ID alone", created.Issued.Token.IsZero(), created.Key.LineageIDs)
	}
	minted := eventsOf(f.events, account.EventKeyMinted)
	if len(minted) != 1 || minted[0].Actor.OutOfBand != "admin-socket" || minted[0].KeyID != created.Key.ID || minted[0].UserID != u.ID {
		t.Errorf("EventKeyMinted = %+v, want one with the out-of-band actor", minted)
	}
	disabled := mustUser(t, f.mem, "carol", access.RoleUser)
	disabled.Enabled = false
	if err := f.mem.UpdateUser(t.Context(), disabled); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if _, err := f.svc.CreateAPIKey(t.Context(), oob, disabled.ID, account.NewKey{}); !errors.Is(err, account.ErrPolicyRefused) {
		t.Errorf("a disabled target = %v, want ErrPolicyRefused", err)
	}
	t.Run("single_owner", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, account.SingleOwnerPolicy{}))
		owner := mustUser(t, f.mem, "owner", access.RoleAdmin)
		if _, err := f.svc.CreateAPIKey(t.Context(), account.OutOfBand("admin-socket"), owner.ID, account.NewKey{Scopes: []string{"read"}}); err != nil {
			t.Errorf("out-of-band mint for the owner under SingleOwnerPolicy = %v, want a key", err)
		}
	})
}

func TestAdminKeyListRevoke(t *testing.T) {
	t.Parallel()
	f := newFixture(t, keyOptions(options{}, nil))
	admin := mustUser(t, f.mem, "root", access.RoleAdmin)
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	apr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
	upr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	adminKey := f.mint(t, account.OutOfBand("admin-socket"), admin.ID, account.NewKey{Scopes: []string{"read"}})
	userKey := f.mint(t, account.As(upr), u.ID, account.NewKey{Scopes: []string{"read"}})
	ownKey := f.mint(t, account.OutOfBand("admin-socket"), u.ID, account.NewKey{Scopes: []string{"write"}})
	all, err := f.svc.AllAPIKeys(t.Context(), account.As(apr))
	if err != nil || !slices.Equal(listedKeyIDs(all), []int64{adminKey.key.ID, userKey.key.ID, ownKey.key.ID}) {
		t.Errorf("AllAPIKeys = %v, %v; want every user's keys by ID", listedKeyIDs(all), err)
	}
	if err := f.svc.RevokeAnyAPIKey(t.Context(), account.As(apr), userKey.key.ID); err != nil {
		t.Fatalf("an admin revoking a RoleUser's key = %v", err)
	}
	if keys := keysOf(t, f.mem, u.ID); !slices.Equal(keyIDs(keys), []int64{ownKey.key.ID}) {
		t.Errorf("the RoleUser's keys = %v, want only the one not revoked", keyIDs(keys))
	}
	revoked := eventsOf(f.events, account.EventKeyRevoked)
	if len(revoked) != 1 || revoked[0].UserID != u.ID || revoked[0].KeyID != userKey.key.ID || revoked[0].Actor.UserID != admin.ID {
		t.Errorf("EventKeyRevoked = %+v, want one for the RoleUser's key with the admin as actor", revoked)
	}
	if err := f.svc.RevokeAnyAPIKey(t.Context(), account.As(apr), 9999); !errors.Is(err, account.ErrNotFound) {
		t.Errorf("an admin revoking an unknown key = %v, want ErrNotFound", err)
	}
	upr2 := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	if _, err := f.svc.AllAPIKeys(t.Context(), account.As(upr2)); !errors.Is(err, account.ErrPolicyRefused) {
		t.Errorf("a RoleUser's AllAPIKeys = %v, want ErrPolicyRefused", err)
	}
	for _, id := range []int64{adminKey.key.ID, 9999} {
		if err := f.svc.RevokeAnyAPIKey(t.Context(), account.As(upr2), id); !errors.Is(err, account.ErrPolicyRefused) {
			t.Errorf("a RoleUser's RevokeAnyAPIKey(%d) = %v, want ErrPolicyRefused whether or not the key exists", id, err)
		}
	}
	own, err := f.svc.APIKeys(t.Context(), upr2)
	if err != nil || !slices.Equal(keyIDs(own), []int64{ownKey.key.ID}) {
		t.Errorf("the owner's APIKeys = %v, %v", keyIDs(own), err)
	}
	if err := f.svc.RevokeAPIKey(t.Context(), upr2, adminKey.key.ID); !errors.Is(err, account.ErrNotFound) {
		t.Errorf("an owner revoking another user's key = %v, want ErrNotFound", err)
	}
	if err := f.svc.RevokeAPIKey(t.Context(), upr2, ownKey.key.ID); err != nil {
		t.Errorf("an owner revoking its own key = %v", err)
	}
	if n := len(keysOf(t, f.mem, admin.ID)); n != 1 {
		t.Errorf("the admin's keys = %d, want 1", n)
	}
	t.Run("admin_scope_key", func(t *testing.T) {
		scoped := f.mint(t, account.OutOfBand("admin-socket"), admin.ID, account.NewKey{Scopes: []string{scopeAdmin}})
		target := f.mint(t, account.OutOfBand("admin-socket"), u.ID, account.NewKey{Scopes: []string{"read"}})
		if _, err := f.svc.AllAPIKeys(t.Context(), account.As(scoped.p)); err != nil {
			t.Errorf("AllAPIKeys from an AdminScope key = %v", err)
		}
		if err := f.svc.RevokeAnyAPIKey(t.Context(), account.As(scoped.p), target.key.ID); err != nil {
			t.Errorf("RevokeAnyAPIKey from an AdminScope key = %v", err)
		}
		if err := f.svc.RevokeAnyAPIKey(t.Context(), account.As(adminKey.p), ownKey.key.ID); !errors.Is(err, account.ErrScopeRequired) {
			t.Errorf("RevokeAnyAPIKey from a key without AdminScope = %v, want ErrScopeRequired", err)
		}
	})
}

func TestKeyMintsNarrowerKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t, keyOptions(options{}, nil))
	admin := mustUser(t, f.mem, "root", access.RoleAdmin)
	pr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
	root := f.mint(t, account.As(pr), admin.ID, account.NewKey{Scopes: []string{scopeKeys, "read"}, ExpiresIn: 2 * time.Hour})
	if !slices.Equal(root.key.LineageIDs, []int64{root.key.ID}) {
		t.Errorf("a session-minted key's path = %v, want its own ID alone", root.key.LineageIDs)
	}
	watcher := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
	child, err := f.svc.CreateAPIKey(t.Context(), account.As(root.p), admin.ID, account.NewKey{Scopes: []string{"read"}, ExpiresIn: time.Hour})
	if err != nil {
		t.Fatalf("the key minting a narrower key = %v", err)
	}
	if !slices.Equal(child.Key.LineageIDs, []int64{root.key.ID, child.Key.ID}) || child.Key.ParentKeyID() != root.key.ID {
		t.Errorf("child path = %v, parent %d; want [%d %d]", child.Key.LineageIDs, child.Key.ParentKeyID(), root.key.ID, child.Key.ID)
	}
	if !child.Key.ExpiresAt.Before(root.key.ExpiresAt) {
		t.Errorf("child expires at %v, want before the parent's %v", child.Key.ExpiresAt, root.key.ExpiresAt)
	}
	if !child.Issued.Token.IsZero() || !unrotated(t, f.mem, watcher) {
		t.Error("a key's mint rotated a session")
	}
	ev := eventsOf(f.events, account.EventKeyMinted)
	if last := ev[len(ev)-1]; last.Actor.KeyID != root.key.ID || last.KeyID != child.Key.ID || last.Actor.SessionID != "" {
		t.Errorf("the key's EventKeyMinted = %+v, want the parent key as actor", last)
	}
	oob := f.mint(t, account.OutOfBand("admin-socket"), admin.ID, account.NewKey{})
	if !slices.Equal(oob.key.LineageIDs, []int64{oob.key.ID}) {
		t.Errorf("an out-of-band key's path = %v, want its own ID alone", oob.key.LineageIDs)
	}
}

func TestKeyLineageDepth(t *testing.T) {
	t.Parallel()
	f := newFixture(t, keyOptions(options{}, nil))
	admin := mustUser(t, f.mem, "root", access.RoleAdmin)
	pr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
	cur := f.mint(t, account.As(pr), admin.ID, account.NewKey{Scopes: []string{scopeKeys}})
	for len(cur.key.LineageIDs) < account.MaxKeyLineage {
		next := f.mint(t, account.As(cur.p), admin.ID, account.NewKey{Scopes: []string{scopeKeys}})
		if want := append(slices.Clone(cur.key.LineageIDs), next.key.ID); !slices.Equal(next.key.LineageIDs, want) {
			t.Fatalf("path = %v, want %v", next.key.LineageIDs, want)
		}
		cur = next
	}
	before, events := len(keysOf(t, f.mem, admin.ID)), len(f.events.all())
	if _, err := f.svc.CreateAPIKey(t.Context(), account.As(cur.p), admin.ID, account.NewKey{Scopes: []string{scopeKeys}}); reason(err) != "lineage_too_deep" {
		t.Errorf("minting below a path of %d IDs = %v, want lineage_too_deep", account.MaxKeyLineage, err)
	}
	if len(keysOf(t, f.mem, admin.ID)) != before || len(f.events.all()) != events {
		t.Error("the refused mint wrote a key or emitted an event")
	}
}

func TestKeyCannotEscalate(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, o options) (*fixture, *access.User, minted) {
		f := newFixture(t, keyOptions(o, nil))
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		pr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		return f, admin, f.mint(t, account.As(pr), admin.ID, account.NewKey{Scopes: []string{scopeKeys, "read"}, ExpiresIn: time.Hour})
	}
	t.Run("refusals", func(t *testing.T) {
		t.Parallel()
		f, admin, parent := setup(t, options{})
		other := mustUser(t, f.mem, "bob", access.RoleAdmin)
		for _, tc := range []struct {
			in     account.NewKey
			name   string
			reason string
			target int64
		}{
			{name: "scope_parent_lacks", in: account.NewKey{Scopes: []string{"write"}, ExpiresIn: time.Minute}, reason: "scopes_not_subset", target: admin.ID},
			{name: "no_expiry_under_expiring_parent", in: account.NewKey{Scopes: []string{"read"}}, reason: "expiry_after_parent", target: admin.ID},
			{name: "later_expiry", in: account.NewKey{Scopes: []string{"read"}, ExpiresIn: 2 * time.Hour}, reason: "expiry_after_parent", target: admin.ID},
			{name: "another_user", in: account.NewKey{Scopes: []string{"read"}, ExpiresIn: time.Minute}, reason: "other_user", target: other.ID},
		} {
			if _, err := f.svc.CreateAPIKey(t.Context(), account.As(parent.p), tc.target, tc.in); reason(err) != tc.reason {
				t.Errorf("%s = %v, want %s", tc.name, err, tc.reason)
			}
		}
		if n := len(keysOf(t, f.mem, admin.ID)); n != 1 {
			t.Errorf("the admin's keys = %d, want only the parent", n)
		}
		if n := len(keysOf(t, f.mem, other.ID)); n != 0 {
			t.Errorf("the other user's keys = %d, want none", n)
		}
	})
	t.Run("parent_revoked_while_held", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f, admin, parent := setup(t, options{store: fs})
		pr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		entered, release := fs.holdUpdate()
		done := make(chan error, 1)
		go func() {
			_, err := f.svc.CreateAPIKey(t.Context(), account.As(parent.p), admin.ID, account.NewKey{Scopes: []string{"read"}, ExpiresIn: time.Minute})
			done <- err
		}()
		<-entered
		if err := f.svc.RevokeAPIKey(t.Context(), pr, parent.key.ID); err != nil {
			t.Fatalf("RevokeAPIKey = %v", err)
		}
		release()
		if err := <-done; reason(err) != "key_not_current" {
			t.Errorf("a mint from a parent revoked meanwhile = %v, want key_not_current", err)
		}
		if n := len(keysOf(t, f.mem, admin.ID)); n != 0 {
			t.Errorf("keys = %d, want none", n)
		}
	})
}

func TestKeyPermissionScopeEmpty(t *testing.T) {
	t.Parallel()
	f := newFixture(t, keyOptions(options{edit: func(c *account.Config) { c.CreateKeysScope = "" }}, nil))
	admin := mustUser(t, f.mem, "root", access.RoleAdmin)
	for _, scopes := range [][]string{{scopeKeys}, {scopeAdmin}, {scopeUsers, "read"}} {
		k := f.mint(t, account.OutOfBand("admin-socket"), admin.ID, account.NewKey{Scopes: scopes})
		if _, err := f.svc.CreateAPIKey(t.Context(), account.As(k.p), admin.ID, account.NewKey{}); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("a %v key under an empty CreateKeysScope = %v, want ErrSessionRequired", scopes, err)
		}
	}
	t.Run("scope_set_key_without_it", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		k := f.mint(t, account.OutOfBand("admin-socket"), admin.ID, account.NewKey{Scopes: []string{scopeAdmin}})
		if _, err := f.svc.CreateAPIKey(t.Context(), account.As(k.p), admin.ID, account.NewKey{}); !errors.Is(err, account.ErrScopeRequired) {
			t.Errorf("an AdminScope key alone = %v, want ErrScopeRequired", err)
		}
	})
}

// family is a parent key P minted by a session, its child C and C's
// sibling S minted by P, and C's child G, each expiring expiresIn after
// Config.Now, or never for 0.
type family struct{ p, c, s, g minted }

func newFamily(t *testing.T, f *fixture, admin *access.User, expiresIn time.Duration) family {
	t.Helper()
	pr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
	in := account.NewKey{Scopes: []string{scopeKeys, "read"}, ExpiresIn: expiresIn}
	var fam family
	fam.p = f.mint(t, account.As(pr), admin.ID, in)
	fam.c = f.mint(t, account.As(fam.p.p), admin.ID, in)
	fam.s = f.mint(t, account.As(fam.p.p), admin.ID, in)
	fam.g = f.mint(t, account.As(fam.c.p), admin.ID, in)
	return fam
}

func TestRevokeCascades(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, fs *faultStore) (*fixture, *access.User, family, access.Principal) {
		f := newFixture(t, keyOptions(options{store: fs}, nil))
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		fam := newFamily(t, f, admin, 0)
		return f, admin, fam, f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
	}
	revokes := map[string]func(*testing.T, *fixture, access.Principal, int64) error{
		"RevokeAPIKey": func(t *testing.T, f *fixture, p access.Principal, id int64) error {
			return f.svc.RevokeAPIKey(t.Context(), p, id)
		},
		"RevokeAnyAPIKey": func(t *testing.T, f *fixture, p access.Principal, id int64) error {
			return f.svc.RevokeAnyAPIKey(t.Context(), account.As(p), id)
		},
	}
	for name, revoke := range revokes {
		t.Run(name+"_parent", func(t *testing.T) {
			t.Parallel()
			fs := newFaultStore()
			f, admin, fam, pr := setup(t, fs)
			fs.resetRecord()
			if err := revoke(t, f, pr, fam.p.key.ID); err != nil {
				t.Fatalf("%s(parent) = %v", name, err)
			}
			if n := len(keysOf(t, f.mem, admin.ID)); n != 0 {
				t.Errorf("keys = %d, want the whole tree gone", n)
			}
			deletes := map[int]int{}
			for _, c := range fs.recorded() {
				if c.name == "DeleteAPIKey" {
					deletes[c.update]++
				}
			}
			if len(deletes) != 1 {
				t.Errorf("the key deletes ran in %d Updates, want one", len(deletes))
			}
			if n := len(eventsOf(f.events, account.EventKeyRevoked)); n != 4 {
				t.Errorf("EventKeyRevoked = %d, want 4: the parent, both children and the grandchild", n)
			}
		})
	}
	t.Run("child", func(t *testing.T) {
		t.Parallel()
		f, admin, fam, pr := setup(t, nil)
		if err := f.svc.RevokeAPIKey(t.Context(), pr, fam.c.key.ID); err != nil {
			t.Fatalf("RevokeAPIKey(child) = %v", err)
		}
		if got := keyIDs(keysOf(t, f.mem, admin.ID)); !slices.Equal(got, []int64{fam.p.key.ID, fam.s.key.ID}) {
			t.Errorf("keys = %v, want the parent and the sibling", got)
		}
	})
	t.Run("faults", func(t *testing.T) {
		t.Parallel()
		for n := 1; n <= 5; n++ {
			for _, panics := range []bool{false, true} {
				fs := newFaultStore()
				f, admin, fam, pr := setup(t, fs)
				if panics {
					fs.panicWrite(n)
					if !crash(func() { _ = f.svc.RevokeAPIKey(t.Context(), pr, fam.p.key.ID) }) {
						t.Errorf("write %d: the panicking revocation returned", n)
					}
				} else {
					fs.failWrite(n)
					if err := f.svc.RevokeAPIKey(t.Context(), pr, fam.p.key.ID); !errors.Is(err, access.ErrAuthBackend) {
						t.Errorf("write %d failing: RevokeAPIKey = %v, want ErrAuthBackend", n, err)
					}
				}
				if got := len(keysOf(t, f.mem, admin.ID)); got != 4 {
					t.Errorf("write %d, panic %t: keys = %d, want all four", n, panics, got)
				}
				if got := len(eventsOf(f.events, account.EventKeyRevoked)); got != 0 {
					t.Errorf("write %d, panic %t: EventKeyRevoked = %d, want none", n, panics, got)
				}
			}
		}
	})
}

// laterClock is a fixed test clock a minute ahead, so a session signed
// in during the test is recent under it and every key minted under it
// shares one ExpiresAt.
func laterClock() *testClock { return newTestClock(time.Now().Add(time.Minute)) }

func TestRevokeDeletesIssuedTokens(t *testing.T) {
	t.Parallel()
	type tokens struct{ childInvite, grandRecovery, sessionInvite access.OneTimeToken }
	setup := func(t *testing.T, fs *faultStore, clock *testClock) (*fixture, *access.User, family, tokens) {
		o := options{store: fs, rules: func() account.Rules {
			r := keyRules()
			r.RevokeKeysOnCredentialChange = true
			return r
		}}
		if clock != nil {
			o.edit = func(c *account.Config) { c.Now = clock.now }
		}
		f := newFixture(t, keyOptions(o, nil))
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		target := mustUser(t, f.mem, "alice", access.RoleUser)
		var expiresIn time.Duration
		if clock != nil {
			expiresIn = time.Hour
		}
		fam := newFamily(t, f, admin, expiresIn)
		return f, admin, fam, tokens{
			childInvite:   seedToken(t, f.mem, access.PurposeInvite, 0, fam.c.key.ID, 24*time.Hour),
			grandRecovery: seedToken(t, f.mem, access.PurposeRecovery, target.ID, fam.g.key.ID, 24*time.Hour),
			sessionInvite: seedToken(t, f.mem, access.PurposeInvite, 0, 0, 24*time.Hour),
		}
	}
	check := func(t *testing.T, f *fixture, tok tokens, revoked bool) {
		t.Helper()
		if got := tokenStored(t, f.mem, tok.childInvite); got == revoked {
			t.Errorf("the child's invite stored = %t, want %t", got, !revoked)
		}
		if got := tokenStored(t, f.mem, tok.grandRecovery); got == revoked {
			t.Errorf("the grandchild's recovery token stored = %t, want %t", got, !revoked)
		}
		if !tokenStored(t, f.mem, tok.sessionInvite) {
			t.Error("the session-issued invite is gone")
		}
	}
	for _, expired := range []bool{false, true} {
		var clock *testClock
		prefix := "live"
		if expired {
			prefix = "expired"
		}
		t.Run(prefix+"_revocation", func(t *testing.T) {
			t.Parallel()
			if expired {
				clock = laterClock()
			}
			fs := newFaultStore()
			f, admin, fam, tok := setup(t, fs, clock)
			pr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
			if expired {
				clock.add(2 * time.Hour)
				keys, err := f.svc.APIKeys(t.Context(), pr)
				if err != nil || len(keys) != 4 {
					t.Fatalf("APIKeys after expiry = %d, %v; want the expired keys still listed", len(keys), err)
				}
				check(t, f, tok, false)
			}
			fs.resetRecord()
			if err := f.svc.RevokeAPIKey(t.Context(), pr, fam.p.key.ID); err != nil {
				t.Fatalf("RevokeAPIKey = %v", err)
			}
			check(t, f, tok, true)
			keyUpdate, tokenUpdate := -1, -2
			for _, c := range fs.recorded() {
				switch c.name {
				case "DeleteAPIKey":
					keyUpdate = c.update
				case "DeleteOneTimeTokensIssuedBy":
					tokenUpdate = c.update
				}
			}
			if keyUpdate != tokenUpdate {
				t.Errorf("keys deleted in Update %d and tokens in %d, want one", keyUpdate, tokenUpdate)
			}
		})
		t.Run(prefix+"_faults", func(t *testing.T) {
			t.Parallel()
			for n := 1; n <= 5; n++ {
				for _, panics := range []bool{false, true} {
					var c *testClock
					if expired {
						c = laterClock()
					}
					fs := newFaultStore()
					f, admin, fam, tok := setup(t, fs, c)
					pr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
					if expired {
						c.add(2 * time.Hour)
					}
					if panics {
						fs.panicWrite(n)
						crash(func() { _ = f.svc.RevokeAPIKey(t.Context(), pr, fam.p.key.ID) })
					} else {
						fs.failWrite(n)
						_ = f.svc.RevokeAPIKey(t.Context(), pr, fam.p.key.ID)
					}
					if got := len(keysOf(t, f.mem, admin.ID)); got != 4 {
						t.Errorf("write %d, panic %t: keys = %d, want all four", n, panics, got)
					}
					check(t, f, tok, false)
				}
			}
		})
	}
	t.Run("set_password", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{options: keyOptions(options{rules: func() account.Rules {
			r := keyRules()
			r.RevokeKeysOnCredentialChange = true
			return r
		}}, nil)})
		admin := passwordUser(t, p.mem, p.hasher, "root", goodPassword)
		admin.Role = access.RoleAdmin
		if err := p.mem.UpdateUser(t.Context(), admin); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		fam := newFamily(t, p.fixture, admin, 0)
		target := mustUser(t, p.mem, "alice", access.RoleUser)
		tok := tokens{
			childInvite:   seedToken(t, p.mem, access.PurposeInvite, 0, fam.c.key.ID, 24*time.Hour),
			grandRecovery: seedToken(t, p.mem, access.PurposeRecovery, target.ID, fam.g.key.ID, 24*time.Hour),
			sessionInvite: seedToken(t, p.mem, access.PurposeInvite, 0, 0, 24*time.Hour),
		}
		pr, _ := p.signedInVia(t, admin, access.MethodPassword)
		if _, err := p.setPassword(t.Context(), pr, goodPassword, newPassword); err != nil {
			t.Fatalf("SetPassword = %v", err)
		}
		if n := len(keysOf(t, p.mem, admin.ID)); n != 0 {
			t.Errorf("keys = %d, want none", n)
		}
		check(t, p.fixture, tok, true)
	})
}

// ownerTear is a Store whose Update transactions list no user gone, and
// which renames user rename to "robert" once a key read ends: when the
// Update whose transaction read the keys returns, or when a key list read
// outside a transaction returns. Any snapshot taken after the key read
// sees a different owner than the one the key read saw.
type ownerTear struct {
	account.Store
	gone, rename *atomic.Int64
}

type goneTx struct {
	account.Tx
	keysRead *bool
	gone     int64
}

func (tx goneTx) ListUsers(ctx context.Context) ([]access.User, error) {
	users, err := tx.Tx.ListUsers(ctx)
	return slices.DeleteFunc(users, func(u access.User) bool { return u.ID == tx.gone }), err
}

func (tx goneTx) ListAPIKeys(ctx context.Context) ([]access.Key, error) {
	*tx.keysRead = true
	return tx.Tx.ListAPIKeys(ctx)
}

func (s ownerTear) Update(ctx context.Context, fn func(tx account.Tx) error) error {
	var keysRead bool
	err := s.Store.Update(ctx, func(tx account.Tx) error {
		return fn(goneTx{Tx: tx, keysRead: &keysRead, gone: s.gone.Load()})
	})
	if !keysRead {
		return err
	}
	if rErr := s.renameNow(ctx); rErr != nil {
		return rErr
	}
	return err
}

func (s ownerTear) ListAPIKeys(ctx context.Context) ([]access.Key, error) {
	keys, err := s.Store.ListAPIKeys(ctx)
	if rErr := s.renameNow(ctx); rErr != nil {
		return nil, rErr
	}
	return keys, err
}

func (s ownerTear) renameNow(ctx context.Context) error {
	if id := s.rename.Swap(0); id != 0 {
		u, found, uErr := s.UserByID(ctx, id)
		if uErr != nil || !found {
			return fmt.Errorf("rename user %d: %t, %w", id, found, uErr)
		}
		u.Username = "robert"
		return s.UpdateUser(ctx, u)
	}
	return nil
}

func TestAllAPIKeysOwner(t *testing.T) {
	t.Parallel()
	var gone, rename atomic.Int64
	f := newFixture(t, keyOptions(options{edit: func(c *account.Config) { c.Store = ownerTear{Store: c.Store, gone: &gone, rename: &rename} }}, nil))
	admin := mustUser(t, f.mem, "root", access.RoleAdmin)
	alice := mustUser(t, f.mem, "alice", access.RoleUser)
	bob := mustUser(t, f.mem, "bob", access.RoleUser)
	apr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
	aliceKey := f.mint(t, account.OutOfBand("admin-socket"), alice.ID, account.NewKey{Scopes: []string{"read"}})
	bobKey := f.mint(t, account.OutOfBand("admin-socket"), bob.ID, account.NewKey{Scopes: []string{"read"}})
	all, err := f.svc.AllAPIKeys(t.Context(), account.As(apr))
	if err != nil {
		t.Fatalf("AllAPIKeys = %v", err)
	}
	want := []account.ListedKey{{Key: aliceKey.key, Owner: "alice"}, {Key: bobKey.key, Owner: "bob"}}
	if len(all) != len(want) {
		t.Fatalf("AllAPIKeys = %d rows, want %d", len(all), len(want))
	}
	for i := range want {
		if all[i].Key.ID != want[i].Key.ID || all[i].Key.UserID != want[i].Key.UserID || all[i].Owner != want[i].Owner {
			t.Errorf("row %d = key %d of user %d owned by %q, want key %d of user %d owned by %q", i, all[i].Key.ID, all[i].Key.UserID, all[i].Owner, want[i].Key.ID, want[i].Key.UserID, want[i].Owner)
		}
	}
	t.Run("rename_after_key_read", func(t *testing.T) {
		rename.Store(bob.ID)
		defer rename.Store(0)
		all, err := f.svc.AllAPIKeys(t.Context(), account.As(apr))
		if err != nil || len(all) != 2 || all[0].Owner != "alice" || all[1].Owner != "bob" {
			t.Errorf("AllAPIKeys = %+v, %v; want the owners of the key read's snapshot, alice and bob", all, err)
		}
	})
	t.Run("owner_row_gone", func(t *testing.T) {
		gone.Store(bob.ID)
		defer gone.Store(0)
		all, err := f.svc.AllAPIKeys(t.Context(), account.As(apr))
		if err != nil || len(all) != 2 || all[0].Owner != "alice" || all[1].Owner != "" {
			t.Errorf("AllAPIKeys with bob absent from the snapshot = %+v, %v; want alice's owner and an empty one", all, err)
		}
	})
}

func TestAllKeysActors(t *testing.T) {
	t.Parallel()
	socket := account.OutOfBand("admin socket")
	t.Run("out_of_band", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		k := f.mint(t, socket, u.ID, account.NewKey{Scopes: []string{"read"}})
		all, err := f.svc.AllAPIKeys(t.Context(), socket)
		if err != nil || !slices.Equal(listedKeyIDs(all), []int64{k.key.ID}) || all[0].Owner != "alice" {
			t.Errorf("AllAPIKeys(OutOfBand) = %+v, %v; want alice's key", all, err)
		}
		if err := f.svc.RevokeAnyAPIKey(t.Context(), socket, k.key.ID); err != nil {
			t.Fatalf("RevokeAnyAPIKey(OutOfBand) = %v", err)
		}
		if keys := keysOf(t, f.mem, u.ID); len(keys) != 0 {
			t.Errorf("alice's keys after the revoke = %v, want none", keyIDs(keys))
		}
		channel := account.EventActor{OutOfBand: "admin socket"}
		revoked := eventsOf(f.events, account.EventKeyRevoked)
		if len(revoked) != 1 || revoked[0].KeyID != k.key.ID || revoked[0].Actor != channel {
			t.Errorf("EventKeyRevoked = %+v, want one for alice's key naming the admin socket", revoked)
		}
		var logged []account.EventActor
		for _, e := range logOf(t, f.mem) {
			if e.Event.Kind == account.EventKeyRevoked {
				logged = append(logged, e.Event.Actor)
			}
		}
		if !slices.Equal(logged, []account.EventActor{channel}) {
			t.Errorf("logged key_revoked actors = %+v, want the admin socket", logged)
		}
	})
	t.Run("zero_actor", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		k := f.mint(t, socket, u.ID, account.NewKey{Scopes: []string{"read"}})
		if _, err := f.svc.AllAPIKeys(t.Context(), account.Actor{}); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("AllAPIKeys(zero Actor) = %v, want ErrSessionRequired", err)
		}
		if err := f.svc.RevokeAnyAPIKey(t.Context(), account.Actor{}, k.key.ID); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("RevokeAnyAPIKey(zero Actor) = %v, want ErrSessionRequired", err)
		}
	})
	t.Run("revoked_key_principal", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		apr := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		scoped := f.mint(t, socket, admin.ID, account.NewKey{Scopes: []string{scopeAdmin}})
		target := f.mint(t, socket, u.ID, account.NewKey{Scopes: []string{"read"}})
		if err := f.svc.RevokeAPIKey(t.Context(), apr, scoped.key.ID); err != nil {
			t.Fatalf("RevokeAPIKey = %v", err)
		}
		if all, err := f.svc.AllAPIKeys(t.Context(), account.As(scoped.p)); reason(err) != "key_not_current" || !errors.Is(err, account.ErrPolicyRefused) {
			t.Errorf("AllAPIKeys from a revoked key = %d rows, %v; want key_not_current", len(all), err)
		}
		if err := f.svc.RevokeAnyAPIKey(t.Context(), account.As(scoped.p), target.key.ID); reason(err) != "key_not_current" {
			t.Errorf("guard: RevokeAnyAPIKey from a revoked key = %v, want key_not_current", err)
		}
		if keys := keysOf(t, f.mem, u.ID); !slices.Equal(keyIDs(keys), []int64{target.key.ID}) {
			t.Errorf("alice's keys = %v, want her key kept", keyIDs(keys))
		}
	})
}
