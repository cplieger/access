package account_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// ownKeysWorld is a user holding a key carrying scopes and a sibling key.
type ownKeysWorld struct {
	f       *fixture
	u       *access.User
	p       access.Principal
	key     access.Key
	sibling access.Key
}

func newOwnKeysWorld(t *testing.T, o options, policy account.Policy, role access.Role, scopes ...string) ownKeysWorld {
	t.Helper()
	f := newFixture(t, keyOptions(o, policy))
	u := mustUser(t, f.mem, "alice", role)
	p, key := f.keyPrincipalFor(t, f.authn, u, time.Time{}, nil, scopes...)
	return ownKeysWorld{f: f, u: u, p: p, key: key, sibling: seedKey(t, f.mem, u.ID, "Agent", time.Time{})}
}

// ownKeyCalls is the three own-key operations made by p on w's sibling.
func ownKeyCalls(t *testing.T, w ownKeysWorld, p access.Principal) map[string]error {
	t.Helper()
	_, list := w.f.svc.APIKeys(t.Context(), p)
	return map[string]error{
		"APIKeys":      list,
		"RenameAPIKey": w.f.svc.RenameAPIKey(t.Context(), p, w.sibling.ID, "Deploy bot"),
		"RevokeAPIKey": w.f.svc.RevokeAPIKey(t.Context(), p, w.sibling.ID),
	}
}

// requireUntouched fails unless w's sibling keeps its label and both keys
// are stored.
func requireUntouched(t *testing.T, w ownKeysWorld) {
	t.Helper()
	keys, err := w.f.mem.ListAPIKeysByUserID(t.Context(), w.u.ID)
	if err != nil {
		t.Fatalf("ListAPIKeysByUserID: %v", err)
	}
	i := slices.IndexFunc(keys, func(k access.Key) bool { return k.ID == w.sibling.ID })
	if len(keys) != 2 || i < 0 || keys[i].Label != w.sibling.Label {
		t.Errorf("keys = %+v, want both keys with the sibling's label %q", keys, w.sibling.Label)
	}
}

// TestOwnKeysByKey: a key manages its own user's keys under
// CreateKeysScope: list, rename and revoke join CreateAPIKey's key arm,
// through the same
// Policy operation, KeysAdminOnly included.
func TestOwnKeysByKey(t *testing.T) {
	t.Parallel()
	t.Run("key_lists_renames_and_revokes", func(t *testing.T) {
		t.Parallel()
		w := newOwnKeysWorld(t, options{}, nil, access.RoleAdmin, scopeKeys)
		keys, err := w.f.svc.APIKeys(t.Context(), w.p)
		if err != nil || len(keys) != 2 || keys[0].ID != w.key.ID || keys[1].ID != w.sibling.ID {
			t.Errorf("APIKeys = %+v, %v; want the key and its sibling by ID", keys, err)
		}
		if err := w.f.svc.RenameAPIKey(t.Context(), w.p, w.sibling.ID, "Deploy bot"); err != nil {
			t.Errorf("RenameAPIKey = %v", err)
		}
		mark := len(w.f.events.all())
		if err := w.f.svc.RevokeAPIKey(t.Context(), w.p, w.sibling.ID); err != nil {
			t.Fatalf("RevokeAPIKey = %v", err)
		}
		evs := w.f.events.all()[mark:]
		if len(evs) != 1 || evs[0].Kind != account.EventKeyRevoked || evs[0].KeyID != w.sibling.ID || evs[0].Actor.KeyID != w.key.ID {
			t.Errorf("events = %+v, want one key_revoked of the sibling by the key", evs)
		}
	})
	t.Run("key_revokes_itself", func(t *testing.T) {
		t.Parallel()
		w := newOwnKeysWorld(t, options{}, nil, access.RoleAdmin, scopeKeys)
		if err := w.f.svc.RevokeAPIKey(t.Context(), w.p, w.key.ID); err != nil {
			t.Fatalf("RevokeAPIKey(itself) = %v", err)
		}
		if _, found, err := w.f.mem.APIKeyByHash(t.Context(), w.key.KeyHash); err != nil || found {
			t.Errorf("the key after revoking itself: found %t, %v", found, err)
		}
	})
	t.Run("key_without_the_scope", func(t *testing.T) {
		t.Parallel()
		w := newOwnKeysWorld(t, options{}, nil, access.RoleAdmin, "read")
		for name, err := range ownKeyCalls(t, w, w.p) {
			if !errors.Is(err, account.ErrScopeRequired) {
				t.Errorf("%s = %v, want ErrScopeRequired", name, err)
			}
		}
		requireUntouched(t, w)
	})
	t.Run("scope_unset", func(t *testing.T) {
		t.Parallel()
		w := newOwnKeysWorld(t, options{edit: func(c *account.Config) { c.CreateKeysScope = "" }}, nil, access.RoleAdmin, scopeKeys)
		for name, err := range ownKeyCalls(t, w, w.p) {
			if !errors.Is(err, account.ErrSessionRequired) {
				t.Errorf("%s = %v, want ErrSessionRequired", name, err)
			}
		}
		requireUntouched(t, w)
	})
	t.Run("policy_decides_the_key", func(t *testing.T) {
		t.Parallel()
		gate := &gatePolicy{}
		w := newOwnKeysWorld(t, options{}, gate, access.RoleAdmin, scopeKeys)
		gate.arm(account.OpCreateOwnKey)
		for name, err := range ownKeyCalls(t, w, w.p) {
			if !errors.Is(err, account.ErrPolicyRefused) || reasonOf(err) != gateReason {
				t.Errorf("%s = %v, want the Policy's refusal of create_own_key", name, err)
			}
		}
		requireUntouched(t, w)
		for _, d := range gate.decisions {
			if p, ok := d.Actor.Principal(); d.Op != account.OpCreateOwnKey || !ok || p.KeyID != w.key.ID || d.Target == nil || d.Target.ID != w.u.ID {
				t.Errorf("decision %+v, want create_own_key by the key on its own user", d)
			}
		}
		if len(gate.decisions) != 3 {
			t.Errorf("%d decisions, want one per call", len(gate.decisions))
		}
		gate.arm(account.OpCreateOwnKey)
		if keys, err := w.f.svc.APIKeys(t.Context(), w.f.sessionPrincipal(t, w.u, time.Now().Add(-time.Hour))); err != nil || len(keys) != 2 || len(gate.decisions) != 0 {
			t.Errorf("the same user's session: APIKeys = %d keys, %v, %d decisions; want its two keys and no Policy asked", len(keys), err, len(gate.decisions))
		}
	})
	t.Run("key_admin_under_keys_admin_only", func(t *testing.T) {
		t.Parallel()
		w := newOwnKeysWorld(t, options{}, account.RolePolicy{KeysAdminOnly: true}, access.RoleAdmin, scopeKeys)
		for name, err := range ownKeyCalls(t, w, w.p) {
			if err != nil {
				t.Errorf("%s by an admin's key = %v", name, err)
			}
		}
	})
	t.Run("authority_reread", func(t *testing.T) {
		t.Parallel()
		w := newOwnKeysWorld(t, options{}, nil, access.RoleAdmin, scopeKeys)
		w.u.Enabled = false
		if err := w.f.mem.UpdateUser(t.Context(), w.u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		for name, err := range ownKeyCalls(t, w, w.p) {
			if !errors.Is(err, account.ErrPolicyRefused) || reasonOf(err) != account.ReasonKeyNotCurrent {
				t.Errorf("%s after the key's user was disabled = %v, want key_not_current", name, err)
			}
		}
		requireUntouched(t, w)
	})
	t.Run("session_stale_still_manages", func(t *testing.T) {
		t.Parallel()
		w := newOwnKeysWorld(t, options{}, nil, access.RoleAdmin, scopeKeys)
		for name, err := range ownKeyCalls(t, w, w.f.sessionPrincipal(t, w.u, time.Now().Add(-time.Hour))) {
			if err != nil {
				t.Errorf("%s by a full session = %v", name, err)
			}
		}
	})
}
