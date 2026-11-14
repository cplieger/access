package account_test

import (
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// seedKey stores a key of userID with label and expiry directly, as an
// existing store holds it, past every create-time rule.
func seedKey(t *testing.T, s account.Store, userID int64, label string, expires time.Time) access.Key {
	t.Helper()
	g, err := access.GenerateAPIKey("")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	key := &access.Key{
		UserID: userID, KeyHash: g.Hash, KeyPrefix: g.DisplayPrefix, KeySuffix: g.DisplaySuffix,
		Label: label, Scopes: []string{"read"}, CreatedAt: time.Now(), ExpiresAt: expires,
	}
	if err := s.CreateAPIKey(t.Context(), key); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	return *key
}

func TestKeyLabelRequired(t *testing.T) {
	t.Parallel()
	f := newFixture(t, keyOptions(options{}, nil))
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	_, err := f.svc.CreateAPIKey(t.Context(), account.OutOfBand("admin-socket"), u.ID, account.NewKey{Scopes: []string{"read"}})
	if te, ok := errors.AsType[*account.TextError](err); !ok || *te != (account.TextError{Field: account.TextFieldLabel, Reason: account.ReasonEmpty}) {
		t.Errorf("CreateAPIKey with no label = %v, want TextError{label, empty}", err)
	}
	if keys, _ := f.mem.ListAPIKeysByUserID(t.Context(), u.ID); len(keys) != 0 {
		t.Errorf("keys after the refusal = %d, want none", len(keys))
	}
}

func TestKeyLabelUnique(t *testing.T) {
	t.Parallel()
	oob := account.OutOfBand("admin-socket")
	for _, tc := range []struct {
		name, first, second string
	}{
		{"case", "Agent", "agent"},
		{"full_case_folding", "Straße", "STRASSE"},
		{"nfc", "Caf\u00e9", "Cafe\u0301"},
		{"identical", "deploy", "deploy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, keyOptions(options{}, nil))
			u := mustUser(t, f.mem, "alice", access.RoleUser)
			f.mint(t, oob, u.ID, account.NewKey{Label: tc.first, Scopes: []string{"read"}})
			before := len(eventsOf(f.events, account.EventKeyMinted))
			if _, err := f.svc.CreateAPIKey(t.Context(), oob, u.ID, account.NewKey{Label: tc.second, Scopes: []string{"read"}}); !errors.Is(err, account.ErrKeyLabelTaken) {
				t.Errorf("CreateAPIKey(%q) after %q = %v, want ErrKeyLabelTaken", tc.second, tc.first, err)
			}
			if keys, _ := f.mem.ListAPIKeysByUserID(t.Context(), u.ID); len(keys) != 1 {
				t.Errorf("keys after the refusal = %d, want 1", len(keys))
			}
			if got := len(eventsOf(f.events, account.EventKeyMinted)); got != before {
				t.Errorf("EventKeyMinted after the refusal = %d, want %d", got, before)
			}
		})
	}
	t.Run("distinct", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		f.mint(t, oob, u.ID, account.NewKey{Label: "Agent", Scopes: []string{"read"}})
		f.mint(t, oob, u.ID, account.NewKey{Label: "Agent 2", Scopes: []string{"read"}})
	})
	t.Run("another_owner", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		alice := mustUser(t, f.mem, "alice", access.RoleUser)
		bob := mustUser(t, f.mem, "bob", access.RoleUser)
		f.mint(t, oob, alice.ID, account.NewKey{Label: "Agent", Scopes: []string{"read"}})
		f.mint(t, oob, bob.ID, account.NewKey{Label: "Agent", Scopes: []string{"read"}})
	})
	t.Run("expired_key_frees_its_label", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		seedKey(t, f.mem, u.ID, "Agent", time.Now().Add(-time.Minute))
		f.mint(t, oob, u.ID, account.NewKey{Label: "agent", Scopes: []string{"read"}})
	})
	t.Run("unexpired_expiring_key_holds_its_label", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		seedKey(t, f.mem, u.ID, "Agent", time.Now().Add(time.Hour))
		if _, err := f.svc.CreateAPIKey(t.Context(), oob, u.ID, account.NewKey{Label: "agent", Scopes: []string{"read"}}); !errors.Is(err, account.ErrKeyLabelTaken) {
			t.Errorf("CreateAPIKey over an unexpired key's label = %v, want ErrKeyLabelTaken", err)
		}
	})
	t.Run("policy_answers_before_the_label", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		u := mustUser(t, f.mem, "carol", access.RoleUser)
		seedKey(t, f.mem, u.ID, "Agent", time.Time{})
		u.Enabled = false
		if err := f.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		if _, err := f.svc.CreateAPIKey(t.Context(), oob, u.ID, account.NewKey{Label: "Agent", Scopes: []string{"read"}}); reason(err) != account.ReasonTargetNotEligible {
			t.Errorf("CreateAPIKey for a disabled owner over a taken label = %v, want target_not_eligible", err)
		}
	})
}

// TestGuardExistingDuplicateLabelsReadable: a store holding keys from
// before the label rule, two with one label and one with none, lists them
// and revokes each by ID.
func TestGuardExistingDuplicateLabelsReadable(t *testing.T) {
	t.Parallel()
	f := newFixture(t, keyOptions(options{}, nil))
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	seeded := []access.Key{
		seedKey(t, f.mem, u.ID, "Agent", time.Time{}),
		seedKey(t, f.mem, u.ID, "agent", time.Time{}),
		seedKey(t, f.mem, u.ID, "", time.Time{}),
	}
	pr := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	keys, err := f.svc.APIKeys(t.Context(), pr)
	if err != nil || len(keys) != len(seeded) {
		t.Fatalf("APIKeys = %d keys, %v; want %d", len(keys), err, len(seeded))
	}
	all, err := f.svc.AllAPIKeys(t.Context(), account.OutOfBand("admin-socket"))
	if err != nil || len(all) != len(seeded) {
		t.Fatalf("AllAPIKeys = %d keys, %v; want %d", len(all), err, len(seeded))
	}
	for _, k := range seeded {
		if err := f.svc.RevokeAPIKey(t.Context(), pr, k.ID); err != nil {
			t.Errorf("RevokeAPIKey(%d, %q) = %v", k.ID, k.Label, err)
		}
	}
	if left, _ := f.mem.ListAPIKeysByUserID(t.Context(), u.ID); len(left) != 0 {
		t.Errorf("keys after revoking each = %d, want none", len(left))
	}
}
