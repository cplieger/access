package account_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// retireWorld is boss, an admin holding one key with the user and key
// permissions, alice, an enabled RoleUser, and dave, a disabled one, over a
// faultStore.
type retireWorld struct {
	f                 *fixture
	fs                *faultStore
	boss, alice, dave *access.User
	key               account.CreatedKey
}

func newRetireWorld(t *testing.T) retireWorld {
	t.Helper()
	w := retireWorld{fs: newFaultStore()}
	w.f = newFixture(t, keyOptions(options{store: w.fs}, nil))
	w.boss = mustUser(t, w.f.mem, "boss", access.RoleAdmin)
	w.alice = mustUser(t, w.f.mem, "alice", access.RoleUser)
	w.dave = mustUser(t, w.f.mem, "dave", access.RoleUser)
	w.dave.Enabled = false
	if err := w.f.mem.Update(t.Context(), func(tx account.Tx) error { return tx.UpdateUser(t.Context(), w.dave) }); err != nil {
		t.Fatalf("disable dave: %v", err)
	}
	created, err := w.f.svc.CreateAPIKey(t.Context(), account.OutOfBand("admin socket"), w.boss.ID,
		account.NewKey{Label: "Automation", Scopes: []string{scopeUsers, scopeKeys}})
	if err != nil {
		t.Fatalf("CreateAPIKey = %v", err)
	}
	w.key = created
	return w
}

// rotate rotates boss's key out of band.
func (w retireWorld) rotate(ctx context.Context, t *testing.T) account.RotatedKey {
	t.Helper()
	rot, err := w.f.svc.RotateAPIKey(ctx, account.OutOfBand("admin socket"), w.key.Key.ID)
	if err != nil {
		t.Fatalf("RotateAPIKey = %v", err)
	}
	return rot
}

// principal is the principal plaintext authenticates as.
func (w retireWorld) principal(t *testing.T, plaintext access.Secret) access.Principal {
	t.Helper()
	p, err := w.f.bearer(t, plaintext)
	if err != nil {
		t.Fatalf("Authenticate(key) = %v", err)
	}
	return p
}

// retiring is the key's first secret verified during the overlap of the
// rotation that superseded it.
func (w retireWorld) retiring(t *testing.T) access.Principal {
	t.Helper()
	w.rotate(t.Context(), t)
	return w.principal(t, w.key.Plaintext)
}

// inFlight is the key's first secret verified while it is current; the
// next Update rotates the key before its callback runs.
func (w retireWorld) inFlight(t *testing.T) access.Principal {
	t.Helper()
	p := w.principal(t, w.key.Plaintext)
	w.fs.onUpdate(func(ctx context.Context, _ int) {
		w.fs.onUpdate(nil)
		w.rotate(ctx, t)
	})
	return p
}

// issuing is one operation that creates or restores a way in, run as p,
// with the Operation its refusal names.
type issuing struct {
	run  func(ctx context.Context, w retireWorld, p access.Principal) error
	name string
	op   account.Operation
}

func issuingOperations() []issuing {
	enable, role := true, access.RoleUser
	update := func(ch account.UserChange) func(context.Context, retireWorld, access.Principal) error {
		return func(ctx context.Context, w retireWorld, p access.Principal) error {
			_, err := w.f.svc.UpdateUser(ctx, p, w.dave.ID, ch)
			return err
		}
	}
	return []issuing{
		{name: "CreateAPIKey", op: account.OpCreateOwnKey, run: func(ctx context.Context, w retireWorld, p access.Principal) error {
			_, err := w.f.svc.CreateAPIKey(ctx, account.As(p), w.boss.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{scopeKeys}})
			return err
		}},
		{name: "CreateUser", op: account.OpCreateUser, run: func(ctx context.Context, w retireWorld, p access.Principal) error {
			_, err := w.f.svc.CreateUser(ctx, account.As(p), account.NewUser{Username: "carol"})
			return err
		}},
		{name: "CreateInvite", op: account.OpInvite, run: func(ctx context.Context, w retireWorld, p access.Principal) error {
			_, err := w.f.svc.CreateInvite(ctx, p, "", 0)
			return err
		}},
		{name: "IssueRecovery", op: account.OpIssueRecovery, run: func(ctx context.Context, w retireWorld, p access.Principal) error {
			_, err := w.f.svc.IssueRecovery(ctx, account.As(p), w.alice.ID, 0)
			return err
		}},
		{name: "UpdateUser_enable", op: account.OpSetEnabled, run: update(account.UserChange{Enabled: &enable})},
		{name: "UpdateUser_role_and_enable", op: account.OpSetEnabled, run: update(account.UserChange{Role: &role, Enabled: &enable})},
	}
}

// TestRetiringKeyRefused: a key principal presenting a secret a rotation
// superseded, whether verified during the overlap or verified before the
// rotation committed inside the operation's window, issues nothing.
func TestRetiringKeyRefused(t *testing.T) {
	t.Parallel()
	modes := map[string]func(retireWorld, *testing.T) access.Principal{
		"previous_secret": retireWorld.retiring,
		"in_flight":       retireWorld.inFlight,
	}
	for _, op := range issuingOperations() {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			for mode, principal := range modes {
				t.Run(mode, func(t *testing.T) {
					t.Parallel()
					w := newRetireWorld(t)
					p := principal(w, t)
					before := len(w.f.events.all())
					err := op.run(t.Context(), w, p)
					if pe, ok := errors.AsType[*account.PolicyError](err); !ok || pe.Op != op.op || pe.Reason != account.ReasonKeyRetiring {
						t.Fatalf("error = %v, want *PolicyError{%s, key_retiring}", err, op.op)
					}
					if !errors.Is(err, account.ErrPolicyRefused) {
						t.Errorf("error = %v, want it to match ErrPolicyRefused", err)
					}
					for _, ev := range w.f.events.all()[before:] {
						if ev.Kind != account.EventKeyRotated {
							t.Errorf("event %s after the refusal, want none but the rotation", ev.Kind)
						}
					}
					stored := keysOf(t, w.f.mem, w.boss.ID)
					if len(stored) != 1 || stored[0].KeyHash.Equal(w.key.Key.KeyHash) {
						t.Errorf("boss's keys = %+v, want the one key, rotated", stored)
					}
				})
			}
		})
	}
}

// TestGuardRetiringKeyDisableAllowed: a retiring key's disable, or a role
// change alone, restores no way in and is not refused.
func TestGuardRetiringKeyDisableAllowed(t *testing.T) {
	t.Parallel()
	disable, role := false, access.RoleUser
	for name, ch := range map[string]account.UserChange{
		"disable":    {Enabled: &disable},
		"role_alone": {Role: &role},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newRetireWorld(t)
			u, err := w.f.svc.UpdateUser(t.Context(), w.retiring(t), w.alice.ID, ch)
			if err != nil {
				t.Fatalf("UpdateUser = %v, want nil", err)
			}
			if u.Enabled != (ch.Enabled == nil) || u.Role != access.RoleUser {
				t.Errorf("user = %+v, want the change applied", u)
			}
		})
	}
}

// TestGuardCurrentKeyCreateUserAndCreateAPIKeyPass: a key's current
// secret, never rotated or the new one after a rotation, still creates a
// user and mints a key.
func TestGuardCurrentKeyCreateUserAndCreateAPIKeyPass(t *testing.T) {
	t.Parallel()
	for name, current := range map[string]func(retireWorld, *testing.T) access.Principal{
		"never_rotated": func(w retireWorld, t *testing.T) access.Principal { return w.principal(t, w.key.Plaintext) },
		"new_secret": func(w retireWorld, t *testing.T) access.Principal {
			return w.principal(t, w.rotate(t.Context(), t).Plaintext)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newRetireWorld(t)
			p := current(w, t)
			if _, err := w.f.svc.CreateUser(t.Context(), account.As(p), account.NewUser{Username: "carol"}); err != nil {
				t.Errorf("CreateUser = %v, want nil", err)
			}
			if _, err := w.f.svc.CreateAPIKey(t.Context(), account.As(p), w.boss.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{scopeKeys}}); err != nil {
				t.Errorf("CreateAPIKey = %v, want nil", err)
			}
		})
	}
}
