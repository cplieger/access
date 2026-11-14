package account_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// rotWorld is alice holding one used key and a recent session, under a
// fixed clock a minute ahead, over a faultStore.
type rotWorld struct {
	f     *fixture
	fs    *faultStore
	clock *testClock
	pol   *gatePolicy
	alice *access.User
	sess  access.Principal
	key   account.CreatedKey
}

func newRotWorld(t *testing.T, rules func(*account.Rules)) rotWorld {
	t.Helper()
	w := rotWorld{fs: newFaultStore(), clock: laterClock(), pol: &gatePolicy{}}
	o := options{store: w.fs, edit: func(c *account.Config) { c.Now = w.clock.now }, rules: func() account.Rules {
		r := keyRules()
		if rules != nil {
			rules(&r)
		}
		return r
	}}
	w.f = newFixture(t, keyOptions(o, w.pol))
	w.alice = mustUser(t, w.f.mem, "alice", access.RoleUser)
	w.sess = w.f.sessionPrincipal(t, w.alice, access.SessionFull, time.Now())
	w.key = w.create(t, w.alice, "Deploy")
	if _, err := w.f.bearer(t, w.key.Plaintext); err != nil {
		t.Fatalf("Authenticate(key) = %v", err)
	}
	return w
}

// create mints a key of u out of band and returns it with its plaintext.
func (w rotWorld) create(t *testing.T, u *access.User, label string) account.CreatedKey {
	t.Helper()
	created, err := w.f.svc.CreateAPIKey(t.Context(), account.OutOfBand("admin socket"), u.ID, account.NewKey{Label: label, Scopes: []string{"read"}, ExpiresIn: 48 * time.Hour})
	if err != nil {
		t.Fatalf("CreateAPIKey = %v", err)
	}
	return created
}

// stored is u's key id as the store holds it.
func (w rotWorld) stored(t *testing.T, userID, id int64) access.Key {
	t.Helper()
	for _, k := range keysOf(t, w.f.mem, userID) {
		if k.ID == id {
			return k
		}
	}
	t.Fatalf("key %d of user %d is gone", id, userID)
	return access.Key{}
}

// grants reports whether plaintext authenticates as key id.
func (w rotWorld) grants(t *testing.T, plaintext access.Secret, id int64) bool {
	t.Helper()
	p, err := w.f.bearer(t, plaintext)
	return err == nil && p.KeyID == id
}

// unchanged fails t when alice's key is not as created and last used.
func (w rotWorld) unchanged(t *testing.T) {
	t.Helper()
	k := w.stored(t, w.alice.ID, w.key.Key.ID)
	if !k.KeyHash.Equal(w.key.Key.KeyHash) || !k.PreviousHash.IsZero() || !k.PreviousUntil.IsZero() || k.LastUsedAt.IsZero() {
		t.Errorf("key after the refusal = %+v, want its secret and last use as before", k)
	}
	if n := len(eventsOf(w.f.events, account.EventKeyRotated)); n != 0 {
		t.Errorf("EventKeyRotated after the refusal = %d, want none", n)
	}
}

func TestRotateAPIKey(t *testing.T) {
	t.Parallel()
	t.Run("session_rotates_its_key", func(t *testing.T) {
		t.Parallel()
		w := newRotWorld(t, nil)
		before := w.stored(t, w.alice.ID, w.key.Key.ID)
		rot, err := w.f.svc.RotateAPIKey(t.Context(), account.As(w.sess), w.key.Key.ID)
		if err != nil {
			t.Fatalf("RotateAPIKey = %v", err)
		}
		k := w.stored(t, w.alice.ID, w.key.Key.ID)
		if k.KeyHash.Equal(before.KeyHash) || !k.PreviousHash.Equal(before.KeyHash) {
			t.Errorf("stored KeyHash, PreviousHash = %v, %v; want a new hash and the superseded one", k.KeyHash, k.PreviousHash)
		}
		if want := w.clock.now().Add(time.Hour); !k.PreviousUntil.Equal(want) {
			t.Errorf("PreviousUntil = %v, want now plus the 1h default, %v", k.PreviousUntil, want)
		}
		if !k.LastUsedAt.IsZero() {
			t.Errorf("LastUsedAt = %v, want zero after the rotation", k.LastUsedAt)
		}
		if k.Label != before.Label || !slices.Equal(k.Scopes, before.Scopes) || !k.ExpiresAt.Equal(before.ExpiresAt) ||
			!k.CreatedAt.Equal(before.CreatedAt) || k.UserID != before.UserID || !slices.Equal(k.LineageIDs, before.LineageIDs) {
			t.Errorf("stored key = %+v, want everything but the secret kept from %+v", k, before)
		}
		if k.KeyPrefix == before.KeyPrefix && k.KeySuffix == before.KeySuffix {
			t.Errorf("display parts = %q…%q, want the new secret's", k.KeyPrefix, k.KeySuffix)
		}
		if got := rot.Key; got.ID != k.ID || !got.KeyHash.Equal(k.KeyHash) || !got.PreviousHash.Equal(k.PreviousHash) ||
			!got.PreviousUntil.Equal(k.PreviousUntil) || !got.LastUsedAt.IsZero() || got.KeyPrefix != k.KeyPrefix || got.KeySuffix != k.KeySuffix || got.Label != k.Label {
			t.Errorf("RotatedKey.Key = %+v, want the stored key %+v", got, k)
		}
		if !access.APIKeyHash(rot.Plaintext.Reveal()).Equal(k.KeyHash) {
			t.Error("Plaintext does not hash to the stored KeyHash")
		}
		if !w.grants(t, w.key.Plaintext, k.ID) || !w.grants(t, rot.Plaintext, k.ID) {
			t.Error("want both the superseded and the new secret to verify during the overlap")
		}
		if rot.Issued.Session.ID != w.sess.SessionID || rot.Issued.Token.IsZero() {
			t.Fatalf("Issued = %+v, want the rotated session %s with its token", rot.Issued, w.sess.SessionID)
		}
		if p, err := w.f.authenticate(t.Context(), rot.Issued.Token); err != nil || p.SessionID != w.sess.SessionID {
			t.Errorf("Authenticate(Issued.Token) = %+v, %v; want session %s", p, err, w.sess.SessionID)
		}
		if _, found, _ := w.f.mem.SessionByHash(t.Context(), w.sess.SessionTokenHash()); found {
			t.Error("the session's old token still finds it, want it rotated")
		}
		evs := eventsOf(w.f.events, account.EventKeyRotated)
		want := account.Event{Kind: account.EventKeyRotated, UserID: w.alice.ID, KeyID: k.ID, Actor: actorOf(w.sess)}
		if len(evs) != 1 || !sameEvent(evs[0], want) {
			t.Errorf("EventKeyRotated = %+v, want one %+v", evs, want)
		}
	})
	t.Run("overlap_from_rules", func(t *testing.T) {
		t.Parallel()
		w := newRotWorld(t, func(r *account.Rules) { r.KeyRotationOverlap = 10 * time.Minute })
		rot, err := w.f.svc.RotateAPIKey(t.Context(), account.As(w.sess), w.key.Key.ID)
		if err != nil {
			t.Fatalf("RotateAPIKey = %v", err)
		}
		if want := w.clock.now().Add(10 * time.Minute); !rot.Key.PreviousUntil.Equal(want) {
			t.Errorf("PreviousUntil = %v, want now plus Rules.KeyRotationOverlap, %v", rot.Key.PreviousUntil, want)
		}
	})
	t.Run("rotation_during_overlap", func(t *testing.T) {
		t.Parallel()
		w := newRotWorld(t, nil)
		b, err := w.f.svc.RotateAPIKey(t.Context(), account.OutOfBand("admin socket"), w.key.Key.ID)
		if err != nil {
			t.Fatalf("first RotateAPIKey = %v", err)
		}
		c, err := w.f.svc.RotateAPIKey(t.Context(), account.OutOfBand("admin socket"), w.key.Key.ID)
		if err != nil {
			t.Fatalf("second RotateAPIKey = %v", err)
		}
		if k := w.stored(t, w.alice.ID, w.key.Key.ID); !k.PreviousHash.Equal(b.Key.KeyHash) || !k.KeyHash.Equal(c.Key.KeyHash) {
			t.Errorf("stored key = %+v, want KeyHash the third secret and PreviousHash the second", k)
		}
		if w.grants(t, w.key.Plaintext, w.key.Key.ID) {
			t.Error("the first secret verifies after a second rotation, want only the one just superseded")
		}
		if !w.grants(t, b.Plaintext, w.key.Key.ID) || !w.grants(t, c.Plaintext, w.key.Key.ID) {
			t.Error("want the second and third secrets to verify")
		}
	})
	t.Run("out_of_band", func(t *testing.T) {
		t.Parallel()
		w := newRotWorld(t, nil)
		rot, err := w.f.svc.RotateAPIKey(t.Context(), account.OutOfBand("admin socket"), w.key.Key.ID)
		if err != nil {
			t.Fatalf("RotateAPIKey(OutOfBand) = %v", err)
		}
		if !rot.Issued.Token.IsZero() || rot.Issued.Session.ID != "" {
			t.Errorf("Issued = %+v, want zero for an out-of-band actor", rot.Issued)
		}
		if !w.grants(t, rot.Plaintext, w.key.Key.ID) {
			t.Error("the new secret does not verify")
		}
		evs := eventsOf(w.f.events, account.EventKeyRotated)
		want := account.Event{Kind: account.EventKeyRotated, UserID: w.alice.ID, KeyID: w.key.Key.ID, Actor: account.EventActor{OutOfBand: "admin socket"}}
		if len(evs) != 1 || !sameEvent(evs[0], want) {
			t.Errorf("EventKeyRotated = %+v, want one %+v", evs, want)
		}
	})
	t.Run("not_a_session", func(t *testing.T) {
		t.Parallel()
		w := newRotWorld(t, nil)
		keyP, err := w.f.bearer(t, w.key.Plaintext)
		if err != nil {
			t.Fatalf("Authenticate(key) = %v", err)
		}
		for name, a := range map[string]account.Actor{
			"own_key":          account.As(keyP),
			"bypass":           account.As(w.f.bypassPrincipal(t)),
			"custom":           account.As(w.f.customPrincipal(t, access.MethodAPIKey, w.key.Key.ID, scopeKeys)),
			"recovery_session": account.As(w.f.sessionPrincipal(t, w.alice, access.SessionRecovery, time.Now())),
			"zero_principal":   account.As(access.Principal{}),
			"zero_actor":       {},
		} {
			t.Run(name, func(t *testing.T) {
				w.fs.resetRecord()
				if _, err := w.f.svc.RotateAPIKey(t.Context(), a, w.key.Key.ID); !errors.Is(err, account.ErrSessionRequired) {
					t.Errorf("RotateAPIKey = %v, want ErrSessionRequired", err)
				}
				if calls := w.fs.recorded(); len(calls) != 0 {
					t.Errorf("store calls before the refusal = %v, want none", calls)
				}
			})
		}
		w.unchanged(t)
	})
	t.Run("stale_session", func(t *testing.T) {
		t.Parallel()
		w := newRotWorld(t, nil)
		stale := w.f.sessionPrincipal(t, w.alice, access.SessionFull, time.Now().Add(-time.Hour))
		if _, err := w.f.svc.RotateAPIKey(t.Context(), account.As(stale), w.key.Key.ID); !errors.Is(err, access.ErrRecentAuthRequired) {
			t.Errorf("RotateAPIKey from a session signed in an hour ago = %v, want ErrRecentAuthRequired", err)
		}
		w.unchanged(t)
	})
	t.Run("no_enumeration", func(t *testing.T) {
		t.Parallel()
		w := newRotWorld(t, nil)
		bob := mustUser(t, w.f.mem, "bob", access.RoleAdmin)
		bobSess := w.f.sessionPrincipal(t, bob, access.SessionFull, time.Now())
		w.pol.arm("")
		_, other := w.f.svc.RotateAPIKey(t.Context(), account.As(bobSess), w.key.Key.ID)
		_, missing := w.f.svc.RotateAPIKey(t.Context(), account.As(bobSess), w.key.Key.ID+1000)
		if !errors.Is(other, account.ErrNotFound) || !errors.Is(missing, account.ErrNotFound) || other.Error() != missing.Error() {
			t.Errorf("an admin's session on another user's key = %v and on no key = %v, want one ErrNotFound for both", other, missing)
		}
		if _, err := w.f.svc.RotateAPIKey(t.Context(), account.OutOfBand("admin socket"), w.key.Key.ID+1000); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("RotateAPIKey(OutOfBand) of no key = %v, want ErrNotFound", err)
		}
		if d := w.pol.taken(); len(d) != 0 {
			t.Errorf("Policy decisions for keys not found = %+v, want none", d)
		}
		w.unchanged(t)
	})
	t.Run("policy_target", func(t *testing.T) {
		t.Parallel()
		for name, a := range map[string]func(w rotWorld) account.Actor{
			"session":     func(w rotWorld) account.Actor { return account.As(w.sess) },
			"out_of_band": func(rotWorld) account.Actor { return account.OutOfBand("admin socket") },
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				w := newRotWorld(t, nil)
				w.alice.DisplayName = "stored after the session"
				if err := w.f.mem.UpdateUser(t.Context(), w.alice); err != nil {
					t.Fatalf("UpdateUser: %v", err)
				}
				w.pol.arm("")
				if _, err := w.f.svc.RotateAPIKey(t.Context(), a(w), w.key.Key.ID); err != nil {
					t.Fatalf("RotateAPIKey = %v", err)
				}
				d := w.pol.taken()
				if len(d) != 1 || d[0].Op != account.OpRotateKey || d[0].Target == nil || d[0].Target.ID != w.alice.ID ||
					d[0].Target.DisplayName != w.alice.DisplayName || account.EventActorOf(d[0].Actor) != account.EventActorOf(a(w)) {
					t.Errorf("decisions = %+v, want one OpRotateKey by the actor, targeting alice as stored", d)
				}
			})
		}
	})
	t.Run("policy_refused", func(t *testing.T) {
		t.Parallel()
		w := newRotWorld(t, nil)
		w.pol.arm(account.OpRotateKey)
		_, err := w.f.svc.RotateAPIKey(t.Context(), account.As(w.sess), w.key.Key.ID)
		if !errors.Is(err, account.ErrPolicyRefused) || reason(err) != gateReason {
			t.Errorf("RotateAPIKey under a refusing Policy = %v, want its refusal", err)
		}
		w.unchanged(t)
	})
	t.Run("keys_admin_only", func(t *testing.T) {
		t.Parallel()
		w := newRotWorld(t, nil)
		svc := newFixture(t, keyOptions(options{store: w.fs, edit: func(c *account.Config) { c.Now = w.clock.now }}, account.RolePolicy{KeysAdminOnly: true})).svc
		if _, err := svc.RotateAPIKey(t.Context(), account.As(w.sess), w.key.Key.ID); reason(err) != account.ReasonNotAdmin {
			t.Errorf("a RoleUser's own rotation under KeysAdminOnly = %v, want not_admin", err)
		}
		w.unchanged(t)
	})
	t.Run("expired_key", func(t *testing.T) {
		t.Parallel()
		w := newRotWorld(t, nil)
		w.clock.add(49 * time.Hour)
		late := w.f.sessionPrincipal(t, w.alice, access.SessionFull, w.clock.now())
		for name, a := range map[string]account.Actor{"session": account.As(late), "out_of_band": account.OutOfBand("admin socket")} {
			t.Run(name, func(t *testing.T) {
				_, err := w.f.svc.RotateAPIKey(t.Context(), a, w.key.Key.ID)
				if pe, ok := errors.AsType[*account.PolicyError](err); !ok || *pe != (account.PolicyError{Op: account.OpRotateKey, Reason: account.ReasonKeyExpired}) || !errors.Is(err, account.ErrPolicyRefused) {
					t.Errorf("RotateAPIKey of an expired key = %v, want PolicyError{rotate_key, key_expired}", err)
				}
			})
		}
		w.unchanged(t)
	})
}

// ownerlessStore runs every Update over an ownerHidden Tx.
type ownerlessStore struct{ account.Store }

func (s ownerlessStore) Update(ctx context.Context, fn func(account.Tx) error) error {
	return s.Store.Update(ctx, func(tx account.Tx) error { return fn(ownerHidden{tx}) })
}

func TestRotateAPIKeyOwnerMissing(t *testing.T) {
	t.Parallel()
	w := newRotWorld(t, nil)
	svc := newFixture(t, keyOptions(options{store: w.fs, edit: func(c *account.Config) { c.Store = ownerlessStore{c.Store} }}, w.pol)).svc
	w.pol.arm("")
	if _, err := svc.RotateAPIKey(t.Context(), account.OutOfBand("admin socket"), w.key.Key.ID); !errors.Is(err, account.ErrNotFound) {
		t.Errorf("RotateAPIKey of a key whose owner row is gone = %v, want ErrNotFound", err)
	}
	if d := w.pol.taken(); len(d) != 0 {
		t.Errorf("Policy decisions = %+v, want none for a key with no owner", d)
	}
	w.unchanged(t)
}

// sameEvent compares two events on everything but At and Seq.
func sameEvent(got, want account.Event) bool {
	got.At, got.Seq = time.Time{}, 0
	return got.Kind == want.Kind && got.UserID == want.UserID && got.KeyID == want.KeyID && got.Actor == want.Actor &&
		slices.Equal(got.SessionIDs, want.SessionIDs)
}
