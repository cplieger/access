package accesstest

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// keySecrets: rule 23, with rule 21's zeroing write and rule 6's scoping of
// UpdateAPIKeySecret and UpdateAPIKeyLabel.
func (c *contract) keySecrets(t *testing.T) {
	for _, cs := range []struct {
		run  func(t *testing.T)
		name string
	}{
		{c.lookupEitherHash, "lookup_either_hash"},
		{c.secretWrite, "secret_write"},
		{c.staleTouch, "stale_touch"},
		{c.rotateDuringOverlap, "rotate_during_overlap"},
		{c.rotationChain, "rotation_chain"},
		{c.revokeDuringOverlap, "revoke_during_overlap"},
		{c.clearRetired, "clear_retired"},
		{c.clearBound, "clear_bound"},
		{c.labelWrite, "label_write"},
	} {
		if !c.viaTx || !storeOnly["rule_23_key_secrets/"+cs.name] {
			t.Run(cs.name, cs.run)
		}
	}
}

// overlapEnd is the overlap bound the rotations of these cases set.
var overlapEnd = epoch.Add(time.Hour)

// rotation is the KeySecret that replaces k's secret with a fresh one and
// keeps k's current secret as the previous one until until.
func rotation(k *access.Key, until time.Time) access.KeySecret {
	return access.KeySecret{
		KeyHash:       access.NewHash(fresh("rotated")),
		KeyPrefix:     "ak",
		KeySuffix:     fresh("sfx"),
		PreviousHash:  k.KeyHash,
		PreviousUntil: until,
	}
}

// rotate writes sec over k and applies it to k, failing on an error.
func rotate(t *testing.T, s account.Store, k *access.Key, sec access.KeySecret) {
	t.Helper()
	if err := s.UpdateAPIKeySecret(t.Context(), access.KeyRef{ID: k.ID, UserID: k.UserID}, sec); err != nil {
		t.Fatalf("UpdateAPIKeySecret: %v", err)
	}
	applySecret(k, sec)
}

// applySecret is what a successful UpdateAPIKeySecret of sec makes of k.
func applySecret(k *access.Key, sec access.KeySecret) {
	k.KeyHash, k.KeyPrefix, k.KeySuffix = sec.KeyHash, sec.KeyPrefix, sec.KeySuffix
	k.PreviousHash, k.PreviousUntil, k.LastUsedAt = sec.PreviousHash, sec.PreviousUntil, time.Time{}
}

// keyBy reads the key h finds, nil when none, failing on an error.
func keyBy(t *testing.T, s account.Store, h access.Hash) *access.Key {
	t.Helper()
	k, found, err := s.APIKeyByHash(t.Context(), h)
	if err != nil {
		t.Fatalf("APIKeyByHash: %v", err)
	}
	if !found {
		return nil
	}
	return k
}

// sameKey reports the first field of got, nil included, that differs from
// want, or "".
func sameKey(want, got *access.Key) string {
	return firstDiff(reflect.ValueOf(*want), reflect.ValueOf(got), "Key")
}

func bothHashes(current, previous access.Hash) map[string]access.Hash {
	return map[string]access.Hash{"current": current, "previous": previous}
}

// touched creates a key of userID whose current secret was used at at.
func touched(t *testing.T, s account.Store, userID int64, at time.Time) *access.Key {
	t.Helper()
	k := newKey(userID)
	mustKey(t, s, k)
	check(t, "TouchAPIKey", s.TouchAPIKey(t.Context(), k.ID, k.KeyHash, at))
	k.LastUsedAt = at
	return k
}

func (c *contract) lookupEitherHash(t *testing.T) {
	s := c.store(t)
	k := touched(t, s, mustUser(t, s, "either").ID, epoch)
	old := k.KeyHash
	rotate(t, s, k, rotation(k, overlapEnd))
	for name, h := range map[string]access.Hash{"the current hash": k.KeyHash, "the previous hash": old} {
		if d := sameKey(k, keyBy(t, s, h)); d != "" {
			t.Errorf("rule 23: APIKeyByHash(%s) differs at %s, want the rotated key", name, d)
		}
	}
	if got := keyBy(t, s, access.Hash{}); got != nil {
		t.Errorf("rule 23: APIKeyByHash(zero hash) found key %d, want nothing", got.ID)
	}
}

func (c *contract) secretWrite(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "secret")
	k := touched(t, s, u.ID, epoch.Add(time.Minute))
	rotate(t, s, k, rotation(k, overlapEnd))
	got := keyBy(t, s, k.KeyHash)
	if d := sameKey(k, got); d != "" {
		t.Errorf("rule 23: after UpdateAPIKeySecret the key differs at %s, want the five fields written and LastUsedAt zero", d)
	}
	for name, ref := range map[string]access.KeyRef{"an unknown ID": {ID: 4242, UserID: u.ID}, "a zero ref": {}} {
		if err := s.UpdateAPIKeySecret(ctx, ref, rotation(k, overlapEnd)); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("rule 23: UpdateAPIKeySecret(%s) = %v, want ErrNotFound", name, err)
		}
	}
}

func (c *contract) staleTouch(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	k := newKey(mustUser(t, s, "stale").ID)
	mustKey(t, s, k)
	old := k.KeyHash
	rotate(t, s, k, rotation(k, overlapEnd))
	check(t, "TouchAPIKey", s.TouchAPIKey(ctx, k.ID, old, epoch.Add(time.Minute)))
	if got := keyBy(t, s, k.KeyHash); got == nil || !got.LastUsedAt.IsZero() {
		t.Errorf("rule 21: a touch carrying the superseded hash left %v, want LastUsedAt zero", got)
	}
	check(t, "TouchAPIKey", s.TouchAPIKey(ctx, k.ID, k.KeyHash, epoch.Add(2*time.Minute)))
	k.LastUsedAt = epoch.Add(2 * time.Minute)
	for name, h := range bothHashes(k.KeyHash, old) {
		if d := sameKey(k, keyBy(t, s, h)); d != "" {
			t.Errorf("rules 21 and 23: after a touch carrying the current hash, the %s hash finds a key differing at %s, want the touched record", name, d)
		}
	}
}

func (c *contract) rotateDuringOverlap(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	k := newKey(mustUser(t, s, "overlap").ID)
	mustKey(t, s, k)
	rotate(t, s, k, rotation(k, overlapEnd))
	second := rotation(k, overlapEnd.Add(time.Minute))
	check(t, "UpdateAPIKeySecret", s.UpdateAPIKeySecret(ctx, access.KeyRef{ID: k.ID, UserID: k.UserID}, second))
	applySecret(k, second)
	for name, h := range bothHashes(k.KeyHash, k.PreviousHash) {
		if d := sameKey(k, keyBy(t, s, h)); d != "" {
			t.Errorf("rule 23: after a rotation during an overlap, the %s hash finds a key differing at %s, want the superseded secret as PreviousHash with the new bound", name, d)
		}
	}
}

func (c *contract) rotationChain(t *testing.T) {
	s := c.store(t)
	k := newKey(mustUser(t, s, "chain").ID)
	mustKey(t, s, k)
	a := k.KeyHash
	rotate(t, s, k, rotation(k, overlapEnd))
	b := k.KeyHash
	rotate(t, s, k, rotation(k, overlapEnd))
	if got := keyBy(t, s, a); got != nil {
		t.Errorf("rule 23: after rotations A to B to C, APIKeyByHash(A) found key %d, want nothing", got.ID)
	}
	for name, h := range map[string]access.Hash{"B": b, "C": k.KeyHash} {
		if got := keyBy(t, s, h); got == nil || got.ID != k.ID {
			t.Errorf("rule 23: after rotations A to B to C, APIKeyByHash(%s) = %v, want key %d", name, got, k.ID)
		}
	}
}

func (c *contract) revokeDuringOverlap(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "revoke")
	for name, revoke := range map[string]func(k *access.Key) error{
		opDeleteKey: func(k *access.Key) error { return s.DeleteAPIKey(ctx, access.KeyRef{ID: k.ID, UserID: u.ID}) },
		"DeleteUserAPIKeys": func(*access.Key) error {
			_, err := s.DeleteUserAPIKeys(ctx, u.ID)
			return err
		},
	} {
		k := newKey(u.ID)
		mustKey(t, s, k)
		old := k.KeyHash
		rotate(t, s, k, rotation(k, overlapEnd))
		check(t, name, revoke(k))
		for which, h := range map[string]access.Hash{"current": k.KeyHash, "previous": old} {
			if got := keyBy(t, s, h); got != nil {
				t.Errorf("rule 23: after %s during an overlap, the %s hash still finds key %d", name, which, got.ID)
			}
		}
	}
}

func (c *contract) clearRetired(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "clear")
	now := overlapEnd
	never := newKey(u.ID)
	mustKey(t, s, never)
	pastBound := newKey(u.ID)
	mustKey(t, s, pastBound)
	pastPrev := pastBound.KeyHash
	rotate(t, s, pastBound, rotation(pastBound, now))
	used := newKey(u.ID)
	mustKey(t, s, used)
	usedPrev := used.KeyHash
	rotate(t, s, used, rotation(used, now.Add(time.Hour)))
	check(t, "TouchAPIKey", s.TouchAPIKey(ctx, used.ID, used.KeyHash, epoch.Add(time.Minute)))
	used.LastUsedAt = epoch.Add(time.Minute)
	live := newKey(u.ID)
	mustKey(t, s, live)
	rotate(t, s, live, rotation(live, now.Add(time.Hour)))
	again := newKey(u.ID)
	mustKey(t, s, again)
	rotate(t, s, again, rotation(again, epoch))
	check(t, "TouchAPIKey", s.TouchAPIKey(ctx, again.ID, again.KeyHash, epoch.Add(time.Minute)))
	rotate(t, s, again, rotation(again, now.Add(time.Hour)))

	n, err := s.ClearRetiredAPIKeySecrets(ctx, now, 10)
	if err != nil || n != 2 {
		t.Errorf("rule 23: ClearRetiredAPIKeySecrets = (%d, %v), want (2, nil): the key past its bound and the key whose new secret was used", n, err)
	}
	for _, k := range []*access.Key{pastBound, used} {
		k.PreviousHash, k.PreviousUntil = access.Hash{}, time.Time{}
	}
	for name, k := range map[string]*access.Key{"never rotated": never, "past its bound": pastBound, "new secret used": used, "inside its overlap": live, "rotated after its overlap ended": again} {
		if d := sameKey(k, keyBy(t, s, k.KeyHash)); d != "" {
			t.Errorf("rule 23: after the clear, the key %s differs at %s", name, d)
		}
	}
	for name, h := range map[string]access.Hash{"past its bound": pastPrev, "new secret used": usedPrev} {
		if got := keyBy(t, s, h); got != nil {
			t.Errorf("rule 23: after the clear, the cleared previous hash of the key %s still finds key %d", name, got.ID)
		}
	}
	if got := keyBy(t, s, live.PreviousHash); got == nil || got.ID != live.ID {
		t.Errorf("rule 23: after the clear, the previous hash of the key inside its overlap = %v, want key %d", got, live.ID)
	}
}

func (c *contract) clearBound(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "bound")
	for range 3 {
		k := newKey(u.ID)
		mustKey(t, s, k)
		rotate(t, s, k, rotation(k, epoch))
	}
	for i, want := range []int{2, 1, 0} {
		if n, err := s.ClearRetiredAPIKeySecrets(ctx, overlapEnd, 2); err != nil || n != want {
			t.Errorf("rule 23: ClearRetiredAPIKeySecrets call %d with limit 2 = (%d, %v), want (%d, nil)", i+1, n, err, want)
		}
	}
}

func (c *contract) labelWrite(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "label")
	k := touched(t, s, u.ID, epoch)
	rotate(t, s, k, rotation(k, overlapEnd))
	check(t, "UpdateAPIKeyLabel", s.UpdateAPIKeyLabel(ctx, access.KeyRef{ID: k.ID, UserID: u.ID}, "renamed"))
	k.Label = "renamed"
	for name, h := range bothHashes(k.KeyHash, k.PreviousHash) {
		if d := sameKey(k, keyBy(t, s, h)); d != "" {
			t.Errorf("rules 6 and 23: after UpdateAPIKeyLabel, the %s hash finds a key differing at %s, want only the label written", name, d)
		}
	}
	for name, bad := range map[string]access.KeyRef{"an unknown ID": {ID: 4242, UserID: u.ID}, "a zero ref": {}} {
		if err := s.UpdateAPIKeyLabel(ctx, bad, "x"); !errors.Is(err, account.ErrNotFound) {
			t.Errorf("rule 6: UpdateAPIKeyLabel(%s) = %v, want ErrNotFound", name, err)
		}
	}
}
