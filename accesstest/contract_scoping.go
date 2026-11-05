package accesstest

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// scoping: rule 6.
func (c *contract) scoping(t *testing.T) {
	t.Run("wrong_owner", c.wrongOwner)
	t.Run("issued_by", c.issuedBy)
}

// owned is one user's passkey, session and key.
type owned struct {
	passkey *access.PasskeyCredential
	session *access.Session
	key     *access.Key
}

// target is the ref every user-scoped op is given.
type target struct {
	sessionID string
	passkeyID int64
	keyID     int64
	userID    int64
}

// ops are rule 6's user-scoped operations, each aimed at tg.
func (o owned) ops(t *testing.T, s account.Store, tg target) map[string]func() error {
	ctx := t.Context()
	sref := access.SessionRef{ID: tg.sessionID, UserID: tg.userID}
	pref := access.PasskeyRef{ID: tg.passkeyID, UserID: tg.userID}
	return map[string]func() error{
		"DeletePasskey": func() error { return s.DeletePasskey(ctx, pref) },
		"RenamePasskey": func() error { return s.RenamePasskey(ctx, pref, "renamed") },
		"UpdatePasskeyAfterLogin": func() error {
			return s.UpdatePasskeyAfterLogin(ctx, tg.userID, o.passkey.CredentialID, access.PasskeyLoginUpdate{At: epoch.Add(time.Hour), SignCount: 9, RawFlags: 0x05})
		},
		"DeleteSession":      func() error { return s.DeleteSession(ctx, sref) },
		"UpdateSessionLabel": func() error { return s.UpdateSessionLabel(ctx, sref, "renamed") },
		"DeleteAPIKey":       func() error { return s.DeleteAPIKey(ctx, access.KeyRef{ID: tg.keyID, UserID: tg.userID}) },
		"RotateSession": func() error {
			next := *o.session
			next.ID, next.UserID, next.TokenHash = tg.sessionID, tg.userID, access.NewHash(fresh("scoped"))
			return s.RotateSession(ctx, account.Rotation{ID: tg.sessionID, UserID: tg.userID, Next: next})
		},
	}
}

// unchanged reports what about o's rows changed since they were written.
func (o owned) unchanged(t *testing.T, s account.Store) []string {
	ctx := t.Context()
	var changed []string
	if p, err := s.PasskeysByUserID(ctx, o.passkey.UserID); err != nil || len(p) != 1 || p[0].Name != o.passkey.Name || p[0].SignCount != o.passkey.SignCount {
		changed = append(changed, "passkey")
	}
	if got, found := sessionFound(t, s, o.session.TokenHash); !found || got.Label != o.session.Label {
		changed = append(changed, "session")
	}
	if _, found, err := s.APIKeyByHash(ctx, o.key.KeyHash); err != nil || !found {
		changed = append(changed, "key")
	}
	return changed
}

func (c *contract) wrongOwner(t *testing.T) {
	s := c.store(t)
	owner, other := mustUser(t, s, "owner"), mustUser(t, s, "other")
	o := owned{passkey: newPasskey(owner.ID), session: newSession(owner.ID, epoch), key: newKey(owner.ID)}
	mustPasskey(t, s, o.passkey)
	mustSession(t, s, o.session)
	mustKey(t, s, o.key)
	mine := target{sessionID: o.session.ID, passkeyID: o.passkey.ID, keyID: o.key.ID}
	wrong, partial := mine, mine
	wrong.userID = other.ID
	for name, tg := range map[string]target{"wrong owner": wrong, "zero ref": {}, "partial ref": partial} {
		for op, call := range o.ops(t, s, tg) {
			if err := call(); !errors.Is(err, account.ErrNotFound) {
				t.Errorf("%s with a %s = %v, want ErrNotFound", op, name, err)
			}
		}
	}
	if changed := o.unchanged(t, s); len(changed) > 0 {
		t.Errorf("refused ops changed the owner's %v", changed)
	}
}

func (c *contract) issuedBy(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "subject")
	tokens := issueTokens(t, s, u.ID, 7, 8, 0)
	for _, ids := range [][]int64{{}, {0}} {
		if n, err := s.DeleteOneTimeTokensIssuedBy(ctx, ids); err != nil || n != 0 {
			t.Errorf("DeleteOneTimeTokensIssuedBy(%v) = (%d, %v), want (0, nil)", ids, n, err)
		}
	}
	if n, err := s.DeleteOneTimeTokensIssuedBy(ctx, []int64{7}); err != nil || n != 3 {
		t.Errorf("DeleteOneTimeTokensIssuedBy([7]) = (%d, %v), want (3, nil)", n, err)
	}
	for _, tok := range tokens {
		got, found, err := s.OneTimeTokenByHash(ctx, tok.Hash)
		if want := tok.IssuedByKey != 7; err != nil || found != want || (found && got.IssuedByKey != tok.IssuedByKey) {
			t.Errorf("token issued by %d: (found %t, IssuedByKey %d, %v), want found %t", tok.IssuedByKey, found, got.IssuedByKey, err, want)
		}
	}
	rec := newSession(u.ID, epoch)
	rec.Kind, rec.IssuedByKey = access.SessionRecovery, 7
	mustSession(t, s, rec)
	if got, found := sessionFound(t, s, rec.TokenHash); !found || got.IssuedByKey != 7 {
		t.Errorf("recovery session IssuedByKey read back = %v, want 7", got)
	}
}

// issueTokens writes a setup, an invite and a recovery token for subject
// from each issuer.
func issueTokens(t *testing.T, s account.Store, subject int64, issuers ...int64) []access.OneTimeToken {
	t.Helper()
	out := make([]access.OneTimeToken, 0, 3*len(issuers))
	for _, issuer := range issuers {
		for _, purpose := range []access.TokenPurpose{access.PurposeSetup, access.PurposeInvite, access.PurposeRecovery} {
			tok := newToken(purpose, subject, epoch.Add(time.Hour))
			tok.IssuedByKey = issuer
			mustToken(t, s, tok)
			out = append(out, tok)
		}
	}
	return out
}

// expiry: rule 7.
func (c *contract) expiry(t *testing.T) {
	t.Run("consume", c.expiredConsume)
	t.Run("live_tokens", c.liveTokens)
}

func (c *contract) expiredConsume(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	tok := newToken(access.PurposeInvite, 0, epoch)
	mustToken(t, s, tok)
	for _, when := range []string{"first", "second"} {
		if _, found, err := s.ConsumeOneTimeToken(ctx, tok.Hash, epoch.Add(time.Millisecond)); err != nil || found {
			t.Errorf("%s consume one tick after ExpiresAt = (%t, %v), want (false, nil)", when, found, err)
		}
	}
	if _, found, err := s.OneTimeTokenByHash(ctx, tok.Hash); err != nil || found {
		t.Errorf("OneTimeTokenByHash after consuming the expired token = (%t, %v), want (false, nil): the consume must delete it", found, err)
	}
}

func (c *contract) liveTokens(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	now := epoch.Add(time.Hour)
	live := map[access.TokenPurpose]access.OneTimeToken{}
	mustToken(t, s, newToken(access.PurposeSetup, 0, now.Add(time.Hour)))
	for _, p := range []access.TokenPurpose{access.PurposeInvite, access.PurposeRecovery} {
		tok := newToken(p, 1, now.Add(time.Hour))
		tok.Role = access.RoleAdmin
		mustToken(t, s, tok)
		live[p] = tok
		mustToken(t, s, newToken(p, 1, now))
	}
	got, err := s.LiveOneTimeTokens(ctx, []access.TokenPurpose{access.PurposeInvite, access.PurposeRecovery}, now)
	if err != nil || len(got) != 2 {
		t.Fatalf("LiveOneTimeTokens([invite recovery]) = (%d tokens, %v), want the 2 live ones", len(got), err)
	}
	for _, g := range got {
		w, ok := live[g.Purpose]
		if !ok || !g.Hash.Equal(w.Hash) || g.Role != w.Role || g.Subject != w.Subject || !g.ExpiresAt.Equal(w.ExpiresAt) {
			t.Errorf("listed %v, want the live %s token as written", g, g.Purpose)
		}
	}
	got[0].Purpose, got[0].Subject = mutated, 99
	again, _ := s.LiveOneTimeTokens(ctx, []access.TokenPurpose{access.PurposeInvite, access.PurposeRecovery}, now)
	for _, g := range again {
		if g.Purpose == mutated || g.Subject == 99 {
			t.Error("mutating a listed token changed the store")
		}
	}
	if none, err := s.LiveOneTimeTokens(ctx, nil, now); err != nil || len(none) != 0 {
		t.Errorf("LiveOneTimeTokens([]) = (%d, %v), want (0, nil)", len(none), err)
	}
}

// callerFaults: rule 12.
func (c *contract) callerFaults(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	a, b := mustUser(t, s, "a"), mustUser(t, s, "b")
	a.OIDC = access.OIDCIdentity{Issuer: testIssuer, Subject: "a"}
	if err := s.UpdateUser(ctx, a); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	p := newPasskey(a.ID)
	mustPasskey(t, s, p)
	sess := newSession(a.ID, epoch)
	mustSession(t, s, sess)
	taken := func(mut func(u *access.User)) func() error {
		return func() error {
			u := b.Clone()
			mut(u)
			return s.UpdateUser(ctx, u)
		}
	}
	next := *sess
	next.TokenHash = access.NewHash(fresh("next"))
	faults := []struct {
		call func() error
		want error
		name string
	}{
		{func() error { return s.UpdateUser(ctx, &access.User{ID: 999, Username: "ghost"}) }, account.ErrNotFound, "UpdateUser(unknown)"},
		{func() error { return s.DeleteUser(ctx, 999) }, account.ErrNotFound, "DeleteUser(unknown)"},
		{func() error { return s.CreateUser(ctx, newUser("a")) }, account.ErrUsernameTaken, "CreateUser(taken name)"},
		{taken(func(u *access.User) { u.Username = "a" }), account.ErrUsernameTaken, "UpdateUser(taken name)"},
		{func() error { u := newUser("c"); u.OIDC = a.OIDC; return s.CreateUser(ctx, u) }, account.ErrOIDCIdentityTaken, "CreateUser(taken identity)"},
		{taken(func(u *access.User) { u.OIDC = a.OIDC }), account.ErrOIDCIdentityTaken, "UpdateUser(taken identity)"},
		{func() error { q := newPasskey(b.ID); q.CredentialID = p.CredentialID; return s.CreatePasskey(ctx, q) }, account.ErrDuplicateCredential, "CreatePasskey(taken credential)"},
		{func() error { return s.CreateInitialUser(ctx, newUser("late")) }, account.ErrSetupComplete, "CreateInitialUser(users exist)"},
		{func() error {
			return s.RotateSession(ctx, account.Rotation{ID: sess.ID, UserID: a.ID, ExpectHash: access.NewHash(fresh("stale")), Next: next})
		}, account.ErrNotFound, "RotateSession(stale ExpectHash)"},
		{func() error {
			return s.RotateSession(ctx, account.Rotation{ID: unknownID, UserID: a.ID, Next: access.Session{ID: unknownID, UserID: a.ID, TokenHash: next.TokenHash}})
		}, account.ErrNotFound, "RotateSession(unknown)"},
		{func() error { return s.UpdateSessionLabel(ctx, access.SessionRef{ID: unknownID, UserID: a.ID}, "x") }, account.ErrNotFound, "UpdateSessionLabel(unknown)"},
		{func() error { return s.DeleteSession(ctx, access.SessionRef{ID: unknownID, UserID: a.ID}) }, account.ErrNotFound, "DeleteSession(unknown)"},
		{func() error { return s.RenamePasskey(ctx, access.PasskeyRef{ID: 999, UserID: a.ID}, "x") }, account.ErrNotFound, "RenamePasskey(unknown)"},
		{func() error { return s.DeletePasskey(ctx, access.PasskeyRef{ID: 999, UserID: a.ID}) }, account.ErrNotFound, "DeletePasskey(unknown)"},
		{func() error { return s.DeleteAPIKey(ctx, access.KeyRef{ID: 999, UserID: a.ID}) }, account.ErrNotFound, "DeleteAPIKey(unknown)"},
	}
	for _, f := range faults {
		if err := f.call(); !errors.Is(err, f.want) {
			t.Errorf("%s = %v, want %v", f.name, err, f.want)
		}
	}
}

// failureRecords: rule 15.
func (c *contract) failureRecords(t *testing.T) {
	t.Run("put_get_delete", c.failurePutGetDelete)
	t.Run("prune", c.failurePrune)
	t.Run("unreported_locks", c.failureUnreported)
}

func failureRef(name string, m access.Method, trusted bool) account.FailureRef {
	return account.FailureRef{Name: name, Method: m, Trusted: trusted}
}

func (c *contract) failurePutGetDelete(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	records := []account.FailureCount{
		{FailureRef: failureRef("n1", access.MethodPassword, false), Count: 1},
		{FailureRef: failureRef("n1", access.MethodPassword, true), Count: 2},
		{FailureRef: failureRef("n1", access.MethodPasskey, false), Count: 3},
		{FailureRef: failureRef("n2", access.MethodPassword, false), Count: 4, Locked: true, LockedAt: epoch},
	}
	for _, f := range records {
		if err := s.PutAuthFailure(ctx, f); err != nil {
			t.Fatalf("PutAuthFailure: %v", err)
		}
	}
	present := func() []int { return presentFailures(t, s, records) }
	if got := present(); !slices.Equal(got, []int{1, 2, 3, 4}) {
		t.Errorf("records read back %v, want all four", got)
	}
	if _, found, err := s.AuthFailure(ctx, failureRef("absent", access.MethodPassword, false)); found || err != nil {
		t.Errorf("AuthFailure(absent) = (%t, %v), want (false, nil)", found, err)
	}
	if err := s.Update(ctx, func(tx account.Tx) error {
		if err := tx.DeleteAuthFailures(ctx, "n1", []access.Method{access.MethodPassword}); err != nil {
			return err
		}
		return errContract
	}); !errors.Is(err, errContract) {
		t.Fatalf("Update = %v, want the callback's error", err)
	}
	if got := present(); !slices.Equal(got, []int{1, 2, 3, 4}) {
		t.Errorf("a rolled-back DeleteAuthFailures left %v, want all four", got)
	}
	if err := s.DeleteAuthFailures(ctx, "n1", []access.Method{access.MethodPassword, access.MethodOIDC}); err != nil {
		t.Fatalf("DeleteAuthFailures: %v", err)
	}
	if got := present(); !slices.Equal(got, []int{3, 4}) {
		t.Errorf("after DeleteAuthFailures(n1, [password oidc]) records left %v, want [3 4]", got)
	}
}

// presentFailures returns the Count of each of records still found, failing
// on one that reads back otherwise than written.
func presentFailures(t *testing.T, s account.Store, records []account.FailureCount) []int {
	t.Helper()
	var out []int
	for i := range records {
		f := &records[i]
		got, found, err := s.AuthFailure(t.Context(), f.FailureRef)
		check(t, "AuthFailure", err)
		if !found {
			continue
		}
		if got.Count != f.Count || got.Locked != f.Locked || !got.LockedAt.Equal(f.LockedAt) {
			t.Errorf("AuthFailure(%v) = %+v, want %+v", f.FailureRef, got, *f)
		}
		out = append(out, f.Count)
	}
	return out
}

func (c *contract) failurePrune(t *testing.T) {
	const names = 1000
	s, ctx := c.store(t), t.Context()
	if err := s.Update(ctx, func(tx account.Tx) error {
		for i := range names {
			if err := tx.PutAuthFailure(ctx, account.FailureCount{FailureRef: failureRef(fmt.Sprintf("name-%d", i), access.MethodPassword, false), Count: 1}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	keep := make([]string, 10)
	for i := range keep {
		keep[i] = fmt.Sprintf("name-%d", i*97)
	}
	if n, err := s.PruneAuthFailures(ctx, keep); err != nil || n != names-10 {
		t.Errorf("PruneAuthFailures = (%d, %v), want (%d, nil)", n, err, names-10)
	}
	for i := range names {
		name := fmt.Sprintf("name-%d", i)
		_, found, err := s.AuthFailure(ctx, failureRef(name, access.MethodPassword, false))
		if err != nil || found != slices.Contains(keep, name) {
			t.Fatalf("after the prune, %s found = (%t, %v), want %t", name, found, err, slices.Contains(keep, name))
		}
	}
}

func (c *contract) failureUnreported(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	locked := []account.FailureCount{
		{FailureRef: failureRef("l1", access.MethodPassword, false), Count: 5, Locked: true, LockedAt: epoch, Unreported: true},
		{FailureRef: failureRef("l2", access.MethodPassword, true), Count: 5, Locked: true, LockedAt: epoch, Unreported: true},
	}
	for _, f := range append(slices.Clone(locked), account.FailureCount{FailureRef: failureRef("quiet", access.MethodPassword, false), Count: 1}) {
		if err := s.PutAuthFailure(ctx, f); err != nil {
			t.Fatalf("PutAuthFailure: %v", err)
		}
	}
	got, err := s.UnreportedLocks(ctx)
	names := map[string]bool{}
	for _, f := range got {
		names[f.Name] = true
	}
	if err != nil || len(got) != 2 || !names["l1"] || !names["l2"] {
		t.Errorf("UnreportedLocks = (%v, %v), want exactly l1 and l2", slices.Sorted(maps.Keys(names)), err)
	}
	for _, f := range locked {
		f.Unreported = false
		if err := s.PutAuthFailure(ctx, f); err != nil {
			t.Fatalf("PutAuthFailure: %v", err)
		}
	}
	if got, err := s.UnreportedLocks(ctx); err != nil || len(got) != 0 {
		t.Errorf("UnreportedLocks after clearing = (%d, %v), want (0, nil)", len(got), err)
	}
}
