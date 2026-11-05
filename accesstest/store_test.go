package accesstest_test

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/printcheck"
	"github.com/cplieger/access/webauthn"
)

var (
	_ account.Store             = (*accesstest.MemStore)(nil)
	_ access.AuthenticatorStore = (*accesstest.MemStore)(nil)
	_ webauthn.Store            = (*accesstest.MemStore)(nil)
)

var t0 = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

func mustCreateUser(t *testing.T, store *accesstest.MemStore, u *access.User) *access.User {
	t.Helper()
	if err := store.CreateUser(t.Context(), u); err != nil {
		t.Fatalf("CreateUser(%q): %v", u.Username, err)
	}
	return u
}

func mustCreateSession(t *testing.T, store *accesstest.MemStore, s *access.Session) {
	t.Helper()
	if err := store.CreateSession(t.Context(), s); err != nil {
		t.Fatalf("CreateSession(%s): %v", s.ID, err)
	}
}

func sessionFound(t *testing.T, store *accesstest.MemStore, h access.Hash) bool {
	t.Helper()
	_, found, err := store.SessionByHash(t.Context(), h)
	if err != nil {
		t.Fatalf("SessionByHash: %v", err)
	}
	return found
}

func TestMemStorePrintingDoesNotRevealHash(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store := accesstest.NewMemStore()
	sessionText, keyText, tokenText := access.HexSHA256("session"), access.HexSHA256("key"), access.HexSHA256("token")
	mustCreateSession(t, store, &access.Session{ID: "s1", TokenHash: access.NewHash(sessionText), UserID: 1, CreatedAt: t0, LastActivity: t0})
	if err := store.CreateAPIKey(ctx, &access.Key{KeyHash: access.NewHash(keyText), UserID: 1}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if err := store.CreateOneTimeToken(ctx, access.OneTimeToken{Hash: access.NewHash(tokenText), Purpose: access.PurposeInvite, ExpiresAt: t0.Add(time.Hour)}); err != nil {
		t.Fatalf("CreateOneTimeToken: %v", err)
	}

	snap := accesstest.Snapshot(store)
	printed := map[string]any{"store": store, "snapshot": snap, "snapshot pointer": &snap}
	for name, v := range printed {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			out := fmt.Sprintf(verb, v)
			for _, text := range []string{sessionText, keyText, tokenText} {
				if printcheck.Leak(out, text) {
					t.Errorf("%s printed with %s holds a stored hash text: %s", name, verb, out)
				}
			}
		}
	}

	if !sessionFound(t, store, access.NewHash(sessionText)) {
		t.Error("SessionByHash(fresh NewHash) found = false, want true")
	}
	if _, found, err := store.APIKeyByHash(ctx, access.NewHash(keyText)); err != nil || !found {
		t.Errorf("APIKeyByHash(fresh NewHash) = (_, %t, %v), want (key, true, nil)", found, err)
	}
	if _, found, err := store.OneTimeTokenByHash(ctx, access.NewHash(tokenText)); err != nil || !found {
		t.Errorf("OneTimeTokenByHash(fresh NewHash) = (_, %t, %v), want (token, true, nil)", found, err)
	}
}

func TestMemStoreActivityMonotonic(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store := accesstest.NewMemStore()
	h := access.NewHash("session")
	mustCreateSession(t, store, &access.Session{ID: "s1", TokenHash: h, UserID: 1, CreatedAt: t0.Add(-time.Hour), LastActivity: t0.Add(-time.Hour)})
	later := t0.Add(30 * time.Minute)

	read := func() access.Session {
		t.Helper()
		s, found, err := store.SessionByHash(ctx, h)
		if err != nil || !found {
			t.Fatalf("SessionByHash = (_, %t, %v), want (session, true, nil)", found, err)
		}
		return *s
	}
	activity := func(at time.Time, ip string) {
		t.Helper()
		if err := store.UpdateSessionActivity(ctx, h, access.SessionActivity{At: at, IP: ip}); err != nil {
			t.Fatalf("UpdateSessionActivity(%v, %s) = %v, want nil", at, ip, err)
		}
	}

	activity(later, "192.0.2.2")
	activity(t0, "192.0.2.1")
	if s := read(); !s.LastActivity.Equal(later) || s.LastIP != "192.0.2.2" {
		t.Errorf("after a newer then an older write, session = (%v, %s), want (%v, 192.0.2.2)", s.LastActivity, s.LastIP, later)
	}
	activity(later, "192.0.2.3")
	if s := read(); s.LastIP != "192.0.2.2" {
		t.Errorf("after an equal-time write, LastIP = %s, want 192.0.2.2", s.LastIP)
	}

	if err := store.CreateAPIKey(ctx, &access.Key{KeyHash: access.NewHash("key"), UserID: 1}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	key, _, err := store.APIKeyByHash(ctx, access.NewHash("key"))
	if err != nil {
		t.Fatalf("APIKeyByHash: %v", err)
	}
	for _, at := range []time.Time{later, t0} {
		if err := store.TouchAPIKey(ctx, key.ID, at); err != nil {
			t.Fatalf("TouchAPIKey(%v) = %v, want nil", at, err)
		}
	}
	if key, _, _ = store.APIKeyByHash(ctx, access.NewHash("key")); !key.LastUsedAt.Equal(later) {
		t.Errorf("after a newer then an older touch, LastUsedAt = %v, want %v", key.LastUsedAt, later)
	}

	next := read()
	next.TokenHash, next.LastActivity, next.LastIP = access.NewHash("rotated"), t0, "192.0.2.1"
	if err := store.RotateSession(ctx, account.Rotation{UserID: 1, ID: "s1", ExpectHash: h, Next: next}); err != nil {
		t.Fatalf("RotateSession: %v", err)
	}
	rotated, found, err := store.SessionByHash(ctx, access.NewHash("rotated"))
	if err != nil || !found {
		t.Fatalf("SessionByHash(rotated) = (_, %t, %v), want (session, true, nil)", found, err)
	}
	if !rotated.LastActivity.Equal(later) || rotated.LastIP != "192.0.2.2" {
		t.Errorf("after a rotation to an older activity, session = (%v, %s), want (%v, 192.0.2.2)", rotated.LastActivity, rotated.LastIP, later)
	}
}

func TestMemStoreCleanupReturnsDeleted(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store := accesstest.NewMemStore()
	timeouts := access.SessionTimeouts{Idle: time.Hour, Absolute: 24 * time.Hour}
	stale := t0.Add(-2 * time.Hour)
	sessions := []access.Session{
		{ID: "a", UserID: 1, CreatedAt: stale, LastActivity: stale},
		{ID: "b", UserID: 2, CreatedAt: stale, LastActivity: stale},
		{ID: "c", UserID: 1, CreatedAt: t0.Add(-25 * time.Hour), LastActivity: t0},
		{ID: "live", UserID: 2, CreatedAt: t0, LastActivity: t0},
	}
	for i := range sessions {
		sessions[i].TokenHash = access.NewHash("hash-" + sessions[i].ID)
		mustCreateSession(t, store, new(sessions[i]))
	}
	allPresent := func() bool {
		t.Helper()
		for _, s := range sessions {
			if !sessionFound(t, store, s.TokenHash) {
				return false
			}
		}
		return true
	}

	if refs, err := store.CleanupExpiredSessions(ctx, t0, timeouts, 0); err == nil || len(refs) != 0 || !allPresent() {
		t.Fatalf("CleanupExpiredSessions(limit 0) = (%v, %v), every session present = %t; want an error and no delete", refs, err, allPresent())
	}

	var got []access.SessionRef
	for call, want := range []int{2, 1, 0} {
		refs, err := store.CleanupExpiredSessions(ctx, t0, timeouts, 2)
		if err != nil {
			t.Fatalf("call %d: CleanupExpiredSessions: %v", call+1, err)
		}
		if len(refs) != want {
			t.Fatalf("call %d returned %v, want %d refs", call+1, refs, want)
		}
		for _, ref := range refs {
			i := slices.IndexFunc(sessions, func(s access.Session) bool { return s.ID == ref.ID && s.UserID == ref.UserID })
			if i < 0 || sessions[i].ID == "live" {
				t.Fatalf("call %d returned %v, which names no expired session", call+1, ref)
			}
			if sessionFound(t, store, sessions[i].TokenHash) {
				t.Errorf("call %d returned %v but the session is still stored", call+1, ref)
			}
		}
		got = append(got, refs...)
	}
	want := []access.SessionRef{{ID: "a", UserID: 1}, {ID: "b", UserID: 2}, {ID: "c", UserID: 1}}
	slices.SortFunc(got, func(x, y access.SessionRef) int { return cmp.Compare(x.ID, y.ID) })
	if !slices.Equal(got, want) {
		t.Errorf("refs over every call = %v, want %v", got, want)
	}
	if !sessionFound(t, store, sessions[3].TokenHash) {
		t.Error("the live session was deleted")
	}
}

func TestMemStoreLiveTokens(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store := accesstest.NewMemStore()
	var live []access.Hash
	for _, p := range []access.TokenPurpose{access.PurposeSetup, access.PurposeInvite, access.PurposeRecovery} {
		for _, expires := range []time.Time{t0.Add(time.Hour), t0} {
			tok := access.OneTimeToken{Hash: access.NewHash(fmt.Sprint(p, expires)), Purpose: p, ExpiresAt: expires, Role: access.RoleUser}
			if err := store.CreateOneTimeToken(ctx, tok); err != nil {
				t.Fatalf("CreateOneTimeToken: %v", err)
			}
			if p != access.PurposeSetup && expires.After(t0) {
				live = append(live, tok.Hash)
			}
		}
	}

	got, err := store.LiveOneTimeTokens(ctx, []access.TokenPurpose{access.PurposeInvite, access.PurposeRecovery}, t0)
	if err != nil {
		t.Fatalf("LiveOneTimeTokens: %v", err)
	}
	if len(got) != len(live) {
		t.Fatalf("LiveOneTimeTokens returned %d tokens, want %d", len(got), len(live))
	}
	for _, h := range live {
		if !slices.ContainsFunc(got, func(tok access.OneTimeToken) bool { return tok.Hash.Equal(h) }) {
			t.Errorf("LiveOneTimeTokens is missing a live token: %v", got)
		}
	}

	got[0].Role = access.RoleAdmin
	again, _, err := store.OneTimeTokenByHash(ctx, got[0].Hash)
	if err != nil || again.Role != access.RoleUser {
		t.Errorf("after mutating a returned token, stored Role = %q (%v), want %q", again.Role, err, access.RoleUser)
	}
}

func TestMemStoreHandleNotAliased(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store := accesstest.NewMemStore()
	u := mustCreateUser(t, store, &access.User{Username: "u", Role: access.RoleUser, Enabled: true, WebAuthnHandle: []byte{1, 2}})
	u.WebAuthnHandle[0] = 9

	got, found, err := store.UserByID(ctx, u.ID)
	if err != nil || !found {
		t.Fatalf("UserByID = (_, %t, %v), want (user, true, nil)", found, err)
	}
	if !slices.Equal(got.WebAuthnHandle, []byte{1, 2}) {
		t.Errorf("after mutating the handle passed to CreateUser, stored handle = %v, want [1 2]", got.WebAuthnHandle)
	}
	got.WebAuthnHandle[0] = 9
	again, found, err := store.UserByWebAuthnHandle(ctx, []byte{1, 2})
	if err != nil || !found {
		t.Fatalf("UserByWebAuthnHandle([1 2]) = (_, %t, %v), want (user, true, nil)", found, err)
	}
	if !slices.Equal(again.WebAuthnHandle, []byte{1, 2}) {
		t.Errorf("after mutating a returned handle, stored handle = %v, want [1 2]", again.WebAuthnHandle)
	}
}

func TestMemStoreIsolatesStoredValues(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store := accesstest.NewMemStore()
	timeouts := access.SessionTimeouts{Idle: time.Hour, Absolute: 24 * time.Hour}

	sess := &access.Session{ID: "s1", TokenHash: access.NewHash("h"), UserID: 1, CreatedAt: t0, LastActivity: t0}
	mustCreateSession(t, store, sess)
	sess.LastActivity = t0.Add(-2 * time.Hour)
	got, _, err := store.SessionByHash(ctx, access.NewHash("h"))
	if err != nil {
		t.Fatalf("SessionByHash: %v", err)
	}
	if verr := access.ValidateSession(got, timeouts, t0); verr != nil {
		t.Errorf("after mutating the session passed to CreateSession, ValidateSession(stored) = %v, want nil", verr)
	}
	got.LastActivity = t0.Add(-2 * time.Hour)
	again, _, err := store.SessionByHash(ctx, access.NewHash("h"))
	if err != nil {
		t.Fatalf("SessionByHash: %v", err)
	}
	if verr := access.ValidateSession(again, timeouts, t0); verr != nil {
		t.Errorf("after mutating a returned session, ValidateSession(stored) = %v, want nil", verr)
	}

	key := &access.Key{KeyHash: access.NewHash("kh"), UserID: 1, Scopes: []string{"read"}, LineageIDs: []int64{5}}
	if err := store.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	key.Scopes[0] = "write"
	key.LineageIDs[0] = 6
	gotKey, _, err := store.APIKeyByHash(ctx, access.NewHash("kh"))
	if err != nil {
		t.Fatalf("APIKeyByHash: %v", err)
	}
	if gotKey.Scopes[0] != "read" || gotKey.LineageIDs[0] != 5 {
		t.Errorf("after mutating the key passed to CreateAPIKey, stored = %v %v, want [read] and lineage [5 ...]", gotKey.Scopes, gotKey.LineageIDs)
	}
	gotKey.Scopes[0] = "write"
	gotKey.LineageIDs[0] = 6
	againKey, _, err := store.APIKeyByHash(ctx, access.NewHash("kh"))
	if err != nil {
		t.Fatalf("APIKeyByHash: %v", err)
	}
	if againKey.Scopes[0] != "read" || againKey.LineageIDs[0] != 5 {
		t.Errorf("after mutating a returned key, stored = %v %v, want [read] and lineage [5 ...]", againKey.Scopes, againKey.LineageIDs)
	}
}

func TestUpdatePanicRollsBack(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store := accesstest.NewMemStore()
	errRefused := errors.New("refused")
	write := func(tx account.Tx) {
		if err := tx.CreateUser(ctx, &access.User{Username: "u"}); err != nil {
			t.Fatalf("tx.CreateUser: %v", err)
		}
		if err := tx.CreateSession(ctx, &access.Session{ID: "s1", TokenHash: access.NewHash("h"), UserID: 1}); err != nil {
			t.Fatalf("tx.CreateSession: %v", err)
		}
		if n, err := tx.UserCount(ctx); err != nil || n != 1 {
			t.Fatalf("tx.UserCount inside the callback = (%d, %v), want (1, nil)", n, err)
		}
	}
	nothingVisible := func(after string) {
		t.Helper()
		if n, err := store.UserCount(ctx); err != nil || n != 0 {
			t.Errorf("after %s, UserCount = (%d, %v), want (0, nil)", after, n, err)
		}
		if sessionFound(t, store, access.NewHash("h")) {
			t.Errorf("after %s, the session is visible", after)
		}
	}

	if err := store.Update(ctx, func(tx account.Tx) error { write(tx); return errRefused }); !errors.Is(err, errRefused) {
		t.Errorf("Update(callback returning an error) = %v, want %v", err, errRefused)
	}
	nothingVisible("an Update whose callback returned an error")

	recovered := func() (r any) {
		defer func() { r = recover() }()
		_ = store.Update(ctx, func(tx account.Tx) error { write(tx); panic("boom") })
		return nil
	}()
	if recovered != "boom" {
		t.Errorf("Update(panicking callback) recovered %v, want the callback's panic", recovered)
	}
	nothingVisible("a panicking Update")

	if err := store.Update(ctx, func(tx account.Tx) error { write(tx); return nil }); err != nil {
		t.Fatalf("Update(callback returning nil) = %v", err)
	}
	if n, _ := store.UserCount(ctx); n != 1 || !sessionFound(t, store, access.NewHash("h")) {
		t.Errorf("after a committed Update, UserCount = %d and the session found = %t, want 1 and true", n, sessionFound(t, store, access.NewHash("h")))
	}
}

func TestMemStoreLineageAndAttributions(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store := accesstest.NewMemStore()
	alice := mustCreateUser(t, store, &access.User{Username: "alice"})
	bob := mustCreateUser(t, store, &access.User{Username: "bob"})

	key := &access.Key{KeyHash: access.NewHash("key"), UserID: alice.ID, LineageIDs: []int64{4, 6}}
	if err := store.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	stored, _, err := store.APIKeyByHash(ctx, access.NewHash("key"))
	if err != nil {
		t.Fatalf("APIKeyByHash: %v", err)
	}
	if want := []int64{4, 6, key.ID}; !slices.Equal(stored.LineageIDs, want) || !slices.Equal(key.LineageIDs, want) {
		t.Errorf("CreateAPIKey(lineage [4 6]) stored %v and wrote back %v, want %v", stored.LineageIDs, key.LineageIDs, want)
	}

	written := []access.KeyAttribution{
		{UserID: alice.ID, Action: access.AttributionCreated, KeyLineage: []int64{key.ID}, At: t0},
		{UserID: bob.ID, Action: access.AttributionDisabled, KeyLineage: []int64{4, key.ID}, At: t0.Add(-time.Hour)},
		{UserID: alice.ID, Action: access.AttributionEnabled, KeyLineage: []int64{6}, At: t0.Add(time.Minute)},
	}
	for i := range written {
		if err := store.CreateKeyAttribution(ctx, &written[i]); err != nil {
			t.Fatalf("CreateKeyAttribution: %v", err)
		}
	}
	list := func() []access.KeyAttribution {
		t.Helper()
		got, err := store.ListKeyAttributions(ctx)
		if err != nil {
			t.Fatalf("ListKeyAttributions: %v", err)
		}
		return got
	}
	same := func(got, want []access.KeyAttribution) bool {
		return slices.EqualFunc(got, want, func(a, b access.KeyAttribution) bool {
			return a.ID == b.ID && a.UserID == b.UserID && a.Action == b.Action && a.At.Equal(b.At) && slices.Equal(a.KeyLineage, b.KeyLineage)
		})
	}
	if got := list(); !same(got, written) {
		t.Errorf("ListKeyAttributions = %+v, want the three in append order %+v", got, written)
	}

	if err := store.DeleteAPIKey(ctx, access.KeyRef{ID: key.ID, UserID: alice.ID}); err != nil {
		t.Fatalf("DeleteAPIKey: %v", err)
	}
	if got := list(); !same(got, written) {
		t.Errorf("after deleting the key the records name, ListKeyAttributions = %+v, want all three", got)
	}

	if err := store.DeleteUser(ctx, bob.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if got, want := list(), []access.KeyAttribution{written[0], written[2]}; !same(got, want) {
		t.Errorf("after deleting bob, ListKeyAttributions = %+v, want alice's two %+v", got, want)
	}
}

func TestMemStoreDeleteUserSessionsKeepsExcepted(t *testing.T) {
	t.Parallel()
	store := accesstest.NewMemStore()
	for _, s := range []access.Session{{ID: "keep", UserID: 1}, {ID: "drop", UserID: 1}, {ID: "other", UserID: 2}} {
		s.TokenHash = access.NewHash(s.ID)
		mustCreateSession(t, store, &s)
	}

	ids, err := store.DeleteUserSessions(t.Context(), 1, "keep")
	if err != nil || !slices.Equal(ids, []string{"drop"}) {
		t.Fatalf("DeleteUserSessions(1, keep) = (%v, %v), want ([drop], nil)", ids, err)
	}
	for id, want := range map[string]bool{"keep": true, "drop": false, "other": true} {
		if got := sessionFound(t, store, access.NewHash(id)); got != want {
			t.Errorf("session %s present = %t, want %t", id, got, want)
		}
	}
}

func TestMemStoreAbsentRows(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	store := accesstest.NewMemStore()

	if u, found, err := store.UserByID(ctx, 999); err != nil || found || u != nil {
		t.Errorf("UserByID(999) = (%+v, %t, %v), want (nil, false, nil)", u, found, err)
	}
	if k, found, err := store.APIKeyByHash(ctx, access.NewHash("absent")); err != nil || found || k != nil {
		t.Errorf("APIKeyByHash(absent) = (%+v, %t, %v), want (nil, false, nil)", k, found, err)
	}
	if s, found, err := store.SessionByHash(ctx, access.NewHash("absent")); err != nil || found || s != nil {
		t.Errorf("SessionByHash(absent) = (%+v, %t, %v), want (nil, false, nil)", s, found, err)
	}
	if err := store.UpdateSessionActivity(ctx, access.NewHash("absent"), access.SessionActivity{At: t0}); err != nil {
		t.Errorf("UpdateSessionActivity(absent) = %v, want nil", err)
	}
	if err := store.TouchAPIKey(ctx, 8, t0); err != nil {
		t.Errorf("TouchAPIKey(unknown ID) = %v, want nil", err)
	}
	if found := sessionFound(t, store, access.NewHash("absent")); found {
		t.Error("UpdateSessionActivity(absent) created a session")
	}
	if keys, err := store.ListAPIKeys(ctx); err != nil || len(keys) != 0 {
		t.Errorf("after TouchAPIKey(unknown ID), ListAPIKeys = (%v, %v), want none", keys, err)
	}
}
