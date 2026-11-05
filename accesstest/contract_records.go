package accesstest

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// absence: rule 1.
func (c *contract) absence(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	h := access.NewHash(fresh("absent"))
	lookups := map[string]func() (isNil, found bool, err error){
		"UserByID": func() (bool, bool, error) { u, f, err := s.UserByID(ctx, 1); return u == nil, f, err },
		opUserByUsername: func() (bool, bool, error) {
			u, f, err := s.UserByUsername(ctx, "absent")
			return u == nil, f, err
		},
		"UserByOIDC": func() (bool, bool, error) {
			u, f, err := s.UserByOIDC(ctx, access.OIDCIdentity{Issuer: testIssuer, Subject: "absent"})
			return u == nil, f, err
		},
		"UserByWebAuthnHandle": func() (bool, bool, error) {
			u, f, err := s.UserByWebAuthnHandle(ctx, access.GenerateWebAuthnHandle())
			return u == nil, f, err
		},
		opSessionByHash: func() (bool, bool, error) { v, f, err := s.SessionByHash(ctx, h); return v == nil, f, err },
		"APIKeyByHash":  func() (bool, bool, error) { v, f, err := s.APIKeyByHash(ctx, h); return v == nil, f, err },
		"OneTimeTokenByHash": func() (bool, bool, error) {
			v, f, err := s.OneTimeTokenByHash(ctx, h)
			return v.Hash.IsZero(), f, err
		},
		"ConsumeOneTimeToken": func() (bool, bool, error) {
			v, f, err := s.ConsumeOneTimeToken(ctx, h, epoch)
			return v.Hash.IsZero(), f, err
		},
		"AuthFailure": func() (bool, bool, error) {
			v, f, err := s.AuthFailure(ctx, account.FailureRef{Name: "absent", Method: access.MethodPassword})
			return v.Name == "", f, err
		},
	}
	for name, lookup := range lookups {
		if isNil, found, err := lookup(); !isNil || found || err != nil {
			t.Errorf("%s on an empty store = (nil %t, found %t, %v), want (nil, false, nil)", name, isNil, found, err)
		}
	}
	lists := map[string]func() (int, error){
		"ListUsers":        func() (int, error) { v, err := s.ListUsers(ctx); return len(v), err },
		"SessionsByUserID": func() (int, error) { v, err := s.SessionsByUserID(ctx, 1); return len(v), err },
		"PasskeysByUserID": func() (int, error) { v, err := s.PasskeysByUserID(ctx, 1); return len(v), err },
		opListUserKeys:     func() (int, error) { v, err := s.ListAPIKeysByUserID(ctx, 1); return len(v), err },
		opListAllKeys:      func() (int, error) { v, err := s.ListAPIKeys(ctx); return len(v), err },
		"LiveOneTimeTokens": func() (int, error) {
			v, err := s.LiveOneTimeTokens(ctx, []access.TokenPurpose{access.PurposeInvite}, epoch)
			return len(v), err
		},
		"ListKeyAttributions": func() (int, error) { v, err := s.ListKeyAttributions(ctx); return len(v), err },
		"UnreportedLocks":     func() (int, error) { v, err := s.UnreportedLocks(ctx); return len(v), err },
	}
	for name, list := range lists {
		if n, err := list(); n != 0 || err != nil {
			t.Errorf("%s on an empty store = (%d rows, %v), want (0, nil)", name, n, err)
		}
	}
}

// flip changes b's first byte, if it has one, so a store aliasing b shows
// the change.
func flip(b []byte) {
	if len(b) > 0 {
		b[0] ^= 0xFF
	}
}

// ownership: rule 2.
func (c *contract) ownership(t *testing.T) {
	t.Run("user", c.ownUser)
	t.Run("key", c.ownKey)
	t.Run("attribution", c.ownAttribution)
	t.Run("passkey", c.ownPasskey)
	t.Run("session", c.ownSession)
}

func (c *contract) ownUser(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "owner")
	want := slices.Clone(u.WebAuthnHandle)
	flip(u.WebAuthnHandle)
	read := func() []byte {
		got, _, err := s.UserByID(ctx, u.ID)
		if err != nil || got == nil {
			t.Fatalf("UserByID = (%v, %v), want the user", got, err)
		}
		return got.WebAuthnHandle
	}
	if got := read(); !bytes.Equal(got, want) {
		t.Errorf("handle after mutating the written user = %x, want %x", got, want)
	}
	flip(read())
	if got := read(); !bytes.Equal(got, want) {
		t.Errorf("handle after mutating a returned user = %x, want %x", got, want)
	}
}

func (c *contract) ownKey(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "owner")
	k := newKey(u.ID)
	k.LineageIDs = []int64{5}
	mustKey(t, s, k)
	wantScopes, wantLineage := []string{"read", "write"}, []int64{5, k.ID}
	k.Scopes[0], k.LineageIDs[0] = mutated, 99
	mutate := func(got *access.Key) {
		if len(got.Scopes) > 0 && len(got.LineageIDs) > 0 {
			got.Scopes[0], got.LineageIDs[0] = mutated, 99
		}
	}
	check := func(when string) {
		got, found, err := s.APIKeyByHash(ctx, k.KeyHash)
		if err != nil || !found {
			t.Fatalf("APIKeyByHash = (%t, %v), want the key", found, err)
		}
		if !slices.Equal(got.Scopes, wantScopes) || !slices.Equal(got.LineageIDs, wantLineage) {
			t.Errorf("%s: key = scopes %v lineage %v, want %v %v", when, got.Scopes, got.LineageIDs, wantScopes, wantLineage)
		}
		mutate(got)
	}
	check("after mutating the written key")
	check("after mutating a returned key")
	list, err := s.ListAPIKeys(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListAPIKeys = (%d keys, %v), want 1", len(list), err)
	}
	mutate(&list[0])
	check("after mutating a listed key")
}

func (c *contract) ownAttribution(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "owner")
	a := &access.KeyAttribution{At: epoch, Action: access.AttributionCreated, KeyLineage: []int64{1, 2}, UserID: u.ID}
	if err := s.CreateKeyAttribution(ctx, a); err != nil {
		t.Fatalf("CreateKeyAttribution: %v", err)
	}
	a.KeyLineage[0] = 99
	for _, when := range []string{"after mutating the written record", "after mutating a returned record"} {
		got, err := s.ListKeyAttributions(ctx)
		if err != nil || len(got) != 1 {
			t.Fatalf("ListKeyAttributions = (%d, %v), want 1", len(got), err)
		}
		if !slices.Equal(got[0].KeyLineage, []int64{1, 2}) {
			t.Fatalf("%s: KeyLineage = %v, want [1 2]", when, got[0].KeyLineage)
		}
		got[0].KeyLineage[0] = 99
	}
}

// passkeyBytes is every reference field of a credential.
func passkeyBytes(p *access.PasskeyCredential) [][]byte {
	return [][]byte{p.CredentialID, p.PublicKey, p.AAGUID, p.RawAttestation}
}

func (c *contract) ownPasskey(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "owner")
	p := newPasskey(u.ID)
	p.RawAttestation, p.Discoverable = []byte{9, 9}, new(true)
	mustPasskey(t, s, p)
	want := p.Clone()
	for _, b := range passkeyBytes(p) {
		flip(b)
	}
	*p.Discoverable = false
	for _, when := range []string{"after mutating the written credential", "after mutating a returned credential"} {
		got, err := s.PasskeysByUserID(ctx, u.ID)
		if err != nil || len(got) != 1 {
			t.Fatalf("PasskeysByUserID = (%d, %v), want 1", len(got), err)
		}
		for i, b := range passkeyBytes(&got[0]) {
			if w := passkeyBytes(want)[i]; !bytes.Equal(b, w) {
				t.Errorf("%s: byte field %d = %x, want %x", when, i, b, w)
			}
			flip(b)
		}
		if got[0].Discoverable == nil || !*got[0].Discoverable {
			t.Errorf("%s: Discoverable = %v, want true", when, got[0].Discoverable)
		} else {
			*got[0].Discoverable = false
		}
	}
}

func (c *contract) ownSession(t *testing.T) {
	s := c.store(t)
	sess := newSession(1, epoch)
	sess.Label = "laptop"
	mustSession(t, s, sess)
	sess.Label = mutated
	for _, when := range []string{"after mutating the written session", "after mutating a returned session"} {
		got, found := sessionFound(t, s, sess.TokenHash)
		if !found {
			t.Fatal("SessionByHash found = false, want true")
		}
		if got.Label != "laptop" {
			t.Errorf("%s: Label = %q, want laptop", when, got.Label)
		}
		got.Label = mutated
	}
}

// canonicalUsernames: rule 3.
func (c *contract) canonicalUsernames(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "MiXed")
	got, found, err := s.UserByID(ctx, u.ID)
	if err != nil || !found || got.Username != "MiXed" {
		t.Errorf("UserByID = (%v, %t, %v), want username MiXed as written", got, found, err)
	}
	if !userFound(t, s, "MiXed") {
		t.Error("UserByUsername(MiXed) found = false, want true")
	}
	if userFound(t, s, "mixed") {
		t.Error("UserByUsername(mixed) found = true: the store folded the name again")
	}
	if err := s.CreateUser(ctx, newUser("mixed")); err != nil {
		t.Errorf("CreateUser(mixed) beside MiXed = %v, want nil", err)
	}
}

// uniqueness: rule 4.
func (c *contract) uniqueness(t *testing.T) {
	for name, dup := range map[string]func(t *testing.T, s account.Store) (error, error){
		"username":      dupUsername,
		"oidc_identity": dupOIDC,
		"handle":        dupHandle,
		"credential_id": dupCredential,
		"key_hash":      dupKeyHash,
		"session_hash":  dupSessionHash,
		"session_id":    dupSessionID,
		"token_hash":    dupTokenHash,
	} {
		t.Run(name, func(t *testing.T) {
			got, want := dup(t, c.store(t))
			if got == nil || (want != nil && !errors.Is(got, want)) {
				t.Errorf("duplicate write = %v, want an error matching %v", got, want)
			}
		})
	}
	t.Run("hash_round_trip", c.hashRoundTrip)
}

func dupUsername(t *testing.T, s account.Store) (got, want error) {
	mustUser(t, s, "dup")
	return s.CreateUser(t.Context(), newUser("dup")), account.ErrUsernameTaken
}

func dupOIDC(t *testing.T, s account.Store) (got, want error) {
	id := access.OIDCIdentity{Issuer: testIssuer, Subject: "sub"}
	a := newUser("a")
	a.OIDC = id
	if err := s.CreateUser(t.Context(), a); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	b := newUser("b")
	b.OIDC = id
	return s.CreateUser(t.Context(), b), account.ErrOIDCIdentityTaken
}

func dupHandle(t *testing.T, s account.Store) (got, want error) {
	a := mustUser(t, s, "a")
	b := newUser("b")
	b.WebAuthnHandle = slices.Clone(a.WebAuthnHandle)
	return s.CreateUser(t.Context(), b), nil
}

func dupCredential(t *testing.T, s account.Store) (got, want error) {
	a, b := mustUser(t, s, "a"), mustUser(t, s, "b")
	p := newPasskey(a.ID)
	mustPasskey(t, s, p)
	q := newPasskey(b.ID)
	q.CredentialID = slices.Clone(p.CredentialID)
	return s.CreatePasskey(t.Context(), q), account.ErrDuplicateCredential
}

func dupKeyHash(t *testing.T, s account.Store) (got, want error) {
	k := newKey(1)
	mustKey(t, s, k)
	again := newKey(1)
	again.KeyHash = k.KeyHash
	return s.CreateAPIKey(t.Context(), again), nil
}

func dupSessionHash(t *testing.T, s account.Store) (got, want error) {
	a := newSession(1, epoch)
	mustSession(t, s, a)
	b := newSession(1, epoch)
	b.TokenHash = a.TokenHash
	return s.CreateSession(t.Context(), b), nil
}

func dupSessionID(t *testing.T, s account.Store) (got, want error) {
	a := newSession(1, epoch)
	mustSession(t, s, a)
	b := newSession(1, epoch)
	b.ID = a.ID
	return s.CreateSession(t.Context(), b), nil
}

func dupTokenHash(t *testing.T, s account.Store) (got, want error) {
	a := newToken(access.PurposeInvite, 0, epoch.Add(time.Hour))
	mustToken(t, s, a)
	b := newToken(access.PurposeRecovery, 1, epoch.Add(time.Hour))
	b.Hash = a.Hash
	return s.CreateOneTimeToken(t.Context(), b), nil
}

// hashRoundTrip: every hash written reads back Equal, and its record is
// found by a fresh NewHash of the same text.
func (c *contract) hashRoundTrip(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	// same fails unless a read through a fresh hash found its record and the
	// hash it read back is Equal to the written one.
	same := func(field string, found bool, err error, read, written access.Hash) {
		if err != nil || !found || !read.Equal(written) {
			t.Errorf("%s: a fresh NewHash of the text finds (%t, %v), or the hash reads back unequal", field, found, err)
		}
	}
	fresher := func(h access.Hash) access.Hash { return access.NewHash(h.Reveal()) }
	u := newUser("hashes")
	check(t, "CreateUser", s.CreateUser(ctx, u))
	gotUser, found, err := s.UserByUsername(ctx, u.Username)
	same("User.PasswordHash", found, err, mustFind(t, opUserByUsername, gotUser, found, err).PasswordHash, u.PasswordHash)
	sess := newSession(u.ID, epoch)
	mustSession(t, s, sess)
	gotSess, found, err := s.SessionByHash(ctx, fresher(sess.TokenHash))
	same("Session.TokenHash", found, err, mustFind(t, opSessionByHash, gotSess, found, err).TokenHash, sess.TokenHash)
	k := newKey(u.ID)
	mustKey(t, s, k)
	gotKey, found, err := s.APIKeyByHash(ctx, fresher(k.KeyHash))
	same("Key.KeyHash", found, err, mustFind(t, "APIKeyByHash", gotKey, found, err).KeyHash, k.KeyHash)
	tok := newToken(access.PurposeInvite, 0, epoch.Add(time.Hour))
	mustToken(t, s, tok)
	gotTok, found, err := s.OneTimeTokenByHash(ctx, fresher(tok.Hash))
	same("OneTimeToken.Hash", found, err, gotTok.Hash, tok.Hash)
	next := *sess
	next.TokenHash = access.NewHash(fresh("rotated"))
	check(t, "RotateSession", s.RotateSession(ctx, account.Rotation{ID: sess.ID, UserID: u.ID, Next: next}))
	gotSess, found, err = s.SessionByHash(ctx, fresher(next.TokenHash))
	same("Rotation.Next.TokenHash", found, err, mustFind(t, opSessionByHash, gotSess, found, err).TokenHash, next.TokenHash)
}

// flags: rule 8.
func (c *contract) flags(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "flags")
	p := newPasskey(u.ID)
	mustPasskey(t, s, p)
	at := epoch.Add(time.Hour)
	if err := s.UpdatePasskeyAfterLogin(ctx, u.ID, p.CredentialID, access.PasskeyLoginUpdate{At: at, SignCount: 7, RawFlags: 0x1D, CloneWarning: true}); err != nil {
		t.Fatalf("UpdatePasskeyAfterLogin: %v", err)
	}
	got, err := s.PasskeysByUserID(ctx, u.ID)
	if err != nil || len(got) != 1 {
		t.Fatalf("PasskeysByUserID = (%d, %v), want 1", len(got), err)
	}
	g := got[0]
	up, uv, be, bs := access.DecodePasskeyFlags(0x1D)
	if g.RawFlags != 0x1D || g.UserPresent != up || g.UserVerified != uv || g.BackupEligible != be || g.BackupState != bs {
		t.Errorf("flags = %#x %t %t %t %t, want 0x1d %t %t %t %t", g.RawFlags, g.UserPresent, g.UserVerified, g.BackupEligible, g.BackupState, up, uv, be, bs)
	}
	if !g.LastUsedAt.Equal(at) || !g.CloneWarning || g.SignCount != 7 {
		t.Errorf("LastUsedAt %v CloneWarning %t SignCount %d, want %v true 7", g.LastUsedAt, g.CloneWarning, g.SignCount, at)
	}
}

// handleProbing: rule 9.
func (c *contract) handleProbing(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	mustUser(t, s, "probe")
	for name, h := range map[string][]byte{
		unknownID: access.GenerateWebAuthnHandle(),
		"nil":     nil,
		"empty":   {},
		"short":   {1},
		"long":    bytes.Repeat([]byte{7}, 65),
	} {
		if u, found, err := s.UserByWebAuthnHandle(ctx, h); u != nil || found || err != nil {
			t.Errorf("UserByWebAuthnHandle(%s) = (%v, %t, %v), want (nil, false, nil)", name, u, found, err)
		}
	}
}

// timeRoundTrip: rule 11. Every written time carries sub-millisecond
// nanoseconds and a non-UTC location.
func (c *contract) timeRoundTrip(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	at := time.Date(2030, time.May, 6, 7, 8, 9, 123_456_789, time.FixedZone("contract", 2*3600))
	same := func(name string, got time.Time) {
		if !got.Truncate(time.Millisecond).Equal(at.Truncate(time.Millisecond)) {
			t.Errorf("%s = %v, want %v within 1 ms", name, got, at)
		}
	}
	u := newUser("time")
	u.CreatedAt, u.UpdatedAt = at, at
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	gotUser, found, err := s.UserByID(ctx, u.ID)
	gotUser = mustFind(t, "UserByID", gotUser, found, err)
	same("User.CreatedAt", gotUser.CreatedAt)
	same("User.UpdatedAt", gotUser.UpdatedAt)
	sess := newSession(u.ID, at)
	mustSession(t, s, sess)
	gotSess, found := sessionFound(t, s, sess.TokenHash)
	gotSess = mustFind(t, opSessionByHash, gotSess, found, nil)
	same("Session.CreatedAt", gotSess.CreatedAt)
	same("Session.LastActivity", gotSess.LastActivity)
	same("Session.AuthTime", gotSess.AuthTime)
	k := newKey(u.ID)
	k.CreatedAt, k.ExpiresAt = at, at
	mustKey(t, s, k)
	check(t, "TouchAPIKey", s.TouchAPIKey(ctx, k.ID, at))
	gotKey, found, err := s.APIKeyByHash(ctx, k.KeyHash)
	gotKey = mustFind(t, "APIKeyByHash", gotKey, found, err)
	same("Key.CreatedAt", gotKey.CreatedAt)
	same("Key.ExpiresAt", gotKey.ExpiresAt)
	same("Key.LastUsedAt", gotKey.LastUsedAt)
	timeRoundTripRest(t, s, u.ID, at, same)
}

func timeRoundTripRest(t *testing.T, s account.Store, userID int64, at time.Time, same func(string, time.Time)) {
	ctx := t.Context()
	p := newPasskey(userID)
	p.CreatedAt, p.LastUsedAt = at, at
	mustPasskey(t, s, p)
	passkeys, err := s.PasskeysByUserID(ctx, userID)
	passkey := mustFind(t, "PasskeysByUserID", passkeys, len(passkeys) == 1, err)[0]
	same("PasskeyCredential.CreatedAt", passkey.CreatedAt)
	same("PasskeyCredential.LastUsedAt", passkey.LastUsedAt)
	tok := newToken(access.PurposeInvite, 0, at)
	tok.CreatedAt = at
	mustToken(t, s, tok)
	gotTok, found, err := s.OneTimeTokenByHash(ctx, tok.Hash)
	gotTok = mustFind(t, "OneTimeTokenByHash", gotTok, found, err)
	same("OneTimeToken.CreatedAt", gotTok.CreatedAt)
	same("OneTimeToken.ExpiresAt", gotTok.ExpiresAt)
	check(t, "CreateKeyAttribution", s.CreateKeyAttribution(ctx, &access.KeyAttribution{At: at, Action: access.AttributionCreated, KeyLineage: []int64{1}, UserID: userID}))
	attributions, err := s.ListKeyAttributions(ctx)
	same("KeyAttribution.At", mustFind(t, "ListKeyAttributions", attributions, len(attributions) == 1, err)[0].At)
	ref := account.FailureRef{Name: "time", Method: access.MethodPassword}
	check(t, "PutAuthFailure", s.PutAuthFailure(ctx, account.FailureCount{FailureRef: ref, Count: 1, Locked: true, LockedAt: at}))
	failure, found, err := s.AuthFailure(ctx, ref)
	same("FailureCount.LockedAt", mustFind(t, "AuthFailure", failure, found, err).LockedAt)
}

// mustFind returns v, failing the test unless the read that made it found
// its row without error.
func mustFind[T any](t *testing.T, what string, v T, found bool, err error) T {
	t.Helper()
	if err != nil || !found {
		t.Fatalf("%s = (found %t, %v), want the row just written", what, found, err)
	}
	return v
}

// absentRows: rule 19.
func (c *contract) absentRows(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "absent")
	if err := s.UpdateSessionActivity(ctx, access.NewHash(fresh("nobody")), access.SessionActivity{At: epoch, IP: ipA}); err != nil {
		t.Errorf("UpdateSessionActivity(unknown hash) = %v, want nil", err)
	}
	if err := s.TouchAPIKey(ctx, 4242, epoch); err != nil {
		t.Errorf("TouchAPIKey(unknown key) = %v, want nil", err)
	}
	if got, _ := s.SessionsByUserID(ctx, 0); len(got) != 0 {
		t.Errorf("an activity write for an unknown hash created %d sessions", len(got))
	}
	if got, _ := s.ListAPIKeys(ctx); len(got) != 0 {
		t.Errorf("TouchAPIKey for an unknown key created %d keys", len(got))
	}
	deleted := newSession(u.ID, epoch)
	mustSession(t, s, deleted)
	if err := s.DeleteSession(ctx, refOf(deleted)); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	rotated := newSession(u.ID, epoch)
	mustSession(t, s, rotated)
	next := *rotated
	next.TokenHash = access.NewHash(fresh("rotated"))
	if err := s.RotateSession(ctx, account.Rotation{ID: rotated.ID, UserID: u.ID, Next: next}); err != nil {
		t.Fatalf("RotateSession: %v", err)
	}
	for name, h := range map[string]access.Hash{"deleted": deleted.TokenHash, "rotated away": rotated.TokenHash} {
		if err := s.UpdateSessionActivity(ctx, h, access.SessionActivity{At: epoch.Add(time.Hour), IP: ipB}); err != nil {
			t.Errorf("UpdateSessionActivity(%s hash) = %v, want nil", name, err)
		}
		if _, found := sessionFound(t, s, h); found {
			t.Errorf("an activity write brought back the %s session", name)
		}
	}
	err := s.UpdatePasskeyAfterLogin(ctx, u.ID, []byte(unknownID), access.PasskeyLoginUpdate{At: epoch, RawFlags: 0x05})
	if !errors.Is(err, account.ErrNotFound) {
		t.Errorf("UpdatePasskeyAfterLogin(unknown credential) = %v, want ErrNotFound", err)
	}
	if got, _ := s.PasskeysByUserID(ctx, u.ID); len(got) != 0 {
		t.Errorf("UpdatePasskeyAfterLogin for an unknown credential created %d passkeys", len(got))
	}
}
