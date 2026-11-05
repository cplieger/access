package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cplieger/access/internal/printcheck"
	"pgregory.net/rapid"
)

func TestProperty_APIKeyHashVerificationRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		k, err := GenerateAPIKey("ak_")
		if err != nil {
			t.Fatalf("GenerateAPIKey(ak_) error = %v", err)
		}
		plaintext, returnedHash := k.Plaintext.Reveal(), k.Hash

		h := sha256.Sum256([]byte(plaintext))
		computedHash := hex.EncodeToString(h[:])

		if computedHash != returnedHash.Reveal() {
			t.Fatalf("hash mismatch")
		}

		other := plaintext + "x"
		otherH := sha256.Sum256([]byte(other))
		otherHash := hex.EncodeToString(otherH[:])
		if otherHash == returnedHash.Reveal() {
			t.Fatalf("different key produced same hash")
		}
	})
}

func TestProperty_APIKeyFormatAndUniqueness(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 20).Draw(t, "n")
		plaintexts := make(map[string]struct{}, n)
		hashes := make(map[string]struct{}, n)

		for range n {
			k, err := GenerateAPIKey("ak_")
			if err != nil {
				t.Fatalf("GenerateAPIKey(ak_) error = %v", err)
			}
			plaintext, hash, prefix, suffix := k.Plaintext.Reveal(), k.Hash, k.DisplayPrefix, k.DisplaySuffix

			if len(plaintext) < 3 || plaintext[:3] != "ak_" {
				t.Fatalf("key does not start with ak_")
			}
			randomPart := plaintext[3:]
			if len(randomPart) < 64 {
				t.Fatalf("random portion length %d < 64", len(randomPart))
			}
			if _, err := hex.DecodeString(randomPart); err != nil {
				t.Fatalf("random portion is not valid hex: %v", err)
			}
			if prefix != plaintext[:8] {
				t.Fatalf("prefix mismatch")
			}
			if suffix != plaintext[len(plaintext)-4:] {
				t.Fatalf("suffix mismatch")
			}
			if _, dup := plaintexts[plaintext]; dup {
				t.Fatalf("duplicate plaintext")
			}
			plaintexts[plaintext] = struct{}{}
			if _, dup := hashes[hash.Reveal()]; dup {
				t.Fatalf("duplicate hash")
			}
			hashes[hash.Reveal()] = struct{}{}
		}
	})
}

func TestVerifyAPIKey_error_paths(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "keyuser", PasswordHash: NewHash("dummy"), Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	plaintext, hash, prefix, suffix := mustAPIKey(t)
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	for _, tc := range []struct {
		name string
		key  string
	}{
		{"nonexistent", "ak_0000000000000000000000000000000000000000000000000000000000000000"},
		{"wrong key", plaintext + "x"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := VerifyAPIKey(ctx, db, tc.key)
			if !errors.Is(err, ErrInvalidAPIKey) {
				t.Errorf("error = %v, want ErrInvalidAPIKey", err)
			}
			if got != nil {
				t.Errorf("got = %+v, want nil", got)
			}
		})
	}

	got, err := VerifyAPIKey(ctx, db, plaintext)
	if err != nil {
		t.Fatalf("VerifyAPIKey(valid) error: %v", err)
	}
	if got == nil {
		t.Fatal("VerifyAPIKey(valid) = nil")
	}
}

func TestVerifyAPIKey_expired(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "keyuser", PasswordHash: NewHash("dummy"), Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	plaintext, hash, prefix, suffix := mustAPIKey(t)

	past := time.Now().Add(-time.Hour)
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix,
		Label: "expired", ExpiresAt: past,
	}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	_, err := VerifyAPIKey(ctx, db, plaintext)
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("VerifyAPIKey(expired) = %v, want ErrInvalidAPIKey", err)
	}
}

func TestVerifyAPIKey_not_expired(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "keyuser", PasswordHash: NewHash("dummy"), Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	plaintext, hash, prefix, suffix := mustAPIKey(t)

	future := time.Now().Add(time.Hour)
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix,
		Label: "valid", ExpiresAt: future,
	}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	got, err := VerifyAPIKey(ctx, db, plaintext)
	if err != nil {
		t.Fatalf("VerifyAPIKey(valid) error: %v", err)
	}
	if got == nil {
		t.Fatal("VerifyAPIKey(valid) = nil")
	}
}

// mustAPIKey generates an "ak_" key and returns the four parts a test stores
// or presents.
func mustAPIKey(tb testing.TB) (plaintext string, hash Hash, prefix, suffix string) {
	tb.Helper()
	k, err := GenerateAPIKey("ak_")
	if err != nil {
		tb.Fatalf("GenerateAPIKey(ak_) error = %v", err)
	}
	return k.Plaintext.Reveal(), k.Hash, k.DisplayPrefix, k.DisplaySuffix
}

func TestGenerateAPIKeyPrefix(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"", "ak_", "AZaz09_", "Abcd_0123456789x"} {
		t.Run("accepts "+prefix, func(t *testing.T) {
			t.Parallel()
			k, err := GenerateAPIKey(prefix)
			if err != nil {
				t.Fatalf("GenerateAPIKey(%q) error = %v, want nil", prefix, err)
			}
			plaintext := k.Plaintext.Reveal()
			random, ok := strings.CutPrefix(plaintext, prefix)
			if !ok {
				t.Fatalf("plaintext %q does not start with %q", plaintext, prefix)
			}
			if b, err := hex.DecodeString(random); err != nil || len(b) != 32 {
				t.Errorf("plaintext after the prefix = %q, want 64 hex characters", random)
			}
			if !k.Hash.Equal(APIKeyHash(plaintext)) {
				t.Errorf("Hash = %s, want APIKeyHash(plaintext)", k.Hash.Reveal())
			}
			if len(k.DisplayPrefix) != 8 || k.DisplayPrefix != plaintext[:8] {
				t.Errorf("DisplayPrefix = %q, want the first 8 bytes of %q", k.DisplayPrefix, plaintext)
			}
			if k.DisplaySuffix != plaintext[len(plaintext)-4:] {
				t.Errorf("DisplaySuffix = %q, want the last 4 bytes of %q", k.DisplaySuffix, plaintext)
			}
			for i := range len(k.DisplayPrefix) {
				if k.DisplayPrefix[i] >= utf8.RuneSelf {
					t.Errorf("DisplayPrefix = %q, want ASCII only", k.DisplayPrefix)
				}
			}
		})
	}
	refused := map[string]string{
		"17 bytes":            "Abcd_0123456789xy",
		"non-ASCII":           "ключ_",
		"hyphen":              "ak-",
		"space":               "ak ",
		"NUL":                 "ak\x00",
		"slash below digits":  "ak/",
		"colon above digits":  "ak:",
		"at below upper":      "ak@",
		"bracket above upper": "ak[",
		"backtick below low":  "ak`",
		"brace above lower":   "ak{",
	}
	for name, prefix := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			t.Parallel()
			k, err := GenerateAPIKey(prefix)
			if !errors.Is(err, ErrInvalidKeyPrefix) {
				t.Errorf("GenerateAPIKey(%q) error = %v, want ErrInvalidKeyPrefix", prefix, err)
			}
			if !k.Plaintext.IsZero() || !k.Hash.IsZero() || k.DisplayPrefix != "" || k.DisplaySuffix != "" {
				t.Errorf("GenerateAPIKey(%q) = %+v, want the zero GeneratedKey", prefix, k)
			}
		})
	}
}

func TestGenerateAPIKeyPrinting(t *testing.T) {
	t.Parallel()
	k, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatalf("GenerateAPIKey(ak_) error = %v", err)
	}
	for name, v := range map[string]any{"value": k, "pointer": &k} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			checkMasked(t, v, k.Plaintext.Reveal())
			checkMasked(t, v, k.Hash.Reveal())
		})
	}
	t.Run("type_graph", func(t *testing.T) {
		t.Parallel()
		checkTypes(t, printcheck.Allow{Fields: []string{"access.GeneratedKey.DisplayPrefix", "access.GeneratedKey.DisplaySuffix"}},
			reflect.TypeFor[*GeneratedKey]())
	})
}

// nilKeyStore answers found with a nil key, a store bug VerifyAPIKey must
// not dereference.
type nilKeyStore struct{}

func (nilKeyStore) APIKeyByHash(context.Context, Hash) (*Key, bool, error) {
	return nil, true, nil
}

func TestVerifyAPIKeyNilKey(t *testing.T) {
	t.Parallel()
	plaintext, _, _, _ := mustAPIKey(t)
	got, err := VerifyAPIKey(t.Context(), nilKeyStore{}, plaintext)
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("VerifyAPIKey(found, nil key) error = %v, want ErrInvalidAPIKey", err)
	}
	if got != nil {
		t.Errorf("VerifyAPIKey(found, nil key) = %+v, want nil", got)
	}
}

// looseAPIKeyStore returns its key for any hash, simulating a store that
// performs a loose or buggy lookup not anchored to an exact hash match.
type looseAPIKeyStore struct {
	key *Key
}

func (s *looseAPIKeyStore) APIKeyByHash(_ context.Context, _ Hash) (*Key, bool, error) {
	return s.key, s.key != nil, nil
}

func TestVerifyAPIKey_rejects_hash_mismatch(t *testing.T) {
	t.Parallel()
	plaintext, _, _, _ := mustAPIKey(t)
	// The store returns a record whose stored hash does NOT match the hash of
	// the presented key. VerifyAPIKey must reject it rather than trust the
	// store's lookup.
	store := &looseAPIKeyStore{key: &Key{KeyHash: NewHash("not-the-right-hash"), UserID: 7}}
	if _, err := VerifyAPIKey(t.Context(), store, plaintext); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("VerifyAPIKey(hash mismatch) = %v, want ErrInvalidAPIKey", err)
	}
}

func TestProperty_APIKeyRoleInheritance(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		db := newFakeSessionStore()
		ctx := t.Context()

		role := rapid.SampledFrom([]string{"admin", "user"}).Draw(rt, "role")
		username := fmt.Sprintf("user_%s", rapid.StringMatching(`[a-z]{4,8}`).Draw(rt, "username"))

		user := &User{
			Username:     username,
			PasswordHash: NewHash("dummy"),
			Role:         Role(role),
			Enabled:      true,
		}
		if err := db.CreateUser(ctx, user); err != nil {
			rt.Fatalf("CreateUser: %v", err)
		}

		k, err := GenerateAPIKey("ak_")
		if err != nil {
			rt.Fatalf("GenerateAPIKey(ak_) error = %v", err)
		}
		plaintext, hash, prefix, suffix := k.Plaintext.Reveal(), k.Hash, k.DisplayPrefix, k.DisplaySuffix
		apiKey := &Key{
			UserID:    user.ID,
			KeyHash:   hash,
			KeyPrefix: prefix,
			KeySuffix: suffix,
			Label:     "test",
		}
		if err := db.CreateAPIKey(ctx, apiKey); err != nil {
			rt.Fatalf("CreateAPIKey: %v", err)
		}

		verified, err := VerifyAPIKey(ctx, db, plaintext)
		if err != nil {
			rt.Fatalf("VerifyAPIKey: %v", err)
		}
		if verified.UserID != user.ID {
			rt.Fatalf("API key user ID mismatch: got %d, want %d", verified.UserID, user.ID)
		}

		resolvedUser, _, err := db.UserByID(ctx, verified.UserID)
		if err != nil {
			rt.Fatalf("UserByID: %v", err)
		}
		if resolvedUser.Role != Role(role) {
			rt.Fatalf("role mismatch: got %s, want %s", resolvedUser.Role, role)
		}
	})
}
