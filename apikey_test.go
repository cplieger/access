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

// answerReader is an app's own minimal APIKeyReader: it answers every
// lookup with key, found and err, as a store doing a loose lookup would.
type answerReader struct {
	err   error
	key   *Key
	found bool
}

func (r answerReader) APIKeyByHash(context.Context, Hash) (*Key, bool, error) {
	return r.key, r.found, r.err
}

// TestGuardVerifyAPIKeyMinimalReader pins VerifyAPIKey over an app's own
// reader whose keys carry no PreviousHash: a key is returned only when its
// stored hash is the presented key's and it is unexpired.
func TestGuardVerifyAPIKeyMinimalReader(t *testing.T) {
	t.Parallel()
	plaintext, hash, _, _ := mustAPIKey(t)
	other, _, _, _ := mustAPIKey(t)
	errDown := errors.New("db down")
	for _, tt := range []struct {
		want   error
		reader answerReader
		name   string
	}{
		{name: "found", reader: answerReader{key: &Key{ID: 7, KeyHash: hash}, found: true}},
		{name: "found with a future expiry", reader: answerReader{key: &Key{ID: 7, KeyHash: hash, ExpiresAt: time.Now().Add(time.Hour)}, found: true}},
		{name: "expired", reader: answerReader{key: &Key{ID: 7, KeyHash: hash, ExpiresAt: time.Now().Add(-time.Hour)}, found: true}, want: ErrInvalidAPIKey},
		{name: "missing", want: ErrInvalidAPIKey},
		{name: "found with a nil key", reader: answerReader{found: true}, want: ErrInvalidAPIKey},
		{name: "another key's hash", reader: answerReader{key: &Key{ID: 7, KeyHash: APIKeyHash(other)}, found: true}, want: ErrInvalidAPIKey},
		{name: "store error", reader: answerReader{err: errDown}, want: errDown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := VerifyAPIKey(t.Context(), tt.reader, plaintext)
			if tt.want == nil {
				if err != nil || got == nil || got.ID != 7 {
					t.Errorf("VerifyAPIKey = (%+v, %v), want key 7", got, err)
				}
				return
			}
			if err != tt.want || got != nil { //nolint:errorlint // the sentinel or the store's error, returned as is
				t.Errorf("VerifyAPIKey = (%+v, %v), want (nil, %v)", got, err, tt.want)
			}
		})
	}
}

// TestVerifyAPIKeyPreviousSecret pins design 2.4's previous-secret rule
// over an app's own reader: the previous secret verifies while PreviousUntil
// is ahead and LastUsedAt is zero.
func TestVerifyAPIKeyPreviousSecret(t *testing.T) {
	t.Parallel()
	current, hash, _, _ := mustAPIKey(t)
	old, oldHash, _, _ := mustAPIKey(t)
	rotated := func(edit func(*Key)) answerReader {
		k := &Key{ID: 7, KeyHash: hash, PreviousHash: oldHash, PreviousUntil: time.Now().Add(time.Hour)}
		if edit != nil {
			edit(k)
		}
		return answerReader{key: k, found: true}
	}
	for _, tt := range []struct {
		reader answerReader
		name   string
		key    string
		ok     bool
	}{
		{name: "current secret", reader: rotated(nil), key: current, ok: true},
		{name: "previous before first use", reader: rotated(nil), key: old, ok: true},
		{name: "previous after first use", reader: rotated(func(k *Key) { k.LastUsedAt = time.Now() }), key: old},
		{name: "previous past its bound", reader: rotated(func(k *Key) { k.PreviousUntil = time.Now().Add(-time.Second) }), key: old},
		{name: "previous of an expired key", reader: rotated(func(k *Key) { k.ExpiresAt = time.Now().Add(-time.Second) }), key: old},
		{name: "current after first use", reader: rotated(func(k *Key) { k.LastUsedAt = time.Now() }), key: current, ok: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := VerifyAPIKey(t.Context(), tt.reader, tt.key)
			if tt.ok {
				if err != nil || got == nil || got.ID != 7 {
					t.Errorf("VerifyAPIKey = (%+v, %v), want key 7", got, err)
				}
				return
			}
			if err != ErrInvalidAPIKey || got != nil { //nolint:errorlint // the bare sentinel
				t.Errorf("VerifyAPIKey = (%+v, %v), want (nil, ErrInvalidAPIKey)", got, err)
			}
		})
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
			if err := ValidateKeyPrefix(prefix); err != nil {
				t.Errorf("ValidateKeyPrefix(%q) = %v, want nil", prefix, err)
			}
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
			if err := ValidateKeyPrefix(prefix); !errors.Is(err, ErrInvalidKeyPrefix) {
				t.Errorf("ValidateKeyPrefix(%q) = %v, want ErrInvalidKeyPrefix", prefix, err)
			}
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
