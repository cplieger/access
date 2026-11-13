package access

import (
	"context"
	"errors"
	"time"
)

// ErrInvalidAPIKey is returned when an API key cannot be verified.
var ErrInvalidAPIKey = errors.New("invalid API key")

// ErrInvalidKeyPrefix is returned by [ValidateKeyPrefix] and
// [GenerateAPIKey] for a prefix that is not 0 to 16 ASCII letters, digits or
// underscores.
var ErrInvalidKeyPrefix = errors.New("access: API key prefix must match ^[A-Za-z0-9_]{0,16}$")

// maxKeyPrefixLength is the longest prefix [GenerateAPIKey] accepts.
const maxKeyPrefixLength = 16

// apiKeyRandomBytes is the entropy behind a generated key's prefix; its hex
// form makes every generated key at least 2*apiKeyRandomBytes bytes long.
const apiKeyRandomBytes = 32

// keyDisplayPrefixLength is the length of [GeneratedKey.DisplayPrefix].
const keyDisplayPrefixLength = 8

// GeneratedKey is a new API key. Plaintext is shown to the user once; Hash,
// DisplayPrefix and DisplaySuffix are what a store keeps.
type GeneratedKey struct {
	// Plaintext is the prefix followed by 64 hex characters (256 random bits).
	Plaintext Secret
	// Hash is the [APIKeyHash] of Plaintext.
	Hash Hash
	// DisplayPrefix is the first 8 bytes of Plaintext, all ASCII.
	DisplayPrefix string
	// DisplaySuffix is the last 4 bytes of Plaintext, all ASCII.
	DisplaySuffix string
}

// GenerateAPIKey generates a new API key with 256 bits of entropy behind
// prefix (e.g. "ak_"). prefix must match ^[A-Za-z0-9_]{0,16}$, so every byte
// of the key, and so of its display parts, is ASCII; any other prefix is
// [ErrInvalidKeyPrefix].
func GenerateAPIKey(prefix string) (GeneratedKey, error) {
	if err := ValidateKeyPrefix(prefix); err != nil {
		return GeneratedKey{}, err
	}
	plaintext := prefix + generateRandomHex(apiKeyRandomBytes)
	return GeneratedKey{
		Plaintext:     NewSecret(plaintext),
		Hash:          APIKeyHash(plaintext),
		DisplayPrefix: plaintext[:keyDisplayPrefixLength],
		DisplaySuffix: plaintext[len(plaintext)-4:],
	}, nil
}

// ValidateKeyPrefix returns nil for a prefix [GenerateAPIKey] accepts, and
// [ErrInvalidKeyPrefix] otherwise.
func ValidateKeyPrefix(prefix string) error {
	if !validKeyPrefix(prefix) {
		return ErrInvalidKeyPrefix
	}
	return nil
}

// parseAPIKey reports whether key has the shape [GenerateAPIKey] returns: a
// valid prefix followed by the lowercase hex of apiKeyRandomBytes bytes. The
// API-key verifier looks up no value this refuses.
func parseAPIKey(key string) bool {
	n := len(key) - 2*apiKeyRandomBytes
	return n >= 0 && validKeyPrefix(key[:n]) && isLowerHex(key[n:])
}

// isLowerHex reports whether every byte of s is one [encoding/hex] emits.
func isLowerHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validKeyPrefix(prefix string) bool {
	if len(prefix) > maxKeyPrefixLength {
		return false
	}
	for i := range len(prefix) {
		c := prefix[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// VerifyAPIKey hashes key, looks it up in the store, and returns the
// matching record. It returns ErrInvalidAPIKey when the store finds no key,
// answers found with a nil key, or holds a key with neither the computed
// hash as its KeyHash nor as its PreviousHash; for a key whose ExpiresAt is
// set and not after now, as the [Authenticator] does; and for a previous
// secret unless now is before PreviousUntil and LastUsedAt is zero. It never
// touches, so a previous secret lasts until PreviousUntil. A store error is
// returned as is.
func VerifyAPIKey(ctx context.Context, store APIKeyReader, key string) (*Key, error) {
	k, previous, err := findAPIKey(ctx, store, APIKeyHash(key))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if keyExpired(k, now) || (previous && !previousUsable(k, now)) {
		return nil, ErrInvalidAPIKey
	}
	return k, nil
}

// APIKeyHash returns the hex-encoded SHA-256 hash of a key string.
func APIKeyHash(key string) Hash {
	return NewHash(HexSHA256(key))
}
