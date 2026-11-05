package access

import (
	"errors"
	"time"
)

// Token errors.
var (
	ErrTokenExpired = errors.New("access: token expired")
	ErrTokenInvalid = errors.New("access: token invalid")
)

// GenerateOpaqueToken generates a cryptographically random opaque token
// suitable for password-reset or email-verification flows. Returns the
// plaintext token (to Reveal only into what is sent to the user) and its hex
// SHA-256 hash (to store in the database). It cannot fail; see
// [generateRandomHex].
func GenerateOpaqueToken() (plaintext Secret, hash Hash) {
	tok := generateRandomHex(32)
	return NewSecret(tok), NewHash(HexSHA256(tok))
}

// VerifyOpaqueToken checks that the plaintext token matches the stored hash
// and that the token has not expired. Returns nil on success.
func VerifyOpaqueToken(plaintext string, storedHash Hash, expiresAt time.Time) error {
	if !NewHash(HexSHA256(plaintext)).Equal(storedHash) {
		return ErrTokenInvalid
	}
	if time.Now().After(expiresAt) {
		return ErrTokenExpired
	}
	return nil
}
