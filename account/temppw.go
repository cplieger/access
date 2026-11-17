package account

import (
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/crockford"
)

// temporaryPasswordRandomBytes is a temporary password's entropy: 64 bits,
// the floor NIST SP 800-63B-4 §4.2.1.1 sets for a saved recovery code, the
// other secret the CSP issues to restore access; the spec sets none for an
// assigned password. Two check bytes follow, so the value is 16 Crockford
// symbols, over SP 800-63B-4 §3.1.1.2's 15-character minimum.
const temporaryPasswordRandomBytes = 8

const temporaryPasswordBytes = temporaryPasswordRandomBytes + 2

// newTemporaryPassword draws a temporary password from crypto/rand: shown is
// its displayed form, XXXX-XXXX-XXXX-XXXX, and canonical the 16 symbols its
// hash covers.
func newTemporaryPassword() (shown access.Secret, canonical string) {
	var r [temporaryPasswordRandomBytes]byte
	_, _ = rand.Read(r[:]) // crypto/rand.Read never fails (Go 1.24+); it crashes the program instead
	canonical = temporaryPasswordFrom(r)
	return access.NewSecret(groupFours(canonical)), canonical
}

// temporaryPasswordFrom is the canonical value of random: the bytes, then
// their check big-endian, in Crockford's base32. The check is public and
// protects nothing: it lets a client recognise the value offline, as the
// CRC-32 in GitHub's token formats does for secret scanning.
func temporaryPasswordFrom(random [temporaryPasswordRandomBytes]byte) string {
	var b [temporaryPasswordBytes]byte
	copy(b[:], random[:])
	binary.BigEndian.PutUint16(b[temporaryPasswordRandomBytes:], temporaryPasswordCheck(random[:]))
	return crockford.Encode(b[:])
}

// temporaryPasswordCheck is the low 16 bits of b's CRC-32/ISO-HDLC; the web
// client's looksLikeTemporaryPassword computes the same value.
func temporaryPasswordCheck(b []byte) uint16 {
	return uint16(crc32.ChecksumIEEE(b) & 0xFFFF)
}

// temporaryPasswordForm is presented normalised as a recovery code is
// (crockford.Normalize), and whether that is the one form a temporary
// password's hash can match: 16 symbols whose check passes.
func temporaryPasswordForm(presented string) (canonical string, ok bool) {
	canonical = crockford.Normalize(presented)
	b, ok := crockford.Decode(canonical)
	if !ok || len(b) != temporaryPasswordBytes ||
		binary.BigEndian.Uint16(b[temporaryPasswordRandomBytes:]) != temporaryPasswordCheck(b[:temporaryPasswordRandomBytes]) {
		return "", false
	}
	return canonical, true
}
