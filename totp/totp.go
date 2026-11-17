package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 4226 §5.2 defines HOTP over HMAC-SHA-1, the only algorithm Google Authenticator reads
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"strings"
	"time"
)

// The fixed parameters of every secret and code.
const (
	SecretBytes = 20               // 160 bits: RFC 4226 §4 R6; NIST SP 800-63B-4 §3.1.4 asks for 112
	Digits      = 6                // RFC 4226 §5.3; the Key Uri Format's default
	Period      = 30 * time.Second // RFC 6238 §5.2's recommended X
	Skew        = 1                // steps accepted either side of now: RFC 6238 §5.2 and §6
)

const (
	period  = int64(Period / time.Second)
	modulus = 1_000_000 // 10^Digits
)

// NewSecret returns SecretBytes from crypto/rand.
func NewSecret() []byte {
	b := make([]byte, SecretBytes)
	rand.Read(b) // never returns an error (Go 1.24+); it crashes instead
	return b
}

// Step is RFC 6238 §4.2's T for t, with T0 = 0 and X = Period.
func Step(t time.Time) int64 {
	u := t.Unix()
	s := u / period
	if u%period < 0 {
		s-- // §4.2's floor, where Go's division truncates toward zero
	}
	return s
}

// Code is the HOTP value of RFC 4226 §5.3 for secret at counter step:
// HMAC-SHA-1, dynamic truncation, then mod 10^Digits, zero-padded.
func Code(secret []byte, step int64) string {
	m := hmac.New(sha1.New, secret)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(step)) //nolint:gosec // G115: §5.1's C is the counter's 8 bytes, two's complement for a pre-1970 step
	m.Write(c[:])
	v := truncate(m.Sum(nil)) % modulus
	var out [Digits]byte
	for i := Digits - 1; i >= 0; i-- {
		out[i] = byte('0' + v%10)
		v /= 10
	}
	return string(out[:])
}

// truncate is RFC 4226 §5.3's DT.
func truncate(sum []byte) uint32 {
	off := sum[len(sum)-1] & 0xf
	return binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
}

// Result is what Match found.
type Result int

// The answers of Match.
const (
	NoMatch Result = iota
	Matched
	Reused    // the code is a step at or below after, and no fresher step matched
	Malformed // not six ASCII digits after removing spaces; the caller refuses it before any count
)

// Match removes ASCII spaces from raw, so "123 456" is the same code as
// "123456" for replay and for the count, then compares it with each step
// from Step(now)+Skew down to Step(now)-Skew by subtle.ConstantTimeCompare,
// stopping at the first match above after. It returns Matched with that
// step; else Reused when a step at or below after matches; else NoMatch.
// The step is meaningful only with Matched, and the caller stores it as the
// next after. Scanning from the newest step keeps a replay refused when two
// steps in the window share a code.
func Match(secret []byte, raw string, now time.Time, after int64) (step int64, r Result) {
	code, ok := normalize(raw)
	if !ok {
		return 0, Malformed
	}
	r = NoMatch
	cur := Step(now)
	for s := cur + Skew; s >= cur-Skew; s-- {
		if subtle.ConstantTimeCompare([]byte(Code(secret, s)), code) != 1 {
			continue
		}
		if s > after {
			return s, Matched
		}
		r = Reused
	}
	return 0, r
}

func normalize(raw string) ([]byte, bool) {
	var b [Digits]byte
	n := 0
	for i := range len(raw) {
		c := raw[i]
		switch {
		case c == ' ':
		case c >= '0' && c <= '9' && n < Digits:
			b[n] = c
			n++
		default:
			return nil, false
		}
	}
	return b[:], n == Digits
}

// URI is the Key Uri Format's otpauth://totp/<issuer>:<account>?secret=…
// with issuer equal to the label prefix, algorithm SHA1, 6 digits and a
// 30-second period. A colon in either part becomes "_", since the format
// reads an encoded colon as the separator too.
func URI(issuer, account string, secret []byte) string {
	iss := escape(strings.ReplaceAll(issuer, ":", "_"))
	return "otpauth://totp/" + iss + ":" + escape(strings.ReplaceAll(account, ":", "_")) +
		"?secret=" + Text(secret) + "&issuer=" + iss + "&algorithm=SHA1&digits=6&period=30"
}

// escape percent-encodes every byte but RFC 3986 §2.3's unreserved set, so
// the same text is safe in the label's path and in the query, and a space
// is %20, never the "+" that only form decoding reads as a space.
func escape(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0xf])
	}
	return b.String()
}

var unpadded = base32.StdEncoding.WithPadding(base32.NoPadding)

// Text is secret in RFC 4648 §6 base32 without padding, the key a person
// types when they cannot scan the URI.
func Text(secret []byte) string { return unpadded.EncodeToString(secret) }
