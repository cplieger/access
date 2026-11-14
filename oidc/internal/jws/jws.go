// Package jws verifies a compact JWS (RFC 7515) carrying a signed JWT
// (RFC 7519) under the algorithms of package jwk, and returns its payload.
// It knows nothing of OpenID Connect.
package jws

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cplieger/access/oidc/internal/jsonmember"
	"github.com/cplieger/access/oidc/internal/jwk"
)

// MaxSize is the longest token Parse reads; a longer one is refused before
// any part is decoded (Authlib CVE-2025-61920).
const MaxSize = 64 << 10

var (
	// ErrInvalid is the error Parse wraps when it refuses a token.
	ErrInvalid = errors.New("jws: token refused")
	// ErrNoKey is the error Verify returns when no key of the set fits the
	// token and verifies its signature: a miss, which a fresher set may fix.
	ErrNoKey = errors.New("jws: no key verifies the token")
)

// Token is a parsed compact JWS whose header passed every check.
type Token struct {
	signingInput string
	kid          string
	payload      []byte
	signature    []byte
	alg          jwk.Alg
	hasKID       bool
}

// Parse checks a compact JWS's size, shape, encoding and header, and that
// its alg names one of the allowed rows, before any key is chosen. Every
// refusal wraps ErrInvalid.
func Parse(token string, allowed []jwk.Alg) (*Token, error) {
	if len(token) > MaxSize {
		return nil, fmt.Errorf("%w: over %d bytes", ErrInvalid, MaxSize)
	}
	first, second, ok := separators(token)
	if !ok {
		return nil, fmt.Errorf("%w: not three base64url parts", ErrInvalid)
	}
	header, err := decode(token[:first])
	if err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrInvalid, err)
	}
	t := &Token{signingInput: token[:second]}
	if t.payload, err = decode(token[first+1 : second]); err != nil {
		return nil, fmt.Errorf("%w: payload: %w", ErrInvalid, err)
	}
	if t.signature, err = decode(token[second+1:]); err != nil {
		return nil, fmt.Errorf("%w: signature: %w", ErrInvalid, err)
	}
	if err := t.readHeader(header); err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrInvalid, err)
	}
	// RFC 8725 §3.1: the alg is held to the provider's rows before any key
	// is chosen, so no key can widen them (PyJWT CVE-2026-48523).
	if !slices.Contains(allowed, t.alg) {
		return nil, fmt.Errorf("%w: alg %s is not among the provider's", ErrInvalid, t.alg)
	}
	return t, nil
}

// separators finds the compact form's two '.' in one scan that refuses
// every byte outside base64url's alphabet (RFC 7515 §2, §7.1), never
// splitting, so a token of periods costs nothing per period (go-jose
// CVE-2025-27144, golang-jwt CVE-2025-30204).
func separators(token string) (first, second int, ok bool) {
	first, second = -1, -1
	for i := range len(token) {
		switch c := token[i]; {
		case c == '.' && first < 0:
			first = i
		case c == '.' && second < 0:
			second = i
		case c == '.':
			return 0, 0, false
		case !base64URL(c):
			return 0, 0, false
		}
	}
	return first, second, second >= 0
}

func base64URL(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

// decode is base64url without padding and with zero trailing bits (RFC
// 4648 §3.5), so each byte string has one encoding (PyJWT CVE-2026-102269).
func decode(part string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(part)
}

// readHeader applies RFC 7515 §4.1 to the header. jku, jwk, x5u and x5c
// are never read: a key never comes from the token (RFC 8725 §3.10).
func (t *Token) readHeader(header []byte) error {
	m, err := jsonmember.Object(header)
	if err != nil {
		return err
	}
	name, ok := jsonmember.String(m, "alg")
	if !ok {
		return errors.New("alg is not a string")
	}
	if t.alg, ok = jwk.ParseAlg(name); !ok {
		return errors.New("alg is not accepted")
	}
	if _, found := m["kid"]; found {
		if t.kid, t.hasKID = jsonmember.String(m, "kid"); !t.hasKID {
			return errors.New("kid is not a string")
		}
	}
	// RFC 7515 §4.1.11: no extension is understood, so crit in any form,
	// [] included, which producers must not send (RFC 7797's b64 too).
	if _, found := m["crit"]; found {
		return errors.New("crit is present")
	}
	if _, found := m["typ"]; found {
		// RFC 7515 §4.1.9 and RFC 7519 §5.1: a media type, compared
		// case-insensitively, whose "application/" prefix may be omitted.
		typ, _ := jsonmember.String(m, "typ")
		if !strings.EqualFold(typ, "JWT") && !strings.EqualFold(typ, "application/jwt") {
			return errors.New("typ is not JWT")
		}
	}
	return nil
}
