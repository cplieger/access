// Package jwk parses a JWK Set (RFC 7517) into the public keys oidc
// verifies ID tokens with: RSA, EC on P-256, P-384 and P-521, and OKP
// Ed25519 (RFC 7518 §6, RFC 8037 §2).
package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"iter"
	"math/big"
	"slices"
	"strings"

	"github.com/cplieger/access/oidc/internal/jsonmember"
)

// MaxKeys is the most keys a JWK Set may hold before Parse refuses it.
const MaxKeys = 100

// RSA moduli outside these bounds are skipped: 2048 is RFC 7518 §3.3's
// floor, and 4096 bounds the CPU a verify costs (go-jose CVE-2026-116587).
const (
	minRSABits = 2048
	maxRSABits = 4096
)

// ErrSet is the error Parse wraps when it refuses a whole JWK Set.
var ErrSet = errors.New("jwk: JWK Set refused")

// privateMembers are the private parameters of RSA (RFC 7518 §6.3.2), EC
// (§6.2.2) and OKP (RFC 8037 §2) keys, k (§6.4.1) and priv, which
// draft-ietf-cose-dilithium's AKP keys use.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"}

type family uint8

const (
	familyNone family = iota
	familyRSA
	familyP256
	familyP384
	familyP521
	familyEd25519
)

func (f family) coordSize() int {
	switch f {
	case familyP256:
		return 32
	case familyP384:
		return 48
	case familyP521:
		return 66
	default:
		return 0
	}
}

// Key is one usable verification key.
type Key struct {
	pub    crypto.PublicKey
	kid    string
	hasKID bool
	alg    Alg
	family family
}

// KeyID is the key's kid, and whether it has one.
func (k Key) KeyID() (string, bool) { return k.kid, k.hasKID }

// Public is the key: *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey.
func (k Key) Public() crypto.PublicKey { return k.pub }

// Fits reports whether the key may verify under row a: its type and curve
// are a's, and its own alg, when present, names a (RFC 8725 §3.1).
func (k Key) Fits(a Alg) bool {
	return a.row().family == k.family && (k.alg == 0 || k.alg == a)
}

// Set is the usable keys of a JWK Set, in the set's order.
type Set struct {
	keys []Key
}

// Parse classifies every JWK of a JWK Set. It refuses the whole set, with
// ErrSet, when the document is not one, holds more than MaxKeys keys or an
// entry that is not an object, or publishes a private RSA, EC or OKP key;
// it skips any other key it cannot use (RFC 7517 §5), so the Set may be
// empty.
func Parse(data []byte) (Set, error) {
	doc, err := jsonmember.Object(data)
	if err != nil {
		return Set{}, fmt.Errorf("%w: %w", ErrSet, err)
	}
	entries, ok := jsonmember.Array(doc["keys"])
	if !ok {
		return Set{}, fmt.Errorf("%w: keys is not an array", ErrSet)
	}
	if len(entries) > MaxKeys {
		return Set{}, fmt.Errorf("%w: %d keys, over %d", ErrSet, len(entries), MaxKeys)
	}
	var s Set
	for i, e := range entries {
		m, err := jsonmember.Object(e)
		if err != nil {
			return Set{}, fmt.Errorf("%w: keys[%d]: %w", ErrSet, i, err)
		}
		k, ok, err := classify(m)
		if err != nil {
			return Set{}, fmt.Errorf("%w: keys[%d]: %w", ErrSet, i, err)
		}
		if ok {
			s.keys = append(s.keys, k)
		}
	}
	return s, nil
}

// Len is the number of usable keys.
func (s Set) Len() int { return len(s.keys) }

// All yields the usable keys in the set's order.
func (s Set) All() iter.Seq[Key] { return slices.Values(s.keys) }

// classify reads one JWK: an error refuses the set, and ok false skips the
// key. The private-member check comes first, so it refuses the set
// whatever the key's crv, use or key_ops.
func classify(m map[string]jsontext.Value) (k Key, ok bool, err error) {
	kty, _ := jsonmember.String(m["kty"])
	if kty == "RSA" || kty == "EC" || kty == "OKP" {
		for _, name := range privateMembers {
			if _, found := m[name]; found {
				return Key{}, false, fmt.Errorf("a %s key publishes the private member %q", kty, name)
			}
		}
	}
	switch kty {
	case "RSA":
		k.pub, k.family, ok = rsaKey(m)
	case "EC":
		k.pub, k.family, ok = ecKey(m)
	case "OKP":
		k.pub, k.family, ok = okpKey(m)
	}
	if !ok || !restrictsNothing(m) {
		return Key{}, false, nil
	}
	k.kid, k.hasKID, k.alg, ok = identity(m, k.family)
	return k, ok, nil
}

// identity reads kid and alg, each optional; ok is false when either is
// present and malformed, or alg names a row of another key type.
func identity(m map[string]jsontext.Value, f family) (kid string, hasKID bool, alg Alg, ok bool) {
	if _, found := m["kid"]; found {
		if kid, hasKID = jsonmember.String(m["kid"]); !hasKID {
			return "", false, 0, false
		}
	}
	if _, found := m["alg"]; found {
		name, _ := jsonmember.String(m["alg"])
		if alg, ok = ParseAlg(name); !ok || alg.row().family != f {
			return "", false, 0, false
		}
	}
	return kid, hasKID, alg, true
}

// restrictsNothing reports whether use and key_ops, when present, allow
// verification (RFC 7517 §4.2, §4.3).
func restrictsNothing(m map[string]jsontext.Value) bool {
	if _, found := m["use"]; found {
		if use, _ := jsonmember.String(m["use"]); use != "sig" {
			return false
		}
	}
	if v, found := m["key_ops"]; found {
		ops, ok := jsonmember.Strings(v)
		return ok && slices.Contains(ops, "verify")
	}
	return true
}

func rsaKey(m map[string]jsontext.Value) (crypto.PublicKey, family, bool) {
	nb, okN := uintMember(m, "n")
	eb, okE := uintMember(m, "e")
	if !okN || !okE {
		return nil, familyNone, false
	}
	n, e := new(big.Int).SetBytes(nb), new(big.Int).SetBytes(eb)
	if n.BitLen() < minRSABits || n.BitLen() > maxRSABits {
		return nil, familyNone, false
	}
	if e.BitLen() > 31 || e.Int64() < 3 || e.Bit(0) == 0 || roca(n) {
		return nil, familyNone, false
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, familyRSA, true
}

// rocaPrimes are the primes the ROCA detector of Nemec et al. checks
// (https://github.com/crocs-muni/roca/blob/df6071d/roca/detect.py#L785).
var rocaPrimes = [...]uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167}

// roca reports whether n carries the fingerprint of Infineon RSALib's
// primes, n mod p in the subgroup 65537 generates for every prime p above;
// such a modulus factors by Coppersmith's method (CVE-2017-15361; Nemec et
// al., "The Return of Coppersmith's Attack", CCS 2017).
func roca(n *big.Int) bool {
	var p, r big.Int
	for _, prime := range rocaPrimes {
		if !generatedBy65537(r.Mod(n, p.SetUint64(prime)).Uint64(), prime) {
			return false
		}
	}
	return true
}

// generatedBy65537 reports whether r is a power of 65537 mod the prime p.
func generatedBy65537(r, p uint64) bool {
	g := uint64(1)
	for range p {
		if g == r {
			return true
		}
		g = g * 65537 % p
	}
	return false
}

func ecKey(m map[string]jsontext.Value) (crypto.PublicKey, family, bool) {
	crv, _ := jsonmember.String(m["crv"])
	var f family
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		f, curve = familyP256, elliptic.P256()
	case "P-384":
		f, curve = familyP384, elliptic.P384()
	case "P-521":
		f, curve = familyP521, elliptic.P521()
	default:
		return nil, familyNone, false
	}
	x, okX := uintMember(m, "x")
	y, okY := uintMember(m, "y")
	if !okX || !okY || len(x) != f.coordSize() || len(y) != f.coordSize() {
		return nil, familyNone, false
	}
	// SEC 1 §2.3.4: ParseUncompressedPublicKey refuses a point off the
	// curve or at infinity (Nimbus CVE-2017-12974).
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, slices.Concat([]byte{4}, x, y))
	if err != nil {
		return nil, familyNone, false
	}
	return pub, f, true
}

func okpKey(m map[string]jsontext.Value) (crypto.PublicKey, family, bool) {
	if crv, _ := jsonmember.String(m["crv"]); crv != "Ed25519" {
		return nil, familyNone, false
	}
	x, ok := uintMember(m, "x")
	if !ok || len(x) != ed25519.PublicKeySize || smallOrder(x) {
		return nil, familyNone, false
	}
	return ed25519.PublicKey(x), familyEd25519, true
}

var p25519 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// smallOrderY is y mod p of edwards25519's eight points of order dividing
// 8. A public key on one verifies a forged signature over any message under
// ed25519.Verify, which is cofactorless and never checks the key's order
// (RFC 8032 §5.1.7 leaves it to the caller); go-jose refuses the same keys
// (https://github.com/go-jose/go-jose/blob/v4.1.9/jwk.go#L966), as does libsodium.
var smallOrderY = func() []*big.Int {
	y8, _ := new(big.Int).SetString("2707385501144840649318225287225658788936804267575313519463743609750303402022", 10)
	return []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(p25519, big.NewInt(1)), y8, new(big.Int).Sub(p25519, y8)}
}()

// smallOrder reads x as RFC 8032 §5.1.3 does, the sign bit dropped and y
// reduced mod p, so a non-canonical encoding of a small-order point is
// caught too.
func smallOrder(x []byte) bool {
	le := slices.Clone(x)
	le[len(le)-1] &= 0x7f
	slices.Reverse(le)
	y := new(big.Int).Mod(new(big.Int).SetBytes(le), p25519)
	return slices.ContainsFunc(smallOrderY, func(s *big.Int) bool { return s.Cmp(y) == 0 })
}

// uintMember decodes a Base64urlUInt or a key's x (RFC 7518 §2): unpadded
// base64url with zero trailing bits (RFC 4648 §3.5). The alphabet scan
// comes first because base64's decoder skips CR and LF even when Strict.
func uintMember(m map[string]jsontext.Value, name string) ([]byte, bool) {
	s, ok := jsonmember.String(m[name])
	if !ok || strings.ContainsFunc(s, notBase64URL) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil
}

func notBase64URL(r rune) bool {
	return (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_'
}
