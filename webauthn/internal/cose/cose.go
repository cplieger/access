// Package cose reads a WebAuthn credential public key, a COSE_Key
// (RFC 9052 §7), for the algorithms access offers, and verifies an assertion
// or self attestation signature under it. Each algorithm has one exact label
// set (WebAuthn §6.5.1: alg is required and no other optional parameter is
// allowed), so a key carrying a private member or any extra label is refused.
package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/cplieger/access/webauthn/internal/cbor"
)

// The refusals, matched with errors.Is.
var (
	ErrUnsupported = errors.New("cose: algorithm or curve not offered")
	ErrMalformed   = errors.New("cose: malformed credential public key")
	ErrSignature   = errors.New("cose: signature does not verify")
)

// COSE_Key common and key-type labels (RFC 9052 §7.1, RFC 9053 §7,
// RFC 8230 §4, RFC 9964 §3).
const (
	labelKty = 1
	labelAlg = 3
	labelCrv = -1 // EC2 and OKP
	labelX   = -2 // EC2 and OKP
	labelY   = -3 // EC2
	labelN   = -1 // RSA
	labelE   = -2 // RSA
	labelPub = -1 // AKP
)

// Key types (RFC 9053 §7, RFC 8230 §4, RFC 9964 §3).
const (
	ktyOKP = 1
	ktyEC2 = 2
	ktyRSA = 3
	ktyAKP = 7
)

// RSA bounds: 4096 bits caps what an unauthenticated sign-in costs to verify,
// and an exponent of at least 3 blocks the e = 1 PKCS #1 v1.5 forgery.
const (
	rsaMinBits = 2048
	rsaMaxBits = 4096
	rsaMinE    = 3
	rsaMaxE    = 1<<31 - 1
)

type family struct {
	parse  func(labels) (crypto.PublicKey, error)
	alg    int
	kty    int64
	others int // labels besides kty and alg
}

// families is the offer order of pubKeyCredParams (WebAuthn §5.4) and the
// only algorithms ParseKey accepts, so the two cannot drift apart.
var families = []family{
	{alg: -48, kty: ktyAKP, others: 1, parse: akp(mldsa.MLDSA44())}, // RFC 9964 §5
	{alg: -49, kty: ktyAKP, others: 1, parse: akp(mldsa.MLDSA65())},
	{alg: -50, kty: ktyAKP, others: 1, parse: akp(mldsa.MLDSA87())},
	{alg: -8, kty: ktyOKP, others: 2, parse: parseOKP},   // EdDSA (Ed25519), RFC 9053 §2.2
	{alg: -7, kty: ktyEC2, others: 3, parse: parseEC2},   // ES256, RFC 9053 §2.1
	{alg: -257, kty: ktyRSA, others: 2, parse: parseRSA}, // RS256, RFC 8812 §2
}

// Offered returns the COSE algorithm identifiers access offers, in its
// preference order.
func Offered() []int {
	out := make([]int, len(families))
	for i, f := range families {
		out[i] = f.alg
	}
	return out
}

// Key is a parsed credential public key; the zero Key verifies nothing.
type Key struct {
	pub crypto.PublicKey
	alg int
}

// Algorithm returns the key's COSE algorithm identifier.
func (k *Key) Algorithm() int { return k.alg }

type labels map[int64]cbor.Value

// ParseKey reads raw as exactly one COSE_Key with no byte after it, and the
// key keeps no reference to raw. An algorithm or curve access does not offer
// is ErrUnsupported; any other refusal is ErrMalformed.
func ParseKey(raw []byte) (*Key, error) {
	v, rest, err := cbor.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after the key", ErrMalformed, len(rest))
	}
	l, err := readLabels(v)
	if err != nil {
		return nil, err
	}
	alg, err := l.int(labelAlg)
	if err != nil {
		return nil, err
	}
	f, ok := lookup(alg)
	if !ok {
		return nil, fmt.Errorf("%w: alg %d", ErrUnsupported, alg)
	}
	kty, err := l.int(labelKty)
	if err != nil {
		return nil, err
	}
	if kty != f.kty {
		return nil, fmt.Errorf("%w: kty %d for alg %d", ErrMalformed, kty, alg)
	}
	pub, err := f.parse(l)
	if err != nil {
		return nil, err
	}
	// Every label parse read is present and keys are unique, so a larger map
	// holds a label outside the set.
	if len(l) != 2+f.others {
		return nil, fmt.Errorf("%w: a label outside alg %d's set", ErrMalformed, alg)
	}
	return &Key{pub: pub, alg: f.alg}, nil
}

func readLabels(v cbor.Value) (labels, error) {
	entries, ok := v.Map()
	if !ok {
		return nil, fmt.Errorf("%w: not a CBOR map", ErrMalformed)
	}
	l := labels{}
	for key, val := range entries {
		label, isInt := key.Int()
		if !isInt {
			return nil, fmt.Errorf("%w: a text label", ErrMalformed)
		}
		l[label] = val
	}
	return l, nil
}

func lookup(alg int64) (family, bool) {
	for _, f := range families {
		if int64(f.alg) == alg {
			return f, true
		}
	}
	return family{}, false
}

func (l labels) int(label int64) (int64, error) {
	v, ok := l[label]
	if !ok {
		return 0, fmt.Errorf("%w: label %d missing", ErrMalformed, label)
	}
	i, ok := v.Int()
	if !ok {
		return 0, fmt.Errorf("%w: label %d is not an integer", ErrMalformed, label)
	}
	return i, nil
}

func (l labels) bytes(label int64) ([]byte, error) {
	v, ok := l[label]
	if !ok {
		return nil, fmt.Errorf("%w: label %d missing", ErrMalformed, label)
	}
	b, ok := v.Bytes()
	if !ok {
		return nil, fmt.Errorf("%w: label %d is not a byte string", ErrMalformed, label)
	}
	return b, nil
}

func (l labels) curve(want int64) error {
	crv, err := l.int(labelCrv)
	if err != nil {
		return err
	}
	if crv != want {
		return fmt.Errorf("%w: crv %d", ErrUnsupported, crv)
	}
	return nil
}

func akp(params mldsa.Parameters) func(labels) (crypto.PublicKey, error) {
	return func(l labels) (crypto.PublicKey, error) {
		pub, err := l.bytes(labelPub)
		if err != nil {
			return nil, err
		}
		// NewPublicKey refuses any length but the parameter set's (FIPS 204 §4).
		k, err := mldsa.NewPublicKey(params, pub)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
		}
		return k, nil
	}
}

func parseOKP(l labels) (crypto.PublicKey, error) {
	if err := l.curve(6); err != nil { // Ed25519, RFC 9053 §7.2
		return nil, err
	}
	x, err := l.bytes(labelX)
	if err != nil {
		return nil, err
	}
	// ed25519.Verify panics on a public key of any other length.
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 x of %d bytes", ErrMalformed, len(x))
	}
	return ed25519.PublicKey(bytes.Clone(x)), nil
}

func parseEC2(l labels) (crypto.PublicKey, error) {
	if err := l.curve(1); err != nil { // P-256, RFC 9053 §7.1
		return nil, err
	}
	x, err := l.bytes(labelX)
	if err != nil {
		return nil, err
	}
	// A boolean y (RFC 9053 §7.1.1's point compression) is refused here as the
	// wrong type.
	y, err := l.bytes(labelY)
	if err != nil {
		return nil, err
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("%w: P-256 coordinates of %d and %d bytes", ErrMalformed, len(x), len(y))
	}
	point := make([]byte, 0, 65)
	point = append(point, 4)
	point = append(point, x...)
	point = append(point, y...)
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return k, nil
}

func parseRSA(l labels) (crypto.PublicKey, error) {
	nb, err := l.bytes(labelN)
	if err != nil {
		return nil, err
	}
	eb, err := l.bytes(labelE)
	if err != nil {
		return nil, err
	}
	// RFC 8230 §4 forbids leading zero bytes, but a number has one reading
	// with or without them, so n and e are read as the integers they encode.
	n := new(big.Int).SetBytes(nb)
	if n.BitLen() < rsaMinBits || n.BitLen() > rsaMaxBits || n.Bit(0) == 0 {
		return nil, fmt.Errorf("%w: RSA modulus of %d bits", ErrMalformed, n.BitLen())
	}
	eb = bytes.TrimLeft(eb, "\x00")
	if len(eb) > 4 {
		return nil, fmt.Errorf("%w: RSA exponent of %d bytes", ErrMalformed, len(eb))
	}
	var e int64
	for _, b := range eb {
		e = e<<8 | int64(b)
	}
	if e < rsaMinE || e > rsaMaxE || e%2 == 0 {
		return nil, fmt.Errorf("%w: RSA exponent %d", ErrMalformed, e)
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

// Verify checks sig over authData ‖ clientDataHash, the message both an
// assertion (WebAuthn §7.2) and a self attestation (§8.2) sign, where
// clientDataHash is SHA-256 of the raw clientDataJSON. It returns nil or an
// error matching ErrSignature.
func (k *Key) Verify(authData []byte, clientDataHash [sha256.Size]byte, sig []byte) error {
	m := make([]byte, 0, len(authData)+sha256.Size)
	m = append(m, authData...)
	m = append(m, clientDataHash[:]...)
	switch pub := k.pub.(type) {
	case *mldsa.PublicKey:
		// Pure ML-DSA with the empty context, RFC 9964 §5; nil options are
		// the empty context.
		if err := mldsa.Verify(pub, m, sig, nil); err != nil {
			return fmt.Errorf("%w: %w", ErrSignature, err)
		}
	case ed25519.PublicKey:
		// Verify refuses a signature that is not 64 bytes (RFC 8032 §5.1.7).
		if !ed25519.Verify(pub, m, sig) {
			return ErrSignature
		}
	case *ecdsa.PublicKey:
		// VerifyASN1 takes the digest; handed m it would read m's leftmost 32
		// bytes, the rpIdHash.
		d := sha256.Sum256(m)
		if !ecdsa.VerifyASN1(pub, d[:], sig) {
			return ErrSignature
		}
	case *rsa.PublicKey:
		d := sha256.Sum256(m)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig); err != nil {
			return fmt.Errorf("%w: %w", ErrSignature, err)
		}
	default:
		return fmt.Errorf("%w: no key", ErrSignature)
	}
	return nil
}
