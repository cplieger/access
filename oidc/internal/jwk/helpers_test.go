package jwk_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	json "encoding/json/v2"
	"maps"
	"math/big"
	"slices"
	"testing"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwkSet marshals {"keys": keys}.
func jwkSet(t testing.TB, keys ...any) []byte {
	t.Helper()
	out, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatalf("marshal set: %v", err)
	}
	return out
}

func with(m map[string]any, kv ...any) map[string]any {
	out := maps.Clone(m)
	for i := 0; i < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

func without(m map[string]any, names ...string) map[string]any {
	out := maps.Clone(m)
	for _, n := range names {
		delete(out, n)
	}
	return out
}

// oddWithBits is 2^(bits-1) + 1: an odd modulus of exactly bits bits. The
// parser reads only n's size, so it needs no factorable modulus.
func oddWithBits(bits int) *big.Int {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return n.Add(n, big.NewInt(1))
}

func rsaJWK(kid string, n *big.Int, e int64) map[string]any {
	return map[string]any{"kty": "RSA", "kid": kid, "n": b64(n.Bytes()), "e": b64(big.NewInt(e).Bytes())}
}

type ecCase struct {
	curve elliptic.Curve
	crv   string
	size  int
}

var ecCurves = []ecCase{
	{elliptic.P256(), "P-256", 32},
	{elliptic.P384(), "P-384", 48},
	{elliptic.P521(), "P-521", 66},
}

func newEC(t testing.TB, c elliptic.Curve) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	return &k.PublicKey
}

// ecJWK writes x and y from the uncompressed point 0x04 ‖ x ‖ y (SEC 1 §2.3.3).
func ecJWK(t testing.TB, kid, crv string, pub *ecdsa.PublicKey) map[string]any {
	t.Helper()
	pt, err := pub.Bytes()
	if err != nil {
		t.Fatalf("ec point: %v", err)
	}
	size := (len(pt) - 1) / 2
	return map[string]any{"kty": "EC", "kid": kid, "crv": crv, "x": b64(pt[1 : 1+size]), "y": b64(pt[1+size:])}
}

func newEd25519(t testing.TB) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	return pub
}

func okpJWK(kid string, pub ed25519.PublicKey) map[string]any {
	return map[string]any{"kty": "OKP", "kid": kid, "crv": "Ed25519", "x": b64(pub)}
}

// smallOrderEncodings derives, from the edwards25519 curve of RFC 8032
// §5.1 (-x² + y² = 1 + d·x²·y² over p = 2^255 − 19), every 32-byte encoding
// of its eight points of order dividing 8: the canonical one, the one with
// the sign bit set when x is 0, and y + p where that still fits in 255 bits
// (RFC 8032 §5.1.3 decoding, which Go accepts for public keys). The
// identity's canonical encoding comes first.
func smallOrderEncodings(t testing.TB) [][]byte {
	t.Helper()
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	mod := func(v *big.Int) *big.Int { return v.Mod(v, p) }
	inv := func(v *big.Int) *big.Int { return new(big.Int).ModInverse(v, p) }
	neg := func(v *big.Int) *big.Int { return mod(new(big.Int).Neg(v)) }
	sqrt := func(v *big.Int) *big.Int { return new(big.Int).ModSqrt(mod(new(big.Int).Set(v)), p) }
	mul := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }
	d := mul(big.NewInt(-121665), inv(big.NewInt(121666)))
	one := big.NewInt(1)

	type point struct{ x, y *big.Int }
	pts := []point{{big.NewInt(0), big.NewInt(1)}, {big.NewInt(0), neg(one)}}
	i := sqrt(neg(one))
	pts = append(pts, point{i, big.NewInt(0)}, point{neg(i), big.NewInt(0)})
	// Order 8: 2P is (±i, 0), so x² = −y² and the curve gives d·y⁴ + 2y² − 1 = 0.
	s := sqrt(new(big.Int).Add(one, d))
	for _, r := range []*big.Int{s, neg(s)} {
		y2 := mul(new(big.Int).Sub(r, one), inv(d))
		y, x := sqrt(y2), sqrt(neg(y2))
		if y == nil || x == nil {
			continue
		}
		for _, py := range []*big.Int{y, neg(y)} {
			for _, px := range []*big.Int{x, neg(x)} {
				pts = append(pts, point{px, py})
			}
		}
	}
	if len(pts) != 8 {
		t.Fatalf("derived %d small-order points; want 8", len(pts))
	}
	for _, pt := range pts {
		x2, y2 := mul(pt.x, pt.x), mul(pt.y, pt.y)
		lhs := mod(new(big.Int).Sub(y2, x2))
		rhs := mod(new(big.Int).Add(one, mul(d, mul(x2, y2))))
		if lhs.Cmp(rhs) != 0 {
			t.Fatalf("(%v, %v) is not on edwards25519", pt.x, pt.y)
		}
	}
	encode := func(y *big.Int, sign uint) []byte {
		b := make([]byte, 32)
		y.FillBytes(b)
		slices.Reverse(b)
		b[31] |= byte(sign << 7)
		return b
	}
	limit := new(big.Int).Lsh(one, 255)
	var out [][]byte
	add := func(b []byte) {
		if !slices.ContainsFunc(out, func(o []byte) bool { return bytes.Equal(o, b) }) {
			out = append(out, b)
		}
	}
	for _, pt := range pts {
		sign := pt.x.Bit(0)
		add(encode(pt.y, sign))
		if pt.x.Sign() == 0 {
			add(encode(pt.y, 1))
		}
		if alt := new(big.Int).Add(pt.y, p); alt.Cmp(limit) < 0 {
			add(encode(alt, sign))
			if pt.x.Sign() == 0 {
				add(encode(alt, 1))
			}
		}
	}
	return out
}

// rocaModulus builds n = p·q from primes of the form RSALib generated, k·M
// + (65537^a mod M) with M the product of the primes up to 167 (Nemec et
// al., "The Return of Coppersmith's Attack", CCS 2017, §2.2). Each prime
// lies in [√2·2^(bits/2−1), 2^(bits/2)), so n has exactly bits bits.
func rocaModulus(t testing.TB, bits int) *big.Int {
	t.Helper()
	m := big.NewInt(1)
	for p := int64(2); p <= 167; p++ {
		if big.NewInt(p).ProbablyPrime(0) {
			m.Mul(m, big.NewInt(p))
		}
	}
	lo := new(big.Int).Sqrt(new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
	hi := new(big.Int).Lsh(big.NewInt(1), uint(bits/2))
	kLo := new(big.Int).Div(lo, m)
	kSpan := new(big.Int).Div(new(big.Int).Sub(hi, lo), m)
	prime := func() *big.Int {
		for range 1 << 16 {
			a, err := rand.Int(rand.Reader, m)
			if err != nil {
				t.Fatal(err)
			}
			k, err := rand.Int(rand.Reader, kSpan)
			if err != nil {
				t.Fatal(err)
			}
			p := new(big.Int).Mul(k.Add(k, kLo), m)
			p.Add(p, new(big.Int).Exp(big.NewInt(65537), a, m))
			if p.Cmp(lo) >= 0 && p.Cmp(hi) < 0 && p.ProbablyPrime(20) {
				return p
			}
		}
		t.Fatal("no RSALib-form prime found")
		return nil
	}
	n := new(big.Int).Mul(prime(), prime())
	if n.BitLen() != bits {
		t.Fatalf("RSALib-form modulus of %d bits; want %d", n.BitLen(), bits)
	}
	return n
}
