package jwk_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"testing"
	"unicode/utf8"

	"github.com/cplieger/access/oidc/internal/jwk"
)

var allAlgs = []jwk.Alg{jwk.RS256, jwk.RS384, jwk.RS512, jwk.PS256, jwk.PS384, jwk.PS512, jwk.ES256, jwk.ES384, jwk.ES512, jwk.EdDSA}

func fuzzSeeds(f *testing.F) {
	rsaKey := rsaJWK("rsa", oddWithBits(2048), 65537)
	var ecKeys []any
	for _, c := range ecCurves {
		p := c.curve.Params()
		x, y := make([]byte, c.size), make([]byte, c.size)
		p.Gx.FillBytes(x)
		p.Gy.FillBytes(y)
		ecKeys = append(ecKeys, map[string]any{"kty": "EC", "crv": c.crv, "x": b64(x), "y": b64(y), "use": "sig"})
	}
	okp := okpJWK("okp", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	f.Add(jwkSet(f, append([]any{rsaKey, okp}, ecKeys...)...))
	f.Add(jwkSet(f, with(rsaKey, "alg", "PS256", "key_ops", []string{"verify"})))
	f.Add(jwkSet(f, with(rsaKey, "d", "AQAB")))
	f.Add(jwkSet(f, map[string]any{"kty": "oct", "k": "c2VjcmV0"}, with(okp, "alg", "Ed25519")))
	f.Add(jwkSet(f, with(okp, "x", b64(smallOrderEncodings(f)[0]))))
	f.Add([]byte(`{"keys":[{"kty":"RSA","kty":"EC"}]}`))
	f.Add([]byte(`{"keys":[null]}`))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"","y":""}]}`))
	f.Add([]byte(`null`))
}

// go-jose CVE-2026-116586 and Nimbus CVE-2019-17195: any input either
// refuses the set with ErrSet or yields keys that each satisfy their row
// (RFC 7518 §6, RFC 8037 §2); it never panics.
func FuzzParseSet(f *testing.F) {
	fuzzSeeds(f)
	small := smallOrderEncodings(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := jwk.Parse(data)
		if err != nil {
			if !errors.Is(err, jwk.ErrSet) {
				t.Fatalf("Parse error %v does not wrap ErrSet", err)
			}
			return
		}
		if !jsontext.Value(data).IsValid() {
			t.Fatalf("Parse accepted JSON jsontext calls invalid: %q", data)
		}
		if s.Len() > jwk.MaxKeys {
			t.Fatalf("Len = %d; over MaxKeys", s.Len())
		}
		again, err := jwk.Parse(data)
		if err != nil || again.Len() != s.Len() {
			t.Fatalf("second Parse = %d, %v; first gave %d", again.Len(), err, s.Len())
		}
		for k := range s.All() {
			checkKey(t, k, small)
		}
	})
}

func checkKey(t *testing.T, k jwk.Key, small [][]byte) {
	t.Helper()
	if id, _ := k.KeyID(); !utf8.ValidString(id) {
		t.Fatalf("kid %q is not UTF-8", id)
	}
	fits := slices.DeleteFunc(slices.Clone(allAlgs), func(a jwk.Alg) bool { return !k.Fits(a) })
	if len(fits) == 0 {
		t.Fatal("a usable key fits no row")
	}
	if a := k.Alg(); a != 0 && !slices.Equal(fits, []jwk.Alg{a}) {
		t.Fatalf("key with alg %v fits %v", a, fits)
	}
	for _, a := range fits {
		checkKeyForRow(t, k, a, small)
	}
}

func checkKeyForRow(t *testing.T, k jwk.Key, a jwk.Alg, small [][]byte) {
	t.Helper()
	switch a.Scheme() {
	case jwk.PKCS1v15, jwk.PSS:
		pub, ok := k.Public().(*rsa.PublicKey)
		if !ok || pub.N.BitLen() < 2048 || pub.N.BitLen() > 4096 || pub.E < 3 || pub.E%2 == 0 || pub.E > 1<<31-1 {
			t.Fatalf("row %v holds %T %v", a, k.Public(), k.Public())
		}
	case jwk.ECDSA:
		pub, ok := k.Public().(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("row %v holds %T", a, k.Public())
		}
		want := map[jwk.Alg]elliptic.Curve{jwk.ES256: elliptic.P256(), jwk.ES384: elliptic.P384(), jwk.ES512: elliptic.P521()}[a]
		if pub.Curve != want {
			t.Fatalf("row %v holds a key on %s", a, pub.Curve.Params().Name)
		}
		if _, err := pub.ECDH(); err != nil {
			t.Fatalf("row %v holds an invalid point: %v", a, err)
		}
	case jwk.Ed25519:
		pub, ok := k.Public().(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize || slices.ContainsFunc(small, func(s []byte) bool { return bytes.Equal(s, pub) }) {
			t.Fatalf("row %v holds %T %x", a, k.Public(), k.Public())
		}
	default:
		t.Fatalf("row %v has no scheme", a)
	}
}
