package jws_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"maps"
	"math/big"
	"runtime"
	"sync"
	"testing"

	"github.com/cplieger/access/oidc/internal/jwk"
	"github.com/cplieger/access/oidc/internal/jws"
)

var allAlgs = []jwk.Alg{jwk.RS256, jwk.RS384, jwk.RS512, jwk.PS256, jwk.PS384, jwk.PS512, jwk.ES256, jwk.ES384, jwk.ES512, jwk.EdDSA}

func b64(b []byte) string  { return base64.RawURLEncoding.EncodeToString(b) }
func b64s(s string) string { return b64([]byte(s)) }

// testKey is a private key and the public JWK it publishes.
type testKey struct {
	priv any
	jwk  map[string]any
}

func (k testKey) without(names ...string) testKey {
	out := testKey{priv: k.priv, jwk: maps.Clone(k.jwk)}
	for _, n := range names {
		delete(out.jwk, n)
	}
	return out
}

func (k testKey) with(kv ...any) testKey {
	out := testKey{priv: k.priv, jwk: maps.Clone(k.jwk)}
	for i := 0; i < len(kv); i += 2 {
		out.jwk[kv[i].(string)] = kv[i+1]
	}
	return out
}

func rsaTestKey(kid string) testKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return rsaFromPriv(kid, priv)
}

func rsaFromPriv(kid string, priv *rsa.PrivateKey) testKey {
	return testKey{priv: priv, jwk: map[string]any{
		"kty": "RSA", "kid": kid, "n": b64(priv.N.Bytes()), "e": b64(big.NewInt(int64(priv.E)).Bytes()),
	}}
}

var curves = map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}

func ecTestKey(t testing.TB, kid, crv string) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curves[crv], rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	return ecFromPriv(t, kid, crv, priv)
}

// ecFromPriv writes x and y from the uncompressed point 0x04 ‖ x ‖ y (SEC 1 §2.3.3).
func ecFromPriv(t testing.TB, kid, crv string, priv *ecdsa.PrivateKey) testKey {
	t.Helper()
	pt, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("ec point: %v", err)
	}
	size := (len(pt) - 1) / 2
	return testKey{priv: priv, jwk: map[string]any{
		"kty": "EC", "kid": kid, "crv": crv, "x": b64(pt[1 : 1+size]), "y": b64(pt[1+size:]),
	}}
}

func edTestKey(t testing.TB, kid string) testKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	return edFromPriv(kid, priv)
}

func edFromPriv(kid string, priv ed25519.PrivateKey) testKey {
	return testKey{priv: priv, jwk: map[string]any{
		"kty": "OKP", "kid": kid, "crv": "Ed25519", "x": b64(priv.Public().(ed25519.PublicKey)),
	}}
}

// Generating 2048-bit RSA keys is slow, so the tests share these.
var (
	rsaA = sync.OnceValue(func() testKey { return rsaTestKey("rsa-a") })
	rsaB = sync.OnceValue(func() testKey { return rsaTestKey("rsa-b") })
)

func hashOf(a jwk.Alg, input string) []byte {
	h := a.Hash().New()
	h.Write([]byte(input))
	return h.Sum(nil)
}

// sign signs input under alg's scheme (RFC 7518 §3.3 to §3.5, RFC 8037
// §3.1), an ES signature as the fixed-size R ‖ S of RFC 7518 §3.4.
func sign(t testing.TB, algName string, k testKey, input string) []byte {
	t.Helper()
	a, ok := jwk.ParseAlg(algName)
	if !ok {
		t.Fatalf("sign: %q is no row", algName)
	}
	switch a.Scheme() {
	case jwk.PKCS1v15:
		sig, err := rsa.SignPKCS1v15(nil, k.priv.(*rsa.PrivateKey), a.Hash(), hashOf(a, input))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return sig
	case jwk.PSS:
		return signPSS(t, a, k, input, rsa.PSSSaltLengthEqualsHash)
	case jwk.ECDSA:
		r, s, err := ecdsa.Sign(rand.Reader, k.priv.(*ecdsa.PrivateKey), hashOf(a, input))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return rs(a.SignatureSize(), r, s)
	case jwk.Ed25519:
		return ed25519.Sign(k.priv.(ed25519.PrivateKey), []byte(input))
	}
	t.Fatalf("sign: no scheme for %s", algName)
	return nil
}

func signPSS(t testing.TB, a jwk.Alg, k testKey, input string, salt int) []byte {
	t.Helper()
	sig, err := rsa.SignPSS(rand.Reader, k.priv.(*rsa.PrivateKey), a.Hash(), hashOf(a, input), &rsa.PSSOptions{SaltLength: salt})
	if err != nil {
		t.Fatalf("sign pss: %v", err)
	}
	return sig
}

func rs(size int, r, s *big.Int) []byte {
	out := make([]byte, size)
	r.FillBytes(out[:size/2])
	s.FillBytes(out[size/2:])
	return out
}

// mint is BASE64URL(header) '.' BASE64URL(payload) '.' BASE64URL(sig)
// (RFC 7515 §7.1), signed by k under the header's alg name.
func mint(t testing.TB, algName string, k testKey, header, payload string) string {
	t.Helper()
	input := b64s(header) + "." + b64s(payload)
	return input + "." + b64(sign(t, algName, k, input))
}

// mintHeader marshals header and mints the token under its alg.
func mintHeader(t testing.TB, k testKey, header map[string]any, payload string) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	return mint(t, header["alg"].(string), k, string(h), payload)
}

func set(t testing.TB, keys ...testKey) jwk.Set {
	t.Helper()
	jwks := make([]map[string]any, len(keys))
	for i, k := range keys {
		jwks[i] = k.jwk
	}
	data, err := json.Marshal(map[string]any{"keys": jwks})
	if err != nil {
		t.Fatalf("marshal set: %v", err)
	}
	s, err := jwk.Parse(data)
	if err != nil {
		t.Fatalf("jwk.Parse: %v", err)
	}
	if s.Len() != len(keys) {
		t.Fatalf("jwk.Parse kept %d of %d keys", s.Len(), len(keys))
	}
	return s
}

func verify(token string, allowed []jwk.Alg, keys jwk.Set) ([]byte, error) {
	tok, err := jws.Parse(token, allowed)
	if err != nil {
		return nil, err
	}
	return tok.Verify(keys)
}

func wantPayload(t *testing.T, token string, allowed []jwk.Alg, keys jwk.Set, want string) {
	t.Helper()
	got, err := verify(token, allowed, keys)
	if err != nil {
		t.Fatalf("verify: %v; want payload %q", err, want)
	}
	if string(got) != want {
		t.Fatalf("payload = %q; want %q", got, want)
	}
}

// wantErr asserts the token is refused with target, ErrInvalid (refused
// before any key is chosen) or ErrNoKey (no key verifies), and not the other.
func wantErr(t *testing.T, token string, allowed []jwk.Alg, keys jwk.Set, target error) {
	t.Helper()
	got, err := verify(token, allowed, keys)
	if !errors.Is(err, target) {
		t.Fatalf("verify = %q, %v; want %v", got, err, target)
	}
	other := jws.ErrNoKey
	if target == jws.ErrNoKey {
		other = jws.ErrInvalid
	}
	if errors.Is(err, other) {
		t.Fatalf("verify error %v also wraps %v", err, other)
	}
	if got != nil {
		t.Fatalf("verify returned payload %q with its error", got)
	}
}

// allocBytes is the mean heap bytes one call of f allocates; the caller
// runs serially, so no other test allocates meanwhile.
func allocBytes(runs int, f func()) uint64 {
	var before, after runtime.MemStats
	f()
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / uint64(runs)
}
