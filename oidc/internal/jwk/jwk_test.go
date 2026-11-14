package jwk_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/access/oidc/internal/jwk"
)

func mustParse(t *testing.T, data []byte) jwk.Set {
	t.Helper()
	s, err := jwk.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return s
}

func keyIDs(s jwk.Set) []string {
	var ids []string
	for k := range s.All() {
		id, _ := k.KeyID()
		ids = append(ids, id)
	}
	return ids
}

// RFC 7518 §3.1, RFC 8037 §3.1 and RFC 9864 §2.2: the accepted rows, each
// with the hash and scheme its section defines; an ES row's signature is
// R ‖ S at twice the curve's coordinate size (RFC 7518 §3.4).
func TestParseAlg_Rows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		want   jwk.Alg
		str    string
		hash   crypto.Hash
		scheme jwk.Scheme
		size   int
	}{
		{"RS256", jwk.RS256, "RS256", crypto.SHA256, jwk.PKCS1v15, 0},
		{"RS384", jwk.RS384, "RS384", crypto.SHA384, jwk.PKCS1v15, 0},
		{"RS512", jwk.RS512, "RS512", crypto.SHA512, jwk.PKCS1v15, 0},
		{"PS256", jwk.PS256, "PS256", crypto.SHA256, jwk.PSS, 0},
		{"PS384", jwk.PS384, "PS384", crypto.SHA384, jwk.PSS, 0},
		{"PS512", jwk.PS512, "PS512", crypto.SHA512, jwk.PSS, 0},
		{"ES256", jwk.ES256, "ES256", crypto.SHA256, jwk.ECDSA, 64},
		{"ES384", jwk.ES384, "ES384", crypto.SHA384, jwk.ECDSA, 96},
		{"ES512", jwk.ES512, "ES512", crypto.SHA512, jwk.ECDSA, 132},
		{"EdDSA", jwk.EdDSA, "EdDSA", 0, jwk.Ed25519, 0},
		{"Ed25519", jwk.EdDSA, "EdDSA", 0, jwk.Ed25519, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			a, ok := jwk.ParseAlg(c.name)
			if !ok || a != c.want {
				t.Fatalf("ParseAlg(%q) = %v, %v; want %v, true", c.name, a, ok, c.want)
			}
			if a.String() != c.str || a.Hash() != c.hash || a.Scheme() != c.scheme || a.SignatureSize() != c.size {
				t.Errorf("row %q = (%q, %v, %v, %d); want (%q, %v, %v, %d)", c.name, a.String(), a.Hash(), a.Scheme(), a.SignatureSize(), c.str, c.hash, c.scheme, c.size)
			}
		})
	}
}

// RFC 8725 §2.1 and §3.1, RFC 7518 §3.1: none, every HS* and any name
// outside the table name no row; JWS alg values are case-sensitive.
func TestParseAlg_Refused(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"none", "HS256", "HS384", "HS512", "RS1", "ES256K", "Ed448", "rs256", "EDDSA", "ed25519", "RS256 ", "", "RSA-OAEP", "A128KW"} {
		if a, ok := jwk.ParseAlg(name); ok || a != 0 {
			t.Errorf("ParseAlg(%q) = %v, %v; want no row", name, a, ok)
		}
	}
}

// RFC 7517 §4, §5; RFC 7518 §6.2.2, §6.3.2; RFC 8037 §2: a published
// private member on an RSA, EC or OKP key refuses the whole set, before
// any other row of the key table, whatever the key's crv, use or alg.
func TestParse_PrivateMemberRefusesSet(t *testing.T) {
	t.Parallel()
	bases := map[string]map[string]any{
		"RSA":    rsaJWK("rsa", oddWithBits(2048), 65537),
		"EC":     ecJWK(t, "ec", "P-256", newEC(t, ecCurves[0].curve)),
		"OKP":    okpJWK("okp", newEd25519(t)),
		"X25519": {"kty": "OKP", "crv": "X25519", "x": b64(make([]byte, 32)), "use": "enc"},
		"Ed448":  {"kty": "OKP", "crv": "Ed448", "x": b64(make([]byte, 57))},
	}
	for kind, base := range bases {
		for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"} {
			t.Run(kind+" "+member, func(t *testing.T) {
				t.Parallel()
				good := rsaJWK("good", oddWithBits(2048), 65537)
				_, err := jwk.Parse(jwkSet(t, good, with(base, member, b64([]byte("secret")))))
				if !errors.Is(err, jwk.ErrSet) {
					t.Errorf("Parse with %s on %s: err = %v; want ErrSet", member, kind, err)
				}
			})
		}
	}
	t.Run("null d", func(t *testing.T) {
		t.Parallel()
		_, err := jwk.Parse(jwkSet(t, with(bases["RSA"], "d", nil)))
		if !errors.Is(err, jwk.ErrSet) {
			t.Errorf("Parse with d null: err = %v; want ErrSet", err)
		}
	})
	t.Run("before alg", func(t *testing.T) {
		t.Parallel()
		_, err := jwk.Parse(jwkSet(t, with(bases["RSA"], "d", "AQAB", "alg", "HS256", "use", "enc", "key_ops", []string{"decrypt"})))
		if !errors.Is(err, jwk.ErrSet) {
			t.Errorf("Parse with d and alg HS256: err = %v; want ErrSet", err)
		}
	})
}

// RFC 7517 §5 and RFC 7518 §6.4: an oct key's k is its whole value, not a
// private member of a public key, so the key is skipped as an unknown type
// and the set stays usable; member names are case-sensitive (RFC 8259 §4),
// so "D" is no private member.
func TestParse_PrivateMemberRowScope(t *testing.T) {
	t.Parallel()
	good := rsaJWK("good", oddWithBits(2048), 65537)
	t.Run("oct k", func(t *testing.T) {
		t.Parallel()
		s := mustParse(t, jwkSet(t, map[string]any{"kty": "oct", "k": b64([]byte("client-secret"))}, good))
		if got := keyIDs(s); !slices.Equal(got, []string{"good"}) {
			t.Errorf("keys = %q; want [good]", got)
		}
	})
	t.Run("uppercase D", func(t *testing.T) {
		t.Parallel()
		s := mustParse(t, jwkSet(t, with(good, "D", "AQAB")))
		if got := keyIDs(s); !slices.Equal(got, []string{"good"}) {
			t.Errorf("keys = %q; want [good]", got)
		}
	})
}

// RFC 7517 §5 (the "keys" member) and 6.3's key table: more than 100 keys,
// an entry that is not an object, or a document that is not a JWK Set
// refuses the whole set.
func TestParse_SetShape(t *testing.T) {
	t.Parallel()
	key := rsaJWK("k", oddWithBits(2048), 65537)
	keys := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = key
		}
		return out
	}
	t.Run("100 keys", func(t *testing.T) {
		t.Parallel()
		if s := mustParse(t, jwkSet(t, keys(jwk.MaxKeys)...)); s.Len() != 100 {
			t.Errorf("Len = %d; want 100", s.Len())
		}
	})
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		if s := mustParse(t, []byte(`{"keys":[]}`)); s.Len() != 0 {
			t.Errorf("Len = %d; want 0", s.Len())
		}
	})
	refused := map[string][]byte{
		"101 keys":      jwkSet(t, keys(101)...),
		"string entry":  jwkSet(t, key, "RSA"),
		"number entry":  jwkSet(t, key, 5),
		"null entry":    jwkSet(t, key, nil),
		"array entry":   jwkSet(t, key, []any{key}),
		"bool entry":    jwkSet(t, key, true),
		"keys missing":  []byte(`{"key":[]}`),
		"keys null":     []byte(`{"keys":null}`),
		"keys object":   []byte(`{"keys":{}}`),
		"keys string":   []byte(`{"keys":"[]"}`),
		"top null":      []byte(`null`),
		"top array":     []byte(`[{"keys":[]}]`),
		"top string":    []byte(`"{}"`),
		"top number":    []byte(`1`),
		"empty input":   []byte(``),
		"trailing data": []byte(`{"keys":[]} {}`),
	}
	for name, data := range refused {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := jwk.Parse(data); !errors.Is(err, jwk.ErrSet) {
				t.Errorf("Parse(%.40q): err = %v; want ErrSet", data, err)
			}
		})
	}
}

// RFC 8259 §4 and §8.1, design 6.2: the set is decoded with unique member
// names, valid UTF-8 and a bounded depth at every level, read members or
// not.
func TestParse_JSON(t *testing.T) {
	t.Parallel()
	good := `{"kty":"RSA","n":"` + b64(oddWithBits(2048).Bytes()) + `","e":"AQAB"`
	cases := map[string]string{
		"duplicate keys":          `{"keys":[],"keys":[` + good + `}]}`,
		"duplicate kty":           `{"keys":[` + good + `,"kty":"EC"}]}`,
		"duplicate unread member": `{"keys":[` + good + `,"x5t":"a","x5t":"b"}]}`,
		"invalid UTF-8 in kid":    `{"keys":[` + good + ",\"kid\":\"a\xffb\"}]}",
		"invalid UTF-8 in name":   `{"keys":[` + good + ",\"x\xff\":1}]}",
		"lone surrogate":          `{"keys":[` + good + `,"kid":"\ud800"}]}`,
		"20000-deep unread":       `{"keys":[` + good + `}],"x":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := jwk.Parse([]byte(data)); !errors.Is(err, jwk.ErrSet) {
				t.Errorf("Parse: err = %v; want ErrSet", err)
			}
		})
	}
	t.Run("valid control", func(t *testing.T) {
		t.Parallel()
		if s := mustParse(t, []byte(`{"keys":[`+good+`,"x5t":"a"}]}`)); s.Len() != 1 {
			t.Errorf("Len = %d; want 1", s.Len())
		}
	})
}

// skipCase is a JWK the key table skips: the set holding it and a usable
// key parses to that usable key alone.
type skipCase struct {
	key  any
	name string
	// cite is the section whose rule skips the key.
	cite string
}

func assertSkipped(t *testing.T, cases []skipCase) {
	t.Helper()
	good := rsaJWK("good", oddWithBits(2048), 65537)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, err := jwk.Parse(jwkSet(t, c.key, good))
			if err != nil {
				t.Fatalf("Parse: %v; want the key skipped (%s)", err, c.cite)
			}
			if got := keyIDs(s); !slices.Equal(got, []string{"good"}) {
				t.Errorf("keys = %q; want [good] (%s)", got, c.cite)
			}
		})
	}
}

// RFC 7517 §5: a kty or crv outside the table is skipped, and the rest of
// the set stays usable.
func TestParse_UnknownTypeSkipped(t *testing.T) {
	t.Parallel()
	const cite = "RFC 7517 §5"
	ec := ecJWK(t, "bad", "P-256", newEC(t, ecCurves[0].curve))
	assertSkipped(t, []skipCase{
		{map[string]any{"kty": "oct", "kid": "bad", "k": "c2VjcmV0"}, "oct", cite},
		{map[string]any{"kty": "OKP", "kid": "bad", "crv": "Ed448", "x": b64(make([]byte, 57))}, "Ed448", cite},
		{map[string]any{"kty": "OKP", "kid": "bad", "crv": "X25519", "x": b64(make([]byte, 32))}, "X25519", cite},
		{with(ec, "crv", "secp256k1"), "secp256k1", cite},
		{with(ec, "crv", "p-256"), "crv case", "RFC 7518 §6.2.1.1"},
		{with(rsaJWK("bad", oddWithBits(2048), 65537), "kty", "rsa"), "kty case", "RFC 7517 §4.1"},
		{map[string]any{"kty": "AKP", "kid": "bad", "alg": "ML-DSA-44", "pub": "AQAB"}, "AKP", cite},
	})
}

// RFC 7518 §6.2.1, §6.3.1 and RFC 8037 §2 name each type's required
// members; a key missing one, or holding one of the wrong kind, is skipped
// (RFC 7517 §5). A Base64urlUInt is unpadded base64url (RFC 7518 §2).
func TestParse_RequiredMemberSkipped(t *testing.T) {
	t.Parallel()
	rsaKey := rsaJWK("bad", oddWithBits(2048), 65537)
	ec := ecJWK(t, "bad", "P-256", newEC(t, ecCurves[0].curve))
	okp := okpJWK("bad", newEd25519(t))
	n := b64(oddWithBits(2048).Bytes())
	assertSkipped(t, []skipCase{
		{without(rsaKey, "kty"), "kty absent", "RFC 7517 §4.1"},
		{with(rsaKey, "kty", 5), "kty number", "RFC 7517 §4.1"},
		{with(rsaKey, "kty", nil), "kty null", "RFC 7517 §4.1"},
		{with(without(rsaKey, "kty"), "KTY", "RSA"), "KTY uppercase", "RFC 8259 §4"},
		{without(rsaKey, "n"), "n absent", "RFC 7518 §6.3.1"},
		{with(rsaKey, "n", 5), "n number", "RFC 7518 §6.3.1"},
		{with(rsaKey, "n", nil), "n null", "RFC 7518 §6.3.1"},
		{with(rsaKey, "n", n+"=="), "n padded", "RFC 7518 §2"},
		{with(rsaKey, "n", strings.NewReplacer("-", "+", "_", "/").Replace(n)+"+/"), "n std alphabet", "RFC 7518 §2"},
		{with(rsaKey, "n", n[:len(n)-1]+"B"), "n trailing bits", "RFC 4648 §3.5"},
		{with(rsaKey, "n", n[:8]+"\n"+n[8:]), "n line feed", "RFC 4648 §3.3"},
		{with(rsaKey, "n", n[:8]+"\r"+n[8:]), "n carriage return", "RFC 4648 §3.3"},
		{without(rsaKey, "e"), "e absent", "RFC 7518 §6.3.1"},
		{with(rsaKey, "e", 65537), "e number", "RFC 7518 §6.3.1"},
		{with(rsaKey, "e", nil), "e null", "RFC 7518 §6.3.1"},
		{without(ec, "crv"), "crv absent", "RFC 7518 §6.2.1"},
		{with(ec, "crv", 256), "crv number", "RFC 7518 §6.2.1"},
		{with(ec, "crv", nil), "crv null", "RFC 7518 §6.2.1"},
		{without(ec, "x"), "x absent", "RFC 7518 §6.2.1"},
		{with(ec, "x", nil), "x null", "RFC 7518 §6.2.1"},
		{without(ec, "y"), "y absent", "RFC 7518 §6.2.1"},
		{with(ec, "y", 5), "y number", "RFC 7518 §6.2.1"},
		{without(okp, "x"), "okp x absent", "RFC 8037 §2"},
		{with(okp, "x", nil), "okp x null", "RFC 8037 §2"},
		{without(okp, "crv"), "okp crv absent", "RFC 8037 §2"},
		{with(okp, "crv", nil), "okp crv null", "RFC 8037 §2"},
	})
}

// RFC 7517 §4.2, §4.3, §4.4 and §4.5: a key whose use is not sig, whose
// key_ops lacks verify, whose alg is outside the table or names a row of
// another key type, or whose kid is not a string, is not a verification
// key here.
func TestParse_UseKeyOpsAlgKidSkipped(t *testing.T) {
	t.Parallel()
	rsaKey := rsaJWK("bad", oddWithBits(2048), 65537)
	ec := ecJWK(t, "bad", "P-256", newEC(t, ecCurves[0].curve))
	okp := okpJWK("bad", newEd25519(t))
	assertSkipped(t, []skipCase{
		{with(rsaKey, "use", "enc"), "use enc", "RFC 7517 §4.2"},
		{with(rsaKey, "use", "SIG"), "use case", "RFC 7517 §4.2"},
		{with(rsaKey, "use", nil), "use null", "RFC 7517 §4.2"},
		{with(rsaKey, "use", 5), "use number", "RFC 7517 §4.2"},
		{with(rsaKey, "key_ops", []string{"encrypt"}), "key_ops encrypt", "RFC 7517 §4.3"},
		{with(rsaKey, "key_ops", []string{"sign"}), "key_ops sign", "RFC 7517 §4.3"},
		{with(rsaKey, "key_ops", []string{}), "key_ops empty", "RFC 7517 §4.3"},
		{with(rsaKey, "key_ops", "verify"), "key_ops string", "RFC 7517 §4.3"},
		{with(rsaKey, "key_ops", nil), "key_ops null", "RFC 7517 §4.3"},
		{with(rsaKey, "key_ops", []any{5, "verify"}), "key_ops number entry", "RFC 7517 §4.3"},
		{with(rsaKey, "key_ops", []any{nil, "verify"}), "key_ops null entry", "RFC 7517 §4.3"},
		{with(rsaKey, "alg", "HS256"), "alg HS256", "RFC 8725 §3.1"},
		{with(rsaKey, "alg", "none"), "alg none", "RFC 8725 §2.1"},
		{with(rsaKey, "alg", "rs256"), "alg case", "RFC 7517 §4.4"},
		{with(rsaKey, "alg", "RSA-OAEP"), "alg encryption", "RFC 7517 §4.4"},
		{with(rsaKey, "alg", nil), "alg null", "RFC 7517 §4.4"},
		{with(rsaKey, "alg", 5), "alg number", "RFC 7517 §4.4"},
		{with(rsaKey, "alg", "ES256"), "alg ES256 on RSA", "RFC 7518 §3.4"},
		{with(ec, "alg", "RS256"), "alg RS256 on EC", "RFC 7518 §3.3"},
		{with(ec, "alg", "ES384"), "alg ES384 on P-256", "RFC 7518 §3.4"},
		{with(okp, "alg", "ES256"), "alg ES256 on OKP", "RFC 8037 §3.1"},
		{with(rsaKey, "kid", 5), "kid number", "RFC 7517 §4.5"},
		{with(rsaKey, "kid", nil), "kid null", "RFC 7517 §4.5"},
	})
}

// RFC 7517 §4.2, §4.3: an absent use and an absent key_ops restrict
// nothing; use sig and a key_ops naming verify are usable.
func TestParse_UseKeyOpsUsable(t *testing.T) {
	t.Parallel()
	base := rsaJWK("k", oddWithBits(2048), 65537)
	for name, key := range map[string]map[string]any{
		"neither":              base,
		"use sig":              with(base, "use", "sig"),
		"key_ops verify":       with(base, "key_ops", []string{"verify"}),
		"key_ops sign, verify": with(base, "key_ops", []string{"sign", "verify"}),
		"both":                 with(base, "use", "sig", "key_ops", []string{"verify"}),
		"alg RS256":            with(base, "alg", "RS256"),
		"alg PS512":            with(base, "alg", "PS512"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if s := mustParse(t, jwkSet(t, key)); s.Len() != 1 {
				t.Errorf("Len = %d; want 1", s.Len())
			}
		})
	}
}

// RFC 7518 §6.3.1 and 6.3's RSA row: n of 2048 to 4096 bits by bit length,
// so a leading zero octet is tolerated; e odd, at least 3 and at most
// 2^31−1. go-jose CVE-2026-116587: a modulus over 4096 bits costs cubic CPU.
func TestParse_RSABounds(t *testing.T) {
	t.Parallel()
	padded := append([]byte{0}, oddWithBits(2048).Bytes()...)
	assertSkipped(t, []skipCase{
		{rsaJWK("bad", oddWithBits(2047), 65537), "n 2047 bits", "6.3 RSA row"},
		{rsaJWK("bad", oddWithBits(4097), 65537), "n 4097 bits", "go-jose CVE-2026-116587"},
		{rsaJWK("bad", oddWithBits(8192), 65537), "n 8192 bits", "go-jose CVE-2026-116587"},
		{with(rsaJWK("bad", oddWithBits(2048), 65537), "n", ""), "n empty", "RFC 7518 §6.3.1.1"},
		{rsaJWK("bad", oddWithBits(2048), 2), "e 2", "6.3 RSA row"},
		{rsaJWK("bad", oddWithBits(2048), 1), "e 1", "6.3 RSA row"},
		{rsaJWK("bad", oddWithBits(2048), 65538), "e even", "6.3 RSA row"},
		{rsaJWK("bad", oddWithBits(2048), 1<<31), "e 2^31", "6.3 RSA row"},
		{rsaJWK("bad", oddWithBits(2048), 1<<32+1), "e 2^32+1", "6.3 RSA row"},
		{with(rsaJWK("bad", oddWithBits(2048), 65537), "e", ""), "e empty", "RFC 7518 §6.3.1.2"},
	})
	usable := []struct {
		name string
		n    []byte
		e    []byte
	}{
		{"n 2048 bits", oddWithBits(2048).Bytes(), big.NewInt(65537).Bytes()},
		{"n 4096 bits", oddWithBits(4096).Bytes(), big.NewInt(65537).Bytes()},
		{"n leading zero", padded, big.NewInt(65537).Bytes()},
		{"e 3", oddWithBits(2048).Bytes(), big.NewInt(3).Bytes()},
		{"e 2^31-1", oddWithBits(2048).Bytes(), big.NewInt(1<<31 - 1).Bytes()},
		{"e leading zero", oddWithBits(2048).Bytes(), []byte{0, 1, 0, 1}},
	}
	for _, c := range usable {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := mustParse(t, jwkSet(t, map[string]any{"kty": "RSA", "n": b64(c.n), "e": b64(c.e)}))
			if s.Len() != 1 {
				t.Fatalf("Len = %d; want 1", s.Len())
			}
			for k := range s.All() {
				pub, ok := k.Public().(*rsa.PublicKey)
				if !ok {
					t.Fatalf("Public = %T; want *rsa.PublicKey", k.Public())
				}
				if pub.N.Cmp(new(big.Int).SetBytes(c.n)) != 0 || int64(pub.E) != new(big.Int).SetBytes(c.e).Int64() {
					t.Errorf("key = (%x, %d); want n and e as published", pub.N, pub.E)
				}
			}
		})
	}
}

// RFC 7518 §6.2.1.2 and §6.2.1.3: x and y are exactly the curve's
// coordinate size; a point off the curve or at infinity is skipped (SEC 1
// §2.3.4; Nimbus CVE-2017-12974).
func TestParse_ECBounds(t *testing.T) {
	t.Parallel()
	for _, c := range ecCurves {
		t.Run(c.crv, func(t *testing.T) {
			t.Parallel()
			pub := newEC(t, c.curve)
			key := ecJWK(t, "bad", c.crv, pub)
			pt, err := pub.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			x, y := pt[1:1+c.size], pt[1+c.size:]
			offY := slices.Clone(y)
			offY[len(offY)-1] ^= 1
			assertSkipped(t, []skipCase{
				{with(key, "x", b64(x[1:])), "x short", "RFC 7518 §6.2.1.2"},
				{with(key, "x", b64(append([]byte{0}, x...))), "x long", "RFC 7518 §6.2.1.2"},
				{with(key, "y", b64(y[1:])), "y short", "RFC 7518 §6.2.1.3"},
				{with(key, "y", b64(append([]byte{0}, y...))), "y long", "RFC 7518 §6.2.1.3"},
				{with(key, "y", b64(offY)), "off curve", "Nimbus CVE-2017-12974"},
				{with(key, "x", b64(make([]byte, c.size)), "y", b64(make([]byte, c.size))), "infinity", "SEC 1 §2.3.4"},
			})
			s := mustParse(t, jwkSet(t, with(key, "kid", "ok")))
			for k := range s.All() {
				got, ok := k.Public().(*ecdsa.PublicKey)
				if !ok || !got.Equal(pub) {
					t.Errorf("Public = %v; want the published point", k.Public())
				}
			}
			if s.Len() != 1 {
				t.Errorf("Len = %d; want 1", s.Len())
			}
		})
	}
}

// RFC 8037 §2: an Ed25519 x is the 32-octet public key. A point of small
// order verifies a forged signature over any message under Go's
// cofactorless ed25519.Verify, as go-jose's and libsodium's key checks
// refuse it; its every encoding is skipped.
func TestParse_Ed25519Bounds(t *testing.T) {
	t.Parallel()
	pub := newEd25519(t)
	key := okpJWK("bad", pub)
	cases := []skipCase{
		{with(key, "x", b64(pub[1:])), "x 31 bytes", "RFC 8037 §2"},
		{with(key, "x", b64(append(slices.Clone(pub), 0))), "x 33 bytes", "RFC 8037 §2"},
	}
	for i, enc := range smallOrderEncodings(t) {
		cases = append(cases, skipCase{with(key, "x", b64(enc)), "small order " + string(rune('a'+i)), "RFC 8032 §5.1.7"})
	}
	assertSkipped(t, cases)
	s := mustParse(t, jwkSet(t, with(key, "kid", "ok")))
	for k := range s.All() {
		if got, ok := k.Public().(ed25519.PublicKey); !ok || !got.Equal(pub) {
			t.Errorf("Public = %v; want the published key", k.Public())
		}
	}
	if s.Len() != 1 {
		t.Errorf("Len = %d; want 1", s.Len())
	}
}

// The small-order fixture is right only if a small-order key forges a
// signature under ed25519.Verify, which is the hazard the skip guards.
func TestSmallOrderEncodings_Forge(t *testing.T) {
	t.Parallel()
	identity := smallOrderEncodings(t)[0]
	sig := append(slices.Clone(identity), make([]byte, 32)...)
	if !ed25519.Verify(ed25519.PublicKey(identity), []byte("any message"), sig) {
		t.Fatal("identity public key did not verify the forged signature; the fixture is wrong")
	}
}

// RFC 7517 §4.5: the kid is a case-sensitive string; absent and empty are
// different keys.
func TestParse_KeyID(t *testing.T) {
	t.Parallel()
	base := rsaJWK("Kid-1", oddWithBits(2048), 65537)
	s := mustParse(t, jwkSet(t, base, with(base, "kid", ""), without(base, "kid")))
	type kid struct {
		id string
		ok bool
	}
	var got []kid
	for k := range s.All() {
		id, ok := k.KeyID()
		got = append(got, kid{id, ok})
	}
	want := []kid{{"Kid-1", true}, {"", true}, {"", false}}
	if !slices.Equal(got, want) {
		t.Errorf("kids = %v; want %v", got, want)
	}
}

// RFC 8725 §3.1, RFC 7518 §3.1, RFC 9864 §2.2: a key fits a row of its own
// type and curve, and, when it carries alg, only the row that alg names;
// EdDSA and Ed25519 name one row.
func TestKey_Fits(t *testing.T) {
	t.Parallel()
	all := []jwk.Alg{jwk.RS256, jwk.RS384, jwk.RS512, jwk.PS256, jwk.PS384, jwk.PS512, jwk.ES256, jwk.ES384, jwk.ES512, jwk.EdDSA}
	rsaKey := rsaJWK("rsa", oddWithBits(2048), 65537)
	okp := okpJWK("okp", newEd25519(t))
	cases := []struct {
		key  map[string]any
		name string
		fits []jwk.Alg
	}{
		{rsaKey, "RSA", []jwk.Alg{jwk.RS256, jwk.RS384, jwk.RS512, jwk.PS256, jwk.PS384, jwk.PS512}},
		{with(rsaKey, "alg", "RS256"), "RSA alg RS256", []jwk.Alg{jwk.RS256}},
		{with(rsaKey, "alg", "PS384"), "RSA alg PS384", []jwk.Alg{jwk.PS384}},
		{ecJWK(t, "p256", "P-256", newEC(t, ecCurves[0].curve)), "P-256", []jwk.Alg{jwk.ES256}},
		{ecJWK(t, "p384", "P-384", newEC(t, ecCurves[1].curve)), "P-384", []jwk.Alg{jwk.ES384}},
		{ecJWK(t, "p521", "P-521", newEC(t, ecCurves[2].curve)), "P-521", []jwk.Alg{jwk.ES512}},
		{with(ecJWK(t, "p521", "P-521", newEC(t, ecCurves[2].curve)), "alg", "ES512"), "P-521 alg ES512", []jwk.Alg{jwk.ES512}},
		{okp, "Ed25519", []jwk.Alg{jwk.EdDSA}},
		{with(okp, "alg", "EdDSA"), "Ed25519 alg EdDSA", []jwk.Alg{jwk.EdDSA}},
		{with(okp, "alg", "Ed25519"), "Ed25519 alg Ed25519", []jwk.Alg{jwk.EdDSA}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := mustParse(t, jwkSet(t, c.key))
			if s.Len() != 1 {
				t.Fatalf("Len = %d; want 1", s.Len())
			}
			for k := range s.All() {
				var fits []jwk.Alg
				for _, a := range all {
					if k.Fits(a) {
						fits = append(fits, a)
					}
				}
				if !slices.Equal(fits, c.fits) {
					t.Errorf("fits %v; want %v", fits, c.fits)
				}
				if k.Fits(0) {
					t.Error("fits the zero Alg")
				}
			}
		})
	}
}

// RFC 7517 §4.4: a key's alg is the row it names, Ed25519 naming EdDSA's
// (RFC 9864 §2.2); a key without alg has none.
func TestKey_Alg(t *testing.T) {
	t.Parallel()
	okp := okpJWK("okp", newEd25519(t))
	cases := map[string]struct {
		key  map[string]any
		want jwk.Alg
	}{
		"absent":  {rsaJWK("rsa", oddWithBits(2048), 65537), 0},
		"PS256":   {with(rsaJWK("rsa", oddWithBits(2048), 65537), "alg", "PS256"), jwk.PS256},
		"Ed25519": {with(okp, "alg", "Ed25519"), jwk.EdDSA},
		"EdDSA":   {with(okp, "alg", "EdDSA"), jwk.EdDSA},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := mustParse(t, jwkSet(t, c.key))
			if s.Len() != 1 {
				t.Fatalf("Len = %d; want 1", s.Len())
			}
			for k := range s.All() {
				if k.Alg() != c.want {
					t.Errorf("Alg = %v; want %v", k.Alg(), c.want)
				}
			}
		})
	}
}
