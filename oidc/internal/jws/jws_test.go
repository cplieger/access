package jws_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cplieger/access/oidc/internal/jwk"
	"github.com/cplieger/access/oidc/internal/jws"
)

const payload = `{"iss":"https://idp.example","sub":"alice"}`

// sized mints an ES256 token of exactly n bytes by sizing its payload.
func sized(t *testing.T, k testKey, n int) (token, body string) {
	t.Helper()
	for pad := range 4 {
		header := `{"alg":"ES256"}` + strings.Repeat(" ", pad)
		fixed := len(b64s(header)) + 2 + base64.RawURLEncoding.EncodedLen(64)
		for size := (n - fixed) * 3 / 4; size <= (n-fixed)*3/4+2; size++ {
			if fixed+base64.RawURLEncoding.EncodedLen(size) == n {
				body = strings.Repeat("a", size)
				return mint(t, "ES256", k, header, body), body
			}
		}
	}
	t.Fatalf("no ES256 token of %d bytes", n)
	return "", ""
}

// RFC 7519 §7.2 step 1, Authlib CVE-2025-61920: a token over 64 KiB is
// refused before any part is decoded, and one of exactly 64 KiB is read.
// Serial: allocBytes reads the process's allocation counter.
func TestParse_Size(t *testing.T) {
	k := ecTestKey(t, "ec", "P-256")
	keys := set(t, k)
	token, body := sized(t, k, jws.MaxSize)
	if len(token) != 64<<10 {
		t.Fatalf("fixture is %d bytes; want 65536", len(token))
	}

	t.Run("64 KiB verifies", func(t *testing.T) {
		wantPayload(t, token, allAlgs, keys, body)
	})
	over := token + "A"
	t.Run("64 KiB plus one byte refused", func(t *testing.T) {
		wantErr(t, over, allAlgs, keys, jws.ErrInvalid)
	})
	t.Run("refused before any decode", func(t *testing.T) {
		read := allocBytes(20, func() { _, _ = jws.Parse(token, allAlgs) })
		if read < 32<<10 {
			t.Fatalf("parsing the 64 KiB token allocated %d bytes; the probe cannot see a decode", read)
		}
		refused := allocBytes(20, func() { _, _ = jws.Parse(over, allAlgs) })
		if refused > 1<<10 {
			t.Fatalf("refusing the 64 KiB + 1 token allocated %d bytes; want under 1 KiB", refused)
		}
	})
}

// RFC 7515 §7.1 and RFC 7519 §7.2 step 1: the compact form is three
// base64url parts (RFC 7515 §2) joined by '.', so any other byte refuses
// the token before decoding, CR and LF included, which Go's base64 decoder
// would otherwise skip.
func TestParse_Alphabet(t *testing.T) {
	t.Parallel()
	k := ecTestKey(t, "ec", "P-256")
	keys := set(t, k)
	token := mint(t, "ES256", k, `{"alg":"ES256"}`, payload)
	wantPayload(t, token, allAlgs, keys, payload)
	dot := strings.IndexByte(token, '.')
	for _, bad := range []string{" ", "+", "/", "=", "\x00", "\n", "\r", "\t", "%", "é", "\x7f", "\xff"} {
		t.Run(fmt.Sprintf("byte %x", bad), func(t *testing.T) {
			t.Parallel()
			wantErr(t, token[:dot+3]+bad+token[dot+3:], allAlgs, keys, jws.ErrInvalid)
		})
	}
}

// RFC 7515 §7.1, go-jose CVE-2025-27144, golang-jwt CVE-2025-30204: exactly
// two separators, counted in one pass without splitting, so a token of
// periods costs no allocation per period; a JWE's five parts (RFC 7516 §7.1)
// are refused here. Serial: allocBytes.
func TestParse_Separators(t *testing.T) {
	k := ecTestKey(t, "ec", "P-256")
	keys := set(t, k)
	token := mint(t, "ES256", k, `{"alg":"ES256"}`, payload)
	cases := map[string]string{
		"empty":                     "",
		"no separator":              strings.ReplaceAll(token, ".", ""),
		"one separator":             token[:strings.LastIndexByte(token, '.')],
		"three separators":          token + ".AA",
		"JWE compact, four":         "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.AAAA.AAAA.AAAA.AAAA",
		"two separators, no parts":  "..",
		"leading separator":         "." + token,
		"60,000 separators":         strings.Repeat(".", 60_000),
		"100,000 separators":        strings.Repeat(".", 100_000),
		"60,000 separators in body": token[:30] + strings.Repeat(".", 60_000) + token[30:],
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			wantErr(t, tok, allAlgs, keys, jws.ErrInvalid)
			if got := allocBytes(20, func() { _, _ = jws.Parse(tok, allAlgs) }); got > 1<<10 {
				t.Fatalf("refusal allocated %d bytes; want under 1 KiB", got)
			}
		})
	}
}

const b64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// withTrailingBits sets the lowest unused bit of a segment's last
// character, which a lenient decoder ignores.
func withTrailingBits(t *testing.T, seg string) string {
	t.Helper()
	idx := strings.IndexByte(b64URLAlphabet, seg[len(seg)-1])
	if len(seg)%4 == 0 || idx < 0 || idx&1 != 0 {
		t.Fatalf("segment %q has no zero trailing bit to set", seg)
	}
	return seg[:len(seg)-1] + string(b64URLAlphabet[idx|1])
}

// RFC 7515 §2 and RFC 4648 §3.5, PyJWT CVE-2026-102269: base64url without
// padding and with zero trailing bits, so no second encoding of the same
// bytes passes.
func TestParse_Base64(t *testing.T) {
	t.Parallel()
	k := ecTestKey(t, "ec", "P-256")
	keys := set(t, k)
	token := mint(t, "ES256", k, `{"alg":"ES256"}`, "{}")
	parts := strings.Split(token, ".")
	if lenient, err := base64.RawURLEncoding.DecodeString(withTrailingBits(t, parts[2])); err != nil || len(lenient) != 64 {
		t.Fatalf("the fixture's altered signature does not decode leniently: %v", err)
	}

	t.Run("canonical verifies", func(t *testing.T) {
		t.Parallel()
		wantPayload(t, token, allAlgs, keys, "{}")
	})
	t.Run("signature with trailing bits", func(t *testing.T) {
		t.Parallel()
		wantErr(t, parts[0]+"."+parts[1]+"."+withTrailingBits(t, parts[2]), allAlgs, keys, jws.ErrInvalid)
	})
	t.Run("payload with trailing bits", func(t *testing.T) {
		t.Parallel()
		wantErr(t, parts[0]+"."+withTrailingBits(t, parts[1])+"."+parts[2], allAlgs, keys, jws.ErrInvalid)
	})
	t.Run("padded signature", func(t *testing.T) {
		t.Parallel()
		wantErr(t, token+"==", allAlgs, keys, jws.ErrInvalid)
	})
}

// RFC 7515 §4 and §4.1.1, §4.1.4, §4.1.9, §4.1.11; RFC 7519 §5.1;
// RFC 7797 §6; RFC 8259 §4, §8.1; RFC 8725 §3.10: the header is one JSON
// object with unique, case-sensitive names and valid UTF-8; alg a string, kid
// absent or a string, typ absent or JWT; crit refused in any form; jku, jwk,
// x5u and x5c ignored. PyJWT CVE-2026-32597, Authlib CVE-2025-59420 (crit);
// PyJWT CVE-2026-102265, Nimbus CVE-2025-53864 (deep nesting).
func TestParse_Header(t *testing.T) {
	t.Parallel()
	k := ecTestKey(t, "ec", "P-256")
	keys := set(t, k)
	deep := strings.Repeat("[", 20_000) + strings.Repeat("]", 20_000)
	accepted := map[string]string{
		"alg alone":                    `{"alg":"ES256"}`,
		"kid":                          `{"alg":"ES256","kid":"ec"}`,
		"typ JWT":                      `{"alg":"ES256","typ":"JWT"}`,
		"typ jwt":                      `{"alg":"ES256","typ":"jwt"}`,
		"typ application/jwt":          `{"alg":"ES256","typ":"application/jwt"}`,
		"typ Application/JWT":          `{"alg":"ES256","typ":"Application/JWT"}`,
		"ALG is another member":        `{"alg":"ES256","ALG":"none"}`,
		"KID is another member":        `{"alg":"ES256","KID":null}`,
		"jku jwk x5u x5c ignored":      `{"alg":"ES256","jku":"https://attacker.example/jwks","jwk":{"kty":"oct","k":"AA"},"x5u":"https://attacker.example/c","x5c":["AA"]}`,
		"unknown member":               `{"alg":"ES256","cty":"JWT","x":null}`,
		"typ with surrounding members": `{"typ":"JWT","alg":"ES256","kid":"ec"}`,
	}
	refused := map[string]string{
		"empty object":              `{}`,
		"alg absent":                `{"kid":"ec"}`,
		"alg a number":              `{"alg":5}`,
		"alg null":                  `{"alg":null}`,
		"alg an array":              `{"alg":["ES256"]}`,
		"kid a number":              `{"alg":"ES256","kid":5}`,
		"kid null":                  `{"alg":"ES256","kid":null}`,
		"crit exp":                  `{"alg":"ES256","crit":["exp"],"exp":1}`,
		"crit empty":                `{"alg":"ES256","crit":[]}`,
		"crit null":                 `{"alg":"ES256","crit":null}`,
		"crit b64":                  `{"alg":"ES256","crit":["b64"],"b64":true}`,
		"typ JOSE":                  `{"alg":"ES256","typ":"JOSE"}`,
		"typ at+jwt":                `{"alg":"ES256","typ":"at+jwt"}`,
		"typ empty":                 `{"alg":"ES256","typ":""}`,
		"typ null":                  `{"alg":"ES256","typ":null}`,
		"typ a number":              `{"alg":"ES256","typ":5}`,
		"duplicate alg":             `{"alg":"ES256","alg":"ES256"}`,
		"invalid UTF-8":             "{\"alg\":\"ES256\",\"x\":\"\xff\"}",
		"20,000-deep unread member": `{"alg":"ES256","x":` + deep + `}`,
	}
	for name, header := range accepted {
		t.Run("accepted "+name, func(t *testing.T) {
			t.Parallel()
			wantPayload(t, mint(t, "ES256", k, header, payload), allAlgs, keys, payload)
		})
	}
	for name, header := range refused {
		t.Run("refused "+name, func(t *testing.T) {
			t.Parallel()
			wantErr(t, mint(t, "ES256", k, header, payload), allAlgs, keys, jws.ErrInvalid)
		})
	}
}

// RFC 8725 §3.10, Authlib CVE-2026-27962: a key is never taken from the
// token, so an unknown kid with a jwk header holding the key that signed it
// is a miss, and a jku or x5u URL is never fetched.
func TestVerify_EmbeddedKeyIgnored(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	t.Cleanup(srv.Close)
	provider := ecTestKey(t, "ec", "P-256")
	attacker := ecTestKey(t, "attacker", "P-256")
	keys := set(t, provider)
	for name, header := range map[string]map[string]any{
		"unknown kid": {"alg": "ES256", "kid": "attacker", "jwk": attacker.jwk, "jku": srv.URL + "/jwks", "x5u": srv.URL + "/x5u"},
		"no kid":      {"alg": "ES256", "jwk": attacker.jwk, "jku": srv.URL + "/jwks"},
		"known kid":   {"alg": "ES256", "kid": "ec", "jwk": attacker.jwk, "jku": srv.URL + "/jwks"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantErr(t, mintHeader(t, attacker, header, payload), allAlgs, keys, jws.ErrNoKey)
		})
	}
	t.Cleanup(func() {
		if n := requests.Load(); n != 0 {
			t.Errorf("the verifier made %d requests to the token's URLs; want 0", n)
		}
	})
}

// RFC 8725 §3.1, RFC 7518 §3.1, PyJWT CVE-2026-48523: the header's alg is
// checked against the provider's rows before any key is chosen, so a token
// outside them is refused (ErrInvalid, never a miss that would refetch)
// even with a key in the set that fits it and verifies it.
func TestParse_AlgOutsideProviderSet(t *testing.T) {
	t.Parallel()
	r := rsaA()
	ed := edTestKey(t, "ed")
	keys := set(t, r, ed)
	rs384 := mint(t, "RS384", r, `{"alg":"RS384"}`, payload)
	eddsa := mint(t, "EdDSA", ed, `{"alg":"EdDSA"}`, payload)

	t.Run("RS384 under RS256 alone", func(t *testing.T) {
		t.Parallel()
		wantErr(t, rs384, []jwk.Alg{jwk.RS256}, keys, jws.ErrInvalid)
	})
	t.Run("RS384 when listed", func(t *testing.T) {
		t.Parallel()
		wantPayload(t, rs384, []jwk.Alg{jwk.RS256, jwk.RS384}, keys, payload)
	})
	t.Run("EdDSA under RS256 alone", func(t *testing.T) {
		t.Parallel()
		wantErr(t, eddsa, []jwk.Alg{jwk.RS256}, keys, jws.ErrInvalid)
	})
	t.Run("Ed25519 name when EdDSA is listed", func(t *testing.T) {
		t.Parallel()
		wantPayload(t, mint(t, "Ed25519", ed, `{"alg":"Ed25519"}`, payload), []jwk.Alg{jwk.EdDSA}, keys, payload)
	})
	t.Run("no rows", func(t *testing.T) {
		t.Parallel()
		wantErr(t, rs384, nil, keys, jws.ErrInvalid)
	})
}

// hs is input '.' HMAC(secret, input) under HS256, HS384 or HS512 (RFC 7518 §3.2).
func hs(h crypto.Hash, secret, input string) string {
	m := hmac.New(h.New, []byte(secret))
	m.Write([]byte(input))
	return input + "." + b64(m.Sum(nil))
}

// RFC 8725 §2.1 and §3.1, RFC 7518 §3.1: none, every HS*, and any name not
// a row are refused before a key is chosen, whatever the signature holds:
// Authlib CVE-2026-28802 (none with a blank signature); node-jsonwebtoken
// CVE-2015-9235, PyJWT CVE-2022-29217, CVE-2026-102268, CVE-2026-102271,
// python-jose CVE-2024-33663, Authlib CVE-2024-37568, CVE-2026-114615 (a
// public key used as an HMAC secret).
func TestParse_RefusedAlgs(t *testing.T) {
	t.Parallel()
	r := rsaA()
	keys := set(t, r)
	n, _ := base64.RawURLEncoding.DecodeString(r.jwk["n"].(string))
	jwkJSON := `{"kty":"RSA","kid":"rsa-a","n":"` + r.jwk["n"].(string) + `","e":"AQAB"}`
	input := func(alg string) string { return b64s(`{"alg":"`+alg+`"}`) + "." + b64s(payload) }
	cases := map[string]string{
		"none, empty signature":          input("none") + ".",
		"none, a signature":              input("none") + "." + b64s("signature"),
		"None":                           input("None") + ".",
		"NONE":                           input("NONE") + ".",
		"HS256 keyed by the modulus":     hs(crypto.SHA256, string(n), input("HS256")),
		"HS256 keyed by the JWK":         hs(crypto.SHA256, jwkJSON, input("HS256")),
		"HS256 keyed by a client secret": hs(crypto.SHA256, "client-secret", input("HS256")),
		"HS384":                          hs(crypto.SHA384, jwkJSON, input("HS384")),
		"HS512":                          hs(crypto.SHA512, jwkJSON, input("HS512")),
		"RS1":                            mint(t, "RS256", r, `{"alg":"RS1"}`, payload),
		"ES256K":                         input("ES256K") + "." + b64(make([]byte, 64)),
		"Ed448":                          input("Ed448") + "." + b64(make([]byte, 114)),
		"lower-case rs256":               mint(t, "RS256", r, `{"alg":"rs256"}`, payload),
		"RS256 with a space":             mint(t, "RS256", r, `{"alg":"RS256 "}`, payload),
		"empty alg":                      mint(t, "RS256", r, `{"alg":""}`, payload),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantErr(t, token, allAlgs, keys, jws.ErrInvalid)
		})
	}
}

// RFC 7515 §4.1.4 and RFC 7517 §4.5: a header kid restricts the candidates
// to the keys carrying that exact kid; without one, every key fitting the
// alg is tried. No candidate, or none that verifies, is the one miss.
func TestVerify_KeySelection(t *testing.T) {
	t.Parallel()
	a := ecTestKey(t, "a", "P-256")
	b := ecTestKey(t, "b", "P-256")
	outsider := ecTestKey(t, "a", "P-256")
	r := rsaA()
	es := func(k testKey, kid string) string {
		if kid == "-" {
			return mint(t, "ES256", k, `{"alg":"ES256"}`, payload)
		}
		return mintHeader(t, k, map[string]any{"alg": "ES256", "kid": kid}, payload)
	}

	t.Run("kid names a key that did not sign", func(t *testing.T) {
		t.Parallel()
		wantErr(t, es(b, "a"), allAlgs, set(t, a, b), jws.ErrNoKey)
	})
	t.Run("kid names the signer", func(t *testing.T) {
		t.Parallel()
		wantPayload(t, es(b, "b"), allAlgs, set(t, a, b), payload)
	})
	t.Run("no kid tries every fitting key", func(t *testing.T) {
		t.Parallel()
		wantPayload(t, es(b, "-"), allAlgs, set(t, r, a, b), payload)
	})
	t.Run("no kid, kid-less keys", func(t *testing.T) {
		t.Parallel()
		wantPayload(t, es(b, "-"), allAlgs, set(t, a.without("kid"), b.without("kid")), payload)
	})
	t.Run("kid the set lacks", func(t *testing.T) {
		t.Parallel()
		wantErr(t, es(a, "z"), allAlgs, set(t, a, b), jws.ErrNoKey)
	})
	t.Run("kid matched case-sensitively", func(t *testing.T) {
		t.Parallel()
		wantErr(t, es(a, "A"), allAlgs, set(t, a, b), jws.ErrNoKey)
	})
	t.Run("kid whose key fits another row", func(t *testing.T) {
		t.Parallel()
		wantErr(t, es(a, "rsa-a"), allAlgs, set(t, r, a.without("kid")), jws.ErrNoKey)
	})
	t.Run("fitting key whose signature fails", func(t *testing.T) {
		t.Parallel()
		wantErr(t, es(outsider, "a"), allAlgs, set(t, a, b), jws.ErrNoKey)
	})
	t.Run("kid against a kid-less key", func(t *testing.T) {
		t.Parallel()
		wantErr(t, es(a, "a"), allAlgs, set(t, a.without("kid")), jws.ErrNoKey)
	})
	t.Run("empty kid is a kid", func(t *testing.T) {
		t.Parallel()
		wantErr(t, es(a, ""), allAlgs, set(t, a.without("kid")), jws.ErrNoKey)
	})
	t.Run("two RSA keys of one kid, the second signs", func(t *testing.T) {
		t.Parallel()
		token := mint(t, "RS256", rsaB(), `{"alg":"RS256","kid":"shared"}`, payload)
		wantPayload(t, token, allAlgs, set(t, r.with("kid", "shared"), rsaB().with("kid", "shared")), payload)
	})
	t.Run("RSA and EC keys of one kid", func(t *testing.T) {
		t.Parallel()
		keys := set(t, r.with("kid", "m"), a.with("kid", "m"))
		wantPayload(t, mint(t, "RS256", r, `{"alg":"RS256","kid":"m"}`, payload), allAlgs, keys, payload)
		wantPayload(t, mint(t, "ES256", a, `{"alg":"ES256","kid":"m"}`, payload), allAlgs, keys, payload)
	})
	t.Run("empty set", func(t *testing.T) {
		t.Parallel()
		wantErr(t, es(a, "-"), allAlgs, set(t), jws.ErrNoKey)
	})
}

// RFC 7518 §3.1, RFC 8725 §3.1, RFC 9864 §2.2: a key's own alg must name
// the header's row, the scheme is the row's, and EdDSA and Ed25519 name one
// row in either order.
func TestVerify_Rows(t *testing.T) {
	t.Parallel()
	r := rsaA()
	ed := edTestKey(t, "ed")

	t.Run("key alg RS256 refuses an RS512 header", func(t *testing.T) {
		t.Parallel()
		wantErr(t, mint(t, "RS512", r, `{"alg":"RS512"}`, payload), allAlgs, set(t, r.with("alg", "RS256")), jws.ErrNoKey)
	})
	t.Run("key alg RS256 verifies RS256", func(t *testing.T) {
		t.Parallel()
		wantPayload(t, mint(t, "RS256", r, `{"alg":"RS256"}`, payload), allAlgs, set(t, r.with("alg", "RS256")), payload)
	})
	t.Run("PKCS1v15 signature under a PS256 header", func(t *testing.T) {
		t.Parallel()
		wantErr(t, mint(t, "RS256", r, `{"alg":"PS256"}`, payload), allAlgs, set(t, r), jws.ErrNoKey)
	})
	t.Run("PSS signature under an RS256 header", func(t *testing.T) {
		t.Parallel()
		wantErr(t, mint(t, "PS256", r, `{"alg":"RS256"}`, payload), allAlgs, set(t, r), jws.ErrNoKey)
	})
	t.Run("EdDSA header, key alg Ed25519", func(t *testing.T) {
		t.Parallel()
		wantPayload(t, mint(t, "EdDSA", ed, `{"alg":"EdDSA"}`, payload), allAlgs, set(t, ed.with("alg", "Ed25519")), payload)
	})
	t.Run("Ed25519 header, key alg EdDSA", func(t *testing.T) {
		t.Parallel()
		wantPayload(t, mint(t, "Ed25519", ed, `{"alg":"Ed25519"}`, payload), allAlgs, set(t, ed.with("alg", "EdDSA")), payload)
	})
	t.Run("SHA-384 signature under an ES256 header", func(t *testing.T) {
		t.Parallel()
		p256 := ecTestKey(t, "p", "P-256")
		a, _ := jwk.ParseAlg("ES384")
		input := b64s(`{"alg":"ES256"}`) + "." + b64s(payload)
		rr, s, err := ecdsa.Sign(rand.Reader, p256.priv.(*ecdsa.PrivateKey), hashOf(a, input))
		if err != nil {
			t.Fatal(err)
		}
		wantErr(t, input+"."+b64(rs(64, rr, s)), allAlgs, set(t, p256), jws.ErrNoKey)
	})
}

func flipBit(sig []byte, i int) []byte {
	out := append([]byte(nil), sig...)
	out[i/8] ^= 1 << (i % 8)
	return out
}

// RFC 7518 §3.3, §3.4, §3.5 and RFC 8037 §3.1: each accepted row verifies a
// token signed by a fresh key under its scheme and hash, and refuses one
// whose signature or signing input changed by one bit.
func TestVerify_EachRow(t *testing.T) {
	t.Parallel()
	r := rsaA()
	keyFor := map[string]testKey{
		"RS256": r, "RS384": r, "RS512": r, "PS256": r, "PS384": r, "PS512": r,
		"ES256":   ecTestKey(t, "ec", "P-256"),
		"ES384":   ecTestKey(t, "ec", "P-384"),
		"ES512":   ecTestKey(t, "ec", "P-521"),
		"EdDSA":   edTestKey(t, "ed"),
		"Ed25519": edTestKey(t, "ed"),
	}
	for alg, k := range keyFor {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			keys := set(t, k)
			input := b64s(`{"alg":"`+alg+`"}`) + "." + b64s(payload)
			sig := sign(t, alg, k, input)
			wantPayload(t, input+"."+b64(sig), allAlgs, keys, payload)
			for _, bit := range []int{0, len(sig) * 4, len(sig)*8 - 1} {
				wantErr(t, input+"."+b64(flipBit(sig, bit)), allAlgs, keys, jws.ErrNoKey)
			}
			other := b64s(`{"alg":"`+alg+`"}`) + "." + b64s(payload+" ")
			wantErr(t, other+"."+b64(sig), allAlgs, keys, jws.ErrNoKey)
		})
	}
}

// RFC 7518 §3.4: an ES signature is R ‖ S at exactly twice the curve's
// coordinate size, never DER, with R and S in [1, N−1] (SEC 1 §4.1.4 step
// 1; CVE-2022-21449's zero signature).
func TestVerify_ECDSASignatureForm(t *testing.T) {
	t.Parallel()
	for alg, crv := range map[string]string{"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"} {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			k := ecTestKey(t, "ec", crv)
			keys := set(t, k)
			a, _ := jwk.ParseAlg(alg)
			size := a.SignatureSize()
			input := b64s(`{"alg":"`+alg+`"}`) + "." + b64s(payload)
			sig := sign(t, alg, k, input)
			priv := k.priv.(*ecdsa.PrivateKey)
			der, err := ecdsa.SignASN1(rand.Reader, priv, hashOf(a, input))
			if err != nil {
				t.Fatal(err)
			}
			n := priv.Curve.Params().N
			s := new(big.Int).SetBytes(sig[size/2:])
			cases := map[string][]byte{
				"one byte short":  sig[:size-1],
				"one byte long":   append(append([]byte(nil), sig...), 0),
				"zero-prefixed":   append([]byte{0}, sig...),
				"S zero-prefixed": append(append(append([]byte(nil), sig[:size/2]...), 0), sig[size/2:]...),
				"DER":             der,
				"R = S = 0":       make([]byte, size),
				"R = 0":           rs(size, big.NewInt(0), s),
				"R = S = N":       rs(size, n, n),
				"S = N":           rs(size, new(big.Int).SetBytes(sig[:size/2]), n),
			}
			wantPayload(t, input+"."+b64(sig), allAlgs, keys, payload)
			for name, bad := range cases {
				t.Run(name, func(t *testing.T) {
					wantErr(t, input+"."+b64(bad), allAlgs, keys, jws.ErrNoKey)
				})
			}
		})
	}
}

// RFC 7518 §3.5: the PSS salt is the size of the hash, so a signature under
// any other salt length is refused.
func TestVerify_PSSSalt(t *testing.T) {
	t.Parallel()
	r := rsaA()
	keys := set(t, r)
	cases := []struct {
		alg  string
		salt int
		ok   bool
	}{
		{"PS256", 32, true},
		{"PS256", 0, false},
		{"PS256", 31, false},
		{"PS256", 33, false},
		{"PS256", 64, false},
		{"PS256", 222, false}, // the largest a 2048-bit key allows under SHA-256
		{"PS384", 48, true},
		{"PS384", 32, false},
		{"PS512", 64, true},
		{"PS512", 32, false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s salt %d", c.alg, c.salt), func(t *testing.T) {
			t.Parallel()
			a, _ := jwk.ParseAlg(c.alg)
			input := b64s(`{"alg":"`+c.alg+`"}`) + "." + b64s(payload)
			token := input + "." + b64(signPSS(t, a, r, input, c.salt))
			if c.ok {
				wantPayload(t, token, allAlgs, keys, payload)
				return
			}
			wantErr(t, token, allAlgs, keys, jws.ErrNoKey)
		})
	}
}

// RFC 8017 §8.2.2 step 1 and §8.1.2 step 1 (an RSA signature is exactly the
// modulus's k octets) and RFC 8032 §5.1.7 (an Ed25519 signature is 64
// octets): a signature of another length is refused even where it holds the
// same integer, which the standard-library calls check themselves.
func TestVerify_SignatureSize(t *testing.T) {
	t.Parallel()
	r := rsaA()
	keys := set(t, r)

	// A PKCS #1 v1.5 signature is deterministic, so vary the payload until
	// its first octet is zero: then its last 255 octets hold the same integer.
	var body, input string
	var sig []byte
	for i := 0; ; i++ {
		body = fmt.Sprintf(`{"n":%d}`, i)
		input = b64s(`{"alg":"RS256"}`) + "." + b64s(body)
		if sig = sign(t, "RS256", r, input); sig[0] == 0 {
			break
		}
	}
	wantPayload(t, input+"."+b64(sig), allAlgs, keys, body)
	t.Run("RS256 of 255 octets", func(t *testing.T) {
		t.Parallel()
		wantErr(t, input+"."+b64(sig[1:]), allAlgs, keys, jws.ErrNoKey)
	})
	t.Run("RS256 of 257 octets", func(t *testing.T) {
		t.Parallel()
		wantErr(t, input+"."+b64(append([]byte{0}, sig...)), allAlgs, keys, jws.ErrNoKey)
	})

	ed := edTestKey(t, "ed")
	edKeys := set(t, ed)
	edInput := b64s(`{"alg":"EdDSA"}`) + "." + b64s(payload)
	edSig := sign(t, "EdDSA", ed, edInput)
	wantPayload(t, edInput+"."+b64(edSig), allAlgs, edKeys, payload)
	t.Run("Ed25519 of 63 octets", func(t *testing.T) {
		t.Parallel()
		wantErr(t, edInput+"."+b64(edSig[:63]), allAlgs, edKeys, jws.ErrNoKey)
	})
	t.Run("Ed25519 of 65 octets", func(t *testing.T) {
		t.Parallel()
		wantErr(t, edInput+"."+b64(append(append([]byte(nil), edSig...), 0)), allAlgs, edKeys, jws.ErrNoKey)
	})
}
