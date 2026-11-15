package jws_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/cplieger/access/oidc/internal/jwk"
	"github.com/cplieger/access/oidc/internal/jws"
)

// fuzzKeys are fixed so a committed crasher replays: RFC 7515 A.3's P-256
// key and an Ed25519 key from a zero seed.
func fuzzKeys(f *testing.F) (ec, ed testKey) {
	f.Helper()
	d, _ := base64.RawURLEncoding.DecodeString("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI")
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		f.Fatalf("RFC 7515 A.3 key: %v", err)
	}
	return ecFromPriv(f, "ec", "P-256", priv), edFromPriv("ed", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
}

// members reads a JSON object's top-level members with jsontext's token
// reader, apart from the decode Parse uses.
func members(t *testing.T, header []byte) map[string]jsontext.Value {
	t.Helper()
	dec := jsontext.NewDecoder(bytes.NewReader(header))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		t.Fatalf("accepted header %q is not a JSON object", header)
	}
	out := map[string]jsontext.Value{}
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			t.Fatalf("accepted header %q: %v", header, err)
		}
		name := tok.String()
		v, err := dec.ReadValue()
		if err != nil {
			t.Fatalf("accepted header %q: %v", header, err)
		}
		out[name] = v.Clone()
	}
	return out
}

func stringValue(v jsontext.Value) (string, bool) {
	var s string
	return s, v.Kind() == '"' && json.Unmarshal(v, &s) == nil
}

// checkHeader asserts what RFC 7515 §4.1.1, §4.1.4, §4.1.9 and §4.1.11
// require of a header the verifier accepted.
func checkHeader(t *testing.T, header []byte) string {
	t.Helper()
	if !jsontext.Value(header).IsValid() {
		t.Fatalf("accepted header %q is not valid RFC 8259 JSON with unique names", header)
	}
	m := members(t, header)
	alg, ok := stringValue(m["alg"])
	if !ok {
		t.Fatalf("accepted header %q has no string alg", header)
	}
	if _, found := m["crit"]; found {
		t.Fatalf("accepted header %q carries crit", header)
	}
	if v, found := m["kid"]; found {
		if _, ok := stringValue(v); !ok {
			t.Fatalf("accepted header %q has a non-string kid", header)
		}
	}
	if v, found := m["typ"]; found {
		typ, ok := stringValue(v)
		if !ok || (!strings.EqualFold(typ, "JWT") && !strings.EqualFold(typ, "application/jwt")) {
			t.Fatalf("accepted header %q has typ %s", header, v)
		}
	}
	return alg
}

// verifiedBy reports whether one of the fuzz keys verifies sig over input
// under alg, computed here with crypto/* directly.
func verifiedBy(ec, ed testKey, alg, input string, sig []byte) bool {
	switch alg {
	case "ES256":
		if len(sig) != 64 {
			return false
		}
		a, _ := jwk.ParseAlg(alg)
		pub := &ec.priv.(*ecdsa.PrivateKey).PublicKey
		return ecdsa.Verify(pub, hashOf(a, input), new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case "EdDSA", "Ed25519":
		return ed25519.Verify(ed.priv.(ed25519.PrivateKey).Public().(ed25519.PublicKey), []byte(input), sig)
	}
	return false
}

func wantClass(t *testing.T, err, class error) {
	t.Helper()
	if !errors.Is(err, class) {
		t.Fatalf("error %v does not wrap %v", err, class)
	}
}

// go-jose CVE-2026-116586, Nimbus CVE-2019-17195: any token either is
// refused with ErrInvalid or ErrNoKey, or yields the payload of a token
// that is at most 64 KiB, three canonical base64url parts (RFC 7515 §2,
// §7.1) and a header RFC 7515 §4 allows, whose signature a key of the set
// verifies over the exact signing input; it never panics.
func FuzzVerify(f *testing.F) {
	ec, ed := fuzzKeys(f)
	keys := set(f, ec, ed)
	for _, s := range []string{
		mint(f, "ES256", ec, `{"alg":"ES256","kid":"ec"}`, payload),
		mint(f, "EdDSA", ed, `{"alg":"EdDSA"}`, payload),
		mint(f, "Ed25519", ed, `{"alg":"Ed25519","typ":"JWT"}`, ""),
		mint(f, "ES256", ec, `{"alg":"ES256","crit":[]}`, payload),
		rfc7515A3, rfc7515A1, rfc7515A5, rfc8037A4,
		"..", "a.b.c", strings.Repeat(".", 1000), "eyJhbGciOiJFUzI1NiJ9.e30.AA==",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		tok, err := jws.Parse(token, allAlgs)
		if err != nil {
			wantClass(t, err, jws.ErrInvalid)
			return
		}
		got, err := tok.Verify(keys)
		if err != nil {
			wantClass(t, err, jws.ErrNoKey)
			return
		}
		parts := strings.Split(token, ".")
		if len(token) > jws.MaxSize || len(parts) != 3 {
			t.Fatalf("accepted a token of %d bytes and %d parts", len(token), len(parts))
		}
		var dec [3][]byte
		for i, p := range parts {
			if dec[i], err = base64.RawURLEncoding.DecodeString(p); err != nil || b64(dec[i]) != p {
				t.Fatalf("accepted non-canonical part %d %q", i, p)
			}
		}
		if !bytes.Equal(got, dec[1]) {
			t.Fatalf("payload %q is not the token's %q", got, dec[1])
		}
		alg := checkHeader(t, dec[0])
		if !verifiedBy(ec, ed, alg, parts[0]+"."+parts[1], dec[2]) {
			t.Fatalf("accepted %q, which no key of the set verifies under %s", token, alg)
		}
	})
}

// RFC 7515 §4 and RFC 8259 §4, §8.1 over the header alone: whatever header
// bytes an ES256 signature covers, an accepted one is a single valid JSON
// object meeting RFC 7515 §4.1's member rules for ES256, and a refused one
// is ErrInvalid or ErrNoKey.
func FuzzParse_header(f *testing.F) {
	ec, _ := fuzzKeys(f)
	keys := set(f, ec)
	for _, s := range []string{
		`{"alg":"ES256"}`, `{"alg":"ES256","kid":"ec"}`, `{"alg":"ES256","kid":null}`,
		`{"alg":"ES256","crit":[]}`, `{"alg":"ES256","typ":"application/JWT"}`, `{"alg":"ES256","typ":"JOSE"}`,
		`{"alg":"ES256","ALG":"none"}`, `{"alg":"ES256","alg":"none"}`, "{\"alg\":\"ES256\",\"x\":\"\xff\"}",
		`{"alg":"ES256","x":[[[[[[[[]]]]]]]]}`, `{"alg":"none"}`, `["alg"]`, `null`, ``, ` {"alg":"ES256"} `,
	} {
		f.Add([]byte(s))
	}
	priv := ec.priv.(*ecdsa.PrivateKey)
	f.Fuzz(func(t *testing.T, header []byte) {
		input := b64(header) + "." + b64s("{}")
		a, _ := jwk.ParseAlg("ES256")
		r, s, err := ecdsa.Sign(rand.Reader, priv, hashOf(a, input))
		if err != nil {
			t.Fatal(err)
		}
		tok, err := jws.Parse(input+"."+b64(rs(64, r, s)), allAlgs)
		if err != nil {
			wantClass(t, err, jws.ErrInvalid)
			return
		}
		if _, err := tok.Verify(keys); err != nil {
			wantClass(t, err, jws.ErrNoKey)
			return
		}
		if alg := checkHeader(t, header); alg != "ES256" {
			t.Fatalf("accepted header %q naming %q over an ES256 signature", header, alg)
		}
	})
}
