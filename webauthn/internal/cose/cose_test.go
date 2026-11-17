package cose_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/access/webauthn/internal/cose"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// pair is one COSE_Key member; v is an int or int64, []byte, bool, string, or
// raw (an item already encoded).
type pair struct {
	k int64
	v any
}

type raw []byte

func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	case n <= 0xffffffff:
		return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{major<<5 | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func encodeInt(i int64) []byte {
	if i >= 0 {
		return head(0, uint64(i))
	}
	return head(1, uint64(-1-i))
}

// encodeMap writes an RFC 8949 map in the order given, shortest heads.
func encodeMap(pairs ...pair) []byte {
	out := head(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(out, encodeInt(p.k)...)
		switch v := p.v.(type) {
		case int:
			out = append(out, encodeInt(int64(v))...)
		case int64:
			out = append(out, encodeInt(v)...)
		case []byte:
			out = append(append(out, head(2, uint64(len(v)))...), v...)
		case string:
			out = append(append(out, head(3, uint64(len(v)))...), v...)
		case bool:
			if v {
				out = append(out, 0xf5)
			} else {
				out = append(out, 0xf4)
			}
		case raw:
			out = append(out, v...)
		default:
			panic("encodeMap: unsupported value type")
		}
	}
	return out
}

func asInt64(v any) int64 {
	if i, ok := v.(int); ok {
		return int64(i)
	}
	return v.(int64)
}

func without(pairs []pair, label int64) []pair {
	return slices.DeleteFunc(slices.Clone(pairs), func(p pair) bool { return p.k == label })
}

func with(pairs []pair, label int64, v any) []pair {
	out := without(pairs, label)
	return append(out, pair{label, v})
}

// The base key of each offered family, from published vectors: ES256 from
// §16.2, EdDSA from §16.11, RS256 from §16.10, ML-DSA from RFC 9964
// Appendix A.
type family struct {
	name  string
	pairs []pair
}

func baseKeys(t testing.TB) []family {
	t.Helper()
	vectors := s16(t)
	es := keyLabels(t, credentialKey(t, vectors["16.2"].Registration.bytes(t, "attestationObject")))
	ed := keyLabels(t, credentialKey(t, vectors["16.11"].Registration.bytes(t, "attestationObject")))
	rs := keyLabels(t, credentialKey(t, vectors["16.10"].Registration.bytes(t, "attestationObject")))
	out := []family{
		{"ES256", []pair{{1, 2}, {3, -7}, {-1, 1}, {-2, es[-2]}, {-3, es[-3]}}},
		{"EdDSA", []pair{{1, 1}, {3, -8}, {-1, 6}, {-2, ed[-2]}}},
		{"RS256", []pair{{1, 3}, {3, -257}, {-1, rs[-1]}, {-2, rs[-2]}}},
	}
	for _, e := range rfc9964(t) {
		if e.Appendix == "A.2 COSE" {
			out = append(out, family{e.ParameterSet, []pair{{1, 7}, {3, mldsaAlg[e.ParameterSet]}, {-1, unhex(t, e.PublicKey)}}})
		}
	}
	return out
}

// WebAuthn §5.4's pubKeyCredParams lists algorithms in preference order;
// access offers ML-DSA-44, -65, -87, EdDSA, ES256, RS256 (RFC 9964 §5,
// RFC 9053 §2, RFC 8812 §2).
func TestOffered_WebAuthn5_4_preferenceOrder(t *testing.T) {
	t.Parallel()
	want := []int{-48, -49, -50, -8, -7, -257}
	if got := cose.Offered(); !slices.Equal(got, want) {
		t.Fatalf("Offered() = %v, want %v", got, want)
	}
	got := cose.Offered()
	got[0] = 0
	if cose.Offered()[0] != -48 {
		t.Error("Offered() returns a slice the caller can change")
	}
}

// WebAuthn §6.5.1: the key "MUST contain the alg parameter and MUST NOT
// contain any other OPTIONAL parameters"; RFC 9052 §7 and each key type's
// RFC fix the rest. Every family has exactly its labels, each of its type.
func TestParseKey_WebAuthn6_5_1_exactLabelSet(t *testing.T) {
	t.Parallel()
	for _, f := range baseKeys(t) {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			k, err := cose.ParseKey(encodeMap(f.pairs...))
			if err != nil {
				t.Fatalf("base key: ParseKey = %v", err)
			}
			if want := asInt64(f.pairs[1].v); int64(k.Algorithm()) != want {
				t.Errorf("Algorithm() = %d, want %d", k.Algorithm(), want)
			}
			for _, p := range f.pairs {
				if _, err := cose.ParseKey(encodeMap(without(f.pairs, p.k)...)); !errors.Is(err, cose.ErrMalformed) {
					t.Errorf("label %d missing: ParseKey = %v, want ErrMalformed", p.k, err)
				}
			}
			// kid (2) and key_ops (4) are common parameters (RFC 9052 §7.1); -4 is
			// d for EC2 and OKP (RFC 9053 §7), -3 is RSA's d (RFC 8230 §4), -2 is
			// AKP's priv (RFC 9964 §3).
			for _, extra := range []int64{2, 4, -4, -5, -2, -3} {
				if slices.ContainsFunc(f.pairs, func(p pair) bool { return p.k == extra }) {
					continue
				}
				if _, err := cose.ParseKey(encodeMap(append(slices.Clone(f.pairs), pair{extra, []byte{1}})...)); !errors.Is(err, cose.ErrMalformed) {
					t.Errorf("extra label %d: ParseKey = %v, want ErrMalformed", extra, err)
				}
			}
			for _, p := range f.pairs {
				var wrong any = "x"
				if _, isText := p.v.(string); isText {
					wrong = 1
				}
				if _, err := cose.ParseKey(encodeMap(with(f.pairs, p.k, wrong)...)); !errors.Is(err, cose.ErrMalformed) {
					t.Errorf("label %d as a text string: ParseKey = %v, want ErrMalformed", p.k, err)
				}
			}
		})
	}
}

// RFC 9052 §7.1: kty and alg must agree; each alg here has one key type.
func TestParseKey_RFC9052_7_1_ktyForAlg(t *testing.T) {
	t.Parallel()
	for _, f := range baseKeys(t) {
		for _, kty := range []int{1, 2, 3, 4, 7} {
			if int64(kty) == asInt64(f.pairs[0].v) {
				continue
			}
			if _, err := cose.ParseKey(encodeMap(with(f.pairs, 1, kty)...)); !errors.Is(err, cose.ErrMalformed) {
				t.Errorf("%s with kty %d: ParseKey = %v, want ErrMalformed", f.name, kty, err)
			}
		}
	}
}

// A COSE_Key label is an int or a text string (RFC 9052 §7); WebAuthn keys
// use the int labels, so a text label is outside every set.
func TestParseKey_RFC9052_7_textLabel(t *testing.T) {
	t.Parallel()
	es := baseKeys(t)[0].pairs
	key := encodeMap(es...)
	key[0]++ // one more entry
	key = append(key, 0x63, 'k', 'i', 'd', 0x41, 0x01)
	if _, err := cose.ParseKey(key); !errors.Is(err, cose.ErrMalformed) {
		t.Errorf("ParseKey(text label) = %v, want ErrMalformed", err)
	}
}

// Only the curves of the offered algorithms: P-256 for ES256 (RFC 9053 §2.1)
// and Ed25519 for EdDSA (WebAuthn §5.8.5: crv MUST be 6).
func TestParseKey_RFC9053_curveNotOffered(t *testing.T) {
	t.Parallel()
	keys := baseKeys(t)
	es, ed := keys[0].pairs, keys[1].pairs
	cases := []struct {
		name  string
		pairs []pair
	}{
		{"EC2 P-384", with(es, -1, 2)},
		{"EC2 P-521", with(es, -1, 3)},
		{"EC2 secp256k1", with(es, -1, 8)},
		{"OKP Ed448", with(ed, -1, 7)},
		{"OKP X25519", with(ed, -1, 4)},
	}
	for _, c := range cases {
		if _, err := cose.ParseKey(encodeMap(c.pairs...)); !errors.Is(err, cose.ErrUnsupported) {
			t.Errorf("%s: ParseKey = %v, want ErrUnsupported", c.name, err)
		}
	}
}

// COSE algorithms access does not offer (IANA COSE Algorithms;
// WebAuthn §7.1's pubKeyCredParams step): ES384, ES512, PS256, RS384, RS1,
// the fully specified ESP256 and Ed25519, and an unregistered value.
func TestParseKey_algNotOffered(t *testing.T) {
	t.Parallel()
	es := baseKeys(t)[0].pairs
	for _, alg := range []int64{-35, -36, -37, -258, -65535, -9, -19, 0, 1 << 40} {
		if _, err := cose.ParseKey(encodeMap(with(es, 3, alg)...)); !errors.Is(err, cose.ErrUnsupported) {
			t.Errorf("alg %d: ParseKey = %v, want ErrUnsupported", alg, err)
		}
	}
}

// RFC 9053 §7.1.1: y may be a boolean, the compressed form; the label table
// requires a 32-byte string, so the boolean is the wrong type. Coordinates
// are 32 bytes for P-256 (SEC 1 §2.3.3).
func TestParseKey_EC2_coordinates(t *testing.T) {
	t.Parallel()
	es := baseKeys(t)[0].pairs
	x, y := es[3].v.([]byte), es[4].v.([]byte)
	cases := []struct {
		name  string
		pairs []pair
	}{
		{"y true", with(es, -3, true)},
		{"y false", with(es, -3, false)},
		{"x of 31 bytes", with(es, -2, x[1:])},
		{"x of 33 bytes", with(es, -2, append([]byte{0}, x...))},
		{"y of 31 bytes", with(es, -3, y[1:])},
		{"y of 33 bytes", with(es, -3, append([]byte{0}, y...))},
		{"x as an integer", with(es, -2, 5)},
		// The same 64 bytes cut 31 and 33 would read as the published point.
		{"x of 31 and y of 33 bytes", with(with(es, -2, x[:31]), -3, append(slices.Clone(x[31:]), y...))},
	}
	for _, c := range cases {
		if _, err := cose.ParseKey(encodeMap(c.pairs...)); !errors.Is(err, cose.ErrMalformed) {
			t.Errorf("%s: ParseKey = %v, want ErrMalformed", c.name, err)
		}
	}
}

// SEC 1 §3.2.2 public key validation: the point is on the curve and is not
// the point at infinity.
func TestParseKey_EC2_SEC1_3_2_2_pointValidation(t *testing.T) {
	t.Parallel()
	es := baseKeys(t)[0].pairs
	y := es[4].v.([]byte)
	cases := []struct {
		name  string
		pairs []pair
	}{
		{"off the curve", with(es, -3, flipLast(y))},
		{"the point at infinity as (0, 0)", with(with(es, -2, make([]byte, 32)), -3, make([]byte, 32))},
		{"x and y all ones, past p", with(with(es, -2, bytes.Repeat([]byte{0xff}, 32)), -3, bytes.Repeat([]byte{0xff}, 32))},
	}
	for _, c := range cases {
		if _, err := cose.ParseKey(encodeMap(c.pairs...)); !errors.Is(err, cose.ErrMalformed) {
			t.Errorf("%s: ParseKey = %v, want ErrMalformed", c.name, err)
		}
	}
}

// An Ed25519 public key is 32 bytes (RFC 8032 §5.1.5); crypto/ed25519.Verify
// panics on any other length, so the parse refuses it first.
func TestParseKey_OKP_RFC8032_5_1_5_keyLength(t *testing.T) {
	t.Parallel()
	ed := baseKeys(t)[1].pairs
	x := ed[3].v.([]byte)
	for _, bad := range [][]byte{x[1:], append(slices.Clone(x), 0), nil} {
		if _, err := cose.ParseKey(encodeMap(with(ed, -2, bad)...)); !errors.Is(err, cose.ErrMalformed) {
			t.Errorf("x of %d bytes: ParseKey = %v, want ErrMalformed", len(bad), err)
		}
	}
}

// FIPS 204 §4 Table 2: ML-DSA-44, -65 and -87 public keys are 1312, 1952
// and 2592 bytes (RFC 9964 §3's pub).
func TestParseKey_AKP_FIPS204_publicKeySize(t *testing.T) {
	t.Parallel()
	pub := unhex(t, rfc9964(t)[0].PublicKey)
	if len(pub) != 1312 {
		t.Fatalf("RFC 9964 Figure 3 key is %d bytes", len(pub))
	}
	cases := []struct {
		name string
		alg  int64
		pub  []byte
	}{
		{"ML-DSA-44 pub of 1311 bytes", -48, pub[:1311]},
		{"ML-DSA-44 pub of 1313 bytes", -48, append(slices.Clone(pub), 0)},
		{"ML-DSA-65 with a 1312-byte pub", -49, pub},
		{"ML-DSA-87 with a 1312-byte pub", -50, pub},
	}
	for _, c := range cases {
		if _, err := cose.ParseKey(akpKey(c.alg, c.pub)); !errors.Is(err, cose.ErrMalformed) {
			t.Errorf("%s: ParseKey = %v, want ErrMalformed", c.name, err)
		}
	}
}

func rsaKey(n, e []byte) []byte {
	return encodeMap(pair{1, 3}, pair{3, -257}, pair{-1, n}, pair{-2, e})
}

// oddOfBits is the odd integer 2^(bits-1) + 1, as big-endian bytes.
func oddOfBits(bits int) []byte {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return n.Add(n, big.NewInt(1)).Bytes()
}

// RFC 8230 §4: n and e are unsigned big-endian byte strings. A leading zero
// byte, which RFC 8230 §4 says not to send, has one reading, so it is read as
// the integer and the WebAuthn §16.10 signature still verifies. n is 2048 to
// 4096 bits and odd; e is odd, at least 3, below 2^31 (RFC 8017 §3.1).
func TestParseKey_RSA_RFC8230_4(t *testing.T) {
	t.Parallel()
	rs := baseKeys(t)[2].pairs
	n, e := rs[2].v.([]byte), rs[3].v.([]byte)
	a := s16(t)["16.10"].Authentication
	authData, hash, sig := a.bytes(t, "authenticatorData"), sha256.Sum256(a.bytes(t, "clientDataJSON")), a.bytes(t, "signature")

	accepted := []struct {
		name string
		n, e []byte
	}{
		{"n with one leading zero byte", append([]byte{0}, n...), e},
		{"e as 00 01 00 01", n, []byte{0, 1, 0, 1}},
	}
	for _, c := range accepted {
		k, err := cose.ParseKey(rsaKey(c.n, c.e))
		if err != nil {
			t.Errorf("%s: ParseKey = %v, want nil", c.name, err)
			continue
		}
		if err := k.Verify(authData, hash, sig); err != nil {
			t.Errorf("%s: Verify(WebAuthn §16.10) = %v, want nil", c.name, err)
		}
	}

	for _, c := range []struct {
		name string
		n, e []byte
	}{
		{"n of 2048 bits", oddOfBits(2048), e},
		{"n of 4096 bits", oddOfBits(4096), e},
		{"e = 3", n, []byte{3}},
		{"e = 2^31 - 1", n, []byte{0x7f, 0xff, 0xff, 0xff}},
	} {
		if _, err := cose.ParseKey(rsaKey(c.n, c.e)); err != nil {
			t.Errorf("%s: ParseKey = %v, want nil", c.name, err)
		}
	}

	even := oddOfBits(2048)
	even[len(even)-1]--
	for _, c := range []struct {
		name string
		n, e []byte
	}{
		{"n of 2047 bits", oddOfBits(2047), e},
		{"n of 4097 bits", oddOfBits(4097), e},
		{"n even", even, e},
		{"n empty", nil, e},
		{"e = 1", n, []byte{1}},
		{"e = 2", n, []byte{2}},
		{"e = 65536, even", n, []byte{1, 0, 0}},
		{"e = 2^31", n, []byte{0x80, 0, 0, 0}},
		{"e of five significant bytes", n, []byte{1, 0, 0, 0, 1}},
		{"e of nine significant bytes, whose low 64 bits read 3", n, []byte{1, 0, 0, 0, 0, 0, 0, 0, 3}},
		{"e empty", n, nil},
	} {
		if _, err := cose.ParseKey(rsaKey(c.n, c.e)); !errors.Is(err, cose.ErrMalformed) {
			t.Errorf("%s: ParseKey = %v, want ErrMalformed", c.name, err)
		}
	}
	for _, c := range []struct {
		name  string
		pairs []pair
	}{
		{"n as an integer", with(rs, -1, 65537)},
		{"e as an integer", with(rs, -2, 65537)},
	} {
		if _, err := cose.ParseKey(encodeMap(c.pairs...)); !errors.Is(err, cose.ErrMalformed) {
			t.Errorf("%s: ParseKey = %v, want ErrMalformed", c.name, err)
		}
	}
}

// WebAuthn §2.4 asks for CTAP2 canonical CBOR; access compares decoded values
// and departs from that SHOULD, so a key with a non-shortest integer and its
// labels out of order is the same key and verifies WebAuthn §16.2's assertion.
func TestParseKey_WebAuthn2_4_canonicalFormDeparture(t *testing.T) {
	t.Parallel()
	es := baseKeys(t)[0].pairs
	key := encodeMap(
		pair{-3, es[4].v},
		pair{3, raw{0x38, 0x06}}, // -7 in two bytes
		pair{-2, es[3].v},
		pair{1, raw{0x18, 0x02}}, // 2 in two bytes
		pair{-1, 1},
	)
	k, err := cose.ParseKey(key)
	if err != nil {
		t.Fatalf("ParseKey = %v, want nil", err)
	}
	a := s16(t)["16.2"].Authentication
	if err := k.Verify(a.bytes(t, "authenticatorData"), sha256.Sum256(a.bytes(t, "clientDataJSON")), a.bytes(t, "signature")); err != nil {
		t.Errorf("Verify(WebAuthn §16.2) = %v, want nil", err)
	}
}

// WebAuthn §6.5.1: credentialPublicKey is one COSE_Key, CBOR-encoded. A raw
// SEC 1 point (the U2F form some libraries take), another CBOR type, an empty
// input and a byte after the key are not that.
func TestParseKey_WebAuthn6_5_1_oneCOSEKey(t *testing.T) {
	t.Parallel()
	es := baseKeys(t)[0].pairs
	key := encodeMap(es...)
	point := append(append([]byte{4}, es[3].v.([]byte)...), es[4].v.([]byte)...)
	cases := []struct {
		name string
		in   []byte
	}{
		{"a raw uncompressed point", point},
		{"an array", []byte{0x81, 0x01}},
		{"empty", nil},
		{"a byte after the key", append(slices.Clone(key), 0x00)},
		{"the key cut short", key[:len(key)-1]},
		{"a duplicate label", append([]byte{0xa6}, append(slices.Clone(key[1:]), 0x01, 0x02)...)},
	}
	for _, c := range cases {
		if _, err := cose.ParseKey(c.in); !errors.Is(err, cose.ErrMalformed) {
			t.Errorf("%s: ParseKey = %v, want ErrMalformed", c.name, err)
		}
	}
}

func es256Assertion(t testing.TB) (*cose.Key, []byte, [sha256.Size]byte, []byte) {
	t.Helper()
	v := s16(t)["16.2"]
	k, err := cose.ParseKey(credentialKey(t, v.Registration.bytes(t, "attestationObject")))
	if err != nil {
		t.Fatalf("ParseKey(WebAuthn §16.2) = %v", err)
	}
	a := v.Authentication
	return k, a.bytes(t, "authenticatorData"), sha256.Sum256(a.bytes(t, "clientDataJSON")), a.bytes(t, "signature")
}

// CVE-2022-21449: an ECDSA signature with r = s = 0 must not verify
// (SEC 1 §4.1.4 step 1 requires r and s in [1, n-1]).
func TestVerify_CVE_2022_21449(t *testing.T) {
	t.Parallel()
	k, authData, hash, _ := es256Assertion(t)
	for _, sig := range []string{"3006020100020100", "30060201000201ff"} {
		if err := k.Verify(authData, hash, unhex(t, sig)); !errors.Is(err, cose.ErrSignature) {
			t.Errorf("Verify(%s) = %v, want ErrSignature", sig, err)
		}
	}
}

// WebAuthn §6.5.5: an ES256 signature is an ASN.1 DER Ecdsa-Sig-Value
// (RFC 3279 §2.2.3). BER forms of the published WebAuthn §16.2 signature, a
// long-form length or a non-minimal integer, and trailing data are refused
// (X.690 §10.1, §8.3.2).
func TestVerify_WebAuthn6_5_5_DER(t *testing.T) {
	t.Parallel()
	k, authData, hash, sig := es256Assertion(t)
	if sig[0] != 0x30 || int(sig[1]) != len(sig)-2 || sig[2] != 0x02 {
		t.Fatalf("WebAuthn §16.2's signature is not a short-form DER SEQUENCE: %x", sig)
	}
	rLen := int(sig[3])
	r, s := sig[4:4+rLen], sig[4+rLen:]
	longForm := append([]byte{0x30, 0x81, sig[1]}, sig[2:]...)
	padded := append([]byte{0x02, byte(rLen + 1), 0x00}, r...)
	padded = append(padded, s...)
	padded = append([]byte{0x30, byte(len(padded))}, padded...)
	cases := []struct {
		name string
		sig  []byte
	}{
		{"a trailing byte", append(slices.Clone(sig), 0x00)},
		{"a long-form length", longForm},
		{"r with a redundant leading zero", padded},
		{"empty", nil},
	}
	for _, c := range cases {
		if err := k.Verify(authData, hash, c.sig); !errors.Is(err, cose.ErrSignature) {
			t.Errorf("%s: Verify = %v, want ErrSignature", c.name, err)
		}
	}
}

// An Ed25519 signature is 64 bytes (RFC 8032 §5.1.6); any other length is
// refused, not read.
func TestVerify_RFC8032_5_1_7_signatureLength(t *testing.T) {
	t.Parallel()
	v := s16(t)["16.11"]
	k, err := cose.ParseKey(credentialKey(t, v.Registration.bytes(t, "attestationObject")))
	if err != nil {
		t.Fatalf("ParseKey(WebAuthn §16.11) = %v", err)
	}
	a := v.Authentication
	authData, hash, sig := a.bytes(t, "authenticatorData"), sha256.Sum256(a.bytes(t, "clientDataJSON")), a.bytes(t, "signature")
	for _, bad := range [][]byte{sig[:63], append(slices.Clone(sig), 0), nil} {
		if err := k.Verify(authData, hash, bad); !errors.Is(err, cose.ErrSignature) {
			t.Errorf("signature of %d bytes: Verify = %v, want ErrSignature", len(bad), err)
		}
	}
}
