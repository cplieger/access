package cose_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cplieger/access/webauthn/internal/cbor"
	"github.com/cplieger/access/webauthn/internal/cose"
)

type half map[string]string

type s16Vector struct {
	Title          string `json:"title"`
	Registration   half   `json:"registration"`
	Authentication half   `json:"authentication"`
}

func (h half) bytes(t testing.TB, name string) []byte {
	t.Helper()
	v, ok := h[name]
	if !ok {
		t.Fatalf("vector has no %s", name)
	}
	return unhex(t, v)
}

func loadJSON(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func s16(t testing.TB) map[string]s16Vector {
	t.Helper()
	var f struct {
		Vectors map[string]s16Vector `json:"vectors"`
	}
	loadJSON(t, "webauthn-l3-s16.json", &f)
	return f.Vectors
}

// attestationMember returns one member of an attestation object (WebAuthn
// §6.5, the fmt, attStmt and authData map).
func attestationMember(t testing.TB, attObj []byte, name string) cbor.Value {
	t.Helper()
	v, _, err := cbor.Decode(attObj)
	if err != nil {
		t.Fatalf("attestation object: %v", err)
	}
	m, ok := v.Map()
	if !ok {
		t.Fatal("attestation object is not a map")
	}
	for k, val := range m {
		if s, _ := k.Text(); s == name {
			return val
		}
	}
	t.Fatalf("attestation object has no %s", name)
	return cbor.Value{}
}

// credentialKey cuts the credential public key out of a registration's
// authData: rpIdHash (32), flags (1), signCount (4), then the attested
// credential data, AAGUID (16), credentialIdLength (2), credentialId and the
// COSE_Key (WebAuthn §6.1, §6.5.1).
func credentialKey(t testing.TB, attObj []byte) []byte {
	t.Helper()
	authData, ok := attestationMember(t, attObj, "authData").Bytes()
	if !ok {
		t.Fatal("authData is not a byte string")
	}
	if authData[32]&0x40 == 0 {
		t.Fatal("AT clear in a registration's authData")
	}
	p := authData[37+16:]
	n := int(p[0])<<8 | int(p[1])
	p = p[2+n:]
	_, rest, err := cbor.Decode(p)
	if err != nil {
		t.Fatalf("credential public key: %v", err)
	}
	return p[:len(p)-len(rest)]
}

func flipLast(b []byte) []byte {
	c := slices.Clone(b)
	c[len(c)-1] ^= 0x01
	return c
}

// §16's layer of vectors that runs Verify alone: every published assertion
// verifies under its registration's credential public key, and a flipped
// signature byte does not (WebAuthn §7.2's signature step).
func TestVerify_WebAuthn16_assertions(t *testing.T) {
	t.Parallel()
	vectors := s16(t)
	want := map[string]int{
		"16.2": -7, "16.3": -7, "16.4": -7, "16.5": -7, "16.6": -7, "16.7": -7,
		"16.13": -7, "16.14": -7, "16.15": -7, "16.16": -7,
		"16.10": -257, "16.11": -8,
	}
	for sec, alg := range want {
		t.Run(sec, func(t *testing.T) {
			t.Parallel()
			v := vectors[sec]
			k, err := cose.ParseKey(credentialKey(t, v.Registration.bytes(t, "attestationObject")))
			if err != nil {
				t.Fatalf("§%s %s: ParseKey: %v", sec, v.Title, err)
			}
			if k.Algorithm() != alg {
				t.Errorf("§%s: Algorithm() = %d, want %d", sec, k.Algorithm(), alg)
			}
			a := v.Authentication
			authData, hash, sig := a.bytes(t, "authenticatorData"), sha256.Sum256(a.bytes(t, "clientDataJSON")), a.bytes(t, "signature")
			if err := k.Verify(authData, hash, sig); err != nil {
				t.Errorf("§%s: Verify(published assertion) = %v, want nil", sec, err)
			}
			if err := k.Verify(authData, hash, flipLast(sig)); !errors.Is(err, cose.ErrSignature) {
				t.Errorf("§%s: Verify(flipped signature) = %v, want ErrSignature", sec, err)
			}
			if err := k.Verify(flipLast(authData), hash, sig); !errors.Is(err, cose.ErrSignature) {
				t.Errorf("§%s: Verify(flipped authData) = %v, want ErrSignature", sec, err)
			}
		})
	}
}

// ES384 (§16.8), ES512 (§16.9) and Ed448 (§16.12) are not offered, so their
// keys are refused as such (WebAuthn §7.1's pubKeyCredParams step).
func TestParseKey_WebAuthn16_notOffered(t *testing.T) {
	t.Parallel()
	vectors := s16(t)
	for _, sec := range []string{"16.8", "16.9", "16.12"} {
		t.Run(sec, func(t *testing.T) {
			t.Parallel()
			raw := credentialKey(t, vectors[sec].Registration.bytes(t, "attestationObject"))
			if _, err := cose.ParseKey(raw); !errors.Is(err, cose.ErrUnsupported) {
				t.Errorf("§%s: ParseKey = %v, want ErrUnsupported", sec, err)
			}
		})
	}
}

// §16.3's packed self attestation is signed by the credential key over
// authData ‖ SHA-256(clientDataJSON) (WebAuthn §8.2, the self attestation
// branch).
func TestVerify_WebAuthn16_3_selfAttestation(t *testing.T) {
	t.Parallel()
	r := s16(t)["16.3"].Registration
	attObj := r.bytes(t, "attestationObject")
	k, err := cose.ParseKey(credentialKey(t, attObj))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	stmt, ok := attestationMember(t, attObj, "attStmt").Map()
	if !ok {
		t.Fatal("attStmt is not a map")
	}
	var alg int64
	var sig []byte
	for key, val := range stmt {
		switch name, _ := key.Text(); name {
		case "alg":
			alg, _ = val.Int()
		case "sig":
			sig, _ = val.Bytes()
		}
	}
	if alg != int64(k.Algorithm()) {
		t.Errorf("attStmt alg %d, credential key alg %d", alg, k.Algorithm())
	}
	authData, _ := attestationMember(t, attObj, "authData").Bytes()
	hash := sha256.Sum256(r.bytes(t, "clientDataJSON"))
	if err := k.Verify(authData, hash, sig); err != nil {
		t.Errorf("Verify(self attestation) = %v, want nil", err)
	}
	if err := k.Verify(authData, hash, flipLast(sig)); !errors.Is(err, cose.ErrSignature) {
		t.Errorf("Verify(flipped self attestation) = %v, want ErrSignature", err)
	}
}

// keyLabels reads a COSE_Key's byte-string members by label.
func keyLabels(t testing.TB, raw []byte) map[int64][]byte {
	t.Helper()
	v, _, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := v.Map()
	out := map[int64][]byte{}
	for k, val := range m {
		label, _ := k.Int()
		if b, ok := val.Bytes(); ok {
			out[label] = b
		}
	}
	return out
}

// The §16 vectors pin which input each primitive takes: ECDSA (§6.5.5) and
// RSASSA-PKCS1-v1_5 verify SHA-256(M), so the published signature fails
// against M itself or against a second hash, and only Verify's rule passes.
func TestVerify_WebAuthn16_digestRule(t *testing.T) {
	t.Parallel()
	vectors := s16(t)
	message := func(sec string) []byte {
		a := vectors[sec].Authentication
		h := sha256.Sum256(a.bytes(t, "clientDataJSON"))
		return append(a.bytes(t, "authenticatorData"), h[:]...)
	}

	t.Run("16.2 ES256", func(t *testing.T) {
		t.Parallel()
		l := keyLabels(t, credentialKey(t, vectors["16.2"].Registration.bytes(t, "attestationObject")))
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, l[-2]...), l[-3]...))
		if err != nil {
			t.Fatal(err)
		}
		m, sig := message("16.2"), vectors["16.2"].Authentication.bytes(t, "signature")
		d := sha256.Sum256(m)
		dd := sha256.Sum256(d[:])
		if !ecdsa.VerifyASN1(pub, d[:], sig) {
			t.Fatal("the vector does not verify over SHA-256(M)")
		}
		if ecdsa.VerifyASN1(pub, m, sig) {
			t.Error("the vector verifies with M handed to VerifyASN1")
		}
		if ecdsa.VerifyASN1(pub, dd[:], sig) {
			t.Error("the vector verifies over SHA-256(SHA-256(M))")
		}
	})

	t.Run("16.10 RS256", func(t *testing.T) {
		t.Parallel()
		l := keyLabels(t, credentialKey(t, vectors["16.10"].Registration.bytes(t, "attestationObject")))
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(l[-1]), E: int(new(big.Int).SetBytes(l[-2]).Int64())}
		m, sig := message("16.10"), vectors["16.10"].Authentication.bytes(t, "signature")
		d := sha256.Sum256(m)
		dd := sha256.Sum256(d[:])
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig); err != nil {
			t.Fatalf("the vector does not verify over SHA-256(M): %v", err)
		}
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, m, sig) == nil {
			t.Error("the vector verifies with M handed to VerifyPKCS1v15")
		}
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, dd[:], sig) == nil {
			t.Error("the vector verifies over SHA-256(SHA-256(M))")
		}
	})
}

// §6.5.1.1's examples: the one complete key (EC2, ES256) parses from its
// published CTAP2 canonical encoding; the RSA examples publish n's length and
// ends but elide its middle, so the RS256 one is built from its label set with
// those ends and a filled middle, and PS256 (-37) is not offered.
func TestParseKey_WebAuthn6_5_1_1(t *testing.T) {
	t.Parallel()
	var f struct {
		EC2 struct {
			X        string `json:"x"`
			Y        string `json:"y"`
			Encoding string `json:"ctap2_canonical_encoding"`
		} `json:"ec2_es256"`
		RSA []struct {
			Alg      int64  `json:"alg"`
			NLength  int    `json:"n_length"`
			NFirst   string `json:"n_first_hex"`
			NLastHex string `json:"n_last_hex"`
			E        string `json:"e"`
		} `json:"rsa"`
	}
	loadJSON(t, "webauthn-l3-s6.5.1.1.json", &f)

	t.Run("EC2 ES256", func(t *testing.T) {
		t.Parallel()
		k, err := cose.ParseKey(unhex(t, f.EC2.Encoding))
		if err != nil {
			t.Fatalf("ParseKey = %v", err)
		}
		if k.Algorithm() != -7 {
			t.Errorf("Algorithm() = %d, want -7", k.Algorithm())
		}
		built := encodeMap(pair{1, 2}, pair{3, -7}, pair{-1, 1}, pair{-2, unhex(t, f.EC2.X)}, pair{-3, unhex(t, f.EC2.Y)})
		if _, err := cose.ParseKey(built); err != nil {
			t.Errorf("ParseKey(the CDDL form with the published x and y) = %v", err)
		}
	})

	for _, r := range f.RSA {
		n := make([]byte, r.NLength)
		for i := range n {
			n[i] = 0x5a
		}
		copy(n, unhex(t, r.NFirst))
		last := r.NLastHex[len(r.NLastHex)-2:]
		copy(n[len(n)-1:], unhex(t, last))
		key := encodeMap(pair{1, 3}, pair{3, r.Alg}, pair{-1, n}, pair{-2, unhex(t, r.E)})
		_, err := cose.ParseKey(key)
		switch r.Alg {
		case -257:
			if err != nil {
				t.Errorf("RS256 example: ParseKey = %v, want nil", err)
			}
		default:
			if !errors.Is(err, cose.ErrUnsupported) {
				t.Errorf("alg %d example: ParseKey = %v, want ErrUnsupported", r.Alg, err)
			}
		}
	}
}

type rfc9964Example struct {
	Appendix     string `json:"appendix"`
	Figure       int    `json:"figure"`
	ParameterSet string `json:"parameter_set"`
	PublicKey    string `json:"raw_public_key"`
	ToBeSigned   string `json:"raw_to_be_signed"`
	Signature    string `json:"raw_signature"`
	COSEKey      string `json:"cose_key"`
}

var mldsaAlg = map[string]int64{"ML-DSA-44": -48, "ML-DSA-65": -49, "ML-DSA-87": -50}

func rfc9964(t testing.TB) []rfc9964Example {
	t.Helper()
	var f struct {
		Examples []rfc9964Example `json:"examples"`
	}
	loadJSON(t, "rfc9964-appendix-a.json", &f)
	return f.Examples
}

// akpKey is an AKP credential public key with exactly kty, alg and pub
// (RFC 9964 §3, WebAuthn §6.5.1).
func akpKey(alg int64, pub []byte) []byte {
	return encodeMap(pair{1, 7}, pair{3, alg}, pair{-1, pub})
}

// verifySplit hands Verify a message M cut so that its last 32 bytes stand in
// for clientDataHash; Verify must sign the concatenation, nothing else.
func verifySplit(k *cose.Key, m, sig []byte) error {
	return k.Verify(m[:len(m)-sha256.Size], [sha256.Size]byte(m[len(m)-sha256.Size:]), sig)
}

// RFC 9964 Appendix A's six signatures verify through Verify's ML-DSA arm:
// pure ML-DSA with the empty context (RFC 9964 §5, FIPS 204 §5.4).
func TestVerify_RFC9964AppendixA(t *testing.T) {
	t.Parallel()
	for _, e := range rfc9964(t) {
		t.Run(e.ParameterSet+" "+e.Appendix, func(t *testing.T) {
			t.Parallel()
			k, err := cose.ParseKey(akpKey(mldsaAlg[e.ParameterSet], unhex(t, e.PublicKey)))
			if err != nil {
				t.Fatalf("Figure %d: ParseKey = %v", e.Figure, err)
			}
			if int64(k.Algorithm()) != mldsaAlg[e.ParameterSet] {
				t.Errorf("Algorithm() = %d", k.Algorithm())
			}
			m, sig := unhex(t, e.ToBeSigned), unhex(t, e.Signature)
			if err := verifySplit(k, m, sig); err != nil {
				t.Errorf("Figure %d: Verify = %v, want nil", e.Figure, err)
			}
			if err := verifySplit(k, m, flipLast(sig)); !errors.Is(err, cose.ErrSignature) {
				t.Errorf("Figure %d: Verify(flipped signature) = %v, want ErrSignature", e.Figure, err)
			}
		})
	}
}

// RFC 9964 Appendix A.2's COSE keys carry kid (2) and the private seed priv
// (-2), which a credential public key may not (WebAuthn §6.5.1: no other
// optional parameter), so each is refused whole.
func TestParseKey_RFC9964AppendixA2_privateMembers(t *testing.T) {
	t.Parallel()
	for _, e := range rfc9964(t) {
		if e.COSEKey == "" {
			continue
		}
		if _, err := cose.ParseKey(unhex(t, e.COSEKey)); !errors.Is(err, cose.ErrMalformed) {
			t.Errorf("Figure %d: ParseKey = %v, want ErrMalformed", e.Figure, err)
		}
	}
}

// NIST ACVP ML-DSA sigVer, the pure empty-context expected-failure cases:
// each is refused by the same Verify the ceremony calls (FIPS 204 §5.3).
func TestVerify_ACVP_MLDSA_sigVer(t *testing.T) {
	t.Parallel()
	var f struct {
		Cases []struct {
			TcID         int    `json:"tcId"`
			ParameterSet string `json:"parameterSet"`
			TestPassed   bool   `json:"testPassed"`
			Context      string `json:"context"`
			PK           string `json:"pk"`
			Message      string `json:"message"`
			Signature    string `json:"signature"`
		} `json:"cases"`
	}
	loadJSON(t, "acvp-mldsa-sigver.json", &f)
	if len(f.Cases) != 3 {
		t.Fatalf("%d cases, want tcId 10, 39 and 64", len(f.Cases))
	}
	for _, c := range f.Cases {
		t.Run(c.ParameterSet, func(t *testing.T) {
			t.Parallel()
			if c.TestPassed || c.Context != "" {
				t.Fatalf("tcId %d is not an empty-context expected failure", c.TcID)
			}
			k, err := cose.ParseKey(akpKey(mldsaAlg[c.ParameterSet], unhex(t, c.PK)))
			if err != nil {
				t.Fatalf("tcId %d: ParseKey = %v", c.TcID, err)
			}
			if err := verifySplit(k, unhex(t, c.Message), unhex(t, c.Signature)); !errors.Is(err, cose.ErrSignature) {
				t.Errorf("tcId %d: Verify = %v, want ErrSignature", c.TcID, err)
			}
		})
	}
}

// ParseKey's contract: the key keeps no reference to the bytes it was read
// from, so a caller may reuse its buffer.
func TestParseKey_doesNotAliasInput(t *testing.T) {
	t.Parallel()
	vectors := s16(t)
	for _, sec := range []string{"16.2", "16.10", "16.11"} {
		v := vectors[sec]
		raw := slices.Clone(credentialKey(t, v.Registration.bytes(t, "attestationObject")))
		k, err := cose.ParseKey(raw)
		if err != nil {
			t.Fatalf("§%s: ParseKey = %v", sec, err)
		}
		clear(raw)
		a := v.Authentication
		if err := k.Verify(a.bytes(t, "authenticatorData"), sha256.Sum256(a.bytes(t, "clientDataJSON")), a.bytes(t, "signature")); err != nil {
			t.Errorf("§%s: Verify after the input was overwritten = %v, want nil", sec, err)
		}
	}
	e := rfc9964(t)[0]
	raw := akpKey(mldsaAlg[e.ParameterSet], unhex(t, e.PublicKey))
	k, err := cose.ParseKey(raw)
	if err != nil {
		t.Fatalf("ParseKey(RFC 9964 Figure %d) = %v", e.Figure, err)
	}
	clear(raw)
	if err := verifySplit(k, unhex(t, e.ToBeSigned), unhex(t, e.Signature)); err != nil {
		t.Errorf("ML-DSA: Verify after the input was overwritten = %v, want nil", err)
	}
}
