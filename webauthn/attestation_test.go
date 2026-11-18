package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cplieger/access/webauthn/internal/cbor"
	"github.com/cplieger/access/webauthn/internal/cose"
)

// selfAttestation is WebAuthn §16.3's packed self attestation, taken apart
// with the CBOR decoder: its authData, its sig, the credential key it signed
// with and SHA-256 of its clientDataJSON.
type selfAttestation struct {
	key      *cose.Key
	authData []byte
	sig      []byte
	hash     [sha256.Size]byte
}

func s16_3(t *testing.T) selfAttestation {
	t.Helper()
	v := s16Section(t, "16.3")
	authData := vectorAuthData(t, v)
	key, err := cose.ParseKey(authData[55+len(v.Registration.bytes(t, "credential_id")):])
	if err != nil {
		t.Fatal(err)
	}
	obj, _, err := cbor.Decode(v.Registration.bytes(t, "attestationObject"))
	if err != nil {
		t.Fatal(err)
	}
	var sig []byte
	entries, _ := obj.Map()
	for k, val := range entries {
		if name, _ := k.Text(); name == "attStmt" {
			stmt, _ := val.Map()
			for sk, sv := range stmt {
				if n, _ := sk.Text(); n == "sig" {
					sig, _ = sv.Bytes()
				}
			}
		}
	}
	if sig == nil {
		t.Fatal("WebAuthn §16.3 has no sig")
	}
	return selfAttestation{key: key, authData: authData, sig: sig, hash: sha256.Sum256(v.Registration.bytes(t, "clientDataJSON"))}
}

func attObj(format, stmt, authData any) []byte {
	return cborEnc(cborMap{"fmt", format, "attStmt", stmt, "authData", authData})
}

// TestParseAttestationObject_WebAuthn6_5_4 checks the attestation object's
// shape: one CBOR map of exactly fmt (text), attStmt (map) and authData
// (bytes), with nothing after it; its key order is not checked (WebAuthn §2.4's
// canonical form, a stated departure in docs/webauthn.md).
func TestParseAttestationObject_WebAuthn6_5_4(t *testing.T) {
	t.Parallel()
	s := s16_3(t)
	none := cborMap{}
	for _, c := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"none", attObj("none", none, s.authData), nil},
		{"members in another order", cborEnc(cborMap{"authData", s.authData, "attStmt", none, "fmt", "none"}), nil},
		{"an array", cborEnc([]any{"none", none, s.authData}), errAttestationObject},
		{"fmt missing", cborEnc(cborMap{"attStmt", none, "authData", s.authData}), errAttestationObject},
		{"attStmt missing", cborEnc(cborMap{"fmt", "none", "authData", s.authData}), errAttestationObject},
		{"authData missing", cborEnc(cborMap{"fmt", "none", "attStmt", none}), errAttestationObject},
		{"a fourth member", cborEnc(cborMap{"fmt", "none", "attStmt", none, "authData", s.authData, "epAtt", true}), errAttestationObject},
		{"an integer key", cborEnc(cborMap{1, "none", "attStmt", none, "authData", s.authData}), errAttestationObject},
		{"fmt as bytes", attObj([]byte("none"), none, s.authData), errAttestationObject},
		{"attStmt as an array", attObj("none", []any{}, s.authData), errAttestationObject},
		{"authData as text", attObj("none", none, string(s.authData)), errAttestationObject},
		{"a duplicate fmt", cborEnc(cborMap{"fmt", "none", "fmt", "none", "attStmt", none, "authData", s.authData}), errAttestationObject},
		{"a byte after it", append(attObj("none", none, s.authData), 0), errAttestationObject},
		{"cut short", attObj("none", none, s.authData)[:20], errAttestationObject},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			o, err := parseAttestationObject(c.raw)
			if c.want != nil {
				if !errors.Is(err, c.want) {
					t.Errorf("parseAttestationObject = %v, want %v", err, c.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAttestationObject = %v, want accepted", err)
			}
			if o.format != "none" || !bytes.Equal(o.authData, s.authData) {
				t.Errorf("fmt %q, authData %x; want none and the bytes sent", o.format, o.authData)
			}
		})
	}
}

// TestVerifyStatement_WebAuthn8_7_none checks the none format: fmt exactly
// none (WebAuthn §7.1's USASCII case-sensitive match) with an empty attStmt.
func TestVerifyStatement_WebAuthn8_7_none(t *testing.T) {
	t.Parallel()
	s := s16_3(t)
	for _, c := range []struct {
		name   string
		format string
		stmt   cborMap
		want   error
	}{
		{"an empty statement", "none", cborMap{}, nil},
		{"a statement with a member", "none", cborMap{"sig", s.sig}, errAttestationStatement},
		{"a statement with an integer member", "none", cborMap{1, 1}, errAttestationStatement},
		{"fmt None", "None", cborMap{}, errAttestationFormat},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := statementResult(t, c.format, c.stmt, s.authData, s)
			if c.want == nil && err != nil {
				t.Errorf("verifyStatement = %v, want accepted", err)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("verifyStatement = %v, want %v", err, c.want)
			}
		})
	}
}

// statementResult runs verifyStatement on an attestation object built
// directly, so the statement check is tested apart from the object parser.
func statementResult(t *testing.T, format string, stmt cborMap, authData []byte, s selfAttestation) error {
	t.Helper()
	v, _, err := cbor.Decode(cborEnc(stmt))
	if err != nil {
		t.Fatal(err)
	}
	o := &attestationObject{format: format, statement: v, authData: authData}
	return o.verifyStatement(s.key, s.hash)
}

// TestVerifyStatement_WebAuthn8_2_self checks packed without x5c, §8.2's self
// attestation: exactly an integer alg equal to the credential key's and a
// byte string sig verifying under it over authData ‖ clientDataHash. packed
// with x5c, and every other format, is refused as a format: access accepts
// only none and self attestation (WebAuthn §5.4.7's default conveyance).
func TestVerifyStatement_WebAuthn8_2_self(t *testing.T) {
	t.Parallel()
	s := s16_3(t)
	flipped := bytes.Clone(s.sig)
	flipped[len(flipped)-1] ^= 1
	otherAuthData := bytes.Clone(s.authData)
	otherAuthData[33] ^= 1 // the signCount, which the signature covers
	for _, c := range []struct {
		name     string
		format   string
		stmt     cborMap
		authData []byte
		want     error
	}{
		{"WebAuthn §16.3 as published", "packed", cborMap{"alg", -7, "sig", s.sig}, s.authData, nil},
		{"members in another order", "packed", cborMap{"sig", s.sig, "alg", -7}, s.authData, nil},
		{"a flipped signature byte", "packed", cborMap{"alg", -7, "sig", flipped}, s.authData, errAttestationSignature},
		{"authData other than the signed", "packed", cborMap{"alg", -7, "sig", s.sig}, otherAuthData, errAttestationSignature},
		{"alg not the key's", "packed", cborMap{"alg", -8, "sig", s.sig}, s.authData, errAttestationStatement},
		{"alg as text", "packed", cborMap{"alg", "-7", "sig", s.sig}, s.authData, errAttestationStatement},
		{"sig as text", "packed", cborMap{"alg", -7, "sig", hex.EncodeToString(s.sig)}, s.authData, errAttestationStatement},
		{"sig missing", "packed", cborMap{"alg", -7}, s.authData, errAttestationStatement},
		{"alg missing", "packed", cborMap{"sig", s.sig}, s.authData, errAttestationStatement},
		{"a third member", "packed", cborMap{"alg", -7, "sig", s.sig, "ver", "2.0"}, s.authData, errAttestationStatement},
		{"an integer member", "packed", cborMap{"alg", -7, "sig", s.sig, 1, 1}, s.authData, errAttestationStatement},
		{"x5c", "packed", cborMap{"alg", -7, "sig", s.sig, "x5c", []any{[]byte{0x30}}}, s.authData, errAttestationFormat},
		{"tpm", "tpm", cborMap{}, s.authData, errAttestationFormat},
		{"android-key", "android-key", cborMap{}, s.authData, errAttestationFormat},
		{"android-safetynet", "android-safetynet", cborMap{}, s.authData, errAttestationFormat},
		{"fido-u2f", "fido-u2f", cborMap{"sig", s.sig}, s.authData, errAttestationFormat},
		{"apple", "apple", cborMap{}, s.authData, errAttestationFormat},
		{"compound", "compound", cborMap{}, s.authData, errAttestationFormat},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := statementResult(t, c.format, c.stmt, c.authData, s)
			if c.want == nil && err != nil {
				t.Errorf("verifyStatement = %v, want accepted", err)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("verifyStatement = %v, want %v", err, c.want)
			}
		})
	}
}
