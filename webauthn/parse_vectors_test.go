package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cplieger/access/webauthn/internal/cbor"
	"github.com/cplieger/access/webauthn/internal/cose"
)

// The relying party and origin every WebAuthn L3 §16 vector is made for.
const (
	vectorRPID   = "example.org"
	vectorOrigin = "https://example.org"
)

type vectorHalf map[string]string

type s16Vector struct {
	Registration   vectorHalf `json:"registration"`
	Authentication vectorHalf `json:"authentication"`
}

func (h vectorHalf) bytes(t testing.TB, name string) []byte {
	t.Helper()
	v, ok := h[name]
	if !ok {
		t.Fatalf("vector has no %s", name)
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

// s16 returns WebAuthn L3 §16.2 to §16.16 as published, keyed by section.
func s16(t testing.TB) map[string]s16Vector {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "vectors", "webauthn-l3-s16.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors map[string]s16Vector `json:"vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Vectors
}

func s16Section(t testing.TB, section string) s16Vector {
	t.Helper()
	v, ok := s16(t)[section]
	if !ok {
		t.Fatalf("no §%s vector", section)
	}
	return v
}

// vectorAuthData returns a registration half's authData, read from its
// published attestation object with the CBOR decoder alone.
func vectorAuthData(t testing.TB, v s16Vector) []byte {
	t.Helper()
	obj, _, err := cbor.Decode(v.Registration.bytes(t, "attestationObject"))
	if err != nil {
		t.Fatalf("attestation object: %v", err)
	}
	entries, _ := obj.Map()
	for key, val := range entries {
		if name, _ := key.Text(); name == "authData" {
			b, _ := val.Bytes()
			return b
		}
	}
	t.Fatal("attestation object has no authData")
	return nil
}

// TestParseVectors_WebAuthn16_attestationObject is layer 2 at the
// attestation object: every §16 registration half parses to its published
// fmt, and its authData to the published AAGUID and credential ID, with the
// key's bytes kept as received (§6.5.1) and the AAGUID kept whatever the
// format (§18.1.1).
func TestParseVectors_WebAuthn16_attestationObject(t *testing.T) {
	t.Parallel()
	formats := map[string]string{
		"16.2": "none", "16.3": "packed", "16.4": "none", "16.5": "none", "16.6": "none",
		"16.7": "packed", "16.8": "packed", "16.9": "packed", "16.10": "packed", "16.11": "packed",
		"16.12": "packed", "16.13": "tpm", "16.14": "android-key", "16.15": "apple", "16.16": "fido-u2f",
	}
	vectors := s16(t)
	if len(vectors) != len(formats) {
		t.Fatalf("%d vectors, want %d", len(vectors), len(formats))
	}
	for section, v := range vectors {
		t.Run(section, func(t *testing.T) {
			t.Parallel()
			o, err := parseAttestationObject(v.Registration.bytes(t, "attestationObject"))
			if err != nil {
				t.Fatalf("parseAttestationObject: %v", err)
			}
			if o.format != formats[section] {
				t.Errorf("fmt = %q, want %q", o.format, formats[section])
			}
			a, err := parseAuthData(o.authData)
			if err != nil {
				t.Fatalf("parseAuthData: %v", err)
			}
			want := sha256.Sum256([]byte(vectorRPID))
			if !bytes.Equal(a.rpIDHash, want[:]) {
				t.Errorf("rpIdHash = %x, want SHA-256(%q)", a.rpIDHash, vectorRPID)
			}
			if a.attested == nil {
				t.Fatal("no attested credential data")
			}
			if aaguid := v.Registration.bytes(t, "aaguid"); !bytes.Equal(a.attested.aaguid, aaguid) {
				t.Errorf("AAGUID = %x, want %x", a.attested.aaguid, aaguid)
			}
			id := v.Registration.bytes(t, "credential_id")
			if !bytes.Equal(a.attested.id, id) {
				t.Errorf("credential ID = %x, want %x", a.attested.id, id)
			}
			// No §16 vector carries extensions, so the key ends authData.
			if keyAt := minAuthDataBytes + attestedHeadBytes + len(id); !bytes.Equal(a.attested.publicKey, o.authData[keyAt:]) {
				t.Errorf("credential public key = %x, want the bytes after the credential ID, %x", a.attested.publicKey, o.authData[keyAt:])
			}
		})
	}
}

// TestParseVectors_WebAuthn16_statement is layer 2 at the statement: the none
// statements of §16.2 and §16.4 to §16.6 and §16.3's self attestation are
// accepted (§8.7, §8.2), and every other published format, packed with x5c
// included, is refused as a format.
func TestParseVectors_WebAuthn16_statement(t *testing.T) {
	t.Parallel()
	for section, v := range s16(t) {
		t.Run(section, func(t *testing.T) {
			t.Parallel()
			o, err := parseAttestationObject(v.Registration.bytes(t, "attestationObject"))
			if err != nil {
				t.Fatalf("parseAttestationObject: %v", err)
			}
			a, err := parseAuthData(o.authData)
			if err != nil {
				t.Fatalf("parseAuthData: %v", err)
			}
			// §16.8, §16.9 and §16.12's keys are not offered; their packed
			// statements carry x5c, refused before the key is read.
			key, _ := cose.ParseKey(a.attested.publicKey)
			hash := sha256.Sum256(v.Registration.bytes(t, "clientDataJSON"))
			err = o.verifyStatement(key, hash)
			switch section {
			case "16.2", "16.3", "16.4", "16.5", "16.6":
				if err != nil {
					t.Errorf("verifyStatement = %v, want accepted", err)
				}
			default:
				if !errors.Is(err, errAttestationFormat) {
					t.Errorf("verifyStatement = %v, want errAttestationFormat", err)
				}
			}
		})
	}
}

// TestParseVectors_WebAuthn16_registrationAuthData runs §7.1's
// authenticator-data steps on every published registration half, each
// stopping at its first refusal in step order: UV, then the algorithm.
func TestParseVectors_WebAuthn16_registrationAuthData(t *testing.T) {
	t.Parallel()
	// From each half's published flags octet and credential key: §16.2,
	// §16.5, §16.6, §16.8, §16.11, §16.12, §16.15 and §16.16 have UV clear;
	// §16.9's key is ES512 (-36).
	refusals := map[string]error{
		"16.2": errUserVerification, "16.5": errUserVerification, "16.6": errUserVerification,
		"16.8": errUserVerification, "16.11": errUserVerification, "16.12": errUserVerification,
		"16.15": errUserVerification, "16.16": errUserVerification, "16.9": cose.ErrUnsupported,
	}
	for section, v := range s16(t) {
		t.Run(section, func(t *testing.T) {
			t.Parallel()
			_, key, err := registrationAuthData(vectorAuthData(t, v), vectorRPID, v.Registration.bytes(t, "credential_id"))
			want, refused := refusals[section]
			switch {
			case refused && !errors.Is(err, want):
				t.Errorf("registrationAuthData = %v, want %v", err, want)
			case !refused && err != nil:
				t.Errorf("registrationAuthData = %v, want accepted", err)
			case !refused && key == nil:
				t.Error("no credential key")
			}
		})
	}
}

// TestParseVectors_WebAuthn16_assertionAuthData runs §7.2's
// authenticator-data steps on every published authentication half: those
// with UV set are accepted and every other is refused at UV.
func TestParseVectors_WebAuthn16_assertionAuthData(t *testing.T) {
	t.Parallel()
	// From each half's published flags octet.
	uvSet := map[string]bool{"16.4": true, "16.5": true, "16.6": true, "16.7": true, "16.8": true, "16.12": true, "16.13": true}
	for section, v := range s16(t) {
		t.Run(section, func(t *testing.T) {
			t.Parallel()
			a, err := assertionAuthData(v.Authentication.bytes(t, "authenticatorData"), vectorRPID)
			if uvSet[section] {
				if err != nil {
					t.Fatalf("assertionAuthData = %v, want accepted", err)
				}
				if a.signCount != 0 {
					t.Errorf("signCount = %d, want the published 0", a.signCount)
				}
				return
			}
			if !errors.Is(err, errUserVerification) {
				t.Errorf("assertionAuthData = %v, want errUserVerification", err)
			}
		})
	}
}

// TestParseVectors_WebAuthn16_framed checks §16.4's crossOrigin and §16.5's
// topOrigin client data, both halves as published, refused as framed
// (§5.8.1; access is never framed).
func TestParseVectors_WebAuthn16_framed(t *testing.T) {
	t.Parallel()
	origin := mustParseOrigin(t, vectorOrigin)
	for _, section := range []string{"16.4", "16.5"} {
		v := s16Section(t, section)
		halves := []struct {
			name string
			half vectorHalf
			typ  clientDataType
		}{
			{"registration", v.Registration, clientDataCreate},
			{"authentication", v.Authentication, clientDataGet},
		}
		for _, h := range halves {
			t.Run(section+" "+h.name, func(t *testing.T) {
				t.Parallel()
				_, err := verifyClientData(h.half.bytes(t, "clientDataJSON"), h.typ, h.half.bytes(t, "challenge"), origin)
				if !errors.Is(err, errFramed) {
					t.Errorf("verifyClientData = %v, want errFramed", err)
				}
			})
		}
	}
}
