package webauthn

import (
	"bytes"
	"testing"

	"github.com/cplieger/access/webauthn/internal/cose"
)

// TestFinishRegistration_WebAuthn16_asPublished runs every §16 registration
// half through the whole finish as published, each answering its own
// ceremony: WebAuthn §16.3's self attestation registers, and every other half
// stops at its first refusal in WebAuthn §7.1's step order.
func TestFinishRegistration_WebAuthn16_asPublished(t *testing.T) {
	t.Parallel()
	// From each half's published client data, flags octet, credential key and
	// fmt (WebAuthn §16): vectors 16.4 and 16.5 are framed; 16.2, 16.6, 16.8,
	// 16.11, 16.12, 16.15 and 16.16 have UV clear; 16.9's key is ES512 (-36);
	// 16.7 and 16.10 are packed with x5c, 16.13 tpm, 16.14 android-key.
	refusals := map[string]error{
		"16.2": errUserVerification, "16.4": errFramed, "16.5": errFramed, "16.6": errUserVerification,
		"16.7": errAttestationFormat, "16.8": errUserVerification, "16.9": cose.ErrUnsupported,
		"16.10": errAttestationFormat, "16.11": errUserVerification, "16.12": errUserVerification,
		"16.13": errAttestationFormat, "16.14": errAttestationFormat, "16.15": errUserVerification,
		"16.16": errUserVerification,
	}
	vectors := s16(t)
	if len(vectors) != len(refusals)+1 {
		t.Fatalf("%d vectors, want %d", len(vectors), len(refusals)+1)
	}
	for section, v := range vectors {
		t.Run(section, func(t *testing.T) {
			t.Parallel()
			c := regCaseWith(t, section, v.Registration.bytes(t, "attestationObject"))
			want, refused := refusals[section]
			if refused {
				wantRefused(t, c, want)
				return
			}
			rec, err := c.finish(t)
			if err != nil {
				t.Fatalf("finishRegistration = %v, want a record", err)
			}
			wantVectorRecord(t, v, vectorAuthData(t, v), rec.CredentialID, rec.PublicKey, rec.AAGUID)
		})
	}
}

// TestFinishRegistration_WebAuthn16_rebuilt registers the ES256 credential
// of WebAuthn §16.2, the RS256 of WebAuthn §16.10 and the Ed25519 of
// WebAuthn §16.11, each half's authData with UV set under a none
// attestation, and checks the record against the vector's bytes.
func TestFinishRegistration_WebAuthn16_rebuilt(t *testing.T) {
	t.Parallel()
	for section, flags := range map[string]uint8{"16.2": 0x5d, "16.10": 0x5d, "16.11": 0x45} {
		t.Run(section, func(t *testing.T) {
			t.Parallel()
			v := s16Section(t, section)
			rec, err := noneCase(t, section).finish(t)
			if err != nil {
				t.Fatalf("finishRegistration = %v, want a record", err)
			}
			wantVectorRecord(t, v, uvSet(t, v), rec.CredentialID, rec.PublicKey, rec.AAGUID)
			if rec.RawFlags != flags || rec.SignCount != 0 {
				t.Errorf("RawFlags %#x, SignCount %d; want %#x and the published 0", rec.RawFlags, rec.SignCount, flags)
			}
		})
	}
}

// wantVectorRecord compares a record's credential ID, key and AAGUID with
// the vector's published credential_id and aaguid and the key bytes after
// the ID in authData (WebAuthn §6.5.1).
func wantVectorRecord(t *testing.T, v s16Vector, authData, id, key, aaguid []byte) {
	t.Helper()
	wantID := v.Registration.bytes(t, "credential_id")
	if !bytes.Equal(id, wantID) {
		t.Errorf("CredentialID = %x, want %x", id, wantID)
	}
	if wantKey := authData[55+len(wantID):]; !bytes.Equal(key, wantKey) {
		t.Errorf("PublicKey = %x, want %x", key, wantKey)
	}
	if want := v.Registration.bytes(t, "aaguid"); !bytes.Equal(aaguid, want) {
		t.Errorf("AAGUID = %x, want %x", aaguid, want)
	}
}
