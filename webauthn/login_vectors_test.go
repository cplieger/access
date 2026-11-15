package webauthn

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn/internal/cose"
)

// vectorCredential is the record of section's registration half as
// published, read at §6.1's and §6.5.1's offsets: its credential ID, the
// key's bytes as received and its flags octet.
func vectorCredential(t testing.TB, section string) access.PasskeyCredential {
	t.Helper()
	v := s16Section(t, section)
	a := vectorAuthData(t, v)
	id := v.Registration.bytes(t, "credential_id")
	return access.PasskeyCredential{UserID: 42, CredentialID: id, PublicKey: a[55+len(id):], RawFlags: a[32], RPID: vectorRPID}
}

// TestVerifyLogin_WebAuthn16_asPublished runs every §16 authentication half
// through both finishes as published, against its registration's record:
// §16.6, §16.7 and §16.13 sign in, and every other half stops at its first
// refusal in §7.2's step order.
func TestVerifyLogin_WebAuthn16_asPublished(t *testing.T) {
	t.Parallel()
	// From each half's published client data, flags octet and its
	// registration's credential key: §16.4 and §16.5 are framed; §16.2,
	// §16.3, §16.9, §16.10, §16.11, §16.14, §16.15 and §16.16 have UV clear;
	// §16.8's key is ES384 (-35) and §16.12's Ed448.
	refusals := map[string]error{
		"16.2": errUserVerification, "16.3": errUserVerification, "16.4": errFramed, "16.5": errFramed,
		"16.8": cose.ErrUnsupported, "16.9": errUserVerification, "16.10": errUserVerification,
		"16.11": errUserVerification, "16.12": cose.ErrUnsupported, "16.14": errUserVerification,
		"16.15": errUserVerification, "16.16": errUserVerification,
	}
	vectors := s16(t)
	if len(vectors) != len(refusals)+3 {
		t.Fatalf("%d vectors, want %d", len(vectors), len(refusals)+3)
	}
	for section, v := range vectors {
		for _, k := range bothKinds {
			t.Run(section+" "+k.name, func(t *testing.T) {
				t.Parallel()
				c := assertCase(t, k.kind, v.Authentication, vectorCredential(t, section))
				res, err := c.finish(t)
				if want, refused := refusals[section]; refused {
					wantNoLogin(t, c, res, err, want)
					return
				}
				wantLoggedIn(t, c, res, err)
				if res.CloneWarning {
					t.Error("CloneWarning set with both counts the published 0")
				}
			})
		}
	}
}

// TestVerifyLogin_WebAuthn16_resigned signs in §16.2's and §16.3's ES256,
// §16.10's RS256 and §16.11's Ed25519 credentials through both finishes,
// against the records finishRegistration stored: each authentication half
// with UV set and BE as registered, signed anew with the vector's private
// key.
func TestVerifyLogin_WebAuthn16_resigned(t *testing.T) {
	t.Parallel()
	for _, section := range []string{"16.2", "16.3", "16.10", "16.11"} {
		for _, k := range bothKinds {
			t.Run(section+" "+k.name, func(t *testing.T) {
				t.Parallel()
				c := resigned(t, k.kind, section)
				res, err := c.finish(t)
				wantLoggedIn(t, c, res, err)
				if got := c.store.recorded[0].upd; got.RawFlags != c.authData[32] || got.SignCount != 0 {
					t.Errorf("written %+v, want RawFlags %#x and the published 0", got, c.authData[32])
				}
			})
		}
	}
}

// mldsaCredential registers an ML-DSA credential of alg (RFC 9964 §5) from a
// fixed seed through finishRegistration, and returns the signer and the
// stored record.
func mldsaCredential(t *testing.T, alg int, params mldsa.Parameters, seed byte) (*mldsa.PrivateKey, access.PasskeyCredential) {
	t.Helper()
	sk, err := mldsa.NewPrivateKey(params, bytes.Repeat([]byte{seed}, mldsa.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}
	id := []byte("ml-dsa credential")
	rpIDHash := sha256.Sum256([]byte(vectorRPID))
	authData := append(rpIDHash[:], 0x45, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(id)))
	authData = append(append(authData, id...), cborEnc(cborMap{1, 7, 3, alg, -1, sk.PublicKey().Bytes()})...)
	challenge := bytes.Repeat([]byte{seed}, 32)
	user := regUser()
	rc := regCase{
		rp: mustNew(t, RPConfig{ID: vectorRPID}),
		st: &ceremonyState{
			kind: ceremonyRegistration, challenge: challenge, origin: mustParseOrigin(t, vectorOrigin),
			userHandle: user.WebAuthnID(), expires: time.Now().Add(CeremonyTimeout),
		},
		user: user,
		m: map[string]any{
			"id": b64(id), "rawId": b64(id), "type": "public-key",
			"response": map[string]any{
				"clientDataJSON":    b64(clientDataJSON("webauthn.create", b64(challenge), vectorOrigin, "")),
				"attestationObject": b64(attObj(formatNone, cborMap{}, authData)),
			},
			"clientExtensionResults": map[string]any{},
		},
	}
	rec, err := rc.finish(t)
	if err != nil {
		t.Fatalf("finishRegistration = %v", err)
	}
	return sk, *rec
}

// TestVerifyLogin_RFC9964_mldsa registers and signs in an ML-DSA-44, -65
// and -87 credential through both finishes. Go's signer cannot prove the
// primitive (RFC 9964 Appendix A does, in cose); a signature over another
// message, or under a non-empty context, refused shows the ceremony hands
// Verify authData ‖ clientDataHash under the empty context RFC 9964 §5
// requires.
func TestVerifyLogin_RFC9964_mldsa(t *testing.T) {
	t.Parallel()
	for _, p := range []struct {
		params mldsa.Parameters
		name   string
		alg    int
		seed   byte
	}{
		{name: "ML-DSA-44", alg: -48, params: mldsa.MLDSA44(), seed: 44},
		{name: "ML-DSA-65", alg: -49, params: mldsa.MLDSA65(), seed: 65},
		{name: "ML-DSA-87", alg: -50, params: mldsa.MLDSA87(), seed: 87},
	} {
		for _, k := range bothKinds {
			for _, c := range []struct {
				sign func(t *testing.T, sk *mldsa.PrivateKey, m []byte) []byte
				want error
				name string
			}{
				{name: "signed", sign: func(t *testing.T, sk *mldsa.PrivateKey, m []byte) []byte { return signM(t, sk, m) }},
				{name: "signed over authData alone", sign: func(t *testing.T, sk *mldsa.PrivateKey, m []byte) []byte {
					return signM(t, sk, m[:len(m)-sha256.Size])
				}, want: errAssertionSignature},
				{name: "signed under a context", sign: func(t *testing.T, sk *mldsa.PrivateKey, m []byte) []byte {
					sig, err := sk.Sign(nil, m, &mldsa.Options{Context: "webauthn"})
					if err != nil {
						t.Fatal(err)
					}
					return sig
				}, want: errAssertionSignature},
			} {
				t.Run(p.name+" "+k.name+" "+c.name, func(t *testing.T) {
					t.Parallel()
					sk, cred := mldsaCredential(t, p.alg, p.params, p.seed)
					challenge := bytes.Repeat([]byte{^p.seed}, 32)
					lc := assertCase(t, k.kind, vectorHalf{"challenge": "00", "clientDataJSON": "00", "authenticatorData": "00", "signature": "00"}, cred)
					lc.st.challenge = challenge
					lc.clientData = clientDataJSON("webauthn.get", b64(challenge), vectorOrigin, "")
					rpIDHash := sha256.Sum256([]byte(vectorRPID))
					lc.authData = append(rpIDHash[:], 0x05, 0, 0, 0, 1)
					lc.sig = c.sign(t, sk, signedMessage(lc.authData, lc.clientData))
					res, err := lc.finish(t)
					if c.want != nil {
						wantNoLogin(t, lc, res, err, c.want)
						return
					}
					wantLoggedIn(t, lc, res, err)
				})
			}
		}
	}
}
