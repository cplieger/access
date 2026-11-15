package cose_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"github.com/cplieger/access/webauthn/internal/cose"
)

// FuzzParseKey checks that ParseKey never panics, that an accepted key names
// an offered algorithm, that it reads exactly one COSE_Key (the same bytes
// with one more are refused), and that Verify under it never panics and
// answers nil or ErrSignature.
func FuzzParseKey(f *testing.F) {
	vectors := s16(f)
	for _, v := range vectors {
		f.Add(credentialKey(f, v.Registration.bytes(f, "attestationObject")))
	}
	for _, fam := range baseKeys(f) {
		f.Add(encodeMap(fam.pairs...))
	}
	for _, e := range rfc9964(f) {
		if e.COSEKey != "" {
			f.Add(unhex(f, e.COSEKey))
		}
	}
	f.Add([]byte{0xa2, 0x01, 0x02, 0x03, 0x26})
	f.Fuzz(func(t *testing.T, raw []byte) {
		k, err := cose.ParseKey(raw)
		if err != nil {
			if !errors.Is(err, cose.ErrMalformed) && !errors.Is(err, cose.ErrUnsupported) {
				t.Fatalf("ParseKey error %v matches neither ErrMalformed nor ErrUnsupported", err)
			}
			return
		}
		if !slices.Contains(cose.Offered(), k.Algorithm()) {
			t.Fatalf("accepted alg %d, not offered", k.Algorithm())
		}
		if _, err := cose.ParseKey(append(slices.Clone(raw), 0)); err == nil {
			t.Fatalf("accepted %x with a byte after it", raw)
		}
		if err := k.Verify(raw, sha256.Sum256(raw), raw); err != nil && !errors.Is(err, cose.ErrSignature) {
			t.Fatalf("Verify error %v does not match ErrSignature", err)
		}
	})
}

// signer is one public key and every message the vectors show it signing;
// RFC 9964's JOSE and COSE examples of a parameter set share one key.
type signer struct {
	key      *cose.Key
	messages [][]byte
}

// FuzzVerify checks, for the §16 and RFC 9964 keys, that Verify never panics,
// answers nil or ErrSignature, and accepts only a message the key signed:
// any other authData ‖ clientDataHash is a forgery.
func FuzzVerify(f *testing.F) {
	var signers []*signer
	byKey := map[string]*signer{}
	add := func(raw, authData []byte, hash [sha256.Size]byte, sig []byte) {
		s, ok := byKey[string(raw)]
		if !ok {
			k, err := cose.ParseKey(raw)
			if err != nil {
				f.Fatal(err)
			}
			s = &signer{key: k}
			byKey[string(raw)] = s
			signers = append(signers, s)
		}
		s.messages = append(s.messages, append(slices.Clone(authData), hash[:]...))
		f.Add(uint8(slices.Index(signers, s)), authData, hash[:], sig)
	}
	vectors := s16(f)
	for _, sec := range []string{"16.2", "16.3", "16.10", "16.11"} {
		v := vectors[sec]
		a := v.Authentication
		add(credentialKey(f, v.Registration.bytes(f, "attestationObject")),
			a.bytes(f, "authenticatorData"), sha256.Sum256(a.bytes(f, "clientDataJSON")), a.bytes(f, "signature"))
	}
	for _, e := range rfc9964(f) {
		m := unhex(f, e.ToBeSigned)
		add(akpKey(mldsaAlg[e.ParameterSet], unhex(f, e.PublicKey)),
			m[:len(m)-sha256.Size], [sha256.Size]byte(m[len(m)-sha256.Size:]), unhex(f, e.Signature))
	}
	f.Add(uint8(0), []byte{}, []byte{}, []byte{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, i uint8, authData, hashBytes, sig []byte) {
		s := signers[int(i)%len(signers)]
		var hash [sha256.Size]byte
		copy(hash[:], hashBytes)
		err := s.key.Verify(authData, hash, sig)
		if err != nil {
			if !errors.Is(err, cose.ErrSignature) {
				t.Fatalf("Verify error %v does not match ErrSignature", err)
			}
			return
		}
		m := append(slices.Clone(authData), hash[:]...)
		if !slices.ContainsFunc(s.messages, func(signed []byte) bool { return bytes.Equal(signed, m) }) {
			t.Fatalf("key %d accepted a message it never signed: %x", int(i)%len(signers), m)
		}
	})
}
