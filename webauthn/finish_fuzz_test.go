package webauthn

import (
	"bytes"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn/internal/cose"
)

// fuzzCeremony is a ceremony of kind begun at the §16 vectors' origin with
// challenge, which the fuzz input carries so that a body answering it
// reaches every step after the client data's.
func fuzzCeremony(t testing.TB, kind ceremonyKind, challenge []byte, user *User) Ceremony {
	st := &ceremonyState{
		kind:      kind,
		challenge: challenge,
		origin:    mustParseOrigin(t, vectorOrigin),
		expires:   time.Now().Add(CeremonyTimeout),
	}
	switch kind {
	case ceremonyRegistration:
		st.userHandle = user.WebAuthnID()
	case ceremonyReauthentication:
		st.userHandle = user.WebAuthnID()
		for _, c := range user.Credentials {
			st.allowed = append(st.allowed, c.CredentialID)
		}
	case ceremonyLogin:
	}
	return Ceremony{st: st}
}

// FuzzFinishRegistration runs untrusted bodies through FinishRegistration,
// seeded with every §16 registration half as published and rebuilt under
// none with UV set. It never panics, returns a record or a refusal, and a
// record is of a present, verified user (§7.1), holds no more bytes than the
// body (no slice sized from a declared length) and a key that parses again
// for the sign-in that reads it.
func FuzzFinishRegistration(f *testing.F) {
	for section, v := range s16(f) {
		published := regCaseWith(f, section, v.Registration.bytes(f, "attestationObject"))
		f.Add(published.st.challenge, marshal(f, published.m))
		rebuilt := noneCase(f, section)
		f.Add(rebuilt.st.challenge, marshal(f, rebuilt.m))
	}
	rp := mustNew(f, RPConfig{ID: vectorRPID})
	f.Fuzz(func(t *testing.T, challenge, body []byte) {
		user := regUser()
		rec, err := FinishRegistration(rp, user, fuzzCeremony(t, ceremonyRegistration, challenge, user), bytes.NewReader(body))
		if (err == nil) != (rec != nil) {
			t.Fatalf("FinishRegistration = %v, %v: want a record or a refusal", rec, err)
		}
		if rec == nil {
			return
		}
		if n := len(rec.CredentialID) + len(rec.PublicKey) + len(rec.AAGUID) + len(rec.Transport); n > len(body) {
			t.Fatalf("the record holds %d bytes of a %d-byte body", n, len(body))
		}
		if up, uv, _, _ := access.DecodePasskeyFlags(rec.RawFlags); !up || !uv {
			t.Fatalf("a record with flags %#x, want UP and UV", rec.RawFlags)
		}
		if _, err := cose.ParseKey(rec.PublicKey); err != nil {
			t.Fatalf("the stored key does not parse: %v", err)
		}
	})
}

// FuzzCompleteAssertion runs untrusted bodies through CompleteLogin and
// CompleteReauthentication against every §16 credential, seeded with every
// §16 authentication half as published and §16.2's, §16.3's, §16.10's and
// §16.11's re-signed with UV set. Neither panics; a refusal writes no
// custody, and a sign-in, of a present, verified user (§7.2), writes it once
// for the credential it returns, which holds no more bytes than the body.
func FuzzCompleteAssertion(f *testing.F) {
	vectors := s16(f)
	creds := make([]access.PasskeyCredential, 0, len(vectors))
	for section, v := range vectors {
		cred := vectorCredential(f, section)
		creds = append(creds, cred)
		published := assertCase(f, ceremonyLogin, v.Authentication, cred)
		f.Add(published.st.challenge, published.body(f))
	}
	for _, section := range []string{"16.2", "16.3", "16.10", "16.11"} {
		c := resigned(f, ceremonyLogin, section)
		f.Add(c.st.challenge, c.body(f))
	}
	rp := mustNew(f, RPConfig{ID: vectorRPID})
	f.Fuzz(func(t *testing.T, challenge, body []byte) {
		user := regUser()
		user.Credentials = creds
		store := &loginStore{users: []*access.User{user.AuthUser, bob()}, passkeys: map[int64][]access.PasskeyCredential{42: creds}}
		legs := map[string]func() (LoginResult, error){
			"CompleteLogin": func() (LoginResult, error) {
				return CompleteLogin(t.Context(), rp, store, fuzzCeremony(t, ceremonyLogin, challenge, user), bytes.NewReader(body))
			},
			"CompleteReauthentication": func() (LoginResult, error) {
				return CompleteReauthentication(t.Context(), rp, store, user, fuzzCeremony(t, ceremonyReauthentication, challenge, user), bytes.NewReader(body))
			},
		}
		for name, leg := range legs {
			store.recorded = nil
			res, err := leg()
			if err != nil {
				if res.User != nil || res.CredentialID != nil || len(store.recorded) != 0 {
					t.Fatalf("%s refused (%v) but returned %+v and wrote %d custody records", name, err, res, len(store.recorded))
				}
				continue
			}
			if res.User == nil || len(store.recorded) != 1 || !bytes.Equal(store.recorded[0].credID, res.CredentialID) {
				t.Fatalf("%s signed in %+v with %d custody writes, want one for its credential", name, res, len(store.recorded))
			}
			if up, uv, _, _ := access.DecodePasskeyFlags(store.recorded[0].upd.RawFlags); !up || !uv {
				t.Fatalf("%s signed in with flags %#x, want UP and UV", name, store.recorded[0].upd.RawFlags)
			}
			if len(res.CredentialID) > len(body) {
				t.Fatalf("%s returned a %d-byte credential ID from a %d-byte body", name, len(res.CredentialID), len(body))
			}
		}
	})
}
