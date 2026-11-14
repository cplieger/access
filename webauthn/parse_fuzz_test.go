package webauthn

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cplieger/access"
)

// FuzzParseRegistrationResponse runs untrusted response bodies through both
// response parsers and the registration parse chain: none panics, and an
// accepted body yields values inside each parser's bounds.
func FuzzParseRegistrationResponse(f *testing.F) {
	f.Add(marshal(f, regMembers(f)))
	f.Add(marshal(f, assertMembers(f, b64([]byte("user-7")))))
	f.Add(withMember(marshal(f, regMembers(f)), `"TYPE":"x"`))
	unfit := regMembers(f)
	unfit["authenticatorAttachment"] = "other"
	response(unfit)["transports"] = []string{"", "a,b", strings.Repeat("u", 33), "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	f.Add(marshal(f, unfit))
	challenge := s16Section(f, "16.2").Registration.bytes(f, "challenge")
	origin, err := ParseOrigin(vectorOrigin)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if r, err := parseAssertionResponse(body); err == nil {
			if len(r.rawID) == 0 || len(r.rawID) > maxCredentialIDBytes || (r.userHandle != nil && (len(r.userHandle) == 0 || len(r.userHandle) > maxUserHandleBytes)) {
				t.Fatalf("assertion out of bounds: rawID %d bytes, userHandle %v", len(r.rawID), r.userHandle)
			}
		}
		r, err := parseRegistrationResponse(body)
		if err != nil {
			return
		}
		if len(r.rawID) == 0 || len(r.rawID) > maxCredentialIDBytes || len(r.transports) > maxTransports {
			t.Fatalf("registration out of bounds: rawID %d bytes, %d transports", len(r.rawID), len(r.transports))
		}
		for _, tr := range r.transports {
			if tr == "" || len(tr) > maxTransportBytes || strings.Contains(tr, ",") {
				t.Fatalf("transport %q kept", tr)
			}
		}
		if r.attachment != "" && r.attachment != access.AttachmentPlatform && r.attachment != access.AttachmentCrossPlatform {
			t.Fatalf("attachment %q kept", r.attachment)
		}
		hash, _ := verifyClientData(r.clientDataJSON, clientDataCreate, challenge, origin)
		o, err := parseAttestationObject(r.attestationObject)
		if err != nil {
			return
		}
		if _, key, err := registrationAuthData(o.authData, vectorRPID, r.rawID); err == nil {
			_ = o.verifyStatement(key, hash)
		}
	})
}

// FuzzParseAuthData checks that parseAuthData never panics and that what it
// accepts it read from the input at §6.1's and §6.5.1's offsets.
func FuzzParseAuthData(f *testing.F) {
	for _, v := range s16(f) {
		f.Add(v.Authentication.bytes(f, "authenticatorData"))
		f.Add(vectorAuthData(f, v))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, err := parseAuthData(raw)
		_, _ = assertionAuthData(raw, vectorRPID)
		if err != nil {
			return
		}
		if a.flags != raw[32] || !bytes.Equal(a.rpIDHash, raw[:32]) {
			t.Fatalf("flags %#x or rpIdHash not read from the input", a.flags)
		}
		if (a.attested != nil) != (raw[32]&flagAttested != 0) {
			t.Fatalf("attested data %v with flags %#x", a.attested != nil, raw[32])
		}
		if c := a.attested; c != nil {
			n := len(c.id)
			if n == 0 || n > maxCredentialIDBytes || !bytes.Equal(c.aaguid, raw[37:53]) || !bytes.Equal(c.id, raw[55:55+n]) || !bytes.HasPrefix(raw[55+n:], c.publicKey) || len(c.publicKey) == 0 {
				t.Fatalf("attested credential not read at its offsets: ID %d bytes", n)
			}
			_, _, _ = registrationAuthData(raw, vectorRPID, c.id)
		}
	})
}
