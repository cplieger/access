package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn/internal/cose"
)

// regUser is the account the registration tests finish for.
func regUser() *User {
	return &User{AuthUser: &access.User{ID: 42, Username: "ada", WebAuthnHandle: []byte("ada's user handle")}}
}

// regState is the registration ceremony a §16 registration half answers:
// begun at the vectors' origin with the half's challenge, for user.
func regState(t testing.TB, half vectorHalf, user *User) *ceremonyState {
	t.Helper()
	return &ceremonyState{
		kind:       ceremonyRegistration,
		challenge:  half.bytes(t, "challenge"),
		origin:     mustParseOrigin(t, vectorOrigin),
		userHandle: user.WebAuthnID(),
		expires:    time.Now().Add(CeremonyTimeout),
	}
}

// regJSON is a RegistrationResponseJSON (§5.1) for half's credential ID and
// client data, carrying attestationObject, as a browser's toJSON() writes it.
func regJSON(t testing.TB, half vectorHalf, attestationObject []byte) map[string]any {
	t.Helper()
	id := b64(half.bytes(t, "credential_id"))
	return map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(half.bytes(t, "clientDataJSON")),
			"attestationObject": b64(attestationObject),
			"transports":        []string{"internal", "hybrid"},
		},
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{"credProps": map[string]any{"rk": true}},
	}
}

// uvSet is a §16 registration half's authData as published but with UV set
// (§6.1, bit 2): most halves have it clear, and access always requires it.
func uvSet(t testing.TB, v s16Vector) []byte {
	t.Helper()
	a := bytes.Clone(vectorAuthData(t, v))
	a[32] |= 0x04
	return a
}

// regCase is one registration finish: the relying party, the ceremony, the
// finishing user and the response's members.
type regCase struct {
	rp   *RelyingParty
	st   *ceremonyState
	user *User
	m    map[string]any
}

// regCaseWith answers section's registration ceremony with attestationObject.
func regCaseWith(t testing.TB, section string, attestationObject []byte) regCase {
	t.Helper()
	v := s16Section(t, section)
	user := regUser()
	return regCase{
		rp:   mustNew(t, RPConfig{ID: vectorRPID}),
		st:   regState(t, v.Registration, user),
		user: user,
		m:    regJSON(t, v.Registration, attestationObject),
	}
}

// noneCase is section's registration with UV set, under a none attestation.
func noneCase(t testing.TB, section string) regCase {
	t.Helper()
	return regCaseWith(t, section, attObj(formatNone, cborMap{}, uvSet(t, s16Section(t, section))))
}

func (c regCase) finish(t testing.TB) (*access.PasskeyCredential, error) {
	t.Helper()
	return finishRegistration(c.rp, c.st, c.user, marshal(t, c.m))
}

// selfSigned is a packed self attestation (§8.2) of authData over
// clientDataJSON, signed anew with section's ES256 credential_private_key.
func selfSigned(t testing.TB, section string, authData, clientDataJSON []byte) []byte {
	t.Helper()
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), s16Section(t, section).Registration.bytes(t, "credential_private_key"))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(clientDataJSON)
	digest := sha256.Sum256(append(bytes.Clone(authData), hash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return attObj(formatPacked, cborMap{"alg", -7, "sig", sig}, authData)
}

func wantRefused(t *testing.T, c regCase, want error) {
	t.Helper()
	rec, err := c.finish(t)
	if !errors.Is(err, want) {
		t.Errorf("finishRegistration = %v, want %v", err, want)
	}
	if rec != nil {
		t.Errorf("finishRegistration returned a record beside its refusal")
	}
}

// TestFinishRegistration_WebAuthn7_1_ceremony checks that the response
// answers this registration: a ceremony from a Begin function
// (ErrCeremonyUnbound otherwise), of the registration kind, holding a
// challenge that has not outlived it (§13.4.3), begun for the user the
// credential is stored for (§7.1's last step, pkOptions.user).
func TestFinishRegistration_WebAuthn7_1_ceremony(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		edit func(*regCase)
		want error
		name string
	}{
		{name: "no ceremony", edit: func(c *regCase) { c.st = nil }, want: ErrCeremonyUnbound},
		{name: "a login ceremony", edit: func(c *regCase) { c.st.kind = ceremonyLogin }, want: errCeremonyKind},
		{name: "a reauthentication ceremony", edit: func(c *regCase) { c.st.kind = ceremonyReauthentication }, want: errCeremonyKind},
		{name: "a ceremony of no kind", edit: func(c *regCase) { c.st.kind = 0 }, want: errCeremonyKind},
		{name: "expired", edit: func(c *regCase) { c.st.expires = time.Now().Add(-time.Second) }, want: errCeremonyExpired},
		{name: "no expiry", edit: func(c *regCase) { c.st.expires = time.Time{} }, want: errCeremonyExpired},
		{name: "begun for another user", edit: func(c *regCase) {
			c.user = &User{AuthUser: &access.User{ID: 43, WebAuthnHandle: []byte("bob's user handle")}}
		}, want: errCeremonyUser},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			rc := noneCase(t, "16.2")
			c.edit(&rc)
			wantRefused(t, rc, c.want)
		})
	}
}

// TestFinishRegistration_WebAuthn7_1_response checks that the finish reads
// the response as §5.1's RegistrationResponseJSON before any other step.
func TestFinishRegistration_WebAuthn7_1_response(t *testing.T) {
	t.Parallel()
	t.Run("not JSON", func(t *testing.T) {
		t.Parallel()
		c := noneCase(t, "16.2")
		rec, err := finishRegistration(c.rp, c.st, c.user, []byte("{"))
		if !errors.Is(err, errResponseJSON) || rec != nil {
			t.Errorf("finishRegistration = %v, %v; want errResponseJSON", rec, err)
		}
	})
	t.Run("type", func(t *testing.T) {
		t.Parallel()
		c := noneCase(t, "16.2")
		c.m["type"] = "password"
		wantRefused(t, c, errCredentialType)
	})
	t.Run("id not rawId", func(t *testing.T) {
		t.Parallel()
		c := noneCase(t, "16.2")
		c.m["id"] = b64([]byte("another credential"))
		wantRefused(t, c, errIDMismatch)
	})
}

// TestFinishRegistration_WebAuthn7_1_clientData checks §7.1's client data
// steps against the ceremony: type webauthn.create, the ceremony's
// challenge, and the origin it began at, so a response made at a second
// origin the relying party allows is refused (§13.4.9).
func TestFinishRegistration_WebAuthn7_1_clientData(t *testing.T) {
	t.Parallel()
	challenge := b64(s16Section(t, "16.2").Registration.bytes(t, "challenge"))
	for _, c := range []struct {
		want       error
		name       string
		clientData []byte
	}{
		{name: "type webauthn.get", clientData: clientDataJSON("webauthn.get", challenge, vectorOrigin, ""), want: errClientDataType},
		{name: "another ceremony's challenge", clientData: s16Section(t, "16.3").Registration.bytes(t, "clientDataJSON"), want: errChallenge},
		{name: "a second allowed origin", clientData: clientDataJSON("webauthn.create", challenge, "https://login.example.org", ""), want: errOrigin},
		{name: "framed", clientData: clientDataJSON("webauthn.create", challenge, vectorOrigin, `,"crossOrigin":true`), want: errFramed},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			rc := noneCase(t, "16.2")
			rc.rp = mustNew(t, RPConfig{ID: vectorRPID, Origins: []string{vectorOrigin, "https://login.example.org"}})
			response(rc.m)["clientDataJSON"] = b64(c.clientData)
			wantRefused(t, rc, c.want)
		})
	}
}

// TestFinishRegistration_WebAuthn7_1_hash checks that the self attestation
// is verified over SHA-256 of clientDataJSON as received (§7.1's hash step),
// a leading byte order mark included, while the client data is parsed
// without it (§7.1's UTF-8 decode step).
func TestFinishRegistration_WebAuthn7_1_hash(t *testing.T) {
	t.Parallel()
	v := s16Section(t, "16.3")
	raw := append([]byte{0xef, 0xbb, 0xbf}, v.Registration.bytes(t, "clientDataJSON")...)
	stripped := raw[3:]
	for _, c := range []struct {
		want     error
		name     string
		signedOn []byte
	}{
		{name: "signed over the bytes sent", signedOn: raw},
		{name: "signed over the bytes parsed", signedOn: stripped, want: errAttestationSignature},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			rc := regCaseWith(t, "16.3", selfSigned(t, "16.3", vectorAuthData(t, v), c.signedOn))
			response(rc.m)["clientDataJSON"] = b64(raw)
			rec, err := rc.finish(t)
			if c.want == nil && (err != nil || rec == nil) {
				t.Errorf("finishRegistration = %v, want a record", err)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("finishRegistration = %v, want %v", err, c.want)
			}
		})
	}
}

// TestFinishRegistration_WebAuthn7_1_attestationObject checks that the
// attestation object is decoded as §6.5.4's fmt, attStmt and authData, and
// nothing else.
func TestFinishRegistration_WebAuthn7_1_attestationObject(t *testing.T) {
	t.Parallel()
	c := noneCase(t, "16.2")
	extra := cborEnc(cborMap{"fmt", formatNone, "attStmt", cborMap{}, "authData", uvSet(t, s16Section(t, "16.2")), "epAtt", true})
	response(c.m)["attestationObject"] = b64(extra)
	wantRefused(t, c, errAttestationObject)
}

// TestFinishRegistration_WebAuthn7_1_authData checks §7.1's authenticator
// data steps: the rpIdHash of the relying party's ID, BS only with BE
// (§6.1.3), and attested credential data whose ID is rawId.
func TestFinishRegistration_WebAuthn7_1_authData(t *testing.T) {
	t.Parallel()
	t.Run("credential scoped to another RP ID", func(t *testing.T) {
		t.Parallel()
		c := noneCase(t, "16.2")
		c.rp = mustNew(t, RPConfig{ID: "login.example.org"})
		wantRefused(t, c, errRPIDHash)
	})
	t.Run("BS without BE", func(t *testing.T) {
		t.Parallel()
		// §16.11's flags are UP and AT (0x41): BE clear.
		a := uvSet(t, s16Section(t, "16.11"))
		a[32] |= 0x10
		c := regCaseWith(t, "16.11", attObj(formatNone, cborMap{}, a))
		wantRefused(t, c, errBackupState)
	})
	t.Run("attested credential ID not rawId", func(t *testing.T) {
		t.Parallel()
		c := noneCase(t, "16.2")
		other := b64(s16Section(t, "16.3").Registration.bytes(t, "credential_id"))
		c.m["id"], c.m["rawId"] = other, other
		wantRefused(t, c, errCredentialID)
	})
}

// TestFinishRegistration_WebAuthn7_1_alg checks §7.1's alg step: a
// credential public key whose alg was not offered is refused, here §16.8's
// ES384 (-35) and §16.12's Ed448 key with UV set.
func TestFinishRegistration_WebAuthn7_1_alg(t *testing.T) {
	t.Parallel()
	for _, section := range []string{"16.8", "16.12"} {
		t.Run(section, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, noneCase(t, section), cose.ErrUnsupported)
		})
	}
}

// relabeled is section's registration authData with UV set and its credential
// key's alg member (label 3) changed from alg to alg2, every other byte kept.
func relabeled(t *testing.T, section string, alg, alg2 int) []byte {
	t.Helper()
	a := uvSet(t, s16Section(t, section))
	idLen := int(binary.BigEndian.Uint16(a[53:55]))
	key := a[55+idLen:]
	from, to := append([]byte{0x03}, cborEnc(alg)...), append([]byte{0x03}, cborEnc(alg2)...)
	i := bytes.Index(key, from)
	if i < 0 || len(from) != len(to) {
		t.Fatalf("§%s's credential key holds no alg %d member", section, alg)
	}
	copy(key[i:], to)
	return a
}

// TestFinishRegistration_RFC9864_fullySpecifiedNotOffered checks that RFC
// 9864's fully specified Ed25519 (-19) and ESP256 (-9) are not offered in
// pubKeyCredParams (§5.4), so a credential key naming one, in its own key
// type's label set, is refused at §7.1's alg step.
func TestFinishRegistration_RFC9864_fullySpecifiedNotOffered(t *testing.T) {
	t.Parallel()
	creation, _, err := BeginRegistration(testRelyingParty(t), regUser(), exampleOrigin(t))
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	for _, p := range creation.Response.Parameters {
		if p.Algorithm == -19 || p.Algorithm == -9 {
			t.Errorf("pubKeyCredParams offers %d", p.Algorithm)
		}
	}
	for _, c := range []struct {
		name, section string
		alg, alg2     int
	}{
		{"Ed25519 -19 for §16.11's OKP key", "16.11", -8, -19},
		{"ESP256 -9 for §16.2's EC2 key", "16.2", -7, -9},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, regCaseWith(t, c.section, attObj(formatNone, cborMap{}, relabeled(t, c.section, c.alg, c.alg2))), cose.ErrUnsupported)
		})
	}
}

// TestFinishRegistration_WebAuthn7_1_statement checks §7.1's attestation
// steps on statements access accepts the format of: §16.3's self
// attestation with a flipped signature byte (§8.2), and fmt matched
// case-sensitively.
func TestFinishRegistration_WebAuthn7_1_statement(t *testing.T) {
	t.Parallel()
	t.Run("self attestation that does not verify", func(t *testing.T) {
		t.Parallel()
		s := s16_3(t)
		sig := bytes.Clone(s.sig)
		sig[len(sig)-1] ^= 1
		c := regCaseWith(t, "16.3", attObj(formatPacked, cborMap{"alg", -7, "sig", sig}, s.authData))
		wantRefused(t, c, errAttestationSignature)
	})
	t.Run("fmt None", func(t *testing.T) {
		t.Parallel()
		c := regCaseWith(t, "16.2", attObj("None", cborMap{}, uvSet(t, s16Section(t, "16.2"))))
		wantRefused(t, c, errAttestationFormat)
	})
}

// TestFinishRegistration_WebAuthn7_1_extensions checks §7.1's extension
// step: credProps.rk false is ErrNotDiscoverable (§10.1.3), since a passkey
// login needs a discoverable credential; an absent output is accepted, as
// the step requires of an extension not acted upon; an unsolicited output
// (§16.17.1.1's prf) is ignored.
func TestFinishRegistration_WebAuthn7_1_extensions(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		ext  any
		want *bool
		err  error
		name string
	}{
		{name: "rk false", ext: map[string]any{"credProps": map[string]any{"rk": false}}, err: ErrNotDiscoverable},
		{name: "rk true", ext: map[string]any{"credProps": map[string]any{"rk": true}}, want: new(true)},
		{name: "no credProps", ext: map[string]any{}},
		{name: "an unsolicited prf output", ext: map[string]any{"prf": map[string]any{"enabled": true}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			rc := noneCase(t, "16.2")
			rc.m["clientExtensionResults"] = c.ext
			rec, err := rc.finish(t)
			if c.err != nil {
				if !errors.Is(err, c.err) || rec != nil {
					t.Errorf("finishRegistration = %v, %v; want %v", rec, err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("finishRegistration = %v, want a record", err)
			}
			if (rec.Discoverable == nil) != (c.want == nil) || (rec.Discoverable != nil && *rec.Discoverable != *c.want) {
				t.Errorf("Discoverable = %v, want %v", rec.Discoverable, c.want)
			}
		})
	}
}

// TestFinishRegistration_WebAuthn7_1_transports checks the record's
// transports, the values getTransports() returned (§7.1's credentialRecord),
// joined by commas: a value the join cannot hold is dropped and at most 8
// are kept.
func TestFinishRegistration_WebAuthn7_1_transports(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		want string
		in   []string
	}{
		{name: "nine kept to eight", in: []string{"usb", "nfc", "ble", "smart-card", "hybrid", "internal", "a", "b", "c"}, want: "usb,nfc,ble,smart-card,hybrid,internal,a,b"},
		{name: "unholdable values dropped", in: []string{"", strings.Repeat("x", 33), "usb,nfc", "internal"}, want: "internal"},
		{name: "none", in: nil, want: ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			rc := noneCase(t, "16.2")
			response(rc.m)["transports"] = c.in
			rec, err := rc.finish(t)
			if err != nil {
				t.Fatalf("finishRegistration = %v", err)
			}
			if rec.Transport != c.want {
				t.Errorf("Transport = %q, want %q", rec.Transport, c.want)
			}
		})
	}
}

// TestFinishRegistration_WebAuthn2_1_1_attachment checks the record's
// attachment: the two modalities of §5.4.5 are kept, and any other value
// is stored as none, since an unknown enumeration value is ignored (§2.1.1).
func TestFinishRegistration_WebAuthn2_1_1_attachment(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]access.AuthenticatorAttachment{
		"platform":       access.AttachmentPlatform,
		"cross-platform": access.AttachmentCrossPlatform,
		"other":          "",
	} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			rc := noneCase(t, "16.2")
			rc.m["authenticatorAttachment"] = in
			rec, err := rc.finish(t)
			if err != nil {
				t.Fatalf("finishRegistration = %v", err)
			}
			if rec.Attachment != want {
				t.Errorf("Attachment = %q, want %q", rec.Attachment, want)
			}
		})
	}
}

// TestFinishRegistration_WebAuthn7_1_record checks §7.1's credentialRecord
// for §16.2's credential with UV set, each value read from the vector at
// §6.1's and §6.5.1's offsets: the publicKey as received, signCount, the
// flags octet and its UV, BE and BS bits, transports, rpId, and the
// relying party's own items (the user, no friendly name, no clone warning).
func TestFinishRegistration_WebAuthn7_1_record(t *testing.T) {
	t.Parallel()
	v := s16Section(t, "16.2")
	authData := uvSet(t, v)
	id := v.Registration.bytes(t, "credential_id")
	rec, err := noneCase(t, "16.2").finish(t)
	if err != nil {
		t.Fatalf("finishRegistration = %v", err)
	}
	if rec.UserID != 42 {
		t.Errorf("UserID = %d, want 42", rec.UserID)
	}
	if !bytes.Equal(rec.CredentialID, id) {
		t.Errorf("CredentialID = %x, want %x", rec.CredentialID, id)
	}
	if key := authData[55+len(id):]; !bytes.Equal(rec.PublicKey, key) {
		t.Errorf("PublicKey = %x, want %x", rec.PublicKey, key)
	}
	if aaguid := v.Registration.bytes(t, "aaguid"); !bytes.Equal(rec.AAGUID, aaguid) {
		t.Errorf("AAGUID = %x, want %x", rec.AAGUID, aaguid)
	}
	// §16.2's flags are UP, BE, BS and AT (0x59); with UV, 0x5d.
	if rec.RawFlags != 0x5d || !rec.UserPresent || !rec.UserVerified || !rec.BackupEligible || !rec.BackupState {
		t.Errorf("RawFlags %#x, UP %v, UV %v, BE %v, BS %v; want 0x5d and all four set",
			rec.RawFlags, rec.UserPresent, rec.UserVerified, rec.BackupEligible, rec.BackupState)
	}
	if rec.SignCount != 0 {
		t.Errorf("SignCount = %d, want the published 0", rec.SignCount)
	}
	if rec.Transport != "internal,hybrid" || rec.Attachment != access.AttachmentPlatform {
		t.Errorf("Transport %q, Attachment %q; want internal,hybrid and platform", rec.Transport, rec.Attachment)
	}
	if rec.RPID != vectorRPID {
		t.Errorf("RPID = %q, want %q", rec.RPID, vectorRPID)
	}
	if rec.Name != "" || rec.CloneWarning || rec.ID != 0 {
		t.Errorf("Name %q, CloneWarning %v, ID %d; want none set", rec.Name, rec.CloneWarning, rec.ID)
	}
}

// TestFinishRegistration_WebAuthn6_1_signCount checks that the record's
// signCount is authData's, big-endian at offset 33 (§6.1).
func TestFinishRegistration_WebAuthn6_1_signCount(t *testing.T) {
	t.Parallel()
	a := uvSet(t, s16Section(t, "16.2"))
	binary.BigEndian.PutUint32(a[33:37], 0x0102012c)
	rec, err := regCaseWith(t, "16.2", attObj(formatNone, cborMap{}, a)).finish(t)
	if err != nil {
		t.Fatalf("finishRegistration = %v", err)
	}
	if rec.SignCount != 0x0102012c {
		t.Errorf("SignCount = %#x, want 0x0102012c", rec.SignCount)
	}
}

// TestFinishRegistration_recordOwnsItsBytes checks that growing one of the
// record's byte slices changes no other.
func TestFinishRegistration_recordOwnsItsBytes(t *testing.T) {
	t.Parallel()
	rec, err := noneCase(t, "16.2").finish(t)
	if err != nil {
		t.Fatalf("finishRegistration = %v", err)
	}
	id, key := bytes.Clone(rec.CredentialID), bytes.Clone(rec.PublicKey)
	_ = append(rec.AAGUID, bytes.Repeat([]byte{0xff}, 64)...)
	_ = append(rec.CredentialID, 0xff, 0xff, 0xff, 0xff)
	if !bytes.Equal(rec.CredentialID, id) || !bytes.Equal(rec.PublicKey, key) {
		t.Error("growing AAGUID or CredentialID wrote over another field")
	}
}
