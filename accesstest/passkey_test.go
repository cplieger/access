package accesstest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cplieger/access/accesstest"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

const (
	passkeyRPID   = "example.com"
	passkeyOrigin = "https://example.com"
)

type passkeyUser struct {
	id    []byte
	creds []gowebauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                           { return u.id }
func (*passkeyUser) WebAuthnName() string                           { return "alice" }
func (*passkeyUser) WebAuthnDisplayName() string                    { return "Alice" }
func (u *passkeyUser) WebAuthnCredentials() []gowebauthn.Credential { return u.creds }

func newRelyingParty(t *testing.T) *gowebauthn.WebAuthn {
	t.Helper()
	wa, err := gowebauthn.New(&gowebauthn.Config{RPID: passkeyRPID, RPDisplayName: "Example", RPOrigins: []string{passkeyOrigin}})
	if err != nil {
		t.Fatalf("gowebauthn.New: %v", err)
	}
	return wa
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return out
}

// register runs a resident-key registration with credProps through go-webauthn
// and stores the credential on user.
func register(t *testing.T, wa *gowebauthn.WebAuthn, dev *accesstest.PasskeyDevice, user *passkeyUser) (*protocol.ParsedCredentialCreationData, *gowebauthn.Credential, error) {
	t.Helper()
	creation, session, err := wa.BeginRegistration(user,
		gowebauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		gowebauthn.WithExtensions(gowebauthn.WithExtensionCredProps()))
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(dev.Register(mustJSON(t, creation)))
	if err != nil {
		t.Fatalf("ParseCredentialCreationResponseBytes: %v", err)
	}
	cred, err := wa.CreateCredential(user, *session, parsed)
	if err == nil {
		user.creds = append(user.creds, *cred)
	}
	return parsed, cred, err
}

// passkeyLogin runs a discoverable login through go-webauthn and returns the
// parsed assertion and the credential go-webauthn validated.
func passkeyLogin(t *testing.T, wa *gowebauthn.WebAuthn, dev *accesstest.PasskeyDevice, user *passkeyUser) (*protocol.ParsedCredentialAssertionData, *gowebauthn.Credential, error) {
	t.Helper()
	assertion, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(dev.Assert(mustJSON(t, assertion)))
	if err != nil {
		t.Fatalf("ParseCredentialRequestResponseBytes: %v", err)
	}
	handler := func(rawID, userHandle []byte) (gowebauthn.User, error) {
		if !bytes.Equal(userHandle, user.id) {
			return nil, protocol.ErrBadRequest.WithDetails("unknown user handle")
		}
		return user, nil
	}
	_, cred, err := wa.ValidatePasskeyLogin(handler, *session, parsed)
	return parsed, cred, err
}

type registeredPasskey struct {
	wa   *gowebauthn.WebAuthn
	dev  *accesstest.PasskeyDevice
	user *passkeyUser
	reg  *protocol.ParsedCredentialCreationData
	cred *gowebauthn.Credential
}

func registeredDevice(t *testing.T) registeredPasskey {
	t.Helper()
	r := registeredPasskey{wa: newRelyingParty(t), dev: accesstest.NewPasskeyDevice(t), user: &passkeyUser{id: []byte("user-handle-1")}}
	var err error
	if r.reg, r.cred, err = register(t, r.wa, r.dev, r.user); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	return r
}

func TestPasskeyDeviceRoundTrip(t *testing.T) {
	t.Run("registration", func(t *testing.T) {
		r := registeredDevice(t)
		if !bytes.Equal(r.cred.ID, r.dev.CredentialID) {
			t.Errorf("credential ID = %x, want the device's %x", r.cred.ID, r.dev.CredentialID)
		}
		if alg := r.reg.Raw.AttestationResponse.PublicKeyAlgorithm; r.cred.AttestationFormat != "none" || alg != -7 {
			t.Errorf("attestation %q alg %d, want none and -7", r.cred.AttestationFormat, alg)
		}
		if r.cred.Extensions.RK == nil || !*r.cred.Extensions.RK {
			t.Errorf("credProps rk = %v, want true", r.cred.Extensions.RK)
		}
		if got := r.reg.Response.AttestationObject.AuthData.Flags; got != 0x5D {
			t.Errorf("registration flags = %#x, want 0x5d", got)
		}
		if r.cred.Authenticator.SignCount != 0 {
			t.Errorf("registration sign count = %d, want 0", r.cred.Authenticator.SignCount)
		}
	})

	t.Run("discoverable_login", func(t *testing.T) {
		r := registeredDevice(t)
		parsed, got, err := passkeyLogin(t, r.wa, r.dev, r.user)
		if err != nil {
			t.Fatalf("ValidatePasskeyLogin: %v", err)
		}
		if got.Authenticator.SignCount != 1 || got.Authenticator.CloneWarning {
			t.Errorf("sign count %d, clone warning %v; want 1 and false", got.Authenticator.SignCount, got.Authenticator.CloneWarning)
		}
		if !bytes.Equal(parsed.Response.UserHandle, r.user.id) {
			t.Errorf("userHandle = %q, want the registered %q", parsed.Response.UserHandle, r.user.id)
		}
		if parsed.Response.AuthenticatorData.Flags != 0x1D {
			t.Errorf("assertion flags = %#x, want 0x1d", parsed.Response.AuthenticatorData.Flags)
		}
		// go-webauthn checked the signature against the COSE key; this checks
		// it against the registration's SPKI publicKey with the stdlib.
		pub, err := x509.ParsePKIXPublicKey(r.reg.Raw.AttestationResponse.PublicKey)
		key, ok := pub.(*ecdsa.PublicKey)
		if err != nil || !ok {
			t.Fatalf("registration publicKey = %T, %v; want an ECDSA key", pub, err)
		}
		clientHash := sha256.Sum256(parsed.Raw.AssertionResponse.ClientDataJSON)
		digest := sha256.Sum256(append(bytes.Clone(parsed.Raw.AssertionResponse.AuthenticatorData), clientHash[:]...))
		if !ecdsa.VerifyASN1(key, digest[:], parsed.Response.Signature) {
			t.Error("the assertion signature does not verify under the registered key")
		}
	})

	t.Run("user_bound_login", func(t *testing.T) {
		r := registeredDevice(t)
		assertion, session, err := r.wa.BeginLogin(r.user)
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		parsed, err := protocol.ParseCredentialRequestResponseBytes(r.dev.Assert(mustJSON(t, assertion)))
		if err != nil {
			t.Fatalf("ParseCredentialRequestResponseBytes: %v", err)
		}
		if _, err := r.wa.ValidateLogin(r.user, *session, parsed); err != nil {
			t.Errorf("ValidateLogin: %v", err)
		}
	})

	t.Run("another_key_is_refused", func(t *testing.T) {
		r := registeredDevice(t)
		impostor := accesstest.NewPasskeyDevice(t)
		impostor.CredentialID = r.dev.CredentialID
		impostor.UserHandle = r.user.id
		if _, _, err := passkeyLogin(t, r.wa, impostor, r.user); err == nil {
			t.Error("an assertion signed by another key validated")
		}
	})
}

func TestPasskeyDeviceKnobs(t *testing.T) {
	t.Run("credential_id", func(t *testing.T) {
		wa := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		dev.CredentialID = bytes.Repeat([]byte{0xA5}, 300)
		user := &passkeyUser{id: []byte("u1")}
		_, cred, err := register(t, wa, dev, user)
		if err != nil {
			t.Fatalf("CreateCredential: %v", err)
		}
		if !bytes.Equal(cred.ID, dev.CredentialID) {
			t.Errorf("credential ID = %x, want %x", cred.ID, dev.CredentialID)
		}
		parsed, _, err := passkeyLogin(t, wa, dev, user)
		if err != nil || !bytes.Equal(parsed.RawID, dev.CredentialID) {
			t.Errorf("login rawId = %x, %v; want %x", parsed.RawID, err, dev.CredentialID)
		}
	})

	t.Run("sign_count_regression", func(t *testing.T) {
		wa := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		user := &passkeyUser{id: []byte("u1")}
		if _, _, err := register(t, wa, dev, user); err != nil {
			t.Fatalf("CreateCredential: %v", err)
		}
		dev.SignCount = 4
		_, cred, err := passkeyLogin(t, wa, dev, user)
		if err != nil {
			t.Fatalf("first login: %v", err)
		}
		if cred.Authenticator.SignCount != 5 || cred.Authenticator.CloneWarning {
			t.Fatalf("first login: count %d, warning %v; want 5 and false", cred.Authenticator.SignCount, cred.Authenticator.CloneWarning)
		}
		user.creds[0] = *cred
		dev.SignCount = 2
		parsed, cred, err := passkeyLogin(t, wa, dev, user)
		if err != nil {
			t.Fatalf("regressed login: %v", err)
		}
		if parsed.Response.AuthenticatorData.Counter != 3 || !cred.Authenticator.CloneWarning {
			t.Errorf("regressed login: counter %d, warning %v; want 3 and true", parsed.Response.AuthenticatorData.Counter, cred.Authenticator.CloneWarning)
		}
	})

	t.Run("flags", func(t *testing.T) {
		wa := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		user := &passkeyUser{id: []byte("u1")}
		dev.Flags = 0x45 // UP, UV and AT: a device-bound credential
		parsedReg, _, err := register(t, wa, dev, user)
		if err != nil {
			t.Fatalf("CreateCredential: %v", err)
		}
		if got := parsedReg.Response.AttestationObject.AuthData.Flags; got != 0x45 {
			t.Errorf("registration flags = %#x, want 0x45", got)
		}
		dev.Flags = 0x0D // UP, UV and BE: inconsistent with the registered BE=0
		parsed, _, err := passkeyLogin(t, wa, dev, user)
		if got := parsed.Response.AuthenticatorData.Flags; got != 0x0D {
			t.Errorf("assertion flags = %#x, want 0x0d", got)
		}
		if err == nil {
			t.Error("a backup-eligibility flip validated")
		}
	})

	t.Run("origin", func(t *testing.T) {
		wa := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		user := &passkeyUser{id: []byte("u1")}
		if _, _, err := register(t, wa, dev, user); err != nil {
			t.Fatalf("CreateCredential: %v", err)
		}
		dev.Origin = "https://evil.example.com:8443"
		parsed, _, err := passkeyLogin(t, wa, dev, user)
		if got := parsed.Response.CollectedClientData.Origin; got != dev.Origin {
			t.Errorf("clientData origin = %q, want %q", got, dev.Origin)
		}
		if err == nil {
			t.Error("an assertion from a foreign origin validated")
		}
	})

	t.Run("user_handle", func(t *testing.T) {
		wa := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		user := &passkeyUser{id: []byte("u1")}
		if _, _, err := register(t, wa, dev, user); err != nil {
			t.Fatalf("CreateCredential: %v", err)
		}
		dev.UserHandle = []byte("someone-else")
		parsed, _, err := passkeyLogin(t, wa, dev, user)
		if !bytes.Equal(parsed.Response.UserHandle, dev.UserHandle) || err == nil {
			t.Errorf("userHandle %q, err %v; want %q and a refusal", parsed.Response.UserHandle, err, dev.UserHandle)
		}
		dev.UserHandle = []byte{}
		parsed, _, err = passkeyLogin(t, wa, dev, user)
		if len(parsed.Response.UserHandle) != 0 || err == nil {
			t.Errorf("userHandle %q, err %v; want none and a refusal", parsed.Response.UserHandle, err)
		}
	})

	t.Run("rp_id_fallbacks", func(t *testing.T) {
		wa := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		user := &passkeyUser{id: []byte("u1")}
		if _, _, err := register(t, wa, dev, user); err != nil {
			t.Fatalf("CreateCredential: %v", err)
		}
		noRPID := []byte(`{"publicKey":{"challenge":"Y2hhbGxlbmdl"}}`)
		want := sha256.Sum256([]byte(passkeyRPID))
		if got := assertedRPIDHash(t, dev.Assert(noRPID)); !bytes.Equal(got, want[:]) {
			t.Errorf("after registration, rpIdHash = %x, want SHA-256(%q)", got, passkeyRPID)
		}
		fresh := accesstest.NewPasskeyDevice(t)
		fresh.Origin = "https://login.example.org:8443"
		want = sha256.Sum256([]byte("login.example.org"))
		if got := assertedRPIDHash(t, fresh.Assert(noRPID)); !bytes.Equal(got, want[:]) {
			t.Errorf("from Origin, rpIdHash = %x, want SHA-256(login.example.org)", got)
		}
	})

	t.Run("cred_props_only_when_asked", func(t *testing.T) {
		dev := accesstest.NewPasskeyDevice(t)
		body := dev.Register([]byte(`{"publicKey":{"rp":{"id":"example.com"},"user":{"id":"dTE"},"challenge":"Y2hhbGxlbmdl"}}`))
		var got struct {
			ClientExtensionResults map[string]any `json:"clientExtensionResults"`
		}
		if err := json.Unmarshal(body, &got); err != nil || len(got.ClientExtensionResults) != 0 {
			t.Errorf("clientExtensionResults = %v, %v; want empty", got.ClientExtensionResults, err)
		}
	})
}

func assertedRPIDHash(t *testing.T, body []byte) []byte {
	t.Helper()
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		t.Fatalf("ParseCredentialRequestResponseBytes: %v", err)
	}
	return parsed.Response.AuthenticatorData.RPIDHash
}

func TestPasskeyDeviceCBORLengths(t *testing.T) {
	prefix := []byte("\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData")
	for _, tc := range []struct {
		name   string
		idLen  int
		head   byte
		argLen int
	}{
		{"one_byte", 32, 0x58, 1},
		{"two_bytes", 300, 0x59, 2},
		{"four_bytes", 65535, 0x5a, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := accesstest.NewPasskeyDevice(t)
			dev.CredentialID = bytes.Repeat([]byte{1}, tc.idLen)
			body := dev.Register([]byte(`{"publicKey":{"rp":{"id":"example.com"},"user":{"id":"dTE"},"challenge":"Y2hhbGxlbmdl"}}`))
			var reg struct {
				Response struct {
					AttestationObject string `json:"attestationObject"`
				} `json:"response"`
			}
			if err := json.Unmarshal(body, &reg); err != nil {
				t.Fatalf("body: %v", err)
			}
			obj, err := base64.RawURLEncoding.DecodeString(reg.Response.AttestationObject)
			if err != nil || !bytes.HasPrefix(obj, prefix) {
				t.Fatalf("attestation object %x..., err %v; want the none-format prefix", obj[:min(len(obj), 40)], err)
			}
			rest := obj[len(prefix):]
			if rest[0] != tc.head {
				t.Fatalf("authData head = %#x, want %#x", rest[0], tc.head)
			}
			var n uint64
			switch tc.argLen {
			case 1:
				n = uint64(rest[1])
			case 2:
				n = uint64(binary.BigEndian.Uint16(rest[1:]))
			case 4:
				n = uint64(binary.BigEndian.Uint32(rest[1:]))
			}
			// 37 head bytes, a 16-byte AAGUID, a 2-byte length and a 77-byte COSE key.
			if want := uint64(37 + 16 + 2 + tc.idLen + 77); n != want || uint64(len(rest)-1-tc.argLen) != want {
				t.Errorf("authData length = %d with %d bytes left, want %d", n, len(rest)-1-tc.argLen, want)
			}
		})
	}
}

func TestPasskeyDeviceRefusals(t *testing.T) {
	const registered = `{"publicKey":{"rp":{"id":"example.com"},"user":{"id":"dTE"},"challenge":"Y2hhbGxlbmdl"}}`
	for _, tc := range []struct {
		name    string
		assert  bool
		options string
		idLen   int
		want    string
	}{
		{"not_json", false, `{`, 0, "creation options"},
		{"no_public_key", false, `{}`, 0, "no publicKey member"},
		{"empty_challenge", false, `{"publicKey":{"rp":{"id":"example.com"},"user":{"id":"dTE"}}}`, 0, "challenge"},
		{"bad_challenge", false, `{"publicKey":{"rp":{"id":"example.com"},"user":{"id":"dTE"},"challenge":"!!"}}`, 0, "challenge"},
		{"no_user_id", false, `{"publicKey":{"rp":{"id":"example.com"},"challenge":"Y2hhbGxlbmdl"}}`, 0, "user.id"},
		{"no_es256", false, `{"publicKey":{"rp":{"id":"example.com"},"user":{"id":"dTE"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-257}]}}`, 0, "no ES256"},
		{"no_rp_id", false, `{"publicKey":{"user":{"id":"dTE"},"challenge":"Y2hhbGxlbmdl"}}`, 0, "no RP ID"},
		{"credential_id_too_long", false, registered, 65536, "over the 65535"},
		{"assert_not_json", true, `[]`, 0, "request options"},
		{"assert_no_public_key", true, `{"mediation":"conditional"}`, 0, "no publicKey member"},
		{"assert_no_challenge", true, `{"publicKey":{"rpId":"example.com"}}`, 0, "challenge"},
		{"assert_no_rp_id", true, `{"publicKey":{"challenge":"Y2hhbGxlbmdl"}}`, 0, "no RP ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &fatalRecorder{TB: t}
			dev := accesstest.NewPasskeyDevice(rec)
			if tc.idLen > 0 {
				dev.CredentialID = make([]byte, tc.idLen)
			}
			done := make(chan []byte)
			go func() {
				var body []byte
				defer func() { done <- body }()
				if tc.assert {
					body = dev.Assert([]byte(tc.options))
				} else {
					body = dev.Register([]byte(tc.options))
				}
			}()
			if body := <-done; body != nil || !strings.Contains(rec.msg, tc.want) {
				t.Errorf("returned %q, recorded %q; want a fatal refusal naming %q", body, rec.msg, tc.want)
			}
		})
	}
}
