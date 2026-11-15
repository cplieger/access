package accesstest_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
)

const passkeyRPID = "example.com"

// relyingParty is access's relying party at https://example.com over a
// MemStore holding one user, the device's counterpart in every round trip.
type relyingParty struct {
	t      *testing.T
	rp     *webauthn.RelyingParty
	store  *accesstest.MemStore
	user   *access.User
	origin webauthn.Origin
}

func newRelyingParty(t *testing.T) *relyingParty {
	t.Helper()
	rp, err := webauthn.New(webauthn.RPConfig{ID: passkeyRPID, DisplayName: "Example"})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	origin, err := webauthn.ParseOrigin("https://" + passkeyRPID)
	if err != nil {
		t.Fatalf("ParseOrigin: %v", err)
	}
	r := &relyingParty{t: t, rp: rp, store: accesstest.NewMemStore(), origin: origin}
	r.user = &access.User{Username: "alice", Enabled: true, Role: access.RoleUser, WebAuthnHandle: access.GenerateWebAuthnHandle()}
	if err := r.store.CreateUser(t.Context(), r.user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return r
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return out
}

func (r *relyingParty) webauthnUser() *webauthn.User {
	r.t.Helper()
	creds, err := r.store.PasskeysByUserID(r.t.Context(), r.user.ID)
	if err != nil {
		r.t.Fatalf("PasskeysByUserID: %v", err)
	}
	wu, err := webauthn.NewUser(r.user, creds)
	if err != nil {
		r.t.Fatalf("NewUser: %v", err)
	}
	return wu
}

// register runs a registration ceremony on dev and stores the record
// FinishRegistration builds.
func (r *relyingParty) register(dev *accesstest.PasskeyDevice) (*access.PasskeyCredential, registrationBody, error) {
	r.t.Helper()
	wu := r.webauthnUser()
	creation, ceremony, err := webauthn.BeginRegistration(r.rp, wu, r.origin)
	if err != nil {
		r.t.Fatalf("BeginRegistration: %v", err)
	}
	raw := dev.Register(mustJSON(r.t, creation))
	var body registrationBody
	if err := json.Unmarshal(raw, &body); err != nil {
		r.t.Fatalf("registration body: %v", err)
	}
	cred, err := webauthn.FinishRegistration(r.rp, wu, ceremony, bytes.NewReader(raw))
	if err != nil {
		return nil, body, err
	}
	if err := r.store.CreatePasskey(r.t.Context(), cred); err != nil {
		r.t.Fatalf("CreatePasskey: %v", err)
	}
	return cred, body, nil
}

func (r *relyingParty) mustRegister(dev *accesstest.PasskeyDevice) (*access.PasskeyCredential, registrationBody) {
	r.t.Helper()
	cred, body, err := r.register(dev)
	if err != nil {
		r.t.Fatalf("FinishRegistration: %v", err)
	}
	return cred, body
}

// login runs a discoverable login on dev.
func (r *relyingParty) login(dev *accesstest.PasskeyDevice) (webauthn.LoginResult, assertionBody, error) {
	r.t.Helper()
	assertion, ceremony, err := webauthn.BeginLogin(r.rp, r.origin)
	if err != nil {
		r.t.Fatalf("BeginLogin: %v", err)
	}
	raw := dev.Assert(mustJSON(r.t, assertion))
	res, err := webauthn.CompleteLogin(r.t.Context(), r.rp, passkeyCustody{r.store}, ceremony, bytes.NewReader(raw))
	return res, r.assertionBody(raw), err
}

// reauthenticate runs an assertion bound to the user's credentials on dev.
func (r *relyingParty) reauthenticate(dev *accesstest.PasskeyDevice) (webauthn.LoginResult, error) {
	r.t.Helper()
	wu := r.webauthnUser()
	assertion, ceremony, err := webauthn.BeginReauthentication(r.rp, wu, r.origin)
	if err != nil {
		r.t.Fatalf("BeginReauthentication: %v", err)
	}
	raw := dev.Assert(mustJSON(r.t, assertion))
	return webauthn.CompleteReauthentication(r.t.Context(), r.rp, passkeyCustody{r.store}, r.webauthnUser(), ceremony, bytes.NewReader(raw))
}

func (r *relyingParty) passkey(credID []byte) access.PasskeyCredential {
	r.t.Helper()
	creds, err := r.store.PasskeysByUserID(r.t.Context(), r.user.ID)
	if err != nil {
		r.t.Fatalf("PasskeysByUserID: %v", err)
	}
	i := slices.IndexFunc(creds, func(c access.PasskeyCredential) bool { return bytes.Equal(c.CredentialID, credID) })
	if i < 0 {
		r.t.Fatalf("the user holds no passkey %x", credID)
	}
	return creds[i]
}

// passkeyCustody is a webauthn.Store over a MemStore whose RecordAssertion
// merges in one Update, under the contract webauthn.Store states.
type passkeyCustody struct{ *accesstest.MemStore }

func (m passkeyCustody) RecordAssertion(ctx context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error {
	return m.Update(ctx, func(tx account.Tx) error {
		held, err := tx.PasskeysByUserID(ctx, userID)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(held, func(pk access.PasskeyCredential) bool { return bytes.Equal(pk.CredentialID, credID) })
		if i < 0 {
			return account.ErrNotFound
		}
		merged := upd
		merged.SignCount = max(held[i].SignCount, upd.SignCount)
		merged.CloneWarning = held[i].CloneWarning || upd.CloneWarning
		return tx.UpdatePasskeyAfterLogin(ctx, userID, credID, merged)
	})
}

// registrationBody is the part of the device's registration body the tests
// read back.
type registrationBody struct {
	Response struct {
		AuthenticatorData  string `json:"authenticatorData"`
		PublicKey          string `json:"publicKey"`
		AttestationObject  string `json:"attestationObject"`
		PublicKeyAlgorithm int    `json:"publicKeyAlgorithm"`
	} `json:"response"`
}

// assertionBody is the device's assertion body, its members decoded.
type assertionBody struct {
	rawID, clientDataJSON, authData, signature, userHandle []byte
}

func (r *relyingParty) assertionBody(raw []byte) assertionBody {
	r.t.Helper()
	var body struct {
		RawID    string `json:"rawId"`
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
			UserHandle        string `json:"userHandle"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		r.t.Fatalf("assertion body: %v", err)
	}
	return assertionBody{
		rawID:          unb64(r.t, body.RawID),
		clientDataJSON: unb64(r.t, body.Response.ClientDataJSON),
		authData:       authDataHead(r.t, unb64(r.t, body.Response.AuthenticatorData)),
		signature:      unb64(r.t, body.Response.Signature),
		userHandle:     unb64(r.t, body.Response.UserHandle),
	}
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	out, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url %q: %v", s, err)
	}
	return out
}

// authDataHead checks that authData holds its fixed head: the rpIdHash, the
// flags octet and the signature counter (WebAuthn L3 §6.1).
func authDataHead(t *testing.T, authData []byte) []byte {
	t.Helper()
	if len(authData) < 37 {
		t.Fatalf("authenticator data is %d bytes, shorter than its 37-byte head", len(authData))
	}
	return authData
}

// The authenticator-data fields at their WebAuthn L3 §6.1 offsets.
func rpIDHash(authData []byte) []byte  { return authData[:32] }
func flags(authData []byte) byte       { return authData[32] }
func signCount(authData []byte) uint32 { return binary.BigEndian.Uint32(authData[33:37]) }

func (b assertionBody) origin(t *testing.T) string {
	t.Helper()
	var c struct {
		Origin string `json:"origin"`
	}
	if err := json.Unmarshal(b.clientDataJSON, &c); err != nil {
		t.Fatalf("clientDataJSON: %v", err)
	}
	return c.Origin
}

func TestPasskeyDeviceRoundTrip(t *testing.T) {
	t.Run("registration", func(t *testing.T) {
		r := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		cred, body := r.mustRegister(dev)
		if !bytes.Equal(cred.CredentialID, dev.CredentialID) {
			t.Errorf("credential ID = %x, want the device's %x", cred.CredentialID, dev.CredentialID)
		}
		attObj := unb64(t, body.Response.AttestationObject)
		if alg := body.Response.PublicKeyAlgorithm; !bytes.HasPrefix(attObj, []byte("\xa3\x63fmt\x64none")) || alg != -7 {
			t.Errorf("attestation object %x..., alg %d; want fmt none and -7", attObj[:min(len(attObj), 12)], alg)
		}
		if cred.Discoverable == nil || !*cred.Discoverable {
			t.Errorf("credProps rk = %v, want true", cred.Discoverable)
		}
		if cred.RawFlags != 0x5D {
			t.Errorf("registration flags = %#x, want 0x5d", cred.RawFlags)
		}
		if cred.SignCount != 0 {
			t.Errorf("registration sign count = %d, want 0", cred.SignCount)
		}
	})

	t.Run("discoverable_login", func(t *testing.T) {
		r := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		_, reg := r.mustRegister(dev)
		res, got, err := r.login(dev)
		if err != nil {
			t.Fatalf("CompleteLogin: %v", err)
		}
		if stored := r.passkey(dev.CredentialID); stored.SignCount != 1 || res.CloneWarning || stored.CloneWarning {
			t.Errorf("sign count %d, clone warning %v (stored %v); want 1 and false", stored.SignCount, res.CloneWarning, stored.CloneWarning)
		}
		if !bytes.Equal(got.userHandle, r.user.WebAuthnHandle) || res.User == nil || res.User.ID != r.user.ID {
			t.Errorf("userHandle = %x signing in %+v, want the registered %x", got.userHandle, res.User, r.user.WebAuthnHandle)
		}
		if flags(got.authData) != 0x1D {
			t.Errorf("assertion flags = %#x, want 0x1d", flags(got.authData))
		}
		// access checked the signature against the COSE key; this checks it
		// against the registration's SPKI publicKey with the stdlib.
		pub, err := x509.ParsePKIXPublicKey(unb64(t, reg.Response.PublicKey))
		key, ok := pub.(*ecdsa.PublicKey)
		if err != nil || !ok {
			t.Fatalf("registration publicKey = %T, %v; want an ECDSA key", pub, err)
		}
		clientHash := sha256.Sum256(got.clientDataJSON)
		digest := sha256.Sum256(append(bytes.Clone(got.authData), clientHash[:]...))
		if !ecdsa.VerifyASN1(key, digest[:], got.signature) {
			t.Error("the assertion signature does not verify under the registered key")
		}
	})

	t.Run("user_bound_login", func(t *testing.T) {
		r := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		r.mustRegister(dev)
		res, err := r.reauthenticate(dev)
		if err != nil {
			t.Fatalf("CompleteReauthentication: %v", err)
		}
		if res.User == nil || res.User.ID != r.user.ID || !bytes.Equal(res.CredentialID, dev.CredentialID) {
			t.Errorf("LoginResult = %+v, want the user's credential %x", res, dev.CredentialID)
		}
	})

	t.Run("another_key_is_refused", func(t *testing.T) {
		r := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		r.mustRegister(dev)
		impostor := accesstest.NewPasskeyDevice(t)
		impostor.CredentialID = dev.CredentialID
		impostor.UserHandle = r.user.WebAuthnHandle
		if _, _, err := r.login(impostor); err == nil {
			t.Error("an assertion signed by another key validated")
		}
	})
}

func TestPasskeyDeviceKnobs(t *testing.T) {
	t.Run("credential_id", func(t *testing.T) {
		r := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		dev.CredentialID = bytes.Repeat([]byte{0xA5}, 300)
		cred, _ := r.mustRegister(dev)
		if !bytes.Equal(cred.CredentialID, dev.CredentialID) {
			t.Errorf("credential ID = %x, want %x", cred.CredentialID, dev.CredentialID)
		}
		res, got, err := r.login(dev)
		if err != nil || !bytes.Equal(got.rawID, dev.CredentialID) || !bytes.Equal(res.CredentialID, dev.CredentialID) {
			t.Errorf("login rawId = %x, signed in with %x, %v; want %x", got.rawID, res.CredentialID, err, dev.CredentialID)
		}
	})

	t.Run("sign_count_regression", func(t *testing.T) {
		r := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		r.mustRegister(dev)
		dev.SignCount = 4
		res, _, err := r.login(dev)
		if err != nil {
			t.Fatalf("first login: %v", err)
		}
		if stored := r.passkey(dev.CredentialID); stored.SignCount != 5 || res.CloneWarning {
			t.Fatalf("first login: count %d, warning %v; want 5 and false", stored.SignCount, res.CloneWarning)
		}
		dev.SignCount = 2
		res, got, err := r.login(dev)
		if err != nil {
			t.Fatalf("regressed login: %v", err)
		}
		if signCount(got.authData) != 3 || !res.CloneWarning {
			t.Errorf("regressed login: counter %d, warning %v; want 3 and true", signCount(got.authData), res.CloneWarning)
		}
	})

	t.Run("flags", func(t *testing.T) {
		r := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		dev.Flags = 0x45 // UP, UV and AT: a device-bound credential
		cred, _ := r.mustRegister(dev)
		if cred.RawFlags != 0x45 {
			t.Errorf("registration flags = %#x, want 0x45", cred.RawFlags)
		}
		dev.Flags = 0x0D // UP, UV and BE: inconsistent with the registered BE=0
		_, got, err := r.login(dev)
		if flags(got.authData) != 0x0D {
			t.Errorf("assertion flags = %#x, want 0x0d", flags(got.authData))
		}
		if err == nil {
			t.Error("a backup-eligibility flip validated")
		}
	})

	t.Run("origin", func(t *testing.T) {
		r := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		r.mustRegister(dev)
		dev.Origin = "https://evil.example.com:8443"
		_, got, err := r.login(dev)
		if o := got.origin(t); o != dev.Origin {
			t.Errorf("clientData origin = %q, want %q", o, dev.Origin)
		}
		if err == nil {
			t.Error("an assertion from a foreign origin validated")
		}
	})

	t.Run("user_handle", func(t *testing.T) {
		r := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		r.mustRegister(dev)
		dev.UserHandle = []byte("someone-else")
		_, got, err := r.login(dev)
		if !bytes.Equal(got.userHandle, dev.UserHandle) || err == nil {
			t.Errorf("userHandle %q, err %v; want %q and a refusal", got.userHandle, err, dev.UserHandle)
		}
		dev.UserHandle = []byte{}
		_, got, err = r.login(dev)
		if len(got.userHandle) != 0 || err == nil {
			t.Errorf("userHandle %q, err %v; want none and a refusal", got.userHandle, err)
		}
	})

	t.Run("rp_id_fallbacks", func(t *testing.T) {
		r := newRelyingParty(t)
		dev := accesstest.NewPasskeyDevice(t)
		r.mustRegister(dev)
		noRPID := []byte(`{"publicKey":{"challenge":"Y2hhbGxlbmdl"}}`)
		want := sha256.Sum256([]byte(passkeyRPID))
		if got := rpIDHash(r.assertionBody(dev.Assert(noRPID)).authData); !bytes.Equal(got, want[:]) {
			t.Errorf("after registration, rpIdHash = %x, want SHA-256(%q)", got, passkeyRPID)
		}
		fresh := accesstest.NewPasskeyDevice(t)
		fresh.Origin = "https://login.example.org:8443"
		want = sha256.Sum256([]byte("login.example.org"))
		if got := rpIDHash(r.assertionBody(fresh.Assert(noRPID)).authData); !bytes.Equal(got, want[:]) {
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
