package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/cplieger/access"
)

// publicKeyJSON returns the publicKey member of v's JSON as a decoded object.
func publicKeyJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var doc struct {
		PublicKey map[string]any `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.PublicKey == nil {
		t.Fatalf("Unmarshal %s: publicKey %v, error %v", raw, doc.PublicKey, err)
	}
	return doc.PublicKey
}

// TestCreationOptions_WebAuthn5_4_4_requireResidentKey checks that the creation
// options send requireResidentKey true beside residentKey "required": WebAuthn
// §5.4.4 has the relying party set it to true for backwards compatibility with
// Level 1 clients, which read only requireResidentKey.
func TestCreationOptions_WebAuthn5_4_4_requireResidentKey(t *testing.T) {
	t.Parallel()
	user := &User{AuthUser: &access.User{ID: 42, Username: "alex", WebAuthnHandle: access.GenerateWebAuthnHandle()}}
	creation, _, err := BeginRegistration(testRelyingParty(t), user, exampleOrigin(t))
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	selection, ok := publicKeyJSON(t, creation)["authenticatorSelection"].(map[string]any)
	if !ok {
		t.Fatalf("publicKey.authenticatorSelection is not an object")
	}
	if got := selection["requireResidentKey"]; got != true {
		t.Errorf("authenticatorSelection.requireResidentKey = %v, want true", got)
	}
	if got := selection["residentKey"]; got != "required" {
		t.Errorf("authenticatorSelection.residentKey = %v, want required", got)
	}
}

// TestOptions_WebAuthn5_4_7_noAttestationOrHints checks that neither options
// dictionary carries attestation, attestationFormats or hints: an absent
// attestation member is the default "none" (WebAuthn §5.4.7), and access
// sends no hints (§5.8.7).
func TestOptions_WebAuthn5_4_7_noAttestationOrHints(t *testing.T) {
	t.Parallel()
	rp := testRelyingParty(t)
	user := &User{AuthUser: &access.User{ID: 42, Username: "alex", WebAuthnHandle: access.GenerateWebAuthnHandle()}}
	creation, _, err := BeginRegistration(rp, user, exampleOrigin(t))
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	login, _, err := BeginLogin(rp, exampleOrigin(t))
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	conditional, _, err := BeginConditionalLogin(rp, exampleOrigin(t))
	if err != nil {
		t.Fatalf("BeginConditionalLogin: %v", err)
	}
	user.Credentials = []access.PasskeyCredential{{CredentialID: []byte{1, 2, 3}}}
	reauth, _, err := BeginReauthentication(rp, user, exampleOrigin(t))
	if err != nil {
		t.Fatalf("BeginReauthentication: %v", err)
	}
	for name, options := range map[string]any{"creation": creation, "login": login, "conditional": conditional, "reauthentication": reauth} {
		publicKey := publicKeyJSON(t, options)
		for _, member := range []string{"attestation", "attestationFormats", "hints"} {
			if v, present := publicKey[member]; present {
				t.Errorf("%s options carry publicKey.%s = %v, want no such member", name, member, v)
			}
		}
	}
}

// TestBase64URL_roundTrip pins the encoding every binary member uses. Padded
// input is accepted on the way in because some clients emit it, but output is
// always unpadded.
func TestBase64URL_roundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{name: "empty", in: []byte{}, want: `""`},
		{name: "one byte needing padding", in: []byte{0xff}, want: `"_w"`},
		{name: "two bytes needing padding", in: []byte{0xff, 0xfe}, want: `"__4"`},
		{name: "three bytes needing none", in: []byte{0xff, 0xfe, 0xfd}, want: `"__79"`},
		{name: "url-unsafe bytes use - and _", in: []byte{0xfb, 0xff}, want: `"-_8"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := json.Marshal(Base64URL(tt.in))
			if err != nil {
				t.Fatalf("Marshal(%x): %v", tt.in, err)
			}
			if string(encoded) != tt.want {
				t.Errorf("Marshal(%x) = %s, want %s", tt.in, encoded, tt.want)
			}
			var back Base64URL
			if err := json.Unmarshal(encoded, &back); err != nil {
				t.Fatalf("Unmarshal(%s): %v", encoded, err)
			}
			if string(back) != string(tt.in) {
				t.Errorf("round trip of %x = %x, want %x", tt.in, back, tt.in)
			}
		})
	}
}

// TestBase64URL_acceptsPaddedInput records the asymmetry deliberately: output is
// unpadded, input tolerates padding.
func TestBase64URL_acceptsPaddedInput(t *testing.T) {
	t.Parallel()
	var got Base64URL
	if err := json.Unmarshal([]byte(`"_w=="`), &got); err != nil {
		t.Fatalf(`Unmarshal("_w=="): %v`, err)
	}
	if len(got) != 1 || got[0] != 0xff {
		t.Errorf(`Unmarshal("_w==") = %x, want ff`, got)
	}
}

// TestBase64URL_rejectsNonBase64 pins the error path, so a malformed member is a
// decode error rather than silent empty bytes.
func TestBase64URL_rejectsNonBase64(t *testing.T) {
	t.Parallel()
	var got Base64URL
	if err := json.Unmarshal([]byte(`"not base64!!"`), &got); err == nil {
		t.Errorf(`Unmarshal("not base64!!") = %x with nil error, want an error`, got)
	}
}

func testRelyingParty(t *testing.T) *RelyingParty {
	t.Helper()
	rp, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return rp
}

// optionsUser is an account holding two passkeys, one with transports.
func optionsUser() *User {
	return &User{
		AuthUser: &access.User{ID: 42, Username: "alex", DisplayName: "Alex", WebAuthnHandle: []byte("alex's user handle")},
		Credentials: []access.PasskeyCredential{
			{CredentialID: []byte{1, 2, 3}, Transport: "internal,hybrid"},
			{CredentialID: []byte{4, 5, 6}},
		},
	}
}

// jsonDoc is v's JSON decoded into maps, slices and scalars, so two
// documents compare by members and values, never by member order.
func jsonDoc(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("Unmarshal %s: %v", raw, err)
	}
	return doc
}

// optionsChallenge returns the publicKey challenge of doc, failing unless it
// is the unpadded base64url of 32 bytes (WebAuthn §13.4.3 asks for at least
// 16 random bytes).
func optionsChallenge(t *testing.T, doc any) string {
	t.Helper()
	top, _ := doc.(map[string]any)
	publicKey, _ := top["publicKey"].(map[string]any)
	challenge, ok := publicKey["challenge"].(string)
	if !ok {
		t.Fatalf("options %v carry no publicKey.challenge string", doc)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	if err != nil || len(raw) != 32 {
		t.Errorf("publicKey.challenge %q decodes to %d bytes (%v), want 32 as unpadded base64url", challenge, len(raw), err)
	}
	return challenge
}

// wantDoc fails unless got is exactly the JSON document want, with
// CHALLENGE standing for the options' own challenge.
func wantDoc(t *testing.T, what string, got any, want string) {
	t.Helper()
	expected := jsonDoc(t, json.RawMessage(strings.ReplaceAll(want, "CHALLENGE", optionsChallenge(t, got))))
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("%s =\n%s\nwant\n%s", what, mustJSON(t, got), mustJSON(t, expected))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}

// TestCreationOptions_WebAuthn5_4_members checks the whole creation options
// document against WebAuthn §5.4's member names and access's values: the
// offer order ML-DSA-44, -65, -87 (RFC 9964 §5), EdDSA, ES256, RS256; a
// required, user-verified resident key (§5.4.4, §5.4.6); the user's passkeys
// in excludeCredentials with their transports (§5.8.3); credProps (§10.1.3);
// a 300000 ms timeout; and no attestation, attestationFormats or hints.
func TestCreationOptions_WebAuthn5_4_members(t *testing.T) {
	t.Parallel()
	creation, _, err := BeginRegistration(testRelyingParty(t), optionsUser(), exampleOrigin(t))
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	wantDoc(t, "creation options", jsonDoc(t, creation), `{"publicKey": {
		"rp": {"name": "Example", "id": "example.com"},
		"user": {"name": "alex", "displayName": "Alex", "id": "`+base64.RawURLEncoding.EncodeToString([]byte("alex's user handle"))+`"},
		"challenge": "CHALLENGE",
		"pubKeyCredParams": [
			{"type": "public-key", "alg": -48}, {"type": "public-key", "alg": -49}, {"type": "public-key", "alg": -50},
			{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}
		],
		"timeout": 300000,
		"excludeCredentials": [
			{"type": "public-key", "id": "AQID", "transports": ["internal", "hybrid"]},
			{"type": "public-key", "id": "BAUG"}
		],
		"authenticatorSelection": {"residentKey": "required", "requireResidentKey": true, "userVerification": "required"},
		"extensions": {"credProps": true}
	}}`)
}

// TestRequestOptions_WebAuthn5_5_members checks each request options
// document against WebAuthn §5.5's member names and access's values:
// rpId, required user verification and a 300000 ms timeout; no
// allowCredentials for a discoverable login and the user's passkeys for a
// reauthentication (§5.5, §5.8.3); and mediation "conditional" for the
// conditional login only (Credential Management Level 1,
// CredentialMediationRequirement).
func TestRequestOptions_WebAuthn5_5_members(t *testing.T) {
	t.Parallel()
	rp := testRelyingParty(t)
	const common = `"rpId": "example.com", "userVerification": "required", "challenge": "CHALLENGE", "timeout": 300000`
	tests := []struct {
		begin func() (*CredentialAssertion, Ceremony, error)
		name  string
		want  string
	}{
		{
			name:  "login",
			begin: func() (*CredentialAssertion, Ceremony, error) { return BeginLogin(rp, exampleOrigin(t)) },
			want:  `{"publicKey": {` + common + `}}`,
		},
		{
			name:  "conditional_login",
			begin: func() (*CredentialAssertion, Ceremony, error) { return BeginConditionalLogin(rp, exampleOrigin(t)) },
			want:  `{"mediation": "conditional", "publicKey": {` + common + `}}`,
		},
		{
			name: "reauthentication",
			begin: func() (*CredentialAssertion, Ceremony, error) {
				return BeginReauthentication(rp, optionsUser(), exampleOrigin(t))
			},
			want: `{"publicKey": {` + common + `, "allowCredentials": [
				{"type": "public-key", "id": "AQID", "transports": ["internal", "hybrid"]},
				{"type": "public-key", "id": "BAUG"}
			]}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			options, _, err := tt.begin()
			if err != nil {
				t.Fatalf("Begin: %v", err)
			}
			wantDoc(t, tt.name+" options", jsonDoc(t, options), tt.want)
		})
	}
}
