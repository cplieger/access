package webauthn

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/cplieger/access"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// TestCreationOptions_serializesLikeUpstream is the test that makes the
// first-party options types safe to ship. The browser reads these dictionaries
// with its own parsers, so a renamed member or a different binary encoding does
// not fail loudly — it produces a ceremony that silently never completes.
//
// Upstream is the oracle: it is the implementation that was on the wire before
// this mirror existed. The two values are marshalled from ONE ceremony, because
// the challenge is fresh per call and two ceremonies could never match.
func TestCreationOptions_serializesLikeUpstream(t *testing.T) {
	t.Parallel()
	rp := testRelyingParty(t)
	user := &User{AuthUser: &access.User{ID: 42, Username: "alex", DisplayName: "Alex", WebAuthnHandle: access.GenerateWebAuthnHandle()}}

	upstream, _, err := testHandle(t, rp).BeginRegistration(&userAdapter{User: user},
		gowebauthn.WithRegistrationOrigin(testOrigin),
		gowebauthn.WithCredentialParameters(gowebauthn.CredentialParametersPQCRecommendedL3()),
		gowebauthn.WithAuthenticatorSelection(upstreamSelection()),
		gowebauthn.WithExclusions(gowebauthn.Credentials((&userAdapter{User: user}).WebAuthnCredentials()).CredentialDescriptors()),
		gowebauthn.WithExtensions(gowebauthn.WithExtensionCredProps()),
	)
	if err != nil {
		t.Fatalf("upstream BeginRegistration: %v", err)
	}

	assertSameJSON(t, "registration options", upstream, creationFromUpstream(upstream, user.WebAuthnID()))
}

// TestRequestOptions_serializesLikeUpstream is the login half.
func TestRequestOptions_serializesLikeUpstream(t *testing.T) {
	t.Parallel()
	rp := testRelyingParty(t)

	upstream, _, err := testHandle(t, rp).BeginDiscoverableLogin(
		gowebauthn.WithLoginOrigin(testOrigin),
		gowebauthn.WithUserVerification("required"),
	)
	if err != nil {
		t.Fatalf("upstream BeginDiscoverableLogin: %v", err)
	}

	assertSameJSON(t, "assertion options", upstream, assertionFromUpstream(upstream))
}

// TestRequestOptions_serializesLikeUpstream_conditional covers the
// mediation member, which the plain login case above leaves empty on both sides
// — so without this case, dropping mediation from the conversion goes unnoticed.
// Conditional mediation is what drives the browser's passkey autofill, so losing
// it would turn autofill off silently.
func TestRequestOptions_serializesLikeUpstream_conditional(t *testing.T) {
	t.Parallel()
	rp := testRelyingParty(t)

	upstream, _, err := testHandle(t, rp).BeginDiscoverableMediatedLogin(protocol.MediationConditional,
		gowebauthn.WithLoginOrigin(testOrigin),
		gowebauthn.WithUserVerification("required"),
	)
	if err != nil {
		t.Fatalf("upstream BeginDiscoverableMediatedLogin: %v", err)
	}
	if upstream.Mediation != protocol.MediationConditional {
		t.Fatalf("upstream mediation = %q, want %q (fixture is not exercising mediation)",
			upstream.Mediation, protocol.MediationConditional)
	}

	assertSameJSON(t, "conditional assertion options", upstream, assertionFromUpstream(upstream))
}

// TestCreationOptions_serializesLikeUpstream_withExcludedCredential
// covers the descriptor list, which the empty-registration case above leaves
// out and which carries a binary member and a transport list.
func TestCreationOptions_serializesLikeUpstream_withExcludedCredential(t *testing.T) {
	t.Parallel()
	rp := testRelyingParty(t)
	user := &User{
		AuthUser: &access.User{ID: 42, Username: "alex", DisplayName: "Alex", WebAuthnHandle: access.GenerateWebAuthnHandle()},
		Credentials: []access.PasskeyCredential{
			{CredentialID: []byte{1, 2, 3}, Transport: "internal,hybrid"},
			{CredentialID: []byte{4, 5, 6}, Transport: "usb"},
		},
	}

	upstream, _, err := testHandle(t, rp).BeginRegistration(&userAdapter{User: user},
		gowebauthn.WithRegistrationOrigin(testOrigin),
		gowebauthn.WithCredentialParameters(gowebauthn.CredentialParametersPQCRecommendedL3()),
		gowebauthn.WithAuthenticatorSelection(upstreamSelection()),
		gowebauthn.WithExclusions(gowebauthn.Credentials((&userAdapter{User: user}).WebAuthnCredentials()).CredentialDescriptors()),
		gowebauthn.WithExtensions(gowebauthn.WithExtensionCredProps()),
	)
	if err != nil {
		t.Fatalf("upstream BeginRegistration: %v", err)
	}
	if len(upstream.Response.CredentialExcludeList) != 2 {
		t.Fatalf("upstream exclude list len = %d, want 2 (fixture is not exercising descriptors)",
			len(upstream.Response.CredentialExcludeList))
	}

	assertSameJSON(t, "registration options with exclusions", upstream, creationFromUpstream(upstream, user.WebAuthnID()))
}

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
// Level 1 clients, which read only requireResidentKey (design 7.4).
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
// attestation member is the default "none" (WebAuthn §5.4.7, design 7.4), and
// access sends no hints (§5.8.7, design 7.16 R1).
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

const testOrigin = "https://example.com"

// testHandle is the upstream oracle for one ceremony at testOrigin, which is
// what every Begin function builds for the origin it is handed.
func testHandle(t *testing.T, rp *RelyingParty) *gowebauthn.WebAuthn {
	t.Helper()
	wa, err := rp.handleFor(testOrigin)
	if err != nil {
		t.Fatalf("handleFor(%q): %v", testOrigin, err)
	}
	return wa
}

func upstreamSelection() protocol.AuthenticatorSelection {
	return protocol.AuthenticatorSelection{
		ResidentKey:        "required",
		RequireResidentKey: protocol.ResidentKeyRequired(),
		UserVerification:   "required",
	}
}

// assertSameJSON marshals both values and compares them as decoded documents.
// The comparison is semantic rather than byte-for-byte on purpose: JSON objects
// are unordered and the browser reads these members by name, so field
// declaration order is free to follow whatever the alignment linter prefers.
// What must match is the member set, the nesting, and every encoded value.
func assertSameJSON(t *testing.T, what string, upstream, mirror any) {
	t.Helper()
	wantJSON, err := json.Marshal(upstream)
	if err != nil {
		t.Fatalf("Marshal upstream %s: %v", what, err)
	}
	gotJSON, err := json.Marshal(mirror)
	if err != nil {
		t.Fatalf("Marshal first-party %s: %v", what, err)
	}

	var want, got any
	if err := json.Unmarshal(wantJSON, &want); err != nil {
		t.Fatalf("Unmarshal upstream %s: %v", what, err)
	}
	if err := json.Unmarshal(gotJSON, &got); err != nil {
		t.Fatalf("Unmarshal first-party %s: %v", what, err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("first-party %s does not serialize to the same document as upstream\n got: %s\nwant: %s", what, gotJSON, wantJSON)
	}
}
