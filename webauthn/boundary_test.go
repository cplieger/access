package webauthn

import (
	"testing"

	"github.com/cplieger/access"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// TestRegistrationRecord_recordsTheRelyingParty pins the field that makes a
// relying-party rename detectable. Without it a stored passkey cannot say which
// relying party it belongs to, and changing the RP ID silently orphans every one
// of them.
func TestRegistrationRecord_recordsTheRelyingParty(t *testing.T) {
	t.Parallel()
	rp := testRelyingParty(t)
	user := &User{AuthUser: &access.User{ID: 99, Username: "alex"}}
	cred := &gowebauthn.Credential{ID: []byte{1, 2, 3}, PublicKey: []byte{4, 5}}

	got, err := registrationRecord(rp, user, cred)
	if err != nil {
		t.Fatalf("registrationRecord: %v", err)
	}

	if got.RPID != "example.com" {
		t.Errorf("registrationRecord().RPID = %q, want %q", got.RPID, "example.com")
	}
	if got.UserID != 99 {
		t.Errorf("registrationRecord().UserID = %d, want 99", got.UserID)
	}
	if got.Name != "" {
		t.Errorf("registrationRecord().Name = %q, want empty (the caller derives it from existing names)", got.Name)
	}
}

// TestUserAdapter_satisfiesUpstreamWithoutExportingIt pins the adapter the
// ceremony functions hand upstream: the exported User's three methods, and the
// credential conversion only the unexported adapter carries.
func TestUserAdapter_satisfiesUpstreamWithoutExportingIt(t *testing.T) {
	t.Parallel()
	user := &User{
		AuthUser: &access.User{ID: 1, Username: "alex", DisplayName: "Alex"},
		Credentials: []access.PasskeyCredential{
			{CredentialID: []byte{7}, Transport: "internal"},
		},
	}
	adapter := &userAdapter{User: user}

	if got := adapter.WebAuthnName(); got != "alex" {
		t.Errorf("adapter.WebAuthnName() = %q, want %q", got, "alex")
	}
	if got := adapter.WebAuthnDisplayName(); got != "Alex" {
		t.Errorf("adapter.WebAuthnDisplayName() = %q, want %q", got, "Alex")
	}
	creds := adapter.WebAuthnCredentials()
	if len(creds) != 1 {
		t.Fatalf("adapter.WebAuthnCredentials() len = %d, want 1", len(creds))
	}
	if creds[0].ID[0] != 7 {
		t.Errorf("adapter.WebAuthnCredentials()[0].ID = %v, want [7]", creds[0].ID)
	}
}
