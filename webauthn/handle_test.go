package webauthn

import (
	"bytes"
	"testing"

	"github.com/cplieger/access"
)

// TestUser_WebAuthnID_returnsTheStoredHandle: the account presents the handle
// the store holds, byte for byte. A passkey is bound to that value, so anything
// but an exact passthrough stops the credential resolving.
func TestUser_WebAuthnID_returnsTheStoredHandle(t *testing.T) {
	t.Parallel()
	stored := access.GenerateWebAuthnHandle()
	u := &User{AuthUser: &access.User{ID: 7, Username: "alex", WebAuthnHandle: stored}}

	got := u.WebAuthnID()

	if !bytes.Equal(got, stored) {
		t.Errorf("WebAuthnID() = %x, want the stored handle %x", got, stored)
	}
}
