package access

import "crypto/rand"

// WebAuthnHandleSize is the length of a generated user handle. WebAuthn caps a
// user handle at 64 bytes and §14.6.1 recommends using all of them, randomly.
const WebAuthnHandleSize = 64

// GenerateWebAuthnHandle returns a new WebAuthn user handle: 64 random bytes, as
// [WebAuthn §14.6.1] recommends. An authenticator may reveal the handle without
// verifying the user, so it carries nothing about the account: no username, no
// email, no sequential ID. Store it on [User.WebAuthnHandle]; it cannot fail
// (see [generateRandomHex]).
//
// [WebAuthn §14.6.1]: https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy
func GenerateWebAuthnHandle() []byte {
	b := make([]byte, WebAuthnHandleSize)
	rand.Read(b) // never returns an error (Go 1.24+); it crashes instead
	return b
}
