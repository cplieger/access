package webauthn

import (
	"bytes"
	"errors"
	"time"
)

// ceremonyKind is the Begin function a ceremony came from, which decides the
// one finish that may complete it.
type ceremonyKind uint8

const (
	ceremonyRegistration ceremonyKind = iota + 1
	ceremonyLogin
	ceremonyReauthentication
)

// The ceremony's refusals.
var (
	errCeremonyKind    = errors.New("access/webauthn: the ceremony was begun for another kind of finish")
	errCeremonyExpired = errors.New("access/webauthn: the ceremony has expired")
	errCeremonyUser    = errors.New("access/webauthn: the ceremony was begun for another user")
)

// ceremonyState is one ceremony's server-side state, set at Begin and never
// changed after.
type ceremonyState struct {
	expires time.Time
	// origin is the one the ceremony began at, which passed CheckOrigin; the
	// response's client data must name it.
	origin    Origin
	challenge []byte
	// userHandle is the user's WebAuthn ID, for registration and
	// reauthentication.
	userHandle []byte
	kind       ceremonyKind
}

// check refuses st unless it came from a Begin function of kind and its
// challenge has not outlived the ceremony timeout (§13.4.3).
func (st *ceremonyState) check(kind ceremonyKind) error {
	switch {
	case st == nil:
		return ErrCeremonyUnbound
	case st.kind != kind:
		return errCeremonyKind
	case !time.Now().Before(st.expires):
		return errCeremonyExpired
	}
	return nil
}

// heldBy refuses st unless it was begun for user.
func (st *ceremonyState) heldBy(user *User) error {
	if !bytes.Equal(st.userHandle, user.WebAuthnID()) {
		return errCeremonyUser
	}
	return nil
}
