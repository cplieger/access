package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn/internal/cbor"
	"github.com/cplieger/access/webauthn/internal/cose"
)

// The authenticator data's refusals (WebAuthn §6.1, §6.5.1).
var (
	errAuthData         = errors.New("access/webauthn: authenticator data is not well-formed")
	errRPIDHash         = errors.New("access/webauthn: rpIdHash is not the SHA-256 of the RP ID")
	errUserPresence     = errors.New("access/webauthn: the authenticator did not report user presence")
	errUserVerification = errors.New("access/webauthn: the authenticator did not verify the user")
	errBackupState      = errors.New("access/webauthn: backup state set on a credential that is not backup eligible")
	errAttestedData     = errors.New("access/webauthn: attested credential data is missing from a registration or present in an assertion")
	errCredentialID     = errors.New("access/webauthn: the attested credential ID is not rawId")
	errCredentialKey    = errors.New("access/webauthn: the credential public key is refused")
)

const (
	// maxCredentialIDBytes is §7.1's bound on a credential ID.
	maxCredentialIDBytes = 1023
	// rpIdHash, flags and signCount (§6.1).
	minAuthDataBytes = sha256.Size + 1 + 4
	// AAGUID and credentialIdLength (§6.5.1).
	attestedHeadBytes = 16 + 2
)

// The flags bits that shape authenticator data (§6.1).
const (
	flagAttested   = 1 << 6 // AT
	flagExtensions = 1 << 7 // ED
)

type authData struct {
	attested  *attestedCredential // nil when AT is clear
	rpIDHash  []byte
	signCount uint32
	flags     uint8
}

// attestedCredential is attested credential data (§6.5.1); its slices alias
// the authenticator data.
type attestedCredential struct {
	aaguid []byte
	id     []byte
	// publicKey is the COSE_Key's bytes as received.
	publicKey []byte
}

// parseAuthData reads authenticator data's structure (§6.1): with AT set,
// attested credential data with a credential ID of 1 to 1023 bytes and one
// well-formed CBOR item as its key; with ED set, one CBOR map of extension
// outputs, checked and not read; no byte after either. It checks no value.
func parseAuthData(raw []byte) (*authData, error) {
	if len(raw) < minAuthDataBytes {
		return nil, fmt.Errorf("%w: %d bytes", errAuthData, len(raw))
	}
	a := &authData{
		rpIDHash:  raw[:sha256.Size],
		flags:     raw[sha256.Size],
		signCount: binary.BigEndian.Uint32(raw[sha256.Size+1 : minAuthDataBytes]),
	}
	rest := raw[minAuthDataBytes:]
	if a.flags&flagAttested != 0 {
		cred, after, err := parseAttestedCredential(rest)
		if err != nil {
			return nil, err
		}
		a.attested, rest = cred, after
	}
	if a.flags&flagExtensions != 0 {
		ext, after, err := cbor.Decode(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: extensions: %w", errAuthData, err)
		}
		if _, isMap := ext.Map(); !isMap {
			return nil, fmt.Errorf("%w: extensions are not a CBOR map", errAuthData)
		}
		rest = after
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after the last flagged item", errAuthData, len(rest))
	}
	return a, nil
}

func parseAttestedCredential(b []byte) (*attestedCredential, []byte, error) {
	if len(b) < attestedHeadBytes {
		return nil, nil, fmt.Errorf("%w: attested credential data of %d bytes", errAuthData, len(b))
	}
	n := int(binary.BigEndian.Uint16(b[16:attestedHeadBytes]))
	if n == 0 || n > maxCredentialIDBytes {
		return nil, nil, fmt.Errorf("%w: a credential ID of %d bytes", errAuthData, n)
	}
	if len(b)-attestedHeadBytes < n {
		return nil, nil, fmt.Errorf("%w: the credential ID runs past the data", errAuthData)
	}
	key := b[attestedHeadBytes+n:]
	_, after, err := cbor.Decode(key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: credential public key: %w", errAuthData, err)
	}
	return &attestedCredential{
		aaguid:    b[:16],
		id:        b[attestedHeadBytes : attestedHeadBytes+n],
		publicKey: key[:len(key)-len(after)],
	}, after, nil
}

// verify runs the checks §7.1 and §7.2 share, in their order: the rpIdHash,
// UP, UV (access always requires it), and BS only with BE (§6.1.3).
func (a *authData) verify(rpID string) error {
	want := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(a.rpIDHash, want[:]) {
		return errRPIDHash
	}
	up, uv, be, bs := access.DecodePasskeyFlags(a.flags)
	switch {
	case !up:
		return errUserPresence
	case !uv:
		return errUserVerification
	case bs && !be:
		return errBackupState
	}
	return nil
}

// registrationAuthData parses and checks a registration's authenticator data
// (§7.1): the shared checks, attested credential data whose ID is rawID, and
// a credential public key cose.ParseKey accepts, which is also §7.1's check
// that its alg was offered.
func registrationAuthData(raw []byte, rpID string, rawID []byte) (*authData, *cose.Key, error) {
	a, err := parseAuthData(raw)
	if err == nil {
		err = a.verify(rpID)
	}
	if err != nil {
		return nil, nil, err
	}
	if a.attested == nil {
		return nil, nil, errAttestedData
	}
	if !bytes.Equal(a.attested.id, rawID) {
		return nil, nil, errCredentialID
	}
	key, err := cose.ParseKey(a.attested.publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errCredentialKey, err)
	}
	return a, key, nil
}

// assertionAuthData parses and checks an assertion's authenticator data
// (§7.2): the shared checks, and AT clear, since only a registration attests
// a credential (§6.1).
func assertionAuthData(raw []byte, rpID string) (*authData, error) {
	a, err := parseAuthData(raw)
	if err == nil {
		err = a.verify(rpID)
	}
	if err != nil {
		return nil, err
	}
	if a.attested != nil {
		return nil, errAttestedData
	}
	return a, nil
}
