package webauthn

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
)

// The client data's refusals (WebAuthn §5.8.1).
var (
	errClientData     = errors.New("access/webauthn: clientDataJSON is not well-formed")
	errClientDataType = errors.New("access/webauthn: the client data type is not the ceremony's")
	errChallenge      = errors.New("access/webauthn: the client data challenge is not the ceremony's")
	errOrigin         = errors.New("access/webauthn: the client data origin is not the one the ceremony began at")
	errFramed         = errors.New("access/webauthn: the client data reports a cross-origin frame")
)

// maxClientDataBytes bounds clientDataJSON, which a browser fills with four
// short members.
const maxClientDataBytes = 4 << 10

// clientDataType is CollectedClientData's type member.
type clientDataType string

const (
	clientDataCreate clientDataType = "webauthn.create"
	clientDataGet    clientDataType = "webauthn.get"
)

// utf8BOM is stripped before parsing, as WebAuthn §7.1's UTF-8 decode step
// requires.
var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// verifyClientData checks clientDataJSON against the ceremony it answers and
// returns its hash, SHA-256 of raw as received (WebAuthn §7.1 and §7.2's hash
// step). origin is the one the ceremony began at; its serialization is the
// only origin accepted, and access is never framed, so crossOrigin true and
// any topOrigin are refused.
func verifyClientData(raw []byte, typ clientDataType, challenge []byte, origin Origin) ([sha256.Size]byte, error) {
	if len(raw) > maxClientDataBytes {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %d bytes", errClientData, len(raw))
	}
	var c struct {
		Type        string         `json:"type"`
		Challenge   string         `json:"challenge"`
		Origin      string         `json:"origin"`
		TopOrigin   jsontext.Value `json:"topOrigin"`
		CrossOrigin bool           `json:"crossOrigin"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(raw, utf8BOM), &c); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %w", errClientData, err)
	}
	want := base64.RawURLEncoding.EncodeToString(challenge)
	switch {
	case c.Type != string(typ):
		return [sha256.Size]byte{}, errClientDataType
	case subtle.ConstantTimeCompare([]byte(c.Challenge), []byte(want)) != 1:
		return [sha256.Size]byte{}, errChallenge
	case c.Origin != origin.String():
		return [sha256.Size]byte{}, errOrigin
	case c.CrossOrigin, len(c.TopOrigin) != 0:
		return [sha256.Size]byte{}, errFramed
	}
	return sha256.Sum256(raw), nil
}
