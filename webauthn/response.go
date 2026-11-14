package webauthn

import (
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"github.com/cplieger/access"
)

// The response JSON's refusals (WebAuthn §5.1).
var (
	errResponseJSON   = errors.New("access/webauthn: the response is not a well-formed credential JSON")
	errCredentialType = errors.New("access/webauthn: the credential type is not public-key")
	errRawID          = errors.New("access/webauthn: rawId is not the unpadded base64url of 1 to 1023 bytes")
	errIDMismatch     = errors.New("access/webauthn: id is not the unpadded base64url of rawId")
	errUserHandle     = errors.New("access/webauthn: userHandle is not the unpadded base64url of 1 to 64 bytes")
)

const (
	// maxUserHandleBytes is §5.4.3's bound on a user handle.
	maxUserHandleBytes = 64
	// The record joins transports with commas, so a kept value is short and
	// holds none.
	maxTransports     = 8
	maxTransportBytes = 32
)

// credentialHead holds the members RegistrationResponseJSON and
// AuthenticationResponseJSON share (§5.1).
type credentialHead struct {
	ID    string `json:"id"`
	RawID string `json:"rawId"`
	Type  string `json:"type"`
}

// base64URL is a binary member that is hashed, parsed or verified as bytes,
// so its spelling carries no meaning and the trailing padding some clients
// send is tolerated.
type base64URL []byte

func (b *base64URL) UnmarshalText(text []byte) error {
	d, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(string(text), "="))
	if err != nil {
		return err
	}
	*b = d
	return nil
}

// registrationResponse is a registration ceremony's response, read from its
// RegistrationResponseJSON.
type registrationResponse struct {
	// residentKey is the credProps output's rk, nil when the client sent none.
	residentKey       *bool
	attachment        access.AuthenticatorAttachment
	rawID             []byte
	clientDataJSON    []byte
	attestationObject []byte
	transports        []string
}

// assertionResponse is an authentication ceremony's response, read from its
// AuthenticationResponseJSON.
type assertionResponse struct {
	rawID             []byte
	clientDataJSON    []byte
	authenticatorData []byte
	signature         []byte
	// userHandle is nil when the response carries none.
	userHandle []byte
}

// parseRegistrationResponse reads a RegistrationResponseJSON (§5.1). Member
// names match exactly, a duplicate member or invalid UTF-8 is refused (RFC
// 8259 §4, §8.1), and members it does not read are ignored (§5.1.8).
func parseRegistrationResponse(body []byte) (*registrationResponse, error) {
	var r struct {
		ClientExtensionResults struct {
			CredProps struct {
				RK *bool `json:"rk"`
			} `json:"credProps"`
		} `json:"clientExtensionResults"`
		Head                    credentialHead `json:",embed"`
		AuthenticatorAttachment string         `json:"authenticatorAttachment"`
		Response                struct {
			ClientDataJSON    base64URL `json:"clientDataJSON"`
			AttestationObject base64URL `json:"attestationObject"`
			Transports        []string  `json:"transports"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", errResponseJSON, err)
	}
	rawID, err := r.Head.credentialID()
	if err != nil {
		return nil, err
	}
	return &registrationResponse{
		rawID:             rawID,
		clientDataJSON:    r.Response.ClientDataJSON,
		attestationObject: r.Response.AttestationObject,
		transports:        keptTransports(r.Response.Transports),
		attachment:        attachment(r.AuthenticatorAttachment),
		residentKey:       r.ClientExtensionResults.CredProps.RK,
	}, nil
}

// parseAssertionResponse reads an AuthenticationResponseJSON (§5.1) under
// parseRegistrationResponse's rules. Its client extension outputs are not
// read, since no assertion requests one.
func parseAssertionResponse(body []byte) (*assertionResponse, error) {
	var r struct {
		Head     credentialHead `json:",embed"`
		Response struct {
			UserHandle        *string   `json:"userHandle"`
			ClientDataJSON    base64URL `json:"clientDataJSON"`
			AuthenticatorData base64URL `json:"authenticatorData"`
			Signature         base64URL `json:"signature"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", errResponseJSON, err)
	}
	rawID, err := r.Head.credentialID()
	if err != nil {
		return nil, err
	}
	var handle []byte
	if r.Response.UserHandle != nil {
		handle, err = decodeUnpadded(*r.Response.UserHandle)
		if err != nil || len(handle) == 0 || len(handle) > maxUserHandleBytes {
			return nil, errUserHandle
		}
	}
	return &assertionResponse{
		rawID:             rawID,
		clientDataJSON:    r.Response.ClientDataJSON,
		authenticatorData: r.Response.AuthenticatorData,
		signature:         r.Response.Signature,
		userHandle:        handle,
	}, nil
}

// credentialID checks type, rawId and id and returns rawId's bytes.
func (h *credentialHead) credentialID() ([]byte, error) {
	if h.Type != "public-key" {
		return nil, errCredentialType
	}
	raw, err := decodeUnpadded(h.RawID)
	if err != nil || len(raw) == 0 || len(raw) > maxCredentialIDBytes {
		return nil, errRawID
	}
	// decodeUnpadded admits one spelling of raw, so id encodes the same
	// bytes exactly when it is the same string.
	if h.ID != h.RawID {
		return nil, errIDMismatch
	}
	return raw, nil
}

// decodeUnpadded reads s as unpadded base64url, admitting no other spelling
// of the same bytes.
func decodeUnpadded(s string) ([]byte, error) {
	// encoding/base64 skips CR and LF, in Strict mode too.
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("a line break in base64url")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// keptTransports drops each value the record cannot hold and keeps at most
// maxTransports of the rest, in order.
func keptTransports(in []string) []string {
	var out []string
	for _, t := range in {
		if len(out) == maxTransports {
			break
		}
		if t != "" && len(t) <= maxTransportBytes && !strings.Contains(t, ",") {
			out = append(out, t)
		}
	}
	return out
}

// attachment keeps the two attachment modalities (§5.4.5) and reads any other
// value as none, since an unknown enumeration value is ignored (§2.1.1).
func attachment(s string) access.AuthenticatorAttachment {
	switch a := access.AuthenticatorAttachment(s); a {
	case access.AttachmentPlatform, access.AttachmentCrossPlatform:
		return a
	default:
		return ""
	}
}
