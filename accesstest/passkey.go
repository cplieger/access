package accesstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// The authenticator-data flag bits (W3C WebAuthn L3 §6.1).
const (
	flagUserPresent    = 0x01
	flagUserVerified   = 0x04
	flagBackupEligible = 0x08
	flagBackupState    = 0x10
	flagAttestedData   = 0x40
)

// A synced passkey: present, verified, backup eligible and backed up.
const (
	passkeyAssertionFlags    = flagUserPresent | flagUserVerified | flagBackupEligible | flagBackupState
	passkeyRegistrationFlags = passkeyAssertionFlags | flagAttestedData
)

const (
	coseAlgES256         = -7
	passkeyIDBytes       = 32
	maxCredentialIDBytes = 1<<16 - 1 // the attested data's two-byte length field
)

// PasskeyDevice is a software WebAuthn authenticator holding one discoverable
// ES256 credential with "none" attestation. Register and Assert read the
// options JSON a relying party sends the browser (a {"publicKey": …} object)
// and return the PublicKeyCredential.toJSON() body the browser sends back.
// The device answers every options it can parse: it ignores allowCredentials
// and excludeCredentials, so a test can present a credential a real
// authenticator would withhold. The exported fields are knobs a test may set
// between ceremonies; a PasskeyDevice is not safe for concurrent use.
type PasskeyDevice struct {
	t   testing.TB
	key *ecdsa.PrivateKey
	// rpID and userID are those of the last registration.
	rpID   string
	userID []byte

	// CredentialID is the credential's raw ID; NewPasskeyDevice draws 32
	// random bytes.
	CredentialID []byte
	// Origin is the origin clientDataJSON names; empty is "https://" plus the
	// RP ID.
	Origin string
	// UserHandle is the userHandle an assertion carries. Nil is the user ID of
	// the last registration (none before one); a non-nil empty slice sends no
	// userHandle.
	UserHandle []byte
	// SignCount is the signature counter of the last ceremony. A registration
	// reports it unchanged and an assertion increments it before signing, so
	// setting it below a value already sent makes the next assertion a
	// regression.
	SignCount uint32
	// Flags, when non-zero, is the authenticator-data flags octet of every
	// ceremony, written as given: a registration still appends the attested
	// credential data whatever the AT bit says. Zero is UP, UV, BE and BS
	// (0x1D), plus AT (0x40) on a registration.
	Flags byte
}

// NewPasskeyDevice returns a device with a fresh P-256 key and a random
// credential ID. Register and Assert fail through the t given to
// NewPasskeyDevice on options they cannot answer, so call them on that
// test's goroutine; a subtest makes its own device.
func NewPasskeyDevice(t testing.TB) *PasskeyDevice {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("accesstest: passkey key: %v", err)
	}
	id := make([]byte, passkeyIDBytes)
	rand.Read(id) // never returns an error (Go 1.24+); it crashes instead
	return &PasskeyDevice{t: t, key: key, CredentialID: id}
}

type passkeyCredParam struct {
	Type      string `json:"type"`
	Algorithm int    `json:"alg"`
}

type passkeyCreationOptions struct {
	PublicKey *struct {
		RP struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Challenge  string             `json:"challenge"`
		Parameters []passkeyCredParam `json:"pubKeyCredParams"`
		Extensions struct {
			CredProps bool `json:"credProps"`
		} `json:"extensions"`
	} `json:"publicKey"`
}

type passkeyRequestOptions struct {
	PublicKey *struct {
		RPID      string `json:"rpId"`
		Challenge string `json:"challenge"`
	} `json:"publicKey"`
}

type passkeyCredentialJSON[R any] struct {
	Response                R              `json:"response"`
	ClientExtensionResults  map[string]any `json:"clientExtensionResults"`
	ID                      string         `json:"id"`
	RawID                   string         `json:"rawId"`
	Type                    string         `json:"type"`
	AuthenticatorAttachment string         `json:"authenticatorAttachment"`
}

type passkeyAttestationJSON struct {
	ClientDataJSON     string   `json:"clientDataJSON"`
	AuthenticatorData  string   `json:"authenticatorData"`
	PublicKey          string   `json:"publicKey"`
	AttestationObject  string   `json:"attestationObject"`
	Transports         []string `json:"transports"`
	PublicKeyAlgorithm int      `json:"publicKeyAlgorithm"`
}

type passkeyAssertionJSON struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// Register answers credential creation options with a registration body and
// records the RP ID and user ID for later assertions. It fails the test when
// the options do not parse, lack a challenge or user ID, offer no ES256
// parameter, leave the RP ID unknown, or CredentialID is over 65535 bytes.
func (d *PasskeyDevice) Register(options []byte) []byte {
	d.t.Helper()
	var opts passkeyCreationOptions
	d.parseOptions("creation", options, &opts)
	pk := opts.PublicKey
	if pk == nil {
		d.t.Fatalf("accesstest: passkey creation options have no publicKey member")
	}
	challenge := d.decode("challenge", pk.Challenge)
	userID := d.decode("user.id", pk.User.ID)
	es256 := func(p passkeyCredParam) bool { return p.Type == "public-key" && p.Algorithm == coseAlgES256 }
	// An empty list means ES256 and RS256 (W3C WebAuthn L3 §5.1.3 step 10).
	if len(pk.Parameters) > 0 && !slices.ContainsFunc(pk.Parameters, es256) {
		d.t.Fatalf("accesstest: passkey creation options offer no ES256 (alg -7) parameter")
	}
	if len(d.CredentialID) > maxCredentialIDBytes {
		d.t.Fatalf("accesstest: passkey CredentialID is %d bytes, over the %d authenticator data can hold", len(d.CredentialID), maxCredentialIDBytes)
	}
	rpID := d.resolveRPID(pk.RP.ID)
	point, err := d.key.PublicKey.Bytes()
	if err != nil {
		d.t.Fatalf("accesstest: passkey public key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&d.key.PublicKey)
	if err != nil {
		d.t.Fatalf("accesstest: passkey public key: %v", err)
	}
	authData := d.authData(rpID, passkeyRegistrationFlags)
	authData = append(authData, make([]byte, 16)...)                                // the zero AAGUID of "none" attestation
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(d.CredentialID))) //nolint:gosec // G115: at most maxCredentialIDBytes, checked above
	authData = append(authData, d.CredentialID...)
	authData = append(authData, coseES256Key(point[1:33], point[33:65])...)
	extensions := map[string]any{}
	if pk.Extensions.CredProps {
		extensions["credProps"] = map[string]bool{"rk": true}
	}
	response := passkeyAttestationJSON{
		ClientDataJSON:     b64(d.clientData("webauthn.create", challenge, rpID)),
		AuthenticatorData:  b64(authData),
		Transports:         []string{"hybrid", "internal"},
		PublicKey:          b64(spki),
		PublicKeyAlgorithm: coseAlgES256,
		AttestationObject:  b64(noneAttestationObject(authData)),
	}
	d.rpID, d.userID = rpID, userID
	return credentialBody(d, response, extensions)
}

// Assert answers credential request options with an assertion body signed by
// the device's key, after incrementing SignCount. The RP ID is the options'
// rpId, else the last registration's, else Origin's host; the test fails when
// none is known or the options do not parse or lack a challenge.
func (d *PasskeyDevice) Assert(options []byte) []byte {
	d.t.Helper()
	var opts passkeyRequestOptions
	d.parseOptions("request", options, &opts)
	if opts.PublicKey == nil {
		d.t.Fatalf("accesstest: passkey request options have no publicKey member")
	}
	challenge := d.decode("challenge", opts.PublicKey.Challenge)
	rpID := d.resolveRPID(opts.PublicKey.RPID)
	d.SignCount++
	clientData := d.clientData("webauthn.get", challenge, rpID)
	authData := d.authData(rpID, passkeyAssertionFlags)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(slices.Clone(authData), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, d.key, digest[:])
	if err != nil {
		d.t.Fatalf("accesstest: passkey signature: %v", err)
	}
	handle := d.UserHandle
	if handle == nil {
		handle = d.userID
	}
	response := passkeyAssertionJSON{
		ClientDataJSON:    b64(clientData),
		AuthenticatorData: b64(authData),
		Signature:         b64(sig),
		UserHandle:        b64(handle),
	}
	return credentialBody(d, response, map[string]any{})
}

func (d *PasskeyDevice) parseOptions(kind string, options []byte, into any) {
	d.t.Helper()
	if err := json.Unmarshal(options, into); err != nil {
		d.t.Fatalf("accesstest: passkey %s options: %v", kind, err)
	}
}

// decode reads a base64url member, padded or not, and fails the test when it
// is empty or malformed.
func (d *PasskeyDevice) decode(member, value string) []byte {
	d.t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
	if err != nil || len(raw) == 0 {
		d.t.Fatalf("accesstest: passkey options %s %q is not non-empty base64url", member, value)
	}
	return raw
}

func (d *PasskeyDevice) resolveRPID(fromOptions string) string {
	d.t.Helper()
	if fromOptions != "" {
		return fromOptions
	}
	if d.rpID != "" {
		return d.rpID
	}
	if u, err := url.Parse(d.Origin); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	d.t.Fatalf("accesstest: passkey options name no RP ID, and neither a registration nor Origin supplies one")
	return ""
}

func (d *PasskeyDevice) clientData(ceremony string, challenge []byte, rpID string) []byte {
	d.t.Helper()
	origin := d.Origin
	if origin == "" {
		origin = "https://" + rpID
	}
	data, err := json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{ceremony, b64(challenge), origin, false})
	if err != nil {
		d.t.Fatalf("accesstest: passkey client data: %v", err)
	}
	return data
}

// authData builds the fixed 37-byte head of authenticator data: the RP ID
// hash, the flags octet and the big-endian signature counter.
func (d *PasskeyDevice) authData(rpID string, defaultFlags byte) []byte {
	flags := d.Flags
	if flags == 0 {
		flags = defaultFlags
	}
	rpHash := sha256.Sum256([]byte(rpID))
	data := make([]byte, 0, len(rpHash)+5)
	data = append(data, rpHash[:]...)
	data = append(data, flags)
	return binary.BigEndian.AppendUint32(data, d.SignCount)
}

func credentialBody[R any](d *PasskeyDevice, response R, extensions map[string]any) []byte {
	d.t.Helper()
	id := b64(d.CredentialID)
	out, err := json.Marshal(passkeyCredentialJSON[R]{
		ID:                      id,
		RawID:                   id,
		Type:                    "public-key",
		Response:                response,
		AuthenticatorAttachment: "platform",
		ClientExtensionResults:  extensions,
	})
	if err != nil {
		d.t.Fatalf("accesstest: passkey body: %v", err)
	}
	return out
}

// noneAttestationObject encodes {"fmt": "none", "attStmt": {}, "authData": …}
// in CTAP2 canonical CBOR, whose map keys sort by encoded length first (CTAP
// 2.1 §8 "Message Encoding").
func noneAttestationObject(authData []byte) []byte {
	out := cborHead(nil, cborMap, 3)
	out = cborText(out, "fmt")
	out = cborText(out, "none")
	out = cborText(out, "attStmt")
	out = cborHead(out, cborMap, 0)
	out = cborText(out, "authData")
	return cborBytes(out, authData)
}

// coseES256Key encodes a P-256 public key as a COSE_Key (RFC 9053 §7.1.1),
// {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}, keys in canonical
// order.
func coseES256Key(x, y []byte) []byte {
	out := cborHead(nil, cborMap, 5)
	out = append(out, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21)
	out = cborBytes(out, x)
	out = append(out, 0x22)
	return cborBytes(out, y)
}

// CBOR major types (RFC 8949 §3.1).
const (
	cborByteString = 2
	cborTextString = 3
	cborMap        = 5
)

// cborHead appends a data item's initial byte and argument (RFC 8949 §3).
// Every length the device writes fits in 32 bits.
func cborHead(out []byte, major byte, n int) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(out, m|byte(n)) //nolint:gosec // G115: n < 24 in this case
	case n <= 0xff:
		return append(out, m|24, byte(n))
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16(append(out, m|25), uint16(n))
	default:
		return binary.BigEndian.AppendUint32(append(out, m|26), uint32(n)) //nolint:gosec // G115: see the function comment
	}
}

func cborText(out []byte, s string) []byte {
	return append(cborHead(out, cborTextString, len(s)), s...)
}

func cborBytes(out, b []byte) []byte {
	return append(cborHead(out, cborByteString, len(b)), b...)
}
