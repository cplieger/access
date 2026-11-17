package webauthn

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/cplieger/access/webauthn/internal/cbor"
	"github.com/cplieger/access/webauthn/internal/cose"
)

// The attestation's refusals (WebAuthn §6.5.4, §8.2, §8.7).
var (
	errAttestationObject    = errors.New("access/webauthn: the attestation object is not well-formed")
	errAttestationFormat    = errors.New("access/webauthn: an attestation format other than none and self attestation")
	errAttestationStatement = errors.New("access/webauthn: the attestation statement is malformed")
	errAttestationSignature = errors.New("access/webauthn: the self attestation signature does not verify")
)

// The formats access accepts: none (WebAuthn §8.7), and packed (§8.2) without
// x5c, which is self attestation.
const (
	formatNone   = "none"
	formatPacked = "packed"
)

type attestationObject struct {
	format    string
	authData  []byte
	statement cbor.Value
}

// parseAttestationObject reads an attestation object (WebAuthn §6.5.4): one
// CBOR map of exactly fmt (text), attStmt (map) and authData (bytes), with
// nothing after it.
func parseAttestationObject(raw []byte) (*attestationObject, error) {
	v, rest, err := cbor.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errAttestationObject, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after it", errAttestationObject, len(rest))
	}
	entries, isMap := v.Map()
	if !isMap {
		return nil, fmt.Errorf("%w: not a CBOR map", errAttestationObject)
	}
	o := &attestationObject{}
	members := 0
	for key, val := range entries {
		name, _ := key.Text()
		var ok bool
		switch name {
		case "fmt":
			o.format, ok = val.Text()
		case "attStmt":
			_, ok = val.Map()
			o.statement = val
		case "authData":
			o.authData, ok = val.Bytes()
		default:
			return nil, fmt.Errorf("%w: a member other than fmt, attStmt and authData", errAttestationObject)
		}
		if !ok {
			return nil, fmt.Errorf("%w: %s of the wrong type", errAttestationObject, name)
		}
		members++
	}
	// The decoder refuses a duplicate key, so three members are the three.
	if members != 3 {
		return nil, fmt.Errorf("%w: a member missing", errAttestationObject)
	}
	return o, nil
}

// verifyStatement accepts a none statement, or a packed self attestation
// whose sig verifies under key over authData ‖ clientDataHash. Any other
// format, and packed with x5c, is errAttestationFormat: under the default
// conveyance the client sends only these two (WebAuthn §5.4.7), and the
// others need the trust model access excludes.
func (o *attestationObject) verifyStatement(key *cose.Key, clientDataHash [sha256.Size]byte) error {
	switch o.format {
	case formatNone:
		if len(o.members()) != 0 {
			return fmt.Errorf("%w: a none statement with members", errAttestationStatement)
		}
		return nil
	case formatPacked:
		return o.verifySelf(key, clientDataHash)
	default:
		return fmt.Errorf("%w: %.32q", errAttestationFormat, o.format)
	}
}

// verifySelf runs WebAuthn §8.2's self attestation branch.
func (o *attestationObject) verifySelf(key *cose.Key, clientDataHash [sha256.Size]byte) error {
	members := o.members()
	if _, full := members["x5c"]; full {
		return fmt.Errorf("%w: packed with x5c", errAttestationFormat)
	}
	alg, isInt := members["alg"].Int()
	sig, isBytes := members["sig"].Bytes()
	if len(members) != 2 || !isInt || !isBytes {
		return fmt.Errorf("%w: packed self attestation is not exactly an integer alg and a byte string sig", errAttestationStatement)
	}
	if alg != int64(key.Algorithm()) {
		return fmt.Errorf("%w: alg %d for a credential key of alg %d", errAttestationStatement, alg, key.Algorithm())
	}
	if err := key.Verify(o.authData, clientDataHash, sig); err != nil {
		return fmt.Errorf("%w: %w", errAttestationSignature, err)
	}
	return nil
}

// members returns attStmt's members by name. An integer key reads as the
// empty name, which no format defines, so it counts as an extra member.
func (o *attestationObject) members() map[string]cbor.Value {
	entries, _ := o.statement.Map()
	out := map[string]cbor.Value{}
	for key, val := range entries {
		name, _ := key.Text()
		out[name] = val
	}
	return out
}
