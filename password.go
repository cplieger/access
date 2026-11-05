// Package access implements authentication primitives: password hashing
// (Argon2id in PHC string format), WebAuthn/FIDO2 passkey ceremonies, OIDC
// provider integration with PKCE, session management with idle/absolute
// timeouts, API key generation and verification, and role-based access
// control helpers.
package access

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters per OWASP recommendations.
const (
	argonMemory      = 19456 // 19 MiB
	argonIterations  = 2
	argonParallelism = 1
	argonSaltLen     = 16
	argonKeyLen      = 32
)

// phcParams is a parsed PHC Argon2id string; params.SaltLength and
// params.KeyLength are the lengths of salt and key.
type phcParams struct {
	salt, key []byte
	params    Argon2Params
}

// format returns the canonical PHC text of p.
func (p phcParams) format() string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.params.Memory, p.params.Iterations, p.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(p.salt), base64.RawStdEncoding.EncodeToString(p.key))
}

var errPHCInvalid = errors.New("access: invalid PHC hash")

// phcMaxLen is the longest canonical PHC text inside the bounds. parsePHC
// refuses longer text before decoding, so a stored hash cannot make it
// allocate in proportion to its length.
var phcMaxLen = len(phcParams{
	salt:   make([]byte, argonMaxLength),
	key:    make([]byte, argonMaxLength),
	params: Argon2Params{Memory: argonMaxMemory, Iterations: argonMaxIterations, Parallelism: argonMaxThreads},
}.format())

// parsePHC accepts only the canonical PHC Argon2id text of parameters inside
// [Argon2Params.Validate]'s bounds: the text must equal its own re-formatting,
// so a stored hash has exactly one spelling.
func parsePHC(encoded string) (phcParams, error) {
	if len(encoded) > phcMaxLen {
		return phcParams{}, errPHCInvalid
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return phcParams{}, errPHCInvalid
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return phcParams{}, errPHCInvalid
	}
	var p phcParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.params.Memory, &p.params.Iterations, &p.params.Parallelism); err != nil {
		return phcParams{}, errPHCInvalid
	}
	var errSalt, errKey error
	p.salt, errSalt = base64.RawStdEncoding.Strict().DecodeString(parts[4])
	p.key, errKey = base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if errSalt != nil || errKey != nil || len(p.salt) > argonMaxLength || len(p.key) > argonMaxLength {
		return phcParams{}, errPHCInvalid
	}
	p.params.SaltLength = uint32(len(p.salt)) //nolint:gosec // G115: at most argonMaxLength, checked above
	p.params.KeyLength = uint32(len(p.key))   //nolint:gosec // G115: at most argonMaxLength, checked above
	if err := p.params.Validate(); err != nil {
		return phcParams{}, fmt.Errorf("%w: %w", errPHCInvalid, err)
	}
	if p.format() != encoded {
		return phcParams{}, errPHCInvalid
	}
	return p, nil
}
