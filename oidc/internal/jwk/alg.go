package jwk

import "crypto"

// Alg is one row of the accepted-algorithm table; the zero Alg names no row.
type Alg uint8

// The rows, one per JWS alg value (RFC 7518 §3.1), except EdDSA, which the
// fully specified name Ed25519 also names (RFC 9864 §2.2).
const (
	RS256 Alg = iota + 1
	RS384
	RS512
	PS256
	PS384
	PS512
	ES256
	ES384
	ES512
	EdDSA
)

// Scheme is the signature scheme a row verifies with.
type Scheme uint8

// The schemes of RFC 7518 §3.3, §3.5, §3.4 and RFC 8037 §3.1.
const (
	PKCS1v15 Scheme = iota + 1
	PSS
	ECDSA
	Ed25519
)

type row struct {
	name   string
	hash   crypto.Hash
	family family
	scheme Scheme
}

var rows = [...]row{
	RS256: {"RS256", crypto.SHA256, familyRSA, PKCS1v15},
	RS384: {"RS384", crypto.SHA384, familyRSA, PKCS1v15},
	RS512: {"RS512", crypto.SHA512, familyRSA, PKCS1v15},
	PS256: {"PS256", crypto.SHA256, familyRSA, PSS},
	PS384: {"PS384", crypto.SHA384, familyRSA, PSS},
	PS512: {"PS512", crypto.SHA512, familyRSA, PSS},
	ES256: {"ES256", crypto.SHA256, familyP256, ECDSA},
	ES384: {"ES384", crypto.SHA384, familyP384, ECDSA},
	ES512: {"ES512", crypto.SHA512, familyP521, ECDSA},
	EdDSA: {"EdDSA", 0, familyEd25519, Ed25519},
}

// ParseAlg returns the row a JWS alg header value names, case-sensitively.
func ParseAlg(name string) (Alg, bool) {
	if name == "Ed25519" {
		return EdDSA, true
	}
	for a := RS256; a <= EdDSA; a++ {
		if rows[a].name == name {
			return a, true
		}
	}
	return 0, false
}

func (a Alg) row() row { return rows[a] }

// String is the row's registered name; EdDSA's is "EdDSA".
func (a Alg) String() string { return a.row().name }

// Hash is the row's digest; zero for EdDSA, which hashes internally.
func (a Alg) Hash() crypto.Hash { return a.row().hash }

// Scheme is the row's signature scheme.
func (a Alg) Scheme() Scheme { return a.row().scheme }

// SignatureSize is the exact signature length an ES row splits into R ‖ S
// (RFC 7518 §3.4); zero for the rows whose verify call checks the size itself.
func (a Alg) SignatureSize() int {
	r := a.row()
	if r.scheme != ECDSA {
		return 0
	}
	return 2 * r.family.coordSize()
}
