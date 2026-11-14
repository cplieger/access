package jws

import "github.com/cplieger/access/oidc/internal/jwk"

// RawToken is a Token under row alg over any signing input, for vector
// suites whose messages are bytes rather than a compact JWS's signing input.
func RawToken(alg jwk.Alg, signingInput, signature []byte) *Token {
	return &Token{alg: alg, signingInput: string(signingInput), signature: signature}
}
