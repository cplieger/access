package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	_ "crypto/sha256" // crypto.Hash.New panics for a hash not linked in
	_ "crypto/sha512"
	"io"
	"math/big"

	"github.com/cplieger/access/oidc/internal/jwk"
)

// Verify tries every key of keys that fits the token's alg and, when the
// header names a kid, carries that exact kid (RFC 7515 §4.1.4); it returns
// the payload under the first that verifies the signature, or ErrNoKey.
func (t *Token) Verify(keys jwk.Set) ([]byte, error) {
	for k := range keys.All() {
		if !k.Fits(t.alg) {
			continue
		}
		if kid, has := k.KeyID(); t.hasKID && (!has || kid != t.kid) {
			continue
		}
		if verify(t.alg, k.Public(), t.signingInput, t.signature) {
			return t.payload, nil
		}
	}
	return nil, ErrNoKey
}

// verify checks sig over input under row a (RFC 7518 §3.3 to §3.5, RFC
// 8037 §3.1). The RSA and Ed25519 calls refuse a signature of the wrong
// length themselves (RFC 8017 §8.1.2 and §8.2.2 step 1, RFC 8032 §5.1.7).
func verify(a jwk.Alg, pub crypto.PublicKey, input string, sig []byte) bool {
	switch a.Scheme() {
	case jwk.PKCS1v15:
		k, ok := pub.(*rsa.PublicKey)
		return ok && rsa.VerifyPKCS1v15(k, a.Hash(), digest(a.Hash(), input), sig) == nil
	case jwk.PSS:
		// Never nil options, which accept any salt length (RFC 7518 §3.5).
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		k, ok := pub.(*rsa.PublicKey)
		return ok && rsa.VerifyPSS(k, a.Hash(), digest(a.Hash(), input), sig, opts) == nil
	case jwk.ECDSA:
		// R ‖ S at the row's fixed size, never DER (RFC 7518 §3.4);
		// ecdsa.Verify refuses R or S outside [1, N−1] (CVE-2022-21449).
		k, ok := pub.(*ecdsa.PublicKey)
		size := a.SignatureSize()
		if !ok || len(sig) != size {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:size/2]), new(big.Int).SetBytes(sig[size/2:])
		return ecdsa.Verify(k, digest(a.Hash(), input), r, s)
	case jwk.Ed25519:
		k, ok := pub.(ed25519.PublicKey)
		return ok && ed25519.Verify(k, []byte(input), sig)
	}
	return false
}

func digest(h crypto.Hash, input string) []byte {
	d := h.New()
	_, _ = io.WriteString(d, input)
	return d.Sum(nil)
}
