package access

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"sync"
)

// maskTagSize is the length of the HMAC-SHA256 tag that leads every masked
// value; its first aes.BlockSize bytes are the CTR IV.
const maskTagSize = sha256.Size

// maskKeys holds the process's two masking keys: one tags each text, the
// other encrypts it. They live only here, so no masked value reaches them.
type maskKeys struct {
	block  cipher.Block
	tagKey []byte
}

var processMaskKeys = sync.OnceValue(func() *maskKeys {
	tagKey := make([]byte, 32)
	encKey := make([]byte, 32)
	rand.Read(tagKey) // never returns an error (Go 1.24+); it crashes instead
	rand.Read(encKey) // never returns an error (Go 1.24+); it crashes instead
	// aes.NewCipher errors only on a key length other than 16, 24 or 32.
	block, _ := aes.NewCipher(encKey)
	return &maskKeys{block: block, tagKey: tagKey}
})

// masked is tag || AES-256-CTR(text), where tag is the HMAC-SHA256 of text
// and its first 16 bytes are the IV. Equal texts mask to equal bytes within
// the process, which is what makes reflect.DeepEqual and maskedEqual agree
// with text equality; the IV depends on the text, so knowing one value's
// text reveals no keystream of another's.
type masked struct {
	b []byte
}

// mask returns the masked form of text, or nil for "".
func mask(text string) *masked {
	if text == "" {
		return nil
	}
	k := processMaskKeys()
	mac := hmac.New(sha256.New, k.tagKey)
	mac.Write([]byte(text))
	b := make([]byte, maskTagSize+len(text))
	copy(b, mac.Sum(nil))
	cipher.NewCTR(k.block, b[:aes.BlockSize]).XORKeyStream(b[maskTagSize:], []byte(text))
	return &masked{b: b}
}

// open returns the text m masks, or "" for nil.
func (m *masked) open() string {
	if m == nil {
		return ""
	}
	out := make([]byte, len(m.b)-maskTagSize)
	cipher.NewCTR(processMaskKeys().block, m.b[:aes.BlockSize]).XORKeyStream(out, m.b[maskTagSize:])
	return string(out)
}

// tag returns m's tag, or 32 zero bytes for nil.
func (m *masked) tag() [maskTagSize]byte {
	var t [maskTagSize]byte
	if m != nil {
		copy(t[:], m.b[:maskTagSize])
	}
	return t
}

// maskedEqual reports whether a and b mask the same text. It compares the
// two fixed-size tags only, so every pair takes the same work whatever the
// texts' lengths; subtle.ConstantTimeCompare returns at once on unequal
// lengths. Two nils are equal; a nil equals a non-nil value only if an HMAC
// output is 32 zero bytes.
func maskedEqual(a, b *masked) bool {
	at, bt := a.tag(), b.tag()
	return subtle.ConstantTimeCompare(at[:], bt[:]) == 1
}
