package access

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Sealer errors.
var (
	// ErrSealInvalid covers every value Open cannot authenticate: malformed,
	// too long, sealed for another purpose, or under no key of the ring.
	ErrSealInvalid = errors.New("access: sealed value invalid")
	// ErrSealExpired is an authentic value opened at or after its expiry.
	ErrSealExpired = errors.New("access: sealed value expired")
	// ErrSealTooLarge is Seal's refusal of a payload over MaxSealPayload.
	ErrSealTooLarge = errors.New("access: payload too large to seal")
)

// SealerKeySize is the length of every Sealer key: AES-256.
const SealerKeySize = 32

// MaxSealPayload is the longest payload Seal accepts: the largest whose
// sealed, encoded form is no longer than the 4096 bytes Open accepts.
// 4096 base64url characters decode to 3072 bytes, less the 12-byte nonce,
// the 12-byte expiry frame and the 16-byte tag.
const MaxSealPayload = 3032

const (
	maxSealerKeys = 4
	// maxSealedLen is the longest value Open decodes: a user agent drops a
	// cookie whose name and value pass 4096 octets (RFC 6265bis §5.6), so
	// no browser returns a longer one.
	maxSealedLen = 4096
	// sealFrameLen is the expiry frame ahead of the payload: Unix seconds
	// (8 bytes) and nanoseconds (4 bytes), big-endian.
	sealFrameLen = 12
	gcmNonceLen  = 12
	// sealOverhead is the GCM nonce and tag around the frame.
	sealOverhead = gcmNonceLen + 16
)

var sealEncoding = base64.RawURLEncoding.Strict()

// Sealer seals short payloads with AES-256-GCM under a key ring. The first
// key seals; every key opens, so a ring can rotate (current, then previous).
// Build one with NewSealer or NewEphemeralSealer; the zero value opens
// nothing, and its Seal panics on any payload within MaxSealPayload.
//
// The ring is held masked, and each call builds its cipher from an opened
// key and drops it, so no field holds a key or its expanded schedule and
// no printer, reflection-based ones included, can show one.
type Sealer struct {
	ring []*masked
}

// NewSealer returns a Sealer whose first key seals and whose every key
// opens. It takes 1 to 4 keys of SealerKeySize bytes each and copies them;
// an error names the count or the bad key's index, never its bytes.
func NewSealer(keys ...[]byte) (*Sealer, error) {
	if len(keys) == 0 || len(keys) > maxSealerKeys {
		return nil, fmt.Errorf("access: NewSealer: %d keys, want 1 to %d", len(keys), maxSealerKeys)
	}
	ring := make([]*masked, len(keys))
	for i, k := range keys {
		if len(k) != SealerKeySize {
			return nil, fmt.Errorf("access: NewSealer: key %d is %d bytes, want %d", i, len(k), SealerKeySize)
		}
		ring[i] = mask(string(k))
	}
	return &Sealer{ring: ring}, nil
}

// NewEphemeralSealer returns a Sealer under one random key that no one
// else holds, so what it seals cannot be opened after a restart.
func NewEphemeralSealer() *Sealer {
	return &Sealer{ring: []*masked{mask(string(GenerateSealerKey()))}}
}

// GenerateSealerKey returns SealerKeySize random bytes, which the caller
// persists and passes to NewSealer.
func GenerateSealerKey() []byte {
	k := make([]byte, SealerKeySize)
	rand.Read(k) // never returns an error (Go 1.24+); it crashes instead
	return k
}

// aead builds the AES-256-GCM cipher of ring key i.
func (s *Sealer) aead(i int) cipher.AEAD {
	block, _ := aes.NewCipher([]byte(s.ring[i].open())) // a SealerKeySize key cannot fail
	return newAEAD(block)
}

// newAEAD returns GCM over an AES block with a random 12-byte nonce that
// Seal prepends and Open splits off, so both arms read and write one wire
// form. NewGCMWithRandomNonce needs the *aes.Block no
// GOEXPERIMENT=boringcrypto build makes, and NewGCM is refused under
// GODEBUG=fips140=only, so neither alone serves every mode:
// https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce
func newAEAD(block cipher.Block) cipher.AEAD {
	if aead, err := cipher.NewGCMWithRandomNonce(block); err == nil {
		return aead
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		// NewGCM refuses a 16-byte block only in FIPS 140-only mode, where
		// crypto/aes makes the *aes.Block the first arm takes, so only a
		// block crypto/aes did not make reaches here, and the Sealer passes
		// none; panic with the reason rather than leave a nil AEAD to fail
		// on first use.
		panic("access: Sealer: " + err.Error())
	}
	return prefixedNonce{gcm: gcm}
}

// prefixedNonce gives an AEAD built by cipher.NewGCM the behaviour of one
// built by cipher.NewGCMWithRandomNonce: it takes no nonce argument, Seal
// draws one and prepends it, and Open splits it off. Unlike that AEAD, dst
// must not overlap the input; the Sealer always passes nil.
type prefixedNonce struct{ gcm cipher.AEAD }

func (prefixedNonce) NonceSize() int { return 0 }

func (p prefixedNonce) Overhead() int { return gcmNonceLen + p.gcm.Overhead() }

func (p prefixedNonce) Seal(dst, _, plaintext, additionalData []byte) []byte {
	nonce := make([]byte, gcmNonceLen)
	rand.Read(nonce) // never returns an error (Go 1.24+); it crashes instead
	return p.gcm.Seal(append(dst, nonce...), nonce, plaintext, additionalData)
}

func (p prefixedNonce) Open(dst, _, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < gcmNonceLen {
		return nil, ErrSealInvalid
	}
	return p.gcm.Open(dst, ciphertext[:gcmNonceLen], ciphertext[gcmNonceLen:], additionalData)
}

// Seal returns base64url(nonce || ciphertext) of payload under the first
// key, with expires sealed inside and purpose bound as additional data, so
// a payload sealed for one cookie cannot open as another. A payload longer
// than MaxSealPayload is refused with ErrSealTooLarge, so Open never
// refuses what Seal accepted. Every value carries a random 96-bit nonce,
// whichever GCM constructor the build accepts, so a first key seals at
// most 2^32 values: before then, put a new key first and keep the old one
// after it.
func (s *Sealer) Seal(purpose string, payload []byte, expires time.Time) (string, error) {
	if len(payload) > MaxSealPayload {
		return "", ErrSealTooLarge
	}
	return sealWith(s.aead(0), purpose, payload, expires), nil
}

// sealWith is Seal under aead, with no bound on the payload's length.
func sealWith(aead cipher.AEAD, purpose string, payload []byte, expires time.Time) string {
	plain := make([]byte, sealFrameLen, sealFrameLen+len(payload))
	binary.BigEndian.PutUint64(plain, uint64(expires.Unix()))           //nolint:gosec // G115: the bits round-trip through int64 in Open
	binary.BigEndian.PutUint32(plain[8:], uint32(expires.Nanosecond())) //nolint:gosec // G115: Nanosecond is in [0, 1e9)
	plain = append(plain, payload...)
	sealed := aead.Seal(nil, nil, plain, []byte(purpose)) //nolint:gosec // G407: a nil nonce is the API; newAEAD's AEAD draws one per call
	return sealEncoding.EncodeToString(sealed)
}

// Open returns the payload of a value Seal made for purpose, trying each
// key in ring order. It returns ErrSealInvalid for anything it cannot
// authenticate, a value over 4096 bytes refused before decoding, and
// ErrSealExpired for an authentic value when now is not before its expiry.
func (s *Sealer) Open(purpose, sealed string, now time.Time) ([]byte, error) {
	if len(sealed) > maxSealedLen {
		return nil, ErrSealInvalid
	}
	raw, err := sealEncoding.DecodeString(sealed)
	// The decoder skips '\r' and '\n'; the length check refuses them, so
	// exactly one string opens to a given value.
	if err != nil || sealEncoding.EncodedLen(len(raw)) != len(sealed) || len(raw) < sealOverhead+sealFrameLen {
		return nil, ErrSealInvalid
	}
	for i := range s.ring {
		plain, err := s.aead(i).Open(nil, nil, raw, []byte(purpose))
		if err != nil {
			continue
		}
		sec := int64(binary.BigEndian.Uint64(plain)) //nolint:gosec // G115: Seal wrote an int64's bits
		expires := time.Unix(sec, int64(binary.BigEndian.Uint32(plain[8:])))
		if !now.Before(expires) {
			return nil, ErrSealExpired
		}
		return plain[sealFrameLen:], nil
	}
	return nil, ErrSealInvalid
}
