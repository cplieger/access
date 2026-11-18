package access

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"testing"
	"time"
)

// fixedNonce is AES-GCM under one key with a set nonce prepended: the fuzz
// engine runs a target's setup again in each worker process, so a seed
// sealed under a fresh nonce would differ from the value that worker
// compares it with.
type fixedNonce struct {
	gcm   cipher.AEAD
	nonce []byte
}

func newFixedNonce(tb testing.TB, key string, nonce byte) fixedNonce {
	tb.Helper()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		tb.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		tb.Fatal(err)
	}
	return fixedNonce{gcm: gcm, nonce: bytes.Repeat([]byte{nonce}, gcmNonceLen)}
}

func (fixedNonce) NonceSize() int { return 0 }

func (f fixedNonce) Overhead() int { return gcmNonceLen + f.gcm.Overhead() }

func (f fixedNonce) Seal(dst, _, plaintext, additionalData []byte) []byte {
	return f.gcm.Seal(append(dst, f.nonce...), f.nonce, plaintext, additionalData)
}

func (f fixedNonce) Open(dst, _, ciphertext, additionalData []byte) ([]byte, error) {
	return prefixedNonce{gcm: f.gcm}.Open(dst, nil, ciphertext, additionalData)
}

// FuzzSealerOpen checks that Open never panics, opens exactly the values
// Seal made for the purpose asked, and refuses every one-bit flip of one.
func FuzzSealerOpen(f *testing.F) {
	s, err := NewSealer([]byte(ringA), []byte(ringB))
	if err != nil {
		f.Fatalf("NewSealer() error = %v", err)
	}
	now := sealNow
	payload := []byte("fuzz-payload")
	sealed := map[string]string{
		"oidc-flow":    sealWith(newFixedNonce(f, ringA, 1), "oidc-flow", payload, now.Add(time.Hour)),
		"oidc-pending": sealWith(newFixedNonce(f, ringB, 2), "oidc-pending", payload, now.Add(time.Hour)),
	}
	good := sealed["oidc-flow"]
	f.Add(good, uint(0))
	f.Add(good, uint(7))
	f.Add(good, uint(len(good)*8-1))
	f.Add(good, uint(len(good)*4))
	f.Add(sealed["oidc-pending"], uint(1))
	f.Add(good[:len(good)-1]+"A", uint(2))
	f.Add(good+"\n", uint(3))
	f.Add("", uint(0))
	f.Add("AAAA", uint(0))
	f.Add(strings.Repeat("A", maxSealedLen+1), uint(5))

	f.Fuzz(func(t *testing.T, in string, bit uint) {
		for purpose, want := range sealed {
			got, err := s.Open(purpose, in, now)
			if in == want {
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("Open(%q) of its own value = %q, %v", purpose, got, err)
				}
				continue
			}
			if err == nil {
				t.Fatalf("Open(%q) accepted a value Seal did not make for it: %q", purpose, in)
			}
		}
		flipped := []byte(good)
		i := bit % uint(len(flipped)*8)
		flipped[i/8] ^= 1 << (i % 8)
		if got, err := s.Open("oidc-flow", string(flipped), now); err == nil {
			t.Fatalf("Open accepted %q with bit %d flipped: %q", flipped, i, got)
		}
	})
}

// FuzzSealerOpenAtRest checks that OpenAtRest never panics, opens exactly
// the values SealAtRest made for the purpose asked, never a Seal value,
// and refuses every one-bit flip of one.
func FuzzSealerOpenAtRest(f *testing.F) {
	s, err := NewSealer([]byte(ringA), []byte(ringB))
	if err != nil {
		f.Fatalf("NewSealer() error = %v", err)
	}
	payload := []byte("fuzz-payload")
	atRest := func(purpose string, nonce byte) string {
		return sealEncoding.EncodeToString(newFixedNonce(f, ringA, nonce).Seal(nil, nil, payload, []byte("access/at-rest\x00"+purpose)))
	}
	sealed := map[string]string{"totp:1": atRest("totp:1", 1), "totp:2": atRest("totp:2", 2)}
	good := sealed["totp:1"]
	f.Add(good, uint(0))
	f.Add(good, uint(len(good)*8-1))
	f.Add(sealed["totp:2"], uint(1))
	f.Add(sealWith(newFixedNonce(f, ringA, 3), "totp:1", payload, sealNow.Add(time.Hour)), uint(2))
	f.Add(good+"\n", uint(3))
	f.Add("", uint(0))
	f.Add(strings.Repeat("A", maxSealedLen+1), uint(5))

	f.Fuzz(func(t *testing.T, in string, bit uint) {
		for purpose, want := range sealed {
			got, current, err := s.OpenAtRest(purpose, in)
			if in == want {
				if err != nil || !current || !bytes.Equal(got, payload) {
					t.Fatalf("OpenAtRest(%q) of its own value = %q, %t, %v", purpose, got, current, err)
				}
				continue
			}
			if err == nil {
				t.Fatalf("OpenAtRest(%q) accepted a value SealAtRest did not make for it: %q", purpose, in)
			}
		}
		flipped := []byte(good)
		i := bit % uint(len(flipped)*8)
		flipped[i/8] ^= 1 << (i % 8)
		if got, _, err := s.OpenAtRest("totp:1", string(flipped)); err == nil {
			t.Fatalf("OpenAtRest accepted %q with bit %d flipped: %q", flipped, i, got)
		}
	})
}
