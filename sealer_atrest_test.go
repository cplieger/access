package access

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustSealAtRest(t *testing.T, s *Sealer, purpose string, payload []byte) string {
	t.Helper()
	v, err := s.SealAtRest(purpose, payload)
	if err != nil {
		t.Fatalf("SealAtRest(%q, %d bytes) error = %v", purpose, len(payload), err)
	}
	return v
}

func checkOpensAtRest(t *testing.T, s *Sealer, purpose, sealed string, payload []byte, current bool) {
	t.Helper()
	got, cur, err := s.OpenAtRest(purpose, sealed)
	if err != nil || !bytes.Equal(got, payload) || cur != current {
		t.Errorf("OpenAtRest(%q) = %q, %t, %v, want %q, %t, nil", purpose, got, cur, err, payload, current)
	}
}

func checkRefusedAtRest(t *testing.T, s *Sealer, purpose, sealed string) {
	t.Helper()
	got, cur, err := s.OpenAtRest(purpose, sealed)
	if !errors.Is(err, ErrSealInvalid) || got != nil || cur {
		t.Errorf("OpenAtRest(%q) = %q, %t, %v, want nil, false, ErrSealInvalid", purpose, got, cur, err)
	}
}

// rawGCM is AES-256-GCM under key with no Sealer code in the path: the
// oracle for the at-rest frame, base64url(nonce || ciphertext)
// with the additional data "access/at-rest\x00" + purpose and no expiry.
func rawGCM(t *testing.T, key string) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcm
}

// TestSealAtRestFrame checks the at-rest frame by sealing and opening
// with crypto/cipher directly.
func TestSealAtRestFrame(t *testing.T) {
	t.Parallel()
	s := sealerOf(t, ringA)
	gcm := rawGCM(t, ringA)
	ad := []byte("access/at-rest\x00totp:1")
	payload := []byte("twenty-byte-secret!!")
	t.Run("sealed_value_opens_by_spec", func(t *testing.T) {
		t.Parallel()
		raw, err := sealEncoding.DecodeString(mustSealAtRest(t, s, "totp:1", payload))
		if err != nil || len(raw) != 12+len(payload)+16 {
			t.Fatalf("sealed value is %d bytes, %v, want nonce, payload and tag: %d", len(raw), err, 12+len(payload)+16)
		}
		plain, err := gcm.Open(nil, raw[:12], raw[12:], ad)
		if err != nil || !bytes.Equal(plain, payload) {
			t.Errorf("AES-GCM open with the at-rest additional data = %q, %v, want the payload with no expiry frame", plain, err)
		}
	})
	t.Run("spec_value_opens", func(t *testing.T) {
		t.Parallel()
		nonce := bytes.Repeat([]byte{7}, 12)
		v := sealEncoding.EncodeToString(gcm.Seal(append([]byte{}, nonce...), nonce, payload, ad))
		checkOpensAtRest(t, s, "totp:1", v, payload, true)
	})
	t.Run("fresh_nonce", func(t *testing.T) {
		t.Parallel()
		first, second := mustSealAtRest(t, s, "totp:1", payload), mustSealAtRest(t, s, "totp:1", payload)
		if first == second {
			t.Error("two at-rest seals of one payload are equal, want a fresh nonce each")
		}
	})
}

// TestSealAtRestSeparation checks the rule that a cookie seal never
// opens at rest and an at-rest seal never opens as a cookie, for the same
// purpose string, both ways, and that no purpose string bridges the two.
func TestSealAtRestSeparation(t *testing.T) {
	t.Parallel()
	s := sealerOf(t, ringA)
	payload := []byte("separation-payload")
	far := sealNow.Add(100 * 365 * 24 * time.Hour)
	atRest := mustSealAtRest(t, s, "totp:1", payload)
	cookie := mustSeal(t, s, "totp:1", payload, far)
	t.Run("at_rest_never_opens_as_cookie", func(t *testing.T) {
		t.Parallel()
		checkRefused(t, s, "totp:1", atRest, sealNow, ErrSealInvalid)
	})
	t.Run("cookie_never_opens_at_rest", func(t *testing.T) {
		t.Parallel()
		checkRefusedAtRest(t, s, "totp:1", cookie)
	})
	for _, purpose := range []string{"access/at-rest\x00totp:1", "\x00", "a\x00b"} {
		t.Run("nul_purpose_panics_"+strings.ReplaceAll(purpose, "\x00", "NUL"), func(t *testing.T) {
			t.Parallel()
			for name, call := range map[string]func(){
				"Seal": func() { _, _ = s.Seal(purpose, payload, far) },
				"Open": func() { _, _ = s.Open(purpose, atRest, sealNow) },
			} {
				func() {
					defer func() {
						if recover() == nil {
							t.Errorf("%s(%q) returned, want a panic", name, purpose)
						}
					}()
					call()
				}()
			}
		})
	}
}

// TestOpenAtRestRing: current is true only when the ring's
// first key opened the value.
func TestOpenAtRestRing(t *testing.T) {
	t.Parallel()
	payload := []byte("ring-payload")
	sealed := mustSealAtRest(t, sealerOf(t, ringA), "totp:7", payload)
	t.Run("first_key", func(t *testing.T) {
		t.Parallel()
		checkOpensAtRest(t, sealerOf(t, ringA, ringB), "totp:7", sealed, payload, true)
	})
	t.Run("second_key", func(t *testing.T) {
		t.Parallel()
		checkOpensAtRest(t, sealerOf(t, ringB, ringA), "totp:7", sealed, payload, false)
	})
	t.Run("key_gone", func(t *testing.T) {
		t.Parallel()
		checkRefusedAtRest(t, sealerOf(t, ringB), "totp:7", sealed)
	})
	t.Run("zero_sealer", func(t *testing.T) {
		t.Parallel()
		checkRefusedAtRest(t, &Sealer{}, "totp:7", sealed)
	})
	t.Run("reseal_is_current", func(t *testing.T) {
		t.Parallel()
		rotated := sealerOf(t, ringB, ringA)
		checkOpensAtRest(t, rotated, "totp:7", mustSealAtRest(t, rotated, "totp:7", payload), payload, true)
	})
}

// TestOpenAtRestPurpose: under the "totp:" + userID purpose a record
// copied onto another user's row does not open.
func TestOpenAtRestPurpose(t *testing.T) {
	t.Parallel()
	s := sealerOf(t, ringA)
	sealed := mustSealAtRest(t, s, "totp:1", []byte("purpose-payload"))
	for _, other := range []string{"totp:2", "totp:10", "totp:", "totp:1 ", "", "TOTP:1"} {
		t.Run(other, func(t *testing.T) {
			t.Parallel()
			checkRefusedAtRest(t, s, other, sealed)
		})
	}
}

// TestOpenAtRestTampered is AES-GCM authenticated decryption (NIST SP
// 800-38D §7.2: a tag that does not verify answers FAIL): any changed bit,
// a truncation or an extension is refused.
func TestOpenAtRestTampered(t *testing.T) {
	t.Parallel()
	s := sealerOf(t, ringA)
	sealed := mustSealAtRest(t, s, "totp:1", []byte("tamper-payload"))
	raw, err := sealEncoding.DecodeString(sealed)
	if err != nil || len(raw) != 12+len("tamper-payload")+16 {
		t.Fatalf("SealAtRest gave %d bytes, %v, want nonce, payload and tag", len(raw), err)
	}
	t.Run("each_bit_flipped", func(t *testing.T) {
		t.Parallel()
		for i := range len(raw) * 8 {
			b := bytes.Clone(raw)
			b[i/8] ^= 1 << (i % 8)
			if got, _, err := s.OpenAtRest("totp:1", sealEncoding.EncodeToString(b)); err == nil {
				t.Fatalf("bit %d flipped opened to %q", i, got)
			}
		}
	})
	cases := map[string]string{
		"truncated_byte":  sealEncoding.EncodeToString(raw[:len(raw)-1]),
		"extended_byte":   sealEncoding.EncodeToString(append(bytes.Clone(raw), 0)),
		"truncated_char":  sealed[:len(sealed)-1],
		"nonce_and_tag":   sealEncoding.EncodeToString(raw[:12+16-1]),
		"empty":           "",
		"padded":          sealed + "==",
		"newline_inside":  sealed[:10] + "\n" + sealed[10:],
		"standard_base64": strings.NewReplacer("-", "+", "_", "/").Replace(sealed) + "+",
		"over_4096":       strings.Repeat("A", maxSealedLen+1),
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			checkRefusedAtRest(t, s, "totp:1", v)
		})
	}
}

func TestSealAtRestBound(t *testing.T) {
	t.Parallel()
	s := sealerOf(t, ringA)
	longest := bytes.Repeat([]byte{'b'}, MaxSealPayload)
	t.Run("longest_payload", func(t *testing.T) {
		t.Parallel()
		checkOpensAtRest(t, s, "bound", mustSealAtRest(t, s, "bound", longest), longest, true)
	})
	t.Run("one_byte_over_refused", func(t *testing.T) {
		t.Parallel()
		v, err := s.SealAtRest("bound", append(bytes.Clone(longest), 'b'))
		if v != "" || !errors.Is(err, ErrSealTooLarge) {
			t.Errorf("SealAtRest(%d bytes) = %d characters, %v, want \"\", ErrSealTooLarge", MaxSealPayload+1, len(v), err)
		}
	})
	t.Run("empty_payload", func(t *testing.T) {
		t.Parallel()
		checkOpensAtRest(t, s, "bound", mustSealAtRest(t, s, "bound", nil), nil, true)
	})
}
