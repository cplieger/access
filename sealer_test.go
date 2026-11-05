package access

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access/internal/printcheck"
)

const (
	ringA = "sealer-rng-A-0451-kn0wn-bytes-AA"
	ringB = "sealer-rng-B-0451-kn0wn-bytes-BB"
)

func sealerOf(t *testing.T, keys ...string) *Sealer {
	t.Helper()
	raw := make([][]byte, len(keys))
	for i, k := range keys {
		raw[i] = []byte(k)
	}
	s, err := NewSealer(raw...)
	if err != nil {
		t.Fatalf("NewSealer() error = %v", err)
	}
	return s
}

func mustSeal(t testing.TB, s *Sealer, purpose string, payload []byte, expires time.Time) string {
	t.Helper()
	v, err := s.Seal(purpose, payload, expires)
	if err != nil {
		t.Fatalf("Seal(%q, %d bytes) error = %v", purpose, len(payload), err)
	}
	return v
}

func checkOpens(t *testing.T, s *Sealer, purpose, sealed string, now time.Time, payload []byte) {
	t.Helper()
	got, err := s.Open(purpose, sealed, now)
	if err != nil {
		t.Fatalf("Open(%q) error = %v, want nil", purpose, err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("Open(%q) = %q, want %q", purpose, got, payload)
	}
}

func checkRefused(t *testing.T, s *Sealer, purpose, sealed string, now time.Time, want error) {
	t.Helper()
	got, err := s.Open(purpose, sealed, now)
	if !errors.Is(err, want) {
		t.Errorf("Open(%q) error = %v, want %v", purpose, err, want)
	}
	if got != nil {
		t.Errorf("Open(%q) = %q with an error, want nil", purpose, got)
	}
}

var sealNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func TestSealerRing(t *testing.T) {
	t.Parallel()
	payload := []byte("ring-payload")
	sealed := mustSeal(t, sealerOf(t, ringA), "ring", payload, sealNow.Add(time.Hour))
	t.Run("open_current_then_previous", func(t *testing.T) {
		t.Parallel()
		checkOpens(t, sealerOf(t, ringA, ringB), "ring", sealed, sealNow, payload)
	})
	t.Run("open_previous_key", func(t *testing.T) {
		t.Parallel()
		checkOpens(t, sealerOf(t, ringB, ringA), "ring", sealed, sealNow, payload)
	})
	t.Run("refused_without_the_key", func(t *testing.T) {
		t.Parallel()
		checkRefused(t, sealerOf(t, ringB), "ring", sealed, sealNow, ErrSealInvalid)
	})
	t.Run("first_key_seals", func(t *testing.T) {
		t.Parallel()
		rotated := mustSeal(t, sealerOf(t, ringB, ringA), "ring", payload, sealNow.Add(time.Hour))
		checkOpens(t, sealerOf(t, ringB), "ring", rotated, sealNow, payload)
		checkRefused(t, sealerOf(t, ringA), "ring", rotated, sealNow, ErrSealInvalid)
	})
	t.Run("four_keys", func(t *testing.T) {
		t.Parallel()
		s := sealerOf(t, ringB, ringB, ringB, ringA)
		checkOpens(t, s, "ring", sealed, sealNow, payload)
	})
	t.Run("ephemeral", func(t *testing.T) {
		t.Parallel()
		a, b := NewEphemeralSealer(), NewEphemeralSealer()
		v := mustSeal(t, a, "ring", payload, sealNow.Add(time.Hour))
		checkOpens(t, a, "ring", v, sealNow, payload)
		checkRefused(t, b, "ring", v, sealNow, ErrSealInvalid)
	})
	t.Run("nonce_per_seal", func(t *testing.T) {
		t.Parallel()
		s := sealerOf(t, ringA)
		first, second := mustSeal(t, s, "ring", payload, sealNow), mustSeal(t, s, "ring", payload, sealNow)
		if first == second {
			t.Error("two seals of one payload are equal, want a fresh nonce each")
		}
	})
}

func TestSealerPurpose(t *testing.T) {
	t.Parallel()
	s := sealerOf(t, ringA)
	payload := []byte("purpose-payload")
	sealed := mustSeal(t, s, "oidc-flow", payload, sealNow.Add(time.Hour))
	checkOpens(t, s, "oidc-flow", sealed, sealNow, payload)
	others := map[string]string{
		"other_cookie":   "oidc-pending",
		"device_cookie":  "ratelimit-device",
		"prefix":         "oidc-flo",
		"trailing_space": "oidc-flow ",
		"empty":          "",
	}
	for name, other := range others {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			checkRefused(t, s, other, sealed, sealNow, ErrSealInvalid)
		})
	}
}

func TestSealerExpiry(t *testing.T) {
	t.Parallel()
	s := sealerOf(t, ringA)
	payload := []byte("expiry-payload")
	expires := sealNow.Add(10*time.Minute + 123456789*time.Nanosecond)
	sealed := mustSeal(t, s, "expiry", payload, expires)
	t.Run("before", func(t *testing.T) {
		t.Parallel()
		checkOpens(t, s, "expiry", sealed, sealNow, payload)
		checkOpens(t, s, "expiry", sealed, expires.Add(-time.Nanosecond), payload)
	})
	t.Run("at_and_after", func(t *testing.T) {
		t.Parallel()
		checkRefused(t, s, "expiry", sealed, expires, ErrSealExpired)
		checkRefused(t, s, "expiry", sealed, expires.Add(time.Nanosecond), ErrSealExpired)
	})
	t.Run("wrong_purpose_is_invalid_not_expired", func(t *testing.T) {
		t.Parallel()
		checkRefused(t, s, "other", sealed, expires.Add(time.Hour), ErrSealInvalid)
	})
	t.Run("zero_expiry", func(t *testing.T) {
		t.Parallel()
		checkRefused(t, s, "expiry", mustSeal(t, s, "expiry", payload, time.Time{}), sealNow, ErrSealExpired)
	})
	t.Run("far_future", func(t *testing.T) {
		t.Parallel()
		far := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
		v := mustSeal(t, s, "expiry", payload, far)
		checkOpens(t, s, "expiry", v, far.Add(-time.Nanosecond), payload)
		checkRefused(t, s, "expiry", v, far, ErrSealExpired)
	})
	t.Run("zone_free", func(t *testing.T) {
		t.Parallel()
		paris := time.FixedZone("CEST", 2*60*60)
		v := mustSeal(t, s, "expiry", payload, expires.In(paris))
		checkOpens(t, s, "expiry", v, expires.Add(-time.Nanosecond), payload)
		checkRefused(t, s, "expiry", v, expires, ErrSealExpired)
	})
}

// Not parallel: over_4096_refused counts allocations, and a test running
// beside it would add its own to the count.
func TestSealerInput(t *testing.T) {
	s := sealerOf(t, ringA)
	sealed := mustSeal(t, s, "input", []byte("x"), sealNow.Add(time.Hour))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, sealed[len(sealed)-1])
	cases := map[string]string{
		"empty":           "",
		"not_base64":      "!!!!",
		"padded":          sealed + "==",
		"newline_inside":  sealed[:10] + "\n" + sealed[10:],
		"carriage_return": sealed + "\r",
		"too_short":       sealed[:sealEncoding.EncodedLen(sealOverhead+sealFrameLen-1)],
		"truncated":       sealed[:len(sealed)-1],
		// One byte of payload leaves two unused bits in the last character;
		// a lax decoder ignores them, so this string decodes to the same bytes.
		"trailing_bits": sealed[:len(sealed)-1] + string(alphabet[last^1]),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			checkRefused(t, s, "input", in, sealNow, ErrSealInvalid)
		})
	}
	t.Run("over_4096_refused", func(t *testing.T) {
		// sealWith has no bound, so this value is authentic: only the
		// length check refuses it.
		payload := bytes.Repeat([]byte{'p'}, MaxSealPayload+1)
		v := sealWith(s.aead(0), "input", payload, sealNow.Add(time.Hour))
		if len(v) <= maxSealedLen {
			t.Fatalf("sealed length = %d, want over %d", len(v), maxSealedLen)
		}
		checkRefused(t, s, "input", v, sealNow, ErrSealInvalid)
		// Decoding allocates; a refusal ahead of it does not.
		if n := testing.AllocsPerRun(100, func() { _, _ = s.Open("input", v, sealNow) }); n != 0 {
			t.Errorf("Open(%d bytes) made %v allocations, want 0 (refused before decoding)", len(v), n)
		}
	})
	t.Run("payload_is_a_copy", func(t *testing.T) {
		t.Parallel()
		got, err := s.Open("input", sealed, sealNow)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		got[0] = 'y'
		checkOpens(t, s, "input", sealed, sealNow, []byte("x"))
	})
	t.Run("zero_sealer_opens_nothing", func(t *testing.T) {
		t.Parallel()
		checkRefused(t, &Sealer{}, "input", sealed, sealNow, ErrSealInvalid)
	})
	t.Run("zero_sealer_seal_panics", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if recover() == nil {
				t.Error("zero Sealer's Seal returned, want a panic")
			}
		}()
		_, _ = (&Sealer{}).Seal("input", []byte("x"), sealNow.Add(time.Hour))
	})
}

func TestSealerWire(t *testing.T) {
	t.Parallel()
	t.Run("url_alphabet_unpadded", func(t *testing.T) {
		t.Parallel()
		// These bytes hold the base64 indices 62 and 63, where the URL and
		// standard alphabets differ, and leave a partial last group.
		if got, want := sealEncoding.EncodeToString([]byte{0xFB, 0xFF, 0xBF, 0xFF}), "-_-__w"; got != want {
			t.Errorf("encoding = %q, want %q", got, want)
		}
	})
	s := sealerOf(t, ringA)
	// A 4096-character value of random bytes lacks both '+' and '/' in the
	// standard alphabet with probability (62/64)^4096, under 1e-56.
	payload := bytes.Repeat([]byte{'w'}, MaxSealPayload)
	sealed := mustSeal(t, s, "wire", payload, sealNow.Add(time.Hour))
	raw, err := base64.RawURLEncoding.Strict().DecodeString(sealed)
	if err != nil {
		t.Fatalf("Seal() gave %d characters, not unpadded base64url: %v", len(sealed), err)
	}
	t.Run("std_alphabet_refused", func(t *testing.T) {
		t.Parallel()
		std := base64.RawStdEncoding.EncodeToString(raw)
		if std == sealed {
			t.Fatal("the sealed value reads the same in both alphabets")
		}
		checkRefused(t, s, "wire", std, sealNow, ErrSealInvalid)
		checkOpens(t, s, "wire", sealed, sealNow, payload)
	})
}

func TestSealerConstruction(t *testing.T) {
	t.Parallel()
	good := []byte(ringA)
	for _, n := range []int{0, 5, 31, 33} {
		bad := bytes.Repeat([]byte{0xA5}, n)
		t.Run("key_of_"+strconv.Itoa(n)+"_bytes", func(t *testing.T) {
			t.Parallel()
			s, err := NewSealer(good, bad)
			if s != nil {
				t.Errorf("NewSealer() = %v, want nil", s)
			}
			// An exact text holds no key byte by construction.
			want := "access: NewSealer: key 1 is " + strconv.Itoa(n) + " bytes, want 32"
			if err == nil || err.Error() != want {
				t.Errorf("NewSealer() error = %v, want %q", err, want)
			}
		})
	}
	t.Run("key_count", func(t *testing.T) {
		t.Parallel()
		for _, n := range []int{0, 5} {
			keys := make([][]byte, n)
			for i := range keys {
				keys[i] = good
			}
			_, err := NewSealer(keys...)
			want := "access: NewSealer: " + strconv.Itoa(n) + " keys, want 1 to 4"
			if err == nil || err.Error() != want {
				t.Errorf("NewSealer(%d keys) error = %v, want %q", n, err, want)
			}
		}
	})
	t.Run("keys_are_copied", func(t *testing.T) {
		t.Parallel()
		k := []byte(ringA)
		s, err := NewSealer(k)
		if err != nil {
			t.Fatalf("NewSealer() error = %v", err)
		}
		v := mustSeal(t, s, "copy", []byte("x"), sealNow.Add(time.Hour))
		k[0] ^= 0xFF
		checkOpens(t, s, "copy", v, sealNow, []byte("x"))
		checkOpens(t, sealerOf(t, ringA), "copy", v, sealNow, []byte("x"))
	})
}

func TestSealerPrinting(t *testing.T) {
	t.Parallel()
	s := sealerOf(t, ringA, ringB)
	for name, v := range map[string]any{"pointer": s, "value": *s} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for route, got := range maskedRenderings(t, v) {
				for _, k := range []string{ringA, ringB} {
					if printcheck.Leak(got, k) {
						t.Errorf("%s printed a key: %s", route, got)
					}
				}
			}
		})
	}
	t.Run("type_graph", func(t *testing.T) {
		t.Parallel()
		checkTypes(t, printcheck.Allow{}, reflect.TypeFor[*Sealer]())
	})
}

func TestGenerateSealerKey(t *testing.T) {
	t.Parallel()
	k := GenerateSealerKey()
	if len(k) != SealerKeySize {
		t.Fatalf("GenerateSealerKey() = %d bytes, want %d", len(k), SealerKeySize)
	}
	if bytes.Equal(GenerateSealerKey(), k) {
		t.Error("two generated keys are equal")
	}
	s, err := NewSealer(k)
	if err != nil {
		t.Fatalf("NewSealer(generated key) error = %v", err)
	}
	checkOpens(t, s, "generated", mustSeal(t, s, "generated", []byte("x"), sealNow.Add(time.Hour)), sealNow, []byte("x"))
}

func TestSealBound(t *testing.T) {
	t.Parallel()
	s := sealerOf(t, ringA)
	expires := sealNow.Add(time.Hour)
	longest := bytes.Repeat([]byte{'b'}, MaxSealPayload)
	for name, purpose := range map[string]string{
		"longest_payload":              "bound",
		"longest_payload_1KiB_purpose": strings.Repeat("p", 1024),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := mustSeal(t, s, purpose, longest, expires)
			if len(v) != 4096 {
				t.Errorf("sealed length = %d, want 4096", len(v))
			}
			checkOpens(t, s, purpose, v, sealNow, longest)
		})
	}
	t.Run("one_byte_over_refused", func(t *testing.T) {
		t.Parallel()
		v, err := s.Seal("bound", append(longest, 'b'), expires)
		if v != "" || !errors.Is(err, ErrSealTooLarge) {
			t.Errorf("Seal(%d bytes) = %d characters, %v, want \"\", ErrSealTooLarge", MaxSealPayload+1, len(v), err)
		}
	})
	t.Run("refused_before_any_key", func(t *testing.T) {
		t.Parallel()
		// The zero Sealer panics on its first key, so only a check ahead
		// of it can answer.
		if _, err := (&Sealer{}).Seal("bound", append(longest, 'b'), expires); !errors.Is(err, ErrSealTooLarge) {
			t.Errorf("zero Sealer's Seal(%d bytes) error = %v, want ErrSealTooLarge", MaxSealPayload+1, err)
		}
	})
	t.Run("empty_payload", func(t *testing.T) {
		t.Parallel()
		checkOpens(t, s, "bound", mustSeal(t, s, "bound", nil, expires), sealNow, nil)
	})
}

// wrappedBlock is an AES block that is not the *aes.Block
// cipher.NewGCMWithRandomNonce requires, as no GOEXPERIMENT=boringcrypto
// block is.
type wrappedBlock struct{ cipher.Block }

func TestSealAEADFallback(t *testing.T) {
	t.Parallel()
	block, err := aes.NewCipher([]byte(ringA))
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	random := newAEAD(block)
	if _, ok := random.(prefixedNonce); ok {
		t.Fatal("newAEAD(*aes.Block) took the cipher.NewGCM arm, want cipher.NewGCMWithRandomNonce")
	}
	explicit := newAEAD(wrappedBlock{block})
	if _, ok := explicit.(prefixedNonce); !ok {
		t.Fatalf("newAEAD(wrapped block) = %T, want the cipher.NewGCM arm", explicit)
	}
	arms := map[string]cipher.AEAD{"random_nonce": random, "explicit_nonce": explicit}
	payload := []byte("fallback-payload")
	for name, aead := range arms {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if aead.NonceSize() != 0 || aead.Overhead() != 12+16 {
				t.Errorf("NonceSize, Overhead = %d, %d, want 0, 28", aead.NonceSize(), aead.Overhead())
			}
			if _, err := aead.Open(nil, nil, make([]byte, 11), []byte("fallback")); err == nil {
				t.Error("Open of 11 bytes, shorter than the nonce, succeeded")
			}
			first := sealWith(aead, "fallback", payload, sealNow.Add(time.Hour))
			if first == sealWith(aead, "fallback", payload, sealNow.Add(time.Hour)) {
				t.Error("two seals of one payload are equal, want a fresh nonce each")
			}
			raw, err := sealEncoding.DecodeString(first)
			if err != nil {
				t.Fatalf("decoding the sealed value: %v", err)
			}
			if want := 12 + 12 + len(payload) + 16; len(raw) != want {
				t.Errorf("sealed value is %d bytes, want %d (nonce, frame, payload, tag)", len(raw), want)
			}
			for opener, other := range arms {
				plain, err := other.Open(nil, nil, raw, []byte("fallback"))
				if err != nil || len(plain) < sealFrameLen || !bytes.Equal(plain[sealFrameLen:], payload) {
					t.Errorf("the %s arm opened it to %q, %v, want the payload", opener, plain, err)
				}
			}
		})
	}
}

const (
	sealedFixturePath = "testdata/sealed-fixture.txt"
	// sealedFixtureRing is the fixed key the fixture is sealed under.
	sealedFixtureRing    = "sealer-fixture-0451-kn0wn-bytesF"
	sealedFixturePayload = "sealed once, opened in every crypto mode"
)

// The fixture is Seal("fixture", sealedFixturePayload, 2100-01-01) under
// sealedFixtureRing, written by UPDATE_GOLDEN=1 go test -run
// '^TestSealerOpensFixture$' . in the default mode. Opening it under
// GOEXPERIMENT=boringcrypto and GODEBUG=fips140=only proves every mode
// shares one wire form.
func TestSealerOpensFixture(t *testing.T) {
	t.Parallel()
	s := sealerOf(t, sealedFixtureRing)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		v := mustSeal(t, s, "fixture", []byte(sealedFixturePayload), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
		if err := os.WriteFile(sealedFixturePath, []byte(v+"\n"), 0o644); err != nil {
			t.Fatalf("writing %s: %v", sealedFixturePath, err)
		}
	}
	const regen = "regenerate with UPDATE_GOLDEN=1 go test -run '^TestSealerOpensFixture$' ."
	data, err := os.ReadFile(sealedFixturePath)
	if err != nil {
		t.Fatalf("reading %s: %v (%s)", sealedFixturePath, err, regen)
	}
	sealed := strings.TrimSuffix(string(data), "\n")
	if want := sealEncoding.EncodedLen(12 + 12 + len(sealedFixturePayload) + 16); len(sealed) != want {
		t.Errorf("fixture is %d characters, want %d (%s)", len(sealed), want, regen)
	}
	got, err := s.Open("fixture", sealed, sealNow)
	if err != nil || string(got) != sealedFixturePayload {
		t.Errorf("Open(fixture) = %q, %v, want %q (%s)", got, err, sealedFixturePayload, regen)
	}
}
