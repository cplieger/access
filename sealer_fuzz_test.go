package access

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

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
		"oidc-flow":    mustSeal(f, s, "oidc-flow", payload, now.Add(time.Hour)),
		"oidc-pending": mustSeal(f, s, "oidc-pending", payload, now.Add(time.Hour)),
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
