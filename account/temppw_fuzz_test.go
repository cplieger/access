package account_test

import (
	"testing"

	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/crockford"
)

// FuzzTemporaryPasswordForm_canonical: whatever is presented, an accepted
// form decodes to ten bytes whose check passes and is the generator's own
// output for its first eight.
func FuzzTemporaryPasswordForm_canonical(f *testing.F) {
	for _, s := range []string{"", "04HM-ASW9-NF6Y-ZMDE", "04HMASW9NF6YZMDF", "ı", "0000000000001QV9"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		canonical, ok := account.TemporaryPasswordForm(s)
		if !ok {
			return
		}
		b, decoded := crockford.Decode(canonical)
		if !decoded || !checkBytes(b) {
			t.Fatalf("TemporaryPasswordForm(%q) accepted %q, whose check fails", s, canonical)
		}
		var r [8]byte
		copy(r[:], b)
		if got := account.TemporaryPasswordFrom(r); got != canonical {
			t.Fatalf("TemporaryPasswordForm(%q) = %q, the generator gives %q", s, canonical, got)
		}
	})
}
