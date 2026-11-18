package crockford

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzEncode_roundtrip(f *testing.F) {
	for _, s := range []string{"", "\x00", "\xff", "0123456789", "\x84\x65\x3a\x56\xd7\xc6\x75\xbe\x77\xdf"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		s := Encode(b)
		if len(s) != (len(b)*8+4)/5 {
			t.Fatalf("Encode(%x) is %d symbols, want ceil(8n/5) = %d", b, len(s), (len(b)*8+4)/5)
		}
		got, ok := Decode(s)
		if !ok || !bytes.Equal(got, b) {
			t.Fatalf("Decode(Encode(%x)) = %x, %t", b, got, ok)
		}
	})
}

// FuzzDecode_canonical: whatever Decode accepts is exactly what Encode
// returns for its bytes, so one byte string has one encoding.
func FuzzDecode_canonical(f *testing.F) {
	for _, s := range []string{"", "ZW", "ZX", "0", "000", "I000", "0123456789ABCDEF", "abcd"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, ok := Decode(s)
		if !ok {
			if b != nil {
				t.Fatalf("Decode(%q) = %x with false, want nil", s, b)
			}
			return
		}
		if got := Encode(b); got != s {
			t.Fatalf("Encode(Decode(%q)) = %q", s, got)
		}
	})
}

// FuzzNormalize_idempotent: Normalize's output holds none of what it maps
// or drops, and normalising it again changes nothing.
func FuzzNormalize_idempotent(f *testing.F) {
	for _, s := range []string{"", "oOiIlL-ab", "ß ı ſ", "abcd-efgh-jkmn-pqrs", "\xff\xfe"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n := Normalize(s)
		if strings.ContainsAny(n, "- OIL") || strings.ContainsFunc(n, func(r rune) bool { return 'a' <= r && r <= 'z' }) {
			t.Fatalf("Normalize(%q) = %q holds a byte it maps or drops", s, n)
		}
		if again := Normalize(n); again != n {
			t.Fatalf("Normalize(Normalize(%q)) = %q, want %q", s, again, n)
		}
		if want := len(s) - strings.Count(s, "-") - strings.Count(s, " "); len(n) != want {
			t.Fatalf("Normalize(%q) is %d bytes, want %d (only '-' and ' ' are dropped)", s, len(n), want)
		}
	})
}
