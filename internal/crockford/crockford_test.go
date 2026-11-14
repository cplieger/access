package crockford

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// The 32 encode symbols of crockford.com/base32.html's table, by value.
const specSymbols = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// TestEncodeSymbolTable checks Encode against the spec's symbol table: each
// 80-bit input packs the values 0 to 15, then 16 to 31, five bits each,
// most significant first. Every expected string agrees with the Python
// base32-crockford package's encode of the same 80-bit number.
func TestEncodeSymbolTable(t *testing.T) {
	t.Parallel()
	vectors := []struct{ hex, want string }{
		{"00443214c74254b635cf", specSymbols[:16]},
		{"84653a56d7c675be77df", specSymbols[16:]},
		{"00000000000000000000", "0000000000000000"},
		{"ffffffffffffffffffff", "ZZZZZZZZZZZZZZZZ"},
		{"38b4e652e44da7f29e26", "72TECMQ49PKZ57H6"},
		{"0e27136550a4a3a65c0c", "1RKH6SAGMJHTCQ0C"},
		{"332f8b1224083fd22f89", "6CQRP4H410ZX4BW9"},
		{"11e81818f8c99d5d3195", "27M1G67RS6ENTCCN"},
	}
	for _, v := range vectors {
		t.Run(v.want, func(t *testing.T) {
			t.Parallel()
			b, err := hex.DecodeString(v.hex)
			if err != nil {
				t.Fatal(err)
			}
			if got := Encode(b); got != v.want {
				t.Errorf("Encode(%s) = %q, want %q", v.hex, got, v.want)
			}
			if got, ok := Decode(v.want); !ok || !bytes.Equal(got, b) {
				t.Errorf("Decode(%q) = %x, %t, want %s, true", v.want, got, ok, v.hex)
			}
		})
	}
}

// TestEncodeAlphabet: crockford.com/base32.html excludes I, L, O and U from
// the encode symbols.
func TestEncodeAlphabet(t *testing.T) {
	t.Parallel()
	seen := map[byte]bool{}
	for v := range 256 {
		for _, c := range []byte(Encode([]byte{byte(v), byte(v), byte(v), byte(v), byte(v)})) {
			seen[c] = true
		}
	}
	for c := range seen {
		if !strings.ContainsRune(specSymbols, rune(c)) {
			t.Errorf("Encode emitted %q, outside the spec's symbols", c)
		}
	}
	if len(seen) != 32 {
		t.Errorf("Encode emitted %d distinct symbols, want 32", len(seen))
	}
}

// TestEncodePadding: a bit count that is not a multiple of five pads the
// last symbol with zero bits, most significant bit first.
func TestEncodePadding(t *testing.T) {
	t.Parallel()
	vectors := []struct{ in, want string }{
		{"", ""},
		{"ff", "ZW"},     // 11111 111(00)
		{"01", "04"},     // 00000 001(00)
		{"ffff", "ZZZG"}, // 11111 11111 11111 1(0000)
		{"0001", "000G"}, // 00000 00000 00000 1(0000)
		{"0000000001", "00000001"},
	}
	for _, v := range vectors {
		t.Run("x"+v.in, func(t *testing.T) {
			t.Parallel()
			b, err := hex.DecodeString(v.in)
			if err != nil {
				t.Fatal(err)
			}
			if got := Encode(b); got != v.want {
				t.Errorf("Encode(%s) = %q, want %q", v.in, got, v.want)
			}
		})
	}
}

// TestDecodeRefuses is Decode accepting only what Encode returns.
func TestDecodeRefuses(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"letter_I":         "I000000000000000",
		"letter_L":         "L000000000000000",
		"letter_O":         "O000000000000000",
		"letter_U":         "U000000000000000",
		"lower_case":       "a000000000000000",
		"dash":             "0000-00000000000",
		"space":            "0000 00000000000",
		"one_symbol":       "0",
		"three_symbols":    "000",
		"six_symbols":      "000000",
		"padding_bit_set":  "ZX",
		"padding_bits_set": "ZZZZ",
		"non_ascii":        "000000000000000ß",
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if b, ok := Decode(s); ok || b != nil {
				t.Errorf("Decode(%q) = %x, %t, want nil, false", s, b, ok)
			}
		})
	}
}

// TestNormalize is 4.6's reading of crockford.com/base32.html's decode
// table: hyphens dropped (the spec), spaces dropped, case folded, O to 0
// and I and L to 1 (the spec); nothing outside ASCII is mapped. The
// Python base32-crockford package's normalize agrees on the ASCII rows.
func TestNormalize(t *testing.T) {
	t.Parallel()
	vectors := []struct{ in, want string }{
		{"oOiIlL-ab", "001111AB"},
		{"abcd-efgh-jkmn-pqrs", "ABCDEFGHJKMNPQRS"},
		{"tvwx yz01 2345 6789", "TVWXYZ0123456789"},
		{"u", "U"},
		{"--  --", ""},
		{"\tA", "\tA"},
		{"A_B", "A_B"},
		// Unicode case mapping would fold these to ASCII letters, and
		// JavaScript's full mapping turns ß into SS: 4.6 keeps them.
		{"ß", "ß"},
		{"ı", "ı"},
		{"ſ", "ſ"},
		{"\u212a", "\u212a"}, // KELVIN SIGN, which Unicode lower-cases to k
		{"１２３", "１２３"},       // fullwidth digits
		{"İ", "İ"},
	}
	for _, v := range vectors {
		t.Run(v.want, func(t *testing.T) {
			t.Parallel()
			if got := Normalize(v.in); got != v.want {
				t.Errorf("Normalize(%q) = %q, want %q", v.in, got, v.want)
			}
		})
	}
	for _, in := range []string{"ABCD-EFGH-JKMN-PQRß", "ABCD-EFGH-JKMN-PQRı", "ABCD-EFGH-JKMN-PQRſ", "ABCD-EFGH-JKMN-PQR１"} {
		t.Run("refused_"+in[len(in)-2:], func(t *testing.T) {
			t.Parallel()
			if b, ok := Decode(Normalize(in)); ok {
				t.Errorf("Decode(Normalize(%q)) = %x, true, want false", in, b)
			}
		})
	}
	t.Run("typed_form_decodes", func(t *testing.T) {
		t.Parallel()
		want, _ := hex.DecodeString("00443214c74254b635cf")
		for _, in := range []string{"0123-4567-89ab-cdef", "o123 4567 89AB CDEF", "0123456789abcdef"} {
			if got, ok := Decode(Normalize(in)); !ok || !bytes.Equal(got, want) {
				t.Errorf("Decode(Normalize(%q)) = %x, %t, want %x, true", in, got, ok, want)
			}
		}
	})
}
