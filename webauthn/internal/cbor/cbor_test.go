package cbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// decodeAll decodes one item and requires that it used the whole input.
func decodeAll(t *testing.T, in string) Value {
	t.Helper()
	v, rest, err := Decode(unhex(t, in))
	if err != nil {
		t.Fatalf("Decode(%s) error = %v", in, err)
	}
	if len(rest) != 0 {
		t.Fatalf("Decode(%s) rest = %x, want none", in, rest)
	}
	return v
}

// RFC 8949 Appendix A, the integer rows, plus the int64 bounds.
func TestDecode_RFC8949AppendixA_integers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want int64
	}{
		{"00", 0},
		{"01", 1},
		{"0a", 10},
		{"17", 23},
		{"1818", 24},
		{"1819", 25},
		{"1864", 100},
		{"1903e8", 1000},
		{"1a000f4240", 1000000},
		{"1b000000e8d4a51000", 1000000000000},
		{"1b7fffffffffffffff", math.MaxInt64},
		{"20", -1},
		{"29", -10},
		{"3863", -100},
		{"3903e7", -1000},
		{"3b7fffffffffffffff", math.MinInt64},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, ok := decodeAll(t, tt.in).Int()
			if !ok || got != tt.want {
				t.Errorf("Int() = %d, %v; want %d, true", got, ok, tt.want)
			}
		})
	}
}

// RFC 8949 Appendix A's byte and text string rows, and §3.1's 1-, 2-, 4- and
// 8-byte length arguments.
func TestDecode_RFC8949AppendixA_strings(t *testing.T) {
	t.Parallel()
	bytesTests := []struct{ in, want string }{
		{"40", ""},
		{"4401020304", "01020304"},
		{"5801ab", "ab"},
		{"590001ab", "ab"},
		{"5a00000001ab", "ab"},
		{"5b0000000000000001ab", "ab"},
	}
	for _, tt := range bytesTests {
		t.Run("bytes "+tt.in, func(t *testing.T) {
			t.Parallel()
			got, ok := decodeAll(t, tt.in).Bytes()
			if !ok || hex.EncodeToString(got) != tt.want {
				t.Errorf("Bytes() = %x, %v; want %s, true", got, ok, tt.want)
			}
		})
	}
	textTests := []struct{ in, want string }{
		{"60", ""},
		{"6161", "a"},
		{"6449455446", "IETF"},
		{"62225c", "\"\\"},
		{"62c3bc", "\u00fc"},
		{"63e6b0b4", "\u6c34"},
		{"64f0908591", "\U00010151"},
		{"780161", "a"},
		{"79000161", "a"},
		{"7a0000000161", "a"},
		{"7b000000000000000161", "a"},
	}
	for _, tt := range textTests {
		t.Run("text "+tt.in, func(t *testing.T) {
			t.Parallel()
			got, ok := decodeAll(t, tt.in).Text()
			if !ok || got != tt.want {
				t.Errorf("Text() = %q, %v; want %q, true", got, ok, tt.want)
			}
		})
	}
}

// render prints a value in RFC 8949 §8 diagnostic notation, enough to compare
// Appendix A's arrays and maps.
func render(v Value) string {
	switch v.kind {
	case kindInt:
		return strconv.FormatInt(v.i, 10)
	case kindBytes:
		return "h'" + hex.EncodeToString(v.b) + "'"
	case kindText:
		return `"` + string(v.b) + `"`
	case kindArray:
		parts := make([]string, len(v.kids))
		for i := range v.kids {
			parts[i] = render(v.kids[i])
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case kindMap:
		entries, _ := v.Map()
		var parts []string
		for k, e := range entries {
			parts = append(parts, render(k)+": "+render(e))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case kindOther:
		return "other"
	default:
		return "invalid"
	}
}

// RFC 8949 Appendix A's array and map rows, and the major-type-7 rows
// (booleans, null, undefined, simple values, floats), which access never
// reads: each decodes to a value no accessor answers for.
func TestDecode_RFC8949AppendixA_containersAndSimple(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"80", "[]"},
		{"83010203", "[1, 2, 3]"},
		{"8301820203820405", "[1, [2, 3], [4, 5]]"},
		{
			"98190102030405060708090a0b0c0d0e0f101112131415161718181819",
			"[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]",
		},
		{"a0", "{}"},
		{"a201020304", "{1: 2, 3: 4}"},
		{"a26161016162820203", `{"a": 1, "b": [2, 3]}`},
		{"826161a161626163", `["a", {"b": "c"}]`},
		{
			"a56161614161626142616361436164614461656145",
			`{"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}`,
		},
		{"f4", "other"},
		{"f5", "other"},
		{"f6", "other"},
		{"f7", "other"},
		{"f0", "other"},
		{"f8ff", "other"},
		{"f90000", "other"},
		{"f98000", "other"},
		{"f93c00", "other"},
		{"f97bff", "other"},
		{"f97c00", "other"},
		{"f97e00", "other"},
		{"fa47c35000", "other"},
		{"fa7f7fffff", "other"},
		{"fb3ff199999999999a", "other"},
		{"fb7e37e43c8800759c", "other"},
		{"fbfff0000000000000", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := render(decodeAll(t, tt.in)); got != tt.want {
				t.Errorf("Decode(%s) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

// RFC 8949 Appendix F.1, every listed example, plus §3.2's indefinite lengths
// and RFC 8949 §3.4's tags, which the decoder refuses outright. Where an
// example reaches a decoder bound before its own error (nine nested arrays
// reach the depth bound), the bound's refusal is the expected one.
func TestDecode_RFC8949AppendixF_notWellFormed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want error
	}{
		// End of input in a head.
		{"18", errTruncated},
		{"19", errTruncated},
		{"1a", errTruncated},
		{"1b", errTruncated},
		{"1901", errTruncated},
		{"1a0102", errTruncated},
		{"1b01020304050607", errTruncated},
		{"38", errTruncated},
		{"58", errTruncated},
		{"78", errTruncated},
		{"98", errTruncated},
		{"9a01ff00", errTruncated},
		{"b8", errTruncated},
		{"d8", errTruncated},
		{"f8", errTruncated},
		{"f900", errTruncated},
		{"fa0000", errTruncated},
		{"fb000000", errTruncated},
		// Definite-length strings with short data.
		{"41", errTruncated},
		{"61", errTruncated},
		{"5affffffff00", errTruncated},
		{"5bffffffffffffffff010203", errTruncated},
		{"7affffffff00", errTruncated},
		{"7b7fffffffffffffff010203", errTruncated},
		// Definite-length maps and arrays not closed with enough items.
		{"81", errTruncated},
		{"818181818181818181", errLimit},
		{"81818181", errTruncated},
		{"8200", errTruncated},
		{"a1", errTruncated},
		{"a20102", errTruncated},
		{"a100", errTruncated},
		{"a2000000", errTruncated},
		// Tag number not followed by tag content.
		{"c0", errTag},
		// Indefinite-length strings, maps and arrays not closed by a break.
		{"5f4100", errIndefinite},
		{"7f6100", errIndefinite},
		{"9f", errIndefinite},
		{"9f0102", errIndefinite},
		{"bf", errIndefinite},
		{"bf01020102", errIndefinite},
		{"819f", errIndefinite},
		{"9f8000", errIndefinite},
		{"9f9f9f9f9fffffffff", errIndefinite},
		{"9f819f819f9fffffff", errIndefinite},
		// Subkind 1: reserved additional information values.
		{"1c", errNotWellFormed},
		{"1d", errNotWellFormed},
		{"1e", errNotWellFormed},
		{"3c", errNotWellFormed},
		{"3d", errNotWellFormed},
		{"3e", errNotWellFormed},
		{"5c", errNotWellFormed},
		{"5d", errNotWellFormed},
		{"5e", errNotWellFormed},
		{"7c", errNotWellFormed},
		{"7d", errNotWellFormed},
		{"7e", errNotWellFormed},
		{"9c", errNotWellFormed},
		{"9d", errNotWellFormed},
		{"9e", errNotWellFormed},
		{"bc", errNotWellFormed},
		{"bd", errNotWellFormed},
		{"be", errNotWellFormed},
		{"dc", errNotWellFormed},
		{"dd", errNotWellFormed},
		{"de", errNotWellFormed},
		{"fc", errNotWellFormed},
		{"fd", errNotWellFormed},
		{"fe", errNotWellFormed},
		// Subkind 2: reserved two-byte encodings of simple values.
		{"f800", errNotWellFormed},
		{"f801", errNotWellFormed},
		{"f818", errNotWellFormed},
		{"f81f", errNotWellFormed},
		// Subkind 3: indefinite-length string chunks.
		{"5f00ff", errIndefinite},
		{"5f21ff", errIndefinite},
		{"5f6100ff", errIndefinite},
		{"5f80ff", errIndefinite},
		{"5fa0ff", errIndefinite},
		{"5fc000ff", errIndefinite},
		{"5fe0ff", errIndefinite},
		{"7f4100ff", errIndefinite},
		{"5f5f4100ffff", errIndefinite},
		{"7f7f6100ffff", errIndefinite},
		// Subkind 4: a break outside an indefinite-length item.
		{"ff", errNotWellFormed},
		{"81ff", errNotWellFormed},
		{"8200ff", errNotWellFormed},
		{"a1ff", errNotWellFormed},
		{"a1ff00", errNotWellFormed},
		{"a100ff", errNotWellFormed},
		{"a20000ff", errNotWellFormed},
		{"9f81ff", errIndefinite},
		{"9f829f819f9fffffffff", errIndefinite},
		{"bf00ff", errIndefinite},
		{"bf000000ff", errIndefinite},
		// Subkind 5: major types 0, 1 and 6 with additional information 31.
		{"1f", errNotWellFormed},
		{"3f", errNotWellFormed},
		{"df", errNotWellFormed},
		// RFC 8949 §3.4: every tag.
		{"c074323031332d30332d32315432303a30343a30305a", errTag},
		{"d82076687474703a2f2f7777772e6578616d706c652e636f6d", errTag},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			_, _, err := Decode(unhex(t, tt.in))
			if !errors.Is(err, tt.want) {
				t.Errorf("Decode(%s) error = %v, want %v", tt.in, err, tt.want)
			}
		})
	}
}

// An integer outside int64 is refused, so no wrapped value can read as
// a COSE label such as -1. The first two rows are RFC 8949 Appendix A's.
func TestDecode_intRange(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"1bffffffffffffffff",
		"3bffffffffffffffff",
		"1b8000000000000000",
		"3b8000000000000000",
		"a13b800000000000000000",
	} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			if _, _, err := Decode(unhex(t, in)); !errors.Is(err, errIntRange) {
				t.Errorf("Decode(%s) error = %v, want errIntRange", in, err)
			}
		})
	}
}

// A map key is an integer or a text string, the only key types
// WebAuthn's CDDL and COSE (RFC 9052 §7) use.
func TestDecode_mapKeyType(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"bytes":     "a14000",
		"array":     "a18000",
		"map":       "a1a000",
		"false":     "a1f400",
		"null":      "a1f600",
		"undefined": "a1f700",
		"simple":    "a1f000",
		"float":     "a1f9000000",
		// py_webauthn#265: Python equates true with 1, so {1: 0, true: 0}
		// overwrote a key; a boolean is never a key here.
		"true beside 1": "a20100f500",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := Decode(unhex(t, in)); !errors.Is(err, errMapKey) {
				t.Errorf("Decode(%s) error = %v, want errMapKey", in, err)
			}
		})
	}
}

// WebAuthn §2.4 and RFC 8949 §5.6: a duplicate map key is refused, equality
// being of type and value, so 1 and "1" are different keys.
func TestDecode_duplicateKey(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"int":              "a2010001f5",
		"text":             "a261610061610f",
		"negative":         "a3200021002000",
		"non-shortest int": "a201001801f6",
		"nested map":       "a101a2020002f6",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := Decode(unhex(t, in)); !errors.Is(err, errDuplicateKey) {
				t.Errorf("Decode(%s) error = %v, want errDuplicateKey", in, err)
			}
		})
	}
	t.Run("int and text are different keys", func(t *testing.T) {
		t.Parallel()
		if got := render(decodeAll(t, "a201006131f5")); got != `{1: 0, "1": other}` {
			t.Errorf("Decode = %s, want {1: 0, \"1\": other}", got)
		}
	})
}

// RFC 8949 §5.3.1: a text string that is not valid UTF-8 is invalid.
func TestDecode_invalidUTF8(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"62c328", "61ff", "63eda080", "a162c32800"} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			if _, _, err := Decode(unhex(t, in)); !errors.Is(err, errUTF8) {
				t.Errorf("Decode(%s) error = %v, want errUTF8", in, err)
			}
		})
	}
}

// GHSA-g3qj-j598-cxmq (fido2-lib): a 5-byte header claiming a 268 MB string
// is refused before anything is allocated.
func TestDecode_GHSA_g3qj_j598_cxmq(t *testing.T) {
	for _, in := range []string{"7a10000000", "5a10000000", "9a10000000", "ba10000000"} {
		t.Run(in, func(t *testing.T) {
			data := unhex(t, in)
			if _, _, err := Decode(data); !errors.Is(err, errTruncated) {
				t.Fatalf("Decode(%s) error = %v, want errTruncated", in, err)
			}
			if n := testing.AllocsPerRun(100, func() { _, _, _ = Decode(data) }); n != 0 {
				t.Errorf("Decode(%s) allocates %v times, want 0", in, n)
			}
		})
	}
}

func nested(open string, depth int, inner string) string {
	return strings.Repeat(open, depth) + inner
}

// The decoder's bounds, read per Decode call: no container deeper than 4 levels, at
// most 256 data items with a map pair counting its key and its value, and at
// most 64 KiB of input.
func TestDecode_limits(t *testing.T) {
	t.Parallel()
	accept := map[string]string{
		"depth 4 array":        nested("81", 4, "00"),
		"depth 4 map":          nested("a100", 3, "a100f6"),
		"256 items in array":   "98ff" + strings.Repeat("00", 255),
		"256 items with a map": "81b87f" + mapPairs(127),
		"64 KiB":               "5a0000fffb" + strings.Repeat("00", 65531),
		"depth 4 then scalars": "8281818100" + "00",
	}
	for name, in := range accept {
		t.Run("accept "+name, func(t *testing.T) {
			t.Parallel()
			decodeAll(t, in)
		})
	}
	refuse := map[string]string{
		"depth 5 array":            nested("81", 5, "00"),
		"depth 5 empty array":      nested("81", 4, "80"),
		"depth 5 map":              nested("a100", 4, "a0"),
		"257 items in array":       "990100" + strings.Repeat("00", 256),
		"257 items in map":         "b880" + mapPairs(128),
		"257 items across arrays":  "82987f" + strings.Repeat("00", 127) + "987f" + strings.Repeat("00", 127),
		"64 KiB + 1":               "5a0000fffc" + strings.Repeat("00", 65532),
		"64 KiB + 1 trailing byte": "5a0000fffb" + strings.Repeat("00", 65531) + "00",
	}
	for name, in := range refuse {
		t.Run("refuse "+name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := Decode(unhex(t, in)); !errors.Is(err, errLimit) {
				t.Errorf("error = %v, want errLimit", err)
			}
		})
	}
}

// mapPairs encodes n distinct integer keys 0..n-1, each with the value 0.
func mapPairs(n int) string {
	var b strings.Builder
	for i := range n {
		switch {
		case i < 24:
			b.WriteString(hex.EncodeToString([]byte{byte(i)}))
		default:
			b.WriteString(hex.EncodeToString([]byte{0x18, byte(i)}))
		}
		b.WriteString("00")
	}
	return b.String()
}

// WebAuthn §2.4 recommends refusing CBOR outside the CTAP2 canonical form;
// access departs from it: a non-shortest integer or length and keys
// out of length-first order decode to their values.
func TestDecode_WebAuthn2_4_canonicalFormDeparture(t *testing.T) {
	t.Parallel()
	t.Run("non-shortest integer", func(t *testing.T) {
		t.Parallel()
		for _, in := range []string{"1817", "190017", "1a00000017", "1b0000000000000017"} {
			if got, ok := decodeAll(t, in).Int(); !ok || got != 23 {
				t.Errorf("Decode(%s).Int() = %d, %v; want 23, true", in, got, ok)
			}
		}
	})
	t.Run("non-shortest length", func(t *testing.T) {
		t.Parallel()
		if got, ok := decodeAll(t, "580161").Text(); ok || got != "" {
			t.Errorf("a byte string read as text: %q, %v", got, ok)
		}
		if got, ok := decodeAll(t, "580161").Bytes(); !ok || string(got) != "a" {
			t.Errorf("Bytes() = %q, %v; want \"a\", true", got, ok)
		}
	})
	t.Run("keys out of length-first order", func(t *testing.T) {
		t.Parallel()
		entries, ok := decodeAll(t, "a203260102").Map()
		if !ok {
			t.Fatal("Map() ok = false")
		}
		var got []int64
		for k, v := range entries {
			ki, _ := k.Int()
			vi, _ := v.Int()
			got = append(got, ki, vi)
		}
		if !slices.Equal(got, []int64{3, -7, 1, 2}) {
			t.Errorf("Map() = %v, want [3 -7 1 2] (keys and values in input order)", got)
		}
	})
}

// Decode reports the bytes after the item, which the attested
// credential data parse (WebAuthn §6.5.1) needs to find the extensions.
func TestDecode_trailingBytes(t *testing.T) {
	t.Parallel()
	data := unhex(t, "0102")
	v, rest, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode error = %v", err)
	}
	if got, ok := v.Int(); !ok || got != 1 {
		t.Errorf("Int() = %d, %v; want 1, true", got, ok)
	}
	if !bytes.Equal(rest, []byte{0x02}) {
		t.Errorf("rest = %x, want 02", rest)
	}
	empty, rest, err := Decode(nil)
	if !errors.Is(err, errTruncated) || empty.kind != kindInvalid || rest != nil {
		t.Errorf("Decode(nil) = %v, %x, %v; want errTruncated", empty.kind, rest, err)
	}
}

// Byte and text strings alias the input, so a large string is never
// copied.
func TestDecode_stringsAliasInput(t *testing.T) {
	t.Parallel()
	data := unhex(t, "824201026161")
	v := decodeAllBytes(t, data)
	arr := v.kids
	if len(arr) != 2 {
		t.Fatalf("array of %d, want 2", len(arr))
	}
	data[2] = 0xee
	data[5] = 'z'
	if b, _ := arr[0].Bytes(); b[0] != 0xee {
		t.Errorf("byte string did not alias the input: %x", b)
	}
	if s, _ := arr[1].Text(); s != "z" {
		t.Errorf("text string did not alias the input: %q", s)
	}
}

func decodeAllBytes(t *testing.T, data []byte) Value {
	t.Helper()
	v, rest, err := Decode(data)
	if err != nil || len(rest) != 0 {
		t.Fatalf("Decode(%x) = rest %x, error %v", data, rest, err)
	}
	return v
}

// Each accessor answers only for its own kind.
func TestValue_accessorsByKind(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"00", "40", "60", "80", "a0", "f4", "f6", "f7", "f0", "f90000"} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			v := decodeAll(t, in)
			_, isInt := v.Int()
			_, isBytes := v.Bytes()
			_, isText := v.Text()
			_, isMap := v.Map()
			got := []bool{isInt, isBytes, isText, isMap}
			want := []bool{in == "00", in == "40", in == "60", in == "a0"}
			for i := range got {
				if got[i] != want[i] {
					t.Errorf("Int, Bytes, Text, Map ok = %v, want %v", got, want)
					break
				}
			}
		})
	}
}
