package cbor

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzDecode checks, for any input, that Decode never panics and that an
// accepted item keeps the decoder's bounds, aliases the input, decodes the same from
// its own span, and is refused as truncated when cut short (a definite-length
// CBOR item is prefix-free, RFC 8949 §3).
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"00", "1b7fffffffffffffff", "3b7fffffffffffffff", "4401020304", "64f0908591",
		"8301820203820405", "a26161016162820203", "a56161614161626142616361436164614461656145",
		"f4", "f8ff", "fb3ff199999999999a", "a203260102", "0102", "818181818100",
		"1c", "f818", "ff", "5f4100", "c0", "7a10000000", "a2010001f5", "62c328", "1bffffffffffffffff",
	} {
		f.Add(unhex(f, s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, rest, err := Decode(data)
		if err != nil {
			return
		}
		if len(data) > maxInput {
			t.Fatalf("accepted %d bytes, bound is %d", len(data), maxInput)
		}
		span := data[:len(data)-len(rest)]
		if !bytes.Equal(rest, data[len(span):]) {
			t.Fatalf("rest %x is not the input's tail", rest)
		}
		var items int
		checkTree(t, v, 1, &items)
		if items > maxItems {
			t.Fatalf("%d items, bound is %d", items, maxItems)
		}

		alone, aloneRest, err := Decode(span)
		if err != nil || len(aloneRest) != 0 || render(alone) != render(v) {
			t.Fatalf("the item's own span %x decodes to %s, rest %x, error %v; want %s",
				span, render(alone), aloneRest, err, render(v))
		}
		for _, n := range []int{len(span) - 1, len(span) / 2} {
			if _, _, err := Decode(span[:n]); !errors.Is(err, ErrTruncated) {
				t.Fatalf("prefix %x of %x: error %v, want ErrTruncated", span[:n], span, err)
			}
		}

		strs := collectStrings(v, nil)
		before := make([][]byte, len(strs))
		for i, s := range strs {
			before[i] = bytes.Clone(s)
		}
		for i := range data {
			data[i] ^= 0xff
		}
		for i, s := range strs {
			for j := range s {
				if s[j] != before[i][j]^0xff {
					t.Fatalf("string %x does not alias the input", before[i])
				}
			}
		}
	})
}

func checkTree(t *testing.T, v Value, depth int, items *int) {
	t.Helper()
	*items++
	switch v.kind {
	case kindArray, kindMap:
		if depth > maxDepth {
			t.Fatalf("a container at depth %d, bound is %d", depth, maxDepth)
		}
	case kindInvalid:
		t.Fatal("an accepted tree holds an invalid value")
	}
	for i := range v.kids {
		checkTree(t, v.kids[i], depth+1, items)
	}
	if v.kind != kindMap {
		return
	}
	seen := map[string]bool{}
	for k := range mustMap(t, v) {
		if k.kind != kindInt && k.kind != kindText {
			t.Fatalf("map key of kind %d", k.kind)
		}
		id := render(k)
		if seen[id] {
			t.Fatalf("duplicate key %s", id)
		}
		seen[id] = true
	}
}

func mustMap(t *testing.T, v Value) func(func(Value, Value) bool) {
	t.Helper()
	entries, ok := v.Map()
	if !ok {
		t.Fatal("a map value's Map() ok = false")
	}
	return entries
}

func collectStrings(v Value, out [][]byte) [][]byte {
	if v.kind == kindBytes || v.kind == kindText {
		out = append(out, v.b)
	}
	for i := range v.kids {
		out = collectStrings(v.kids[i], out)
	}
	return out
}
