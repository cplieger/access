package printcheck

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"slices"
	"testing"
	"time"
	"unsafe"
)

// masker stands in for a masked type: Unmasked must not enter it.
type masker struct{ text string }

type words []string

type node struct {
	next  *node
	label string
}

type list []list

type kinds struct {
	str      string
	bytes    []byte
	schedule [60]uint32
	ids      []int64
	boxed    any
	byKey    map[string]int
	byValue  map[int][]uint8
	nested   *struct{ deep []*struct{ s string } }
	masked   masker
	maskedP  *masker
	when     time.Time
	n        int
	ok       bool
	f        func() string
	c        chan string
	p        unsafe.Pointer
	floats   []float64
	reviewed string
}

func TestUnmasked(t *testing.T) {
	t.Parallel()
	allow := Allow{
		Masked: []reflect.Type{reflect.TypeFor[masker]()},
		Fields: []string{"printcheck.kinds.reviewed"},
		Types:  []string{"time.Time"},
	}
	t.Run("kinds", func(t *testing.T) {
		t.Parallel()
		// A field this literal does not write is dead to deadset, which keeps a
		// field reflection reads only where the program writes it
		// (github.com/cplieger/deadset-go docs/encoding-reflection.md).
		fixture := &kinds{
			str:      "s",
			bytes:    []byte("b"),
			schedule: [60]uint32{1},
			ids:      []int64{1},
			boxed:    1,
			byKey:    map[string]int{"k": 1},
			byValue:  map[int][]uint8{1: {1}},
			nested:   &struct{ deep []*struct{ s string } }{deep: []*struct{ s string }{{s: "s"}}},
			masked:   masker{text: "t"},
			maskedP:  &masker{text: "t"},
			when:     time.Unix(1, 0),
			n:        1,
			ok:       true,
			f:        func() string { return "" },
			c:        make(chan string),
			p:        unsafe.Pointer(nil),
			floats:   []float64{1},
			reviewed: "r",
		}
		got := Unmasked(allow, reflect.TypeOf(fixture))
		want := []string{
			"printcheck.kinds.boxed: holds an interface (interface {})",
			"printcheck.kinds.byKey: holds a string (string)",
			"printcheck.kinds.byValue: holds an integer sequence ([]uint8)",
			"printcheck.kinds.bytes: holds an integer sequence ([]uint8)",
			"printcheck.kinds.ids: holds an integer sequence ([]int64)",
			"printcheck.kinds.schedule: holds an integer sequence ([60]uint32)",
			"printcheck.kinds.str: holds a string (string)",
			"struct { s string }.s: holds a string (string)",
		}
		if !slices.Equal(got, want) {
			t.Errorf("Unmasked() =\n%q\nwant\n%q", got, want)
		}
	})
	t.Run("root_leaf", func(t *testing.T) {
		t.Parallel()
		got := Unmasked(Allow{}, reflect.TypeFor[map[string]bool]())
		want := []string{"map[string]bool: holds a string (string)"}
		if !slices.Equal(got, want) {
			t.Errorf("Unmasked() = %q, want %q", got, want)
		}
	})
	t.Run("same_type_fields", func(t *testing.T) {
		t.Parallel()
		got := Unmasked(Allow{}, reflect.TypeFor[struct{ a, b words }]())
		want := []string{
			"struct { a printcheck.words; b printcheck.words }.a: holds a string (string)",
			"struct { a printcheck.words; b printcheck.words }.b: holds a string (string)",
		}
		if !slices.Equal(got, want) {
			t.Errorf("Unmasked() = %q, want %q", got, want)
		}
	})
	t.Run("stale_allow", func(t *testing.T) {
		t.Parallel()
		got := Unmasked(allow, reflect.TypeFor[struct{ n int }]())
		want := []string{
			"allow entry printcheck.kinds.reviewed: reached by no root",
			"allow entry time.Time: reached by no root",
		}
		if !slices.Equal(got, want) {
			t.Errorf("Unmasked() = %q, want %q", got, want)
		}
	})
	t.Run("cycles", func(t *testing.T) {
		t.Parallel()
		loop := &node{label: "loop"}
		loop.next = loop
		done := make(chan []string, 1)
		go func() { done <- Unmasked(Allow{}, reflect.TypeOf(*loop), reflect.TypeFor[list]()) }()
		select {
		case got := <-done:
			want := []string{"printcheck.node.label: holds a string (string)"}
			if !slices.Equal(got, want) {
				t.Errorf("Unmasked() = %q, want %q", got, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Unmasked did not return within 10s on a cyclic type")
		}
	})
}

func TestLeak(t *testing.T) {
	t.Parallel()
	const text = "s3cret>?~"
	std := func(prefix, suffix string) string {
		return base64.StdEncoding.EncodeToString([]byte(prefix + text + suffix))
	}
	cases := []struct {
		name, got string
		want      bool
	}{
		{name: "clear", got: "x=s3cret>?~;", want: true},
		{name: "hex", got: "7333637265743e3f7e", want: true},
		{name: "upper_hex", got: "7333637265743E3F7E", want: true},
		{name: "std_base64", got: "czNjcmV0Pj9+", want: true},
		{name: "url_base64", got: "czNjcmV0Pj9-", want: true},
		{name: "base64_offset_1", got: std("x", ""), want: true},
		{name: "base64_offset_2", got: std("xy", ""), want: true},
		{name: "base64_offset_1_followed", got: std("x", "!"), want: true},
		{name: "url_base64_offset_2_followed", got: base64.URLEncoding.EncodeToString([]byte("xy" + text + "tail")), want: true},
		{name: "other_text", got: base64.StdEncoding.EncodeToString([]byte("x" + "s3cret>?!")), want: false},
		{name: "redacted", got: "[redacted]", want: false},
	}
	for _, tc := range cases {
		if got := Leak(tc.got, text); got != tc.want {
			t.Errorf("%s: Leak(%q) = %t, want %t", tc.name, tc.got, got, tc.want)
		}
	}
	t.Run("hmac_pads", func(t *testing.T) {
		t.Parallel()
		key := make([]byte, 32)
		unrelated := make([]byte, 32)
		for i := range key {
			key[i] = byte(i*7 + 1)
			unrelated[i] = byte(i*11 + 200)
		}
		// crypto/hmac caches the key, zero-padded to the block, XOR 0x36
		// and XOR 0x5c (RFC 2104 §2); a printed HMAC shows those bytes.
		padded := func(b byte) []byte {
			block := make([]byte, sha256.BlockSize)
			copy(block, key)
			for i := range block {
				block[i] ^= b
			}
			return block
		}
		for name, block := range map[string][]byte{"ipad": padded(0x36), "opad": padded(0x5c)} {
			for route, got := range map[string]string{
				"clear":  string(block),
				"hex":    hex.EncodeToString(block),
				"base64": base64.StdEncoding.EncodeToString(block),
			} {
				if !Leak(got, string(key)) {
					t.Errorf("Leak(%s %s, key) = false, want true", name, route)
				}
			}
		}
		if Leak(hex.EncodeToString(unrelated)+base64.StdEncoding.EncodeToString(unrelated), string(key)) {
			t.Error("Leak(an unrelated 32-byte value, key) = true, want false")
		}
	})
}
