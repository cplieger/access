package access

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/access/internal/printcheck"
)

// runtimeVerb builds a format string at run time, so go vet's printf check
// cannot see the verb the call uses.
func runtimeVerb(verb rune) string { return "%" + string(verb) }

// maskedVerbs are the verbs every masked value and its holders are printed
// with; %p is added separately, through runtimeVerb.
var maskedVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x"}

// maskedRenderings returns v printed through every route a masked value
// must survive, keyed by route. The %p route is fmt's bad-verb path for a
// non-pointer, which prints the fields by reflection without calling Format.
func maskedRenderings(t *testing.T, v any) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for _, verb := range maskedVerbs {
		out[verb] = fmt.Sprintf(verb, v)
	}
	out["%p"] = fmt.Sprintf(runtimeVerb('p'), v)
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("msg", "v", v)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("msg", "v", v)
	out["slog.TextHandler"] = text.String()
	out["slog.JSONHandler"] = js.String()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error = %v", v, err)
	}
	out["json.Marshal"] = string(b)
	return out
}

// checkMasked requires that no rendering of v contains a leak form of text
// and that every route fmt or a codec hands to the masked type's own methods
// renders "[redacted]".
func checkMasked(t *testing.T, v any, text string) {
	t.Helper()
	for route, got := range maskedRenderings(t, v) {
		if printcheck.Leak(got, text) {
			t.Errorf("%s printed the text: %s", route, got)
		}
		if route != "%p" && !strings.Contains(got, redacted) {
			t.Errorf("%s = %s, want it to contain %q", route, got, redacted)
		}
	}
}

// maskedTypes are the types printcheck.Unmasked does not enter: the
// "types" subtest of TestHash pins their fields.
var maskedTypes = []reflect.Type{reflect.TypeFor[Hash](), reflect.TypeFor[Secret](), reflect.TypeFor[masked]()}

// checkTypes requires that every field of roots' type graphs that can carry
// text is masked or one of allow's reviewed non-secret fields and types.
func checkTypes(t *testing.T, allow printcheck.Allow, roots ...reflect.Type) {
	t.Helper()
	allow.Masked = maskedTypes
	for _, line := range printcheck.Unmasked(allow, roots...) {
		t.Error(line)
	}
}

// checkMaskedBytes requires that v, a Hash or a Secret, holds exactly the
// masked bytes of text, a 32-byte tag and the encrypted text, and that they
// hold no leak form of text: everything a printer that follows the pointer
// can reach. It reads the field by reflection, so a red-check that changes
// the field's type still compiles.
func checkMaskedBytes(t *testing.T, v any, text string) {
	t.Helper()
	f := reflect.ValueOf(v).Field(1)
	if f.Type() != reflect.TypeFor[*masked]() {
		t.Fatalf("%T holds %s, want *masked", v, f.Type())
	}
	if f.IsNil() {
		t.Fatalf("%T of a non-empty text holds a nil *masked", v)
	}
	b := f.Elem().Field(0).Bytes()
	if got, want := len(b), sha256.Size+len(text); got != want {
		t.Errorf("%T holds %d masked bytes, want %d", v, got, want)
	}
	if printcheck.Leak(string(b), text) {
		t.Errorf("%T holds the text in its masked bytes: %q", v, b)
	}
}

func TestHash(t *testing.T) {
	t.Parallel()
	const text = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$a2V5"
	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		for name, z := range map[string]Hash{"literal": {}, "empty": NewHash("")} {
			if !z.IsZero() {
				t.Errorf("%s: IsZero() = false, want true", name)
			}
			if got := z.Reveal(); got != "" {
				t.Errorf("%s: Reveal() = %q, want empty", name, got)
			}
		}
	})
	t.Run("reveal", func(t *testing.T) {
		t.Parallel()
		h := NewHash(text)
		if h.IsZero() {
			t.Error("IsZero() = true for a non-empty text, want false")
		}
		if got := h.Reveal(); got != text {
			t.Errorf("Reveal() = %q, want %q", got, text)
		}
	})
	t.Run("equal", func(t *testing.T) {
		t.Parallel()
		first := "X" + text[1:]
		last := text[:len(text)-1] + "X"
		longerSalt := strings.Replace(text, "$c2FsdA$", "$c2FsdAB$", 1)
		cases := []struct {
			a, b Hash
			name string
			want bool
		}{
			{name: "same_text", a: NewHash(text), b: NewHash(text), want: true},
			{name: "first_byte_differs", a: NewHash(text), b: NewHash(first), want: false},
			{name: "last_byte_differs", a: NewHash(text), b: NewHash(last), want: false},
			{name: "unequal_length", a: NewHash("a"), b: NewHash("aa"), want: false},
			{name: "phc_extra_salt_byte", a: NewHash(text), b: NewHash(longerSalt), want: false},
			{name: "two_zero", a: Hash{}, b: NewHash(""), want: true},
			{name: "zero_and_non_zero", a: Hash{}, b: NewHash(text), want: false},
			{name: "non_zero_and_zero", a: NewHash(text), b: Hash{}, want: false},
		}
		for _, tc := range cases {
			if got := tc.a.Equal(tc.b); got != tc.want {
				t.Errorf("%s: Equal() = %t, want %t", tc.name, got, tc.want)
			}
		}
	})
	t.Run("deep_equal", func(t *testing.T) {
		t.Parallel()
		if !reflect.DeepEqual(NewHash(text), NewHash(text)) {
			t.Error("reflect.DeepEqual of two NewHash of one text = false, want true")
		}
		if reflect.DeepEqual(NewHash(text), NewHash(text+"X")) {
			t.Error("reflect.DeepEqual of two NewHash of different texts = true, want false")
		}
	})
	t.Run("iv_depends_on_text", func(t *testing.T) {
		t.Parallel()
		a, b := text, "X"+text[1:len(text)-1]+"X"
		ma, mb := mask(a), mask(b)
		if bytes.Equal(ma.b[:aes.BlockSize], mb.b[:aes.BlockSize]) {
			t.Error("two texts masked with one IV")
		}
		bodies := make([]byte, len(a))
		texts := make([]byte, len(a))
		for i := range len(a) {
			bodies[i] = ma.b[sha256.Size+i] ^ mb.b[sha256.Size+i]
			texts[i] = a[i] ^ b[i]
		}
		if bytes.Equal(bodies, texts) {
			t.Error("two texts share a keystream: the XOR of their masked bodies is the XOR of the texts")
		}
	})
	t.Run("types", func(t *testing.T) {
		t.Parallel()
		ht, st := reflect.TypeFor[Hash](), reflect.TypeFor[Secret]()
		if ht.Comparable() {
			t.Error("Hash is comparable, want == not to compile")
		}
		if st.Comparable() {
			t.Error("Secret is comparable, want == not to compile")
		}
		if ht.ConvertibleTo(st) {
			t.Error("Hash converts to Secret")
		}
		if st.ConvertibleTo(ht) {
			t.Error("Secret converts to Hash")
		}
		mt := reflect.TypeFor[masked]()
		if got, want := fieldTypes(mt), []reflect.Type{reflect.TypeFor[[]byte]()}; !slices.Equal(got, want) {
			t.Errorf("masked field types = %v, want %v", got, want)
		}
		want := []reflect.Type{reflect.TypeFor[[0]func()](), reflect.TypeFor[*masked]()}
		for _, typ := range []reflect.Type{ht, st} {
			if got := fieldTypes(typ); !slices.Equal(got, want) {
				t.Errorf("%s field types = %v, want %v", typ, got, want)
			}
		}
	})
}

// fieldTypes returns the types of typ's fields in order.
func fieldTypes(typ reflect.Type) []reflect.Type {
	out := make([]reflect.Type, typ.NumField())
	for i := range out {
		out[i] = typ.Field(i).Type
	}
	return out
}

// hashHolder is a plain struct with no printing methods of its own.
type hashHolder struct {
	Label  string
	Value  Hash
	hidden Hash
}

func TestHashPrinting(t *testing.T) {
	t.Parallel()
	const known = "kn0wn-st0red-h4sh-0451"
	h := NewHash(known)
	holder := hashHolder{Label: "lbl", Value: h, hidden: h}
	values := map[string]any{
		"value":             h,
		"pointer":           &h,
		"holder":            holder,
		"pointer_to_holder": &holder,
	}
	for name, v := range values {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			checkMasked(t, v, known)
		})
	}
	t.Run("masked_bytes", func(t *testing.T) {
		t.Parallel()
		checkMaskedBytes(t, h, known)
	})
	t.Run("type_graph", func(t *testing.T) {
		t.Parallel()
		checkTypes(t, printcheck.Allow{Fields: []string{"access.hashHolder.Label"}}, reflect.TypeFor[*hashHolder]())
	})
	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		var zero Hash
		for _, verb := range maskedVerbs {
			if got := fmt.Sprintf(verb, zero); got != "" {
				t.Errorf("Sprintf(%s, zero) = %q, want empty", verb, got)
			}
			if got := fmt.Sprintf(verb, &zero); got != "" {
				t.Errorf("Sprintf(%s, &zero) = %q, want empty", verb, got)
			}
		}
		if got := zero.LogValue().String(); got != "" {
			t.Errorf("zero.LogValue() = %q, want empty", got)
		}
		b, err := json.Marshal(zero)
		if err != nil {
			t.Fatalf("json.Marshal(zero) error = %v", err)
		}
		if got := string(b); got != `""` {
			t.Errorf("json.Marshal(zero) = %s, want \"\"", got)
		}
	})
}

func TestHashKey(t *testing.T) {
	t.Parallel()
	// At most 32 bytes, so a Key that copied the text's leading bytes would
	// hold the whole text, which the leak subtest looks for.
	const text = "kn0wn-st0red-h4sh-0451"
	other := "X" + text[1:]
	shared := strings.Repeat("s", 32)
	t.Run("same_text", func(t *testing.T) {
		t.Parallel()
		a, b := NewHash(text), NewHash(text)
		if a.Key() != b.Key() {
			t.Error("two NewHash of one text give different keys")
		}
	})
	t.Run("different_text", func(t *testing.T) {
		t.Parallel()
		if NewHash(text).Key() == NewHash(other).Key() {
			t.Error("two NewHash of different texts give one key")
		}
	})
	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		for name, z := range map[string]Hash{"literal": {}, "empty": NewHash("")} {
			if z.Key() != (HashKey{}) {
				t.Errorf("%s: Key() = %x, want the zero HashKey", name, z.Key())
			}
		}
		if NewHash(text).Key() == (HashKey{}) {
			t.Error("a non-zero Hash gives the zero HashKey")
		}
	})
	t.Run("agrees_with_equal", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			a, b Hash
			name string
			want bool
		}{
			{name: "same_text", a: NewHash(text), b: NewHash(text), want: true},
			{name: "first_byte_differs", a: NewHash(text), b: NewHash(other), want: false},
			{name: "unequal_length", a: NewHash("a"), b: NewHash("aa"), want: false},
			{name: "shared_32_byte_prefix", a: NewHash(shared + strings.Repeat("a", 32)), b: NewHash(shared + strings.Repeat("b", 32)), want: false},
			{name: "two_zero", a: Hash{}, b: NewHash(""), want: true},
			{name: "zero_and_non_zero", a: Hash{}, b: NewHash(text), want: false},
		}
		for _, tc := range cases {
			if got := tc.a.Equal(tc.b); got != tc.want {
				t.Errorf("%s: Equal() = %t, want %t", tc.name, got, tc.want)
			}
			if got := tc.a.Key() == tc.b.Key(); got != tc.want {
				t.Errorf("%s: Key() == Key() is %t, want %t", tc.name, got, tc.want)
			}
		}
	})
	t.Run("is_masked_tag", func(t *testing.T) {
		t.Parallel()
		// The tag is keyed per process; an unkeyed digest of the text would
		// fingerprint the hash across processes.
		h := NewHash(text)
		if got, want := h.Key(), HashKey(h.h.b[:maskTagSize]); got != want {
			t.Errorf("Key() = %x, want the masked value's tag %x", got, want)
		}
	})
	t.Run("map_key", func(t *testing.T) {
		t.Parallel()
		m := map[HashKey]int{NewHash(text).Key(): 7}
		if got, ok := m[NewHash(text).Key()]; !ok || got != 7 {
			t.Errorf("map lookup by a fresh NewHash = (%d, %t), want (7, true)", got, ok)
		}
		if _, ok := m[NewHash(other).Key()]; ok {
			t.Error("map lookup by another text's key found a value")
		}
	})
	t.Run("leak", func(t *testing.T) {
		t.Parallel()
		k := NewHash(text).Key()
		for _, verb := range []string{"%x", "%s"} {
			if got := fmt.Sprintf(verb, k); printcheck.Leak(got, text) {
				t.Errorf("Sprintf(%s, Key()) printed the text: %s", verb, got)
			}
		}
	})
}
