package jsonmember_test

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access/oidc/internal/jsonmember"
)

// RFC 8259 §4: an object is a set of name/value pairs. Names are compared
// as strings, so a case variant is another member and an escape spells the
// same name; whitespace may surround any token.
func TestObject_Accepted(t *testing.T) {
	t.Parallel()
	for data, want := range map[string][]string{
		`{}`:                                  {},
		` {"a" : 1 , "b":null} `:              {"a", "b"},
		`{"a":1,"A":2}`:                       {"A", "a"},
		`{"\u0061":1,"b":"\u00e9"}`:           {"a", "b"},
		`{"a":{"a":1},"b":[{"a":1},{"a":2}]}`: {"a", "b"},
		"{\"nom\":\"é\"}":                     {"nom"},
		`{"a":` + strings.Repeat("[", 100) + strings.Repeat("]", 100) + `}`: {"a"},
	} {
		m, err := jsonmember.Object([]byte(data))
		got := slices.Sorted(maps.Keys(m))
		if err != nil || !slices.Equal(got, want) || m == nil {
			t.Errorf("Object(%.60q) = %v, %v; want members %v", data, got, err, want)
		}
	}
	m, err := jsonmember.Object([]byte(`{"a":"x","b":[1, 2]}`))
	if err != nil || string(m["a"]) != `"x"` || string(m["b"]) != `[1, 2]` {
		t.Errorf("Object kept the values %q, %v; want each member's JSON text", m, err)
	}
}

// RFC 8259 §4: names within an object SHOULD be unique, and a receiver may
// refuse one that is not (RFC 7515 §4, RFC 7519 §4), at any depth and
// whatever the escape; §8.1: the text is UTF-8, so invalid UTF-8 or a lone
// surrogate escape is refused anywhere. Nesting is bounded (PyJWT
// CVE-2026-102265, Nimbus CVE-2025-53864), and a document is one value.
func TestObject_Refused(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat("[", 20_000) + strings.Repeat("]", 20_000)
	for name, data := range map[string]string{
		"duplicate":                `{"a":1,"a":1}`,
		"duplicate by escape":      `{"a":1,"\u0061":2}`,
		"duplicate nested":         `{"a":{"b":1,"b":2}}`,
		"duplicate in an array":    `{"a":[{"b":1,"b":2}]}`,
		"invalid UTF-8 in a value": "{\"a\":\"\xff\"}",
		"invalid UTF-8 in a name":  "{\"\xc3\x28\":1}",
		"invalid UTF-8 nested":     "{\"a\":[\"\xed\xa0\x80\"]}",
		"lone surrogate escape":    `{"a":"\ud800"}`,
		"20,000-deep value":        `{"a":` + deep + `}`,
		"trailing value":           `{} {}`,
		"truncated":                `{"a":1`,
		"null":                     `null`,
		"array":                    `[{"a":1}]`,
		"string":                   `"a"`,
		"number":                   `1`,
		"true":                     `true`,
		"empty":                    ``,
		"whitespace":               ` `,
		"single-quoted":            `{'a':1}`,
		"comment":                  `{"a":1 /* x */}`,
		"trailing comma":           `{"a":1,}`,
	} {
		if m, err := jsonmember.Object([]byte(data)); err == nil {
			t.Errorf("%s: Object(%.40q) = %v, nil; want an error", name, data, m)
		}
	}
}

// encoding/json/v2 decodes null into a Go string, number or bool as its
// zero value with no error, so a decode into a Go type cannot tell null from
// "", 0 or false; this is the behaviour String and Strings read past.
func TestNullDecodesToZero(t *testing.T) {
	t.Parallel()
	s, n, b := "x", 1, true
	for _, dst := range []any{&s, &n, &b} {
		if err := json.Unmarshal([]byte(`null`), dst); err != nil {
			t.Errorf("json/v2 refused null into %T: %v", dst, err)
		}
	}
	if s != "" || n != 0 || b {
		t.Errorf("json/v2 decoded null as %q, %d, %v; want the zero values", s, n, b)
	}
}

// RFC 8259 §7: a string is quoted; null, a number, true, false, an array
// and an object are other kinds, and an absent member is no member.
func TestString(t *testing.T) {
	t.Parallel()
	m, err := jsonmember.Object([]byte(`{"s":"x","esc":"\u0041\n","empty":"","null":null,"num":5,"t":true,"f":false,"arr":["x"],"obj":{"s":"x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"s": "x", "esc": "A\n", "empty": ""} {
		if got, ok := jsonmember.String(m[name]); !ok || got != want {
			t.Errorf("String(%s) = %q, %v; want %q, true", name, got, ok, want)
		}
	}
	for _, name := range []string{"null", "num", "t", "f", "arr", "obj", "absent", "S"} {
		if got, ok := jsonmember.String(m[name]); ok || got != "" {
			t.Errorf("String(%s) = %q, %v; want \"\", false", name, got, ok)
		}
	}
	if got, ok := jsonmember.String(jsontext.Value(`"a" x`)); ok {
		t.Errorf(`String("a" x) = %q, true; want false for text that is not one value`, got)
	}
}

// RFC 8259 §3: true and false are literal names; a string spelling one, a
// number, null and an absent member are other values.
func TestBool(t *testing.T) {
	t.Parallel()
	for v, want := range map[string]bool{`true`: true, `false`: false, ` true `: true} {
		if got, ok := jsonmember.Bool(jsontext.Value(v)); !ok || got != want {
			t.Errorf("Bool(%s) = %v, %v; want %v, true", v, got, ok, want)
		}
	}
	for _, v := range []string{`"true"`, `"false"`, `1`, `0`, `null`, `[true]`, `tru`, `truex`, `True`, ``} {
		if got, ok := jsonmember.Bool(jsontext.Value(v)); ok || got {
			t.Errorf("Bool(%q) = %v, %v; want false, false", v, got, ok)
		}
	}
}

// RFC 7519 §2: a NumericDate is a JSON number of seconds since
// 1970-01-01T00:00:00Z, which may carry a fraction. The range [0,
// 253402300799] (9999-12-31T23:59:59Z) is judged on the number itself, so
// -0.1 is not read as 0 nor 1e300 converted to an integer; null, a string
// and an absent member are not numbers (RFC 8259 §6).
func TestNumericDate(t *testing.T) {
	t.Parallel()
	for v, want := range map[string]int64{
		`0`:                          0,
		`-0`:                         0,
		`0.5`:                        0,
		`1`:                          1,
		`1760000000`:                 1_760_000_000,
		`1760000000.999`:             1_760_000_000,
		`1.76e9`:                     1_760_000_000,
		`17600000000E-1`:             1_760_000_000,
		`253402300799`:               253_402_300_799,
		`253402300799.0`:             253_402_300_799,
		`2.53402300799e11`:           253_402_300_799,
		`1E+3`:                       1000,
		`1e-400`:                     0,
		`0.000000000000000000001e25`: 10_000,
		`1e-99999999999999999999`:    0,
		`-0e5`:                       0,
	} {
		got, ok := jsonmember.NumericDate(jsontext.Value(v))
		if !ok || !got.Equal(time.Unix(want, 0)) {
			t.Errorf("NumericDate(%s) = %v, %v; want %v, true", v, got, ok, time.Unix(want, 0).UTC())
		}
	}
	for _, v := range []string{
		`-1`, `-0.1`, `-1e-3`, `-1e-400`, `253402300800`, `253402300799.5`, `253402300799.00000000001`,
		`2.534023008e11`, `1e300`, `1e400`, `-1e400`, `1e99999999999999999999`, `1e12`,
		`"1760000000"`, `null`, `true`, `[1760000000]`, `{}`, ``, `01`, `1760000000 1`, `.5`, `1.`, `+1`,
	} {
		if got, ok := jsonmember.NumericDate(jsontext.Value(v)); ok {
			t.Errorf("NumericDate(%q) = %v, true; want false", v, got)
		}
	}
}

// RFC 8259 §5: an array is a sequence of values, each of any kind; Strings
// accepts only one whose every value is a string, so a null entry is never
// read as "".
func TestArrayAndStrings(t *testing.T) {
	t.Parallel()
	vals, ok := jsonmember.Array(jsontext.Value(`[1,"a",null,[],{}]`))
	if !ok || len(vals) != 5 || string(vals[1]) != `"a"` || vals[2].Kind() != 'n' {
		t.Errorf("Array = %q, %v; want the five values", vals, ok)
	}
	if vals, ok := jsonmember.Array(jsontext.Value(`[]`)); !ok || len(vals) != 0 {
		t.Errorf("Array([]) = %q, %v; want none, true", vals, ok)
	}
	for v, want := range map[string][]string{`["a","b","a"]`: {"a", "b", "a"}, `[]`: {}, `[""]`: {""}} {
		if got, ok := jsonmember.Strings(jsontext.Value(v)); !ok || !slices.Equal(got, want) || got == nil {
			t.Errorf("Strings(%s) = %q, %v; want %q, true", v, got, ok, want)
		}
	}
	for _, v := range []string{`null`, `"a"`, `{"a":"b"}`, `5`, `["a",null]`, `["a",1]`, `["a",["b"]]`, `[true]`} {
		if got, ok := jsonmember.Strings(jsontext.Value(v)); ok || got != nil {
			t.Errorf("Strings(%s) = %q, %v; want nil, false", v, got, ok)
		}
		if v[0] != '[' {
			if got, ok := jsonmember.Array(jsontext.Value(v)); ok || got != nil {
				t.Errorf("Array(%s) = %q, %v; want nil, false", v, got, ok)
			}
		}
	}
}
