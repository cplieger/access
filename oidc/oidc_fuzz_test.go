package oidc

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

// FuzzClaimsStrings: any claim value either reads as the string or the
// strings it holds, or reports false; it never panics.
func FuzzClaimsStrings(f *testing.F) {
	for _, seed := range []string{`"admins"`, `["a","b"]`, `[]`, `null`, `3`, `["a",1]`, `{"a":"b"}`, `"\u0000"`, `[`, ``, `[null]`, `["a"] x`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, ok := Claims{Raw: map[string]json.RawMessage{"g": raw}}.Strings("g")
		var v any
		if json.Unmarshal(raw, &v) != nil {
			if ok {
				t.Fatalf("Strings(%q) = %q, true for invalid JSON", raw, got)
			}
			return
		}
		var want []string
		wantOK := true
		switch x := v.(type) {
		case string:
			want = []string{x}
		case []any:
			want = []string{}
			for _, e := range x {
				s, isString := e.(string)
				if !isString {
					wantOK = false
					break
				}
				want = append(want, s)
			}
		default:
			wantOK = false
		}
		if ok != wantOK || ok && !slices.Equal(got, want) {
			t.Fatalf("Strings(%q) = %q, %t; want %q, %t", raw, got, ok, want, wantOK)
		}
	})
}

// FuzzEmailVerified: any email_verified value decodes to a boolean only
// from true, false, "true" or "false" (and absent or null as false), and
// is refused with ErrTokenInvalid otherwise; it never panics.
func FuzzEmailVerified(f *testing.F) {
	for _, seed := range []string{`true`, `false`, `"true"`, `"false"`, `null`, `"TRUE"`, `1`, `"\u0074rue"`, `[true]`, `tru`, ``} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := decodeClaims(map[string]json.RawMessage{"email_verified": raw})
		var v any
		valid := json.Unmarshal(raw, &v) == nil
		want, wantOK := false, false
		switch x := v.(type) {
		case nil:
			wantOK = valid
		case bool:
			want, wantOK = x, true
		case string:
			want, wantOK = x == "true", x == "true" || x == "false"
		}
		if !wantOK {
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("email_verified %q: decodeClaims = %+v, %v; want ErrTokenInvalid", raw, got, err)
			}
			return
		}
		if err != nil || got.EmailVerified != want {
			t.Fatalf("email_verified %q: EmailVerified = %t, %v; want %t", raw, got.EmailVerified, err, want)
		}
	})
}
