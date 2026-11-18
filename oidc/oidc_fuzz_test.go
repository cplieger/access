package oidc

import (
	"encoding/json"
	json2 "encoding/json/v2"
	"errors"
	"slices"
	"testing"
	"time"
)

// FuzzClaimsStrings: any claim value either reads as the string or the
// strings it holds, by RFC 8259's grammar with unique names and valid
// UTF-8, or reports false; it never panics.
func FuzzClaimsStrings(f *testing.F) {
	for _, seed := range []string{`"admins"`, `["a","b"]`, `[]`, `null`, `3`, `["a",1]`, `{"a":"b"}`, `"\u0000"`, `[`, ``, `[null]`, `["a"] x`, "\"\xff\"", `[{"a":1,"a":2}]`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, ok := Claims{Raw: map[string]json.RawMessage{"g": raw}}.Strings("g")
		var v any
		if json2.Unmarshal(raw, &v) != nil {
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

// FuzzEmailVerified: any email_verified value reads as a boolean only from
// true, false, "true" or "false", and null as false; anything else refuses
// the token with ErrTokenInvalid; it never panics.
func FuzzEmailVerified(f *testing.F) {
	for _, seed := range []string{`true`, `false`, `"true"`, `"false"`, `null`, `"TRUE"`, `1`, `"\u0074rue"`, `[true]`, `tru`, ``, ` true `} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		base := fuzzToken(t)
		payload := []byte(`{"email_verified":` + string(raw) + "," + string(base[1:]))
		got, err := checkIDToken(payload, rulesFor(IntentSignIn))
		var v any
		valid := json2.Unmarshal(payload, &v) == nil
		var verified any
		if valid {
			verified = v.(map[string]any)["email_verified"]
		}
		want, wantOK := false, false
		switch x := verified.(type) {
		case nil:
			wantOK = valid
		case bool:
			want, wantOK = x, true
		case string:
			want, wantOK = x == "true", x == "true" || x == "false"
		}
		if !wantOK {
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("email_verified %q: checkIDToken = %+v, %v; want ErrTokenInvalid", raw, got, err)
			}
			return
		}
		if err != nil || got.EmailVerified != want {
			t.Fatalf("email_verified %q: EmailVerified = %t, %v; want %t", raw, got.EmailVerified, err, want)
		}
	})
}

// FuzzIDTokenClaims: any payload either refuses or yields Claims for the
// configured issuer, a sub of 1 to 255 printable ASCII characters
// (OpenID Connect Core 1.0 §2), an aud of this client alone, the sealed nonce
// and an unexpired token (Core 1.0 §3.1.3.7 steps 2, 3, 9 and 11); it never
// panics.
func FuzzIDTokenClaims(f *testing.F) {
	f.Add(fuzzToken(f))
	for _, seed := range []string{
		`{}`, `null`, `[]`, `{"iss":"accounts.google.com"}`,
		`{"iss":"https://idp.example/realms/main","sub":"a","aud":[],"nonce":"sealed-nonce","iat":1760000000,"exp":1760000300}`,
		`{"iss":"https://idp.example/realms/main","sub":"a","aud":["client","x"],"nonce":"sealed-nonce","iat":1760000000,"exp":1760000300}`,
		`{"iss":"https://idp.example/realms/main","sub":"a","aud":"client","nonce":"sealed-nonce","iat":-0.1,"exp":1e300}`,
		`{"iss":"https://idp.example/realms/main","sub":"a","aud":"client","nonce":"sealed-nonce","iat":1760000000,"exp":1760000300,"nbf":null,"azp":null}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		r := rulesFor(IntentSignIn)
		c, err := checkIDToken(payload, r)
		if err != nil {
			return
		}
		if c.Identity.Issuer != r.issuer || !validSubject(c.Identity.Subject) {
			t.Fatalf("checkIDToken(%q) Identity = %+v", payload, c.Identity)
		}
		var claims struct {
			Aud   any     `json:"aud"`
			Nonce string  `json:"nonce"`
			Exp   float64 `json:"exp"`
		}
		if err := json2.Unmarshal(payload, &claims); err != nil {
			t.Fatalf("checkIDToken accepted %q, which json/v2 refuses: %v", payload, err)
		}
		switch aud := claims.Aud.(type) {
		case string:
			if aud != r.clientID {
				t.Fatalf("checkIDToken(%q) accepted aud %q", payload, aud)
			}
		case []any:
			if len(aud) == 0 || slices.ContainsFunc(aud, func(a any) bool { return a != r.clientID }) {
				t.Fatalf("checkIDToken(%q) accepted aud %v", payload, aud)
			}
		default:
			t.Fatalf("checkIDToken(%q) accepted aud %v", payload, aud)
		}
		if claims.Nonce != r.nonce {
			t.Fatalf("checkIDToken(%q) accepted nonce %q", payload, claims.Nonce)
		}
		if exp := time.Unix(int64(claims.Exp), 0); !r.now.Before(exp.Add(tokenSkew)) {
			t.Fatalf("checkIDToken(%q) accepted exp %v at %v", payload, exp, r.now)
		}
	})
}

func fuzzToken(tb testing.TB) []byte {
	tb.Helper()
	b, err := json.Marshal(map[string]any{
		"iss": testIssuer, "sub": testSubject, "aud": testClient, "nonce": testNonce,
		"iat": tokenNow.Unix(), "exp": tokenNow.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		tb.Fatal(err)
	}
	return b
}
