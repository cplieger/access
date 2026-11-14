package access

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestCookieConfig_Validate_RejectsControlChars(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  CookieConfig
	}{
		{"null in name", CookieConfig{Posture: PosturePerRequest, Name: "bad\x00name"}},
		{"newline in name", CookieConfig{Posture: PosturePerRequest, Name: "bad\nname"}},
		{"cr in name", CookieConfig{Posture: PosturePerRequest, Name: "bad\rname"}},
		{"semicolon in name", CookieConfig{Posture: PosturePerRequest, Name: "bad;name"}},
		{"space in name", CookieConfig{Posture: PosturePerRequest, Name: "bad name"}},
		{"slash in name", CookieConfig{Posture: PosturePerRequest, Name: "a/b"}},
		{"parenthesis in name", CookieConfig{Posture: PosturePerRequest, Name: "a(b)"}},
		{"at sign in name", CookieConfig{Posture: PosturePerRequest, Name: "a@b"}},
		{"non-ASCII name", CookieConfig{Posture: PosturePerRequest, Name: "日本"}},
		{"__Secure- name under PosturePerRequest", CookieConfig{Posture: PosturePerRequest, Name: "__Secure-sess"}},
		{"__host- name under PosturePerRequest", CookieConfig{Posture: PosturePerRequest, Name: "__host-sess"}},
		{"__HOST- name under PostureSecure", CookieConfig{Posture: PostureSecure, Name: "__HOST-x"}},
		{"__Http- name under PostureSecure", CookieConfig{Posture: PostureSecure, Name: "__Http-sess"}},
		{"__hTTp- name under PosturePerRequest", CookieConfig{Posture: PosturePerRequest, Name: "__hTTp-sess"}},
		{"posture past the last constant", CookieConfig{Posture: PosturePerRequest + 1, Name: "ok"}},
		{"negative posture", CookieConfig{Posture: -1, Name: "ok"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.cfg.Validate(); err == nil {
				t.Fatal("expected Validate() to reject config with invalid characters")
			}
		})
	}
	for _, name := range []string{"__Secure-sess", "__Http-sess"} {
		t.Run("prefix_message_"+name, func(t *testing.T) {
			t.Parallel()
			err := (&CookieConfig{Posture: PosturePerRequest, Name: name}).Validate()
			const want = "access: CookieConfig.Name must not carry a __Secure-, __Host- or __Http- prefix"
			if err == nil || err.Error() != want {
				t.Errorf("Validate(Name %q) = %v, want %q", name, err, want)
			}
		})
	}
}

func TestCookieConfig_Validate_AcceptsValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  CookieConfig
	}{
		{"default", DefaultCookieConfig()},
		{"custom name per-request", CookieConfig{Posture: PosturePerRequest, Name: "my_session"}},
		{"zero value", CookieConfig{}},
		{"strict", CookieConfig{SameSite: http.SameSiteStrictMode}},
		{"name of 64 bytes", CookieConfig{Posture: PosturePerRequest, Name: strings.Repeat("a", 64)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestValidateSameSiteNone(t *testing.T) {
	t.Parallel()
	for _, posture := range postures {
		for _, sameSite := range []http.SameSite{http.SameSiteNoneMode, http.SameSiteDefaultMode, http.SameSite(99)} {
			t.Run(fmt.Sprintf("%s_samesite_%d", posture, sameSite), func(t *testing.T) {
				t.Parallel()
				cfg := CookieConfig{Name: "sess", SameSite: sameSite, Posture: posture}
				if err := cfg.Validate(); err == nil {
					t.Errorf("Validate(SameSite %d, %s) = nil, want refused", sameSite, posture)
				}
			})
		}
	}
}
