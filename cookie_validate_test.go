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
		{"null in name", CookieConfig{Posture: PostureInsecureLAN, Name: "bad\x00name"}},
		{"newline in name", CookieConfig{Posture: PostureInsecureLAN, Name: "bad\nname"}},
		{"cr in name", CookieConfig{Posture: PostureInsecureLAN, Name: "bad\rname"}},
		{"semicolon in name", CookieConfig{Posture: PostureInsecureLAN, Name: "bad;name"}},
		{"space in name", CookieConfig{Posture: PostureInsecureLAN, Name: "bad name"}},
		{"null in domain", CookieConfig{Posture: PostureInsecureLAN, Name: "ok", Domain: "evil\x00.com"}},
		{"newline in path", CookieConfig{Posture: PostureInsecureLAN, Name: "ok", Path: "/\nevil"}},
		{"relative path", CookieConfig{Posture: PostureInsecureLAN, Name: "ok", Path: "app"}},
		{"semicolon in path", CookieConfig{Posture: PostureInsecureLAN, Name: "ok", Path: "/a;b"}},
		{"slash in name", CookieConfig{Posture: PostureInsecureLAN, Name: "a/b"}},
		{"parenthesis in name", CookieConfig{Posture: PostureInsecureLAN, Name: "a(b)"}},
		{"at sign in name", CookieConfig{Posture: PostureInsecureLAN, Name: "a@b"}},
		{"non-ASCII name", CookieConfig{Posture: PostureInsecureLAN, Name: "日本"}},
		{"invalid domain", CookieConfig{Posture: PostureInsecureLAN, Name: "ok", Domain: "exa mple.com"}},
		{"IPv6 domain", CookieConfig{Posture: PostureInsecureLAN, Name: "ok", Domain: "::1"}},
		{"domain under __Host-", CookieConfig{Posture: PostureSecure, Name: "ok", Domain: "example.com"}},
		{"sub-path under __Host-", CookieConfig{Posture: PostureSecure, Name: "ok", Path: "/app"}},
		{"nil HTTPS under PosturePerRequest", CookieConfig{Posture: PosturePerRequest, Name: "ok"}},
		{"__Secure- name under PostureInsecureLAN", CookieConfig{Posture: PostureInsecureLAN, Name: "__Secure-sess"}},
		{"__host- name under PosturePerRequest", CookieConfig{Posture: PosturePerRequest, Name: "__host-sess", HTTPS: RequestIsHTTPS}},
		{"__HOST- name under PostureSecure", CookieConfig{Posture: PostureSecure, Name: "__HOST-x"}},
		{"__Http- name under PostureInsecureLAN", CookieConfig{Posture: PostureInsecureLAN, Name: "__Http-sess"}},
		{"__hTTp- name under PosturePerRequest", CookieConfig{Posture: PosturePerRequest, Name: "__hTTp-sess", HTTPS: RequestIsHTTPS}},
		{"path over 1024 bytes", CookieConfig{Posture: PostureInsecureLAN, Name: "ok", Path: "/" + strings.Repeat("a", 1024)}},
		{"posture past the last constant", CookieConfig{Posture: PosturePerRequest + 1, Name: "ok", HTTPS: RequestIsHTTPS}},
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
			err := (&CookieConfig{Posture: PostureInsecureLAN, Name: name}).Validate()
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
		{"custom name insecure", CookieConfig{Posture: PostureInsecureLAN, Name: "my_session"}},
		{"with domain", CookieConfig{Posture: PostureInsecureLAN, Name: "sess", Domain: "example.com"}},
		{"with path", CookieConfig{Posture: PostureInsecureLAN, Name: "sess", Path: "/app/auth"}},
		{"space in path", CookieConfig{Posture: PostureInsecureLAN, Name: "sess", Path: "/a b"}},
		{"zero value", CookieConfig{}},
		{"strict", CookieConfig{SameSite: http.SameSiteStrictMode}},
		{"per-request with HTTPS", CookieConfig{Posture: PosturePerRequest, Name: "sess", HTTPS: RequestIsHTTPS}},
		{"IPv4 domain", CookieConfig{Posture: PostureInsecureLAN, Name: "sess", Domain: "192.0.2.77"}},
		{"path of 1024 bytes", CookieConfig{Posture: PostureInsecureLAN, Name: "sess", Path: "/" + strings.Repeat("a", 1023)}},
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
	for _, posture := range []CookiePosture{PostureSecure, PostureInsecureLAN, PosturePerRequest} {
		for _, sameSite := range []http.SameSite{http.SameSiteNoneMode, http.SameSiteDefaultMode, http.SameSite(99)} {
			t.Run(fmt.Sprintf("%s_samesite_%d", posture, sameSite), func(t *testing.T) {
				t.Parallel()
				cfg := CookieConfig{Name: "sess", SameSite: sameSite, Posture: posture, HTTPS: RequestIsHTTPS}
				if err := cfg.Validate(); err == nil {
					t.Errorf("Validate(SameSite %d, %s) = nil, want refused", sameSite, posture)
				}
			})
		}
	}
}
