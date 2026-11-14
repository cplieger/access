package access

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// defaultSecureCookieName is the cookie name the default (PostureSecure) config
// emits: the __Host- prefix on the default base name.
const defaultSecureCookieName = "__Host-" + defaultCookieName

var postures = []CookiePosture{PostureSecure, PosturePerRequest}

func TestCookieConfig_Defaults(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	if cfg.Name != "auth_session" {
		t.Errorf("default Name = %q, want %q", cfg.Name, "auth_session")
	}
	if cfg.Posture != PostureSecure {
		t.Errorf("default Posture = %d, want PostureSecure", cfg.Posture)
	}
	if cfg.SameSite != http.SameSiteLaxMode {
		t.Errorf("default SameSite = %d, want Lax", cfg.SameSite)
	}
}

// setCookie runs SetCookie for one transport and returns its one cookie
// and its Set-Cookie line.
func setCookie(t *testing.T, cfg CookieConfig, secure bool, maxAge int) (*http.Cookie, string) {
	t.Helper()
	w := httptest.NewRecorder()
	cfg.SetCookie(w, secure, "tok", maxAge)
	lines := w.Header().Values("Set-Cookie")
	if len(lines) != 1 {
		t.Fatalf("SetCookie wrote %d Set-Cookie lines, want 1: %q", len(lines), lines)
	}
	c, err := http.ParseSetCookie(lines[0])
	if err != nil {
		t.Fatalf("Set-Cookie %q: %v", lines[0], err)
	}
	return c, lines[0]
}

// TestCookieNameTransport pins the name and the Secure flag each posture
// gives each transport: PosturePerRequest drops the prefix and the flag
// for a plain request, PostureSecure keeps one name and the flag for both.
func TestCookieNameTransport(t *testing.T) {
	t.Parallel()
	cases := []struct {
		posture  CookiePosture
		secure   bool
		wantName string
		wantFlag bool
	}{
		{PosturePerRequest, true, "__Host-sess", true},
		{PosturePerRequest, false, "sess", false},
		{PostureSecure, true, "__Host-sess", true},
		{PostureSecure, false, "__Host-sess", true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_secure_%t", tc.posture, tc.secure), func(t *testing.T) {
			t.Parallel()
			cfg := CookieConfig{Posture: tc.posture, Name: "sess"}
			if got := cfg.CookieName(tc.secure); got != tc.wantName {
				t.Errorf("CookieName(%t) = %q, want %q", tc.secure, got, tc.wantName)
			}
			c, line := setCookie(t, cfg, tc.secure, 60)
			if c.Name != tc.wantName || c.Secure != tc.wantFlag {
				t.Errorf("SetCookie(%t) = %q, want name %q with Secure %t", tc.secure, line, tc.wantName, tc.wantFlag)
			}
			if c.Path != "/" || c.Domain != "" || !c.HttpOnly {
				t.Errorf("SetCookie(%t) = %q, want HttpOnly, Path=/ and no Domain", tc.secure, line)
			}
		})
	}
	t.Run("unset_base_name", func(t *testing.T) {
		t.Parallel()
		cfg := CookieConfig{}
		if got := cfg.CookieName(true); got != defaultSecureCookieName {
			t.Errorf("zero config CookieName(true) = %q, want %q", got, defaultSecureCookieName)
		}
	})
}

// TestSetCookiePlainDropsMaxAge pins that no cookie set for a plain
// request outlives the browser, under both postures and for every
// companion, while a secure request's keeps its lifetime and a clear
// sends Max-Age=0 on either transport.
func TestSetCookiePlainDropsMaxAge(t *testing.T) {
	t.Parallel()
	for _, posture := range postures {
		session := CookieConfig{Posture: posture, Name: "sess", SameSite: http.SameSiteStrictMode}
		configs := map[string]CookieConfig{
			"session":      session,
			"device":       session.Derive("device", http.SameSiteLaxMode),
			"oidc_pending": session.Derive("oidc_pending", http.SameSiteLaxMode),
			"oidc":         session.Derive("oidc", http.SameSiteLaxMode),
		}
		for name, cfg := range configs {
			t.Run(fmt.Sprintf("%s_%s", posture, name), func(t *testing.T) {
				t.Parallel()
				if c, line := setCookie(t, cfg, true, 3600); c.MaxAge != 3600 || !strings.Contains(line, "Max-Age=3600") {
					t.Errorf("secure Set-Cookie = %q, want Max-Age=3600", line)
				}
				if _, line := setCookie(t, cfg, false, 3600); strings.Contains(line, "Max-Age") || strings.Contains(line, "Expires") {
					t.Errorf("plain Set-Cookie = %q, want neither Max-Age nor Expires", line)
				}
				for _, secure := range []bool{true, false} {
					w := httptest.NewRecorder()
					cfg.ClearCookie(w, secure)
					if line := w.Header().Get("Set-Cookie"); !strings.Contains(line, "Max-Age=0") {
						t.Errorf("ClearCookie(%t) Set-Cookie = %q, want Max-Age=0", secure, line)
					}
				}
			})
		}
	}
}

func TestCookieConfig_SetAndRead(t *testing.T) {
	t.Parallel()
	for _, posture := range postures {
		for _, secure := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s_secure_%t", posture, secure), func(t *testing.T) {
				t.Parallel()
				cfg := CookieConfig{Posture: posture, Name: "test_sess"}
				c, _ := setCookie(t, cfg, secure, 3600)
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.AddCookie(c)
				if got := cfg.ReadCookie(r, secure); got != "tok" {
					t.Errorf("ReadCookie(%t) = %q, want the cookie SetCookie(%t) set", secure, got, secure)
				}
			})
		}
	}
}

func TestCookieConfig_SameSite(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		set  http.SameSite
		want http.SameSite
	}{{0, http.SameSiteLaxMode}, {http.SameSiteLaxMode, http.SameSiteLaxMode}, {http.SameSiteStrictMode, http.SameSiteStrictMode}} {
		cfg := CookieConfig{Name: "s", SameSite: tc.set}
		if c, line := setCookie(t, cfg, true, 100); c.SameSite != tc.want {
			t.Errorf("SameSite %d: Set-Cookie = %q, want SameSite %d", tc.set, line, tc.want)
		}
	}
}

func TestCookieConfig_CacheControl(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	w := httptest.NewRecorder()
	cfg.SetCookie(w, true, "tok", 3600)
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %q", got)
	}
}

// TestCookieConfig_Secure_ReadCookie_ignoresUnprefixedCookie pins the
// session-fixation defense: under PostureSecure, a bare (unprefixed)
// cookie an attacker can set over plain HTTP is never read as the session
// token, whatever the transport.
func TestCookieConfig_Secure_ReadCookie_ignoresUnprefixedCookie(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureSecure, Name: "sess"}
	for _, secure := range []bool{true, false} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: "sess", Value: "attacker-token"})
		if got := cfg.ReadCookie(r, secure); got != "" {
			t.Errorf("ReadCookie(%t) read an unprefixed cookie %q under PostureSecure, want \"\" (session fixation)", secure, got)
		}
	}
}

func TestCookiePosture_String(t *testing.T) {
	t.Parallel()
	cases := []struct {
		posture CookiePosture
		want    string
	}{
		{PostureSecure, "PostureSecure"},
		{PosturePerRequest, "PosturePerRequest"},
		{CookiePosture(99), "CookiePosture(99)"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			if got := tc.posture.String(); got != tc.want {
				t.Errorf("CookiePosture(%d).String() = %q, want %q", int(tc.posture), got, tc.want)
			}
		})
	}
}

func TestDeriveSuffix(t *testing.T) {
	t.Parallel()
	base := CookieConfig{
		Name:     "sess",
		SameSite: http.SameSiteStrictMode,
		Posture:  PosturePerRequest,
	}
	for _, suffix := range []string{"oidc", "oidc_pending", "device", "_", strings.Repeat("z", 16)} {
		t.Run("valid_"+suffix, func(t *testing.T) {
			t.Parallel()
			d := base.Derive(suffix, http.SameSiteLaxMode)
			if want := "sess_" + suffix; d.Name != want {
				t.Errorf("Derive(%q).Name = %q, want %q", suffix, d.Name, want)
			}
			for _, secure := range []bool{true, false} {
				if d.CookieName(secure) == base.CookieName(secure) {
					t.Errorf("Derive(%q) name %q equals the base name", suffix, d.CookieName(secure))
				}
			}
			if d.Posture != base.Posture {
				t.Errorf("Derive(%q).Posture = %v, want the base's", suffix, d.Posture)
			}
			if d.SameSite != http.SameSiteLaxMode {
				t.Errorf("Derive(%q).SameSite = %v, want Lax", suffix, d.SameSite)
			}
		})
	}
	t.Run("unset_samesite", func(t *testing.T) {
		t.Parallel()
		d := base.Derive("device", 0)
		if _, line := setCookie(t, d, true, 60); !strings.Contains(line, "; SameSite=Lax") {
			t.Errorf("Derive(device, unset) Set-Cookie %q lacks SameSite=Lax", line)
		}
	})
	t.Run("unset_base_name", func(t *testing.T) {
		t.Parallel()
		d := CookieConfig{}.Derive("device", http.SameSiteLaxMode)
		if got := d.CookieName(true); got != "__Host-auth_session_device" {
			t.Errorf("zero config Derive(device) name = %q, want %q", got, "__Host-auth_session_device")
		}
	})
	for _, suffix := range []string{"", strings.Repeat("z", 17), "OIDC", "oidc-x", "oidc.x", "a b", "dévice", "oidc\x00", "oidc1"} {
		t.Run(fmt.Sprintf("invalid_%q", suffix), func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Errorf("Derive(%q) did not panic, want the suffix refused", suffix)
				}
			}()
			base.Derive(suffix, http.SameSiteLaxMode)
		})
	}
	for _, sameSite := range []http.SameSite{http.SameSiteNoneMode, http.SameSiteDefaultMode, http.SameSite(99)} {
		t.Run(fmt.Sprintf("invalid_samesite_%d", sameSite), func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Errorf("Derive(device, SameSite %d) did not panic, want it refused", sameSite)
				}
			}()
			base.Derive("device", sameSite)
		})
	}
}

func TestCookieConfig_ReadCookie_exactlyOne(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PosturePerRequest, Name: "s"}
	cases := []struct {
		name   string
		header []string
		want   string
	}{
		{"none", nil, ""},
		{"one", []string{"s=tok"}, "tok"},
		{"one_beside_others", []string{"a=1; s=tok; b=2"}, "tok"},
		{"two_in_one_line", []string{"s=tok; s=planted"}, ""},
		{"two_across_lines", []string{"s=tok", "s=planted"}, ""},
		{"two_equal_values", []string{"s=tok; s=tok"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, h := range tc.header {
				r.Header.Add("Cookie", h)
			}
			if got := cfg.ReadCookie(r, false); got != tc.want {
				t.Errorf("ReadCookie(Cookie: %q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestCookieConfig_NameBound(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ok   bool
	}{{strings.Repeat("a", 64), true}, {strings.Repeat("a", 65), false}} {
		cfg := DefaultCookieConfig()
		cfg.Name = tc.name
		if err := cfg.Validate(); (err == nil) != tc.ok {
			t.Errorf("Validate() of a %d-byte Name = %v, want ok %t", len(tc.name), err, tc.ok)
		}
	}
}
