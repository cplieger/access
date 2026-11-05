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

func TestCookieConfig_Defaults(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	if cfg.Name != "auth_session" {
		t.Errorf("default Name = %q, want %q", cfg.Name, "auth_session")
	}
	if cfg.Posture != PostureSecure {
		t.Errorf("default Posture = %d, want PostureSecure", cfg.Posture)
	}
	if cfg.Path != "/" {
		t.Errorf("default Path = %q, want %q", cfg.Path, "/")
	}
	if cfg.SameSite != http.SameSiteLaxMode {
		t.Errorf("default SameSite = %d, want Lax", cfg.SameSite)
	}
}

func TestCookieConfig_EffectiveName_Secure(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	if got := cfg.EffectiveName(); got != "__Host-auth_session" {
		t.Fatalf("expected __Host-auth_session, got %s", got)
	}
}

func TestCookieConfig_EffectiveName_InsecureLAN(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "auth_session"}
	if got := cfg.EffectiveName(); got != "auth_session" {
		t.Fatalf("expected auth_session, got %s", got)
	}
}

func TestCookieConfig_CustomName(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureSecure, Name: "my_sess"}
	if got := cfg.EffectiveName(); got != "__Host-my_sess" {
		t.Fatalf("expected __Host-my_sess, got %s", got)
	}
}

func TestCookieConfig_SetAndRead(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "test_sess"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "tok123", 3600)

	resp := w.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Name != "test_sess" {
		t.Errorf("cookie name = %q, want %q", cookies[0].Name, "test_sess")
	}
	if cookies[0].Value != "tok123" {
		t.Errorf("cookie value = %q, want %q", cookies[0].Value, "tok123")
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])
	if got := cfg.ReadCookie(r2); got != "tok123" {
		t.Errorf("ReadCookie() = %q, want %q", got, "tok123")
	}
}

func TestCookieConfig_CustomSameSiteAndPath(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{
		Posture:  PostureInsecureLAN,
		Name:     "s",
		Path:     "/app",
		SameSite: http.SameSiteStrictMode,
	}
	r := httptest.NewRequest(http.MethodGet, "/app", nil)
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "v", 100)
	resp := w.Result()
	defer resp.Body.Close()
	c := resp.Cookies()[0]
	if c.Path != "/app" {
		t.Errorf("cookie Path = %q, want %q", c.Path, "/app")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %d, want Strict", c.SameSite)
	}
}

func TestCookieConfig_SecurePosture(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureSecure, Name: "s"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "v", 100)
	resp := w.Result()
	defer resp.Body.Close()
	if !resp.Cookies()[0].Secure {
		t.Fatal("expected Secure=true for PostureSecure regardless of request scheme")
	}
}

func TestCookieConfig_InsecureLAN_NoSecure(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "v", 100)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.Cookies()[0].Secure {
		t.Fatal("expected Secure=false for PostureInsecureLAN")
	}
}

func TestCookieConfig_ClearCookie(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	cfg.ClearCookie(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	c := resp.Cookies()[0]
	if c.MaxAge != -1 {
		t.Fatalf("expected MaxAge=-1, got %d", c.MaxAge)
	}
}

func TestCookieConfig_CacheControl(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "tok", 3600)
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %q", got)
	}
}

func TestCookieConfig_StableNamePerPosture(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-Forwarded-Proto", "https")
	if cfg.CookieName(r1) != cfg.CookieName(r2) {
		t.Fatal("cookie name should be stable regardless of request")
	}
}

// TestCookieConfig_Secure_ReadCookie_ignoresUnprefixedCookie pins the
// session-fixation defense: under a __Host- posture, a bare (unprefixed) cookie
// an attacker can set over plain HTTP must not be read as the session token.
func TestCookieConfig_Secure_ReadCookie_ignoresUnprefixedCookie(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureSecure, Name: "sess"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sess", Value: "attacker-token"})
	if got := cfg.ReadCookie(r); got != "" {
		t.Fatalf("ReadCookie read an unprefixed cookie %q under PostureSecure, want \"\" (session fixation)", got)
	}
}

// TestCookieConfig_SetCookie_alwaysHttpOnly confirms the session cookie is
// HttpOnly under every posture, including the insecure-LAN posture that drops
// the Secure flag.
func TestCookieConfig_SetCookie_alwaysHttpOnly(t *testing.T) {
	t.Parallel()
	for _, posture := range []CookiePosture{PostureSecure, PostureInsecureLAN, PosturePerRequest} {
		t.Run(fmt.Sprintf("posture_%d", posture), func(t *testing.T) {
			t.Parallel()
			cfg := CookieConfig{Posture: posture, Name: "s", HTTPS: RequestIsHTTPS}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			cfg.SetCookie(w, r, "tok", 3600)
			resp := w.Result()
			defer resp.Body.Close()
			if c := resp.Cookies()[0]; !c.HttpOnly {
				t.Errorf("posture %d: cookie HttpOnly = false, want true", posture)
			}
		})
	}
}

func TestCookiePosture_String(t *testing.T) {
	t.Parallel()
	cases := []struct {
		posture CookiePosture
		want    string
	}{
		{PostureSecure, "PostureSecure"},
		{PostureInsecureLAN, "PostureInsecureLAN"},
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

func TestRequestIsHTTPS(t *testing.T) {
	t.Parallel()
	t.Run("tls", func(t *testing.T) {
		t.Parallel()
		if !RequestIsHTTPS(httpsRequest()) {
			t.Error("RequestIsHTTPS(TLS request) = false, want true")
		}
	})
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"https", "https", true},
		{"upper_case", "HTTPS", true},
		{"mixed_case", "Https", true},
		{"surrounding_space", " https ", true},
		{"first_token_https", "HTTPS,http", true},
		{"first_token_https_with_space", "https, http", true},
		{"http", "http", false},
		{"first_token_http", "http,https", false},
		{"empty", "", false},
		{"https_prefix_only", "httpsx", false},
		{"wss", "wss", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			r.RemoteAddr = "203.0.113.9:4242"
			if tc.value != "" {
				r.Header.Set("X-Forwarded-Proto", tc.value)
			}
			if got := RequestIsHTTPS(r); got != tc.want {
				t.Errorf("RequestIsHTTPS(X-Forwarded-Proto=%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
	t.Run("first_header_line", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		r.Header.Add("X-Forwarded-Proto", "http")
		r.Header.Add("X-Forwarded-Proto", "https")
		if RequestIsHTTPS(r) {
			t.Error("RequestIsHTTPS read a later X-Forwarded-Proto line, want the first token of the first")
		}
	})
}

func setCookieLine(t *testing.T, cfg CookieConfig, r *http.Request, maxAge int) string {
	t.Helper()
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "tok", maxAge)
	lines := w.Header().Values("Set-Cookie")
	if len(lines) != 1 {
		t.Fatalf("SetCookie wrote %d Set-Cookie lines, want 1: %q", len(lines), lines)
	}
	return lines[0]
}

func TestPersistentCookie(t *testing.T) {
	t.Parallel()
	never := func(*http.Request) bool { return false }
	always := func(*http.Request) bool { return true }
	plain := func() *http.Request { return httptest.NewRequest(http.MethodGet, "http://192.0.2.77:9847/", nil) }

	t.Run("not_persistent_drops_max_age", func(t *testing.T) {
		t.Parallel()
		line := setCookieLine(t, CookieConfig{Posture: PostureInsecureLAN, Name: "s", Persistent: never}, plain(), 3600)
		if strings.Contains(line, "Max-Age") || strings.Contains(line, "Expires") {
			t.Errorf("Set-Cookie = %q, want neither Max-Age nor Expires", line)
		}
	})
	t.Run("not_persistent_clear_sends_max_age_zero", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s", Persistent: never}
		cfg.ClearCookie(w, plain())
		if line := w.Header().Get("Set-Cookie"); !strings.Contains(line, "Max-Age=0") {
			t.Errorf("clear Set-Cookie = %q, want Max-Age=0", line)
		}
	})
	t.Run("nil_keeps_max_age", func(t *testing.T) {
		t.Parallel()
		line := setCookieLine(t, CookieConfig{Posture: PostureInsecureLAN, Name: "s"}, plain(), 3600)
		if !strings.Contains(line, "Max-Age=3600") {
			t.Errorf("Set-Cookie = %q, want Max-Age=3600", line)
		}
	})
	t.Run("persistent_keeps_max_age", func(t *testing.T) {
		t.Parallel()
		line := setCookieLine(t, CookieConfig{Posture: PostureInsecureLAN, Name: "s", Persistent: always}, plain(), 3600)
		if !strings.Contains(line, "Max-Age=3600") {
			t.Errorf("Set-Cookie = %q, want Max-Age=3600", line)
		}
	})
	t.Run("per_request", func(t *testing.T) {
		t.Parallel()
		cfg := CookieConfig{Posture: PosturePerRequest, Name: "s", HTTPS: RequestIsHTTPS, Persistent: RequestIsHTTPS}
		if line := setCookieLine(t, cfg, httptest.NewRequest(http.MethodGet, "https://example.test/", nil), 3600); !strings.Contains(line, "Max-Age=3600") {
			t.Errorf("HTTPS Set-Cookie = %q, want Max-Age=3600", line)
		}
		if line := setCookieLine(t, cfg, plain(), 3600); strings.Contains(line, "Max-Age") {
			t.Errorf("plain Set-Cookie = %q, want no Max-Age", line)
		}
	})
}

func TestDeriveSuffix(t *testing.T) {
	t.Parallel()
	marked := func(r *http.Request) bool { return r.Header.Get("X-Test-HTTPS") == "1" }
	base := CookieConfig{
		Name:       "sess",
		Path:       "/",
		SameSite:   http.SameSiteStrictMode,
		Posture:    PosturePerRequest,
		HTTPS:      marked,
		Persistent: func(*http.Request) bool { return false },
	}
	for _, suffix := range []string{"oidc", "oidc_pending", "device", "_", strings.Repeat("z", 16)} {
		t.Run("valid_"+suffix, func(t *testing.T) {
			t.Parallel()
			d := base.Derive(suffix, http.SameSiteLaxMode)
			if want := "sess_" + suffix; d.Name != want {
				t.Errorf("Derive(%q).Name = %q, want %q", suffix, d.Name, want)
			}
			if d.EffectiveName() == base.EffectiveName() {
				t.Errorf("Derive(%q) name %q equals the base name", suffix, d.EffectiveName())
			}
			if d.Posture != base.Posture || d.Path != base.Path || d.Domain != base.Domain {
				t.Errorf("Derive(%q) = Posture %v Path %q Domain %q, want the base's", suffix, d.Posture, d.Path, d.Domain)
			}
			if d.SameSite != http.SameSiteLaxMode {
				t.Errorf("Derive(%q).SameSite = %v, want Lax", suffix, d.SameSite)
			}
			if d.Persistent != nil {
				t.Errorf("Derive(%q).Persistent is set, want nil", suffix)
			}
			marker := httptest.NewRequest(http.MethodGet, "/", nil)
			marker.Header.Set("X-Test-HTTPS", "1")
			if d.HTTPS == nil || !d.HTTPS(marker) || d.HTTPS(httptest.NewRequest(http.MethodGet, "/", nil)) {
				t.Errorf("Derive(%q).HTTPS is not the base's predicate", suffix)
			}
		})
	}
	t.Run("unset_samesite", func(t *testing.T) {
		t.Parallel()
		d := base.Derive("device", 0)
		if got := d.effectiveSameSite(); got != http.SameSiteLaxMode {
			t.Errorf("Derive(device, unset).effectiveSameSite() = %v, want Lax", got)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		d.SetCookie(w, r, "tok", 60)
		if line := w.Header().Get("Set-Cookie"); !strings.Contains(line, "; SameSite=Lax") {
			t.Errorf("Derive(device, unset) Set-Cookie %q lacks SameSite=Lax", line)
		}
	})
	t.Run("unset_base_name", func(t *testing.T) {
		t.Parallel()
		d := CookieConfig{}.Derive("device", http.SameSiteLaxMode)
		if got := d.EffectiveName(); got != "__Host-auth_session_device" {
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
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
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
			if got := cfg.ReadCookie(r); got != tc.want {
				t.Errorf("ReadCookie(Cookie: %q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestCookieConfig_PerRequest_nilHTTPSPanics(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PosturePerRequest, Name: "s"}
	defer func() {
		if recover() == nil {
			t.Error("CookieName under PosturePerRequest with a nil HTTPS did not panic")
		}
	}()
	cfg.CookieName(httpsRequest())
}
