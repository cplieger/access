package access

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func FuzzCookieConfigValidate(f *testing.F) {
	f.Add("session", "/", "", uint8(http.SameSiteLaxMode), uint8(PostureSecure))
	f.Add("session", "/app", "example.com", uint8(http.SameSiteStrictMode), uint8(PostureInsecureLAN))
	f.Add("sess", "/", "", uint8(http.SameSiteNoneMode), uint8(PostureInsecureLAN))
	f.Add("sess", "/", "", uint8(http.SameSiteDefaultMode), uint8(PosturePerRequest))
	f.Add("", "", "", uint8(0), uint8(PosturePerRequest))
	f.Add("a\x00b", "/\x1f", "dom\x7f", uint8(0), uint8(PostureInsecureLAN))
	f.Add("spaces here", "/path;bad", "evil;domain", uint8(0), uint8(PostureInsecureLAN))
	f.Add("a/b", "/", "", uint8(0), uint8(PostureInsecureLAN))
	f.Add("sess", "app", "", uint8(0), uint8(PostureInsecureLAN))
	f.Add("sess", "/\"", ".example.com", uint8(0), uint8(PostureInsecureLAN))
	f.Add("日本語クッキー", "/", "", uint8(0), uint8(PostureInsecureLAN))
	f.Add("__Secure-sess", "/", "", uint8(0), uint8(PostureInsecureLAN))
	f.Add("__hOsT-sess", "/", "", uint8(0), uint8(PosturePerRequest))
	f.Add("sess", "/", "", uint8(0), uint8(PosturePerRequest+1))
	f.Add("__HTTP-sess", "/", "", uint8(0), uint8(PostureInsecureLAN))
	f.Add("sess", "/"+strings.Repeat("p", 1024), "", uint8(0), uint8(PostureInsecureLAN))

	f.Fuzz(func(t *testing.T, name, path, domain string, sameSite, posture uint8) {
		cfg := CookieConfig{
			Name:     name,
			Path:     path,
			Domain:   domain,
			SameSite: http.SameSite(sameSite),
			Posture:  CookiePosture(posture),
			HTTPS:    RequestIsHTTPS,
		}
		err := cfg.Validate()
		if cfg.SameSite == http.SameSiteNoneMode && err == nil {
			t.Fatal("Validate() = nil with SameSite=None")
		}
		if err != nil {
			return
		}
		if cfg.Posture.String() == fmt.Sprintf("CookiePosture(%d)", posture) {
			t.Fatalf("Validate() = nil with undeclared Posture %d", posture)
		}
		if l := strings.ToLower(cfg.baseName()); strings.HasPrefix(l, "__secure-") || strings.HasPrefix(l, "__host-") || strings.HasPrefix(l, "__http-") {
			t.Fatalf("Validate() = nil with Name %q, which carries a cookie-name prefix", name)
		}
		if verr := (&http.Cookie{Name: cfg.EffectiveName(), Value: "x", Path: path, Domain: domain}).Valid(); verr != nil {
			t.Fatalf("Validate() = nil but http.Cookie.Valid refuses the cookie: %v", verr)
		}
		if (path != "" && path[0] != '/') || len(path) > maxCookiePath {
			t.Fatalf("Validate() = nil with Path %q, which a browser replaces by its default path", path)
		}
		// A nil error promises http.SetCookie emits the cookie as configured
		// on every scheme, rather than dropping or sanitizing it.
		for _, target := range []string{"http://example.test/", "https://example.test/"} {
			r := httptest.NewRequest(http.MethodGet, target, nil)
			w := httptest.NewRecorder()
			cfg.SetCookie(w, r, "tok", 60)
			lines := w.Header().Values("Set-Cookie")
			if len(lines) != 1 {
				t.Fatalf("Validate() = nil but SetCookie wrote %d Set-Cookie lines on %s", len(lines), target)
			}
			line := lines[0]
			want := []string{"; Path=" + cfg.effectivePath() + ";", "; HttpOnly"}
			if domain != "" {
				want = append(want, "; Domain="+strings.TrimPrefix(domain, "."))
			}
			if !strings.HasPrefix(line, cfg.CookieName(r)+"=tok;") {
				t.Errorf("Set-Cookie %q does not start with %s=tok", line, cfg.CookieName(r))
			}
			for _, attr := range want {
				if !strings.Contains(line, attr) {
					t.Errorf("Set-Cookie %q lacks %q", line, attr)
				}
			}
			if !strings.Contains(line, "; SameSite=Lax") && !strings.Contains(line, "; SameSite=Strict") {
				t.Errorf("Set-Cookie %q carries no SameSite=Lax or Strict", line)
			}
		}
	})
}

func FuzzReadCookie(f *testing.F) {
	f.Add("", "", "", "tok", "tok")
	f.Add("a=1", "b=2", "c=3", "tok", "planted")
	f.Add("__Host-sess=other", "", "", "", "x")
	f.Add("garbage;;;", "=", "\"q\"", "v1", "")

	f.Fuzz(func(t *testing.T, prefix, middle, suffix, first, second string) {
		const name = "__Host-sess"
		for _, v := range []string{first, second} {
			if (&http.Cookie{Name: name, Value: v}).Valid() != nil {
				return
			}
		}
		cfg := CookieConfig{Name: "sess"}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Cookie", prefix+"; "+name+"="+first+"; "+middle+"; "+name+"="+second+"; "+suffix)
		if got := cfg.ReadCookie(r); got != "" {
			t.Fatalf("ReadCookie(%q) = %q with two %s cookies, want \"\"", r.Header.Get("Cookie"), got, name)
		}
	})
}
