package access

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func httpsRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}
	return r
}

func TestCookieConfig_PerRequest_HTTPS_EmitsHostSecure(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session", HTTPS: RequestIsHTTPS}
	r := httpsRequest()
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "tok", 3600)

	resp := w.Result()
	defer resp.Body.Close()
	c := resp.Cookies()[0]
	if c.Name != "__Host-sfx_session" {
		t.Errorf("HTTPS cookie name = %q, want %q", c.Name, "__Host-sfx_session")
	}
	if !c.Secure {
		t.Errorf("HTTPS cookie Secure = %v, want true", c.Secure)
	}
	if got := cfg.CookieName(r); got != "__Host-sfx_session" {
		t.Errorf("HTTPS CookieName() = %q, want %q", got, "__Host-sfx_session")
	}
}

func TestCookieConfig_PerRequest_HTTP_EmitsBareNoSecure(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session", HTTPS: RequestIsHTTPS}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "tok", 3600)

	resp := w.Result()
	defer resp.Body.Close()
	c := resp.Cookies()[0]
	if c.Name != "sfx_session" {
		t.Errorf("HTTP cookie name = %q, want bare %q", c.Name, "sfx_session")
	}
	if c.Secure {
		t.Errorf("HTTP cookie Secure = %v, want false", c.Secure)
	}
	if got := cfg.CookieName(r); got != "sfx_session" {
		t.Errorf("HTTP CookieName() = %q, want %q", got, "sfx_session")
	}
}

func TestUntrustedForwardedProtoUpgrades(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session", HTTPS: RequestIsHTTPS}
	r := httptest.NewRequest(http.MethodGet, "http://media.example.test/", nil)
	r.RemoteAddr = "203.0.113.9:4242"
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "tok", 3600)
	resp := w.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("SetCookie set %d cookies, want 1", len(cookies))
	}
	if c := cookies[0]; c.Name != "__Host-sfx_session" || !c.Secure {
		t.Errorf("cookie = name %q Secure %v, want __Host-sfx_session with Secure", c.Name, c.Secure)
	}
}

func TestSetCookieCoherentHTTPSDecision(t *testing.T) {
	t.Parallel()
	for _, first := range []bool{true, false} {
		t.Run(fmt.Sprintf("first_answer_%v", first), func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			flipping := func(*http.Request) bool { return (calls.Add(1) == 1) == first }
			cfg := CookieConfig{Posture: PosturePerRequest, Name: "sess", HTTPS: flipping}
			w := httptest.NewRecorder()
			cfg.SetCookie(w, httptest.NewRequest(http.MethodGet, "/", nil), "tok", 3600)
			resp := w.Result()
			defer resp.Body.Close()
			set := resp.Cookies()
			if len(set) != 1 {
				t.Fatalf("SetCookie set %d cookies, want 1", len(set))
			}
			if n := calls.Load(); n != 1 {
				t.Errorf("SetCookie asked HTTPS %d times, want 1", n)
			}
			want := "sess"
			if first {
				want = "__Host-sess"
			}
			if set[0].Name != want || set[0].Secure != first {
				t.Errorf("cookie = name %q Secure %v, want %q Secure %v", set[0].Name, set[0].Secure, want, first)
			}
		})
	}
}

func TestPerRequestPostureNames(t *testing.T) {
	t.Parallel()
	session := CookieConfig{Name: "marotte_session", SameSite: http.SameSiteStrictMode, Posture: PosturePerRequest, HTTPS: RequestIsHTTPS}
	configs := []struct {
		cfg      CookieConfig
		base     string
		sameSite http.SameSite
	}{
		{session, "marotte_session", http.SameSiteStrictMode},
		{session.Derive("oidc", http.SameSiteLaxMode), "marotte_session_oidc", http.SameSiteLaxMode},
		{session.Derive("oidc_pending", http.SameSiteLaxMode), "marotte_session_oidc_pending", http.SameSiteLaxMode},
		{session.Derive("device", http.SameSiteLaxMode), "marotte_session_device", http.SameSiteLaxMode},
	}
	hosts := []struct {
		url   string
		https bool
	}{
		{"https://marotte.example.test/", true},
		{"http://localhost/", false},
		{"http://192.0.2.77:9847/", false},
	}
	for _, c := range configs {
		if err := c.cfg.Validate(); err != nil {
			t.Fatalf("Validate(%s) = %v, want nil", c.base, err)
		}
		for _, h := range hosts {
			t.Run(c.base+"_"+h.url, func(t *testing.T) {
				t.Parallel()
				w := httptest.NewRecorder()
				c.cfg.SetCookie(w, httptest.NewRequest(http.MethodGet, h.url, nil), "tok-"+h.url, 3600)
				resp := w.Result()
				defer resp.Body.Close()
				set := resp.Cookies()
				if len(set) != 1 {
					t.Fatalf("SetCookie set %d cookies, want 1", len(set))
				}
				want := c.base
				if h.https {
					want = "__Host-" + c.base
				}
				if set[0].Name != want || set[0].Secure != h.https || set[0].SameSite != c.sameSite {
					t.Errorf("cookie = name %q Secure %v SameSite %v, want %q Secure %v SameSite %v",
						set[0].Name, set[0].Secure, set[0].SameSite, want, h.https, c.sameSite)
				}
				same := httptest.NewRequest(http.MethodGet, h.url, nil)
				same.AddCookie(set[0])
				if got := c.cfg.ReadCookie(same); got != "tok-"+h.url {
					t.Errorf("ReadCookie on the same scheme = %q, want the cookie set there", got)
				}
				for _, other := range hosts {
					if other.https == h.https {
						continue
					}
					cross := httptest.NewRequest(http.MethodGet, other.url, nil)
					cross.AddCookie(set[0])
					if got := c.cfg.ReadCookie(cross); got != "" {
						t.Errorf("ReadCookie on %s read %q, a cookie set on %s", other.url, got, h.url)
					}
				}
			})
		}
	}
}

func TestCookieConfig_PerRequest_ReadCookie_RoundTrip(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session", HTTPS: RequestIsHTTPS}

	t.Run("https writes and reads the __Host- name", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		cfg.SetCookie(w, httpsRequest(), "secure-tok", 3600)
		resp := w.Result()
		defer resp.Body.Close()
		readReq := httpsRequest()
		for _, ck := range resp.Cookies() {
			readReq.AddCookie(ck)
		}
		if got := cfg.ReadCookie(readReq); got != "secure-tok" {
			t.Errorf("HTTPS round-trip ReadCookie() = %q, want %q", got, "secure-tok")
		}
	})
	t.Run("http writes and reads the bare name", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		cfg.SetCookie(w, httptest.NewRequest(http.MethodGet, "/", nil), "lan-tok", 3600)
		resp := w.Result()
		defer resp.Body.Close()
		readReq := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, ck := range resp.Cookies() {
			readReq.AddCookie(ck)
		}
		if got := cfg.ReadCookie(readReq); got != "lan-tok" {
			t.Errorf("HTTP round-trip ReadCookie() = %q, want %q", got, "lan-tok")
		}
	})
}

// TestCookieConfig_PerRequest_DefaultPostureUnchanged confirms that adding
// PosturePerRequest leaves the default PostureSecure behavior bit-for-bit
// identical: stable __Host- name and Secure=true regardless of request scheme.
func TestCookieConfig_PerRequest_DefaultPostureUnchanged(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig() // PostureSecure
	httpReq := httptest.NewRequest(http.MethodGet, "/", nil)
	httpsReq := httpsRequest()

	if got := cfg.CookieName(httpReq); got != "__Host-auth_session" {
		t.Errorf("default posture CookieName(HTTP) = %q, want %q", got, "__Host-auth_session")
	}
	if got := cfg.CookieName(httpsReq); got != "__Host-auth_session" {
		t.Errorf("default posture CookieName(HTTPS) = %q, want %q", got, "__Host-auth_session")
	}

	for _, r := range []*http.Request{httpReq, httpsReq} {
		w := httptest.NewRecorder()
		cfg.SetCookie(w, r, "v", 100)
		resp := w.Result()
		c := resp.Cookies()[0]
		resp.Body.Close()
		if c.Name != "__Host-auth_session" || !c.Secure {
			t.Errorf("default posture SetCookie emitted name=%q secure=%v, want __Host-auth_session with Secure", c.Name, c.Secure)
		}
	}
}
