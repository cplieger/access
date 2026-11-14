package access

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPerRequestPostureNames pins that under PosturePerRequest the session
// cookie and each companion is read back on its own transport only: the
// cookie set for one transport is never read for the other.
func TestPerRequestPostureNames(t *testing.T) {
	t.Parallel()
	session := CookieConfig{Name: "marotte_session", SameSite: http.SameSiteStrictMode, Posture: PosturePerRequest}
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
	for _, c := range configs {
		if err := c.cfg.Validate(); err != nil {
			t.Fatalf("Validate(%s) = %v, want nil", c.base, err)
		}
		for _, secure := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s_secure_%t", c.base, secure), func(t *testing.T) {
				t.Parallel()
				w := httptest.NewRecorder()
				c.cfg.SetCookie(w, secure, "tok", 3600)
				resp := w.Result()
				defer resp.Body.Close()
				set := resp.Cookies()
				if len(set) != 1 {
					t.Fatalf("SetCookie set %d cookies, want 1", len(set))
				}
				want := c.base
				if secure {
					want = "__Host-" + c.base
				}
				if set[0].Name != want || set[0].Secure != secure || set[0].SameSite != c.sameSite {
					t.Errorf("cookie = name %q Secure %v SameSite %v, want %q Secure %v SameSite %v",
						set[0].Name, set[0].Secure, set[0].SameSite, want, secure, c.sameSite)
				}
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.AddCookie(set[0])
				if got := c.cfg.ReadCookie(r, secure); got != "tok" {
					t.Errorf("ReadCookie(%t) = %q, want the cookie set for that transport", secure, got)
				}
				if got := c.cfg.ReadCookie(r, !secure); got != "" {
					t.Errorf("ReadCookie(%t) read %q, a cookie set for the other transport", !secure, got)
				}
			})
		}
	}
}
