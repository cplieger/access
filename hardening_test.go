package access

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- Cookie Posture Tests ---

func TestPosture_SecureNeverEmitsUnprefixedName(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureSecure, Name: "sess"}
	for i := range 100 {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if i%2 == 0 {
			r.Header.Set("X-Forwarded-Proto", "http")
		}
		name := cfg.CookieName(r)
		if name != "__Host-sess" {
			t.Fatalf("PostureSecure emitted unprefixed name: %q", name)
		}
	}
}

func TestPosture_InsecureLANNeverEmitsHostPrefix(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "sess"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	name := cfg.CookieName(r)
	if name != "sess" {
		t.Fatalf("PostureInsecureLAN emitted prefixed name: %q", name)
	}
}

// --- Role Interface Tests ---

func TestRoleInterface_SessionReader(t *testing.T) {
	t.Parallel()
	var _ SessionReader = newFakeSessionStore()
}

func TestRoleInterface_UserReader(t *testing.T) {
	t.Parallel()
	var _ UserReader = newFakeSessionStore()
}

func TestRoleInterface_APIKeyReader(t *testing.T) {
	t.Parallel()
	var _ APIKeyReader = newFakeSessionStore()
}

func TestRoleInterface_AuthenticatorStore(t *testing.T) {
	t.Parallel()
	var _ AuthenticatorStore = newFakeSessionStore()
}
