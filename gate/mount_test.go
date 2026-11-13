package gate_test

import (
	"net/http"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/gate"
)

// TestMount pins what a client sees of a gate mounted on the app's own
// ServeMux on patterns with no method, at a prefix and at an exact path:
// the outer mux cleans a path and adds the prefix's slash with its own 307
// before the gate runs, and every other answer is the gate's.
func TestMount(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	routes := []gate.Route{
		{Name: "items", Method: http.MethodGet, Path: "/api/items", Class: gate.Public},
		{Name: "agent", Method: http.MethodGet, Path: "/api/agent", Class: gate.Key},
		{Name: "metrics", Method: http.MethodGet, Path: "/metrics", Class: gate.Key},
	}
	g := mustGate(t, gate.Config{Authenticator: f.authn}, routes, &served{})
	outer := http.NewServeMux()
	outer.Handle("/api/", g)
	outer.Handle("/metrics", g)
	t.Run("outer_redirects", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct{ target, location string }{
			{"/api//items", "/api/items"},
			{"/api/./items", "/api/items"},
			{"/api/x/../items", "/api/items"},
			{"/api", "/api/"},
		} {
			a := do(t, f, outer, http.MethodGet, tc.target)
			if a.status != http.StatusTemporaryRedirect || a.header.Get("Location") != tc.location {
				t.Errorf("GET %s = %d Location %q, want the outer mux's 307 to %s", tc.target, a.status, a.header.Get("Location"), tc.location)
			}
		}
	})
	t.Run("redirect_targets_reach_the_gate", func(t *testing.T) {
		t.Parallel()
		if a := do(t, f, outer, http.MethodGet, "/api/items"); a.status != http.StatusOK || a.body != "ok:items" {
			t.Errorf("GET /api/items = %d %q, want the row", a.status, a.body)
		}
		if a := do(t, f, outer, http.MethodGet, "/api/"); a.status != http.StatusNotFound || a.code != access.CodeNotFound {
			t.Errorf("GET /api/ = %d %q, want the gate's 404 %s", a.status, a.code, access.CodeNotFound)
		}
	})
	t.Run("exact_mount_method_not_allowed", func(t *testing.T) {
		t.Parallel()
		a := do(t, f, outer, http.MethodPost, "/metrics", keyReadCred)
		if a.status != http.StatusMethodNotAllowed || a.code != access.CodeMethodNotAllowed {
			t.Errorf("POST /metrics = %d %q, want 405 %s through Errors", a.status, a.code, access.CodeMethodNotAllowed)
		}
		if got := a.header.Get("Allow"); got != "GET, HEAD" {
			t.Errorf("POST /metrics Allow = %q, want %q", got, "GET, HEAD")
		}
		if a := do(t, f, outer, http.MethodGet, "/metrics", keyReadCred); a.status != http.StatusOK {
			t.Errorf("GET /metrics with a key = %d %q, want 200", a.status, a.code)
		}
	})
	t.Run("cookie_and_key", func(t *testing.T) {
		t.Parallel()
		// The session verifier runs first, so the principal is the session.
		a := do(t, f, outer, http.MethodGet, "/api/agent", sessionCred, keyReadCred)
		if a.status != http.StatusForbidden || a.code != access.CodeKeyRequired {
			t.Errorf("GET /api/agent with a cookie and a key = %d %q, want 403 %s", a.status, a.code, access.CodeKeyRequired)
		}
	})
}
