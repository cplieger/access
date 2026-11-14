package gate_test

import (
	"net/http"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/gate"
)

// TestMatching holds the gate to ServeMux's precedence over its own rows,
// and to its own answers where ServeMux would redirect or write text.
func TestMatching(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	routes := []gate.Route{
		{Name: "root", Method: http.MethodGet, Path: "/{$}", Class: gate.Public},
		{Name: "file", Method: http.MethodGet, Path: "/files/{name}", Class: gate.Public},
		{Name: "upload_get", Method: http.MethodGet, Path: "/files/upload", Class: gate.Public},
		{Name: "upload_post", Method: http.MethodPost, Path: "/files/upload", Class: gate.Public},
		{Name: "tree", Method: http.MethodGet, Path: "/tree/{rest...}", Class: gate.Public},
		{Name: "submit", Method: http.MethodPost, Path: "/submit", Class: gate.Public},
	}
	hs := map[string]http.Handler{}
	for _, r := range routes {
		hs[r.Name] = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write([]byte(r.Name + "|" + req.PathValue("name") + req.PathValue("rest")))
		})
	}
	g, err := gate.New(gate.Config{Authenticator: f.authn, Errors: writeError}, routes, hs)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("served", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct{ method, target, body string }{
			{http.MethodGet, "/", "root|"},
			// The precedence case: the literal row wins over the wildcard
			// for GET, and POST has its own row.
			{http.MethodGet, "/files/upload", "upload_get|"},
			{http.MethodGet, "/files/a.txt", "file|a.txt"},
			{http.MethodPost, "/files/upload", "upload_post|"},
			// A GET row answers HEAD; the server, not the gate, drops the body.
			{http.MethodHead, "/files/upload", "upload_get|"},
			{http.MethodGet, "/tree/", "tree|"},
			{http.MethodGet, "/tree/a/b", "tree|a/b"},
		} {
			a := do(t, f, g, tc.method, tc.target)
			if a.status != http.StatusOK || a.body != tc.body {
				t.Errorf("%s %s = %d %q, want 200 %q", tc.method, tc.target, a.status, a.body, tc.body)
			}
		}
	})
	t.Run("method_not_allowed", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct{ method, target, allow string }{
			{http.MethodDelete, "/files/upload", "GET, HEAD, POST"},
			{http.MethodPost, "/files/a.txt", "GET, HEAD"},
			{http.MethodHead, "/submit", "POST"},
			{http.MethodOptions, "/submit", "POST"},
			{http.MethodPost, "/", "GET, HEAD"},
		} {
			a := do(t, f, g, tc.method, tc.target)
			if a.status != http.StatusMethodNotAllowed || a.code != access.CodeMethodNotAllowed {
				t.Errorf("%s %s = %d %q, want 405 %s", tc.method, tc.target, a.status, a.code, access.CodeMethodNotAllowed)
			}
			if got := a.header.Get("Allow"); got != tc.allow {
				t.Errorf("%s %s Allow = %q, want %q", tc.method, tc.target, got, tc.allow)
			}
			if got := a.header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("%s %s Cache-Control = %q, want no-store", tc.method, tc.target, got)
			}
		}
	})
	// ServeMux would redirect each of these (a non-canonical path, and /tree
	// to /tree/ for a {rest...} row); the gate answers 404 itself.
	t.Run("not_found", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct{ method, target string }{
			{http.MethodGet, "/nothing"},
			{http.MethodGet, "/files"},
			{http.MethodGet, "/files/a/b"},
			{http.MethodGet, "//files/upload"},
			{http.MethodGet, "/files/./upload"},
			{http.MethodGet, "/files/x/../upload"},
			{http.MethodPost, "//submit"},
			{http.MethodGet, "/tree"},
			{http.MethodGet, "/nothing/"},
		} {
			a := do(t, f, g, tc.method, tc.target)
			if a.status != http.StatusNotFound || a.code != access.CodeNotFound {
				t.Errorf("%s %s = %d %q, want 404 %s", tc.method, tc.target, a.status, a.code, access.CodeNotFound)
			}
			if loc := a.header.Get("Location"); loc != "" {
				t.Errorf("%s %s Location = %q, want none", tc.method, tc.target, loc)
			}
			if got := a.header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("%s %s Cache-Control = %q, want no-store", tc.method, tc.target, got)
			}
		}
	})
}
