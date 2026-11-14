package gate_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/cplieger/access/gate"
)

// TestNewRefuses: every table New must refuse comes back as an error naming
// the problem, never a panic and never a gate.
func TestNewRefuses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ok := gate.Route{Name: "ok", Method: http.MethodGet, Path: "/ok", Class: gate.Session}
	row := func(r gate.Route) []gate.Route { return []gate.Route{ok, r} }
	for _, tc := range []struct {
		cfg      *gate.Config
		handlers func(routes []gate.Route) map[string]http.Handler
		name     string
		want     string
		routes   []gate.Route
	}{
		{name: "nil_authenticator", cfg: &gate.Config{Errors: writeError}, routes: []gate.Route{ok}, want: "Authenticator"},
		{name: "nil_errors", cfg: &gate.Config{Authenticator: f.authn}, routes: []gate.Route{ok}, want: "Errors"},
		{name: "duplicate_name", routes: row(gate.Route{Name: "ok", Method: http.MethodPost, Path: "/ok", Class: gate.Session}), want: `"ok"`},
		{name: "empty_name", routes: row(gate.Route{Method: http.MethodGet, Path: "/x", Class: gate.Session}), want: "Name"},
		{name: "method_head", routes: row(gate.Route{Name: "x", Method: http.MethodHead, Path: "/x", Class: gate.Session}), want: "method"},
		{name: "method_options", routes: row(gate.Route{Name: "x", Method: http.MethodOptions, Path: "/x", Class: gate.Session}), want: "method"},
		{name: "method_lower_case", routes: row(gate.Route{Name: "x", Method: "get", Path: "/x", Class: gate.Session}), want: "method"},
		{name: "method_empty", routes: row(gate.Route{Name: "x", Path: "/x", Class: gate.Session}), want: "method"},
		{name: "path_empty", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Class: gate.Session}), want: "path"},
		{name: "path_relative", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "x", Class: gate.Session}), want: "path"},
		{name: "path_with_host", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "example.com/x", Class: gate.Session}), want: "path"},
		{name: "path_trailing_slash", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x/", Class: gate.Session}), want: "path"},
		{name: "path_bare_root", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/", Class: gate.Session}), want: "path"},
		{name: "path_end_anchor_below_root", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x/{$}", Class: gate.Session}), want: "path"},
		{name: "path_not_clean_dot", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/a/./b", Class: gate.Session}), want: "path"},
		{name: "path_not_clean_double_slash", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/a//b", Class: gate.Session}), want: "path"},
		{name: "path_not_clean_dot_dot", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/a/../b", Class: gate.Session}), want: "path"},
		{name: "path_bad_wildcard", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/a/{b", Class: gate.Session}), want: "/a/{b"},
		{name: "same_method_and_path", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/ok", Class: gate.Session}), want: "GET /ok"},
		// The two patterns both match /a/a and neither is more specific, so
		// ServeMux refuses to register them together.
		{name: "servemux_conflict", routes: []gate.Route{
			{Name: "x", Method: http.MethodGet, Path: "/a/{x}", Class: gate.Session},
			{Name: "y", Method: http.MethodGet, Path: "/{y}/a", Class: gate.Session},
		}, want: "conflict"},
		{name: "class_zero", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x"}), want: "class"},
		{name: "class_unknown", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x", Class: gate.Scoped + 1}), want: "class"},
		{name: "scope_on_public", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x", Class: gate.Public, Scope: "read"}), want: "scope"},
		{name: "scope_on_session", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x", Class: gate.Session, Scope: "read"}), want: "scope"},
		{name: "scope_missing_on_scoped", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x", Class: gate.Scoped}), want: "scope"},
		// RFC 6750 §3: a scope-token is 1*( %x21 / %x23-5B / %x5D-7E ).
		{name: "scope_space", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x", Class: gate.Scoped, Scope: "a b"}), want: "scope"},
		{name: "scope_dquote", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x", Class: gate.Key, Scope: `a"b`}), want: "scope"},
		{name: "scope_backslash", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x", Class: gate.Key, Scope: `a\b`}), want: "scope"},
		{name: "scope_non_ascii", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x", Class: gate.Key, Scope: "café"}), want: "scope"},
		{name: "passive_on_public", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x", Class: gate.Public, Passive: true}), want: "Passive"},
		{
			name: "row_with_no_handler", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x", Class: gate.Session}), want: `"x"`,
			handlers: func([]gate.Route) map[string]http.Handler {
				return map[string]http.Handler{"ok": http.NotFoundHandler()}
			},
		},
		{
			name: "row_with_nil_handler", routes: row(gate.Route{Name: "x", Method: http.MethodGet, Path: "/x", Class: gate.Session}), want: `"x"`,
			handlers: func([]gate.Route) map[string]http.Handler {
				return map[string]http.Handler{"ok": http.NotFoundHandler(), "x": nil}
			},
		},
		{
			name: "handler_with_no_row", routes: []gate.Route{ok}, want: `"stray"`,
			handlers: func([]gate.Route) map[string]http.Handler {
				return map[string]http.Handler{"ok": http.NotFoundHandler(), "stray": http.NotFoundHandler()}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := gate.Config{Authenticator: f.authn, Errors: writeError}
			if tc.cfg != nil {
				cfg = *tc.cfg
			}
			hs := handlersFor(&served{}, tc.routes)
			if tc.handlers != nil {
				hs = tc.handlers(tc.routes)
			}
			g, err := gate.New(cfg, tc.routes, hs)
			if err == nil || g != nil {
				t.Fatalf("New = (%v, %v), want no gate and an error", g, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("New error %q does not name %q", err, tc.want)
			}
		})
	}
}

// TestNewAccepts: the shapes Route's rules allow build a gate.
func TestNewAccepts(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	routes := []gate.Route{
		{Name: "root", Method: http.MethodGet, Path: "/{$}", Class: gate.Public},
		{Name: "file", Method: http.MethodGet, Path: "/files/{name}", Class: gate.Session, Passive: true},
		{Name: "upload", Method: http.MethodGet, Path: "/files/upload", Class: gate.Session},
		{Name: "tree", Method: http.MethodGet, Path: "/tree/{rest...}", Class: gate.Key},
		{Name: "put", Method: http.MethodPut, Path: "/files/{name}", Class: gate.Key, Scope: "write"},
		{Name: "patch", Method: http.MethodPatch, Path: "/files/{name}", Class: gate.Scoped, Scope: "write:files"},
		{Name: "delete", Method: http.MethodDelete, Path: "/files/{name}", Class: gate.Scoped, Scope: "admin"},
		{Name: "post", Method: http.MethodPost, Path: "/files/upload", Class: gate.Session},
	}
	if _, err := gate.New(gate.Config{Authenticator: f.authn, Errors: writeError}, routes, handlersFor(&served{}, routes)); err != nil {
		t.Errorf("New: %v", err)
	}
}
