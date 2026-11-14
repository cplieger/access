package gate

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/cplieger/access/internal/scopetoken"
)

// allowOrder is the methods a Route may have, in the order Allow lists them.
var allowOrder = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// rootPath is the one Path that may hold {$}: any other makes ServeMux
// redirect /foo to /foo/.
const rootPath = "/{$}"

// checkTable returns every reason New refuses cfg, routes and handlers,
// joined, or nil.
func checkTable(cfg *Config, routes []Route, handlers map[string]http.Handler) error {
	var errs []error
	if cfg.Authenticator == nil {
		errs = append(errs, errors.New("gate: New: nil Config.Authenticator"))
	}
	if cfg.Errors == nil {
		errs = append(errs, errors.New("gate: New: nil Config.Errors"))
	}
	names := make(map[string]bool, len(routes))
	patterns := make(map[string]bool, len(routes))
	for i := range routes {
		rt := &routes[i]
		if names[rt.Name] {
			errs = append(errs, fmt.Errorf("gate: New: two routes are named %q", rt.Name))
		}
		names[rt.Name] = true
		if pattern := rt.Method + " " + rt.Path; patterns[pattern] {
			errs = append(errs, fmt.Errorf("gate: New: two routes have %q", pattern))
		} else {
			patterns[pattern] = true
		}
		errs = append(errs, checkRoute(rt)...)
		if handlers[rt.Name] == nil {
			errs = append(errs, fmt.Errorf("gate: New: route %q has no handler", rt.Name))
		}
	}
	var stray []string
	for name := range handlers {
		if !names[name] {
			stray = append(stray, name)
		}
	}
	slices.Sort(stray)
	for _, name := range stray {
		errs = append(errs, fmt.Errorf("gate: New: handler %q has no route", name))
	}
	return errors.Join(errs...)
}

// checkRoute returns every way rt breaks Route's rules.
func checkRoute(rt *Route) []error {
	var errs []error
	bad := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("gate: New: route %q: "+format, append([]any{rt.Name}, args...)...))
	}
	if rt.Name == "" {
		bad("no Name")
	}
	if !slices.Contains(allowOrder, rt.Method) {
		bad("method %q is not GET, POST, PUT, PATCH or DELETE", rt.Method)
	}
	if !validPath(rt.Path) {
		bad("path %q does not start with \"/\", is not clean, ends in \"/\" or holds {$} below the root", rt.Path)
	}
	switch rt.Class {
	case Public, Session:
		if rt.Scope != "" {
			bad("a Public or Session route takes no scope")
		}
	case Scoped:
		if rt.Scope == "" {
			bad("a Scoped route needs a scope")
		}
	case Key:
	default:
		bad("class %d is not Public, Session, Key or Scoped", rt.Class)
	}
	if rt.Scope != "" && !scopetoken.Valid(rt.Scope) {
		bad("scope %q is not one RFC 6750 scope-token", rt.Scope)
	}
	if rt.Passive && rt.Class == Public {
		bad("Passive on a Public route, which authenticates nothing")
	}
	return errs
}

func validPath(p string) bool {
	if p == rootPath {
		return true
	}
	return strings.HasPrefix(p, "/") && !strings.HasSuffix(p, "/") && path.Clean(p) == p && !strings.Contains(p, "{$}")
}

// canonical reports whether ServeMux serves path p as it is, rather than
// redirecting to its cleaned form.
func canonical(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	c := path.Clean(p)
	if c != "/" && strings.HasSuffix(p, "/") {
		c += "/"
	}
	return c == p
}

// crossChecked reports whether rt runs the cross-origin check: an unsafe
// method on a class that admits a session.
func crossChecked(rt *Route) bool {
	return rt.Method != http.MethodGet && (rt.Class == Session || rt.Class == Scoped)
}

// tableMethods is the methods routes use, in allowOrder.
func tableMethods(routes []Route) []string {
	var out []string
	for _, m := range allowOrder {
		if slices.ContainsFunc(routes, func(rt Route) bool { return rt.Method == m }) {
			out = append(out, m)
		}
	}
	return out
}
