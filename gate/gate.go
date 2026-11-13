// Package gate guards an app's own routes with an [access.Authenticator]:
// one table of rows, each with its class, and one handler per row. It
// answers every refusal through the app's [access.ErrorWriter] with the
// codes and challenge the auth tree uses, and imports nothing of the
// sign-in packages.
package gate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/crossorigin"
	"github.com/cplieger/access/internal/refusal"
)

// Class is what a row admits.
type Class int

// The classes.
const (
	Public  Class = iota + 1 // nothing is read: no principal, no refusal
	Session                  // a full session only
	Key                      // an API key only; with a Scope, Allow decides it too
	Scoped                   // Allow decides, for every principal
)

// Route is one row of the app's endpoint table.
type Route struct {
	Name    string // unique; the app's name for the route
	Method  string // GET, POST, PUT, PATCH or DELETE; a GET row also answers HEAD
	Path    string // a ServeMux path: starts with "/", clean, no host, no trailing "/"; the root alone is "/{$}"
	Scope   string // required on Scoped, optional on Key, refused on Public and Session; one RFC 6750 scope-token
	Class   Class
	Passive bool // authenticate under access.Passive; refused on Public
}

// Config configures a [Gate].
type Config struct {
	Authenticator *access.Authenticator // required; supplies the realm
	Errors        access.ErrorWriter    // required; the same writer as the auth tree
	// Allow decides a Scoped row, and a Key row with a Scope. Nil is
	// p.IsSession() || (p.IsAPIKey() && p.HasScope(scope)).
	Allow func(p access.Principal, scope string) bool
	// Logger receives the gate's log lines; nil is slog.Default() at each
	// call.
	Logger *slog.Logger
}

// Gate serves exactly the rows it was built with. Build it with [New].
type Gate struct {
	cfg Config
	mux *http.ServeMux
	// methods are the table's methods in [allowOrder], for the 405 probe.
	methods []string
}

// row is the handler the gate registers for one Route. ServeHTTP serves
// only a *row ServeMux returns: any other handler is ServeMux's own
// redirect, 404 or 405.
type row struct {
	g     *Gate
	next  http.Handler
	serve http.Handler // next behind the row's cross-origin check and class
	route Route
}

func (rw *row) ServeHTTP(w http.ResponseWriter, r *http.Request) { rw.serve.ServeHTTP(w, r) }

// The gate's own refusals, for the app's log.
var (
	errNotFound         = errors.New("gate: no route matches")
	errMethodNotAllowed = errors.New("gate: method not allowed")
	errCrossOrigin      = errors.New("gate: cross-origin request refused")
	errClass            = errors.New("gate: the route's class refuses this principal")
)

// New builds the gate over the app's endpoint table and one handler per
// row, by Name. It returns an error, never panics, for: a nil
// Authenticator or Errors; a duplicate Name; a Method or Path outside
// Route's rules; two rows with one method and path; paths net/http.ServeMux
// would refuse to register together; a Scope on the wrong class or outside
// the scope-token charset; Passive on Public; a row with no handler; and a
// handler with no row.
func New(cfg Config, routes []Route, handlers map[string]http.Handler) (*Gate, error) {
	if err := checkTable(&cfg, routes, handlers); err != nil {
		return nil, err
	}
	if cfg.Allow == nil {
		cfg.Allow = defaultAllow
	}
	g := &Gate{cfg: cfg, mux: http.NewServeMux(), methods: tableMethods(routes)}
	for i := range routes {
		if err := register(g.mux, g.row(&routes[i], handlers[routes[i].Name])); err != nil {
			return nil, err
		}
	}
	return g, nil
}

func defaultAllow(p access.Principal, scope string) bool { //nolint:gocritic // hugeParam: Config.Allow's signature
	return p.IsSession() || (p.IsAPIKey() && p.HasScope(scope))
}

func (g *Gate) row(rt *Route, next http.Handler) *row {
	rw := &row{g: g, route: *rt, next: next, serve: next}
	if rt.Class != Public {
		rw.serve = http.HandlerFunc(rw.admit)
	}
	if crossChecked(rt) {
		rw.serve = crossorigin.Guard(rw.serve, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.refuse(w, r, "", access.NewError(access.CodeCrossOrigin, "", errCrossOrigin))
		}))
	}
	return rw
}

// register adds rw to mux, returning the panic ServeMux raises for a
// pattern it cannot parse or that conflicts with one already registered.
func register(mux *http.ServeMux, rw *row) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("gate: New: route %q: %v", rw.route.Name, v)
		}
	}()
	mux.Handle(rw.route.Method+" "+rw.route.Path, rw)
	return nil
}

// ServeHTTP serves r on the row its method and path match, and answers
// every other request through Config.Errors: 404 auth_not_found for a path
// that is not canonical or that no row has, and 405 auth_method_not_allowed
// with Allow for a path whose rows want another method.
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ServeMux would answer a path it cleans with a redirect.
	if !canonical(r.URL.EscapedPath()) {
		g.refuse(w, r, "", access.NewError(access.CodeNotFound, "", errNotFound))
		return
	}
	if h, _ := g.mux.Handler(r); isRow(h) {
		g.mux.ServeHTTP(w, r)
		return
	}
	if allow := g.allowed(r); allow != "" {
		w.Header().Set("Allow", allow)
		g.refuse(w, r, "", access.NewError(access.CodeMethodNotAllowed, "", errMethodNotAllowed))
		return
	}
	g.refuse(w, r, "", access.NewError(access.CodeNotFound, "", errNotFound))
}

func isRow(h http.Handler) bool {
	_, ok := h.(*row)
	return ok
}

// allowed is the Allow value for r's path: each table method a row serves
// it with, and HEAD beside GET; empty when no row has the path.
func (g *Gate) allowed(r *http.Request) string {
	var allow []string
	for _, m := range g.methods {
		probe := r.Clone(r.Context())
		probe.Method = m
		if h, _ := g.mux.Handler(probe); isRow(h) {
			allow = append(allow, m)
			if m == http.MethodGet {
				allow = append(allow, http.MethodHead)
			}
		}
	}
	return strings.Join(allow, ", ")
}

// admit authenticates r for an authenticating row and serves it when the
// row's class admits the principal.
func (rw *row) admit(w http.ResponseWriter, r *http.Request) {
	g, rt := rw.g, &rw.route
	if rt.Passive {
		r = r.WithContext(access.Passive(r.Context()))
	}
	p, err := g.cfg.Authenticator.Authenticate(r)
	if err != nil {
		g.unauthenticated(w, r, rt, err)
		return
	}
	if code := g.decide(rt, p); code != "" {
		g.refuse(w, r, rt.Scope, access.NewError(code, "", errClass))
		return
	}
	rw.next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
}

// decide is the class table: the code that refuses p on rt, or "" to admit.
func (g *Gate) decide(rt *Route, p access.Principal) access.Code { //nolint:gocritic // hugeParam: the Principal Authenticate returned
	switch rt.Class {
	case Session:
		if !p.IsSession() {
			return access.CodeSessionRequired
		}
	case Key:
		if !p.IsAPIKey() {
			return access.CodeKeyRequired
		}
		if rt.Scope != "" && !g.cfg.Allow(p, rt.Scope) {
			return access.CodeScopeRequired
		}
	case Scoped:
		switch {
		case g.cfg.Allow(p, rt.Scope):
		case p.IsAPIKey():
			return access.CodeScopeRequired
		default:
			return access.CodeForbidden
		}
	default:
	}
	return ""
}

// unauthenticated answers an Authenticate error. An error ErrorFor does not
// map is the verifier's own and answers 503; only r.Context().Err() tells
// a client walking away from a real failure.
func (g *Gate) unauthenticated(w http.ResponseWriter, r *http.Request, rt *Route, err error) {
	e, mapped := access.ErrorFor(err)
	ctx := r.Context()
	switch ctxErr := ctx.Err(); {
	case ctxErr != nil && errors.Is(err, ctxErr):
		g.log().DebugContext(ctx, "gate: request ended", "route", rt.Name, "err", err.Error())
	case !mapped:
		g.log().ErrorContext(ctx, "gate: verifier error access does not map", "route", rt.Name, "err", err.Error())
	case e.Code == access.CodeUnavailable:
		g.log().WarnContext(ctx, "gate: authentication unavailable", "route", rt.Name, "err", err.Error())
	default:
	}
	if !mapped {
		e = access.NewError(access.CodeUnavailable, "", err)
	}
	g.refuse(w, r, rt.Scope, e)
}

// refuse answers e through Config.Errors; refusal.Write owns the headers
// set before it.
func (g *Gate) refuse(w http.ResponseWriter, r *http.Request, scope string, e access.Error) { //nolint:gocritic // hugeParam: the ErrorWriter takes the Error by value
	refusal.Write(w, r, g.cfg.Authenticator, g.cfg.Errors, e, scope)
}

func (g *Gate) log() *slog.Logger {
	if g.cfg.Logger != nil {
		return g.cfg.Logger
	}
	return slog.Default()
}

type principalKey struct{}

// Principal is the principal the gate admitted r's route for; false on a
// Public route.
func Principal(ctx context.Context) (access.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(access.Principal)
	return p, ok
}
