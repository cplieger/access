package accesshttp

import (
	"errors"
	"net/http"
	"reflect"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/crossorigin"
	"github.com/cplieger/access/internal/refusal"
)

// The transport's own refusals.
var (
	errMethodNotAllowed = errors.New("accesshttp: method not allowed")
	errCrossOrigin      = errors.New("accesshttp: cross-origin request refused")
)

// serveFunc is one route's handler, run after the guard, the path value
// and the query decode; it writes its success and returns its refusal.
type serveFunc func(h *Handler, c *call) error

// call is one request on one route.
type call struct {
	w         http.ResponseWriter
	r         *http.Request
	spec      *routeSpec
	desc      *Descriptor
	query     reflect.Value // the decoded Query struct; invalid when the route has none
	sessionID string        // pathSession
	method    access.Method // pathMethod
	username  string        // the canonical username the audit names; "" when refused
	client    account.Client
	p         access.Principal
	id        int64 // pathInt
}

// queryOf is c's decoded Query. T must be its route's Query type: another
// panics, as a route's spec and handler disagreeing must.
func queryOf[T any](c *call) T {
	var q T
	reflect.ValueOf(&q).Elem().Set(c.query)
	return q
}

// mount wraps s.serve with Cache-Control: no-store on every response and,
// on an unsafe method, its own cross-origin check, so the route does not
// rely on the app's.
func (h *Handler) mount(s *routeSpec, d *Descriptor) http.Handler {
	var next http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.serve(&call{w: w, r: r, spec: s, desc: d, client: h.client(r)})
	})
	if s.method != http.MethodGet {
		next = crossorigin.Guard(next, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.fail(&call{w: w, r: r, spec: s, desc: d, client: h.client(r)}, errCrossOrigin)
		}))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) serve(c *call) {
	if c.r.Method != c.desc.Method {
		c.w.Header().Set("Allow", c.desc.Method)
		h.fail(c, errMethodNotAllowed)
		return
	}
	if err := h.prepare(c); err != nil {
		h.fail(c, err)
		return
	}
	if err := c.spec.serve(h, c); err != nil {
		h.fail(c, err)
	}
}

// prepare runs the class guard, then parses the path value and the query.
func (h *Handler) prepare(c *call) error {
	r, p, guardErr := h.guard(c.r, c.desc)
	c.r, c.p = r, p
	if guardErr != nil {
		return guardErr
	}
	if err := pathValues(c.spec, c.r, c); err != nil {
		return err
	}
	query, err := decodeQuery(c.spec, c.r)
	if err != nil {
		return err
	}
	c.query = query
	return nil
}

// fail answers err through the ErrorWriter.
func (h *Handler) fail(c *call, err error) {
	refusal.Write(c.w, c.r, h.acct.Authenticator(), h.errors, h.refusal(c, err), c.desc.Scope)
}

// refusal maps err for c's route through routeError and audits it; a
// contract break is logged at ERROR and answered auth_unavailable.
func (h *Handler) refusal(c *call, err error) access.Error {
	e, broken := routeError(err, c.spec.cer, c.desc.Codes)
	if broken {
		h.logBreak(c, err, e.Code)
		e = access.NewError(access.CodeUnavailable, "", err)
	}
	h.auditFailure(c, err, e)
	return e
}

// logBreak logs an unmapped or unlisted err. An error carrying the
// request's own ended context is the client walking away, not a break:
// only r.Context().Err() tells it from account's own timeout.
func (h *Handler) logBreak(c *call, err error, code access.Code) {
	ctx := c.r.Context()
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		h.log().DebugContext(ctx, "accesshttp: request ended", "route", c.desc.Name, "err", err.Error())
		return
	}
	h.log().ErrorContext(ctx, "accesshttp: contract break", "route", c.desc.Name, "code", string(code), "err", err.Error())
}

func noContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }
