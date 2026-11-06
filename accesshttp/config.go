package accesshttp

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// Config configures the handlers.
type Config struct {
	// Account supplies the Authenticator, and through it the session cookie
	// and timeouts; accesshttp holds no copy of either. Required.
	Account *account.Service
	// Errors renders every refusal. Required.
	Errors ErrorWriter
	// Audit receives the request-level outcomes that change no state. Optional.
	Audit         func(r *http.Request, e AuditEvent)
	PendingSealer *access.Sealer // seals the pending-link cookie; nil: an ephemeral sealer
	Logger        *slog.Logger   // nil: slog.Default() at each log call
	Prefix        string         // e.g. "/api/auth"; every path not under OIDCPrefix starts with it
	OIDCPrefix    string         // the OIDC start and callback routes' prefix
	SignInPath    string         // where the OIDC callback sends a browser on a non-success outcome
}

// Handler serves the access routes. Build it with New.
type Handler struct {
	acct    accountAPI
	errors  ErrorWriter
	audit   func(r *http.Request, e AuditEvent)
	pending *access.Sealer
	logger  *slog.Logger
	signIn  string
	routes  []Route
}

// Route is one descriptor and its handler, which the app mounts on its own
// mux at Method and Path.
type Route struct {
	Handler http.Handler
	Descriptor
}

// New refuses a nil Account or Errors.
func New(cfg Config) (*Handler, error) { //nolint:gocritic // hugeParam: a construction-time config, read once
	if cfg.Account == nil {
		return nil, errors.New("accesshttp: Config.Account is required")
	}
	return newHandler(cfg, cfg.Account)
}

// newHandler builds the handler over acct, which tests replace.
func newHandler(cfg Config, acct accountAPI) (*Handler, error) { //nolint:gocritic // hugeParam: as New
	if cfg.Errors == nil {
		return nil, errors.New("accesshttp: Config.Errors is required")
	}
	h := &Handler{
		acct:    acct,
		errors:  cfg.Errors,
		audit:   cfg.Audit,
		pending: cfg.PendingSealer,
		logger:  cfg.Logger,
		signIn:  cfg.SignInPath,
	}
	if h.pending == nil {
		h.pending = access.NewEphemeralSealer()
	}
	dc := DescriptorConfig{
		Prefix: cfg.Prefix, OIDCPrefix: cfg.OIDCPrefix,
		AdminScope: acct.AdminScope(), ManageUsersScope: acct.ManageUsersScope(), CreateKeysScope: acct.CreateKeysScope(),
	}
	for i := range specs {
		s := &specs[i]
		d := s.descriptor(&dc)
		h.routes = append(h.routes, Route{Descriptor: d, Handler: h.mount(s, &d)})
	}
	return h, nil
}

// Routes returns a copy of the routes; the app mounts any subset on its own
// mux.
func (h *Handler) Routes() []Route {
	out := make([]Route, len(h.routes))
	for i := range h.routes {
		out[i] = h.routes[i]
		out[i].Codes = append([]Code(nil), h.routes[i].Codes...)
	}
	return out
}

func (h *Handler) log() *slog.Logger {
	if h.logger != nil {
		return h.logger
	}
	return slog.Default()
}
