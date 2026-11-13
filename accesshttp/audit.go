package accesshttp

import (
	"strings"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/failreason"
)

// AuditEvent is one request-level outcome that changes no state: a
// failure, a refusal or a rate limit, and the sign-ins beside them. It
// carries no raw request text: no user agent, no provider
// error_description, no typed username that failed normalisation.
type AuditEvent struct {
	Kind     string // "login.success", "login.failure", "login.rate_limited", "setup.failure", ...
	Username string // canonical, or "" when the input was refused; never the raw input
	IP       string
	Method   access.Method
	// Reason is a code-like class: "invalid_credentials", "method_locked",
	// "provider_error:access_denied", "exchange_failed".
	Reason    string
	SessionID string
	UserID    int64
	KeyID     int64
	Success   bool
}

// emit fills the event's address from the request's Client and hands it
// to Config.Audit; a route with no audit kind emits nothing.
func (h *Handler) emit(c *call, e AuditEvent) { //nolint:gocritic // hugeParam: one event, built per request
	if h.audit == nil || c.spec.audit == "" {
		return
	}
	e.Kind = c.spec.audit + "." + e.Kind
	if ip := c.client.IP(); ip.IsValid() {
		e.IP = ip.String()
	}
	h.audit(c.r, e)
}

// auditFailure emits a refusal: Reason is the internal failure reason when
// account carried one (method_locked), else the answer's Reason, else its
// code without the prefix.
func (h *Handler) auditFailure(c *call, err error, e Error) { //nolint:gocritic // hugeParam: the answer just mapped
	kind := "failure"
	if e.Code == CodeRateLimited {
		kind = "rate_limited"
	}
	reason := failreason.Of(err)
	if reason == "" {
		reason = e.Reason
	}
	if reason == "" {
		reason = strings.TrimPrefix(string(e.Code), "auth_")
	}
	h.emit(c, AuditEvent{Kind: kind, Username: c.username, Method: c.p.Method, Reason: reason, UserID: principalUser(c.p), KeyID: c.p.KeyID})
}

// auditSuccess emits a sign-in or a step-up that account committed; u,
// when known, names the user.
func (h *Handler) auditSuccess(c *call, u *access.User, s access.Session) { //nolint:gocritic // hugeParam: account's committed session, read once
	e := AuditEvent{Kind: "success", Success: true, SessionID: s.ID, UserID: s.UserID, Method: s.AuthMethod}
	if u != nil {
		e.Username = u.Username
	}
	h.emit(c, e)
}

func principalUser(p access.Principal) int64 { //nolint:gocritic // hugeParam: the Principal Authenticate returned
	if p.User == nil {
		return 0
	}
	return p.User.ID
}
