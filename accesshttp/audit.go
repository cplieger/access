package accesshttp

import (
	"strings"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/failreason"
)

// emit fills the event's address from the request's Client and hands it
// to Config.Audit; a route with no audit kind emits nothing.
func (h *Handler) emit(c *call, e access.AuditEvent) { //nolint:gocritic // hugeParam: one event, built per request
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
func (h *Handler) auditFailure(c *call, err error, e access.Error) { //nolint:gocritic // hugeParam: the answer just mapped
	kind := "failure"
	if e.Code == access.CodeRateLimited {
		kind = "rate_limited"
	}
	reason := failreason.Of(err)
	if reason == "" {
		reason = e.Reason
	}
	if reason == "" {
		reason = strings.TrimPrefix(string(e.Code), "auth_")
	}
	h.emit(c, access.AuditEvent{Kind: kind, Username: c.username, Method: c.p.Method, Reason: reason, UserID: principalUser(c.p), KeyID: c.p.KeyID})
}

// auditSuccess emits a sign-in or a step-up that account committed; u,
// when known, names the user.
func (h *Handler) auditSuccess(c *call, u *access.User, s access.Session) { //nolint:gocritic // hugeParam: account's committed session, read once
	e := access.AuditEvent{Kind: "success", Success: true, SessionID: s.ID, UserID: s.UserID, Method: s.AuthMethod}
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
