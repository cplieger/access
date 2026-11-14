package gate

import (
	"cmp"
	"errors"
	"net/http"
	"strings"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/failreason"
)

// The audit kinds.
const (
	kindFailure   = "gate.failure"
	kindForbidden = "gate.forbidden"
)

// The gate.forbidden reasons that are not a class refusal's code.
const (
	reasonRecoverySession = "recovery_session"
	reasonCrossOrigin     = "cross_origin"
)

// auditUnauthenticated reports the Authenticate error err the gate answers
// with code: a recovery session is gate.forbidden, any other refused
// credential gate.failure with the verifier's reason. No credential and a
// 503 report nothing, so a store outage never counts as failed sign-ins.
func (g *Gate) auditUnauthenticated(r *http.Request, err error, code access.Code) {
	e := access.AuditEvent{Kind: kindFailure}
	switch code {
	case access.CodeAuthRequired, access.CodeUnavailable:
		return
	case access.CodeSessionRequired:
		e.Kind, e.Reason = kindForbidden, reasonRecoverySession
	default:
		// Only a custom verifier's refusal carries no reason.
		e.Reason = cmp.Or(failreason.Of(err), failreason.CredentialInvalid)
		if ice, ok := errors.AsType[*access.InvalidCredentialError](err); ok {
			e.Method, e.KeyID = ice.Method, ice.KeyID
		}
	}
	g.audit(r, &e)
}

// auditForbidden reports the class refusal code of the principal p.
func (g *Gate) auditForbidden(r *http.Request, code access.Code, p *access.Principal) {
	e := access.AuditEvent{Kind: kindForbidden, Reason: strings.TrimPrefix(string(code), "auth_"), KeyID: p.KeyID}
	if p.User != nil {
		e.UserID = p.User.ID
	}
	if !p.IsSession() {
		e.Method = p.Method
	}
	g.audit(r, &e)
}

// audit hands e, with r's client address, to Config.Audit.
func (g *Gate) audit(r *http.Request, e *access.AuditEvent) {
	if g.cfg.Audit == nil {
		return
	}
	if ip := g.cfg.Authenticator.ClientAddr(r).IP(); ip.IsValid() {
		e.IP = ip.String()
	}
	g.cfg.Audit(r, *e)
}
