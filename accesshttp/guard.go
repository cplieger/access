package accesshttp

import (
	"net/http"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// guard authenticates r for a class that authenticates and checks the
// class predicate through account's own helpers, so both layers admit the
// same principals. It returns r with the context the route runs under.
func (h *Handler) guard(r *http.Request, d *Descriptor) (*http.Request, access.Principal, error) {
	if d.Class == ClassPublic {
		return r, access.Principal{}, nil
	}
	ctx := r.Context()
	if d.Passive {
		ctx = access.Passive(ctx)
	}
	r = r.WithContext(ctx)
	p, err := h.acct.Authenticator().Authenticate(r)
	if err != nil {
		return r, access.Principal{}, err
	}
	return r, p, h.admit(d, p)
}

func (h *Handler) admit(d *Descriptor, p access.Principal) error { //nolint:gocritic // hugeParam: the Principal Authenticate returned
	switch d.Class {
	case ClassSession:
		if !p.IsSession() {
			return account.ErrSessionRequired
		}
	case ClassRecentAuth:
		if !p.IsSession() {
			return account.ErrSessionRequired
		}
		return h.acct.RequireRecentAuth(p)
	case ClassKeyScope:
		return h.acct.RequireKeyScope(p, d.Scope)
	case ClassKeyPermission:
		return h.acct.RequireKeyPermission(p, d.Scope)
	default:
	}
	return nil
}
