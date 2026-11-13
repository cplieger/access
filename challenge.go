package access

import (
	"net/http"

	"github.com/cplieger/access/internal/scopetoken"
)

// Challenge sets h's WWW-Authenticate for a refusal answered with code, from
// RFC 6750 §3 and §3.1, with the realm from [Config.Realm]:
//   - auth_key_invalid: Bearer realm="R", error="invalid_token";
//   - auth_scope_required: Bearer realm="R", error="insufficient_scope",
//     scope="S", with no scope attribute when scope is empty;
//   - every other 401: Bearer realm="R";
//   - every other code, one [Codes] does not list included: none, and h is
//     left unchanged.
//
// It sets the header, never adds a second one. scope is empty or one RFC
// 6750 scope-token; any other panics, as a programming error.
func (a *Authenticator) Challenge(h http.Header, code Code, scope string) {
	if scope != "" && !scopetoken.Valid(scope) {
		panic("access: Challenge: scope is not an RFC 6750 scope-token")
	}
	v := `Bearer realm="` + a.cfg.Realm + `"`
	switch {
	case code == CodeKeyInvalid:
		v += `, error="invalid_token"`
	case code == CodeScopeRequired:
		v += `, error="insufficient_scope"`
		if scope != "" {
			v += `, scope="` + scope + `"`
		}
	case codeStatus(code) != http.StatusUnauthorized:
		return
	default:
	}
	h.Set("WWW-Authenticate", v)
}
