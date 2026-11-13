package access

import (
	"net/http"

	"github.com/cplieger/access/internal/scopetoken"
)

// Challenge sets h's one WWW-Authenticate for a refusal answered with code
// (RFC 6750 §3 and §3.1), realm [Config.Realm]: auth_key_invalid gets
// error="invalid_token"; auth_scope_required gets error="insufficient_scope"
// and, when scope is set, scope="S"; every other 401, and auth_key_required,
// gets the bare Bearer realm="R"; any other code leaves h unchanged. scope is
// empty or one RFC 6750 scope-token; any other panics, as a programming error.
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
	case code != CodeKeyRequired && codeStatus(code) != http.StatusUnauthorized:
		return
	default:
	}
	h.Set("WWW-Authenticate", v)
}
