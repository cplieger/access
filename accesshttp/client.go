package accesshttp

import (
	"net/http"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
)

// client is what the request tells account about its caller, built once per
// request from the app's one resolver.
func (h *Handler) client(r *http.Request) account.Client {
	authn := h.acct.Authenticator()
	device := deviceCookie(authn.Cookie())
	return account.Client{
		Host:       r.Host,
		UserAgent:  r.UserAgent(),
		Device:     access.NewSecret(device.ReadCookie(r)),
		ClientAddr: authn.ClientAddr(r),
	}
}

// ceremonyHeader carries the ceremony ID a WebAuthn begin answered.
const ceremonyHeader = "X-Auth-Ceremony"

// requestOrigin is the request's Origin header as a WebAuthn ceremony's
// origin; a missing or malformed one is its *webauthn.OriginError.
func requestOrigin(r *http.Request) (webauthn.Origin, error) {
	return webauthn.ParseOrigin(r.Header.Get("Origin"))
}
