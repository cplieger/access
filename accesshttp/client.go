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
	session := authn.Cookie()
	device := deviceCookie(session)
	ca := authn.ClientAddr(r)
	var presented access.Hash
	if token := session.ReadCookie(r, ca.Secure); token != "" {
		presented = access.SessionHash(token)
	}
	return account.Client{
		Host:       r.Host,
		UserAgent:  r.UserAgent(),
		Device:     access.NewSecret(device.ReadCookie(r, ca.Secure)),
		Presented:  presented,
		ClientAddr: ca,
	}
}

// ceremonyHeader carries the ceremony ID a WebAuthn begin answered.
const ceremonyHeader = "X-Auth-Ceremony"

// requestOrigin is the request's Origin header as a WebAuthn ceremony's
// origin; a missing or malformed one is its *webauthn.OriginError.
func requestOrigin(r *http.Request) (webauthn.Origin, error) {
	return webauthn.ParseOrigin(r.Header.Get("Origin"))
}
