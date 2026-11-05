package accesshttp

import (
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
)

// maxUserAgentBytes caps the user agent a Client carries.
const maxUserAgentBytes = 256

// client is what the request tells account about its caller, built once per
// request from the app's one resolver.
func (h *Handler) client(r *http.Request) account.Client {
	authn := h.acct.Authenticator()
	device := deviceCookie(authn.Cookie())
	return account.Client{
		Host:       r.Host,
		UserAgent:  sanitizeUserAgent(r.UserAgent()),
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

// sanitizeUserAgent drops invalid UTF-8 and every control, format or line
// separator rune, so a stored or displayed agent stays on one line and
// cannot reorder text around it, and stops before maxUserAgentBytes.
func sanitizeUserAgent(ua string) string {
	var b strings.Builder
	for _, r := range ua {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxUserAgentBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
