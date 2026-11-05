package accesshttp

import (
	"net/http"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// Companion cookie lifetimes, in seconds.
const (
	deviceCookieMaxAge  = int(180 * 24 * time.Hour / time.Second)
	pendingCookieMaxAge = int(pendingLifetime / time.Second)
)

func deviceCookie(session access.CookieConfig) access.CookieConfig { //nolint:gocritic // hugeParam: the Authenticator's config, read once
	return session.Derive("device", http.SameSiteLaxMode)
}

func pendingCookie(session access.CookieConfig) access.CookieConfig { //nolint:gocritic // hugeParam: as deviceCookie
	return session.Derive("oidc_pending", http.SameSiteLaxMode)
}

// setSession sets the session cookie for Timeouts.Absolute, which the
// CookieConfig's Persistent may turn into a browser-session cookie.
func (h *Handler) setSession(w http.ResponseWriter, r *http.Request, token access.Secret) {
	authn := h.acct.Authenticator()
	cfg := authn.Cookie()
	cfg.SetCookie(w, r, token.Reveal(), int(authn.Timeouts().Absolute/time.Second))
}

// setRecoverySession sets the restricted session cookie a recovery start
// opens, for the recovery session's own lifetime.
func (h *Handler) setRecoverySession(w http.ResponseWriter, r *http.Request, token access.Secret) {
	cfg := h.acct.Authenticator().Cookie()
	cfg.SetCookie(w, r, token.Reveal(), int(access.RecoverySessionLifetime/time.Second))
}

func (h *Handler) clearSession(w http.ResponseWriter, r *http.Request) {
	cfg := h.acct.Authenticator().Cookie()
	cfg.ClearCookie(w, r)
}

// setDevice sets the device cookie when account issued one.
func (h *Handler) setDevice(w http.ResponseWriter, r *http.Request, device access.Secret) {
	if device.IsZero() {
		return
	}
	cfg := deviceCookie(h.acct.Authenticator().Cookie())
	cfg.SetCookie(w, r, device.Reveal(), deviceCookieMaxAge)
}

// setPending sets the sealed pending-link cookie.
func (h *Handler) setPending(w http.ResponseWriter, r *http.Request, sealed string) {
	cfg := pendingCookie(h.acct.Authenticator().Cookie())
	cfg.SetCookie(w, r, sealed, pendingCookieMaxAge)
}

func (h *Handler) clearPending(w http.ResponseWriter, r *http.Request) {
	cfg := pendingCookie(h.acct.Authenticator().Cookie())
	cfg.ClearCookie(w, r)
}

// setIssued sets a rotated session's cookie and the device cookie it carries.
func (h *Handler) setIssued(w http.ResponseWriter, r *http.Request, is account.Issued) { //nolint:gocritic // hugeParam: account's own result, read once
	h.setSession(w, r, is.Token)
	h.setDevice(w, r, is.DeviceCookie)
}

func (h *Handler) setSignedIn(w http.ResponseWriter, r *http.Request, s account.SignedIn) { //nolint:gocritic // hugeParam: as setIssued
	h.setSession(w, r, s.Token)
	h.setDevice(w, r, s.DeviceCookie)
}
