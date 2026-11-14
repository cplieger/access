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

func deviceCookie(session access.CookieConfig) access.CookieConfig {
	return session.Derive("device", http.SameSiteLaxMode)
}

func pendingCookie(session access.CookieConfig) access.CookieConfig {
	return session.Derive("oidc_pending", http.SameSiteLaxMode)
}

// setSession sets the session cookie for Timeouts.Absolute.
func (h *Handler) setSession(w http.ResponseWriter, secure bool, token access.Secret) {
	authn := h.acct.Authenticator()
	cfg := authn.Cookie()
	cfg.SetCookie(w, secure, token.Reveal(), int(authn.Timeouts().Absolute/time.Second))
}

// setRecoverySession sets the restricted session cookie a recovery start
// opens, for the recovery session's own lifetime.
func (h *Handler) setRecoverySession(w http.ResponseWriter, secure bool, token access.Secret) {
	cfg := h.acct.Authenticator().Cookie()
	cfg.SetCookie(w, secure, token.Reveal(), int(access.RecoverySessionLifetime/time.Second))
}

func (h *Handler) clearSession(w http.ResponseWriter, secure bool) {
	cfg := h.acct.Authenticator().Cookie()
	cfg.ClearCookie(w, secure)
}

// setDevice sets the device cookie when account issued one.
func (h *Handler) setDevice(w http.ResponseWriter, secure bool, device access.Secret) {
	if device.IsZero() {
		return
	}
	cfg := deviceCookie(h.acct.Authenticator().Cookie())
	cfg.SetCookie(w, secure, device.Reveal(), deviceCookieMaxAge)
}

// setPending sets the sealed pending-link cookie.
func (h *Handler) setPending(w http.ResponseWriter, secure bool, sealed string) {
	cfg := pendingCookie(h.acct.Authenticator().Cookie())
	cfg.SetCookie(w, secure, sealed, pendingCookieMaxAge)
}

func (h *Handler) clearPending(w http.ResponseWriter, secure bool) {
	cfg := pendingCookie(h.acct.Authenticator().Cookie())
	cfg.ClearCookie(w, secure)
}

// setIssued sets a rotated session's cookie and the device cookie it carries.
func (h *Handler) setIssued(w http.ResponseWriter, secure bool, is account.Issued) { //nolint:gocritic // hugeParam: account's own result, read once
	h.setSession(w, secure, is.Token)
	h.setDevice(w, secure, is.DeviceCookie)
}

func (h *Handler) setSignedIn(w http.ResponseWriter, secure bool, s account.SignedIn) { //nolint:gocritic // hugeParam: as setIssued
	h.setSession(w, secure, s.Token)
	h.setDevice(w, secure, s.DeviceCookie)
}
