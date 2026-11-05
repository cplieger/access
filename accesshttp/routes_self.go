package accesshttp

import (
	"math"
	"net/http"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

func serveMe(h *Handler, c *call) error {
	me, err := h.acct.Me(c.r.Context(), c.p)
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, meResponse(&me))
	return nil
}

func serveProfile(h *Handler, c *call) error {
	req, err := decodeJSON[ProfileRequest](c.w, c.r)
	if err != nil {
		return err
	}
	me, err := h.acct.UpdateProfile(c.r.Context(), c.p, req.DisplayName)
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, meResponse(&me))
	return nil
}

func serveMethodReenable(h *Handler, c *call) error {
	if err := h.acct.ReenableMethod(c.r.Context(), c.p, c.method); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

func serveStepUpPassword(h *Handler, c *call) error {
	req, err := decodeJSON[PasswordRequest](c.w, c.r)
	if err != nil {
		return err
	}
	password, err := requireSecret("password", req.Password)
	if err != nil {
		return err
	}
	is, err := h.acct.StepUpPassword(c.r.Context(), c.client, c.p, password)
	if err != nil {
		return err
	}
	h.setIssued(c.w, c.r, is)
	h.auditSuccess(c, c.p.User, is.Session)
	noContent(c.w)
	return nil
}

// servePasswordSet passes an absent current password as the zero Secret:
// account decides whether the user holds one that it must prove.
func servePasswordSet(h *Handler, c *call) error {
	req, err := decodeJSON[PasswordChangeRequest](c.w, c.r)
	if err != nil {
		return err
	}
	current := access.NewSecret(req.CurrentPassword)
	password, err := requireSecret("password", req.Password)
	if err != nil {
		return err
	}
	is, err := h.acct.SetPassword(c.r.Context(), c.client, c.p, current, password)
	if err != nil {
		return err
	}
	h.setIssued(c.w, c.r, is)
	noContent(c.w)
	return nil
}

// servePasswordRemove leaves an empty current password to account, which
// answers it current_password_required.
func servePasswordRemove(h *Handler, c *call) error {
	req, err := decodeJSON[PasswordRemoveRequest](c.w, c.r)
	if err != nil {
		return err
	}
	current := access.NewSecret(req.CurrentPassword)
	is, err := h.acct.RemovePassword(c.r.Context(), c.client, c.p, current)
	if err != nil {
		return err
	}
	h.setIssued(c.w, c.r, is)
	noContent(c.w)
	return nil
}

func serveStepUpPasskeyBegin(h *Handler, c *call) error {
	origin, err := requestOrigin(c.r)
	if err != nil {
		return err
	}
	pc, err := h.acct.StepUpPasskeyBegin(c.r.Context(), c.p, origin)
	if err != nil {
		return err
	}
	return writeCeremony(c, pc)
}

func serveStepUpPasskeyFinish(h *Handler, c *call) error {
	body, err := readCredential(c.w, c.r)
	if err != nil {
		return err
	}
	is, err := h.acct.StepUpPasskeyFinish(c.r.Context(), c.client, c.p, c.r.Header.Get(ceremonyHeader), body)
	if err != nil {
		return err
	}
	h.setIssued(c.w, c.r, is)
	h.auditSuccess(c, c.p.User, is.Session)
	noContent(c.w)
	return nil
}

func servePasskeys(h *Handler, c *call) error {
	creds, err := h.acct.Passkeys(c.r.Context(), c.p)
	if err != nil {
		return err
	}
	views := make([]PasskeyView, len(creds))
	for i := range creds {
		views[i] = passkeyView(&creds[i])
	}
	writeJSON(c.w, http.StatusOK, views)
	return nil
}

func servePasskeyRegisterBegin(h *Handler, c *call) error {
	origin, err := requestOrigin(c.r)
	if err != nil {
		return err
	}
	pc, err := h.acct.PasskeyRegisterBegin(c.r.Context(), c.p, origin)
	if err != nil {
		return err
	}
	return writeCeremony(c, pc)
}

func servePasskeyRegisterFinish(h *Handler, c *call) error {
	body, err := readCredential(c.w, c.r)
	if err != nil {
		return err
	}
	reg, err := h.acct.PasskeyRegisterFinish(c.r.Context(), c.p, c.r.Header.Get(ceremonyHeader), body)
	if err != nil {
		return err
	}
	h.setIssued(c.w, c.r, reg.Issued)
	writeJSON(c.w, http.StatusCreated, passkeyView(&reg.Passkey))
	return nil
}

func servePasskeyRename(h *Handler, c *call) error {
	req, err := decodeJSON[NameRequest](c.w, c.r)
	if err != nil {
		return err
	}
	if err := h.acct.RenamePasskey(c.r.Context(), c.p, c.id, req.Name); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

func servePasskeyRemove(h *Handler, c *call) error {
	if err := h.acct.RemovePasskey(c.r.Context(), c.p, c.id); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

func serveWebAuthnSignals(h *Handler, c *call) error {
	sig, err := h.acct.WebAuthnSignals(c.r.Context(), c.p)
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, sig)
	return nil
}

func serveSessions(h *Handler, c *call) error {
	sessions, err := h.acct.Sessions(c.r.Context(), c.p)
	if err != nil {
		return err
	}
	timeouts := h.acct.Authenticator().Timeouts()
	views := make([]SessionView, len(sessions))
	for i := range sessions {
		views[i] = sessionView(&sessions[i], timeouts, c.p.SessionID)
	}
	writeJSON(c.w, http.StatusOK, views)
	return nil
}

func serveSessionRename(h *Handler, c *call) error {
	req, err := decodeJSON[NameRequest](c.w, c.r)
	if err != nil {
		return err
	}
	if err := h.acct.RenameSession(c.r.Context(), c.p, account.SessionLabel{ID: c.sessionID, Label: req.Name}); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

// serveSessionRevoke clears the cookie when the caller ends its own
// session, whose token no longer authenticates.
func serveSessionRevoke(h *Handler, c *call) error {
	if err := h.acct.RevokeSession(c.r.Context(), c.p, c.sessionID); err != nil {
		return err
	}
	if c.sessionID == c.p.SessionID {
		h.clearSession(c.w, c.r)
	}
	noContent(c.w)
	return nil
}

func serveSessionsRevokeOthers(h *Handler, c *call) error {
	if err := h.acct.RevokeOtherSessions(c.r.Context(), c.p); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

func serveKeys(h *Handler, c *call) error {
	keys, err := h.acct.APIKeys(c.r.Context(), c.p)
	if err != nil {
		return err
	}
	views := make([]KeyView, len(keys))
	for i := range keys {
		views[i] = keyView(&keys[i], "")
	}
	writeJSON(c.w, http.StatusOK, views)
	return nil
}

// serveKeyCreate mints a key for the caller's own user; a session caller's
// rotated session comes back in Issued, a key caller's is zero.
func serveKeyCreate(h *Handler, c *call) error {
	req, err := decodeJSON[NewKeyRequest](c.w, c.r)
	if err != nil {
		return err
	}
	in := account.NewKey{Label: req.Label, Scopes: req.Scopes, ExpiresIn: units(req.ExpiresInDays, 24*time.Hour)}
	created, err := h.acct.CreateAPIKey(c.r.Context(), account.As(c.p), c.p.User.ID, in)
	if err != nil {
		return err
	}
	if !created.Issued.Token.IsZero() {
		h.setIssued(c.w, c.r, created.Issued)
	}
	writeShownOnce(c.w, http.StatusCreated, KeyCreatedResponse{Details: keyView(&created.Key, "")}, created.Plaintext)
	return nil
}

func serveKeyRevoke(h *Handler, c *call) error {
	if err := h.acct.RevokeAPIKey(c.r.Context(), c.p, c.id); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

// units is n units as a Duration, saturating where n units would overflow
// one, so account's own bounds see the sign and size the client sent
// rather than a wrapped value.
func units(n int, unit time.Duration) time.Duration {
	limit := int64(math.MaxInt64 / unit)
	switch {
	case int64(n) > limit:
		return math.MaxInt64
	case int64(n) < -limit:
		return -math.MaxInt64
	}
	return time.Duration(n) * unit
}
