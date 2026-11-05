package accesshttp

import (
	"net/http"

	"github.com/cplieger/access/account"
)

func serveRecoveryStart(h *Handler, c *call) error {
	req, err := decodeJSON[TokenRequest](c.w, c.r)
	if err != nil {
		return err
	}
	token, err := requireSecret("token", req.Token)
	if err != nil {
		return err
	}
	rec, err := h.acct.StartRecovery(c.r.Context(), c.client, token)
	if err != nil {
		return err
	}
	h.setRecoverySession(c.w, c.r, rec.Issued.Token)
	writeJSON(c.w, http.StatusOK, RecoveryResponse{Username: rec.Username, Methods: methodsView(rec.Methods)})
	return nil
}

// serveRecoveryPassword completes a recovery and signs nobody in: the
// restricted session ends with it, so its cookie is cleared.
func serveRecoveryPassword(h *Handler, c *call) error {
	req, err := decodeJSON[RecoverPasswordRequest](c.w, c.r)
	if err != nil {
		return err
	}
	password, err := requireSecret("password", req.Password)
	if err != nil {
		return err
	}
	opts := account.RecoverOptions{KeepSessions: req.KeepSessions, KeepKeys: req.KeepKeys}
	if err := h.acct.RecoverWithPassword(c.r.Context(), c.p, password, opts); err != nil {
		return err
	}
	h.clearSession(c.w, c.r)
	noContent(c.w)
	return nil
}

func serveRecoveryPasskeyBegin(h *Handler, c *call) error {
	origin, err := requestOrigin(c.r)
	if err != nil {
		return err
	}
	pc, err := h.acct.RecoverPasskeyBegin(c.r.Context(), c.p, origin)
	if err != nil {
		return err
	}
	return writeCeremony(c, pc)
}

// serveRecoveryPasskeyFinish completes a recovery with a new passkey and,
// as serveRecoveryPassword, signs nobody in and clears the cookie.
func serveRecoveryPasskeyFinish(h *Handler, c *call) error {
	q := queryOf[RecoveryPasskeyFinishQuery](c)
	body, err := readCredential(c.w, c.r)
	if err != nil {
		return err
	}
	opts := account.RecoverOptions{KeepSessions: q.KeepSessions, KeepKeys: q.KeepKeys}
	if err := h.acct.RecoverPasskeyFinish(c.r.Context(), c.p, c.r.Header.Get(ceremonyHeader), body, opts); err != nil {
		return err
	}
	h.clearSession(c.w, c.r)
	noContent(c.w)
	return nil
}
