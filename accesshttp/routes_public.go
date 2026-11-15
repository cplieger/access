package accesshttp

import (
	"net/http"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// canonical is the username an audit may name: the normalised form, or ""
// for an input NormalizeUsername refuses.
func canonical(username string) string {
	name, err := access.NormalizeUsername(username)
	if err != nil {
		return ""
	}
	return name
}

// signedIn sets the new session's cookies and answers SignedInResponse.
func (h *Handler) signedIn(c *call, s account.SignedIn) { //nolint:gocritic // hugeParam: account's own result, read once
	h.setSignedIn(c.w, c.client.Secure, s)
	h.auditSuccess(c, s.User, s.Session)
	writeJSON(c.w, http.StatusOK, signedInResponse(s))
}

func serveState(h *Handler, c *call) error {
	st, err := h.acct.State(c.r.Context(), c.client)
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, stateResponse(&st))
	return nil
}

func serveSetupPassword(h *Handler, c *call) error {
	req, err := decodeJSON[SetupPasswordRequest](c.w, c.r)
	if err != nil {
		return err
	}
	token := access.NewSecret(req.Token)
	password, err := requireSecret("password", req.Password)
	if err != nil {
		return err
	}
	c.username = canonical(req.Username)
	out, err := h.acct.SetupWithPassword(c.r.Context(), c.client, account.SetupPassword{Token: token, Password: password, Username: req.Username})
	if err != nil {
		return err
	}
	h.loginOutcome(c, out)
	return nil
}

func serveSetupPasskeyBegin(h *Handler, c *call) error {
	req, err := decodeJSON[SetupPasskeyBeginRequest](c.w, c.r)
	if err != nil {
		return err
	}
	token := access.NewSecret(req.Token)
	c.username = canonical(req.Username)
	origin, err := requestOrigin(c.r)
	if err != nil {
		return err
	}
	pc, err := h.acct.SetupPasskeyBegin(c.r.Context(), c.client, account.SetupPasskey{Token: token, Username: req.Username, Origin: origin})
	if err != nil {
		return err
	}
	return writeCeremony(c, pc)
}

func serveSetupPasskeyFinish(h *Handler, c *call) error {
	body, err := readCredential(c.w, c.r)
	if err != nil {
		return err
	}
	out, err := h.acct.SetupPasskeyFinish(c.r.Context(), c.client, c.r.Header.Get(ceremonyHeader), body)
	if err != nil {
		return err
	}
	h.signedIn(c, out)
	return nil
}

func serveLoginPassword(h *Handler, c *call) error {
	req, err := decodeJSON[LoginRequest](c.w, c.r)
	if err != nil {
		return err
	}
	password, err := requireSecret("password", req.Password)
	if err != nil {
		return err
	}
	c.username = canonical(req.Username)
	out, err := h.acct.PasswordLogin(c.r.Context(), c.client, account.Credentials{Password: password, Username: req.Username})
	if err != nil {
		return err
	}
	h.loginOutcome(c, out)
	return nil
}

// loginOutcome answers a sign-in step: SignInOutcome's signed_in with the
// session's cookies, or its pending with no cookie, since the ticket rides
// the body only.
func (h *Handler) loginOutcome(c *call, out account.LoginResult) { //nolint:gocritic // hugeParam: account's own result, read once
	if p := out.Pending; p != nil {
		h.emit(c, access.AuditEvent{Kind: "pending", Username: c.username, Method: access.MethodPassword})
		writeJSON(c.w, http.StatusOK, SignInOutcome{Pending: pendingView(p)})
		return
	}
	h.setSignedIn(c.w, c.client.Secure, out.SignedIn)
	h.auditSuccess(c, out.SignedIn.User, out.SignedIn.Session)
	signed := signedInResponse(out.SignedIn)
	writeJSON(c.w, http.StatusOK, SignInOutcome{SignedIn: &signed})
}

func serveLoginPasskeyBegin(h *Handler, c *call) error {
	mode := account.LoginModal
	if queryOf[PasskeyBeginQuery](c).Mediation == mediationConditional {
		mode = account.LoginConditional
	}
	origin, err := requestOrigin(c.r)
	if err != nil {
		return err
	}
	pc, err := h.acct.PasskeyLoginBegin(c.r.Context(), c.client, origin, mode)
	if err != nil {
		return err
	}
	return writeCeremony(c, pc)
}

func serveLoginPasskeyFinish(h *Handler, c *call) error {
	body, err := readCredential(c.w, c.r)
	if err != nil {
		return err
	}
	out, err := h.acct.PasskeyLoginFinish(c.r.Context(), c.client, c.r.Header.Get(ceremonyHeader), body)
	if err != nil {
		return err
	}
	h.signedIn(c, out)
	return nil
}

// serveLogout ends the session the request presented, if any, and clears
// the cookie. A refusal keeps the cookie, so the browser can retry the
// logout instead of forgetting a token whose session still lives.
func serveLogout(h *Handler, c *call) error {
	if err := h.acct.Logout(c.r.Context(), c.client.Presented); err != nil {
		return err
	}
	h.clearSession(c.w, c.client.Secure)
	noContent(c.w)
	return nil
}

func serveInviteAcceptPassword(h *Handler, c *call) error {
	req, err := decodeJSON[InviteAcceptRequest](c.w, c.r)
	if err != nil {
		return err
	}
	token, err := requireSecret("token", req.Token)
	if err != nil {
		return err
	}
	password, err := requireSecret("password", req.Password)
	if err != nil {
		return err
	}
	c.username = canonical(req.Username)
	out, err := h.acct.AcceptInvitePassword(c.r.Context(), c.client, account.AcceptInvite{Token: token, Password: password, Username: req.Username})
	if err != nil {
		return err
	}
	h.loginOutcome(c, out)
	return nil
}

// writeCeremony answers a begun ceremony.
func writeCeremony(c *call, pc account.PendingCeremony) error {
	resp, err := ceremonyResponse(pc)
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, resp)
	return nil
}
