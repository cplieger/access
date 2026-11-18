package accesshttp

import (
	"github.com/cplieger/access/account"
)

func serveRegisterPassword(h *Handler, c *call) error {
	req, err := decodeJSON[RegisterPasswordRequest](c.w, c.r)
	if err != nil {
		return err
	}
	password, err := requireSecret("password", req.Password)
	if err != nil {
		return err
	}
	c.username = canonical(req.Username)
	out, err := h.acct.RegisterPassword(c.r.Context(), c.client, account.Registration{Username: req.Username, Password: password})
	if err != nil {
		return err
	}
	if out.Waiting != nil {
		h.auditWaiting(c, out.Waiting.User)
		c.answer(RegistrationOutcome{WaitingApproval: true})
		return nil
	}
	signed, pending := h.signInArms(c, account.LoginResult{Pending: out.Pending, SignedIn: out.SignedIn})
	c.answer(RegistrationOutcome{SignedIn: signed, Pending: pending})
	return nil
}

func serveRegisterPasskeyBegin(h *Handler, c *call) error {
	req, err := decodeJSON[RegisterPasskeyBeginRequest](c.w, c.r)
	if err != nil {
		return err
	}
	c.username = canonical(req.Username)
	origin, err := requestOrigin(c.r)
	if err != nil {
		return err
	}
	pc, err := h.acct.RegisterPasskeyBegin(c.r.Context(), c.client, account.RegistrationPasskey{Username: req.Username, Origin: origin})
	if err != nil {
		return err
	}
	return writeCeremony(c, pc)
}

func serveRegisterPasskeyFinish(h *Handler, c *call) error {
	body, err := readCredential(c.w, c.r)
	if err != nil {
		return err
	}
	out, err := h.acct.RegisterPasskeyFinish(c.r.Context(), c.client, c.r.Header.Get(ceremonyHeader), body)
	if err != nil {
		return err
	}
	h.enrolled(c, out)
	return nil
}
