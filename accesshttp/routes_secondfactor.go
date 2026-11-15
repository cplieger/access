package accesshttp

import (
	"net/http"

	"github.com/cplieger/access/account"
)

func serveLoginCode(h *Handler, c *call) error {
	req, err := decodeJSON[CodeRequest](c.w, c.r)
	if err != nil {
		return err
	}
	ticket, err := requireSecret("ticket", req.Ticket)
	if err != nil {
		return err
	}
	out, err := h.acct.SignInWithCode(c.r.Context(), c.client, ticket, req.Code)
	if err != nil {
		return err
	}
	h.loginOutcome(c, out)
	return nil
}

func serveLoginSecondPasskeyBegin(h *Handler, c *call) error {
	req, err := decodeJSON[TicketRequest](c.w, c.r)
	if err != nil {
		return err
	}
	ticket, err := requireSecret("ticket", req.Ticket)
	if err != nil {
		return err
	}
	origin, err := requestOrigin(c.r)
	if err != nil {
		return err
	}
	pc, err := h.acct.SecondFactorPasskeyBegin(c.r.Context(), c.client, ticket, origin)
	if err != nil {
		return err
	}
	return writeCeremony(c, pc)
}

func serveLoginSecondPasskeyFinish(h *Handler, c *call) error {
	body, err := readCredential(c.w, c.r)
	if err != nil {
		return err
	}
	out, err := h.acct.SecondFactorPasskeyFinish(c.r.Context(), c.client, c.r.Header.Get(ceremonyHeader), body)
	if err != nil {
		return err
	}
	h.loginOutcome(c, out)
	return nil
}

func serveTOTPBegin(h *Handler, c *call) error {
	e, err := h.acct.BeginTOTP(c.r.Context(), c.p)
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, TOTPBeginResponse{URI: e.URI.Reveal(), Text: e.Text.Reveal(), Ticket: e.Ticket.Reveal()})
	return nil
}

func serveTOTPFinish(h *Handler, c *call) error {
	req, err := decodeJSON[TOTPFinishRequest](c.w, c.r)
	if err != nil {
		return err
	}
	ticket, err := requireSecret("ticket", req.Ticket)
	if err != nil {
		return err
	}
	in := account.TOTPFinish{Ticket: ticket, Code: req.Code, CurrentCode: req.CurrentCode}
	done, err := h.acct.FinishTOTP(c.r.Context(), c.client, c.p, in)
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, RecoveryCodeIssuedResponse{RecoveryCode: done.RecoveryCode.Reveal()})
	return nil
}

func serveRecoveryCodeRegenerate(h *Handler, c *call) error {
	proof, err := decodeProof(c.w, c.r)
	if err != nil {
		return err
	}
	code, err := h.acct.RegenerateRecoveryCode(c.r.Context(), c.client, c.p, proof)
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, RecoveryCodeResponse{RecoveryCode: code.Reveal()})
	return nil
}

func serveTOTPRemove(h *Handler, c *call) error {
	proof, err := decodeProof(c.w, c.r)
	if err != nil {
		return err
	}
	if err := h.acct.RemoveTOTP(c.r.Context(), c.client, c.p, proof); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

func serveStepUpCode(h *Handler, c *call) error {
	req, err := decodeJSON[StepUpCodeRequest](c.w, c.r)
	if err != nil {
		return err
	}
	is, err := h.acct.StepUpCode(c.r.Context(), c.client, c.p, req.Code)
	if err != nil {
		return err
	}
	h.setIssued(c.w, c.client.Secure, is)
	h.auditSuccess(c, c.p.User, is.Session)
	noContent(c.w)
	return nil
}
