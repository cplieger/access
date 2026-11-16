package accesshttp

import (
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

func serveLoginRecoveryCode(h *Handler, c *call) error {
	req, err := decodeJSON[CodeRequest](c.w, c.r)
	if err != nil {
		return err
	}
	ticket, err := requireSecret("ticket", req.Ticket)
	if err != nil {
		return err
	}
	out, err := h.acct.SignInWithRecoveryCode(c.r.Context(), c.client, ticket, req.Code)
	if err != nil {
		return err
	}
	h.loginOutcome(c, out)
	return nil
}

func serveLoginSetPassword(h *Handler, c *call) error {
	req, err := decodeJSON[SetPasswordRequest](c.w, c.r)
	if err != nil {
		return err
	}
	ticket, err := requireSecret("ticket", req.Ticket)
	if err != nil {
		return err
	}
	password, err := requireSecret("password", req.Password)
	if err != nil {
		return err
	}
	out, err := h.acct.SetCredentialPassword(c.r.Context(), c.client, ticket, password)
	if err != nil {
		return err
	}
	h.loginOutcome(c, out)
	return nil
}

func serveLoginSetPasskeyBegin(h *Handler, c *call) error {
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
	pc, err := h.acct.SetCredentialPasskeyBegin(c.r.Context(), c.client, ticket, origin)
	if err != nil {
		return err
	}
	return writeCeremony(c, pc)
}

func serveLoginSetPasskeyFinish(h *Handler, c *call) error {
	body, err := readCredential(c.w, c.r)
	if err != nil {
		return err
	}
	s, err := h.acct.SetCredentialPasskeyFinish(c.r.Context(), c.client, c.r.Header.Get(ceremonyHeader), body)
	if err != nil {
		return err
	}
	h.loginOutcome(c, account.LoginResult{SignedIn: s})
	return nil
}

func servePendingTOTPBegin(h *Handler, c *call) error {
	req, err := decodeJSON[TicketRequest](c.w, c.r)
	if err != nil {
		return err
	}
	ticket, err := requireSecret("ticket", req.Ticket)
	if err != nil {
		return err
	}
	e, err := h.acct.PendingTOTPBegin(c.r.Context(), c.client, ticket)
	if err != nil {
		return err
	}
	c.answer(PendingTOTPBeginResponse{URI: e.URI.Reveal(), Text: e.Text.Reveal()})
	return nil
}

func servePendingTOTPFinish(h *Handler, c *call) error {
	req, err := decodeJSON[CodeRequest](c.w, c.r)
	if err != nil {
		return err
	}
	ticket, err := requireSecret("ticket", req.Ticket)
	if err != nil {
		return err
	}
	in, err := h.acct.PendingTOTPFinish(c.r.Context(), c.client, ticket, req.Code)
	if err != nil {
		return err
	}
	h.enrolled(c, in)
	return nil
}

func servePendingPasskeyBegin(h *Handler, c *call) error {
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
	pc, err := h.acct.PendingPasskeyBegin(c.r.Context(), c.client, ticket, origin)
	if err != nil {
		return err
	}
	return writeCeremony(c, pc)
}

func servePendingPasskeyFinish(h *Handler, c *call) error {
	body, err := readCredential(c.w, c.r)
	if err != nil {
		return err
	}
	in, err := h.acct.PendingPasskeyFinish(c.r.Context(), c.client, c.r.Header.Get(ceremonyHeader), body)
	if err != nil {
		return err
	}
	h.enrolled(c, in)
	return nil
}

// enrolled answers a pending enrolment finish or a passkey registration:
// EnrolmentOutcome's signed_in with the session's cookies, or its
// waiting_approval with none.
func (h *Handler) enrolled(c *call, out account.EnrolmentResult) { //nolint:gocritic // hugeParam: account's own result, read once
	if wt := out.Waiting; wt != nil {
		h.auditWaiting(c, wt.User)
		c.answer(EnrolmentOutcome{WaitingApproval: true, RecoveryCode: wt.RecoveryCode.Reveal()})
		return
	}
	s := out.SignedIn
	h.setSignedIn(c.w, c.client.Secure, s)
	h.auditSuccess(c, s.User, s.Session)
	signed := signedInResponse(s)
	c.answer(EnrolmentOutcome{SignedIn: &signed})
}

func serveTOTPBegin(h *Handler, c *call) error {
	e, err := h.acct.BeginTOTP(c.r.Context(), c.p)
	if err != nil {
		return err
	}
	c.answer(TOTPBeginResponse{URI: e.URI.Reveal(), Text: e.Text.Reveal(), Ticket: e.Ticket.Reveal()})
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
	c.answer(RecoveryCodeIssuedResponse{RecoveryCode: done.RecoveryCode.Reveal()})
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
	c.answer(RecoveryCodeResponse{RecoveryCode: code.Reveal()})
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
	c.done()
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
	c.done()
	return nil
}
