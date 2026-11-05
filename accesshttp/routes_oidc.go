package accesshttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

// The pending-link cookie (§6.6): its seal purpose and lifetime.
const (
	pendingPurpose  = "oidc-pending"
	pendingLifetime = 10 * time.Minute
)

// maxCookieBytes bounds a cookie's name plus value: a user agent drops a
// longer one (RFC 6265bis section 5.6).
const maxCookieBytes = 4096

// errPendingTooLarge is a not-linked outcome whose pending link does not
// fit its cookie.
var errPendingTooLarge = errors.New("accesshttp: the pending link does not fit its cookie")

// pendingPayload is the pending link as sealed into its cookie.
type pendingPayload struct {
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
	UsernameHint string `json:"hint,omitempty"`
	Email        string `json:"email,omitempty"`
}

func serveOIDCStartSignIn(h *Handler, c *call) error {
	p, err := h.acct.AdmitOIDC(c.client)
	if err != nil {
		return err
	}
	q := queryOf[OIDCSignInQuery](c)
	authURL, err := p.Begin(c.w, c.r, h.acct.Authenticator().Cookie(), oidc.BeginRequest{Intent: oidc.IntentSignIn, Redirect: q.Redirect})
	if err != nil {
		return err
	}
	redirect(c.w, c.r, authURL)
	return nil
}

func serveOIDCStartLink(h *Handler, c *call) error { return h.startSessionFlow(c, oidc.IntentLink) }

func serveOIDCStartStepUp(h *Handler, c *call) error { return h.startSessionFlow(c, oidc.IntentStepUp) }

// startSessionFlow begins a link or step-up flow from c's session. The
// Sec-Fetch-Site check is the handler's own: CrossOriginProtection admits
// "none", which a session-bound start refuses.
func (h *Handler) startSessionFlow(c *call, intent oidc.Intent) error {
	if site, sent := c.r.Header["Sec-Fetch-Site"]; sent && !slices.Equal(site, []string{"same-origin"}) {
		return errCrossOrigin
	}
	req, err := decodeJSON[RedirectRequest](c.w, c.r)
	if err != nil {
		return err
	}
	p := h.acct.OIDCProvider()
	if p == nil {
		return account.ErrOIDCUnavailable
	}
	authURL, err := p.Begin(c.w, c.r, h.acct.Authenticator().Cookie(), oidc.BeginRequest{
		Intent: intent, SessionID: c.p.SessionID, UserID: c.p.User.ID, Redirect: req.Redirect,
	})
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, OIDCStartResponse{URL: authURL})
	return nil
}

// serveOIDCCallback answers every outcome with a redirect (§7.2's callback
// table), so it returns no error for fail to write.
func serveOIDCCallback(h *Handler, c *call) error {
	if flow, err := h.completeCallback(c); err != nil {
		h.redirectFailure(c, err, flow)
	}
	return nil
}

// completeCallback runs the callback to its redirect, or returns its
// failure with the Flow Finish opened, zero before the flow cookie opened.
func (h *Handler) completeCallback(c *call) (oidc.Flow, error) {
	p, err := h.acct.AdmitOIDC(c.client)
	if err != nil {
		return oidc.Flow{}, err
	}
	flow, claims, err := p.Finish(c.w, c.r, h.acct.Authenticator().Cookie(), oidc.Callback(queryOf[OIDCCallbackQuery](c)))
	if err != nil {
		return flow, err
	}
	out, err := h.acct.OIDCComplete(c.r.Context(), c.client, flow, claims)
	if err != nil {
		return flow, err
	}
	return flow, h.land(c, &out)
}

// land sets the cookies out carries and redirects per §7.2.
func (h *Handler) land(c *call, out *account.OIDCOutcome) error {
	switch out.Kind {
	case account.OutcomeSignedIn:
		h.setSignedIn(c.w, c.r, out.SignedIn)
		h.auditSuccess(c, out.SignedIn.User, out.SignedIn.Session)
		redirect(c.w, c.r, out.Redirect)
	case account.OutcomeLinked:
		h.setIssued(c.w, c.r, out.Issued)
		redirect(c.w, c.r, withMarker(out.Redirect, markerOIDC, "linked"))
	case account.OutcomeSteppedUp:
		h.setIssued(c.w, c.r, out.Issued)
		h.auditSuccess(c, nil, out.Issued.Session)
		redirect(c.w, c.r, withMarker(out.Redirect, markerOIDC, "stepped_up"))
	case account.OutcomeNotLinked:
		if err := h.setPendingLink(c, out.Pending); err != nil {
			return err
		}
		redirect(c.w, c.r, withMarker(h.signIn, markerOIDC, "not_linked"))
	default:
		return fmt.Errorf("accesshttp: unknown OIDC outcome %d", out.Kind)
	}
	return nil
}

// redirectFailure answers a callback failure: to the sealed redirect of a
// link or step-up flow Finish opened, else to SignInPath, with auth_error.
func (h *Handler) redirectFailure(c *call, err error, flow oidc.Flow) { //nolint:gocritic // hugeParam: the Flow Finish returned, read once
	e := h.refusal(c, err)
	target := h.signIn
	if flow.Intent == oidc.IntentLink || flow.Intent == oidc.IntentStepUp {
		target = flow.Redirect
	}
	redirect(c.w, c.r, withMarker(target, markerError, string(e.Code)))
}

// setPendingLink seals p into the pending cookie. A link whose payload Seal
// refuses as too large, or whose cookie name and value pass maxCookieBytes,
// sets no cookie and is errPendingTooLarge.
func (h *Handler) setPendingLink(c *call, p account.PendingLink) error {
	payload, err := json.Marshal(pendingPayload{Issuer: p.Identity.Issuer, Subject: p.Identity.Subject, UsernameHint: p.UsernameHint, Email: p.Email})
	if err != nil {
		return err
	}
	sealed, err := h.pending.Seal(pendingPurpose, payload, time.Now().Add(pendingLifetime))
	cfg := pendingCookie(h.acct.Authenticator().Cookie())
	switch {
	case errors.Is(err, access.ErrSealTooLarge), err == nil && len(cfg.CookieName(c.r))+len(sealed) > maxCookieBytes:
		h.log().WarnContext(c.r.Context(), "accesshttp: the OIDC pending link does not fit its cookie; none set", "payload_bytes", len(payload))
		return errPendingTooLarge
	case err != nil:
		return err
	}
	h.setPending(c.w, c.r, sealed)
	return nil
}

// readPending opens the pending cookie; false when there is none or it
// does not open.
func (h *Handler) readPending(r *http.Request) (account.PendingLink, bool) {
	cfg := pendingCookie(h.acct.Authenticator().Cookie())
	sealed := cfg.ReadCookie(r)
	if sealed == "" {
		return account.PendingLink{}, false
	}
	payload, err := h.pending.Open(pendingPurpose, sealed, time.Now())
	if err != nil {
		return account.PendingLink{}, false
	}
	var p pendingPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return account.PendingLink{}, false
	}
	return account.PendingLink{Identity: access.OIDCIdentity{Issuer: p.Issuer, Subject: p.Subject}, UsernameHint: p.UsernameHint, Email: p.Email}, true
}

func serveOIDCPending(h *Handler, c *call) error {
	p, ok := h.readPending(c.r)
	if !ok {
		return account.ErrNotFound
	}
	writeJSON(c.w, http.StatusOK, PendingLinkResponse{Issuer: p.Identity.Issuer, UsernameHint: p.UsernameHint, Email: p.Email})
	return nil
}

// serveOIDCLinkPending clears the pending cookie only once the link
// commits: a refusal (auth_already_linked, a lapsed recent auth) keeps it,
// so the user can act and retry. A cookie that does not open reaches
// LinkPendingOIDC as the zero PendingLink, which it refuses as not found.
// The body is the view the link committed with; no later read can fail
// after the cookies are set.
func serveOIDCLinkPending(h *Handler, c *call) error {
	pending, _ := h.readPending(c.r)
	is, me, err := h.acct.LinkPendingOIDC(c.r.Context(), c.p, pending)
	if err != nil {
		return err
	}
	h.clearPending(c.w, c.r)
	h.setIssued(c.w, c.r, is)
	writeJSON(c.w, http.StatusOK, meResponse(&me))
	return nil
}

func serveOIDCUnlink(h *Handler, c *call) error {
	if err := h.acct.UnlinkOIDC(c.r.Context(), c.p); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}
