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
	// Provision is the role CreatePendingOIDC may create the account with;
	// absent unless provisioning offered the creation.
	Provision *access.Role `json:"provision,omitempty"`
	// Invite is the stored hash of the invite CreatePendingOIDC may accept;
	// absent unless an invite's callback found its name taken.
	Invite       string `json:"invite,omitempty"`
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
	UsernameHint string `json:"hint,omitempty"`
	Email        string `json:"email,omitempty"`
	Suggested    string `json:"suggested,omitempty"`
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
	redirect(c.w, authURL)
	return nil
}

func serveOIDCStartLink(h *Handler, c *call) error { return h.startSessionFlow(c, oidc.IntentLink) }

func serveOIDCStartStepUp(h *Handler, c *call) error { return h.startSessionFlow(c, oidc.IntentStepUp) }

// serveInviteAcceptOIDC begins an invite's acceptance by OIDC; the
// invite's hash travels sealed in the flow cookie.
func serveInviteAcceptOIDC(h *Handler, c *call) error {
	if err := sameOriginFetch(c); err != nil {
		return err
	}
	req, err := decodeJSON[TokenRequest](c.w, c.r)
	if err != nil {
		return err
	}
	token, err := requireSecret("token", req.Token)
	if err != nil {
		return err
	}
	p, err := h.acct.AdmitOIDC(c.client)
	if err != nil {
		return err
	}
	begin, err := h.acct.AcceptInviteOIDCBegin(c.r.Context(), c.client, token)
	if err != nil {
		return err
	}
	authURL, err := p.Begin(c.w, c.r, h.acct.Authenticator().Cookie(), begin)
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, OIDCStartResponse{URL: authURL})
	return nil
}

// sameOriginFetch refuses a Sec-Fetch-Site other than same-origin, which
// Provider.Begin would refuse for every intent but sign-in; the check is
// the handler's own, because CrossOriginProtection admits "none".
func sameOriginFetch(c *call) error {
	if site, sent := c.r.Header["Sec-Fetch-Site"]; sent && !slices.Equal(site, []string{"same-origin"}) {
		return errCrossOrigin
	}
	return nil
}

// startSessionFlow begins a link or step-up flow from c's session.
func (h *Handler) startSessionFlow(c *call, intent oidc.Intent) error {
	if err := sameOriginFetch(c); err != nil {
		return err
	}
	req, err := decodeJSON[RedirectRequest](c.w, c.r)
	if err != nil {
		return err
	}
	p, err := h.acct.AdmitOIDCSession(c.client, c.p)
	if err != nil {
		return err
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
		h.setSignedIn(c.w, c.client.Secure, out.SignedIn)
		h.auditSuccess(c, out.SignedIn.User, out.SignedIn.Session)
		redirect(c.w, out.Redirect)
	case account.OutcomeLinked:
		h.setIssued(c.w, c.client.Secure, out.Issued)
		redirect(c.w, withMarker(out.Redirect, markerOIDC, oidcLinked))
	case account.OutcomeSteppedUp:
		h.setIssued(c.w, c.client.Secure, out.Issued)
		h.auditSuccess(c, nil, out.Issued.Session)
		redirect(c.w, withMarker(out.Redirect, markerOIDC, oidcSteppedUp))
	case account.OutcomeNotLinked:
		if err := h.setPendingLink(c, &out.Pending); err != nil {
			return err
		}
		redirect(c.w, withMarker(h.signIn, markerOIDC, oidcNotLinked))
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
	redirect(c.w, withMarker(target, markerError, string(e.Code)))
}

// setPendingLink seals p into the pending cookie. A link whose payload Seal
// refuses as too large, or whose cookie name and value pass maxCookieBytes,
// sets no cookie and is errPendingTooLarge.
func (h *Handler) setPendingLink(c *call, p *account.PendingLink) error {
	pp := pendingPayload{
		Issuer: p.Identity.Issuer, Subject: p.Identity.Subject, UsernameHint: p.UsernameHint, Email: p.Email,
		Suggested: p.SuggestedUsername, Invite: p.Invite.Reveal(),
	}
	if p.Provision != nil {
		pp.Provision = &p.Provision.Role
	}
	payload, err := json.Marshal(pp)
	if err != nil {
		return err
	}
	sealed, err := h.pending.Seal(pendingPurpose, payload, time.Now().Add(pendingLifetime))
	cfg := pendingCookie(h.acct.Authenticator().Cookie())
	switch {
	case errors.Is(err, access.ErrSealTooLarge), err == nil && len(cfg.CookieName(c.client.Secure))+len(sealed) > maxCookieBytes:
		h.log().WarnContext(c.r.Context(), "accesshttp: the OIDC pending link does not fit its cookie; none set", "payload_bytes", len(payload))
		return errPendingTooLarge
	case err != nil:
		return err
	}
	h.setPending(c.w, c.client.Secure, sealed)
	return nil
}

// readPending opens the pending cookie; false when there is none or it
// does not open.
func (h *Handler) readPending(c *call) (account.PendingLink, bool) {
	cfg := pendingCookie(h.acct.Authenticator().Cookie())
	sealed := cfg.ReadCookie(c.r, c.client.Secure)
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
	out := account.PendingLink{
		Identity: access.OIDCIdentity{Issuer: p.Issuer, Subject: p.Subject}, UsernameHint: p.UsernameHint, Email: p.Email, SuggestedUsername: p.Suggested,
		Invite: access.NewHash(p.Invite),
	}
	if p.Provision != nil {
		out.Provision = &account.Provision{Role: *p.Provision}
	}
	return out, true
}

// serveOIDCPending reads the pending cookie only once AdmitOIDC admits the
// request.
func serveOIDCPending(h *Handler, c *call) error {
	if _, err := h.acct.AdmitOIDC(c.client); err != nil {
		return err
	}
	p, ok := h.readPending(c)
	if !ok {
		return account.ErrNotFound
	}
	writeJSON(c.w, http.StatusOK, PendingLinkResponse{
		Issuer: p.Identity.Issuer, UsernameHint: p.UsernameHint, Email: p.Email,
		CanCreate: p.CanCreate(), SuggestedUsername: p.SuggestedUsername,
	})
	return nil
}

// serveOIDCCreatePending clears the pending cookie only once the account
// is created: a taken name keeps it for another pick. A cookie that does
// not open reaches CreatePendingOIDC as the zero PendingLink, which it
// refuses as not found.
func serveOIDCCreatePending(h *Handler, c *call) error {
	req, err := decodeJSON[PendingCreateRequest](c.w, c.r)
	if err != nil {
		return err
	}
	if _, admitErr := h.acct.AdmitOIDC(c.client); admitErr != nil {
		return admitErr
	}
	pending, _ := h.readPending(c)
	out, err := h.acct.CreatePendingOIDC(c.r.Context(), c.client, pending, req.Username)
	if err != nil {
		return err
	}
	h.clearPending(c.w, c.client.Secure)
	h.signedIn(c, out)
	return nil
}

// serveOIDCLinkByAdmin charges the IP's request window before it reads the
// pending cookie, and clears the cookie only once the link commits: a
// refused name or secret keeps it for another try. A cookie that does not
// open reaches LinkPendingOIDCByAdmin as the zero PendingLink, which it
// refuses as not found before any hash.
func serveOIDCLinkByAdmin(h *Handler, c *call) error {
	req, err := decodeJSON[PendingLinkByAdminRequest](c.w, c.r)
	if err != nil {
		return err
	}
	secret, err := requireSecret("temporary_password", req.TemporaryPassword)
	if err != nil {
		return err
	}
	c.username = canonical(req.Username)
	if _, admitErr := h.acct.AdmitOIDC(c.client); admitErr != nil {
		return admitErr
	}
	pending, _ := h.readPending(c)
	out, err := h.acct.LinkPendingOIDCByAdmin(c.r.Context(), c.client, pending, req.Username, secret)
	if err != nil {
		return err
	}
	h.clearPending(c.w, c.client.Secure)
	h.signedIn(c, out)
	return nil
}

// serveOIDCLinkPending clears the pending cookie only once the link
// commits: a refusal (auth_already_linked, a lapsed recent auth) keeps it,
// so the user can act and retry. A cookie that does not open reaches
// LinkPendingOIDC as the zero PendingLink, which it refuses as not found.
// The body is the view the link committed with; no later read can fail
// after the cookies are set.
func serveOIDCLinkPending(h *Handler, c *call) error {
	pending, _ := h.readPending(c)
	is, me, err := h.acct.LinkPendingOIDC(c.r.Context(), c.p, pending)
	if err != nil {
		return err
	}
	h.clearPending(c.w, c.client.Secure)
	h.setIssued(c.w, c.client.Secure, is)
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
