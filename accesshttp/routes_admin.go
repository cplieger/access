package accesshttp

import (
	"net/http"
	"strings"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// serveAdminUserCreate creates a user; an empty password creates one with
// no sign-in method.
func serveAdminUserCreate(h *Handler, c *call) error {
	req, err := decodeJSON[NewUserRequest](c.w, c.r)
	if err != nil {
		return err
	}
	password := access.NewSecret(req.Password)
	u, err := h.acct.CreateUser(c.r.Context(), account.As(c.p), account.NewUser{Password: password, Username: req.Username, Role: req.Role})
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusCreated, userView(u))
	return nil
}

// serveAdminUsers lists the users with their key lineage and methods,
// which only this list carries.
func serveAdminUsers(h *Handler, c *call) error {
	q := queryOf[AdminUsersQuery](c)
	users, err := h.acct.Users(c.r.Context(), c.p, account.UserFilter{AttributedToKey: q.Key})
	if err != nil {
		return err
	}
	views := make([]UserView, len(users))
	for i := range users {
		views[i] = listedUserView(&users[i])
	}
	writeJSON(c.w, http.StatusOK, views)
	return nil
}

func serveAdminUserUpdate(h *Handler, c *call) error {
	req, err := decodeJSON[UserUpdateRequest](c.w, c.r)
	if err != nil {
		return err
	}
	u, err := h.acct.UpdateUser(c.r.Context(), c.p, c.id, account.UserChange{Role: req.Role, Enabled: req.Enabled})
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, userView(u))
	return nil
}

// serveAdminOwner sets a user's owner flag.
func serveAdminOwner(h *Handler, c *call) error {
	req, err := decodeJSON[OwnerRequest](c.w, c.r)
	if err != nil {
		return err
	}
	u, err := h.acct.SetOwner(c.r.Context(), account.As(c.p), c.id, req.Owner)
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, userView(u))
	return nil
}

// serveAdminSSOReadiness reads what a change of the SSO mode would do; a
// state refusal is the body's, as authAdminSSOApply would answer it.
func serveAdminSSOReadiness(h *Handler, c *call) error {
	mode, ok := account.ParseSSOMode(queryOf[SSOReadinessQuery](c).Mode)
	if !ok {
		return account.ErrUnknownSSOMode
	}
	rd, err := h.acct.SSOReadiness(c.r.Context(), account.As(c.p), mode)
	if err != nil {
		return err
	}
	v := Readiness{
		LockedOut: rd.LockedOut, MethodsMadeDormant: rd.MethodsMadeDormant, MethodsRestored: rd.MethodsRestored,
		TemporaryPasswordsWithdrawn: rd.TemporaryPasswordsWithdrawn,
	}
	if rd.Refusal != nil {
		e, broken := routeError(rd.Refusal, ceremonyNone, c.desc.Codes)
		if broken {
			return rd.Refusal
		}
		v.Refusal = &ReadinessRefusal{Code: e.Code, Reason: e.Reason}
	}
	writeJSON(c.w, http.StatusOK, v)
	return nil
}

// serveAdminSSOApply changes the stored SSO mode.
func serveAdminSSOApply(h *Handler, c *call) error {
	req, err := decodeJSON[SSORequest](c.w, c.r)
	if err != nil {
		return err
	}
	mode, ok := account.ParseSSOMode(req.Mode)
	if !ok {
		return account.ErrUnknownSSOMode
	}
	if err := h.acct.ApplySSO(c.r.Context(), account.As(c.p), mode); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

func serveAdminUserDelete(h *Handler, c *call) error {
	if err := h.acct.DeleteUser(c.r.Context(), c.p, c.id); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

// serveAdminOIDCUnlink removes a user's identity-provider link.
func serveAdminOIDCUnlink(h *Handler, c *call) error {
	if err := h.acct.AdminUnlinkOIDC(c.r.Context(), account.As(c.p), c.id); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

// serveAdminTemporaryPassword issues a temporary password and answers it
// once, https_only read after the issue commits (account owns why).
func serveAdminTemporaryPassword(h *Handler, c *call) error {
	req, err := decodeJSON[TemporaryPasswordOptions](c.w, c.r)
	if err != nil {
		return err
	}
	in := account.TemporaryPasswordOptions{TTL: units(req.TTLHours, time.Hour), RevokePasskeys: req.RevokePasskeys, KeepKeys: req.KeepKeys}
	issued, err := h.acct.SetTemporaryPassword(c.r.Context(), account.As(c.p), c.id, in)
	if err != nil {
		return err
	}
	writeShownOnce(c.w, http.StatusOK, TemporaryPasswordResponse{
		ExpiresAt: issued.ExpiresAt, HTTPSOrigin: issued.HTTPSOrigin, HTTPSOnly: h.acct.TemporaryPasswordHTTPSOnly(issued),
		Dormant: issued.Dormant, PasswordKept: issued.PasswordKept,
	}, issued.Password)
	return nil
}

func serveAdminInvite(h *Handler, c *call) error {
	req, err := decodeJSON[InviteRequest](c.w, c.r)
	if err != nil {
		return err
	}
	it, err := h.acct.CreateInvite(c.r.Context(), c.p, req.Role, units(req.Hours, time.Hour))
	if err != nil {
		return err
	}
	writeToken(c, it)
	return nil
}

func serveAdminKeys(h *Handler, c *call) error {
	keys, err := h.acct.AllAPIKeys(c.r.Context(), account.As(c.p))
	if err != nil {
		return err
	}
	views, now := make([]KeyView, len(keys)), time.Now()
	for i := range keys {
		views[i] = keyView(&keys[i].Key, keys[i].Owner, now)
	}
	writeJSON(c.w, http.StatusOK, views)
	return nil
}

func serveAdminKeyRevoke(h *Handler, c *call) error {
	if err := h.acct.RevokeAnyAPIKey(c.r.Context(), account.As(c.p), c.id); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

func serveAdminTokens(h *Handler, c *call) error {
	tokens, err := h.acct.Tokens(c.r.Context(), c.p)
	if err != nil {
		return err
	}
	views := make([]TokenView, len(tokens))
	for i := range tokens {
		views[i] = tokenView(&tokens[i])
	}
	writeJSON(c.w, http.StatusOK, views)
	return nil
}

// serveAdminSecurityLog reads one security-log page. An empty kinds value
// is every kind; a non-empty one is split on ",", so an empty element
// reaches account as an empty kind, which it refuses.
func serveAdminSecurityLog(h *Handler, c *call) error {
	q := queryOf[AdminSecurityLogQuery](c)
	f := account.LogFilter{
		UserID: q.User, ActorUserID: q.Actor, ActorKeyID: q.ActorKey,
		AfterSeq: uint64(q.After), BeforeSeq: uint64(q.Before), //nolint:gosec // G115: the query decode admits only positive int64s, which a uint64 holds
		// Clamped before narrowing: on a 32-bit int an oversized limit would
		// wrap into a valid one, and account refuses MaxLogPage+1 as it is.
		Limit:       int(min(q.Limit, account.MaxLogPage+1)),
		OldestFirst: q.OldestFirst,
	}
	if q.Kinds != "" {
		for k := range strings.SplitSeq(q.Kinds, ",") {
			f.Kinds = append(f.Kinds, account.EventKind(k))
		}
	}
	page, err := h.acct.SecurityLog(c.r.Context(), c.p, f)
	if err != nil {
		return err
	}
	writeJSON(c.w, http.StatusOK, securityLogView(&page))
	return nil
}

// writeToken answers a minted invite token, its expiry the one
// account stored.
func writeToken(c *call, it account.IssuedToken) {
	writeShownOnce(c.w, http.StatusCreated, TokenResponse{ExpiresAt: it.ExpiresAt}, it.Plaintext)
}
