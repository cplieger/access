package accesshttp

import (
	"net/http"
	"strings"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// serveAdminUserCreate creates a user; an empty password creates one with
// no sign-in method until a recovery link.
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

func serveAdminUserDelete(h *Handler, c *call) error {
	if err := h.acct.DeleteUser(c.r.Context(), c.p, c.id); err != nil {
		return err
	}
	noContent(c.w)
	return nil
}

func serveAdminRecovery(h *Handler, c *call) error {
	req, err := decodeJSON[TTLRequest](c.w, c.r)
	if err != nil {
		return err
	}
	it, err := h.acct.IssueRecovery(c.r.Context(), account.As(c.p), c.id, units(req.Hours, time.Hour))
	if err != nil {
		return err
	}
	writeToken(c, it)
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
	views := make([]KeyView, len(keys))
	for i := range keys {
		views[i] = keyView(&keys[i].Key, keys[i].Owner)
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

// writeToken answers a minted invite or recovery token, its expiry the one
// account stored.
func writeToken(c *call, it account.IssuedToken) {
	writeShownOnce(c.w, http.StatusCreated, TokenResponse{ExpiresAt: it.ExpiresAt}, it.Plaintext)
}
