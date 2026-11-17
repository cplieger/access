package accesshttp

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// A key under CreateKeysScope lists, renames and revokes its
// own user's keys, and a key under AdminScope reads SSO readiness; a key
// without the scope is refused before the operation.
func TestKeyScopeRoutes(t *testing.T) {
	t.Parallel()
	t.Run("own_keys_by_key", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, allScopes)
		e.rootSession(t)
		k := e.mintKey(t, "root", account.NewKey{Label: "ci", Scopes: []string{scopeKeysName}})
		sibling := e.mintKey(t, "root", account.NewKey{Label: "agent"})
		id := strconv.FormatInt(sibling.Key.ID, 10)
		if w := do(e.route(t, "authKeys"), bearer(e.at(t, "authKeys", "", ""), k.Plaintext)); w.Code != http.StatusOK {
			t.Errorf("GET /apikeys by key = %d %s", w.Code, w.Body)
		}
		if w := do(e.route(t, "authKeyRename"), bearer(e.at(t, "authKeyRename", id, jsonBody(t, NameRequest{Name: "deploy"})), k.Plaintext)); w.Code != http.StatusNoContent {
			t.Errorf("PUT /apikeys/{id} by key = %d %s", w.Code, w.Body)
		}
		if w := do(e.route(t, "authKeyRevoke"), bearer(e.at(t, "authKeyRevoke", id, ""), k.Plaintext)); w.Code != http.StatusNoContent {
			t.Errorf("DELETE /apikeys/{id} by key = %d %s", w.Code, w.Body)
		}
	})
	t.Run("own_keys_without_the_scope", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, allScopes)
		e.rootSession(t)
		k := e.mintKey(t, "root", account.NewKey{Label: "ci", Scopes: []string{"read"}})
		w := do(e.route(t, "authKeys"), bearer(e.at(t, "authKeys", "", ""), k.Plaintext))
		e.requireRefused(t, w, access.CodeScopeRequired)
	})
	t.Run("readiness_by_admin_key", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, allScopes)
		e.rootSession(t)
		k := e.mintKey(t, "root", account.NewKey{Label: "ops", Scopes: []string{scopeAdminName}})
		if w := do(e.route(t, "authAdminSSOReadiness"), bearer(e.at(t, "authAdminSSOReadiness", "", ""), k.Plaintext)); w.Code != http.StatusOK {
			t.Errorf("GET /sso/readiness by an AdminScope key = %d %s", w.Code, w.Body)
		}
	})
	t.Run("readiness_by_non_owner_admin", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, envOptions{})
		e.rootSession(t)
		e.createUser(t, "kim", access.RoleAdmin)
		stale := e.storedSession(t, "kim", time.Hour, 0)
		if w := do(e.route(t, "authAdminSSOReadiness"), e.at(t, "authAdminSSOReadiness", "", "", stale)); w.Code != http.StatusOK {
			t.Errorf("GET /sso/readiness by a non-owner admin an hour after sign-in = %d %s", w.Code, w.Body)
		}
	})
}
