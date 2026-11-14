package accesshttp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// scoped configures the non-empty key scopes and lists them, with read,
// in Rules.Scopes.
func scoped(admin, users, keys string) envOptions {
	return envOptions{
		edit: func(c *account.Config) { c.AdminScope, c.ManageUsersScope, c.CreateKeysScope = admin, users, keys },
		rules: func(r *account.Rules) {
			for _, s := range []string{admin, users, keys, "read"} {
				if s != "" {
					r.Scopes = append(r.Scopes, s)
				}
			}
		},
	}
}

const (
	scopeAdminName = "admin"
	scopeUsersName = "manage_users"
	scopeKeysName  = "create_keys"
)

// allScopes configures all three key scopes.
var allScopes = scoped(scopeAdminName, scopeUsersName, scopeKeysName)

// keyPrincipal is what the Authenticator grants key.
func (e *env) keyPrincipal(t testing.TB, key access.Secret) access.Principal {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testOrigin+"/", http.NoBody)
	p, err := e.authn.Authenticate(bearer(r, key))
	if err != nil {
		t.Fatalf("Authenticate(key): %v", err)
	}
	return p
}

// liveTokens is every live invite and recovery token as stored.
func (e *env) liveTokens(t testing.TB) []access.OneTimeToken {
	t.Helper()
	tokens, err := e.mem.LiveOneTimeTokens(t.Context(), []access.TokenPurpose{access.PurposeInvite, access.PurposeRecovery}, time.Now())
	if err != nil {
		t.Fatalf("LiveOneTimeTokens: %v", err)
	}
	return tokens
}

// object decodes the JSON object at path in body, the top level when path
// is empty.
func object(t testing.TB, body []byte, path ...string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	for _, key := range path {
		inner := m[key]
		m = nil
		if err := json.Unmarshal(inner, &m); err != nil {
			t.Fatalf("decode %s of %q: %v", key, body, err)
		}
	}
	return m
}

func TestRouteAuthAdminUsers(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.rootSession(t)
		views := decoded[[]UserView](t, e, do(e.route(t, "authAdminUsers"), e.post(t, "authAdminUsers", "", cookie)), http.StatusOK)
		if len(views) != 2 || views[0].Username != "root" || views[1].Username != "alice" || views[1].Role != access.RoleUser || views[0].ID >= views[1].ID {
			t.Errorf("users %+v, want root then alice by ID", views)
		}
	})
}

// TestAdminUsersCarryMethods: the admin list carries each user's password
// and passkey count, and no other UserView carries methods.
func TestAdminUsersCarryMethods(t *testing.T) {
	e := newEnv(t, passkeys)
	root := e.rootSession(t)
	e.enrol(t, "alice")
	e.enrol(t, "alice")
	now := time.Now()
	bob := &access.User{Username: "bob", Role: access.RoleUser, Enabled: true, WebAuthnHandle: access.GenerateWebAuthnHandle(), CreatedAt: now, UpdatedAt: now}
	if err := e.mem.CreateUser(t.Context(), bob); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	views := decoded[[]UserView](t, e, do(e.route(t, "authAdminUsers"), e.post(t, "authAdminUsers", "", root)), http.StatusOK)
	want := map[string]UserMethodsView{"root": {Password: true}, "alice": {Password: true, PasskeyCount: 2}, "bob": {}}
	for _, v := range views {
		if w, ok := want[v.Username]; !ok || v.Methods == nil || *v.Methods != w {
			t.Errorf("%s methods %+v, want %+v", v.Username, v.Methods, w)
		}
	}
	alice := e.sessionCookie(t, "alice")
	for name, body := range map[string][]byte{
		"authMe":      do(e.route(t, "authMe"), e.post(t, "authMe", "", alice)).Body.Bytes(),
		"authProfile": do(e.route(t, "authProfile"), e.post(t, "authProfile", jsonBody(t, ProfileRequest{DisplayName: "A"}), alice)).Body.Bytes(),
	} {
		if _, has := object(t, body, "user")["methods"]; has {
			t.Errorf("%s's user carries methods: %s", name, body)
		}
	}
	w := do(e.route(t, "authAdminUserUpdate"), e.at(t, "authAdminUserUpdate", e.userID(t, "alice"), `{"enabled":true}`, root))
	e.requireStatus(t, w, http.StatusOK)
	if _, has := object(t, w.Body.Bytes())["methods"]; has {
		t.Errorf("authAdminUserUpdate carries methods: %s", w.Body.String())
	}
}

func TestRouteAuthAdminUserCreate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.rootSession(t)
		view := decoded[UserView](t, e, do(e.route(t, "authAdminUserCreate"), e.post(t, "authAdminUserCreate", jsonBody(t, NewUserRequest{Username: "carol", Password: testPassword}), cookie)), http.StatusCreated)
		if u := e.user(t, "carol"); view.ID != u.ID || view.Role != access.RoleUser || !view.Enabled || view.Methods != nil || !e.signsIn(t, "carol", testPassword) {
			t.Errorf("view %+v, want the stored user carol, who signs in", view)
		}
	})
	t.Run("no_password", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.rootSession(t)
		e.requireStatus(t, do(e.route(t, "authAdminUserCreate"), e.post(t, "authAdminUserCreate", jsonBody(t, NewUserRequest{Username: "dave"}), cookie)), http.StatusCreated)
		if !e.user(t, "dave").PasswordHash.IsZero() {
			t.Error("dave holds a password")
		}
	})
}

func TestRouteAuthAdminUserUpdate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.rootSession(t)
		view := decoded[UserView](t, e, do(e.route(t, "authAdminUserUpdate"), e.at(t, "authAdminUserUpdate", e.userID(t, "alice"), `{"enabled":false}`, cookie)), http.StatusOK)
		if view.Username != "alice" || view.Enabled || e.user(t, "alice").Enabled {
			t.Errorf("view %+v, want alice disabled", view)
		}
	})
}

func TestRouteAuthAdminUserDelete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.rootSession(t)
		id := e.user(t, "alice").ID
		e.requireStatus(t, do(e.route(t, "authAdminUserDelete"), e.at(t, "authAdminUserDelete", strconv.FormatInt(id, 10), "", cookie)), http.StatusNoContent)
		if _, found, err := e.mem.UserByID(t.Context(), id); err != nil || found {
			t.Errorf("alice still stored (%v, %v)", found, err)
		}
	})
}

func TestRouteAuthAdminRecovery(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.rootSession(t)
		start := time.Now()
		resp := decoded[TokenResponse](t, e, do(e.route(t, "authAdminRecovery"), e.at(t, "authAdminRecovery", e.userID(t, "alice"), `{"hours":2}`, cookie)), http.StatusCreated)
		if resp.Token == "" || resp.ExpiresAt.Before(start.Add(2*time.Hour).Truncate(time.Second)) || resp.ExpiresAt.After(time.Now().Add(2*time.Hour)) {
			t.Errorf("response %+v, want a token expiring in 2 h", resp)
		}
	})
	t.Run("negative_hours", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.rootSession(t)
		w := do(e.route(t, "authAdminRecovery"), e.at(t, "authAdminRecovery", e.userID(t, "alice"), `{"hours":-1}`, cookie))
		if got := e.requireRefused(t, w, access.CodeBadRequest); got.Reason != ReasonTTLNegative || len(e.liveTokens(t)) != 0 {
			t.Errorf("reason %q, %d live tokens; want %s and none", got.Reason, len(e.liveTokens(t)), ReasonTTLNegative)
		}
	})
}

// TestAdminRecoverySelfRefused: an admin session's recovery link for its
// own user is refused with no token, while one for another user is issued.
func TestAdminRecoverySelfRefused(t *testing.T) {
	e := newEnv(t, envOptions{})
	cookie := e.rootSession(t)
	w := do(e.route(t, "authAdminRecovery"), e.at(t, "authAdminRecovery", e.userID(t, "root"), `{}`, cookie))
	if got := e.requireRefused(t, w, access.CodeForbidden); got.Reason != account.ReasonSelfRecovery {
		t.Errorf("reason %q, want %s", got.Reason, account.ReasonSelfRecovery)
	}
	if strings.Contains(w.Body.String(), "token") || len(e.liveTokens(t)) != 0 {
		t.Errorf("body %q, %d live tokens; want no token", w.Body.String(), len(e.liveTokens(t)))
	}
	e.requireStatus(t, do(e.route(t, "authAdminRecovery"), e.at(t, "authAdminRecovery", e.userID(t, "alice"), `{}`, cookie)), http.StatusCreated)
}

func TestRouteAuthAdminInvite(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.rootSession(t)
		start := time.Now()
		resp := decoded[TokenResponse](t, e, do(e.route(t, "authAdminInvite"), e.post(t, "authAdminInvite", `{"role":"user"}`, cookie)), http.StatusCreated)
		week := 7 * 24 * time.Hour
		if resp.Token == "" || resp.ExpiresAt.Before(start.Add(week).Truncate(time.Second)) || resp.ExpiresAt.After(time.Now().Add(week)) {
			t.Errorf("response %+v, want a token expiring in 7 days", resp)
		}
	})
	t.Run("negative_hours", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.rootSession(t)
		w := do(e.route(t, "authAdminInvite"), e.post(t, "authAdminInvite", `{"role":"user","hours":-1}`, cookie))
		if got := e.requireRefused(t, w, access.CodeBadRequest); got.Reason != ReasonTTLNegative || len(e.liveTokens(t)) != 0 {
			t.Errorf("reason %q, %d live tokens; want %s and none", got.Reason, len(e.liveTokens(t)), ReasonTTLNegative)
		}
	})
}

// TestAdminKeysOwner: the admin key list names each key's owner, and the
// caller's own list names none.
func TestAdminKeysOwner(t *testing.T) {
	e := newEnv(t, envOptions{})
	cookie := e.rootSession(t)
	e.createUser(t, "bob", access.RoleUser)
	want := map[int64]string{}
	for _, name := range []string{"root", "alice", "bob"} {
		want[e.mintKey(t, name, account.NewKey{Label: name + "-key"}).Key.ID] = name
	}
	views := decoded[[]KeyView](t, e, do(e.route(t, "authAdminKeys"), e.post(t, "authAdminKeys", "", cookie)), http.StatusOK)
	got := map[int64]string{}
	for _, v := range views {
		got[v.ID] = v.Owner
	}
	if !maps.Equal(got, want) {
		t.Errorf("owners %v, want %v", got, want)
	}
	own := decoded[[]KeyView](t, e, do(e.route(t, "authKeys"), e.post(t, "authKeys", "", cookie)), http.StatusOK)
	if len(own) != 1 || own[0].Owner != "" {
		t.Errorf("own keys %+v, want root's one with no owner", own)
	}
}

func TestRouteAuthAdminKeyRevoke(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		cookie := e.rootSession(t)
		key := e.mintKey(t, "alice", account.NewKey{Label: "ci"})
		e.requireStatus(t, do(e.route(t, "authAdminKeyRevoke"), e.at(t, "authAdminKeyRevoke", strconv.FormatInt(key.Key.ID, 10), "", cookie)), http.StatusNoContent)
		if keys, err := e.mem.ListAPIKeys(t.Context()); err != nil || len(keys) != 0 {
			t.Errorf("stored keys %+v, %v; want none", keys, err)
		}
	})
}

// TestAdminTokensListsLiveTokens is §9.5 "Views" for authAdminTokens.
func TestAdminTokensListsLiveTokens(t *testing.T) {
	e := newEnv(t, allScopes)
	root := e.rootSession(t)
	e.createUser(t, "bob", access.RoleUser)
	rootID := e.user(t, "root").ID
	k1 := e.mintKey(t, "root", account.NewKey{Label: "k1", Scopes: []string{scopeUsersName, scopeKeysName}})
	mintBy := func(parent access.Secret, label string, scopes ...string) account.CreatedKey {
		created, err := e.svc.CreateAPIKey(t.Context(), account.As(e.keyPrincipal(t, parent)), rootID, account.NewKey{Label: label, Scopes: scopes})
		if err != nil {
			t.Fatalf("CreateAPIKey(%s): %v", label, err)
		}
		return created
	}
	k2 := mintBy(k1.Plaintext, "k2", scopeUsersName, scopeKeysName)
	k3 := mintBy(k2.Plaintext, "k3", scopeUsersName)
	k3p := e.keyPrincipal(t, k3.Plaintext)
	keyInvite, err := e.svc.CreateInvite(t.Context(), k3p, access.RoleUser, 0)
	if err != nil {
		t.Fatalf("CreateInvite(k3): %v", err)
	}
	keyRecovery, err := e.svc.IssueRecovery(t.Context(), account.As(k3p), e.user(t, "alice").ID, 0)
	if err != nil {
		t.Fatalf("IssueRecovery(k3): %v", err)
	}
	sessionInvite, err := e.svc.CreateInvite(t.Context(), e.principal(t, root), access.RoleAdmin, 0)
	if err != nil {
		t.Fatalf("CreateInvite(root): %v", err)
	}
	now := time.Now()
	setupPlain, setupHash := access.GenerateOpaqueToken()
	expiredPlain, expiredHash := access.GenerateOpaqueToken()
	for _, tok := range []access.OneTimeToken{
		{Hash: setupHash, Purpose: access.PurposeSetup, CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
		{Hash: expiredHash, Purpose: access.PurposeRecovery, Subject: e.user(t, "bob").ID, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
	} {
		if err := e.mem.CreateOneTimeToken(t.Context(), tok); err != nil {
			t.Fatalf("CreateOneTimeToken(%s): %v", tok.Purpose, err)
		}
	}
	stored := e.liveTokens(t)
	if len(stored) != 3 {
		t.Fatalf("fixture: %d live invite and recovery tokens, want 3", len(stored))
	}

	list := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		return do(e.route(t, "authAdminTokens"), e.post(t, "authAdminTokens", "", cookie))
	}
	w := list(root)
	views := decoded[[]TokenView](t, e, w, http.StatusOK)
	path := k3.Key.LineageIDs
	if len(path) != 3 || path[0] != k1.Key.ID || path[1] != k2.Key.ID || path[2] != k3.Key.ID {
		t.Fatalf("fixture: k3's path %v, want k1, k2, k3", path)
	}
	var sawInvite, sawRecovery, sawSession bool
	for _, v := range views {
		i := slices.IndexFunc(stored, func(s access.OneTimeToken) bool {
			return s.Purpose == v.Purpose && s.IssuedByKey == v.IssuedByKey && s.Role == v.Role
		})
		if i < 0 || !v.CreatedAt.Equal(stored[i].CreatedAt) || !v.ExpiresAt.Equal(stored[i].ExpiresAt) || v.Subject != stored[i].Subject {
			t.Errorf("view %+v matches no stored token", v)
			continue
		}
		switch {
		case v.IssuedByKey == k3.Key.ID && v.Purpose == access.PurposeInvite:
			sawInvite = v.Role == access.RoleUser && v.Subject == 0 && slices.Equal(v.IssuerLineage, path)
		case v.IssuedByKey == k3.Key.ID && v.Purpose == access.PurposeRecovery:
			sawRecovery = v.Role == "" && v.Subject == e.user(t, "alice").ID && slices.Equal(v.IssuerLineage, path)
		case v.IssuedByKey == 0:
			sawSession = v.Role == access.RoleAdmin && v.IssuerLineage == nil
		}
	}
	if len(views) != 3 || !sawInvite || !sawRecovery || !sawSession {
		t.Errorf("tokens %+v, want k3's invite and recovery with k3's path and root's invite with none", views)
	}
	body := w.Body.String()
	secrets := []string{keyInvite.Plaintext.Reveal(), keyRecovery.Plaintext.Reveal(), sessionInvite.Plaintext.Reveal(), setupPlain.Reveal(), expiredPlain.Reveal(), setupHash.Reveal(), expiredHash.Reveal()}
	for i := range stored {
		secrets = append(secrets, stored[i].Hash.Reveal())
	}
	for _, s := range secrets {
		if strings.Contains(body, s) || strings.Contains(body, hex.EncodeToString([]byte(s))) {
			t.Errorf("the body holds a token, its hex or its hash: %s", body)
		}
	}
	if strings.Contains(body, string(access.PurposeSetup)) {
		t.Errorf("the body lists the setup token: %s", body)
	}

	t.Run("refused", func(t *testing.T) {
		alice := e.sessionCookie(t, "alice")
		for _, name := range []string{"authAdminTokens", "authAdminUsers"} {
			keyW := do(e.route(t, name), bearer(e.post(t, name, ""), k3.Plaintext))
			e.requireRefused(t, keyW, access.CodeScopeRequired)
			e.requireRefused(t, do(e.route(t, name), e.post(t, name, "", alice)), access.CodeForbidden)
		}
	})
	t.Run("issuer_revoked", func(t *testing.T) {
		e.requireStatus(t, do(e.route(t, "authKeyRevoke"), e.at(t, "authKeyRevoke", strconv.FormatInt(k3.Key.ID, 10), "", root)), http.StatusNoContent)
		after := decoded[[]TokenView](t, e, list(root), http.StatusOK)
		if len(after) != 1 || after[0].IssuedByKey != 0 {
			t.Errorf("tokens %+v after k3's revocation, want root's invite alone", after)
		}
	})
}

// TestKeyNeverMints: with ManageUsersScope and CreateKeysScope empty, an
// admin's key holding AdminScope mints nothing on the minting routes.
func TestKeyNeverMints(t *testing.T) {
	e := newEnv(t, scoped(scopeAdminName, "", ""))
	e.rootSession(t)
	key := e.mintKey(t, "root", account.NewKey{Label: "ops", Scopes: []string{scopeAdminName}})
	for name, body := range map[string]string{
		"authKeyCreate":       keyBody(t, "child"),
		"authAdminUserCreate": jsonBody(t, NewUserRequest{Username: "carol", Password: testPassword}),
		"authAdminInvite":     `{"role":"user"}`,
	} {
		t.Run(name, func(t *testing.T) {
			w := do(e.route(t, name), bearer(e.post(t, name, body), key.Plaintext))
			e.requireRefused(t, w, access.CodeSessionRequired)
		})
	}
	keys, err := e.mem.ListAPIKeys(t.Context())
	if n, _ := e.mem.UserCount(t.Context()); err != nil || len(keys) != 1 || n != 2 || len(e.liveTokens(t)) != 0 {
		t.Errorf("%d keys (%v), %d users, %d tokens; want the one key, root and alice, no token", len(keys), err, n, len(e.liveTokens(t)))
	}
}

// TestKeyPermissionRoutes: with both permission scopes set, each key mints
// only what its own permission grants.
func TestKeyPermissionRoutes(t *testing.T) {
	e := newEnv(t, allScopes)
	e.rootSession(t)
	keys := map[string]access.Secret{}
	for _, scope := range []string{scopeAdminName, scopeUsersName, scopeKeysName} {
		keys[scope] = e.mintKey(t, "root", account.NewKey{Label: scope, Scopes: []string{scope}}).Plaintext
	}
	mint := func(scope string) *httptest.ResponseRecorder {
		return do(e.route(t, "authKeyCreate"), bearer(e.post(t, "authKeyCreate", keyBody(t, "child")), keys[scope]))
	}
	create := func(scope, name string) *httptest.ResponseRecorder {
		return do(e.route(t, "authAdminUserCreate"), bearer(e.post(t, "authAdminUserCreate", jsonBody(t, NewUserRequest{Username: name, Password: testPassword})), keys[scope]))
	}
	t.Run("create_keys_mints", func(t *testing.T) {
		w := mint(scopeKeysName)
		e.requireStatus(t, w, http.StatusCreated)
		if c := w.Result().Cookies(); len(c) != 0 {
			t.Errorf("a key's mint set cookies %v", c)
		}
	})
	t.Run("manage_users_creates", func(t *testing.T) {
		e.requireStatus(t, create(scopeUsersName, "carol"), http.StatusCreated)
		e.user(t, "carol")
	})
	t.Run("other_scopes_refused", func(t *testing.T) {
		for _, scope := range []string{scopeAdminName, scopeUsersName} {
			e.requireRefused(t, mint(scope), access.CodeScopeRequired)
		}
		for _, scope := range []string{scopeAdminName, scopeKeysName} {
			e.requireRefused(t, create(scope, "dave"), access.CodeScopeRequired)
		}
		if _, found, err := e.mem.UserByUsername(t.Context(), "dave"); err != nil || found {
			t.Errorf("dave stored (%v, %v)", found, err)
		}
	})
}

// TestKeyAdminTargetRoutes: a manage_users key acts on RoleUser targets
// only, its tokens expire with it and die with it, and the users it touched
// list its lineage.
func TestKeyAdminTargetRoutes(t *testing.T) {
	e := newEnv(t, scoped("", scopeUsersName, ""))
	root := e.rootSession(t)
	e.createUser(t, "bob", access.RoleUser)
	key := e.mintKey(t, "root", account.NewKey{Label: "ops", Scopes: []string{scopeUsersName}, ExpiresIn: time.Hour})
	send := func(name, id, body string) *httptest.ResponseRecorder {
		return do(e.route(t, name), bearer(e.at(t, name, id, body), key.Plaintext))
	}
	rootID, aliceID := e.userID(t, "root"), e.userID(t, "alice")

	t.Run("admin_target_refused", func(t *testing.T) {
		for _, c := range []struct{ label, name, id, body string }{
			{"create_admin", "authAdminUserCreate", "", jsonBody(t, NewUserRequest{Username: "eve", Password: testPassword, Role: access.RoleAdmin})},
			{"promote", "authAdminUserUpdate", aliceID, `{"role":"admin"}`},
			{"invite_admin", "authAdminInvite", "", `{"role":"admin"}`},
			{"update_admin", "authAdminUserUpdate", rootID, `{"enabled":false}`},
			{"delete_admin", "authAdminUserDelete", rootID, ""},
			{"recover_admin", "authAdminRecovery", rootID, `{}`},
		} {
			t.Run(c.label, func(t *testing.T) {
				e.requireRefused(t, send(c.name, c.id, c.body), access.CodeForbidden)
			})
		}
		n, err := e.mem.UserCount(t.Context())
		if r, a := e.user(t, "root"), e.user(t, "alice"); err != nil || n != 3 || r.Role != access.RoleAdmin || !r.Enabled || a.Role != access.RoleUser || len(e.liveTokens(t)) != 0 {
			t.Errorf("after the refusals: %d users (%v), root %+v, alice %+v, %d tokens; want nothing written", n, err, r, a, len(e.liveTokens(t)))
		}
	})

	var invite, aliceRecovery TokenResponse
	t.Run("tokens_expire_with_the_key", func(t *testing.T) {
		invite = decoded[TokenResponse](t, e, send("authAdminInvite", "", `{"role":"user"}`), http.StatusCreated)
		aliceRecovery = decoded[TokenResponse](t, e, send("authAdminRecovery", aliceID, `{}`), http.StatusCreated)
		for _, got := range []TokenResponse{invite, aliceRecovery} {
			if !got.ExpiresAt.Equal(key.Key.ExpiresAt) {
				t.Errorf("expires_at %v, want the key's %v", got.ExpiresAt, key.Key.ExpiresAt)
			}
		}
	})
	e.requireStatus(t, send("authAdminUserCreate", "", jsonBody(t, NewUserRequest{Username: "carol", Password: testPassword})), http.StatusCreated)
	bobRecovery := decoded[TokenResponse](t, e, send("authAdminRecovery", e.userID(t, "bob"), `{}`), http.StatusCreated)
	started := do(e.route(t, "authRecoveryStart"), e.post(t, "authRecoveryStart", jsonBody(t, TokenRequest{Token: bobRecovery.Token})))
	e.requireStatus(t, started, http.StatusOK)
	sessionName, _ := e.names()
	recovery := cookieNamed(started, sessionName)
	e.requireStatus(t, do(e.route(t, "authRecoveryPassword"), e.post(t, "authRecoveryPassword", recoveryPasswordBody(t, newPassword), recovery)), http.StatusNoContent)
	e.requireStatus(t, do(e.route(t, "authKeyRevoke"), e.at(t, "authKeyRevoke", strconv.FormatInt(key.Key.ID, 10), "", root)), http.StatusNoContent)

	t.Run("tokens_die_with_the_key", func(t *testing.T) {
		for name, body := range map[string]string{
			"authInviteAcceptPassword": jsonBody(t, InviteAcceptRequest{Token: invite.Token, Username: "invitee", Password: testPassword}),
			"authRecoveryStart":        jsonBody(t, TokenRequest{Token: aliceRecovery.Token}),
		} {
			w := do(e.route(t, name), e.post(t, name, body))
			e.requireRefused(t, w, access.CodeTokenInvalid)
			if c := w.Result().Cookies(); len(c) != 0 {
				t.Errorf("%s set cookies %v", name, c)
			}
		}
	})

	users := func(rawQuery string) *httptest.ResponseRecorder {
		r := e.post(t, "authAdminUsers", "", root)
		r.URL.RawQuery = rawQuery
		return do(e.route(t, "authAdminUsers"), r)
	}
	t.Run("lineage", func(t *testing.T) {
		attributed := decoded[[]UserView](t, e, users("key="+strconv.FormatInt(key.Key.ID, 10)), http.StatusOK)
		names := map[string]bool{}
		for _, v := range attributed {
			names[v.Username] = len(v.KeyLineage) > 0 && v.KeyLineage[len(v.KeyLineage)-1] == key.Key.ID
		}
		if len(attributed) != 2 || !names["carol"] || !names["bob"] {
			t.Errorf("users attributed to the key %+v, want carol and bob with lineage ending in %d", attributed, key.Key.ID)
		}
		for _, v := range decoded[[]UserView](t, e, users(""), http.StatusOK) {
			if (v.Username == "root" || v.Username == "alice") && v.KeyLineage != nil {
				t.Errorf("%s lists key_lineage %v, which no key touched", v.Username, v.KeyLineage)
			}
		}
		updated := do(e.route(t, "authAdminUserUpdate"), e.at(t, "authAdminUserUpdate", e.userID(t, "carol"), `{"enabled":true}`, root))
		e.requireStatus(t, updated, http.StatusOK)
		me := do(e.route(t, "authMe"), e.post(t, "authMe", "", e.sessionCookie(t, "carol")))
		e.requireStatus(t, me, http.StatusOK)
		if _, has := object(t, updated.Body.Bytes())["key_lineage"]; has {
			t.Errorf("authAdminUserUpdate carries key_lineage: %s", updated.Body.String())
		}
		if _, has := object(t, me.Body.Bytes(), "user")["key_lineage"]; has {
			t.Errorf("authMe carries key_lineage: %s", me.Body.String())
		}
	})
	t.Run("bad_key_query", func(t *testing.T) {
		for _, q := range []string{"key=0", "key=-1", "key=x", "key=1&key=2"} {
			if got := e.requireRefused(t, users(q), access.CodeBadRequest); got.Reason != "key" {
				t.Errorf("%s: reason %q, want key", q, got.Reason)
			}
		}
	})
}

// TestKeysAdminOnlyRoute is §9.5 "Key minting policy" through authKeyCreate.
func TestKeysAdminOnlyRoute(t *testing.T) {
	mint := func(e *env, cookie *http.Cookie, scopes ...string) *httptest.ResponseRecorder {
		return do(e.route(t, "authKeyCreate"), e.post(t, "authKeyCreate", keyBody(t, "ci "+strings.Join(scopes, " "), scopes...), cookie))
	}
	// refused checks a refused mint: the code, no key and no rotation.
	refused := func(t *testing.T, e *env, w *httptest.ResponseRecorder, reason string) {
		t.Helper()
		if got := e.requireRefused(t, w, access.CodeForbidden); reason != "" && got.Reason != reason {
			t.Errorf("reason %q, want %s", got.Reason, reason)
		}
		keys, err := e.mem.ListAPIKeysByUserID(t.Context(), e.user(t, "alice").ID)
		if err != nil || len(keys) != 0 || len(w.Result().Cookies()) != 0 {
			t.Errorf("%d keys (%v), cookies %v; want none of either", len(keys), err, w.Result().Cookies())
		}
	}
	t.Run("keys_admin_only", func(t *testing.T) {
		e := newEnv(t, envOptions{edit: func(c *account.Config) { c.Policy = account.RolePolicy{KeysAdminOnly: true} }})
		root := e.rootSession(t)
		alice := e.sessionCookie(t, "alice")
		refused(t, e, mint(e, alice), "")
		e.requireStatus(t, mint(e, root), http.StatusCreated)
		key := e.mintKey(t, "alice", account.NewKey{Label: "oob"})
		listed := decoded[[]KeyView](t, e, do(e.route(t, "authKeys"), e.post(t, "authKeys", "", alice)), http.StatusOK)
		if len(listed) != 1 || listed[0].ID != key.Key.ID {
			t.Fatalf("alice's keys %+v, want the out-of-band one", listed)
		}
		e.requireStatus(t, do(e.route(t, "authKeyRevoke"), e.at(t, "authKeyRevoke", strconv.FormatInt(key.Key.ID, 10), "", alice)), http.StatusNoContent)
	})
	t.Run("any_user", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.requireStatus(t, mint(e, e.aliceSession(t)), http.StatusCreated)
	})
	t.Run("permission_scopes", func(t *testing.T) {
		e := newEnv(t, allScopes)
		root := e.rootSession(t)
		alice := e.sessionCookie(t, "alice")
		for _, scope := range []string{scopeAdminName, scopeUsersName, scopeKeysName} {
			refused(t, e, mint(e, alice, scope), account.ReasonPermissionNotAdmin)
		}
		e.requireStatus(t, mint(e, alice, "read"), http.StatusCreated)
		sessionName, _ := e.names()
		for _, scope := range []string{scopeAdminName, scopeUsersName, scopeKeysName} {
			w := mint(e, root, scope)
			e.requireStatus(t, w, http.StatusCreated)
			root = cookieNamed(w, sessionName)
		}
	})
}

// TestShownOnceRoutes: each show-once body holds its plaintext exactly
// once, in its key or token field, and that plaintext works.
func TestShownOnceRoutes(t *testing.T) {
	e := newEnv(t, envOptions{})
	root := e.rootSession(t)
	alice := e.sessionCookie(t, "alice")
	once := func(t *testing.T, body, plaintext string) {
		t.Helper()
		if plaintext == "" || strings.Count(body, plaintext) != 1 {
			t.Errorf("body %s holds %q %d times, want once", body, plaintext, strings.Count(body, plaintext))
		}
	}
	t.Run("authKeyCreate", func(t *testing.T) {
		w := do(e.route(t, "authKeyCreate"), e.post(t, "authKeyCreate", keyBody(t, "ci"), alice))
		resp := decoded[KeyCreatedResponse](t, e, w, http.StatusCreated)
		once(t, w.Body.String(), resp.Key)
		if p := e.keyPrincipal(t, access.NewSecret(resp.Key)); p.KeyID != resp.Details.ID {
			t.Errorf("the key authenticates as key %d, want %d", p.KeyID, resp.Details.ID)
		}
	})
	t.Run("authAdminRecovery", func(t *testing.T) {
		w := do(e.route(t, "authAdminRecovery"), e.at(t, "authAdminRecovery", e.userID(t, "alice"), `{}`, root))
		resp := decoded[TokenResponse](t, e, w, http.StatusCreated)
		once(t, w.Body.String(), resp.Token)
		if rec, err := e.svc.StartRecovery(t.Context(), account.Client{}, access.NewSecret(resp.Token)); err != nil || rec.Username != "alice" {
			t.Errorf("StartRecovery = %+v, %v; want alice's recovery", rec, err)
		}
	})
	t.Run("authAdminInvite", func(t *testing.T) {
		w := do(e.route(t, "authAdminInvite"), e.post(t, "authAdminInvite", `{"role":"user"}`, root))
		resp := decoded[TokenResponse](t, e, w, http.StatusCreated)
		once(t, w.Body.String(), resp.Token)
		in := account.AcceptInvite{Token: access.NewSecret(resp.Token), Username: "invitee", Password: access.NewSecret(testPassword)}
		if _, err := e.svc.AcceptInvitePassword(t.Context(), account.Client{}, in); err != nil {
			t.Errorf("AcceptInvitePassword: %v", err)
		}
	})
}

// TestRulesReloadInvalidHTTP is §9.5 "Breach client on reload" through
// authPasswordSet.
func TestRulesReloadInvalidHTTP(t *testing.T) {
	failOpen := &atomic.Bool{}
	e := newEnv(t, envOptions{rules: func(r *account.Rules) {
		if failOpen.Load() {
			r.Breach = account.BreachFailOpen
		}
	}})
	cookie := e.aliceSession(t)
	before := e.user(t, "alice").PasswordHash
	errorsBefore := countLevel(e, slog.LevelError)
	failOpen.Store(true)
	w := do(e.route(t, "authPasswordSet"), e.post(t, "authPasswordSet", passwordSetBody(t, testPassword, newPassword), cookie))
	e.requireRefused(t, w, access.CodeUnavailable)
	if n := countLevel(e, slog.LevelError) - errorsBefore; n != 1 {
		t.Errorf("%d ERROR logs, want one", n)
	}
	if !e.user(t, "alice").PasswordHash.Equal(before) || !e.authenticates(t, cookie) || len(w.Result().Cookies()) != 0 {
		t.Error("the refused change wrote: the hash or the session moved")
	}
}

// countLevel counts e's log records at level.
func countLevel(e *env, level slog.Level) int {
	n := 0
	for _, r := range e.logs.Records("") {
		if r.Level == level {
			n++
		}
	}
	return n
}

// securityLog is authAdminSecurityLog's request with rawQuery.
func (e *env) securityLog(t testing.TB, rawQuery string, cookies ...*http.Cookie) *http.Request {
	t.Helper()
	rt := e.route(t, "authAdminSecurityLog")
	return requestAt(testOrigin, rt.Path+"?"+rawQuery, rt, "", cookies...)
}

// appendApp appends an app entry made by a through the Service.
func (e *env) appendApp(t testing.TB, a account.Actor, in account.AppEntry) {
	t.Helper()
	in.Actor = a
	if err := e.mem.Update(t.Context(), func(tx account.Tx) error {
		_, err := e.svc.AppendLog(t.Context(), tx, in)
		return err
	}); err != nil {
		t.Fatalf("AppendLog(%s): %v", in.Kind, err)
	}
}

// filterSpy records the LogFilter each SecurityLog call gets.
type filterSpy struct {
	accountAPI
	got *recorded[account.LogFilter]
}

func (s filterSpy) SecurityLog(ctx context.Context, p access.Principal, f account.LogFilter) (account.LogPage, error) {
	s.got.add(f)
	return s.accountAPI.SecurityLog(ctx, p, f)
}

// requireEntryView checks that v carries every field of the stored e.
func requireEntryView(t *testing.T, v LogEntryView, e *account.LogEntry) {
	t.Helper()
	ev := &e.Event
	ip := ""
	if e.IP.IsValid() {
		ip = e.IP.String()
	}
	want := LogActorView{
		UserID: ev.Actor.UserID, SessionID: ev.Actor.SessionID, KeyID: ev.Actor.KeyID, OutOfBand: ev.Actor.OutOfBand,
		Label: e.ActorLabel, UserAgent: e.ActorUserAgent, KeySuffix: e.ActorKeySuffix,
	}
	if v.Seq != int64(ev.Seq) || !v.At.Equal(e.At) || !v.OccurredAt.Equal(ev.At) || v.Class != e.Class || v.Kind != string(ev.Kind) ||
		v.UserID != ev.UserID || v.IP != ip || !slices.Equal(v.SessionIDs, ev.SessionIDs) || v.KeyID != ev.KeyID ||
		v.PasskeyID != ev.PasskeyID || v.Method != ev.Method || v.Role != ev.Role || v.Trusted != ev.Trusted ||
		v.Detail != e.Detail || v.Actor != want {
		t.Errorf("view %+v, want the entry %+v", v, *e)
	}
}

// TestAdminSecurityLog is authAdminSecurityLog: the page, its query keys,
// its refusals and its gate.
func TestAdminSecurityLog(t *testing.T) {
	t.Run("page", func(t *testing.T) {
		spy := &recorded[account.LogFilter]{}
		e := newEnv(t, with(allScopes, envOptions{wrap: func(_ *env, s *account.Service) accountAPI { return filterSpy{accountAPI: s, got: spy} }}))
		root := e.rootSession(t)
		rootP := e.principal(t, root)
		rootP.IP = netip.MustParseAddr("192.0.2.7")
		if err := e.svc.RenameSession(t.Context(), rootP, account.SessionLabel{ID: rootP.SessionID, Label: "laptop"}); err != nil {
			t.Fatalf("RenameSession: %v", err)
		}
		if _, err := e.svc.PasswordLogin(t.Context(), account.Client{UserAgent: "Firefox"}, account.Credentials{Username: "alice", Password: access.NewSecret(testPassword)}); err != nil {
			t.Fatalf("PasswordLogin: %v", err)
		}
		if _, err := e.svc.CreateInvite(t.Context(), rootP, access.RoleAdmin, 0); err != nil {
			t.Fatalf("CreateInvite: %v", err)
		}
		key := e.mintKey(t, "root", account.NewKey{Label: "ci", Scopes: []string{scopeAdminName}})
		e.appendApp(t, account.As(rootP), account.AppEntry{Kind: "app.setting", Method: access.MethodPassword, Detail: "password sign-in on"})
		e.appendApp(t, account.As(e.keyPrincipal(t, key.Plaintext)), account.AppEntry{Kind: "app.reset"})
		stored, err := e.mem.ListLog(t.Context(), account.LogRange{Limit: account.MaxLogPage, Descending: true})
		if err != nil || len(stored) < 5 {
			t.Fatalf("ListLog = %d entries, %v; want the fixture's", len(stored), err)
		}

		page := decoded[SecurityLogView](t, e, do(e.route(t, "authAdminSecurityLog"), e.securityLog(t, "", root)), http.StatusOK)
		if len(page.Entries) != len(stored) {
			t.Fatalf("%d entries, want the %d stored", len(page.Entries), len(stored))
		}
		for i := range stored {
			requireEntryView(t, page.Entries[i], &stored[i])
		}
		want := []LogClassView{{Class: account.LogClassChange}, {Class: account.LogClassSession}}
		for _, st := range stored {
			want[slices.IndexFunc(want, func(c LogClassView) bool { return c.Class == st.Class })].Count++
		}
		if !slices.Equal(page.Classes, want) {
			t.Errorf("classes %+v, want %+v", page.Classes, want)
		}

		decoded[SecurityLogView](t, e, do(e.route(t, "authAdminSecurityLog"), e.securityLog(t, "kinds=", root)), http.StatusOK)
		decoded[SecurityLogView](t, e, do(e.route(t, "authAdminSecurityLog"), e.securityLog(t, "user=3&actor=4&actor_key=5&after=6&before=9&limit=7&kinds=a.b,signed_in", root)), http.StatusOK)
		decoded[SecurityLogView](t, e, do(e.route(t, "authAdminSecurityLog"), e.securityLog(t, "oldest_first=true", root)), http.StatusOK)
		decoded[SecurityLogView](t, e, do(e.route(t, "authAdminSecurityLog"), e.securityLog(t, "after=6&oldest_first=true", root)), http.StatusOK)
		got := spy.all()
		wantFilters := []account.LogFilter{
			{},
			{},
			{UserID: 3, ActorUserID: 4, ActorKeyID: 5, AfterSeq: 6, BeforeSeq: 9, Limit: 7, Kinds: []account.EventKind{"a.b", account.EventSignedIn}},
			{OldestFirst: true},
			{AfterSeq: 6, OldestFirst: true},
		}
		if len(got) != len(wantFilters) {
			t.Fatalf("filters %+v, want %+v", got, wantFilters)
		}
		for i := range got {
			if !reflect.DeepEqual(got[i], wantFilters[i]) {
				t.Errorf("filter %d = %+v, want %+v", i, got[i], wantFilters[i])
			}
		}
	})
	t.Run("empty", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		root := e.rootSession(t)
		w := do(e.route(t, "authAdminSecurityLog"), e.securityLog(t, "kinds=app.none", root))
		page := decoded[SecurityLogView](t, e, w, http.StatusOK)
		if len(page.Entries) != 0 || !strings.Contains(w.Body.String(), `"entries":[]`) {
			t.Errorf("body %s, want an empty entries array", w.Body.String())
		}
	})
	t.Run("refused", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		root := e.rootSession(t)
		refusals := map[string]string{
			"kinds=a.b,": account.ReasonLogKind,
			"limit=501":  account.ReasonLogLimit,
			// 2^32 and 2^32+50, which a 32-bit int would wrap to 0 and 50.
			"limit=4294967296": account.ReasonLogLimit,
			"limit=4294967346": account.ReasonLogLimit,
		}
		for _, key := range []string{"user", "actor", "actor_key", "after", "before", "limit"} {
			for _, raw := range []string{key + "=0", key + "=-1", key + "=x", key + "=1&" + key + "=2"} {
				refusals[raw] = key
			}
		}
		for _, raw := range []string{"oldest_first=false", "oldest_first=1", "oldest_first=", "oldest_first=true&oldest_first=true"} {
			refusals[raw] = "oldest_first"
		}
		for raw, reason := range refusals {
			if got := e.requireRefused(t, do(e.route(t, "authAdminSecurityLog"), e.securityLog(t, raw, root)), access.CodeBadRequest); got.Reason != reason {
				t.Errorf("%s: reason %q, want %q", raw, got.Reason, reason)
			}
		}
		e.requireRefused(t, do(e.route(t, "authAdminSecurityLog"), e.securityLog(t, "", e.sessionCookie(t, "alice"))), access.CodeForbidden)
	})
	t.Run("evicted", func(t *testing.T) {
		e := newEnv(t, envOptions{edit: func(c *account.Config) { c.LogMaxChanges = 2 }})
		root := e.rootSession(t)
		for range 5 {
			e.appendApp(t, account.OutOfBand("test"), account.AppEntry{Kind: "app.tick"})
		}
		page := decoded[SecurityLogView](t, e, do(e.route(t, "authAdminSecurityLog"), e.securityLog(t, "", root)), http.StatusOK)
		if len(page.Classes) != 2 || page.Classes[0] != (LogClassView{Class: account.LogClassChange, Count: 2, Evicted: 3}) {
			t.Errorf("classes %+v, want change with 2 kept and 3 evicted", page.Classes)
		}
	})
	t.Run("keys", func(t *testing.T) {
		scopedEnv := newEnv(t, scoped(scopeAdminName, "", ""))
		scopedEnv.rootSession(t)
		admin := scopedEnv.mintKey(t, "root", account.NewKey{Label: "admin", Scopes: []string{scopeAdminName}})
		read := scopedEnv.mintKey(t, "root", account.NewKey{Label: "read", Scopes: []string{"read"}})
		decoded[SecurityLogView](t, scopedEnv, do(scopedEnv.route(t, "authAdminSecurityLog"), bearer(scopedEnv.securityLog(t, ""), admin.Plaintext)), http.StatusOK)
		scopedEnv.requireRefused(t, do(scopedEnv.route(t, "authAdminSecurityLog"), bearer(scopedEnv.securityLog(t, ""), read.Plaintext)), access.CodeScopeRequired)

		open := newEnv(t, envOptions{})
		open.rootSession(t)
		k := open.mintKey(t, "root", account.NewKey{Label: "ci"})
		open.requireRefused(t, do(open.route(t, "authAdminSecurityLog"), bearer(open.securityLog(t, ""), k.Plaintext)), access.CodeSessionRequired)
	})
}
