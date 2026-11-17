package accesshttp

import (
	"maps"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// retiringRequest is what one route sends for the walk: the user whose ID
// fills {id}, "" for none, and its body.
type retiringRequest struct {
	target string
	body   func(t testing.TB) string
}

func literal(body string) func(testing.TB) string { return func(testing.TB) string { return body } }

// Every route a key can reach, sorted by design Part 2's rule "A retiring
// secret cannot create or restore a way in" and 5.28. A route in
// keyIssuing issues a credential or changes a binding, so a key's
// superseded secret is refused there; keyGrantsNothing names why a route's
// writes stay open; keyReads write nothing.
var (
	keyIssuing = map[string]retiringRequest{
		"authKeyCreate": {body: func(t testing.TB) string { return keyBody(t, "child", scopeKeysName) }},
		"authAdminUserCreate": {body: func(t testing.TB) string {
			return jsonBody(t, NewUserRequest{Username: "carol", Password: testPassword})
		}},
		"authAdminInvite":            {body: literal(`{"role":"user"}`)},
		"authAdminUserUpdate":        {target: "dave", body: literal(`{"enabled":true}`)},
		"authAdminTemporaryPassword": {target: "alice", body: literal(`{}`)},
		"authAdminOIDCUnlink":        {target: "alice", body: literal("")},
		"authAdminOIDCRelink":        {target: "alice", body: literal(`{}`)},
		"authAdminSecondFactorReset": {target: "alice", body: literal("")},
	}
	keyGrantsNothing = map[string]string{
		"authAdminUserUpdate": "a disable, or a role change alone, removes access",
		"authAdminUserDelete": "deleting an account leaves no way in",
		"authAdminKeyRevoke":  "revoking any key is no new power and issues nothing",
		"authKeyRevoke":       "revoking the caller's own key removes access",
		"authKeyRename":       "a label is no authentication state",
	}
	keyReads = []string{"authKeys", "authAdminUsers", "authAdminSSOReadiness", "authAdminKeys", "authAdminTokens", "authAdminSecurityLog"}
)

// TestKeyRoutesClassified fails on a route a key can reach that the walk
// does not sort, so a new key route cannot skip the retiring-secret rule.
func TestKeyRoutesClassified(t *testing.T) {
	t.Parallel()
	reachable := map[string]bool{}
	for i := range specs {
		s := &specs[i]
		if s.scope == 0 {
			continue
		}
		reachable[s.name] = true
		_, issues := keyIssuing[s.name]
		_, open := keyGrantsNothing[s.name]
		read := slices.Contains(keyReads, s.name)
		switch {
		case !issues && !open && !read:
			t.Errorf("%s (%s) admits a key and is in no list of the retiring-secret walk", s.name, s.op)
		case read && (issues || open):
			t.Errorf("%s is listed as a read and as a write", s.name)
		case read != (s.method == http.MethodGet):
			t.Errorf("%s is %s, read %t: a key's reads are its GET routes", s.name, s.method, read)
		}
	}
	listed := slices.Concat(slices.Collect(maps.Keys(keyIssuing)), slices.Collect(maps.Keys(keyGrantsNothing)), keyReads)
	for _, name := range listed {
		if !reachable[name] {
			t.Errorf("the walk lists %s, which no key can reach", name)
		}
	}
}

// TestRetiringKeyIssuesNothing is design 5.28 through the wire: a key
// presenting the secret a rotation superseded gets 403 auth_forbidden,
// reason key_retiring, from every route in keyIssuing.
func TestRetiringKeyIssuesNothing(t *testing.T) {
	t.Parallel()
	for name, req := range keyIssuing {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, allScopes)
			e.rootSession(t)
			e.createUser(t, "dave", access.RoleUser)
			dave := e.user(t, "dave")
			dave.Enabled = false
			if err := e.mem.UpdateUser(t.Context(), dave); err != nil {
				t.Fatalf("disable dave: %v", err)
			}
			if err := e.mem.SetTOTP(t.Context(), access.TOTP{UserID: e.user(t, "alice").ID, Sealed: "sealed", CreatedAt: time.Now()}); err != nil {
				t.Fatalf("SetTOTP: %v", err)
			}
			key := e.mintKey(t, "root", account.NewKey{Label: "ops", Scopes: []string{scopeAdminName, scopeUsersName, scopeKeysName}})
			if _, err := e.svc.RotateAPIKey(t.Context(), account.OutOfBand("test"), key.Key.ID); err != nil {
				t.Fatalf("RotateAPIKey: %v", err)
			}
			id := ""
			if req.target != "" {
				id = e.userID(t, req.target)
			}
			w := do(e.route(t, name), bearer(e.at(t, name, id, req.body(t)), key.Plaintext))
			if got := e.requireRefused(t, w, access.CodeForbidden); got.Reason != account.ReasonKeyRetiring {
				t.Errorf("reason %q, want %s", got.Reason, account.ReasonKeyRetiring)
			}
		})
	}
}
