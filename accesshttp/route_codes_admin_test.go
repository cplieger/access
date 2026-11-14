package accesshttp

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// missingUserID is a user ID no fixture stores.
const missingUserID = "999"

// rootSession stores admin root and RoleUser alice, and returns root's full
// password session.
func (e *env) rootSession(t testing.TB) *http.Cookie {
	t.Helper()
	e.createUser(t, "root", access.RoleAdmin)
	e.createUser(t, "alice", access.RoleUser)
	return e.sessionCookie(t, "root")
}

// userID is name's stored ID as a path value.
func (e *env) userID(t testing.TB, name string) string {
	t.Helper()
	return strconv.FormatInt(e.user(t, name).ID, 10)
}

func adminScenarios() map[scenarioKey]scenario {
	out := map[scenarioKey]scenario{}
	// byAlice is alice's request on an admin route, which RolePolicy refuses
	// a RoleUser.
	byAlice := func(name, body string) scenario {
		return scenario{arrange: func(t *testing.T, e *env) *http.Request {
			e.rootSession(t)
			return e.at(t, name, e.userID(t, "root"), body, e.sessionCookie(t, "alice"))
		}}
	}
	byRoot := func(name string, id func(t *testing.T, e *env) string, body string) func(t *testing.T, e *env) *http.Request {
		return func(t *testing.T, e *env) *http.Request {
			cookie := e.rootSession(t)
			return e.at(t, name, id(t, e), body, cookie)
		}
	}
	aliceID := func(t *testing.T, e *env) string { return e.userID(t, "alice") }
	rootID := func(t *testing.T, e *env) string { return e.userID(t, "root") }
	missing := func(*testing.T, *env) string { return missingUserID }
	newUser := func(name, password string) string {
		return `{"username":"` + name + `","password":"` + password + `","role":"user"}`
	}
	enable := `{"enabled":false}`

	for _, name := range []string{"authAdminUsers", "authAdminKeys", "authAdminTokens", "authAdminSecurityLog"} {
		out[scenarioKey{name, access.CodeForbidden}] = byAlice(name, "")
		out[scenarioKey{name, access.CodeUnavailable}] = closing(envOptions{}, byRoot(name, missing, ""))
	}

	out[scenarioKey{"authAdminSecurityLog", access.CodeBadRequest}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.securityLog(t, "kinds=a.b,", e.rootSession(t))
	}}

	const create = "authAdminUserCreate"
	out[scenarioKey{create, access.CodeForbidden}] = byAlice(create, newUser("carol", testPassword))
	out[scenarioKey{create, access.CodeBusy}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		r := byRoot(create, missing, newUser("carol", testPassword))(t, e)
		e.holdBudget(t)
		return r
	}}
	out[scenarioKey{create, access.CodeUnavailable}] = closing(envOptions{}, byRoot(create, missing, newUser("carol", testPassword)))
	out[scenarioKey{create, access.CodeUsernameInvalid}] = scenario{arrange: byRoot(create, missing, newUser("", testPassword))}
	out[scenarioKey{create, access.CodeUsernameTaken}] = scenario{arrange: byRoot(create, missing, newUser("alice", testPassword))}
	out[scenarioKey{create, access.CodePasswordRejected}] = scenario{arrange: byRoot(create, missing, newUser("carol", "short"))}
	out[scenarioKey{create, access.CodeBreachCheckUnavailable}] = scenario{opts: breachDown, arrange: byRoot(create, missing, newUser("carol", testPassword))}

	const update, del = "authAdminUserUpdate", "authAdminUserDelete"
	out[scenarioKey{update, access.CodeForbidden}] = byAlice(update, enable)
	out[scenarioKey{update, access.CodeUnavailable}] = closing(envOptions{}, byRoot(update, aliceID, enable))
	out[scenarioKey{update, access.CodeBadRequest}] = scenario{arrange: byRoot(update, aliceID, `{}`)}
	out[scenarioKey{update, access.CodeNotFound}] = scenario{arrange: byRoot(update, missing, enable)}
	out[scenarioKey{del, access.CodeForbidden}] = byAlice(del, "")
	out[scenarioKey{del, access.CodeUnavailable}] = closing(envOptions{}, byRoot(del, aliceID, ""))
	out[scenarioKey{del, access.CodeNotFound}] = scenario{arrange: byRoot(del, missing, "")}

	const recovery, invite = "authAdminRecovery", "authAdminInvite"
	hours := func(n int) string { return `{"hours":` + strconv.Itoa(n) + `}` }
	out[scenarioKey{recovery, access.CodeForbidden}] = scenario{arrange: byRoot(recovery, rootID, hours(0))}
	out[scenarioKey{recovery, access.CodeUnavailable}] = closing(envOptions{}, byRoot(recovery, aliceID, hours(0)))
	out[scenarioKey{recovery, access.CodeBadRequest}] = scenario{arrange: byRoot(recovery, aliceID, hours(7*24+1))}
	out[scenarioKey{recovery, access.CodeNotFound}] = scenario{arrange: byRoot(recovery, missing, hours(0))}
	inviteBody := func(n int) string { return `{"role":"user","hours":` + strconv.Itoa(n) + `}` }
	out[scenarioKey{invite, access.CodeForbidden}] = byAlice(invite, inviteBody(0))
	out[scenarioKey{invite, access.CodeUnavailable}] = closing(envOptions{}, byRoot(invite, missing, inviteBody(0)))
	out[scenarioKey{invite, access.CodeBadRequest}] = scenario{arrange: byRoot(invite, missing, inviteBody(7*7*24+1))}

	const revoke = "authAdminKeyRevoke"
	aliceKey := func(t *testing.T, e *env) string {
		created, err := e.svc.CreateAPIKey(t.Context(), account.OutOfBand("test"), e.user(t, "alice").ID, account.NewKey{Label: "ci"})
		if err != nil {
			t.Fatalf("CreateAPIKey: %v", err)
		}
		return strconv.FormatInt(created.Key.ID, 10)
	}
	out[scenarioKey{revoke, access.CodeForbidden}] = byAlice(revoke, "")
	out[scenarioKey{revoke, access.CodeUnavailable}] = closing(envOptions{}, byRoot(revoke, aliceKey, ""))
	out[scenarioKey{revoke, access.CodeNotFound}] = scenario{arrange: byRoot(revoke, missing, "")}
	return out
}
