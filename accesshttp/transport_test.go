package accesshttp

import (
	"net/http"
	"testing"

	"github.com/cplieger/access"
)

// TestTransportChangedRoute pins the answer to a secure session's token
// sent over plain HTTP under the plain cookie name: 401
// auth_session_expired with reason transport_changed, and the session is
// gone.
func TestTransportChangedRoute(t *testing.T) {
	e := newEnv(t, perRequest)
	e.createUser(t, "alice", access.RoleUser)
	secure := e.sessionCookie(t, "alice")
	me := e.route(t, "authMe")
	const plain = "http://192.168.1.77:9847"
	plainName := e.jarNames(plain).session
	w := do(me, requestAt(plain, me.Path, me, "", &http.Cookie{Name: plainName, Value: secure.Value}))
	errs := e.errs.all()
	if w.Code != http.StatusUnauthorized || len(errs) != 1 || errs[0].Code != access.CodeSessionExpired || errs[0].Reason != "transport_changed" {
		t.Fatalf("plain authMe with a secure token: status %d, errors %+v; want 401 auth_session_expired transport_changed", w.Code, errs)
	}
	if _, found, _ := e.mem.SessionByHash(t.Context(), access.SessionHash(secure.Value)); found {
		t.Error("the session survived the refusal, want it revoked")
	}
	if w := do(me, request(me, "", secure)); w.Code != http.StatusUnauthorized {
		t.Errorf("the secure cookie after the revoke: status %d, want 401", w.Code)
	}
}
