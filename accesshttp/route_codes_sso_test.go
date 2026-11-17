package accesshttp

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// ssoScenarios reach the codes of the two SSO-mode routes.
func ssoScenarios() map[scenarioKey]scenario {
	out := map[scenarioKey]scenario{}
	const readiness, apply = "authAdminSSOReadiness", "authAdminSSOApply"
	body := `{"mode":"for_linked"}`
	byRoot := func(name, body string) func(t *testing.T, e *env) *http.Request {
		return func(t *testing.T, e *env) *http.Request { return e.at(t, name, "", body, e.rootSession(t)) }
	}
	unwired := envOptions{edit: func(c *account.Config) { c.OIDC = nil }}
	for name, b := range map[string]string{readiness: "", apply: body} {
		out[scenarioKey{name, access.CodeForbidden}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
			e.rootSession(t)
			return e.at(t, name, "", b, e.sessionCookie(t, "alice"))
		}}
		out[scenarioKey{name, access.CodeUnavailable}] = closing(envOptions{}, byRoot(name, b))
		out[scenarioKey{name, access.CodeOIDCUnavailable}] = scenario{opts: unwired, arrange: byRoot(name, b)}
	}
	// An unknown mode is account.ErrUnknownSSOMode, which carries no reason.
	out[scenarioKey{readiness, access.CodeBadRequest}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		r := byRoot(readiness, "")(t, e)
		r.URL.RawQuery = "mode=nope"
		return r
	}}
	out[scenarioKey{apply, access.CodeBadRequest}] = scenario{arrange: byRoot(apply, `{"mode":"nope"}`)}
	return out
}

// authAdminSSOApply answers a state refusal with exactly the
// refusal authAdminSSOReadiness showed, and the readiness read answers it
// in its body.
func TestSSOReadinessRefusalIsApplysAnswer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		mode    string
		arrange func(t *testing.T, e *env)
		want    ReadinessRefusal
	}{
		{name: "provider_off", mode: "for_linked", want: ReadinessRefusal{Code: access.CodeOIDCUnavailable}},
		{name: "owner_without_local_method", mode: "only", want: ReadinessRefusal{Code: access.CodeForbidden, Reason: account.ReasonOwnerNeedsLocalMethod}, arrange: func(t *testing.T, e *env) {
			e.useIdP(t, accesstest.IdPOptions{}, nil)
			root := e.user(t, "root")
			root.PasswordHash = access.Hash{}
			if err := e.mem.UpdateUser(t.Context(), root); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, envOptions{})
			cookie := e.rootSession(t)
			if tc.arrange != nil {
				tc.arrange(t, e)
			}
			rt := e.route(t, "authAdminSSOReadiness")
			var rd Readiness
			w := do(rt, requestAt(testOrigin, rt.Path+"?mode="+tc.mode, rt, "", cookie))
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &rd) != nil || rd.Refusal == nil || *rd.Refusal != tc.want {
				t.Fatalf("readiness = %d %s, want 200 with refusal %+v", w.Code, w.Body, tc.want)
			}
			ap := e.route(t, "authAdminSSOApply")
			before := len(e.errs.all())
			w = do(ap, requestFor(ap, "", `{"mode":"`+tc.mode+`"}`, cookie))
			errs := e.errs.all()[before:]
			if len(errs) != 1 || errs[0].Code != rd.Refusal.Code || errs[0].Reason != rd.Refusal.Reason {
				t.Errorf("apply = %d %+v, want exactly the readiness refusal %+v", w.Code, errs, *rd.Refusal)
			}
			if mode, set, err := e.mem.SSOMode(t.Context()); err != nil || set || mode != account.SSOAlongside {
				t.Errorf("stored mode = %v, set %t, %v; want nothing written", mode, set, err)
			}
		})
	}
}

// An unknown mode is auth_bad_request before any account call.
func TestSSOUnknownMode(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envOptions{})
	cookie := e.rootSession(t)
	rt := e.route(t, "authAdminSSOReadiness")
	if w := do(rt, requestAt(testOrigin, rt.Path+"?mode=everyone", rt, "", cookie)); w.Code != http.StatusBadRequest {
		t.Errorf("readiness with an unknown mode = %d", w.Code)
	}
	ap := e.route(t, "authAdminSSOApply")
	if w := do(ap, requestFor(ap, "", `{"mode":"everyone"}`, cookie)); w.Code != http.StatusBadRequest {
		t.Errorf("apply with an unknown mode = %d", w.Code)
	}
}
