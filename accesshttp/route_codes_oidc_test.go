package accesshttp

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// otherIdentity is an identity of testIssuer no default IdP signs in.
var otherIdentity = access.OIDCIdentity{Issuer: testIssuer, Subject: "other-subject"}

// signedInBrowser creates name and returns a browser holding a fresh
// password session of it.
func (e *env) signedInBrowser(t *testing.T, name string) *browser {
	t.Helper()
	e.createUser(t, name, access.RoleUser)
	return newBrowser(t, e.sessionCookie(t, name))
}

// linkCallback starts a link flow for alice back to /settings and returns
// its callback request with the browser's cookies, after between runs.
func (e *env) linkCallback(t *testing.T, between func(alice *access.User)) *http.Request {
	t.Helper()
	idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
	b := e.signedInBrowser(t, "alice")
	cb := authorize(t, idp, e.startSession(t, b, "authOIDCStartLink", "/settings"))
	if between != nil {
		between(e.user(t, "alice"))
	}
	return b.with(cb)
}

// bareCallback is a callback request with a state and no flow cookie.
func (e *env) bareCallback(t *testing.T) *http.Request {
	t.Helper()
	return get(e.route(t, "authOIDCCallback"), "state=x&code=y")
}

// skewed is a Service clock a test moves forward mid-flow.
type skewed struct{ by atomic.Int64 }

func (s *skewed) now() time.Time { return time.Now().Add(time.Duration(s.by.Load())) }

func (s *skewed) opts() envOptions {
	return envOptions{edit: func(c *account.Config) { c.Now = s.now }}
}

// ssoRefused governs accounts by SSO under a Policy that refuses the
// migration.
var ssoRefused = envOptions{
	rules: func(r *account.Rules) { r.SSOGoverned = true },
	edit:  refuse(account.OpMigrateToSSO),
}

func oidcScenarios() map[scenarioKey]scenario {
	out := map[scenarioKey]scenario{}
	addCallbackScenarios(out)
	addStartScenarios(out)
	addLinkScenarios(out)
	return out
}

func addCallbackScenarios(out map[scenarioKey]scenario) {
	const route = "authOIDCCallback"
	recent := &skewed{}
	out[scenarioKey{route, CodeSessionExpired}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.linkCallback(t, func(alice *access.User) {
			if _, err := e.mem.DeleteUserSessions(t.Context(), alice.ID, ""); err != nil {
				t.Fatalf("DeleteUserSessions: %v", err)
			}
		})
	}}
	out[scenarioKey{route, CodeInvalidCredentials}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		e.createUser(t, "alice", access.RoleUser)
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		u := e.user(t, "alice")
		u.Enabled = false
		if err := e.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		b := newBrowser(t)
		return b.with(authorize(t, idp, e.startSignIn(t, b, "")))
	}}
	out[scenarioKey{route, CodeRecentAuthRequired}] = scenario{opts: recent.opts(), arrange: func(t *testing.T, e *env) *http.Request {
		return e.linkCallback(t, func(*access.User) { recent.by.Store(int64(11 * time.Minute)) })
	}}
	out[scenarioKey{route, CodeForbidden}] = scenario{opts: ssoRefused, arrange: func(t *testing.T, e *env) *http.Request {
		return e.linkCallback(t, nil)
	}}
	out[scenarioKey{route, CodeRateLimited}] = scenario{opts: limited, arrange: func(t *testing.T, e *env) *http.Request {
		e.useIdP(t, accesstest.IdPOptions{}, nil)
		e.spendRequest(t)
		return e.bareCallback(t)
	}}
	out[scenarioKey{route, CodeUnavailable}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		e.useIdP(t, accesstest.IdPOptions{}, nil)
		e.shutdown(t)
		return e.bareCallback(t)
	}}
	out[scenarioKey{route, CodeIdentityTaken}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		e.createUser(t, "bob", access.RoleUser)
		e.linkUser(t, "bob", idpIdentity(testIssuer))
		return e.linkCallback(t, nil)
	}}
	out[scenarioKey{route, CodeAlreadyLinked}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.linkCallback(t, func(*access.User) { e.linkUser(t, "alice", otherIdentity) })
	}}
	out[scenarioKey{route, CodeOIDCUnavailable}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return e.bareCallback(t)
	}}
	out[scenarioKey{route, CodeOIDCFailed}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		e.useIdP(t, accesstest.IdPOptions{}, nil)
		return e.bareCallback(t)
	}}
}

func addStartScenarios(out map[scenarioKey]scenario) {
	const signIn = "authOIDCStartSignIn"
	signInGet := func(t *testing.T, e *env) *http.Request { return get(e.route(t, signIn), "") }
	out[scenarioKey{signIn, CodeRateLimited}] = scenario{opts: limited, arrange: func(t *testing.T, e *env) *http.Request {
		e.useIdP(t, accesstest.IdPOptions{}, nil)
		e.spendRequest(t)
		return signInGet(t, e)
	}}
	out[scenarioKey{signIn, CodeUnavailable}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		e.useIdP(t, accesstest.IdPOptions{}, nil)
		e.shutdown(t)
		return signInGet(t, e)
	}}
	out[scenarioKey{signIn, CodeOIDCUnavailable}] = scenario{arrange: signInGet}
	for _, route := range []string{"authOIDCStartLink", "authOIDCStartStepUp"} {
		start := func(t *testing.T, e *env, body string) *http.Request {
			b := e.signedInBrowser(t, "alice")
			return b.with(request(e.route(t, route), body))
		}
		out[scenarioKey{route, CodeBadRequest}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
			e.useIdP(t, accesstest.IdPOptions{}, nil)
			return start(t, e, jsonBody(t, RedirectRequest{Redirect: "/" + strings.Repeat("a", 512)}))
		}}
		out[scenarioKey{route, CodeCrossOrigin}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
			e.useIdP(t, accesstest.IdPOptions{}, nil)
			r := start(t, e, jsonBody(t, RedirectRequest{}))
			r.Header.Set("Sec-Fetch-Site", "none")
			return r
		}}
		out[scenarioKey{route, CodeOIDCUnavailable}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
			return start(t, e, jsonBody(t, RedirectRequest{}))
		}}
	}
	out[scenarioKey{"authOIDCPending", CodeNotFound}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return get(e.route(t, "authOIDCPending"), "")
	}}
}

func addLinkScenarios(out map[scenarioKey]scenario) {
	const linkRoute, unlinkRoute = "authOIDCLinkPending", "authOIDCUnlink"
	pending := pendingPayload{Issuer: testIssuer, Subject: accesstest.DefaultIdPSubject, UsernameHint: "alice"}
	// link is alice's link of the pending identity, with the IdP on.
	link := func(t *testing.T, e *env, withPending bool) *http.Request {
		b := e.signedInBrowser(t, "alice")
		r := b.with(request(e.route(t, linkRoute), ""))
		if withPending {
			r.AddCookie(e.pendingCookie(t, pending))
		}
		return r
	}
	withIdP := func(t *testing.T, e *env) { e.useIdP(t, accesstest.IdPOptions{}, nil) }
	out[scenarioKey{linkRoute, CodeSessionExpired}] = scenario{opts: vanishes, arrange: func(t *testing.T, e *env) *http.Request {
		withIdP(t, e)
		return link(t, e, true)
	}}
	out[scenarioKey{linkRoute, CodeForbidden}] = scenario{opts: ssoRefused, arrange: func(t *testing.T, e *env) *http.Request {
		withIdP(t, e)
		return link(t, e, true)
	}}
	out[scenarioKey{linkRoute, CodeUnavailable}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		withIdP(t, e)
		r := link(t, e, true)
		e.shutdown(t)
		return r
	}}
	out[scenarioKey{linkRoute, CodeIdentityTaken}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		withIdP(t, e)
		e.createUser(t, "bob", access.RoleUser)
		e.linkUser(t, "bob", idpIdentity(testIssuer))
		return link(t, e, true)
	}}
	out[scenarioKey{linkRoute, CodeAlreadyLinked}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		withIdP(t, e)
		r := link(t, e, true)
		e.linkUser(t, "alice", otherIdentity)
		return r
	}}
	out[scenarioKey{linkRoute, CodeOIDCUnavailable}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return link(t, e, true)
	}}
	out[scenarioKey{linkRoute, CodeNotFound}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		withIdP(t, e)
		return link(t, e, false)
	}}
	// unlink is alice's unlink of her identity.
	unlink := func(t *testing.T, e *env, linked bool) *http.Request {
		b := e.signedInBrowser(t, "alice")
		if linked {
			e.linkUser(t, "alice", idpIdentity(testIssuer))
		}
		return b.with(request(e.route(t, unlinkRoute), ""))
	}
	out[scenarioKey{unlinkRoute, CodeSessionExpired}] = scenario{opts: vanishes, arrange: func(t *testing.T, e *env) *http.Request {
		return unlink(t, e, true)
	}}
	out[scenarioKey{unlinkRoute, CodeUnavailable}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		r := unlink(t, e, true)
		e.shutdown(t)
		return r
	}}
	out[scenarioKey{unlinkRoute, CodeLastMethod}] = scenario{opts: passwordUnusable, arrange: func(t *testing.T, e *env) *http.Request {
		return unlink(t, e, true)
	}}
	out[scenarioKey{unlinkRoute, CodeNotFound}] = scenario{arrange: func(t *testing.T, e *env) *http.Request {
		return unlink(t, e, false)
	}}
}
