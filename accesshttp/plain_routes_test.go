package accesshttp

import (
	"encoding/hex"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

// plainOrigin is a plain-HTTP LAN origin.
const plainOrigin = "http://192.168.1.77:9847"

// plainRefusedRoutes is docs/plain-http.md's refused column: under
// PosturePerRequest each answers a plain request 403 auth_https_required.
var plainRefusedRoutes = map[string]bool{
	"authSetupPasskeyBegin": true, "authSetupPasskeyFinish": true, "authLoginPasskeyBegin": true, "authLoginPasskeyFinish": true,
	"authOIDCStartSignIn": true, "authOIDCStartLink": true, "authOIDCStartStepUp": true, "authOIDCCallback": true,
	"authOIDCPending": true, "authOIDCLinkPending": true, "authAdminSSOReadiness": true, "authAdminSSOApply": true,
	"authStepUpPassword": true, "authStepUpPasskeyBegin": true, "authStepUpPasskeyFinish": true,
	"authPasswordRemove": true, "authPasskeyRegisterBegin": true, "authPasskeyRegisterFinish": true,
	"authInviteAcceptPassword": true,
	"authKeyCreate":            true, "authKeyRotate": true, "authAdminInvite": true,
}

// transportSession stores a password session for name, signed in now over
// the transport secure names, and returns its cookie under that
// transport's name.
func (e *env) transportSession(t testing.TB, name string, secure bool) *http.Cookie {
	t.Helper()
	token, hash := access.GenerateSessionToken()
	now := time.Now()
	s := &access.Session{
		ID: hex.EncodeToString(randomBytes(16)), UserID: e.user(t, name).ID, TokenHash: hash, AuthMethod: access.MethodPassword,
		CreatedAt: now, LastActivity: now, AuthTime: now, Secure: secure,
	}
	if err := e.mem.CreateSession(t.Context(), s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	cfg := e.authn.Cookie()
	return &http.Cookie{Name: cfg.CookieName(secure), Value: token.Reveal()}
}

// useCountingIdP is useIdP whose Provider counts each call it makes to the
// IdP after NewProvider returns.
func (e *env) useCountingIdP(t testing.TB) (*accesstest.IdP, *atomic.Int64) {
	t.Helper()
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{URL: testIssuer})
	calls := &atomic.Int64{}
	base := idp.Client()
	client := &http.Client{Timeout: base.Timeout, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return base.Transport.RoundTrip(r)
	})}
	p, err := oidc.NewProvider(t.Context(), oidc.Config{
		IssuerURL: idp.Issuer(), ClientID: idp.ClientID(), ClientSecret: access.NewSecret(idp.ClientSecret()),
		RedirectURL: testCallback, HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	calls.Store(0)
	e.provider.Store(p)
	return idp, calls
}

// plainWorld is a PosturePerRequest env holding admin root and RoleUser
// alice, a fresh session of root made over its transport, and an IdP whose
// calls it counts.
type plainWorld struct {
	*env
	idp      *accesstest.IdP
	idpCalls *atomic.Int64
	session  *http.Cookie
	origin   string
}

func newPlainWorld(t *testing.T, secure bool, opts ...envOptions) *plainWorld {
	t.Helper()
	w := &plainWorld{env: newEnv(t, with(append([]envOptions{perRequest}, opts...)...)), origin: plainOrigin}
	if secure {
		w.origin = testOrigin
	}
	w.idp, w.idpCalls = w.useCountingIdP(t)
	w.createUser(t, "root", access.RoleAdmin)
	w.createUser(t, "alice", access.RoleUser)
	w.session = w.transportSession(t, "root", secure)
	return w
}

// outcome is what one request answered: its status, the code its Error or
// its redirect's auth_error carried ("" for none), and its Set-Cookie
// names.
type outcome struct {
	code    access.Code
	cookies []string
	status  int
}

// observe serves r on rt and returns what it answered.
func (e *env) observe(t *testing.T, rt Route, r *http.Request) outcome {
	t.Helper()
	before := len(e.errs.all())
	w := do(rt, r)
	errs := e.errs.all()[before:]
	out := outcome{status: w.Code}
	for _, c := range w.Result().Cookies() {
		out.cookies = append(out.cookies, c.Name)
	}
	switch {
	case w.Code == http.StatusFound:
		out.code = redirectedCode(t, w)
	case len(errs) == 1:
		out.code = errs[0].Code
	case len(errs) > 1:
		t.Fatalf("%s answered %d errors %+v, want at most one", rt.Name, len(errs), errs)
	default:
	}
	return out
}

// send sends name's census request at w's origin with root's session, and
// returns its outcome.
func (w *plainWorld) send(t *testing.T, name string) outcome {
	t.Helper()
	rt := w.route(t, name)
	path := strings.NewReplacer("{id}", censusPathValue(t, rt), "{method}", censusPathValue(t, rt)).Replace(rt.Path)
	return w.observe(t, rt, requestAt(w.origin, path, rt, censusBody(t, rt), w.session))
}

// requireHTTPSRequired fails unless out is auth_https_required, at its 403
// or as a callback redirect's auth_error, with no cookie set.
func requireHTTPSRequired(t *testing.T, out outcome) {
	t.Helper()
	want := access.NewError(access.CodeHTTPSRequired, "", nil).Status
	if out.code != access.CodeHTTPSRequired || out.status != want && out.status != http.StatusFound || len(out.cookies) != 0 {
		t.Errorf("status %d, code %q, Set-Cookie %v; want %d auth_https_required and no cookie", out.status, out.code, out.cookies, want)
	}
}

// TestPlainRoutesPerRequest is docs/plain-http.md's policy table over the
// routes under PosturePerRequest: every refused route answers a plain
// request auth_https_required, setting no cookie and calling no IdP, and
// every allowed route answers a plain session as its secure twin answers a
// secure one.
func TestPlainRoutesPerRequest(t *testing.T) {
	t.Parallel()
	names := []string{}
	for _, rt := range newEnv(t, perRequest).h.Routes() {
		names = append(names, rt.Name)
	}
	for name := range plainRefusedRoutes {
		if !slices.Contains(names, name) {
			t.Errorf("plainRefusedRoutes names %s, which is no route", name)
		}
	}
	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		for _, name := range slices.Sorted(maps.Keys(plainRefusedRoutes)) {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				w := newPlainWorld(t, false)
				requireHTTPSRequired(t, w.send(t, name))
				if n := w.idpCalls.Load(); n != 0 || len(w.idp.Authorizations()) != 0 {
					t.Errorf("%d calls to the IdP and %d authorizations, want none", n, len(w.idp.Authorizations()))
				}
			})
		}
	})
	t.Run("allowed", func(t *testing.T) {
		t.Parallel()
		for _, name := range slices.DeleteFunc(names, func(n string) bool { return plainRefusedRoutes[n] }) {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				got, want := newPlainWorld(t, false).send(t, name), newPlainWorld(t, true).send(t, name)
				if got.status != want.status || got.code != want.code || got.code == access.CodeHTTPSRequired {
					t.Errorf("plain: status %d code %q; secure: status %d code %q; want the same answer", got.status, got.code, want.status, want.code)
				}
			})
		}
	})
	t.Run("keys", func(t *testing.T) {
		t.Parallel()
		w := newPlainWorld(t, false, envOptions{
			edit:  func(c *account.Config) { c.AdminScope, c.CreateKeysScope = scopeAdminName, scopeKeysName },
			rules: func(r *account.Rules) { r.Scopes = []string{scopeAdminName, scopeKeysName} },
		})
		key := w.mintKey(t, "root", account.NewKey{Label: "admin", Scopes: []string{scopeAdminName, scopeKeysName}})
		other := w.mintKey(t, "root", account.NewKey{Label: "other"})
		send := func(name, id, body string) outcome {
			rt := w.route(t, name)
			r := requestAt(plainOrigin, strings.Replace(rt.Path, "{id}", id, 1), rt, body)
			return w.observe(t, rt, bearer(r, key.Plaintext))
		}
		if out := send("authAdminKeys", "", ""); out.status != http.StatusOK || out.code != "" {
			t.Errorf("plain key on authAdminKeys: status %d code %q, want 200", out.status, out.code)
		}
		if out := send("authAdminKeyRevoke", strconv.FormatInt(other.Key.ID, 10), ""); out.status != http.StatusNoContent || out.code != "" {
			t.Errorf("plain key on authAdminKeyRevoke: status %d code %q, want 204", out.status, out.code)
		}
		requireHTTPSRequired(t, send("authKeyCreate", "", keyBody(t, "minted")))
	})
}

// TestPlainRoutesPostureSecure is PostureSecure's plain answer on every
// route: auth_https_required everywhere but authState and authLogout, and
// the presented __Host- session, the deployment's one name, survives every
// refusal untouched.
func TestPlainRoutesPostureSecure(t *testing.T) {
	e := newEnv(t, envOptions{})
	idp, calls := e.useCountingIdP(t)
	e.createUser(t, "root", access.RoleAdmin)
	e.createUser(t, "alice", access.RoleUser)
	cookie := e.sessionCookie(t, "root")
	stored := func(t *testing.T) *access.Session {
		t.Helper()
		s, found, err := e.mem.SessionByHash(t.Context(), access.SessionHash(cookie.Value))
		if err != nil || !found {
			t.Fatalf("SessionByHash = %v, %v; the session is gone", found, err)
		}
		return s
	}
	activity := stored(t).LastActivity
	send := func(t *testing.T, rt Route) outcome {
		t.Helper()
		path := strings.NewReplacer("{id}", censusPathValue(t, rt), "{method}", censusPathValue(t, rt)).Replace(rt.Path)
		return e.observe(t, rt, requestAt(plainOrigin, path, rt, censusBody(t, rt), cookie))
	}
	for _, rt := range slices.DeleteFunc(e.h.Routes(), func(rt Route) bool { return rt.Name == "authState" || rt.Name == "authLogout" }) {
		t.Run(rt.Name, func(t *testing.T) {
			requireHTTPSRequired(t, send(t, rt))
			if got := stored(t).LastActivity; !got.Equal(activity) {
				t.Errorf("LastActivity %v after the refusal, want %v", got, activity)
			}
		})
	}
	if n := calls.Load(); n != 0 || len(idp.Authorizations()) != 0 {
		t.Errorf("%d calls to the IdP and %d authorizations, want none", n, len(idp.Authorizations()))
	}
	t.Run("authState", func(t *testing.T) {
		if out := send(t, e.route(t, "authState")); out.status != http.StatusOK || out.code != "" {
			t.Errorf("plain authState: status %d code %q, want 200", out.status, out.code)
		}
	})
	t.Run("authLogout", func(t *testing.T) {
		if out := send(t, e.route(t, "authLogout")); out.status != http.StatusNoContent || out.code != "" {
			t.Errorf("plain authLogout: status %d code %q, want 204", out.status, out.code)
		}
	})
}
