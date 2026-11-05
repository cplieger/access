package accesshttp

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/oidc"
)

// testIssuer is the issuer every test IdP presents unless a test names
// another.
const testIssuer = "https://idp.example.com"

// testCallback is the callback route's URL, the Provider's RedirectURL.
const testCallback = testOrigin + "/api/auth/oidc/callback"

// useIdP starts an IdP for o, presenting testIssuer unless o.URL names
// another, and makes its Provider, sealing flows with sealer (nil: the
// Provider's own), the one Config.OIDC returns.
func (e *env) useIdP(t testing.TB, o accesstest.IdPOptions, sealer *access.Sealer) *accesstest.IdP {
	t.Helper()
	if o.URL == "" {
		o.URL = testIssuer
	}
	idp := accesstest.NewIdP(t, o)
	e.provider.Store(newProvider(t, idp, sealer))
	return idp
}

func newProvider(t testing.TB, idp *accesstest.IdP, sealer *access.Sealer) *oidc.Provider {
	t.Helper()
	p, err := oidc.NewProvider(t.Context(), oidc.Config{
		IssuerURL: idp.Issuer(), ClientID: idp.ClientID(), ClientSecret: access.NewSecret(idp.ClientSecret()),
		RedirectURL: testCallback, HTTPClient: idp.Client(), FlowSealer: sealer,
	})
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	return p
}

// idpIdentity is the identity an IdP presenting issuer signs in by default.
func idpIdentity(issuer string) access.OIDCIdentity {
	return access.OIDCIdentity{Issuer: issuer, Subject: accesstest.DefaultIdPSubject}
}

// linkUser stores id as name's OIDC link.
func (e *env) linkUser(t testing.TB, name string, id access.OIDCIdentity) {
	t.Helper()
	u := e.user(t, name)
	u.OIDC = id
	if err := e.mem.UpdateUser(t.Context(), u); err != nil {
		t.Fatalf("UpdateUser(link): %v", err)
	}
}

// browser is one user agent's cookies for one origin.
type browser struct {
	jar    *cookiejar.Jar
	app    *url.URL
	origin string
}

// newBrowser is a browser for testOrigin.
func newBrowser(t testing.TB, cookies ...*http.Cookie) *browser {
	t.Helper()
	return newBrowserAt(t, testOrigin, cookies...)
}

func newBrowserAt(t testing.TB, origin string, cookies ...*http.Cookie) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	app, err := url.Parse(origin + "/")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	jar.SetCookies(app, cookies)
	return &browser{jar: jar, app: app, origin: origin}
}

// request is a same-origin request for rt from the browser's origin, its
// cookies added by send.
func (b *browser) request(rt Route, body string) *http.Request {
	return requestAt(b.origin, rt.Path, rt, body)
}

// with adds the browser's cookies to r.
func (b *browser) with(r *http.Request) *http.Request {
	for _, c := range b.jar.Cookies(b.app) {
		r.AddCookie(c)
	}
	return r
}

// send serves r on rt with the browser's cookies and keeps what it sets.
func (b *browser) send(rt Route, r *http.Request) *httptest.ResponseRecorder {
	w := do(rt, b.with(r))
	b.jar.SetCookies(b.app, w.Result().Cookies())
	return w
}

// get is a GET of rt's path with rawQuery.
func get(rt Route, rawQuery string) *http.Request {
	target := testOrigin + rt.Path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	return httptest.NewRequest(http.MethodGet, target, nil)
}

// authorize follows authURL at idp and returns the callback request its
// redirect names.
func authorize(t testing.TB, idp *accesstest.IdP, authURL string) *http.Request {
	t.Helper()
	client := &http.Client{Transport: idp.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("authorize answered %s with no redirect", resp.Status)
	}
	return httptest.NewRequestWithContext(t.Context(), http.MethodGet, loc.String(), nil)
}

// startSignIn serves the sign-in start with rawQuery and returns its
// authorization URL.
func (e *env) startSignIn(t testing.TB, b *browser, rawQuery string) string {
	t.Helper()
	w := b.send(e.route(t, "authOIDCStartSignIn"), get(e.route(t, "authOIDCStartSignIn"), rawQuery))
	if w.Code != http.StatusFound {
		t.Fatalf("sign-in start = %d, want 302", w.Code)
	}
	return w.Header().Get("Location")
}

// startSession serves the link or step-up start route with target as its
// redirect and returns its authorization URL.
func (e *env) startSession(t testing.TB, b *browser, route, target string) string {
	t.Helper()
	rt := e.route(t, route)
	w := b.send(rt, request(rt, jsonBody(t, RedirectRequest{Redirect: target})))
	if w.Code != http.StatusOK {
		t.Fatalf("%s = %d, want 200", route, w.Code)
	}
	var out OIDCStartResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", route, err)
	}
	return out.URL
}

// callback serves the callback request r with the browser's cookies.
func (e *env) callback(t testing.TB, b *browser, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	return b.send(e.route(t, "authOIDCCallback"), r)
}

// signInFlow is a whole sign-in flow from b, returning the callback's
// response.
func (e *env) signInFlow(t testing.TB, b *browser, idp *accesstest.IdP, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	return e.callback(t, b, authorize(t, idp, e.startSignIn(t, b, rawQuery)))
}

// sessionFlow is a whole link or step-up flow from b back to target,
// returning the callback's response; between runs before the callback.
func (e *env) sessionFlow(t testing.TB, b *browser, idp *accesstest.IdP, route, target string, between func()) *httptest.ResponseRecorder {
	t.Helper()
	cb := authorize(t, idp, e.startSession(t, b, route, target))
	if between != nil {
		between()
	}
	return e.callback(t, b, cb)
}

// pendingCookie seals p as the handler's pending-link cookie.
func (e *env) pendingCookie(t testing.TB, p pendingPayload) *http.Cookie {
	t.Helper()
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	sealed, err := e.h.pending.Seal(pendingPurpose, payload, time.Now().Add(pendingLifetime))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	cfg := pendingCookie(e.authn.Cookie())
	return &http.Cookie{Name: cfg.CookieName(httptest.NewRequest(http.MethodGet, testOrigin+"/", nil)), Value: sealed}
}

// flowCookieName is the flow cookie's name on testOrigin.
func (e *env) flowCookieName() string {
	cfg := e.authn.Cookie().Derive("oidc", http.SameSiteLaxMode)
	return cfg.CookieName(httptest.NewRequest(http.MethodGet, testOrigin+"/", nil))
}

// pendingCookieName is the pending-link cookie's name on testOrigin.
func (e *env) pendingCookieName() string {
	cfg := e.authn.Cookie().Derive("oidc_pending", http.SameSiteLaxMode)
	return cfg.CookieName(httptest.NewRequest(http.MethodGet, testOrigin+"/", nil))
}

// location is w's redirect target, failing unless w is a 302.
func location(t testing.TB, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("status %d, want 302", w.Code)
	}
	return w.Header().Get("Location")
}
