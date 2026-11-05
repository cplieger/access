package account_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

// oidcIssuer is the issuer every test IdP presents, so the identities of
// two IdPs in one test differ by subject alone.
const oidcIssuer = "https://idp.example.com"

const oidcCallback = "https://" + rpID + "/auth/oidc/callback"

// oidcRig is one IdP and the Provider discovered from it.
type oidcRig struct {
	idp      *accesstest.IdP
	provider *oidc.Provider
	subject  string
}

// newOIDCRig starts an IdP presenting oidcIssuer for o and discovers it.
func newOIDCRig(t testing.TB, o accesstest.IdPOptions) *oidcRig {
	t.Helper()
	o.URL = oidcIssuer
	subject := accesstest.DefaultIdPSubject
	if o.Subject != nil {
		subject = *o.Subject
	}
	idp := accesstest.NewIdP(t, o)
	p, err := oidc.NewProvider(t.Context(), oidc.Config{
		IssuerURL: idp.Issuer(), ClientID: idp.ClientID(), ClientSecret: access.NewSecret(idp.ClientSecret()),
		RedirectURL: oidcCallback, HTTPClient: idp.Client(),
	})
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	return &oidcRig{idp: idp, provider: p, subject: subject}
}

// rigFor is a rig whose IdP signs in subject.
func rigFor(t testing.TB, subject string) *oidcRig {
	t.Helper()
	return newOIDCRig(t, accesstest.IdPOptions{Subject: &subject})
}

func (g *oidcRig) identity() access.OIDCIdentity {
	return access.OIDCIdentity{Issuer: oidcIssuer, Subject: g.subject}
}

// withOIDC is a Config edit resolving g's Provider.
func (g *oidcRig) withOIDC(c *account.Config) {
	c.OIDC = func() *oidc.Provider { return g.provider }
}

// run is one browser's whole flow for req: Begin, the IdP's authorize and
// Finish, returning what Finish recovered.
func (g *oidcRig) run(t testing.TB, req oidc.BeginRequest) (oidc.Flow, oidc.Claims) {
	t.Helper()
	session := access.DefaultCookieConfig()
	rec := httptest.NewRecorder()
	start := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+rpID+"/auth/oidc/start", http.NoBody)
	authURL, err := g.provider.Begin(rec, start, session, req)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	browser := &http.Client{Transport: g.idp.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := browser.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("authorize answered %s with no redirect", resp.Status)
	}
	q := loc.Query()
	cb := oidc.Callback{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error")}
	back := httptest.NewRequestWithContext(t.Context(), http.MethodGet, oidcCallback+"?"+loc.RawQuery, http.NoBody)
	for _, c := range rec.Result().Cookies() {
		back.AddCookie(c)
	}
	flow, claims, err := g.provider.Finish(httptest.NewRecorder(), back, session, cb)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return flow, claims
}

// signInFlow is a sign-in flow returning to /home.
func (g *oidcRig) signInFlow(t testing.TB) (oidc.Flow, oidc.Claims) {
	t.Helper()
	return g.run(t, oidc.BeginRequest{Intent: oidc.IntentSignIn, Redirect: "/home"})
}

// sessionFlow is a link or step-up flow begun from session id of u,
// returning to /settings.
func (g *oidcRig) sessionFlow(t testing.TB, intent oidc.Intent, u *access.User, id string) (oidc.Flow, oidc.Claims) {
	t.Helper()
	return g.run(t, oidc.BeginRequest{Intent: intent, SessionID: id, UserID: u.ID, Redirect: "/settings"})
}

// linkIdentity stores id as u's OIDC link.
func linkIdentity(t testing.TB, s account.Store, u *access.User, id access.OIDCIdentity) {
	t.Helper()
	u.OIDC = id
	if err := s.UpdateUser(t.Context(), u); err != nil {
		t.Fatalf("UpdateUser(link): %v", err)
	}
}

// putSession stores sess under a fresh token, unverified, and returns it
// as stored.
func putSession(t testing.TB, s account.Store, sess access.Session) access.Session {
	t.Helper()
	_, hash := access.GenerateSessionToken()
	sess.TokenHash = hash
	if err := s.CreateSession(t.Context(), &sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return sess
}
