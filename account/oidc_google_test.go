package account_test

import (
	"sync/atomic"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

const googleIssuer = "https://accounts.google.com"

// googleRig is an IdP at Google's issuer whose ID tokens carry iss, and the
// Provider discovered from it.
func googleRig(t *testing.T, iss string) *oidcRig {
	t.Helper()
	o := accesstest.IdPOptions{URL: googleIssuer}
	if iss != googleIssuer {
		o.IssuerClaim = iss
	}
	idp := accesstest.NewIdP(t, o)
	p, err := oidc.NewProvider(t.Context(), oidc.Config{
		IssuerURL: googleIssuer, ClientID: idp.ClientID(), ClientSecret: access.NewSecret(idp.ClientSecret()),
		RedirectURL: oidcCallback, HTTPClient: idp.Client(),
	})
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	return &oidcRig{idp: idp, provider: p, subject: accesstest.DefaultIdPSubject}
}

// TestOIDCGoogleIssuerForms: Google's ID tokens carry iss as
// "https://accounts.google.com" or "accounts.google.com"
// (https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken),
// and both are the configured issuer's one identity (OpenID Connect Core
// 1.0 §3.1.3.7 step 2): a link under one form signs in and steps up under
// the other as the same user, with no provisioning and no pending link.
func TestOIDCGoogleIssuerForms(t *testing.T) {
	t.Parallel()
	want := access.OIDCIdentity{Issuer: googleIssuer, Subject: accesstest.DefaultIdPSubject}
	for name, forms := range map[string][2]string{
		"link_without_scheme": {"accounts.google.com", googleIssuer},
		"link_with_scheme":    {googleIssuer, "accounts.google.com"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			linkRig, otherRig := googleRig(t, forms[0]), googleRig(t, forms[1])
			var cur atomic.Pointer[oidcRig]
			cur.Store(linkRig)
			f := newOIDCFixture(t, linkRig, pwOptions{rules: provisioningOn(), edit: func(c *account.Config) {
				c.OIDC = func() *oidc.Provider { return cur.Load().provider }
			}})
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)

			sess := putSession(t, f.mem, liveSession(t, u))
			flow, claims := linkRig.sessionFlow(t, oidc.IntentLink, u, sess.ID)
			if out, err := f.complete(t, localClient, flow, claims); err != nil || out.Kind != account.OutcomeLinked {
				t.Fatalf("link under iss %q: OIDCComplete = %+v, %v; want Linked", forms[0], out, err)
			}
			if got := storedUser(t, f.mem, u.ID).OIDC; got != want {
				t.Fatalf("stored link = %+v, want %+v", got, want)
			}

			cur.Store(otherRig)
			flow, claims = otherRig.signInFlow(t)
			out, err := f.complete(t, localClient, flow, claims)
			if err != nil || out.Kind != account.OutcomeSignedIn || out.SignedIn.User == nil || out.SignedIn.User.ID != u.ID {
				t.Fatalf("sign-in under iss %q: OIDCComplete = %+v, %v; want alice signed in", forms[1], out, err)
			}
			step := putSession(t, f.mem, liveSession(t, u))
			flow, claims = otherRig.sessionFlow(t, oidc.IntentStepUp, u, step.ID)
			if out, err := f.complete(t, localClient, flow, claims); err != nil || out.Kind != account.OutcomeSteppedUp {
				t.Errorf("step-up under iss %q: OIDCComplete = %+v, %v; want SteppedUp", forms[1], out, err)
			}
			if n := userCount(t, f.fixture); n != 1 {
				t.Errorf("users = %d, want alice alone: no identity was provisioned", n)
			}
			if got := storedUser(t, f.mem, u.ID).OIDC; got != want {
				t.Errorf("stored link after both forms = %+v, want %+v", got, want)
			}
		})
	}
}
