package oidc_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/internal/printcheck"
	"github.com/cplieger/access/oidc"
)

const appCallback = "https://app.example/auth/callback"

var (
	signIn = oidc.BeginRequest{Intent: oidc.IntentSignIn, Redirect: "/home?tab=1"}
	link   = oidc.BeginRequest{Intent: oidc.IntentLink, SessionID: "session-1", UserID: 7, Redirect: "/settings"}
	stepUp = oidc.BeginRequest{Intent: oidc.IntentStepUp, SessionID: "session-2", UserID: 9, Redirect: "/keys?new=1"}
	invite = oidc.BeginRequest{Intent: oidc.IntentInvite, InviteHash: []byte(strings.Repeat("0f", oidc.MaxInviteHashBytes/2)), Redirect: "/welcome"}
)

func configFor(idp *accesstest.IdP) oidc.Config {
	return oidc.Config{
		IssuerURL:    idp.Issuer(),
		ClientID:     idp.ClientID(),
		ClientSecret: access.NewSecret(idp.ClientSecret()),
		RedirectURL:  appCallback,
	}
}

func mustProvider(t *testing.T, cfg oidc.Config) *oidc.Provider {
	t.Helper()
	p, err := oidc.NewProvider(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

// browser is one user agent: a cookie jar for the app's origin, and the
// session cookie config the app passes to Begin and Finish.
type browser struct {
	t       *testing.T
	jar     *cookiejar.Jar
	app     *url.URL
	session access.CookieConfig
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	app, _ := url.Parse("https://app.example/")
	return &browser{t: t, jar: jar, app: app, session: access.DefaultCookieConfig()}
}

func (b *browser) flowCookie() string {
	flow := b.session.Derive("oidc", http.SameSiteLaxMode)
	return flow.CookieName(true)
}

// begin calls Begin on a request from this browser and keeps what it set.
func (b *browser) begin(p *oidc.Provider, req oidc.BeginRequest, header http.Header) (string, []*http.Cookie, error) {
	b.t.Helper()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, b.app.String()+"auth/start", nil)
	maps.Copy(r.Header, header)
	authURL, err := p.Begin(rec, r, b.session, req)
	set := rec.Result().Cookies()
	b.jar.SetCookies(b.app, set)
	return authURL, set, err
}

// authorize follows authURL to the IdP and returns the callback values of
// its redirect and the redirect itself.
func (b *browser) authorize(idp *accesstest.IdP, authURL string) (oidc.Callback, *url.URL) {
	b.t.Helper()
	c := &http.Client{Transport: idp.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(authURL)
	if err != nil {
		b.t.Fatalf("GET authorize: %v", err)
	}
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		b.t.Fatalf("authorize answered %s with no redirect", resp.Status)
	}
	q := loc.Query()
	return oidc.Callback{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error")}, loc
}

type finished struct {
	resp   *http.Response
	flow   oidc.Flow
	claims oidc.Claims
	err    error
}

// finish calls Finish on a request to target carrying this browser's
// cookies.
func (b *browser) finish(p *oidc.Provider, cb oidc.Callback, target string) finished {
	b.t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range b.jar.Cookies(b.app) {
		r.AddCookie(c)
	}
	return b.finishRequest(p, cb, r)
}

func (b *browser) finishRequest(p *oidc.Provider, cb oidc.Callback, r *http.Request) finished {
	rec := httptest.NewRecorder()
	flow, claims, err := p.Finish(rec, r, b.session, cb)
	resp := rec.Result()
	b.jar.SetCookies(b.app, resp.Cookies())
	return finished{resp: resp, flow: flow, claims: claims, err: err}
}

// run is one whole flow: Begin, the IdP's authorize, Finish.
func (b *browser) run(idp *accesstest.IdP, p *oidc.Provider, req oidc.BeginRequest) finished {
	b.t.Helper()
	authURL, _, err := b.begin(p, req, nil)
	if err != nil {
		b.t.Fatalf("Begin: %v", err)
	}
	cb, loc := b.authorize(idp, authURL)
	return b.finish(p, cb, loc.String())
}

// wantFlow compares the request a flow began with to the Flow Finish
// returned.
func wantFlow(t *testing.T, got oidc.Flow, req oidc.BeginRequest) {
	t.Helper()
	if got.Intent != req.Intent || got.SessionID != req.SessionID || got.UserID != req.UserID || got.Redirect != req.Redirect || !bytes.Equal(got.InviteHash, req.InviteHash) || got.BeganAt.IsZero() {
		t.Errorf("Flow = %+v, want the sealed %+v", got, req)
	}
}

func wantZeroFlow(t *testing.T, f finished) {
	t.Helper()
	if !reflect.ValueOf(f.flow).IsZero() {
		t.Errorf("Flow = %+v, want the zero Flow", f.flow)
	}
}

// cleared reports whether resp clears the cookie named name.
func cleared(resp *http.Response, name string) bool {
	for _, c := range resp.Cookies() {
		if c.Name == name && c.MaxAge < 0 && c.Value == "" {
			return true
		}
	}
	return false
}

// recordingTransport stands in for an app's SSRF-guarding transport: it
// records the path of every request it carries.
type recordingTransport struct {
	next  http.RoundTripper
	paths []string
	mu    sync.Mutex
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.paths = append(rt.paths, r.URL.Path)
	rt.mu.Unlock()
	return rt.next.RoundTrip(r)
}

func (rt *recordingTransport) saw(path string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return slices.Contains(rt.paths, path)
}

func TestFlow(t *testing.T) { //nolint:paralleltest // the outbound/hung_jwks case shortens a package default, which no parallel test may read meanwhile
	t.Run("accepted", flowAccepted)
	t.Run("refused", flowRefused)
	t.Run("claims", flowClaims)
	t.Run("flow_cookie", flowCookie)
	t.Run("provider_errors", flowProviderErrors)
	t.Run("reauthentication", flowReauthentication)
	t.Run("begin_guard", flowBeginGuard)
	t.Run("outbound", flowOutbound)
	t.Run("config", flowConfig)
	t.Run("cookie_name", flowCookieName)
	t.Run("callback", flowCallback)
	t.Run("discovery", flowDiscovery)
	t.Run("key_rotation", flowKeyRotation)
	t.Run("embedded_key", flowEmbeddedKey)
}

func flowAccepted(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	p := mustProvider(t, configFor(idp))
	b := newBrowser(t)
	f := b.run(idp, p, signIn)
	if f.err != nil {
		t.Fatalf("Finish: %v", f.err)
	}
	wantFlow(t, f.flow, signIn)
	c := f.claims
	if want := (access.OIDCIdentity{Issuer: idp.Issuer(), Subject: accesstest.DefaultIdPSubject}); c.Identity != want {
		t.Errorf("Identity = %+v, want %+v", c.Identity, want)
	}
	if c.Email != accesstest.DefaultIdPEmail || !c.EmailVerified || c.PreferredUsername != accesstest.DefaultIdPUsername {
		t.Errorf("Claims = %+v, want the IdP's user", c)
	}
	if c.AuthTime.IsZero() {
		t.Error("AuthTime is zero, want the IdP's auth_time")
	}
	if _, ok := c.Raw["sub"]; !ok {
		t.Error("Raw lacks sub")
	}
	if !cleared(f.resp, b.flowCookie()) {
		t.Error("Finish did not clear the flow cookie")
	}
	q := idp.Authorizations()[0]
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Errorf("authorize request %v lacks PKCE S256, nonce or state", q)
	}
	if got := q.Get("scope"); got != "openid profile email" {
		t.Errorf("scope = %q, want the default openid profile email", got)
	}
	t.Run("exp_inside_the_skew", func(t *testing.T) {
		// exp one minute past is inside the 5-minute skew (OpenID Connect
		// Core 1.0 §3.1.3.7 step 9; RFC 7519 §4.1.4).
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{Lifetime: -time.Minute})
		if f := newBrowser(t).run(idp, mustProvider(t, configFor(idp)), signIn); f.err != nil {
			t.Errorf("a token one minute past exp: Finish = %v, want nil", f.err)
		}
	})
	t.Run("https_dns_issuer", func(t *testing.T) {
		const issuer = "https://idp.example.com:8443"
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{URL: issuer})
		cfg := configFor(idp)
		cfg.HTTPClient = idp.Client()
		f := newBrowser(t).run(idp, mustProvider(t, cfg), signIn)
		if f.err != nil {
			t.Fatalf("Finish: %v", f.err)
		}
		if f.claims.Identity.Issuer != issuer {
			t.Errorf("Identity.Issuer = %q, want %q", f.claims.Identity.Issuer, issuer)
		}
	})
}

func flowRefused(t *testing.T) {
	cases := map[string]struct {
		want error
		opts accesstest.IdPOptions
	}{
		"nonce":       {oidc.ErrNonceMismatch, accesstest.IdPOptions{Nonce: new("another-nonce")}},
		"empty_nonce": {oidc.ErrNonceMismatch, accesstest.IdPOptions{Nonce: new("")}},
		"aud":         {oidc.ErrTokenInvalid, accesstest.IdPOptions{Audience: []string{"another-client"}}},
		"multi_aud":   {oidc.ErrTokenInvalid, accesstest.IdPOptions{Audience: []string{accesstest.DefaultIdPClientID, "another-client"}, AuthorizedParty: accesstest.DefaultIdPClientID}},
		"azp":         {oidc.ErrTokenInvalid, accesstest.IdPOptions{AuthorizedParty: "another-client"}},
		// exp six minutes past is beyond the 5-minute skew (OpenID Connect
		// Core 1.0 §3.1.3.7 step 9; RFC 7519 §4.1.4).
		"expired":   {oidc.ErrTokenInvalid, accesstest.IdPOptions{Lifetime: -6 * time.Minute}},
		"alg_none":  {oidc.ErrTokenInvalid, accesstest.IdPOptions{Algorithm: accesstest.AlgNone}},
		"hs256":     {oidc.ErrTokenInvalid, accesstest.IdPOptions{Algorithm: accesstest.AlgHS256}},
		"empty_sub": {oidc.ErrTokenInvalid, accesstest.IdPOptions{Subject: new("")}},
		// Google's scheme-less iss stands for https://accounts.google.com
		// alone (OpenID Connect Core 1.0 §3.1.3.7 step 2).
		"google_iss_elsewhere": {oidc.ErrTokenInvalid, accesstest.IdPOptions{IssuerClaim: "accounts.google.com"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			idp := accesstest.NewIdP(t, tc.opts)
			p := mustProvider(t, configFor(idp))
			f := newBrowser(t).run(idp, p, signIn)
			if !errors.Is(f.err, tc.want) {
				t.Fatalf("Finish = %v, want %v", f.err, tc.want)
			}
			if !reflect.DeepEqual(f.claims, oidc.Claims{}) {
				t.Errorf("Claims = %+v on a refusal, want zero", f.claims)
			}
			wantFlow(t, f.flow, signIn)
		})
	}
	t.Run("issuer", func(t *testing.T) {
		t.Parallel()
		// idp's discovery sends the code to other, whose token is signed
		// with the keys idp's JWKS serves and differs from idp's only by iss.
		other := accesstest.NewIdP(t, accesstest.IdPOptions{})
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{AuthorizationEndpoint: other.Issuer() + "/authorize", TokenEndpoint: other.Issuer() + "/token"})
		f := newBrowser(t).run(other, mustProvider(t, configFor(idp)), signIn)
		if !errors.Is(f.err, oidc.ErrTokenInvalid) {
			t.Fatalf("Finish over another issuer's token = %v, want ErrTokenInvalid", f.err)
		}
		if !reflect.DeepEqual(f.claims, oidc.Claims{}) {
			t.Errorf("Claims = %+v on a refusal, want zero", f.claims)
		}
		wantFlow(t, f.flow, signIn)
	})
	t.Run("matching_azp", func(t *testing.T) {
		t.Parallel()
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{AuthorizedParty: accesstest.DefaultIdPClientID, Algorithm: accesstest.AlgES256})
		if f := newBrowser(t).run(idp, mustProvider(t, configFor(idp)), signIn); f.err != nil {
			t.Errorf("an ES256 token with azp equal to the client: Finish = %v, want nil", f.err)
		}
	})
}

func flowClaims(t *testing.T) {
	cases := map[string]struct {
		check func(*testing.T, oidc.Claims)
		opts  accesstest.IdPOptions
	}{
		"email_verified_string_true": {func(t *testing.T, c oidc.Claims) {
			if !c.EmailVerified {
				t.Error(`email_verified "true" decoded as false`)
			}
		}, accesstest.IdPOptions{EmailVerified: "true"}},
		"email_verified_string_false": {func(t *testing.T, c oidc.Claims) {
			if c.EmailVerified {
				t.Error(`email_verified "false" decoded as true`)
			}
		}, accesstest.IdPOptions{EmailVerified: "false"}},
		"groups_string": {func(t *testing.T, c oidc.Claims) {
			if got, ok := c.Strings("groups"); !ok || !slices.Equal(got, []string{"admins"}) {
				t.Errorf("Strings(groups) = %q, %t; want [admins]", got, ok)
			}
		}, accesstest.IdPOptions{Groups: "admins"}},
		"groups_array": {func(t *testing.T, c oidc.Claims) {
			if got, ok := c.Strings("groups"); !ok || !slices.Equal(got, []string{"staff", "admins"}) {
				t.Errorf("Strings(groups) = %q, %t; want [staff admins]", got, ok)
			}
		}, accesstest.IdPOptions{Groups: []string{"staff", "admins"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			idp := accesstest.NewIdP(t, tc.opts)
			f := newBrowser(t).run(idp, mustProvider(t, configFor(idp)), signIn)
			if f.err != nil {
				t.Fatalf("Finish: %v", f.err)
			}
			tc.check(t, f.claims)
		})
	}
}

// clock is a settable test clock.
type clock struct{ ns atomic.Int64 }

func newClock() *clock {
	c := &clock{}
	c.ns.Store(time.Now().UnixNano())
	return c
}

func (c *clock) now() time.Time            { return time.Unix(0, c.ns.Load()) }
func (c *clock) add(d time.Duration)       { c.ns.Add(int64(d)) }
func (b *browser) flowValue() *http.Cookie { return b.cookie(b.flowCookie()) }

func (b *browser) cookie(name string) *http.Cookie {
	for _, c := range b.jar.Cookies(b.app) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func flowCookie(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	// beginOnly starts a flow and authorizes it, so a case can tamper with
	// the cookie before Finish.
	beginOnly := func(t *testing.T, p *oidc.Provider, req oidc.BeginRequest) (*browser, oidc.Callback, *url.URL) {
		t.Helper()
		b := newBrowser(t)
		authURL, _, err := b.begin(p, req, nil)
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		cb, loc := b.authorize(idp, authURL)
		return b, cb, loc
	}
	t.Run("state_mismatch", func(t *testing.T) {
		t.Parallel()
		p := mustProvider(t, configFor(idp))
		b, cb, loc := beginOnly(t, p, link)
		cb.State = "another-state"
		f := b.finish(p, cb, loc.String())
		if !errors.Is(f.err, oidc.ErrFlowInvalid) {
			t.Fatalf("Finish with another state = %v, want ErrFlowInvalid", f.err)
		}
		wantFlow(t, f.flow, link)
	})
	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		p := mustProvider(t, configFor(idp))
		b, cb, loc := beginOnly(t, p, signIn)
		b.jar, _ = cookiejar.New(nil)
		f := b.finish(p, cb, loc.String())
		if !errors.Is(f.err, oidc.ErrFlowInvalid) {
			t.Fatalf("Finish without the cookie = %v, want ErrFlowInvalid", f.err)
		}
		wantZeroFlow(t, f)
	})
	t.Run("expired", func(t *testing.T) {
		t.Parallel()
		clk := newClock()
		cfg := configFor(idp)
		cfg.Now = clk.now
		p := mustProvider(t, cfg)
		b, cb, loc := beginOnly(t, p, link)
		clk.add(10*time.Minute + time.Second)
		f := b.finish(p, cb, loc.String())
		if !errors.Is(f.err, oidc.ErrFlowInvalid) || !errors.Is(f.err, access.ErrSealExpired) {
			t.Fatalf("Finish after 10 minutes = %v, want ErrFlowInvalid wrapping access.ErrSealExpired", f.err)
		}
		wantZeroFlow(t, f)
	})
	tampered := map[string]func(*testing.T, *access.Sealer, *http.Cookie) []*http.Cookie{
		"forged": func(_ *testing.T, _ *access.Sealer, c *http.Cookie) []*http.Cookie {
			c.Value = strings.Repeat("A", len(c.Value))
			return []*http.Cookie{c}
		},
		"other_purpose": func(t *testing.T, s *access.Sealer, c *http.Cookie) []*http.Cookie {
			payload, err := s.Open("oidc-flow", c.Value, time.Now())
			if err != nil {
				t.Fatalf("Open the flow cookie: %v", err)
			}
			if c.Value, err = s.Seal("oidc-pending", payload, time.Now().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			return []*http.Cookie{c}
		},
		"two_cookies": func(_ *testing.T, _ *access.Sealer, c *http.Cookie) []*http.Cookie {
			return []*http.Cookie{c, c}
		},
	}
	for name, tamper := range tampered {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := configFor(idp)
			cfg.FlowSealer = access.NewEphemeralSealer()
			p := mustProvider(t, cfg)
			b, cb, loc := beginOnly(t, p, link)
			r := httptest.NewRequest(http.MethodGet, loc.String(), nil)
			for _, c := range tamper(t, cfg.FlowSealer, b.flowValue()) {
				r.AddCookie(c)
			}
			f := b.finishRequest(p, cb, r)
			if !errors.Is(f.err, oidc.ErrFlowInvalid) {
				t.Fatalf("Finish = %v, want ErrFlowInvalid", f.err)
			}
			wantZeroFlow(t, f)
		})
	}
	other := accesstest.NewIdP(t, accesstest.IdPOptions{})
	edits := map[string]func(*oidc.Config){
		"client_id": func(c *oidc.Config) { c.ClientID = "another-client" },
		"issuer":    func(c *oidc.Config) { c.IssuerURL = other.Issuer() },
		"redirect":  func(c *oidc.Config) { c.RedirectURL = "https://app.example/other" },
	}
	for name, edit := range edits {
		t.Run("provider_edited/"+name, func(t *testing.T) {
			t.Parallel()
			cfg := configFor(idp)
			cfg.FlowSealer = access.NewEphemeralSealer()
			b, cb, loc := beginOnly(t, mustProvider(t, cfg), link)
			edit(&cfg)
			f := b.finish(mustProvider(t, cfg), cb, loc.String())
			if !errors.Is(f.err, oidc.ErrFlowInvalid) {
				t.Fatalf("Finish under the edited provider = %v, want ErrFlowInvalid", f.err)
			}
			wantZeroFlow(t, f)
		})
	}
	t.Run("cleared_on_every_outcome", func(t *testing.T) {
		t.Parallel()
		p := mustProvider(t, configFor(idp))
		outcomes := map[string]func(*oidc.Callback, *browser){
			"success":        func(*oidc.Callback, *browser) {},
			"state_mismatch": func(cb *oidc.Callback, _ *browser) { cb.State = "x" },
			"provider_error": func(cb *oidc.Callback, _ *browser) { cb.Code, cb.Error = "", "access_denied" },
			"bad_code":       func(cb *oidc.Callback, _ *browser) { cb.Code = "not-a-code" },
			"missing_cookie": func(_ *oidc.Callback, b *browser) { b.jar, _ = cookiejar.New(nil) },
		}
		for name, mod := range outcomes {
			b, cb, loc := beginOnly(t, p, signIn)
			name0 := b.flowCookie()
			mod(&cb, b)
			if f := b.finish(p, cb, loc.String()); !cleared(f.resp, name0) {
				t.Errorf("%s: Finish (%v) did not clear %s", name, f.err, name0)
			}
		}
	})
}

func flowProviderErrors(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	const description = "private-description-text-from-the-provider"
	run := func(t *testing.T, client *http.Client, cb func(sealed oidc.Callback) oidc.Callback) finished {
		t.Helper()
		cfg := configFor(idp)
		cfg.HTTPClient = client
		p := mustProvider(t, cfg)
		b := newBrowser(t)
		authURL, _, err := b.begin(p, signIn, nil)
		if err != nil {
			t.Fatal(err)
		}
		sealed, _ := b.authorize(idp, authURL)
		target := appCallback + "?error=access_denied&error_description=" + description
		return b.finish(p, cb(sealed), target)
	}
	t.Run("bad_state", func(t *testing.T) {
		t.Parallel()
		f := run(t, nil, func(oidc.Callback) oidc.Callback { return oidc.Callback{State: "wrong", Error: "access_denied"} })
		var pe *oidc.ProviderError
		if !errors.Is(f.err, oidc.ErrFlowInvalid) || errors.As(f.err, &pe) {
			t.Errorf("a provider error with a bad state: Finish = %v, want ErrFlowInvalid and no ProviderError", f.err)
		}
	})
	t.Run("good_state", func(t *testing.T) {
		t.Parallel()
		f := run(t, nil, func(s oidc.Callback) oidc.Callback { return oidc.Callback{State: s.State, Error: "access_denied"} })
		var pe *oidc.ProviderError
		if !errors.As(f.err, &pe) || pe.Code != "access_denied" {
			t.Fatalf("Finish = %v, want *ProviderError{Code: access_denied}", f.err)
		}
		if strings.Contains(f.err.Error(), description) {
			t.Errorf("the error %q carries error_description", f.err)
		}
		wantFlow(t, f.flow, signIn)
	})
	t.Run("unknown_code", func(t *testing.T) {
		t.Parallel()
		f := run(t, nil, func(s oidc.Callback) oidc.Callback { return oidc.Callback{State: s.State, Error: "made_up_code"} })
		var pe *oidc.ProviderError
		if !errors.As(f.err, &pe) || pe.Code != "other" {
			t.Errorf("Finish = %v, want *ProviderError{Code: other}", f.err)
		}
	})
	t.Run("code_only_after_state", func(t *testing.T) {
		t.Parallel()
		guard := &recordingTransport{next: http.DefaultTransport}
		f := run(t, &http.Client{Transport: guard}, func(s oidc.Callback) oidc.Callback { return oidc.Callback{State: "wrong", Code: s.Code} })
		if !errors.Is(f.err, oidc.ErrFlowInvalid) {
			t.Fatalf("Finish = %v, want ErrFlowInvalid", f.err)
		}
		if guard.saw("/token") {
			t.Error("the code was exchanged before the state matched")
		}
	})
}

// flowReauthentication is every intent but sign-in: OpenID Connect Core 1.0
// §3.1.2.1 max_age=0 and prompt=login on the authorize request, and §2's
// auth_time, required once max_age is sent, no earlier than the flow's
// start less the skew.
func flowReauthentication(t *testing.T) {
	for _, req := range []oidc.BeginRequest{link, stepUp, invite} {
		t.Run(string(req.Intent), func(t *testing.T) {
			t.Parallel()
			t.Run("fresh", func(t *testing.T) {
				t.Parallel()
				idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
				f := newBrowser(t).run(idp, mustProvider(t, configFor(idp)), req)
				if f.err != nil {
					t.Fatalf("Finish: %v", f.err)
				}
				wantFlow(t, f.flow, req)
				q := idp.Authorizations()[0]
				if q.Get("max_age") != "0" || q.Get("prompt") != "login" {
					t.Errorf("authorize request %v, want max_age=0 and prompt=login", q)
				}
			})
			for name, opts := range map[string]accesstest.IdPOptions{
				"no_auth_time":    {OmitAuthTime: true},
				"before_the_skew": {AuthTimeOffset: -2 * time.Minute},
			} {
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					idp := accesstest.NewIdP(t, opts)
					f := newBrowser(t).run(idp, mustProvider(t, configFor(idp)), req)
					if !errors.Is(f.err, oidc.ErrStaleAuthentication) {
						t.Fatalf("Finish = %v, want ErrStaleAuthentication", f.err)
					}
					wantFlow(t, f.flow, req)
				})
			}
			t.Run("inside_the_skew", func(t *testing.T) {
				t.Parallel()
				idp := accesstest.NewIdP(t, accesstest.IdPOptions{AuthTimeOffset: -50 * time.Second})
				if f := newBrowser(t).run(idp, mustProvider(t, configFor(idp)), req); f.err != nil {
					t.Errorf("auth_time 50s before the flow: Finish = %v, want nil", f.err)
				}
			})
			t.Run("forged_cookie", func(t *testing.T) {
				t.Parallel()
				idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
				p := mustProvider(t, configFor(idp))
				b := newBrowser(t)
				authURL, _, err := b.begin(p, req, nil)
				if err != nil {
					t.Fatal(err)
				}
				cb, loc := b.authorize(idp, authURL)
				c := b.flowValue()
				c.Value = "forged" + c.Value[6:]
				r := httptest.NewRequest(http.MethodGet, loc.String(), nil)
				r.AddCookie(c)
				f := b.finishRequest(p, cb, r)
				if !errors.Is(f.err, oidc.ErrFlowInvalid) {
					t.Fatalf("Finish = %v, want ErrFlowInvalid", f.err)
				}
				wantZeroFlow(t, f)
			})
			// Mattermost CVE-2025-12421, Keycloak CVE-2026-92358: a code
			// finished in a browser that did not begin its flow binds nothing.
			t.Run("other_browser", func(t *testing.T) {
				t.Parallel()
				idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
				p := mustProvider(t, configFor(idp))
				authURL, _, err := newBrowser(t).begin(p, req, nil)
				if err != nil {
					t.Fatal(err)
				}
				other := newBrowser(t)
				cb, loc := other.authorize(idp, authURL)
				f := other.finish(p, cb, loc.String())
				if !errors.Is(f.err, oidc.ErrFlowInvalid) {
					t.Fatalf("Finish in another browser = %v, want ErrFlowInvalid", f.err)
				}
				wantZeroFlow(t, f)
			})
		})
	}
	t.Run("signin_sends_neither", func(t *testing.T) {
		t.Parallel()
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{OmitAuthTime: true})
		if f := newBrowser(t).run(idp, mustProvider(t, configFor(idp)), signIn); f.err != nil {
			t.Fatalf("a sign-in without auth_time: Finish = %v, want nil", f.err)
		}
		q := idp.Authorizations()[0]
		if q.Has("max_age") || q.Has("prompt") {
			t.Errorf("sign-in authorize request %v carries max_age or prompt", q)
		}
	})
}

func flowBeginGuard(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	p := mustProvider(t, configFor(idp))
	for _, req := range []oidc.BeginRequest{link, stepUp, invite} {
		for _, site := range []string{"cross-site", "same-site", "none"} {
			t.Run(string(req.Intent)+"_"+site, func(t *testing.T) {
				t.Parallel()
				_, set, err := newBrowser(t).begin(p, req, http.Header{"Sec-Fetch-Site": {site}})
				if !errors.Is(err, oidc.ErrFlowInvalid) || len(set) != 0 {
					t.Errorf("Sec-Fetch-Site %s: Begin = %v with %d cookies, want ErrFlowInvalid and none", site, err, len(set))
				}
			})
		}
		for name, h := range map[string]http.Header{"same-origin": {"Sec-Fetch-Site": {"same-origin"}}, "absent": nil} {
			t.Run(string(req.Intent)+"_"+name, func(t *testing.T) {
				t.Parallel()
				if _, set, err := newBrowser(t).begin(p, req, h); err != nil || len(set) != 1 {
					t.Errorf("Begin = %v with %d cookies, want nil and the flow cookie", err, len(set))
				}
			})
		}
	}
	t.Run("signin_cross-site", func(t *testing.T) {
		t.Parallel()
		if _, _, err := newBrowser(t).begin(p, signIn, http.Header{"Sec-Fetch-Site": {"cross-site"}}); err != nil {
			t.Errorf("a cross-site sign-in: Begin = %v, want nil", err)
		}
	})
	t.Run("request_shape", func(t *testing.T) {
		t.Parallel()
		for name, req := range map[string]oidc.BeginRequest{
			"unknown intent":       {Intent: "admin"},
			"sign-in with a user":  {Intent: oidc.IntentSignIn, UserID: 1},
			"link without user":    {Intent: oidc.IntentLink, SessionID: "s"},
			"step-up no session":   {Intent: oidc.IntentStepUp, UserID: 1},
			"negative user":        {Intent: oidc.IntentLink, SessionID: "s", UserID: -1},
			"sign-in with a hash":  {Intent: oidc.IntentSignIn, InviteHash: invite.InviteHash},
			"link with a hash":     {Intent: oidc.IntentLink, SessionID: "s", UserID: 1, InviteHash: invite.InviteHash},
			"invite with no hash":  {Intent: oidc.IntentInvite},
			"invite with a user":   {Intent: oidc.IntentInvite, InviteHash: invite.InviteHash, SessionID: "s", UserID: 1},
			"invite hash too long": {Intent: oidc.IntentInvite, InviteHash: make([]byte, oidc.MaxInviteHashBytes+1)},
		} {
			if _, set, err := newBrowser(t).begin(p, req, nil); !errors.Is(err, oidc.ErrFlowInvalid) || len(set) != 0 {
				t.Errorf("%s: Begin = %v with %d cookies, want ErrFlowInvalid and none", name, err, len(set))
			}
		}
	})
}

// clients are the two shapes every outbound case runs on: the default
// client, and an injected one with a zero Timeout over a recording
// transport.
func clients() map[string]func() (*http.Client, *recordingTransport) {
	return map[string]func() (*http.Client, *recordingTransport){
		"default": func() (*http.Client, *recordingTransport) { return nil, nil },
		"injected": func() (*http.Client, *recordingTransport) {
			guard := &recordingTransport{next: http.DefaultTransport}
			return &http.Client{Transport: guard}, guard
		},
	}
}

func flowOutbound(t *testing.T) {
	t.Run("hung_jwks", func(t *testing.T) {
		oidc.SetDefaultHTTPTimeout(t, 500*time.Millisecond)
		for name, mk := range clients() {
			idp := accesstest.NewIdP(t, accesstest.IdPOptions{JWKS: accesstest.IdPEndpoint{Delay: time.Hour}})
			client, _ := mk()
			cfg := configFor(idp)
			cfg.HTTPClient = client
			// The backstop ends a NewProvider whose client has no timeout,
			// which then fails the elapsed check instead of hanging.
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			start := time.Now()
			_, err := oidc.NewProvider(ctx, cfg)
			cancel()
			if elapsed := time.Since(start); !errors.Is(err, oidc.ErrDiscovery) || elapsed > 10*time.Second {
				t.Errorf("%s: NewProvider over a hung JWKS = %v after %v, want ErrDiscovery within the client timeout", name, err, elapsed)
			}
		}
	})
	t.Run("jwks_refused", func(t *testing.T) {
		t.Parallel()
		outboundJWKS(t)
	})
	t.Run("token_redirect", func(t *testing.T) {
		t.Parallel()
		outboundTokenRedirect(t)
	})
	t.Run("body_cap", func(t *testing.T) {
		for name, mk := range clients() {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				outboundBodyCap(t, mk)
			})
		}
	})
	t.Run("guard_sees_every_request", func(t *testing.T) {
		t.Parallel()
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
		client, guard := clients()["injected"]()
		cfg := configFor(idp)
		cfg.HTTPClient = client
		if f := newBrowser(t).run(idp, mustProvider(t, cfg), signIn); f.err != nil {
			t.Fatalf("Finish: %v", f.err)
		}
		for _, path := range []string{"/.well-known/openid-configuration", "/jwks", "/token"} {
			if !guard.saw(path) {
				t.Errorf("the injected transport never saw %s", path)
			}
		}
	})
	t.Run("redirect", func(t *testing.T) {
		t.Parallel()
		outboundRedirect(t)
	})
	t.Run("client_unchanged", func(t *testing.T) {
		t.Parallel()
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
		guard := &recordingTransport{next: http.DefaultTransport}
		jar, _ := cookiejar.New(nil)
		check := func(*http.Request, []*http.Request) error { return nil }
		given := &http.Client{Transport: guard, Jar: jar, CheckRedirect: check}
		cfg := configFor(idp)
		cfg.HTTPClient = given
		p := mustProvider(t, cfg)
		if given.Transport != guard || given.Jar != jar || given.Timeout != 0 || reflect.ValueOf(given.CheckRedirect).Pointer() != reflect.ValueOf(check).Pointer() {
			t.Errorf("NewProvider changed the caller's client: %+v", given)
		}
		used := oidc.ProviderHTTPClient(p)
		if used == given || used.Jar != jar || reflect.ValueOf(used.CheckRedirect).Pointer() != reflect.ValueOf(check).Pointer() {
			t.Error("the provider's client is not a copy keeping the caller's Jar and CheckRedirect")
		}
	})
	t.Run("negative_timeout", func(t *testing.T) {
		t.Parallel()
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
		cfg := configFor(idp)
		cfg.HTTPClient = &http.Client{Timeout: -time.Second}
		if _, err := oidc.NewProvider(t.Context(), cfg); !errors.Is(err, oidc.ErrConfigInvalid) {
			t.Errorf("NewProvider with a negative timeout = %v, want ErrConfigInvalid", err)
		}
	})
}

func outboundBodyCap(t *testing.T, mk func() (*http.Client, *recordingTransport)) {
	const over = 2 << 20
	newCfg := func(t *testing.T, opts accesstest.IdPOptions) (*accesstest.IdP, oidc.Config) {
		idp := accesstest.NewIdP(t, opts)
		client, _ := mk()
		cfg := configFor(idp)
		cfg.HTTPClient = client
		return idp, cfg
	}
	for name, opts := range map[string]accesstest.IdPOptions{
		"discovery":          {Discovery: accesstest.IdPEndpoint{BodyBytes: over}},
		"discovery_streamed": {Discovery: accesstest.IdPEndpoint{BodyBytes: over, Streamed: true}},
		"jwks":               {JWKS: accesstest.IdPEndpoint{BodyBytes: over}},
		"jwks_streamed":      {JWKS: accesstest.IdPEndpoint{BodyBytes: over, Streamed: true}},
	} {
		t.Run(name, func(t *testing.T) {
			_, cfg := newCfg(t, opts)
			if _, err := oidc.NewProvider(t.Context(), cfg); !errors.Is(err, oidc.ErrDiscovery) || !errors.Is(err, oidc.ErrResponseTooLarge) {
				t.Errorf("NewProvider over a 2 MiB %s body = %v, want ErrDiscovery from the cap", name, err)
			}
		})
	}
	for name, opts := range map[string]accesstest.IdPOptions{
		"discovery_at_cap": {Discovery: accesstest.IdPEndpoint{BodyBytes: 1 << 20}},
		"jwks_at_cap":      {JWKS: accesstest.IdPEndpoint{BodyBytes: 1 << 20}},
	} {
		t.Run(name, func(t *testing.T) {
			_, cfg := newCfg(t, opts)
			if _, err := oidc.NewProvider(t.Context(), cfg); err != nil {
				t.Errorf("NewProvider over a 1 MiB body = %v, want nil", err)
			}
		})
	}
	// x/oauth2 wraps a body read error with %v, so the cap is known by its
	// message: https://github.com/golang/oauth2/blob/v0.37.0/internal/token.go#L266.
	fromCap := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), oidc.ErrResponseTooLarge.Error())
	}
	for _, tc := range []struct {
		want error
		name string
		opts accesstest.IdPOptions
	}{
		{name: "token", want: oidc.ErrExchange, opts: accesstest.IdPOptions{Token: accesstest.IdPEndpoint{BodyBytes: over}}},
		{name: "token_streamed", want: oidc.ErrExchange, opts: accesstest.IdPOptions{Token: accesstest.IdPEndpoint{BodyBytes: over, Streamed: true}}},
		{name: "token_at_cap", opts: accesstest.IdPOptions{Token: accesstest.IdPEndpoint{BodyBytes: 1 << 20}}},
		{name: "token_at_cap_streamed", opts: accesstest.IdPOptions{Token: accesstest.IdPEndpoint{BodyBytes: 1 << 20, Streamed: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp, cfg := newCfg(t, tc.opts)
			f := newBrowser(t).run(idp, mustProvider(t, cfg), signIn)
			if tc.want == nil && f.err != nil || tc.want != nil && (!errors.Is(f.err, tc.want) || !fromCap(f.err)) {
				t.Errorf("Finish = %v, want %v from the cap", f.err, tc.want)
			}
		})
	}
}

// outboundRedirect serves discovery from a server whose well-known URL
// redirects to the document, which names that server as the issuer. The
// discovery fetch follows no redirect and never asks the caller's
// CheckRedirect, whatever it would allow (OpenID Connect Discovery 1.0
// §4.2; PyJWT CVE-2026-102267).
func outboundRedirect(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	var moved atomic.Int32
	var front *httptest.Server
	front = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			http.Redirect(w, r, "/moved", http.StatusFound)
		case "/moved":
			moved.Add(1)
			writeDiscovery(t, w, idp, front.URL, nil)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(front.Close)
	cfg := configFor(idp)
	cfg.IssuerURL = front.URL
	var asked atomic.Int32
	for name, check := range map[string]func(*http.Request, []*http.Request) error{
		"default client": nil,
		"a refusing CheckRedirect": func(*http.Request, []*http.Request) error {
			asked.Add(1)
			return errors.New("redirects refused")
		},
		"an allowing CheckRedirect": func(*http.Request, []*http.Request) error {
			asked.Add(1)
			return nil
		},
	} {
		cfg.HTTPClient = nil
		if check != nil {
			cfg.HTTPClient = &http.Client{CheckRedirect: check}
		}
		if _, err := oidc.NewProvider(t.Context(), cfg); !errors.Is(err, oidc.ErrDiscovery) {
			t.Errorf("%s: NewProvider through a redirect = %v, want ErrDiscovery", name, err)
		}
	}
	if asked.Load() != 0 || moved.Load() != 0 {
		t.Errorf("CheckRedirect asked %d times and the target served %d times, want 0 and 0", asked.Load(), moved.Load())
	}
}

// writeDiscovery serves idp's discovery document with issuer replaced, after
// edit when it is non-nil.
func writeDiscovery(t *testing.T, w http.ResponseWriter, idp *accesstest.IdP, issuer string, edit func(map[string]any)) {
	resp, err := idp.Client().Get(idp.Issuer() + "/.well-known/openid-configuration")
	if err != nil {
		t.Errorf("fetch the IdP's discovery: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Errorf("decode the IdP's discovery: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	doc["issuer"] = issuer
	if edit != nil {
		edit(doc)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// outboundJWKS: NewProvider reads the JWK Set and refuses with ErrDiscovery
// a set it cannot use: an answer other than 200, whose body is never
// decoded (OpenID Connect Discovery 1.0 §4.2's rule, which the JWKS fetch
// follows), a redirect, followed for no CheckRedirect and asking none
// (PyJWT CVE-2026-102267), a body that is not a JWK Set (RFC 7517 §5), and
// a set with no key of an accepted type (RFC 7517 §5: other keys are
// skipped).
func outboundJWKS(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	resp, err := idp.Client().Get(idp.Issuer() + "/jwks")
	if err != nil {
		t.Fatalf("fetch the IdP's JWKS: %v", err)
	}
	set, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read the IdP's JWKS: %v", err)
	}
	var moved atomic.Int32
	answers := map[string]func(http.ResponseWriter, *http.Request){
		"/ok": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(set) },
		"/status_500": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(set)
		},
		"/status_203": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			_, _ = w.Write(set)
		},
		"/redirect":  func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/moved", http.StatusFound) },
		"/moved":     func(w http.ResponseWriter, _ *http.Request) { moved.Add(1); _, _ = w.Write(set) },
		"/not_a_set": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"keys":{}}`)) },
		"/empty":     func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"keys":[]}`)) },
		"/oct_only": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"keys":[{"kty":"oct","kid":"h","k":"AAEC"}]}`))
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := answers[r.URL.Path]; ok {
			h(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	newCfg := func(path string) oidc.Config {
		return configFor(accesstest.NewIdP(t, accesstest.IdPOptions{JWKSURI: srv.URL + path}))
	}
	if _, err := oidc.NewProvider(t.Context(), newCfg("/ok")); err != nil {
		t.Fatalf("NewProvider over the IdP's own set from the test server = %v, want nil", err)
	}
	for _, path := range []string{"/status_500", "/status_203", "/redirect", "/not_a_set", "/empty", "/oct_only"} {
		if _, err := oidc.NewProvider(t.Context(), newCfg(path)); !errors.Is(err, oidc.ErrDiscovery) {
			t.Errorf("NewProvider over the JWKS at %s = %v, want ErrDiscovery", path, err)
		}
	}
	var asked atomic.Int32
	cfg := newCfg("/redirect")
	cfg.HTTPClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		asked.Add(1)
		return nil
	}}
	if _, err := oidc.NewProvider(t.Context(), cfg); !errors.Is(err, oidc.ErrDiscovery) {
		t.Errorf("NewProvider over a redirecting JWKS under an allowing CheckRedirect = %v, want ErrDiscovery", err)
	}
	if asked.Load() != 0 || moved.Load() != 0 {
		t.Errorf("CheckRedirect asked %d times and the target served %d times, want 0 and 0", asked.Load(), moved.Load())
	}
}

// outboundTokenRedirect: the token exchange, unlike discovery and the JWKS,
// runs under the caller's CheckRedirect, which is asked only for the token
// endpoint's redirect (RFC 9110 §15.4.8: a 307 keeps the POST and its body).
// x/oauth2 retries a failed exchange once in the other client
// authentication style, so a refusal is asked again:
// https://github.com/golang/oauth2/blob/v0.38.0/internal/token.go#L230.
func outboundTokenRedirect(t *testing.T) {
	var issuer atomic.Pointer[string]
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, *issuer.Load()+"/token", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(front.Close)
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{TokenEndpoint: front.URL + "/token"})
	iss := idp.Issuer()
	issuer.Store(&iss)
	for name, tc := range map[string]struct {
		want  error
		asked int32
	}{"allowing": {asked: 1}, "refusing": {want: oidc.ErrExchange, asked: 2}} {
		var asked atomic.Int32
		var other atomic.Int32
		cfg := configFor(idp)
		cfg.HTTPClient = &http.Client{CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if via[0].URL.Host != strings.TrimPrefix(front.URL, "http://") || via[0].URL.Path != "/token" {
				other.Add(1)
			}
			asked.Add(1)
			if tc.want != nil {
				return errors.New("redirects refused")
			}
			return nil
		}}
		if f := newBrowser(t).run(idp, mustProvider(t, cfg), signIn); !errors.Is(f.err, tc.want) {
			t.Errorf("%s CheckRedirect: Finish through a redirecting token endpoint = %v, want %v", name, f.err, tc.want)
		}
		if n := asked.Load(); n != tc.asked || other.Load() != 0 {
			t.Errorf("%s CheckRedirect asked %d times, %d of them for another request; want %d, all for the token endpoint", name, n, other.Load(), tc.asked)
		}
	}
}

func flowConfig(t *testing.T) {
	t.Run("http_issuer", func(t *testing.T) {
		t.Parallel()
		cfg := oidc.Config{IssuerURL: "http://idp.example", ClientID: "c", RedirectURL: appCallback}
		if _, err := oidc.NewProvider(t.Context(), cfg); !errors.Is(err, oidc.ErrConfigInvalid) {
			t.Errorf("NewProvider with a non-loopback http issuer = %v, want ErrConfigInvalid", err)
		}
	})
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	p := mustProvider(t, configFor(idp))
	t.Run("invalid_session", func(t *testing.T) {
		t.Parallel()
		b := newBrowser(t)
		b.session.SameSite = http.SameSiteNoneMode
		if _, set, err := b.begin(p, signIn, nil); !errors.Is(err, oidc.ErrConfigInvalid) || len(set) != 0 {
			t.Errorf("Begin = %v with %d cookies, want ErrConfigInvalid and none", err, len(set))
		}
		r := httptest.NewRequest(http.MethodGet, appCallback, nil)
		if f := b.finishRequest(p, oidc.Callback{}, r); !errors.Is(f.err, oidc.ErrConfigInvalid) || len(f.resp.Cookies()) != 0 {
			t.Errorf("Finish = %v with %d cookies, want ErrConfigInvalid and none", f.err, len(f.resp.Cookies()))
		}
	})
	t.Run("redirect_too_long", func(t *testing.T) {
		t.Parallel()
		for _, n := range []int{oidc.MaxRedirectBytes + 1, 2049} {
			req := signIn
			req.Redirect = "/" + strings.Repeat("a", n-1)
			if _, set, err := newBrowser(t).begin(p, req, nil); !errors.Is(err, oidc.ErrRedirectTooLong) || len(set) != 0 {
				t.Errorf("a %d-byte redirect: Begin = %v with %d cookies, want ErrRedirectTooLong and none", n, err, len(set))
			}
		}
	})
	t.Run("long_cookie_name", func(t *testing.T) {
		t.Parallel()
		b := newBrowser(t)
		b.session.Name = strings.Repeat("n", access.MaxCookieNameBytes+1)
		_, set, err := b.begin(p, signIn, nil)
		if !errors.Is(err, oidc.ErrConfigInvalid) || len(set) != 0 {
			t.Errorf("Begin with a %d-byte session cookie Name = %v with %d cookies, want ErrConfigInvalid and none", len(b.session.Name), err, len(set))
		}
	})
	t.Run("seal_too_large", func(t *testing.T) {
		t.Parallel()
		big := accesstest.NewIdP(t, accesstest.IdPOptions{ClientID: strings.Repeat("c", 3<<10)})
		if _, err := oidc.NewProvider(t.Context(), configFor(big)); !errors.Is(err, oidc.ErrConfigInvalid) || !errors.Is(err, access.ErrSealTooLarge) {
			t.Errorf("NewProvider = %v, want ErrConfigInvalid wrapping access.ErrSealTooLarge", err)
		}
	})
	t.Run("bounds_round_trip", func(t *testing.T) {
		t.Parallel()
		configBounds(t)
	})
}

// configBounds runs a step-up whose redirect is MaxRedirectBytes of "/" and
// "&" and whose issuer, client ID and redirect URL are 255 bytes each.
func configBounds(t *testing.T) {
	const base = "https://idp.example.com:8443/"
	issuer := base + strings.Repeat("i", 255-len(base))
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{URL: issuer, ClientID: strings.Repeat("c", 255)})
	cfg := configFor(idp)
	cfg.HTTPClient = idp.Client()
	cfg.RedirectURL = appCallback + "/" + strings.Repeat("r", 255-len(appCallback)-1)
	for name, n := range map[string]int{"issuer": len(cfg.IssuerURL), "client ID": len(cfg.ClientID), "redirect URL": len(cfg.RedirectURL)} {
		if n != 255 {
			t.Fatalf("the %s is %d bytes, want 255", name, n)
		}
	}
	req := stepUp
	req.Redirect = "/" + strings.Repeat("&", oidc.MaxRedirectBytes-1)
	b := newBrowser(t)
	f := b.run(idp, mustProvider(t, cfg), req)
	if f.err != nil {
		t.Fatalf("Finish: %v", f.err)
	}
	wantFlow(t, f.flow, req)
}

// flowCookieName pins that Begin always sets the secure name with Secure,
// under either posture and over either transport: a plain caller's flow
// cookie is one the browser drops.
func flowCookieName(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	p := mustProvider(t, configFor(idp))
	cases := map[string]struct {
		session access.CookieConfig
		app     string
		want    string
	}{
		"secure":            {access.DefaultCookieConfig(), "https://app.example/", "__Host-auth_session_oidc"},
		"per_request_https": {access.CookieConfig{Name: "pr", Posture: access.PosturePerRequest}, "https://app.example/", "__Host-pr_oidc"},
		"per_request_http":  {access.CookieConfig{Name: "pr", Posture: access.PosturePerRequest}, "http://app.example/", "__Host-pr_oidc"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tc.app+"auth/start", nil)
			if _, err := p.Begin(rec, r, tc.session, link); err != nil {
				t.Fatalf("Begin: %v", err)
			}
			set := rec.Result().Cookies()
			if len(set) != 1 || set[0].Name != tc.want {
				t.Fatalf("Begin set %v, want exactly one cookie named %s", set, tc.want)
			}
			if c := set[0]; !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || !c.Secure || c.MaxAge != 600 {
				t.Errorf("flow cookie %+v, want HttpOnly, Lax, Secure and Max-Age 600", c)
			}
		})
	}
}

func flowCallback(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	p := mustProvider(t, configFor(idp))
	start := func(t *testing.T) (*browser, oidc.Callback) {
		t.Helper()
		b := newBrowser(t)
		authURL, _, err := b.begin(p, signIn, nil)
		if err != nil {
			t.Fatal(err)
		}
		cb, _ := b.authorize(idp, authURL)
		return b, cb
	}
	query := func(kv ...string) string {
		q := url.Values{}
		for i := 0; i < len(kv); i += 2 {
			q.Set(kv[i], kv[i+1])
		}
		return appCallback + "?" + q.Encode()
	}
	t.Run("url_state_ignored", func(t *testing.T) {
		t.Parallel()
		b, sealed := start(t)
		f := b.finish(p, oidc.Callback{State: "another-state", Code: sealed.Code}, query("state", sealed.State, "code", sealed.Code))
		if !errors.Is(f.err, oidc.ErrFlowInvalid) {
			t.Errorf("the sealed state only in the URL: Finish = %v, want ErrFlowInvalid", f.err)
		}
	})
	t.Run("url_error_ignored", func(t *testing.T) {
		t.Parallel()
		b, sealed := start(t)
		f := b.finish(p, oidc.Callback{State: sealed.State, Code: sealed.Code}, query("state", "wrong", "error", "access_denied"))
		if f.err != nil {
			t.Errorf("a wrong state and an error only in the URL: Finish = %v, want nil", f.err)
		}
	})
	t.Run("url_error_with_sealed_state", func(t *testing.T) {
		t.Parallel()
		b, sealed := start(t)
		f := b.finish(p, oidc.Callback{State: sealed.State, Code: sealed.Code}, query("state", sealed.State, "error", "access_denied"))
		if f.err != nil {
			t.Errorf("an error only in the URL: Finish = %v, want nil", f.err)
		}
	})
}

func flowDiscovery(t *testing.T) {
	const secret = "query-secret"
	bad := map[string]string{
		"http":     "http://127.0.0.1:1/x?q=" + secret,
		"relative": "/x?q=" + secret,
		"hostless": "https:///x?q=" + secret,
		"opaque":   "https:idp.example/x?q=" + secret,
		"userinfo": "https://u:p@idp.example/x?q=" + secret,
	}
	set := func(o *accesstest.IdPOptions, field, v string) {
		switch field {
		case "authorization_endpoint":
			o.AuthorizationEndpoint = v
		case "token_endpoint":
			o.TokenEndpoint = v
		case "jwks_uri":
			o.JWKSURI = v
		}
	}
	for _, field := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			for name, v := range bad {
				opts := accesstest.IdPOptions{TLS: true}
				set(&opts, field, v)
				idp := accesstest.NewIdP(t, opts)
				cfg := configFor(idp)
				cfg.HTTPClient = idp.Client()
				_, err := oidc.NewProvider(t.Context(), cfg)
				if !errors.Is(err, oidc.ErrDiscovery) || !strings.Contains(fmt.Sprint(err), field) || strings.Contains(fmt.Sprint(err), secret) {
					t.Errorf("%s %s under an https issuer: NewProvider = %v, want ErrDiscovery naming the field without the URL", name, field, err)
				}
			}
			opts := accesstest.IdPOptions{}
			set(&opts, field, "http://idp.example/x")
			idp := accesstest.NewIdP(t, opts)
			if _, err := oidc.NewProvider(t.Context(), configFor(idp)); !errors.Is(err, oidc.ErrDiscovery) || !strings.Contains(fmt.Sprint(err), field) {
				t.Errorf("a non-loopback http %s under a loopback issuer: NewProvider = %v, want ErrDiscovery naming it", field, err)
			}
		})
	}
	t.Run("loopback", func(t *testing.T) {
		t.Parallel()
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
		if _, err := oidc.NewProvider(t.Context(), configFor(idp)); err != nil {
			t.Errorf("loopback http endpoints under a loopback http issuer: NewProvider = %v, want nil", err)
		}
		tls := accesstest.NewIdP(t, accesstest.IdPOptions{TLS: true})
		cfg := configFor(tls)
		cfg.HTTPClient = tls.Client()
		if f := newBrowser(t).run(tls, mustProvider(t, cfg), signIn); f.err != nil {
			t.Errorf("an https IdP: Finish = %v, want nil", f.err)
		}
	})
	t.Run("algorithms", discoveryAlgorithms)
}

// discoveryAlgorithms: the provider's set is its
// id_token_signing_alg_values_supported (OpenID Connect Discovery 1.0 §3)
// less every algorithm RFC 7518 §3 and RFC 8037 do not accept here, and
// NewProvider refuses one with nothing left with ErrDiscovery; an absent
// list is RS256 (OpenID Connect Core 1.0 §3.1.3.7 step 7). An ES256 token
// verifies only under a set that holds ES256 (RFC 8725 §3.1).
func discoveryAlgorithms(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		want    error
		list    any
		absent  bool
		refused bool
	}{
		"hs256_and_none":  {list: []string{"HS256", "none"}, refused: true},
		"empty":           {list: []string{}, refused: true},
		"not_strings":     {list: []any{"ES256", 5}, refused: true},
		"es256_among_hs":  {list: []string{"HS256", "ES256"}},
		"rs256_only":      {list: []string{"RS256"}, want: oidc.ErrTokenInvalid},
		"absent_is_rs256": {absent: true, want: oidc.ErrTokenInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var idp atomic.Pointer[accesstest.IdP]
			var front *httptest.Server
			front = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeDiscovery(t, w, idp.Load(), front.URL, func(doc map[string]any) {
					if tc.absent {
						delete(doc, "id_token_signing_alg_values_supported")
						return
					}
					doc["id_token_signing_alg_values_supported"] = tc.list
				})
			}))
			t.Cleanup(front.Close)
			idp.Store(accesstest.NewIdP(t, accesstest.IdPOptions{Algorithm: accesstest.AlgES256, IssuerClaim: front.URL}))
			cfg := configFor(idp.Load())
			cfg.IssuerURL = front.URL
			p, err := oidc.NewProvider(t.Context(), cfg)
			if tc.refused {
				if !errors.Is(err, oidc.ErrDiscovery) {
					t.Errorf("NewProvider = %v, want ErrDiscovery", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewProvider = %v, want nil", err)
			}
			if f := newBrowser(t).run(idp.Load(), p, signIn); !errors.Is(f.err, tc.want) {
				t.Errorf("Finish over an ES256 token = %v, want %v", f.err, tc.want)
			}
		})
	}
}

func TestProviderIssuer(t *testing.T) {
	t.Parallel()
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	if got := mustProvider(t, configFor(idp)).Issuer(); got != idp.Issuer() {
		t.Errorf("Issuer() = %q, want %q", got, idp.Issuer())
	}
}

func TestProviderPrinting(t *testing.T) {
	t.Parallel()
	const secret = "provider-printing-client-secret-text"
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{ClientSecret: secret})
	cfg := configFor(idp)
	cfg.FlowSealer = access.NewEphemeralSealer()
	p := mustProvider(t, cfg)
	if f := newBrowser(t).run(idp, p, signIn); f.err != nil {
		t.Fatalf("Finish: %v", f.err)
	}
	t.Run("routes", func(t *testing.T) {
		t.Parallel()
		routes := map[string]string{}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%p"} {
			routes["pointer "+verb] = fmt.Sprintf(verb, p)
			routes["value "+verb] = fmt.Sprintf(verb, *p)
			routes["config "+verb] = fmt.Sprintf(verb, cfg)
		}
		var text, js strings.Builder
		slog.New(slog.NewTextHandler(&text, nil)).Info("p", "provider", p, "config", cfg)
		slog.New(slog.NewJSONHandler(&js, nil)).Info("p", "provider", p, "config", cfg)
		routes["slog text"], routes["slog json"] = text.String(), js.String()
		for route, got := range routes {
			if printcheck.Leak(got, secret) {
				t.Errorf("%s printed the client secret: %s", route, got)
			}
		}
		if !strings.Contains(routes["slog text"], idp.Issuer()) || !strings.Contains(routes["slog text"], idp.ClientID()) {
			t.Errorf("LogValue = %s, want the issuer and client ID", routes["slog text"])
		}
	})
	t.Run("type_graph", func(t *testing.T) {
		t.Parallel()
		allow := printcheck.Allow{
			Masked: []reflect.Type{reflect.TypeFor[access.Secret]()},
			// TestSealerPrinting pins the sealer's ring.
			Types: []string{"access.Sealer"},
			Fields: []string{
				"oidc.Config.IssuerURL", "oidc.Config.ClientID", "oidc.Config.RedirectURL", "oidc.Config.Scopes",
				// The app's own logger.
				"oidc.Config.Logger",
				// The caller's own transport and jar, the SSRF guard among them.
				"http.Client.Transport", "http.Client.Jar",
				// The discovered public endpoint URLs and algorithm rows.
				"oidc.Provider.endpoint", "oidc.Provider.algs",
				// The discovered jwks_uri and the public keys fetched from it.
				"oidc.Provider.keys",
			},
		}
		for _, line := range printcheck.Unmasked(allow, reflect.TypeFor[*oidc.Provider](), reflect.TypeFor[oidc.Config]()) {
			t.Error(line)
		}
	})
}

func TestProviderConfigDefaults(t *testing.T) {
	t.Parallel()
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	big := accesstest.NewIdP(t, accesstest.IdPOptions{JWKS: accesstest.IdPEndpoint{BodyBytes: 2 << 20}})
	cfg := configFor(idp)
	p := mustProvider(t, cfg)
	client := oidc.ProviderHTTPClient(p)
	if client.Timeout != 10*time.Second {
		t.Errorf("the default client's Timeout = %v, want 10s", client.Timeout)
	}
	resp, err := client.Get(big.Issuer() + "/jwks")
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	if !errors.Is(err, oidc.ErrResponseTooLarge) {
		t.Errorf("the default client fetched a 2 MiB body: %v, want the 1 MiB cap", err)
	}
	ok := accesstest.NewIdP(t, accesstest.IdPOptions{})
	cfg = configFor(ok)
	b := newBrowser(t)
	authURL, _, err := b.begin(mustProvider(t, cfg), signIn, nil)
	if err != nil {
		t.Fatal(err)
	}
	cb, loc := b.authorize(ok, authURL)
	if f := b.finish(mustProvider(t, cfg), cb, loc.String()); !errors.Is(f.err, oidc.ErrFlowInvalid) {
		t.Errorf("a second provider from the same Config: Finish = %v, want ErrFlowInvalid", f.err)
	}
	before := time.Now().Truncate(time.Millisecond)
	f := newBrowser(t).run(ok, mustProvider(t, cfg), signIn)
	after := time.Now()
	if f.err != nil {
		t.Fatalf("Finish: %v", f.err)
	}
	if f.flow.BeganAt.Before(before) || f.flow.BeganAt.After(after) {
		t.Errorf("BeganAt = %v, want time.Now's, between %v and %v", f.flow.BeganAt, before, after)
	}
	cfg.HTTPClient = &http.Client{Timeout: -1}
	if _, err := oidc.NewProvider(t.Context(), cfg); !errors.Is(err, oidc.ErrConfigInvalid) {
		t.Errorf("a negative Timeout: NewProvider = %v, want ErrConfigInvalid", err)
	}
}

// keyTransport counts the JWKS reads it carries and keeps the body of each
// /token response. With hold set, it keeps the first /token response,
// closing minted once the IdP has signed it, until release closes. With
// replay set, it answers every /token request with replay and never asks
// the IdP.
type keyTransport struct {
	next      http.RoundTripper
	minted    chan struct{}
	release   chan struct{}
	replay    []byte
	tokens    [][]byte
	jwksReads int
	mu        sync.Mutex
	hold      bool
}

func newKeyTransport(idp *accesstest.IdP, hold bool) *keyTransport {
	return &keyTransport{next: idp.Client().Transport, hold: hold, minted: make(chan struct{}), release: make(chan struct{})}
}

func (kt *keyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if path.Base(r.URL.Path) == "token" && kt.replay != nil {
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(bytes.NewReader(kt.replay)), ContentLength: int64(len(kt.replay)), Request: r,
		}, nil
	}
	resp, err := kt.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	switch path.Base(r.URL.Path) {
	case "jwks":
		kt.mu.Lock()
		kt.jwksReads++
		kt.mu.Unlock()
	case "token":
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		kt.mu.Lock()
		kt.tokens = append(kt.tokens, body)
		hold := kt.hold
		kt.hold = false
		kt.mu.Unlock()
		if hold {
			close(kt.minted)
			select {
			case <-kt.release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
	}
	return resp, nil
}

func (kt *keyTransport) reads() int {
	kt.mu.Lock()
	defer kt.mu.Unlock()
	return kt.jwksReads
}

// lastToken is the newest /token response body; nil before the first.
func (kt *keyTransport) lastToken() []byte {
	kt.mu.Lock()
	defer kt.mu.Unlock()
	if len(kt.tokens) == 0 {
		return nil
	}
	return kt.tokens[len(kt.tokens)-1]
}

func (kt *keyTransport) lastKid() string { return idTokenKid(kt.lastToken()) }

// idTokenKid is the kid in the JWS header of a token response's id_token;
// empty when the body holds none.
func idTokenKid(body []byte) string {
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if json.Unmarshal(body, &tok) != nil {
		return ""
	}
	header, _, _ := strings.Cut(tok.IDToken, ".")
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return ""
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return h.Kid
}

// flowKeyRotation: an IdP rotating its signing key (OpenID Connect Core 1.0
// §10.1.1). NewProvider reads the JWKS, a token under a kid the set lacks
// re-reads it once, at most once a minute and never held back by
// NewProvider's read. A token under a kid the IdP retired verifies from a
// set read before the retirement, and a set read after it refuses the same
// token.
func flowKeyRotation(t *testing.T) {
	for _, alg := range []string{accesstest.AlgRS256, accesstest.AlgES256} {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			idp := accesstest.NewIdP(t, accesstest.IdPOptions{Algorithm: alg})
			sealer, clk := access.NewEphemeralSealer(), newClock()
			provider := func(kt *keyTransport) *oidc.Provider {
				cfg := configFor(idp)
				cfg.HTTPClient = &http.Client{Transport: kt}
				cfg.FlowSealer, cfg.Now = sealer, clk.now
				return mustProvider(t, cfg)
			}
			rpKeys, lateKeys := newKeyTransport(idp, false), newKeyTransport(idp, true)
			rp, late := provider(rpKeys), provider(lateKeys)
			t.Cleanup(func() {
				select {
				case <-lateKeys.release:
				default:
					close(lateKeys.release)
				}
			})
			if r, l := rpKeys.reads(), lateKeys.reads(); r != 1 || l != 1 {
				t.Errorf("JWKS reads at NewProvider = %d and %d, want 1 each", r, l)
			}

			lateBrowser := newBrowser(t)
			authURL, _, err := lateBrowser.begin(late, signIn, nil)
			if err != nil {
				t.Fatalf("Begin: %v", err)
			}
			cb, loc := lateBrowser.authorize(idp, authURL)
			heldCookies := lateBrowser.jar.Cookies(lateBrowser.app)
			lateDone := make(chan finished, 1)
			go func() { lateDone <- lateBrowser.finish(late, cb, loc.String()) }()
			select {
			case <-lateKeys.minted:
			case <-time.After(10 * time.Second):
				t.Fatal("the held sign-in's token was not minted within 10 s")
			}
			firstKid := lateKeys.lastKid()

			if f := newBrowser(t).run(idp, rp, signIn); f.err != nil {
				t.Fatalf("sign-in before RotateKey: Finish = %v", f.err)
			}
			if n := rpKeys.reads(); n != 1 {
				t.Errorf("JWKS reads after a sign-in under a kid NewProvider read = %d, want 1", n)
			}

			// The clock stands still from here to the next add, so each
			// re-read below falls within 60 s of NewProvider's read.
			idp.RotateKey()
			if f := newBrowser(t).run(idp, rp, signIn); f.err != nil {
				t.Fatalf("sign-in after RotateKey: Finish = %v, want the new key found by re-reading the JWKS", f.err)
			}
			if kid := rpKeys.lastKid(); kid == firstKid || kid == "" {
				t.Fatalf("token kid after RotateKey = %q, want one other than %q", kid, firstKid)
			}
			if n := rpKeys.reads(); n != 2 {
				t.Errorf("JWKS reads after the rotated sign-in = %d, want 2: one re-read for the new kid", n)
			}

			idp.RotateKey()
			if f := newBrowser(t).run(idp, rp, signIn); !errors.Is(f.err, oidc.ErrTokenInvalid) {
				t.Errorf("a second rotation within 60 s of the re-read: Finish = %v, want ErrTokenInvalid", f.err)
			}
			if n := rpKeys.reads(); n != 2 {
				t.Errorf("JWKS reads within 60 s of the re-read = %d, want still 2", n)
			}
			clk.add(61 * time.Second)
			if f := newBrowser(t).run(idp, rp, signIn); f.err != nil {
				t.Errorf("the same rotation 61 s later: Finish = %v, want nil", f.err)
			}
			if n := rpKeys.reads(); n != 3 {
				t.Errorf("JWKS reads 61 s after the re-read = %d, want 3", n)
			}

			idp.RetireOldKeys()
			close(lateKeys.release)
			if f := <-lateDone; f.err != nil {
				t.Errorf("the held token under the retired kid %q: Finish = %v, want it verified from the set read at NewProvider", firstKid, f.err)
			}
			if n := lateKeys.reads(); n != 1 {
				t.Errorf("JWKS reads of the provider built before the rotation = %d, want 1", n)
			}

			freshKeys := newKeyTransport(idp, false)
			freshKeys.replay = lateKeys.lastToken()
			fresh := provider(freshKeys)
			r := httptest.NewRequest(http.MethodGet, loc.String(), nil)
			for _, c := range heldCookies {
				r.AddCookie(c)
			}
			f := newBrowser(t).finishRequest(fresh, cb, r)
			if !errors.Is(f.err, oidc.ErrTokenInvalid) {
				t.Errorf("the held token at a provider built after RetireOldKeys: Finish = %v, want ErrTokenInvalid", f.err)
			}
			if !reflect.DeepEqual(f.claims, oidc.Claims{}) {
				t.Errorf("Claims = %+v on a refusal, want zero", f.claims)
			}
			if n := freshKeys.reads(); n != 2 {
				t.Errorf("JWKS reads of the provider built after RetireOldKeys = %d, want 2: NewProvider's and one for the miss", n)
			}
		})
	}
}

// forgeTransport swaps the id_token of every /token response for one the
// test signs with key under kid, carrying key's public half in its jwk
// header and claims the provider would accept.
type forgeTransport struct {
	next http.RoundTripper
	idp  *accesstest.IdP
	key  *rsa.PrivateKey
	kid  string
}

func (ft *forgeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := ft.next.RoundTrip(r)
	if err != nil || path.Base(r.URL.Path) != "token" {
		return resp, err
	}
	var body map[string]any
	err = json.NewDecoder(resp.Body).Decode(&body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	auths := ft.idp.Authorizations()
	now := time.Now()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": ft.kid, "jwk": publicJWK(&ft.key.PublicKey, ft.kid)})
	payload, _ := json.Marshal(map[string]any{
		"iss": ft.idp.Issuer(), "sub": accesstest.DefaultIdPSubject, "aud": ft.idp.ClientID(),
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": auths[len(auths)-1].Get("nonce"),
	})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, ft.key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, err
	}
	body["id_token"] = input + "." + base64.RawURLEncoding.EncodeToString(sig)
	out, _ := json.Marshal(body)
	resp.Body, resp.ContentLength = io.NopCloser(bytes.NewReader(out)), int64(len(out))
	resp.Header.Del("Content-Length")
	return resp, nil
}

func publicJWK(pub *rsa.PublicKey, kid string) map[string]string {
	return map[string]string{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// flowEmbeddedKey: a token under a kid the provider's set lacks, whose jwk
// header carries the very key that signed it, is refused after one re-read
// of the JWKS: a key is never taken from the token (RFC 8725 §3.10;
// Authlib CVE-2026-27962). The control serves that key in the JWKS, where
// the same token verifies.
func flowEmbeddedKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "attacker"
	for name, published := range map[string]bool{"key_only_in_the_header": false, "key_in_the_jwks": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var idp atomic.Pointer[accesstest.IdP]
			var reads atomic.Int32
			jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reads.Add(1)
				resp, err := idp.Load().Client().Get(idp.Load().Issuer() + "/jwks")
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				var set struct {
					Keys []any `json:"keys"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				if published {
					set.Keys = append(set.Keys, publicJWK(&key.PublicKey, kid))
				}
				_ = json.NewEncoder(w).Encode(set)
			}))
			t.Cleanup(jwks.Close)
			idp.Store(accesstest.NewIdP(t, accesstest.IdPOptions{JWKSURI: jwks.URL + "/jwks"}))
			cfg := configFor(idp.Load())
			cfg.HTTPClient = &http.Client{Transport: &forgeTransport{next: http.DefaultTransport, idp: idp.Load(), key: key, kid: kid}}
			f := newBrowser(t).run(idp.Load(), mustProvider(t, cfg), signIn)
			if published {
				if f.err != nil {
					t.Errorf("the forged token with its key in the JWKS: Finish = %v, want nil", f.err)
				}
				return
			}
			if !errors.Is(f.err, oidc.ErrTokenInvalid) {
				t.Errorf("a token whose key is only in its jwk header: Finish = %v, want ErrTokenInvalid", f.err)
			}
			if n := reads.Load(); n != 2 {
				t.Errorf("JWKS reads = %d, want 2: NewProvider's and one for the unknown kid", n)
			}
		})
	}
}

// captureLogs points slog.Default at a text handler until t's cleanup; the
// caller must not run in parallel.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// TestProviderLogger: a JWKS re-read that fails keeps the cached set and
// WARNs on Config.Logger, or, when it is nil, on slog.Default as it stands
// at the re-read, not at NewProvider.
func TestProviderLogger(t *testing.T) { //nolint:paralleltest // swaps slog.Default
	for name, own := range map[string]bool{"config_logger": true, "nil_is_default_at_call_time": false} {
		t.Run(name, func(t *testing.T) {
			var idp atomic.Pointer[accesstest.IdP]
			var failing atomic.Bool
			jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if failing.Load() {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				resp, err := idp.Load().Client().Get(idp.Load().Issuer() + "/jwks")
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				_, _ = io.Copy(w, resp.Body)
			}))
			t.Cleanup(jwks.Close)
			idp.Store(accesstest.NewIdP(t, accesstest.IdPOptions{JWKSURI: jwks.URL + "/jwks"}))
			cfg := configFor(idp.Load())
			var given bytes.Buffer
			if own {
				cfg.Logger = slog.New(slog.NewTextHandler(&given, nil))
			}
			p := mustProvider(t, cfg)
			deflt := captureLogs(t)
			failing.Store(true)
			idp.Load().RotateKey()
			if f := newBrowser(t).run(idp.Load(), p, signIn); !errors.Is(f.err, oidc.ErrTokenInvalid) {
				t.Errorf("a new kid while the JWKS fails: Finish = %v, want ErrTokenInvalid", f.err)
			}
			if f := newBrowser(t).run(idp.Load(), p, signIn); !errors.Is(f.err, oidc.ErrTokenInvalid) {
				t.Errorf("a second sign-in within the gate: Finish = %v, want ErrTokenInvalid", f.err)
			}
			want, unwanted := deflt, &given
			if own {
				want, unwanted = &given, deflt
			}
			if got := want.String(); strings.Count(got, "level=WARN") != 1 || !strings.Contains(got, "JWKS refetch failed") {
				t.Errorf("logs = %q, want one WARN for the one failed re-read", got)
			}
			if unwanted.Len() != 0 {
				t.Errorf("the other logger received %q, want nothing", unwanted.String())
			}
		})
	}
}
