package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
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
	return flow.CookieName(httptest.NewRequest(http.MethodGet, b.app.String(), nil))
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
	if got.Intent != req.Intent || got.SessionID != req.SessionID || got.UserID != req.UserID || got.Redirect != req.Redirect || got.BeganAt.IsZero() {
		t.Errorf("Flow = %+v, want the sealed %+v", got, req)
	}
}

func wantZeroFlow(t *testing.T, f finished) {
	t.Helper()
	if f.flow != (oidc.Flow{}) {
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
	t.Run("stepup_and_link", flowStepUpAndLink)
	t.Run("begin_guard", flowBeginGuard)
	t.Run("outbound", flowOutbound)
	t.Run("config", flowConfig)
	t.Run("cookie_name", flowCookieName)
	t.Run("callback", flowCallback)
	t.Run("discovery", flowDiscovery)
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
		"expired":     {oidc.ErrTokenInvalid, accesstest.IdPOptions{Lifetime: -time.Minute}},
		"alg_none":    {oidc.ErrTokenInvalid, accesstest.IdPOptions{Algorithm: accesstest.AlgNone}},
		"hs256":       {oidc.ErrTokenInvalid, accesstest.IdPOptions{Algorithm: accesstest.AlgHS256}},
		"empty_sub":   {oidc.ErrTokenInvalid, accesstest.IdPOptions{Subject: new("")}},
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

func flowStepUpAndLink(t *testing.T) {
	for _, req := range []oidc.BeginRequest{link, stepUp} {
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
	for _, req := range []oidc.BeginRequest{link, stepUp} {
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
			"unknown intent":      {Intent: "admin"},
			"sign-in with a user": {Intent: oidc.IntentSignIn, UserID: 1},
			"link without user":   {Intent: oidc.IntentLink, SessionID: "s"},
			"step-up no session":  {Intent: oidc.IntentStepUp, UserID: 1},
			"negative user":       {Intent: oidc.IntentLink, SessionID: "s", UserID: -1},
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
			p := mustProvider(t, cfg)
			b := newBrowser(t)
			authURL, _, err := b.begin(p, signIn, nil)
			if err != nil {
				t.Fatal(err)
			}
			cb, loc := b.authorize(idp, authURL)
			// The backstop ends a run whose client has no timeout, which then
			// fails the elapsed check instead of hanging.
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			start := time.Now()
			r := httptest.NewRequestWithContext(ctx, http.MethodGet, loc.String(), nil)
			for _, c := range b.jar.Cookies(b.app) {
				r.AddCookie(c)
			}
			f := b.finishRequest(p, cb, r)
			cancel()
			if elapsed := time.Since(start); !errors.Is(f.err, oidc.ErrTokenInvalid) || elapsed > 10*time.Second {
				t.Errorf("%s: Finish over a hung JWKS = %v after %v, want ErrTokenInvalid within the client timeout", name, f.err, elapsed)
			}
		}
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
	// go-oidc and x/oauth2 wrap a body read error with %v, so the cap is
	// known by its message:
	// https://github.com/coreos/go-oidc/blob/v3.21.0/oidc/oidc.go#L314,
	// https://github.com/coreos/go-oidc/blob/v3.21.0/oidc/jwks.go#L317,
	// https://github.com/golang/oauth2/blob/v0.37.0/internal/token.go#L266.
	fromCap := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), oidc.ErrResponseTooLarge.Error())
	}
	for name, ep := range map[string]accesstest.IdPEndpoint{
		"discovery":          {BodyBytes: over},
		"discovery_streamed": {BodyBytes: over, Streamed: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, cfg := newCfg(t, accesstest.IdPOptions{Discovery: ep})
			if _, err := oidc.NewProvider(t.Context(), cfg); !errors.Is(err, oidc.ErrDiscovery) || !fromCap(err) {
				t.Errorf("NewProvider over a 2 MiB discovery body = %v, want ErrDiscovery from the cap", err)
			}
		})
	}
	t.Run("discovery_at_cap", func(t *testing.T) {
		_, cfg := newCfg(t, accesstest.IdPOptions{Discovery: accesstest.IdPEndpoint{BodyBytes: 1 << 20}})
		if _, err := oidc.NewProvider(t.Context(), cfg); err != nil {
			t.Errorf("NewProvider over a 1 MiB discovery body = %v, want nil", err)
		}
	})
	for _, tc := range []struct {
		want error
		name string
		opts accesstest.IdPOptions
	}{
		{name: "jwks", want: oidc.ErrTokenInvalid, opts: accesstest.IdPOptions{JWKS: accesstest.IdPEndpoint{BodyBytes: over}}},
		{name: "jwks_streamed", want: oidc.ErrTokenInvalid, opts: accesstest.IdPOptions{JWKS: accesstest.IdPEndpoint{BodyBytes: over, Streamed: true}}},
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
// redirects to the document, which names that server as the issuer.
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
			writeDiscovery(t, w, idp, front.URL)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(front.Close)
	cfg := configFor(idp)
	cfg.IssuerURL = front.URL
	if _, err := oidc.NewProvider(t.Context(), cfg); err != nil {
		t.Errorf("default client: NewProvider through a redirect = %v, want nil", err)
	}
	var asked atomic.Int32
	cfg.HTTPClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		asked.Add(1)
		return errors.New("redirects refused")
	}}
	before := moved.Load()
	if _, err := oidc.NewProvider(t.Context(), cfg); !errors.Is(err, oidc.ErrDiscovery) {
		t.Errorf("a refusing CheckRedirect: NewProvider = %v, want ErrDiscovery", err)
	}
	if asked.Load() != 1 || moved.Load() != before {
		t.Errorf("CheckRedirect asked %d times and the target served %d times, want 1 and 0", asked.Load(), moved.Load()-before)
	}
	cfg.HTTPClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		asked.Add(1)
		return nil
	}}
	if _, err := oidc.NewProvider(t.Context(), cfg); err != nil || asked.Load() != 2 {
		t.Errorf("an allowing CheckRedirect: NewProvider = %v after %d asks, want nil after 2", err, asked.Load())
	}
}

// writeDiscovery serves idp's discovery document with issuer replaced.
func writeDiscovery(t *testing.T, w http.ResponseWriter, idp *accesstest.IdP, issuer string) {
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
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

func flowCookieName(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	p := mustProvider(t, configFor(idp))
	cases := map[string]struct {
		session access.CookieConfig
		app     string
		secure  bool
	}{
		"secure":            {access.DefaultCookieConfig(), "https://app.example/", true},
		"insecure_lan":      {access.CookieConfig{Name: "lan", Posture: access.PostureInsecureLAN}, "http://app.example/", false},
		"per_request_https": {access.CookieConfig{Name: "pr", Posture: access.PosturePerRequest, HTTPS: access.RequestIsHTTPS}, "https://app.example/", true},
		"per_request_http":  {access.CookieConfig{Name: "pr", Posture: access.PosturePerRequest, HTTPS: access.RequestIsHTTPS}, "http://app.example/", false},
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
			flow := tc.session.Derive("oidc", http.SameSiteLaxMode)
			want := flow.CookieName(r)
			if len(set) != 1 || set[0].Name != want {
				t.Fatalf("Begin set %v, want exactly one cookie named %s", set, want)
			}
			c := set[0]
			if c.Name == tc.session.CookieName(r) || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure != tc.secure {
				t.Errorf("flow cookie %+v, want HttpOnly, Lax, Secure=%t and not the session cookie's name", c, tc.secure)
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
				// The caller's own transport and jar, the SSRF guard among them.
				"http.Client.Transport", "http.Client.Jar",
				// The discovered public endpoint URLs.
				"oidc.Provider.endpoint",
				// go-oidc's verifier: the issuer, client ID, algorithms and the
				// key set of public keys fetched from jwks_uri.
				"oidc.Provider.verifier",
			},
		}
		for _, line := range printcheck.Unmasked(allow, reflect.TypeFor[*oidc.Provider](), reflect.TypeFor[oidc.Config]()) {
			t.Error(line)
		}
	})
}

func TestProviderConfigDefaults(t *testing.T) {
	t.Parallel()
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{JWKS: accesstest.IdPEndpoint{BodyBytes: 2 << 20}})
	cfg := configFor(idp)
	p := mustProvider(t, cfg)
	client := oidc.ProviderHTTPClient(p)
	if client.Timeout != 10*time.Second {
		t.Errorf("the default client's Timeout = %v, want 10s", client.Timeout)
	}
	resp, err := client.Get(idp.Issuer() + "/jwks")
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
