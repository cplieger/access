package accesshttp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
)

// linkedAlice is an env whose alice is linked to the default IdP's
// identity, and that IdP.
func linkedAlice(t *testing.T, o envOptions) (*env, *accesstest.IdP) {
	t.Helper()
	e := newEnv(t, o)
	idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
	e.createUser(t, "alice", access.RoleUser)
	e.linkUser(t, "alice", idpIdentity(testIssuer))
	return e, idp
}

func TestOIDCSignInCallback(t *testing.T) {
	e, idp := linkedAlice(t, trustLimits)
	b := newBrowser(t)
	w := e.signInFlow(t, b, idp, "redirect="+url.QueryEscape("/home?tab=1"))
	if loc := location(t, w); loc != "/home?tab=1" {
		t.Errorf("Location %q, want the sealed /home?tab=1", loc)
	}
	session, device := e.names()
	sc := cookieNamed(w, session)
	if sc == nil || sc.Value == "" || cookieNamed(w, device) == nil {
		t.Fatalf("Set-Cookie %v, want a session and a device cookie", w.Result().Cookies())
	}
	if p := e.principal(t, sc); p.User.Username != "alice" || p.Method != access.MethodOIDC {
		t.Errorf("session for %s by %s, want alice by oidc", p.User.Username, p.Method)
	}
	if lifetime := int(e.authn.Timeouts().Absolute / time.Second); sc.MaxAge != lifetime {
		t.Errorf("session cookie Max-Age %d, want the absolute timeout %d", sc.MaxAge, lifetime)
	}
	if fc := cookieNamed(w, e.flowCookieName()); fc == nil || fc.MaxAge >= 0 {
		t.Errorf("flow cookie %v, want cleared", fc)
	}
	audits := e.audits.all()
	if len(audits) != 1 || audits[0].Kind != "oidc.callback.success" || audits[0].UserID != e.user(t, "alice").ID || audits[0].SessionID == "" {
		t.Errorf("audits %+v, want one oidc.callback.success for alice's session", audits)
	}
	e.requireTrustedDevice(t, "alice", cookieNamed(w, device))
}

func TestCallbackRedirects(t *testing.T) {
	stale := accesstest.IdPOptions{AuthTimeOffset: -time.Hour}
	// session runs one link or step-up flow from alice's session back to
	// target and returns the callback's Location.
	session := func(t *testing.T, o accesstest.IdPOptions, route, target string, linked bool) (*env, *httptest.ResponseRecorder) {
		t.Helper()
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, o, nil)
		b := e.signedInBrowser(t, "alice")
		if linked {
			e.linkUser(t, "alice", idpIdentity(testIssuer))
		}
		return e, e.sessionFlow(t, b, idp, route, target, nil)
	}
	t.Run("stepped_up", func(t *testing.T) {
		e := newEnv(t, trustLimits)
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		old := e.signedInBrowser(t, "alice")
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		before := old.jar.Cookies(old.app)
		w := e.sessionFlow(t, old, idp, "authOIDCStartStepUp", "/keys?new=1", nil)
		if loc := location(t, w); loc != "/keys?new=1&oidc=stepped_up" {
			t.Errorf("Location %q, want /keys?new=1&oidc=stepped_up", loc)
		}
		name, device := e.names()
		sc := cookieNamed(w, name)
		if sc == nil || cookieNamed(w, device) == nil || slices.ContainsFunc(before, func(c *http.Cookie) bool { return c.Value == sc.Value }) {
			t.Fatalf("Set-Cookie %v, want a new session cookie and a device cookie", w.Result().Cookies())
		}
		if p := e.principal(t, sc); p.Method != access.MethodOIDC || time.Since(p.AuthTime) > time.Minute {
			t.Errorf("rotated session by %s at %v, want oidc now", p.Method, p.AuthTime)
		}
		if lifetime := int(e.authn.Timeouts().Absolute / time.Second); sc.MaxAge != lifetime {
			t.Errorf("session cookie Max-Age %d, want the absolute timeout %d", sc.MaxAge, lifetime)
		}
		e.requireTrustedDevice(t, "alice", cookieNamed(w, device))
	})
	t.Run("linked", func(t *testing.T) {
		e, w := session(t, accesstest.IdPOptions{}, "authOIDCStartLink", "/settings", false)
		if loc := location(t, w); loc != "/settings?oidc=linked" {
			t.Errorf("Location %q, want /settings?oidc=linked", loc)
		}
		if got := e.user(t, "alice").OIDC; got != idpIdentity(testIssuer) {
			t.Errorf("alice linked to %+v, want the IdP's identity", got)
		}
		e.requireLinkRotated(t, w, "alice")
	})
	for _, tc := range []struct {
		name, route, target, want string
		o                         accesstest.IdPOptions
		linked                    bool
	}{
		{"stale_link", "authOIDCStartLink", "/settings", "/settings?auth_error=auth_oidc_failed", stale, false},
		{"stale_step_up", "authOIDCStartStepUp", "/settings", "/settings?auth_error=auth_oidc_failed", stale, true},
		{"one_oidc_marker", "authOIDCStartLink", "/settings?oidc=x", "/settings?oidc=linked", accesstest.IdPOptions{}, false},
		{"success_drops_auth_error", "authOIDCStartStepUp", "/p?auth_error=x", "/p?oidc=stepped_up", accesstest.IdPOptions{}, true},
		{"failure_drops_oidc", "authOIDCStartLink", "/p?oidc=stepped_up", "/p?auth_error=auth_oidc_failed", stale, false},
		{"other_pairs_survive", "authOIDCStartLink", "/x?a=%zz&b=1", "/x?a=%zz&b=1&oidc=linked", accesstest.IdPOptions{}, false},
		{"fragment_kept", "authOIDCStartLink", "/a#x?y", "/a?oidc=linked#x?y", accesstest.IdPOptions{}, false},
		{"fragment_dot_segments_kept", "authOIDCStartLink", "/settings#/../../admin", "/settings?oidc=linked#/../../admin", accesstest.IdPOptions{}, false},
		{"non_ascii_escaped", "authOIDCStartLink", "/caf\u00e9#\u00e9", "/caf%C3%A9?oidc=linked#%C3%A9", accesstest.IdPOptions{}, false},
		{"redirect_512_bytes", "authOIDCStartLink", "/" + strings.Repeat("a", 511), "/" + strings.Repeat("a", 511) + "?oidc=linked", accesstest.IdPOptions{}, false},
		{"escaped_path_link", "authOIDCStartLink", "/A%2Fb?x=1", "/A%2Fb?x=1&oidc=linked", accesstest.IdPOptions{}, false},
		{"escaped_path_step_up", "authOIDCStartStepUp", "/A%2Fb?x=1", "/A%2Fb?x=1&oidc=stepped_up", accesstest.IdPOptions{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, w := session(t, tc.o, tc.route, tc.target, tc.linked)
			if loc := location(t, w); loc != tc.want {
				t.Errorf("Location %q, want %q", loc, tc.want)
			}
		})
	}
	t.Run("sealed_path_bytes", func(t *testing.T) {
		app, err := url.Parse("https://app.example/")
		if err != nil {
			t.Fatal(err)
		}
		for _, seed := range []string{"/%2Fevil.com/|", "/%2f</@", "/%2F%2Fevil.com x", "/a#x?y", "/A%2Fb?x=1", "/settings#/../../admin", "/a/../b/", "/caf\u00e9#\u00e9", "/a\xff"} {
			sealed := access.ValidateRedirectURI(seed)
			for _, target := range []string{
				sealed,
				withMarker(sealed, markerOIDC, "linked"),
				withMarker(sealed, markerOIDC, "stepped_up"),
				withMarker(sealed, markerError, "x"),
			} {
				w := httptest.NewRecorder()
				redirect(w, target)
				loc := w.Header().Get("Location")
				if want := asciiLocation(target); loc != want {
					t.Errorf("seed %q: Location %q, want %q", seed, loc, want)
				}
				ref, err := url.Parse(browserNormalised(loc))
				if err != nil {
					t.Errorf("seed %q: Location %q does not parse: %v", seed, loc, err)
					continue
				}
				if got := app.ResolveReference(ref); got.Scheme != "https" || got.Host != "app.example" {
					t.Errorf("seed %q: Location %q resolves to %s", seed, loc, got)
				}
			}
		}
	})
	t.Run("forged_flow_cookie", func(t *testing.T) {
		e, idp := linkedAlice(t, envOptions{})
		b := newBrowser(t)
		cb := authorize(t, idp, e.startSignIn(t, b, ""))
		b.jar.SetCookies(b.app, []*http.Cookie{{Name: e.flowCookieName(), Value: "forged"}})
		if loc := location(t, e.callback(t, b, cb)); loc != "/signin?auth_error=auth_oidc_failed" {
			t.Errorf("Location %q, want /signin?auth_error=auth_oidc_failed", loc)
		}
	})
	t.Run("sign_in_path_refused", func(t *testing.T) {
		for _, signIn := range []string{"", "https://evil.example/login", "//evil.example/login"} {
			handler := envOptions{handler: func(c *Config) { c.SignInPath = signIn }}
			e, idp := linkedAlice(t, handler)
			b := newBrowser(t)
			cb := authorize(t, idp, e.startSignIn(t, b, ""))
			b.jar.SetCookies(b.app, []*http.Cookie{{Name: e.flowCookieName(), Value: "forged"}})
			if loc := location(t, e.callback(t, b, cb)); loc != "/?auth_error=auth_oidc_failed" {
				t.Errorf("SignInPath %q: failure Location %q, want /?auth_error=auth_oidc_failed", signIn, loc)
			}
			e = newEnv(t, handler)
			idp = e.useIdP(t, accesstest.IdPOptions{}, nil)
			if loc := location(t, e.signInFlow(t, newBrowser(t), idp, "")); loc != "/?oidc=not_linked" {
				t.Errorf("SignInPath %q: not-linked Location %q, want /?oidc=not_linked", signIn, loc)
			}
		}
	})
	t.Run("provider_changed", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		b := e.signedInBrowser(t, "alice")
		w := e.sessionFlow(t, b, idp, "authOIDCStartLink", "/settings", func() {
			e.useIdP(t, accesstest.IdPOptions{URL: "https://idp2.example.com"}, nil)
		})
		if loc := location(t, w); loc != "/signin?auth_error=auth_oidc_failed" {
			t.Errorf("Location %q, want /signin?auth_error=auth_oidc_failed: the flow never opened", loc)
		}
	})
	t.Run("redirect_too_long", func(t *testing.T) {
		for _, route := range []string{"authOIDCStartLink", "authOIDCStartStepUp"} {
			e := newEnv(t, envOptions{})
			e.useIdP(t, accesstest.IdPOptions{}, nil)
			b := e.signedInBrowser(t, "alice")
			rt := e.route(t, route)
			w := b.send(rt, request(rt, jsonBody(t, RedirectRequest{Redirect: "/" + strings.Repeat("a", 512)})))
			errs := e.errs.all()
			if w.Code != http.StatusBadRequest || len(errs) != 1 || errs[0].Code != access.CodeBadRequest || errs[0].Reason != "redirect_too_long" {
				t.Errorf("%s: status %d errors %+v, want 400 auth_bad_request redirect_too_long", route, w.Code, errs)
			}
			if fc := cookieNamed(w, e.flowCookieName()); fc != nil {
				t.Errorf("%s set the flow cookie %v", route, fc)
			}
		}
	})
	t.Run("sign_in_redirect", func(t *testing.T) {
		for _, tc := range []struct{ query, want string }{
			{"redirect=/ok", "/ok"},
			{"redirect=/" + strings.Repeat("a", 512), "/"},
			{"redirect=" + url.QueryEscape("//evil.com"), "/"},
			{"redirect=/a&redirect=/b", "/"},
			{"redirect=" + url.QueryEscape("/settings#/../../admin"), "/settings#/../../admin"},
			{"redirect=" + url.QueryEscape("/#/../\r/evil.com"), "/"},
			{"redirect=" + url.QueryEscape("/caf\u00e9#\u00e9"), "/caf%C3%A9#%C3%A9"},
			{"redirect=" + url.QueryEscape("/a\xff"), "/a%FF"},
		} {
			e, idp := linkedAlice(t, envOptions{})
			if loc := location(t, e.signInFlow(t, newBrowser(t), idp, tc.query)); loc != tc.want {
				t.Errorf("%s: Location %q, want %q", tc.query[:min(len(tc.query), 40)], loc, tc.want)
			}
		}
	})
	t.Run("not_linked", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		w := e.signInFlow(t, newBrowser(t), idp, "")
		if loc := location(t, w); loc != "/signin?oidc=not_linked" {
			t.Errorf("Location %q, want /signin?oidc=not_linked", loc)
		}
		pc := cookieNamed(w, e.pendingCookieName())
		if pc == nil || pc.Value == "" {
			t.Fatalf("Set-Cookie %v, want the pending cookie", w.Result().Cookies())
		}
		if pc.MaxAge != 600 || !pc.HttpOnly || pc.SameSite != http.SameSiteLaxMode {
			t.Errorf("pending cookie %+v, want HttpOnly, Lax, Max-Age 600", pc)
		}
		sealedAt := time.Now()
		if _, err := e.h.pending.Open(pendingPurpose, pc.Value, sealedAt.Add(9*time.Minute)); err != nil {
			t.Errorf("the pending link does not open within its 10 minutes: %v", err)
		}
		if _, err := e.h.pending.Open(pendingPurpose, pc.Value, sealedAt.Add(11*time.Minute)); err == nil {
			t.Errorf("the pending link still opens after its 10 minutes")
		}
	})
}

func TestCrossSiteOIDCStart(t *testing.T) {
	t.Run("sign_in_start_only_signs_in", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		b := e.signedInBrowser(t, "alice")
		r := get(e.route(t, "authOIDCStartSignIn"), "")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		w := b.send(e.route(t, "authOIDCStartSignIn"), r)
		cb := authorize(t, idp, location(t, w))
		if loc := location(t, e.callback(t, b, cb)); loc != "/signin?oidc=not_linked" {
			t.Errorf("Location %q, want /signin?oidc=not_linked: the sealed intent is sign-in", loc)
		}
		if got := e.user(t, "alice").OIDC; !got.IsZero() {
			t.Errorf("alice linked to %+v by a sign-in start", got)
		}
	})
	for _, route := range []string{"authOIDCStartLink", "authOIDCStartStepUp"} {
		for name, set := range map[string]func(*http.Request){
			"sec_fetch_site_cross_site": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
			"sec_fetch_site_same_site":  func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") },
			"sec_fetch_site_none":       func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "none") },
			"foreign_origin":            func(r *http.Request) { r.Header.Del("Sec-Fetch-Site"); r.Header.Set("Origin", evilOrigin) },
		} {
			t.Run(route+"/"+name, func(t *testing.T) {
				e := newEnv(t, envOptions{})
				e.useIdP(t, accesstest.IdPOptions{}, nil)
				b := e.signedInBrowser(t, "alice")
				e.linkUser(t, "alice", idpIdentity(testIssuer))
				rt := e.route(t, route)
				r := request(rt, jsonBody(t, RedirectRequest{Redirect: "/settings"}))
				set(r)
				w := b.send(rt, r)
				errs := e.errs.all()
				if w.Code != http.StatusForbidden || len(errs) != 1 || errs[0].Code != access.CodeCrossOrigin {
					t.Errorf("status %d errors %+v, want 403 auth_cross_origin", w.Code, errs)
				}
				if fc := cookieNamed(w, e.flowCookieName()); fc != nil {
					t.Errorf("flow cookie %v set", fc)
				}
				if strings.Contains(w.Body.String(), "authorize") || w.Header().Get("Location") != "" {
					t.Errorf("an IdP redirect was answered: %q %q", w.Header().Get("Location"), w.Body.String())
				}
			})
		}
		t.Run(route+"/get", func(t *testing.T) {
			e := newEnv(t, envOptions{})
			rt := e.route(t, route)
			if w := do(rt, get(rt, "")); w.Code != http.StatusMethodNotAllowed {
				t.Errorf("GET %s = %d, want 405", route, w.Code)
			}
		})
	}
}

func TestOIDCProviderSwap(t *testing.T) {
	e := newEnv(t, envOptions{})
	b := e.signedInBrowser(t, "alice")
	starts := func(t *testing.T) []*httptest.ResponseRecorder {
		t.Helper()
		link := e.route(t, "authOIDCStartLink")
		return []*httptest.ResponseRecorder{
			b.send(e.route(t, "authOIDCStartSignIn"), get(e.route(t, "authOIDCStartSignIn"), "")),
			b.send(link, request(link, jsonBody(t, RedirectRequest{}))),
		}
	}
	for _, w := range starts(t) {
		if w.Code != http.StatusBadRequest || len(w.Result().Cookies()) != 0 {
			t.Errorf("OIDC off: status %d Set-Cookie %v, want 400 and none", w.Code, w.Result().Cookies())
		}
	}
	cb := do(e.route(t, "authOIDCCallback"), e.bareCallback(t))
	if loc := location(t, cb); loc != "/signin?auth_error=auth_oidc_unavailable" || len(cb.Result().Cookies()) != 0 {
		t.Errorf("OIDC off callback: Location %q Set-Cookie %v, want /signin?auth_error=auth_oidc_unavailable and none", loc, cb.Result().Cookies())
	}
	for _, er := range e.errs.all() {
		if er.Code != access.CodeOIDCUnavailable {
			t.Errorf("OIDC off answered %s, want auth_oidc_unavailable", er.Code)
		}
	}
	first := e.useIdP(t, accesstest.IdPOptions{}, nil)
	for _, w := range starts(t) {
		if fc := cookieNamed(w, e.flowCookieName()); fc == nil || fc.Value == "" {
			t.Errorf("first provider: status %d, no flow cookie named %s", w.Code, e.flowCookieName())
		}
	}
	authURL := e.startSignIn(t, b, "")
	cbReq := authorize(t, first, authURL)
	e.useIdP(t, accesstest.IdPOptions{URL: "https://idp2.example.com"}, nil)
	if loc := location(t, e.callback(t, b, cbReq)); loc != "/signin?auth_error=auth_oidc_failed" {
		t.Errorf("flow begun under the first provider, finished under the second: Location %q, want auth_oidc_failed", loc)
	}
}

func TestFlowSealerAcrossRebuild(t *testing.T) {
	e := newEnv(t, envOptions{})
	sealer := access.NewEphemeralSealer()
	idp := e.useIdP(t, accesstest.IdPOptions{}, sealer)
	e.createUser(t, "alice", access.RoleUser)
	e.linkUser(t, "alice", idpIdentity(testIssuer))
	for _, tc := range []struct {
		name   string
		sealer *access.Sealer
		want   string
	}{
		{"same_sealer", sealer, "/home"},
		{"nil_sealer", nil, "/signin?auth_error=auth_oidc_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			cb := authorize(t, idp, e.startSignIn(t, b, "redirect=/home"))
			e.provider.Store(newProvider(t, idp, tc.sealer))
			if loc := location(t, e.callback(t, b, cb)); loc != tc.want {
				t.Errorf("Location %q, want %q", loc, tc.want)
			}
			e.provider.Store(newProvider(t, idp, sealer))
		})
	}
}

func TestOIDCStartFloodNoState(t *testing.T) {
	cs := &countingStore{}
	e := newEnv(t, envOptions{edit: func(c *account.Config) { cs.wrap(c.Store); c.Store = cs }})
	e.useIdP(t, accesstest.IdPOptions{}, nil)
	limit := ratelimit.DefaultConfig().Request.Limit
	rt := e.route(t, "authOIDCStartSignIn")
	before := cs.calls.Load()
	var admitted, refused int
	for range 1000 {
		w := do(rt, get(rt, ""))
		switch {
		case w.Code == http.StatusFound:
			admitted++
		case w.Code == http.StatusTooManyRequests && len(w.Result().Cookies()) == 0:
			refused++
		default:
			t.Fatalf("start = %d with Set-Cookie %v, want 302 or a cookieless 429", w.Code, w.Result().Cookies())
		}
	}
	if admitted != limit || refused != 1000-limit {
		t.Errorf("%d admitted, %d refused, want %d and %d", admitted, refused, limit, 1000-limit)
	}
	if n := cs.calls.Load() - before; n != 0 {
		t.Errorf("the flood made %d store calls, want none", n)
	}
	errs := e.errs.all()
	if len(errs) != refused || slices.ContainsFunc(errs, func(er access.Error) bool { return er.Code != access.CodeRateLimited }) {
		t.Errorf("%d refusals not all auth_rate_limited: %+v", len(errs), errs[:min(3, len(errs))])
	}
}

func TestHEADRefused(t *testing.T) {
	e := newEnv(t, envOptions{limits: ipLimit})
	e.useIdP(t, accesstest.IdPOptions{}, nil)
	for _, name := range []string{"authOIDCStartSignIn", "authOIDCCallback"} {
		rt := e.route(t, name)
		w := do(rt, httptest.NewRequest(http.MethodHead, testOrigin+rt.Path, nil))
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet || len(w.Result().Cookies()) != 0 {
			t.Errorf("HEAD %s = %d Allow %q Set-Cookie %v, want 405 Allow GET and none", name, w.Code, w.Header().Get("Allow"), w.Result().Cookies())
		}
	}
	// ipLimit admits one request: the HEADs charged nothing.
	b := newBrowser(t)
	if authURL := e.startSignIn(t, b, ""); !strings.HasPrefix(authURL, testIssuer) {
		t.Errorf("GET after the HEADs went to %q, want the IdP", authURL)
	}
}

func TestNotLinkedIdenticalShape(t *testing.T) {
	answer := func(t *testing.T, nameExists bool) (status int, loc, body string, cookies []string) {
		t.Helper()
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		if nameExists {
			e.createUser(t, accesstest.DefaultIdPUsername, access.RoleUser)
		}
		w := e.signInFlow(t, newBrowser(t), idp, "")
		value := regexp.MustCompile(`^([^=]+)=([^;]*)`)
		for _, sc := range w.Result().Header.Values("Set-Cookie") {
			m := value.FindStringSubmatch(sc)
			cookies = append(cookies, m[1]+"=<"+strconv.Itoa(len(m[2]))+" bytes>"+strings.TrimPrefix(sc, m[0]))
		}
		return w.Code, w.Header().Get("Location"), w.Body.String(), cookies
	}
	s1, l1, b1, c1 := answer(t, true)
	s2, l2, b2, c2 := answer(t, false)
	if s1 != s2 || l1 != l2 || b1 != b2 || !slices.Equal(c1, c2) {
		t.Errorf("name exists: %d %q %q %v\nname missing: %d %q %q %v", s1, l1, b1, c1, s2, l2, b2, c2)
	}
	if l1 != "/signin?oidc=not_linked" {
		t.Errorf("Location %q, want /signin?oidc=not_linked", l1)
	}
}

func TestExchangeErrorClassAudited(t *testing.T) {
	failure := func(t *testing.T, e *env) access.AuditEvent {
		t.Helper()
		audits := e.audits.all()
		if len(audits) != 1 || audits[0].Kind != "oidc.callback.failure" {
			t.Fatalf("audits %+v, want one oidc.callback.failure", audits)
		}
		return audits[0]
	}
	t.Run("exchange_failed", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{Token: accesstest.IdPEndpoint{BodyBytes: 2 << 20}}, nil)
		w := e.signInFlow(t, newBrowser(t), idp, "")
		if loc := location(t, w); loc != "/signin?auth_error=auth_oidc_failed" {
			t.Errorf("Location %q, want auth_oidc_failed", loc)
		}
		if ev := failure(t, e); ev.Reason != "exchange_failed" {
			t.Errorf("Reason %q, want exchange_failed", ev.Reason)
		}
	})
	t.Run("provider_error", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.useIdP(t, accesstest.IdPOptions{}, nil)
		b := newBrowser(t)
		state := authState(t, e.startSignIn(t, b, ""))
		const description = "the-provider-said-something-private"
		r := get(e.route(t, "authOIDCCallback"), "state="+state+"&error=access_denied&error_description="+description)
		w := e.callback(t, b, r)
		if loc := location(t, w); loc != "/signin?auth_error=auth_oidc_failed" {
			t.Errorf("Location %q, want auth_oidc_failed", loc)
		}
		ev := failure(t, e)
		if ev.Reason != "provider_error:access_denied" || strings.Contains(ev.Reason+ev.Username+ev.Kind, description) {
			t.Errorf("audit %+v, want Reason provider_error:access_denied and no error_description", ev)
		}
	})
}

// authState is the state parameter of an authorization URL.
func authState(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("authorization URL %q: %v", authURL, err)
	}
	return u.Query().Get("state")
}

func TestCallbackPassesDecodedQuery(t *testing.T) {
	q, err := decodeQuery(specNamed(t, "authOIDCCallback"), httptest.NewRequest(http.MethodGet, "/cb?state=s&code=c&error=e&iss=https%3A%2F%2Fidp.example.com&session_state=z", nil))
	if err != nil {
		t.Fatalf("decodeQuery: %v", err)
	}
	if got := q.Interface(); got != (OIDCCallbackQuery{State: "s", Code: "c", Error: "e"}) {
		t.Errorf("decoded %+v, want exactly state, code and error", got)
	}
	// code is the callback query the IdP sent for a fresh sign-in flow, and
	// its browser.
	code := func(t *testing.T, e *env, idp *accesstest.IdP) (*browser, url.Values) {
		t.Helper()
		b := newBrowser(t)
		return b, authorize(t, idp, e.startSignIn(t, b, "redirect=/home")).URL.Query()
	}
	for _, tc := range []struct {
		name  string
		query func(v url.Values) string
		want  string
	}{
		{"iss_ignored", func(v url.Values) string { return v.Encode() }, "/home"},
		{"first_state_used", func(v url.Values) string {
			return "state=" + v.Get("state") + "&state=other&code=" + v.Get("code")
		}, "/home"},
		{"first_state_wrong", func(v url.Values) string {
			return "state=other&state=" + v.Get("state") + "&code=" + v.Get("code")
		}, "/signin?auth_error=auth_oidc_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, idp := linkedAlice(t, envOptions{})
			b, v := code(t, e, idp)
			if !v.Has("iss") {
				t.Fatalf("the IdP's redirect carries no iss: %v", v)
			}
			w := e.callback(t, b, get(e.route(t, "authOIDCCallback"), tc.query(v)))
			if loc := location(t, w); loc != tc.want {
				t.Errorf("Location %q, want %q", loc, tc.want)
			}
			if fc := cookieNamed(w, e.flowCookieName()); fc == nil || fc.MaxAge >= 0 {
				t.Errorf("flow cookie %v, want cleared on this outcome", fc)
			}
		})
	}
}

// TestPendingTooLarge oversizes the IdP's sub claim, which the pending
// link carries as Identity.Subject: accesstest's IdP has no option for
// preferred_username, the other IdP-controlled claim it carries.
func TestPendingTooLarge(t *testing.T) {
	// fits is the longest subject whose pending payload Seal accepts.
	fits := func() int {
		n := access.MaxSealPayload
		for ; n > 0; n-- {
			p, _ := json.Marshal(pendingPayload{Issuer: testIssuer, Subject: strings.Repeat("s", n), UsernameHint: accesstest.DefaultIdPUsername, Email: accesstest.DefaultIdPEmail})
			if len(p) <= access.MaxSealPayload {
				return n
			}
		}
		return 0
	}()
	for _, tc := range []struct {
		name    string
		subject string
	}{
		{"seal_refuses", strings.Repeat("s", 4<<10)},
		{"cookie_over_4096", strings.Repeat("s", fits)},
	} {
		for _, exists := range []bool{true, false} {
			t.Run(tc.name+"/name_exists_"+map[bool]string{true: "yes", false: "no"}[exists], func(t *testing.T) {
				e := newEnv(t, envOptions{})
				idp := e.useIdP(t, accesstest.IdPOptions{Subject: &tc.subject}, nil)
				if exists {
					e.createUser(t, accesstest.DefaultIdPUsername, access.RoleUser)
				}
				if tc.name == "cookie_over_4096" {
					requireOverCookieBound(t, e, tc.subject)
				}
				w := e.signInFlow(t, newBrowser(t), idp, "")
				if loc := location(t, w); loc != "/signin?auth_error=auth_oidc_failed" {
					t.Errorf("Location %q, want /signin?auth_error=auth_oidc_failed", loc)
				}
				if pc := cookieNamed(w, e.pendingCookieName()); pc != nil {
					t.Errorf("pending cookie %v set", pc)
				}
				audits := e.audits.all()
				if len(audits) != 1 || audits[0].Reason != "pending_too_large" {
					t.Errorf("audits %+v, want one with Reason pending_too_large", audits)
				}
				if recs := e.logs.Records("does not fit its cookie"); len(recs) != 1 || recs[0].Level != slog.LevelWarn {
					t.Errorf("logs %v, want one WARN", recs)
				}
			})
		}
	}
}

// requireOverCookieBound fails the fixture unless subject's pending payload
// seals within MaxSealPayload to a value the derived cookie name pushes past
// 4096 bytes.
func requireOverCookieBound(t *testing.T, e *env, subject string) {
	t.Helper()
	c := e.pendingCookie(t, pendingPayload{Issuer: testIssuer, Subject: subject, UsernameHint: accesstest.DefaultIdPUsername, Email: accesstest.DefaultIdPEmail})
	if n := len(c.Name) + len(c.Value); n <= maxCookieBytes || len(c.Value) > maxCookieBytes {
		t.Fatalf("fixture: name %d + value %d bytes, want the sum past %d with the value within it", len(c.Name), len(c.Value), maxCookieBytes)
	}
}

func TestOIDCPendingRoutes(t *testing.T) {
	notLinked := func(t *testing.T) (*env, *browser) {
		t.Helper()
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		b := e.signedInBrowser(t, "alice")
		if loc := location(t, e.signInFlow(t, b, idp, "")); loc != "/signin?oidc=not_linked" {
			t.Fatalf("Location %q, want not_linked", loc)
		}
		return e, b
	}
	t.Run("pending_shows_identity", func(t *testing.T) {
		e, b := notLinked(t)
		rt := e.route(t, "authOIDCPending")
		w := b.send(rt, get(rt, ""))
		var got PendingLinkResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
			t.Fatalf("status %d body %q, want 200 PendingLinkResponse", w.Code, w.Body.String())
		}
		want := PendingLinkResponse{Issuer: testIssuer, UsernameHint: accesstest.DefaultIdPUsername, Email: accesstest.DefaultIdPEmail}
		if got != want {
			t.Errorf("pending %+v, want %+v", got, want)
		}
		if len(w.Result().Cookies()) != 0 {
			t.Errorf("Set-Cookie %v on a passive read", w.Result().Cookies())
		}
	})
	t.Run("link_consumes", func(t *testing.T) {
		e, b := notLinked(t)
		rt := e.route(t, "authOIDCLinkPending")
		w := b.send(rt, request(rt, ""))
		var me MeResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &me) != nil {
			t.Fatalf("status %d body %q, want 200 MeResponse", w.Code, w.Body.String())
		}
		if !me.User.OIDCLinked || !me.Methods.OIDCLinked || !me.Methods.OIDCAvailable || me.CanLinkOIDC || me.User.Username != "alice" {
			t.Errorf("Me %+v, want alice linked with OIDC available", me)
		}
		if got := e.user(t, "alice").OIDC; got != idpIdentity(testIssuer) {
			t.Errorf("alice linked to %+v, want the pending identity", got)
		}
		if pc := cookieNamed(w, e.pendingCookieName()); pc == nil || pc.MaxAge >= 0 {
			t.Errorf("pending cookie %v, want cleared", pc)
		}
		e.requireLinkRotated(t, w, "alice")
	})
	t.Run("pending_does_not_open", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.useIdP(t, accesstest.IdPOptions{}, nil)
		foreign, err := access.NewEphemeralSealer().Seal(pendingPurpose, jsonBytes(t, pendingPayload{Issuer: testIssuer, Subject: accesstest.DefaultIdPSubject}), time.Now().Add(pendingLifetime))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		for name, value := range map[string]string{"forged": "forged", "foreign_sealer": foreign} {
			rt := e.route(t, "authOIDCPending")
			r := get(rt, "")
			r.AddCookie(&http.Cookie{Name: e.pendingCookieName(), Value: value})
			w := do(rt, r)
			errs := e.errs.all()
			if w.Code != http.StatusNotFound || len(errs) == 0 || errs[len(errs)-1].Code != access.CodeNotFound {
				t.Errorf("%s: status %d errors %+v, want 404 auth_not_found", name, w.Code, errs)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Errorf("%s: Set-Cookie %v, want the cookie left as it is", name, w.Result().Cookies())
			}
		}
	})
	t.Run("store_error_rolls_back", func(t *testing.T) {
		var inUpdate, single atomic.Bool
		e := newEnv(t, envOptions{edit: func(c *account.Config) {
			c.Store = passkeyReadsFail{Store: c.Store, inUpdate: &inUpdate, single: &single}
		}})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		b := e.signedInBrowser(t, "alice")
		if loc := location(t, e.signInFlow(t, b, idp, "")); loc != "/signin?oidc=not_linked" {
			t.Fatalf("Location %q, want not_linked", loc)
		}
		rt := e.route(t, "authOIDCLinkPending")
		inUpdate.Store(true)
		w := b.send(rt, request(rt, ""))
		inUpdate.Store(false)
		if errs := e.errs.all(); w.Code != http.StatusServiceUnavailable || len(errs) != 1 || errs[0].Code != access.CodeUnavailable {
			t.Errorf("status %d errors %+v, want 503 auth_unavailable", w.Code, errs)
		}
		if len(w.Result().Cookies()) != 0 {
			t.Errorf("Set-Cookie %v on a link that rolled back", w.Result().Cookies())
		}
		if got := e.user(t, "alice").OIDC; !got.IsZero() {
			t.Errorf("alice linked to %+v by a rolled-back link", got)
		}
		single.Store(true)
		w = b.send(rt, request(rt, ""))
		var me MeResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &me) != nil || !me.Methods.OIDCLinked {
			t.Errorf("retry with reads outside the Update failing: status %d body %q, want 200 with the committed view", w.Code, w.Body.String())
		}
	})
	t.Run("refused_link_keeps_cookie", func(t *testing.T) {
		e, b := notLinked(t)
		e.linkUser(t, "alice", otherIdentity)
		rt := e.route(t, "authOIDCLinkPending")
		w := b.send(rt, request(rt, ""))
		if errs := e.errs.all(); w.Code != http.StatusConflict || len(errs) != 1 || errs[0].Code != access.CodeAlreadyLinked {
			t.Errorf("status %d errors %+v, want 409 auth_already_linked", w.Code, errs)
		}
		if pc := cookieNamed(w, e.pendingCookieName()); pc != nil {
			t.Errorf("pending cookie %v touched by a refused link", pc)
		}
	})
	t.Run("unlink", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.useIdP(t, accesstest.IdPOptions{}, nil)
		b := e.signedInBrowser(t, "alice")
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		rt := e.route(t, "authOIDCUnlink")
		if w := b.send(rt, request(rt, "")); w.Code != http.StatusNoContent {
			t.Errorf("unlink = %d, want 204", w.Code)
		}
		if got := e.user(t, "alice").OIDC; !got.IsZero() {
			t.Errorf("alice still linked to %+v", got)
		}
	})
}

// passkeyReadsFail is a Store whose PasskeysByUserID fails inside an Update
// while inUpdate is set, and as a single call while single is set.
type passkeyReadsFail struct {
	account.Store
	inUpdate, single *atomic.Bool
}

func (s passkeyReadsFail) PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error) {
	if s.single.Load() {
		return nil, errPasskeyRead
	}
	return s.Store.PasskeysByUserID(ctx, userID)
}

func (s passkeyReadsFail) Update(ctx context.Context, fn func(account.Tx) error) error {
	return s.Store.Update(ctx, func(tx account.Tx) error { return fn(passkeyReadsFailTx{Tx: tx, armed: s.inUpdate}) })
}

type passkeyReadsFailTx struct {
	account.Tx
	armed *atomic.Bool
}

func (t passkeyReadsFailTx) PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error) {
	if t.armed.Load() {
		return nil, errPasskeyRead
	}
	return t.Tx.PasskeysByUserID(ctx, userID)
}

var errPasskeyRead = errors.New("test store: passkey read failed")
