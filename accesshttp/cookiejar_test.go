package accesshttp

import (
	"bytes"
	"cmp"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
)

// The companion cookies' lifetimes in seconds (§7.4, §4.1), and the
// restricted recovery session's (§6.7).
const (
	deviceSeconds   = 180 * 24 * 60 * 60
	flowSeconds     = 10 * 60
	pendingSeconds  = 10 * 60
	recoverySeconds = 15 * 60
)

// jarNames are the four cookie names a request to an origin uses, the
// companions derived as §7.4 names them.
type jarNames struct{ session, device, flow, pending string }

func (e *env) jarNames(origin string) jarNames {
	r := httptest.NewRequest(http.MethodGet, origin+"/", nil)
	cfg := e.authn.Cookie()
	name := func(suffix string) string {
		d := cfg.Derive(suffix, http.SameSiteLaxMode)
		return d.CookieName(r)
	}
	return jarNames{session: cfg.CookieName(r), device: name("device"), flow: name("oidc"), pending: name("oidc_pending")}
}

// setCookies parses every Set-Cookie line of w, by cookie name.
func setCookies(t testing.TB, w *httptest.ResponseRecorder) map[string]*http.Cookie {
	t.Helper()
	out := map[string]*http.Cookie{}
	for _, line := range w.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			t.Fatalf("Set-Cookie %q: %v", line, err)
		}
		if out[c.Name] != nil {
			t.Errorf("Set-Cookie sets %s twice", c.Name)
		}
		out[c.Name] = c
	}
	return out
}

// requireBrowserSession checks that c ends with the browser session: its
// line carries neither Max-Age nor Expires.
func requireBrowserSession(t testing.TB, c *http.Cookie) {
	t.Helper()
	if c.MaxAge != 0 || !c.Expires.IsZero() || strings.Contains(c.Raw, "Max-Age") || strings.Contains(c.Raw, "Expires") {
		t.Errorf("session cookie %q, want neither Max-Age nor Expires", c.Raw)
	}
}

// walked is what cookieWalk's browser was sent: the last cookie set under
// each name, a clear excluded.
type walked struct {
	b   *browser
	set map[string]*http.Cookie
}

// cookieWalk is §9.5's cookie-jar run from a new browser at origin: alice,
// who must exist, signs in by password, an OIDC sign-in for an identity no
// user holds leaves a pending link, and a link flow begins and is left
// open. Each step must set only its own cookies, and the jar must end
// holding four, its session still alice's.
func (e *env) cookieWalk(t *testing.T, idp *accesstest.IdP, origin string) walked {
	t.Helper()
	n := e.jarNames(origin)
	wk := walked{b: newBrowserAt(t, origin), set: map[string]*http.Cookie{}}
	step := func(what string, rt Route, r *http.Request, status int, names ...string) (*httptest.ResponseRecorder, map[string]*http.Cookie) {
		t.Helper()
		w := wk.b.send(rt, r)
		if w.Code != status {
			t.Fatalf("%s at %s: status %d, errors %+v, want %d", what, origin, w.Code, e.errs.all(), status)
		}
		got := setCookies(t, w)
		if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, slices.Sorted(slices.Values(names))) {
			t.Fatalf("%s at %s set %v, want exactly %v", what, origin, keys, names)
		}
		for name, c := range got {
			if c.MaxAge >= 0 {
				wk.set[name] = c
			}
		}
		return w, got
	}
	login := e.route(t, "authLoginPassword")
	step("password sign-in", login, wk.b.request(login, signInBody(t, "alice")), http.StatusOK, n.session, n.device)
	start := e.route(t, "authOIDCStartSignIn")
	w, _ := step("OIDC sign-in start", start, wk.b.request(start, ""), http.StatusFound, n.flow)
	cb := authorize(t, idp, w.Header().Get("Location"))
	callback := e.route(t, "authOIDCCallback")
	w, got := step("OIDC callback", callback, httptest.NewRequestWithContext(t.Context(), http.MethodGet, origin+cb.URL.RequestURI(), nil), http.StatusFound, n.flow, n.pending)
	if loc := w.Header().Get("Location"); loc != "/signin?oidc=not_linked" {
		t.Fatalf("callback at %s landed on %q, want /signin?oidc=not_linked", origin, loc)
	}
	if got[n.flow].MaxAge >= 0 {
		t.Errorf("callback at %s set the flow cookie %q, want it cleared", origin, got[n.flow].Raw)
	}
	link := e.route(t, "authOIDCStartLink")
	step("link start", link, wk.b.request(link, jsonBody(t, RedirectRequest{Redirect: "/settings"})), http.StatusOK, n.flow)

	var held []string
	values := map[string]bool{}
	for _, c := range wk.b.jar.Cookies(wk.b.app) {
		held = append(held, c.Name)
		values[c.Value] = true
	}
	if want := slices.Sorted(slices.Values([]string{n.session, n.device, n.flow, n.pending})); !slices.Equal(slices.Sorted(slices.Values(held)), want) || len(values) != len(want) {
		t.Errorf("jar at %s holds %v with %d distinct values, want %v, each its own", origin, held, len(values), want)
	}
	if me := e.meOf(t, wk.b); me.User.Username != "alice" {
		t.Errorf("the jar's session at %s is %s's, want alice's", origin, me.User.Username)
	}
	return wk
}

// meOf is the authMe answer to b's cookies, which must be 200.
func (e *env) meOf(t *testing.T, b *browser) MeResponse {
	t.Helper()
	rt := e.route(t, "authMe")
	return decoded[MeResponse](t, e, b.send(rt, b.request(rt, "")), http.StatusOK)
}

// jarSession is b's session cookie.
func (e *env) jarSession(t *testing.T, b *browser) *http.Cookie {
	t.Helper()
	name := e.jarNames(b.origin).session
	for _, c := range b.jar.Cookies(b.app) {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("the jar holds no %s", name)
	return nil
}

func TestCookieJarCoexistence(t *testing.T) {
	t.Run("four_cookies", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		e.createUser(t, "alice", access.RoleUser)
		wk := e.cookieWalk(t, idp, testOrigin)
		want := []string{"__Host-auth_session", "__Host-auth_session_device", "__Host-auth_session_oidc", "__Host-auth_session_oidc_pending"}
		if got := slices.Sorted(maps.Keys(wk.set)); !slices.Equal(got, want) {
			t.Errorf("cookies %v, want %v", got, want)
		}
	})
	abandoned := func(route string) func(t *testing.T) {
		return func(t *testing.T) {
			e := newEnv(t, envOptions{})
			e.useIdP(t, accesstest.IdPOptions{}, nil)
			b := e.signedInBrowser(t, "alice")
			if route == "authOIDCStartStepUp" {
				e.linkUser(t, "alice", idpIdentity(testIssuer))
			}
			before := e.jarSession(t, b)
			rt := e.route(t, route)
			w := b.send(rt, b.request(rt, jsonBody(t, RedirectRequest{Redirect: "/settings"})))
			if keys := slices.Sorted(maps.Keys(setCookies(t, w))); w.Code != http.StatusOK || !slices.Equal(keys, []string{e.flowCookieName()}) {
				t.Fatalf("start: status %d set %v, want 200 setting the flow cookie alone", w.Code, keys)
			}
			b.jar.SetCookies(b.app, []*http.Cookie{{Name: e.flowCookieName(), Path: "/", MaxAge: -1}})
			if after := e.jarSession(t, b); after.Value != before.Value {
				t.Errorf("an abandoned flow replaced the session cookie")
			}
			if me := e.meOf(t, b); me.Session.ID != e.sessionIDOf(t, before) {
				t.Errorf("session after an abandoned flow is %q, want the original %q", me.Session.ID, e.sessionIDOf(t, before))
			}
		}
	}
	t.Run("abandoned_link", abandoned("authOIDCStartLink"))
	t.Run("abandoned_step_up", abandoned("authOIDCStartStepUp"))
	t.Run("completed_link", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		b := e.signedInBrowser(t, "alice")
		if loc := location(t, e.sessionFlow(t, b, idp, "authOIDCStartLink", "/settings", nil)); loc != "/settings?oidc=linked" {
			t.Fatalf("link landed on %q, want /settings?oidc=linked", loc)
		}
		if me := e.meOf(t, b); !me.User.OIDCLinked {
			t.Errorf("after the link the jar's session shows %+v, want alice linked", me.User)
		}
	})
	t.Run("completed_step_up", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		b := e.signedInBrowser(t, "alice")
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		before := e.jarSession(t, b)
		if loc := location(t, e.sessionFlow(t, b, idp, "authOIDCStartStepUp", "/settings", nil)); loc != "/settings?oidc=stepped_up" {
			t.Fatalf("step-up landed on %q, want /settings?oidc=stepped_up", loc)
		}
		after := e.jarSession(t, b)
		if after.Value == before.Value || e.authenticates(t, before) {
			t.Errorf("a step-up left the session cookie unrotated")
		}
		if me := e.meOf(t, b); me.Session.ID != e.sessionIDOf(t, after) || me.Session.Method != access.MethodOIDC {
			t.Errorf("after the step-up the jar's session is %+v, want the rotated one, by oidc", me.Session)
		}
	})
}

// postureOrigins are §9.5's per-request posture hosts: HTTPS, plain
// loopback and a plain LAN address.
var postureOrigins = []string{testOrigin, "http://localhost", "http://192.168.1.77:9847"}

// perRequest is §9.5's marotte-shaped session cookie under
// PosturePerRequest, with persistent as its Persistent.
func perRequest(persistent func(*http.Request) bool) envOptions {
	return envOptions{authn: func(_ *env, c *access.Config) {
		c.Cookie = access.CookieConfig{Name: "marotte_session", SameSite: http.SameSiteStrictMode, Posture: access.PosturePerRequest, HTTPS: access.RequestIsHTTPS, Persistent: persistent}
	}}
}

func TestPerRequestPostureEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		persistent func(*http.Request) bool
		name       string
	}{{name: "persistent_nil"}, {name: "persistent_https", persistent: access.RequestIsHTTPS}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, perRequest(tc.persistent))
			idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
			e.createUser(t, "alice", access.RoleUser)
			absolute := int(e.authn.Timeouts().Absolute / time.Second)
			sessions := map[string]*http.Cookie{}
			for _, origin := range postureOrigins {
				https := strings.HasPrefix(origin, "https://")
				prefix := ""
				if https {
					prefix = "__Host-"
				}
				want := map[string]http.SameSite{
					prefix + "marotte_session":              http.SameSiteStrictMode,
					prefix + "marotte_session_device":       http.SameSiteLaxMode,
					prefix + "marotte_session_oidc":         http.SameSiteLaxMode,
					prefix + "marotte_session_oidc_pending": http.SameSiteLaxMode,
				}
				wk := e.cookieWalk(t, idp, origin)
				if got := slices.Sorted(maps.Keys(wk.set)); !slices.Equal(got, slices.Sorted(maps.Keys(want))) {
					t.Fatalf("%s: cookies %v, want %v", origin, got, slices.Sorted(maps.Keys(want)))
				}
				for name, c := range wk.set {
					if c.Secure != https || c.SameSite != want[name] {
						t.Errorf("%s: %q, want Secure %v and SameSite %v", origin, c.Raw, https, want[name])
					}
				}
				session := wk.set[prefix+"marotte_session"]
				if tc.persistent == nil || https {
					if session.MaxAge != absolute {
						t.Errorf("%s: session cookie %q, want Max-Age %d", origin, session.Raw, absolute)
					}
				} else {
					requireBrowserSession(t, session)
				}
				for name, seconds := range map[string]int{"device": deviceSeconds, "oidc": flowSeconds, "oidc_pending": pendingSeconds} {
					if c := wk.set[prefix+"marotte_session_"+name]; c.MaxAge != seconds {
						t.Errorf("%s: %q, want Max-Age %d", origin, c.Raw, seconds)
					}
				}
				sessions[origin] = session
			}
			me := e.route(t, "authMe")
			for from, c := range sessions {
				for _, to := range postureOrigins {
					want := http.StatusUnauthorized
					if strings.HasPrefix(from, "https://") == strings.HasPrefix(to, "https://") {
						want = http.StatusOK
					}
					if w := do(me, requestAt(to, me.Path, me, "", &http.Cookie{Name: c.Name, Value: c.Value})); w.Code != want {
						t.Errorf("the session cookie set at %s, presented at %s: status %d, want %d", from, to, w.Code, want)
					}
				}
			}
		})
	}
}

// never makes every cookie set a browser-session cookie.
var never = envOptions{authn: func(_ *env, c *access.Config) { c.Cookie.Persistent = func(*http.Request) bool { return false } }}

// sessionCookieCases are the passthrough cases whose answer sets a session
// cookie: all but the refused sign-in and the key-authenticated mint,
// which has no session to rotate.
func sessionCookieCases() []passthroughCase {
	return slices.DeleteFunc(passthroughCases(), func(c passthroughCase) bool { return c.want != "" || c.name == "key_mint_key" })
}

func TestPersistentCookieHTTP(t *testing.T) {
	t.Run("routes", func(t *testing.T) {
		for _, tc := range sessionCookieCases() {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				lifetime := map[string]int{"authRecoveryStart": recoverySeconds}[tc.route]
				for _, persistent := range []bool{false, true} {
					t.Run(fmt.Sprintf("persistent_%v", persistent), func(t *testing.T) {
						opts := with(tc.opts, never)
						if persistent {
							opts = tc.opts
						}
						e := newEnv(t, opts)
						got := setCookies(t, tc.run(t, e))
						sessionName, deviceName := e.names()
						session := got[sessionName]
						if session == nil || session.Value == "" {
							t.Fatalf("Set-Cookie %v, want a session cookie", slices.Sorted(maps.Keys(got)))
						}
						if !persistent {
							requireBrowserSession(t, session)
						} else if want := cmp.Or(lifetime, int(e.authn.Timeouts().Absolute/time.Second)); session.MaxAge != want {
							t.Errorf("session cookie %q, want Max-Age %d", session.Raw, want)
						}
						if d := got[deviceName]; d != nil && d.MaxAge != deviceSeconds {
							t.Errorf("device cookie %q, want Max-Age %d", d.Raw, deviceSeconds)
						}
					})
				}
			})
		}
	})
	t.Run("companions_keep_their_lifetimes", func(t *testing.T) {
		e := newEnv(t, never)
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		e.createUser(t, "alice", access.RoleUser)
		wk := e.cookieWalk(t, idp, testOrigin)
		n := e.jarNames(testOrigin)
		requireBrowserSession(t, wk.set[n.session])
		for name, seconds := range map[string]int{n.device: deviceSeconds, n.flow: flowSeconds, n.pending: pendingSeconds} {
			if c := wk.set[name]; c.MaxAge != seconds {
				t.Errorf("%q, want Max-Age %d", c.Raw, seconds)
			}
		}
	})
	t.Run("clear_sends_max_age_zero", func(t *testing.T) {
		e := newEnv(t, never)
		w := do(e.route(t, "authLogout"), e.post(t, "authLogout", "", e.aliceSession(t)))
		sessionName, _ := e.names()
		if c := setCookies(t, w)[sessionName]; c == nil || !strings.Contains(c.Raw, "Max-Age=0") {
			t.Errorf("logout's session Set-Cookie %v, want Max-Age=0", c)
		}
	})
}

// requireFailureTrusted checks that a password failure presenting device
// counts as trusted: under trustLimits an untrusted failure spends name's
// whole untrusted budget, so the untrusted sign-in after it is admitted
// only when the failure counted against the device.
func (e *env) requireFailureTrusted(t *testing.T, name string, device *http.Cookie) {
	t.Helper()
	if device == nil || device.Value == "" {
		t.Fatal("no device cookie set")
	}
	rt := e.route(t, "authLoginPassword")
	wrong := jsonBody(t, LoginRequest{Username: name, Password: "not-" + testPassword})
	if w := do(rt, e.post(t, "authLoginPassword", wrong, &http.Cookie{Name: device.Name, Value: device.Value})); w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong password presenting the device cookie answered %d, want 401", w.Code)
	}
	if w := do(rt, e.post(t, "authLoginPassword", signInBody(t, name))); w.Code != http.StatusOK {
		t.Errorf("an untrusted sign-in after that failure answered %d, errors %+v; want 200, the failure counted as trusted", w.Code, e.errs.all())
	}
}

// lockUntrusted signs alice in from a new browser, which keeps its device
// cookie, then fails FailureCap untrusted password attempts from as many
// addresses, which locks alice's untrusted context.
func (e *env) lockUntrusted(t *testing.T) *browser {
	t.Helper()
	b := newBrowser(t)
	login := e.route(t, "authLoginPassword")
	if w := b.send(login, b.request(login, signInBody(t, "alice"))); w.Code != http.StatusOK {
		t.Fatalf("browser sign-in: status %d, errors %+v", w.Code, e.errs.all())
	}
	wrong := jsonBody(t, LoginRequest{Username: "alice", Password: "not-" + testPassword})
	for i := range account.FailureCap {
		r := e.post(t, "authLoginPassword", wrong)
		r.RemoteAddr = fmt.Sprintf("198.18.%d.%d:4000", i/200, i%200+1)
		if w := do(login, r); w.Code != http.StatusUnauthorized {
			t.Fatalf("untrusted failure %d: status %d, errors %+v, want 401", i, w.Code, e.errs.all())
		}
	}
	return b
}

// requireUntrustedLocked checks that alice's untrusted password context is
// locked, by the limiter when limiter is set, else by the persisted
// failure cap alone, that /me shows the lock, and that b, presenting its
// device cookie, still signs in.
func (e *env) requireUntrustedLocked(t *testing.T, b *browser, limiter bool) {
	t.Helper()
	login := e.route(t, "authLoginPassword")
	r := e.post(t, "authLoginPassword", signInBody(t, "alice"))
	r.RemoteAddr = "198.18.9.9:4000"
	w := do(login, r)
	errs, audits := e.errs.all(), e.audits.all()
	if len(errs) == 0 || len(audits) == 0 {
		t.Fatalf("an untrusted sign-in answered %d with no refusal recorded", w.Code)
	}
	last, audit := errs[len(errs)-1], audits[len(audits)-1]
	switch {
	case limiter:
		if w.Code != http.StatusTooManyRequests || last.Code != CodeRateLimited {
			t.Errorf("an untrusted sign-in answered %d %+v, want the limiter's 429", w.Code, last)
		}
	case w.Code != http.StatusUnauthorized || last.Code != CodeInvalidCredentials || audit.Reason != "method_locked":
		t.Errorf("an untrusted sign-in answered %d %+v, audit %+v; want 401 from the persisted lock (method_locked)", w.Code, last, audit)
	}
	if locks := e.meOf(t, b).Methods.Locks; !slices.Equal(locks, []MethodLockView{{Method: access.MethodPassword, Untrusted: true}}) {
		t.Errorf("locks %+v, want the untrusted password lock alone", locks)
	}
	if w := b.send(login, b.request(login, signInBody(t, "alice"))); w.Code != http.StatusOK {
		t.Errorf("the trusted browser's sign-in answered %d, errors %+v; want 200", w.Code, e.errs.all())
	}
}

func TestDeviceCookieEveryMethod(t *testing.T) {
	methods := []struct {
		run  func(t *testing.T, e *env) *httptest.ResponseRecorder
		name string
	}{
		{name: "password_sign_in", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			e.createUser(t, "alice", access.RoleUser)
			return do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", signInBody(t, "alice")))
		}},
		{name: "passkey_sign_in", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			return do(e.route(t, "authLoginPasskeyFinish"), e.loginFinish(t, nil))
		}},
		{name: "oidc_sign_in", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
			e.createUser(t, "alice", access.RoleUser)
			e.linkUser(t, "alice", idpIdentity(testIssuer))
			return e.signInFlow(t, newBrowser(t), idp, "")
		}},
		{name: "password_step_up", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			cookie := e.aliceSession(t)
			return do(e.route(t, "authStepUpPassword"), e.post(t, "authStepUpPassword", jsonBody(t, PasswordRequest{Password: testPassword}), cookie))
		}},
		{name: "passkey_step_up", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			cookie := e.aliceSession(t)
			return do(e.route(t, "authStepUpPasskeyFinish"), e.stepUpFinish(t, cookie, e.enrol(t, "alice"), nil, nil))
		}},
		{name: "oidc_step_up", run: func(t *testing.T, e *env) *httptest.ResponseRecorder {
			idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
			b := e.signedInBrowser(t, "alice")
			e.linkUser(t, "alice", idpIdentity(testIssuer))
			return e.sessionFlow(t, b, idp, "authOIDCStartStepUp", "/settings", nil)
		}},
	}
	t.Run("methods", func(t *testing.T) {
		for _, tc := range methods {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				e := newEnv(t, with(trustLimits, passkeys))
				w := tc.run(t, e)
				if w.Code >= http.StatusBadRequest || (w.Code == http.StatusFound && redirectedCode(t, w) != "") {
					t.Fatalf("status %d, errors %+v, Location %q; want success", w.Code, e.errs.all(), w.Header().Get("Location"))
				}
				_, deviceName := e.names()
				device := cookieNamed(w, deviceName)
				e.requireFailureTrusted(t, "alice", device)
				e.requireTrustedDevice(t, "alice", device)
			})
		}
	})
	t.Run("oidc_sign_in_keeps_device_id", func(t *testing.T) {
		sealer := access.NewEphemeralSealer()
		e := newEnv(t, envOptions{limits: func(c *ratelimit.Config) { c.Devices = sealer }})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		e.createUser(t, "alice", access.RoleUser)
		e.linkUser(t, "alice", idpIdentity(testIssuer))
		_, deviceName := e.names()
		// The payload is the account's digest and the device ID (§2), so
		// for one account equal payloads are equal device IDs.
		payload := func(w *httptest.ResponseRecorder) []byte {
			t.Helper()
			c := cookieNamed(w, deviceName)
			if c == nil {
				t.Fatalf("Set-Cookie %v, want a device cookie", w.Result().Cookies())
			}
			p, err := sealer.Open("ratelimit-device", c.Value, time.Now())
			if err != nil {
				t.Fatalf("Open device cookie: %v", err)
			}
			return p
		}
		b := newBrowser(t)
		login := e.route(t, "authLoginPassword")
		first := payload(b.send(login, b.request(login, signInBody(t, "alice"))))
		if again := payload(e.signInFlow(t, b, idp, "")); !bytes.Equal(again, first) {
			t.Errorf("an OIDC sign-in from a browser holding a device cookie issued another device ID")
		}
		if fresh := payload(e.signInFlow(t, newBrowser(t), idp, "")); bytes.Equal(fresh, first) {
			t.Errorf("fixture: a new browser's OIDC sign-in kept the first browser's device ID")
		}
	})
	t.Run("no_device_protocol_off", func(t *testing.T) {
		t.Run("ephemeral", func(t *testing.T) {
			e := newEnv(t, envOptions{})
			e.createUser(t, "alice", access.RoleUser)
			e.requireUntrustedLocked(t, e.lockUntrusted(t), true)
		})
		t.Run("persisted_ring", func(t *testing.T) {
			current, previous := access.GenerateSealerKey(), access.GenerateSealerKey()
			ring := func() envOptions {
				sealer, err := access.NewSealer(current, previous)
				if err != nil {
					t.Fatalf("NewSealer: %v", err)
				}
				return envOptions{limits: func(c *ratelimit.Config) { c.Devices = sealer }}
			}
			first := newEnv(t, ring())
			first.createUser(t, "alice", access.RoleUser)
			b := first.lockUntrusted(t)
			first.requireUntrustedLocked(t, b, true)
			rebuilt := newEnv(t, with(ring(), envOptions{mem: first.mem}))
			rebuilt.requireUntrustedLocked(t, b, false)
		})
	})
}
