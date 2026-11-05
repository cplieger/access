package accesshttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// testClientIP is httptest.NewRequest's RemoteAddr host, the address the
// default resolver hands account.
var testClientIP = netip.MustParseAddr("192.0.2.1")

// refusingPolicy refuses the listed operations and lets RolePolicy decide
// the rest.
type refusingPolicy map[account.Operation]bool

func (p refusingPolicy) Authorize(ctx context.Context, d account.Decision) error {
	if p[d.Op] {
		return &account.PolicyError{Reason: "test_refused"}
	}
	return account.RolePolicy{}.Authorize(ctx, d)
}

func refuse(ops ...account.Operation) func(*account.Config) {
	p := refusingPolicy{}
	for _, op := range ops {
		p[op] = true
	}
	return func(c *account.Config) { c.Policy = p }
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// breachDown is a breach client that never reaches the service, under
// BreachFailClosed.
var breachDown = envOptions{
	rules: func(r *account.Rules) { r.Breach = account.BreachFailClosed },
	edit: func(c *account.Config) {
		c.Breach = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("breach service down")
		})}
	},
}

// ipLimit lets one attempt and one request through per IP.
func ipLimit(c *ratelimit.Config) {
	one := ratelimit.Rate{Limit: 1, Window: c.IP.Window}
	c.IP, c.Request = one, one
}

// spendAttempt fails the one IP attempt ipLimit allows the test client.
func (e *env) spendAttempt(t testing.TB) {
	t.Helper()
	e.spendAttemptOf(t, testClientIP)
}

// spendAttemptOf fails the one IP attempt ipLimit allows ip.
func (e *env) spendAttemptOf(t testing.TB, ip netip.Addr) {
	t.Helper()
	res, err := e.limiter.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(ip)})
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	res.Fail()
}

// spendRequest takes the one IP request ipLimit allows the test client.
func (e *env) spendRequest(t testing.TB) {
	t.Helper()
	if err := e.limiter.Request(ratelimit.IPKey(testClientIP)); err != nil {
		t.Fatalf("Request: %v", err)
	}
}

// holdBudget reserves the whole hash budget until the test ends, so any
// hash or verify answers access.ErrHashBusy after hashWait.
func (e *env) holdBudget(t testing.TB) {
	t.Helper()
	for {
		permit, err := e.hasher.Reserve(t.Context())
		if err != nil {
			if !errors.Is(err, access.ErrHashBusy) {
				t.Fatalf("Reserve: %v", err)
			}
			return
		}
		t.Cleanup(permit.Release)
	}
}

// shutdown closes the Service, so each operation answers ErrServiceClosed.
func (e *env) shutdown(t testing.TB) {
	t.Helper()
	if err := e.svc.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// user is name as stored.
func (e *env) user(t testing.TB, name string) *access.User {
	t.Helper()
	u, found, err := e.mem.UserByUsername(t.Context(), name)
	if err != nil || !found {
		t.Fatalf("UserByUsername(%s) = %v, %v", name, found, err)
	}
	return u
}

// principal is what the Authenticator grants a request carrying cookie.
func (e *env) principal(t testing.TB, cookie *http.Cookie) access.Principal {
	t.Helper()
	r := httptest.NewRequestWithContext(access.AllowRecoverySession(t.Context()), http.MethodGet, testOrigin+"/", http.NoBody)
	r.AddCookie(cookie)
	p, err := e.authn.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return p
}

// enrol registers a new device's passkey for name through the Service.
func (e *env) enrol(t testing.TB, name string) *accesstest.PasskeyDevice {
	t.Helper()
	dev := accesstest.NewPasskeyDevice(t)
	p := e.principal(t, e.sessionCookie(t, name))
	origin, err := webauthn.ParseOrigin(testOrigin)
	if err != nil {
		t.Fatalf("ParseOrigin: %v", err)
	}
	pc, err := e.svc.PasskeyRegisterBegin(t.Context(), p, origin)
	if err != nil {
		t.Fatalf("PasskeyRegisterBegin: %v", err)
	}
	if _, err := e.svc.PasskeyRegisterFinish(t.Context(), p, pc.ID, bytes.NewReader(dev.Register(jsonBytes(t, pc.Creation)))); err != nil {
		t.Fatalf("PasskeyRegisterFinish: %v", err)
	}
	return dev
}

// recoveryCookie opens a recovery session for name from an out-of-band
// recovery link.
func (e *env) recoveryCookie(t testing.TB, name string) *http.Cookie {
	t.Helper()
	issued, err := e.svc.IssueRecovery(t.Context(), account.OutOfBand("test"), e.user(t, name).ID, 0)
	if err != nil {
		t.Fatalf("IssueRecovery: %v", err)
	}
	return e.startRecovery(t, issued.Plaintext)
}

func (e *env) startRecovery(t testing.TB, token access.Secret) *http.Cookie {
	t.Helper()
	rec, err := e.svc.StartRecovery(t.Context(), account.Client{}, token)
	if err != nil {
		t.Fatalf("StartRecovery: %v", err)
	}
	return e.cookie(rec.Issued.Token)
}

// cookie is the session cookie carrying token.
func (e *env) cookie(token access.Secret) *http.Cookie {
	cfg := e.authn.Cookie()
	return &http.Cookie{Name: cfg.CookieName(httptest.NewRequest(http.MethodGet, testOrigin+"/", nil)), Value: token.Reveal()}
}

// keyScopes configures ManageUsersScope as "manage_users" and lists it.
var keyScopes = envOptions{
	rules: func(r *account.Rules) { r.Scopes = []string{"manage_users"} },
	edit:  func(c *account.Config) { c.ManageUsersScope = "manage_users" },
}

// keyIssuedRecovery stores admin root and user alice, and opens a recovery
// session for alice from a link a manage_users key of root issued; revoke
// deletes that key. The env needs keyScopes.
func (e *env) keyIssuedRecovery(t testing.TB) (cookie *http.Cookie, revoke func()) {
	t.Helper()
	e.createUser(t, "root", access.RoleAdmin)
	e.createUser(t, "alice", access.RoleUser)
	root := e.user(t, "root")
	key, err := e.svc.CreateAPIKey(t.Context(), account.OutOfBand("test"), root.ID, account.NewKey{Label: "k", Scopes: []string{"manage_users"}})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, testOrigin+"/", http.NoBody)
	r.Header.Set("Authorization", "Bearer "+key.Plaintext.Reveal())
	kp, err := e.authn.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate(key): %v", err)
	}
	issued, err := e.svc.IssueRecovery(t.Context(), account.As(kp), e.user(t, "alice").ID, 0)
	if err != nil {
		t.Fatalf("IssueRecovery(key): %v", err)
	}
	return e.startRecovery(t, issued.Plaintext), func() {
		if err := e.mem.DeleteAPIKey(t.Context(), access.KeyRef{ID: key.Key.ID, UserID: root.ID}); err != nil {
			t.Fatalf("DeleteAPIKey: %v", err)
		}
	}
}

// invite is an invite link for a RoleUser, issued by admin root, which it
// stores first.
func (e *env) invite(t testing.TB) access.Secret {
	t.Helper()
	e.createUser(t, "root", access.RoleAdmin)
	issued, err := e.svc.CreateInvite(t.Context(), e.principal(t, e.sessionCookie(t, "root")), access.RoleUser, 0)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	return issued.Plaintext
}

// vanishing deletes the caller's user, and with it its sessions, before
// each operation it wraps runs, as a write outside account would between
// the guard and the operation.
type vanishing struct {
	accountAPI
	mem *accesstest.MemStore
}

func vanish(e *env, s *account.Service) accountAPI { return vanishing{accountAPI: s, mem: e.mem} }

func (v vanishing) drop(ctx context.Context, p access.Principal) {
	_ = v.mem.DeleteUser(ctx, p.User.ID)
}

func (v vanishing) RecoverWithPassword(ctx context.Context, p access.Principal, password access.Secret, opts account.RecoverOptions) error {
	v.drop(ctx, p)
	return v.accountAPI.RecoverWithPassword(ctx, p, password, opts)
}

func (v vanishing) RecoverPasskeyBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (account.PendingCeremony, error) {
	v.drop(ctx, p)
	return v.accountAPI.RecoverPasskeyBegin(ctx, p, origin)
}

func (v vanishing) RecoverPasskeyFinish(ctx context.Context, p access.Principal, id string, body io.Reader, opts account.RecoverOptions) error {
	v.drop(ctx, p)
	return v.accountAPI.RecoverPasskeyFinish(ctx, p, id, body, opts)
}

func (v vanishing) LinkPendingOIDC(ctx context.Context, p access.Principal, pending account.PendingLink) (account.Issued, account.Me, error) {
	v.drop(ctx, p)
	return v.accountAPI.LinkPendingOIDC(ctx, p, pending)
}

func (v vanishing) UnlinkOIDC(ctx context.Context, p access.Principal) error {
	v.drop(ctx, p)
	return v.accountAPI.UnlinkOIDC(ctx, p)
}

func (v vanishing) Me(ctx context.Context, p access.Principal) (account.Me, error) {
	v.drop(ctx, p)
	return v.accountAPI.Me(ctx, p)
}

func (v vanishing) UpdateProfile(ctx context.Context, p access.Principal, displayName string) (account.Me, error) {
	v.drop(ctx, p)
	return v.accountAPI.UpdateProfile(ctx, p, displayName)
}

func (v vanishing) SetPassword(ctx context.Context, c account.Client, p access.Principal, current, password access.Secret) (account.Issued, error) {
	v.drop(ctx, p)
	return v.accountAPI.SetPassword(ctx, c, p, current, password)
}

func (v vanishing) RemovePassword(ctx context.Context, c account.Client, p access.Principal, current access.Secret) (account.Issued, error) {
	v.drop(ctx, p)
	return v.accountAPI.RemovePassword(ctx, c, p, current)
}

func (v vanishing) StepUpPasskeyBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (account.PendingCeremony, error) {
	v.drop(ctx, p)
	return v.accountAPI.StepUpPasskeyBegin(ctx, p, origin)
}

func (v vanishing) StepUpPasskeyFinish(ctx context.Context, c account.Client, p access.Principal, id string, body io.Reader) (account.Issued, error) {
	v.drop(ctx, p)
	return v.accountAPI.StepUpPasskeyFinish(ctx, c, p, id, body)
}

func (v vanishing) PasskeyRegisterBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (account.PendingCeremony, error) {
	v.drop(ctx, p)
	return v.accountAPI.PasskeyRegisterBegin(ctx, p, origin)
}

func (v vanishing) PasskeyRegisterFinish(ctx context.Context, p access.Principal, id string, body io.Reader) (account.Registered, error) {
	v.drop(ctx, p)
	return v.accountAPI.PasskeyRegisterFinish(ctx, p, id, body)
}

func (v vanishing) RemovePasskey(ctx context.Context, p access.Principal, id int64) error {
	v.drop(ctx, p)
	return v.accountAPI.RemovePasskey(ctx, p, id)
}

func (v vanishing) WebAuthnSignals(ctx context.Context, p access.Principal) (webauthn.Signals, error) {
	v.drop(ctx, p)
	return v.accountAPI.WebAuthnSignals(ctx, p)
}

// ending deletes the caller's session before each operation it wraps runs,
// so the operation's rotation finds it gone.
type ending struct {
	accountAPI
	mem *accesstest.MemStore
}

func (x ending) drop(ctx context.Context, p access.Principal) {
	_ = x.mem.DeleteSession(ctx, access.SessionRef{ID: p.SessionID, UserID: p.User.ID})
}

func (x ending) StepUpPassword(ctx context.Context, c account.Client, p access.Principal, password access.Secret) (account.Issued, error) {
	x.drop(ctx, p)
	return x.accountAPI.StepUpPassword(ctx, c, p, password)
}

func (x ending) CreateAPIKey(ctx context.Context, a account.Actor, userID int64, in account.NewKey) (account.CreatedKey, error) {
	if p, ok := a.Principal(); ok {
		x.drop(ctx, p)
	}
	return x.accountAPI.CreateAPIKey(ctx, a, userID, in)
}

// ends wraps the account in ending.
var ends = envOptions{wrap: func(e *env, s *account.Service) accountAPI { return ending{accountAPI: s, mem: e.mem} }}

// jsonBytes marshals v or fails the test.
func jsonBytes(t testing.TB, v any) []byte {
	t.Helper()
	return []byte(jsonBody(t, v))
}

// begin serves a WebAuthn begin route and returns its ceremony ID and the
// options the browser hands the authenticator.
func (e *env) begin(t testing.TB, name, rawQuery, body string, cookies ...*http.Cookie) (id string, options []byte) {
	t.Helper()
	rt := e.route(t, name)
	r := request(rt, body, cookies...)
	r.URL.RawQuery = rawQuery
	w := do(rt, r)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d, errors %+v", name, w.Code, e.errs.all())
	}
	var resp CeremonyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%s: decode %q: %v", name, w.Body.String(), err)
	}
	return resp.Ceremony, resp.PublicKey
}

// finish is a WebAuthn finish request for rt carrying credential.
func finish(rt Route, ceremonyID string, credential []byte, cookies ...*http.Cookie) *http.Request {
	r := request(rt, string(credential), cookies...)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(ceremonyHeader, ceremonyID)
	return r
}

// notDiscoverable rewrites a registration body so its client reports the
// credential as not discoverable.
func notDiscoverable(t testing.TB, body []byte) []byte {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode credential: %v", err)
	}
	v["clientExtensionResults"] = map[string]any{"credProps": map[string]any{"rk": false}}
	return jsonBytes(t, v)
}

// cookieNamed is the Set-Cookie w set for name, or nil.
func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// names are the cookie names a request to testOrigin uses, the device
// cookie's derived as §7.4 names it rather than through deviceCookie.
func (e *env) names() (session, device string) {
	r := httptest.NewRequest(http.MethodGet, testOrigin+"/", nil)
	cfg := e.authn.Cookie()
	dcfg := cfg.Derive("device", http.SameSiteLaxMode)
	return cfg.CookieName(r), dcfg.CookieName(r)
}

// requireSignedIn checks a SignedInResponse for name with a session and a
// device cookie, and returns the session cookie.
func (e *env) requireSignedIn(t testing.TB, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, errors %+v, want 200", w.Code, e.errs.all())
	}
	var resp SignedInResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	u := e.user(t, name)
	want := UserView{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, Enabled: u.Enabled, OIDCLinked: !u.OIDC.IsZero()}
	got := resp.User
	if !got.CreatedAt.Equal(u.CreatedAt) {
		t.Errorf("user created_at %v, want the stored %v", got.CreatedAt, u.CreatedAt)
	}
	got.CreatedAt = time.Time{}
	if !reflect.DeepEqual(got, want) || resp.SessionID == "" || resp.CloneWarning {
		t.Errorf("signed in %+v, want user %+v with a session ID and no clone warning", resp, want)
	}
	sessionName, deviceName := e.names()
	session, device := cookieNamed(w, sessionName), cookieNamed(w, deviceName)
	if session == nil || session.Value == "" || device == nil || device.Value == "" || device.Value == session.Value {
		t.Fatalf("cookies %v, want a session and a separate device cookie", w.Result().Cookies())
	}
	if lifetime := int(e.authn.Timeouts().Absolute / time.Second); session.MaxAge != lifetime {
		t.Errorf("session cookie Max-Age %d, want the absolute timeout %d", session.MaxAge, lifetime)
	}
	if got := e.principal(t, session); got.SessionID != resp.SessionID || !got.IsSession() {
		t.Errorf("session cookie authenticates %+v, want full session %s", got, resp.SessionID)
	}
	return session
}

// trustLimits lets one failure from an untrusted client spend an account's
// whole untrusted budget, so requireTrustedDevice can tell a device cookie
// the limiter trusts from any other value.
var trustLimits = envOptions{limits: func(c *ratelimit.Config) { c.Account = ratelimit.Rate{Limit: 1, Window: time.Hour} }}

// requireTrustedDevice checks that device is a device cookie the limiter
// trusts for name: once a failure without it spends name's untrusted
// budget, a password sign-in without it is refused and one presenting it
// is admitted. e is built with trustLimits.
func (e *env) requireTrustedDevice(t *testing.T, name string, device *http.Cookie) {
	t.Helper()
	rt := e.route(t, "authLoginPassword")
	do(rt, e.post(t, "authLoginPassword", jsonBody(t, LoginRequest{Username: name, Password: "not-" + testPassword})))
	if w := do(rt, e.post(t, "authLoginPassword", signInBody(t, name))); w.Code != http.StatusTooManyRequests {
		t.Fatalf("fixture: an untrusted sign-in after the failure answered %d, want 429", w.Code)
	}
	trusted := do(rt, e.post(t, "authLoginPassword", signInBody(t, name), &http.Cookie{Name: device.Name, Value: device.Value}))
	if trusted.Code != http.StatusOK {
		t.Errorf("a sign-in presenting the device cookie answered %d, errors %+v; want it trusted", trusted.Code, e.errs.all())
	}
}

// requireLinkRotated checks that a link's response set a session cookie
// for name's full session, for the absolute timeout, and no device cookie:
// a link is neither a sign-in nor a step-up (§7.4).
func (e *env) requireLinkRotated(t testing.TB, w *httptest.ResponseRecorder, name string) {
	t.Helper()
	sessionName, deviceName := e.names()
	sc := cookieNamed(w, sessionName)
	if sc == nil || sc.Value == "" {
		t.Fatalf("Set-Cookie %v, want a rotated session cookie", w.Result().Cookies())
	}
	if p := e.principal(t, sc); p.User.Username != name || !p.IsSession() {
		t.Errorf("rotated cookie authenticates %+v, want %s's full session", p, name)
	}
	if lifetime := int(e.authn.Timeouts().Absolute / time.Second); sc.MaxAge != lifetime {
		t.Errorf("session cookie Max-Age %d, want the absolute timeout %d", sc.MaxAge, lifetime)
	}
	if d := cookieNamed(w, deviceName); d != nil {
		t.Errorf("a link set the device cookie %v", d)
	}
}

// requireCleared checks that w cleared the session cookie.
func (e *env) requireCleared(t testing.TB, w *httptest.ResponseRecorder) {
	t.Helper()
	sessionName, _ := e.names()
	if c := cookieNamed(w, sessionName); c == nil || c.MaxAge >= 0 || c.Value != "" {
		t.Errorf("session Set-Cookie %v, want a clearing one", c)
	}
}

// signInBody is a LoginRequest for name with testPassword.
func signInBody(t testing.TB, name string) string {
	t.Helper()
	return jsonBody(t, LoginRequest{Username: name, Password: testPassword})
}

// longBody is n bytes of JSON-looking filler.
func longBody(n int) string { return `"` + strings.Repeat("a", n-2) + `"` }
