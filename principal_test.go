package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access/internal/failreason"
	"github.com/cplieger/access/internal/printcheck"
)

func TestPrincipalPrinting(t *testing.T) {
	t.Parallel()
	const (
		known  = "kn0wn-pr1nc1pal-h4sh-0451"
		marker = "4242"
	)
	p := Principal{
		User:       &User{ID: 7, Username: "alice", Role: RoleUser, PasswordHash: NewHash(known)},
		Method:     MethodAPIKey,
		KeyID:      4242,
		Scopes:     []string{"read"},
		SessionID:  "sess-1",
		credential: NewHash(known),
		source:     sourceSession,
	}
	values := map[string]any{"Principal": p, "*Principal": &p}
	// The same marker exceptions as TestRecordPrinting.
	noMarker := []string{"%T", "%q", "%x", "%X"}
	for name, v := range values {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			isPointer := reflect.ValueOf(v).Kind() == reflect.Pointer
			for route, got := range recordRenderings(t, v) {
				if printcheck.Leak(got, known) {
					t.Errorf("%s printed the hash: %s", route, got)
				}
				verb, nested := strings.CutPrefix(route, "[]any ")
				addressOnly := (verb == "%p" && (nested || isPointer)) || (nested && isPointer)
				if !slices.Contains(noMarker, verb) && !addressOnly && !strings.Contains(got, marker) {
					t.Errorf("%s = %s, want the principal's %s in it", route, got, marker)
				}
			}
		})
	}
	t.Run("type_graph", func(t *testing.T) {
		t.Parallel()
		checkTypes(t, printcheck.Allow{Fields: principalFields, Types: []string{"time.Time", "netip.Addr"}}, reflect.TypeFor[*Principal]())
	})
}

// principalFields are the text fields a principal reaches that hold no
// secret: its own identifiers and enums, and its user's (recordFields).
var principalFields = []string{
	"access.Principal.Method", "access.Principal.SessionID", "access.Principal.Scopes",
	"access.Principal.KeyLabel",
	"access.User.Username", "access.User.Email", "access.User.DisplayName", "access.User.Role",
	"access.User.WebAuthnHandle", "access.OIDCIdentity.Issuer", "access.OIDCIdentity.Subject",
}

func TestPrincipalLogValue(t *testing.T) {
	t.Parallel()
	p := Principal{
		User: &User{ID: 5}, Method: MethodPassword, SessionID: "sid",
		KeyID: 3, Scopes: []string{"read"}, credential: NewHash("h"),
	}
	want := map[string]any{
		"method": "password", "user_id": int64(5), "session_id": "sid",
		"key_id": int64(3), "scopes": []string{"read"},
	}
	if got := logAttrs(t, p); !reflect.DeepEqual(got, want) {
		t.Errorf("LogValue() = %v, want %v", got, want)
	}
	if _, ok := logAttrs(t, Principal{Method: "custom"})["user_id"]; ok {
		t.Error("LogValue() of a principal with no user has a user_id")
	}
}

func TestPrincipalAccessors(t *testing.T) {
	t.Parallel()
	hash := NewHash("h")
	full := Principal{User: &User{ID: 1, Enabled: true}, Method: MethodPassword, credential: hash, source: sourceSession}
	key := Principal{User: &User{ID: 1, Enabled: true}, Method: MethodAPIKey, KeyID: 2, credential: hash, source: sourceAPIKey}
	custom := Principal{User: &User{Enabled: true}, Method: "custom", SessionID: "forged", AuthTime: time.Now()}
	customKey := Principal{User: &User{Enabled: true}, Method: MethodAPIKey, KeyID: 2, credential: hash}
	for _, tt := range []struct {
		name              string
		p                 Principal
		session           bool
		tokenHash, apiKey bool
	}{
		{name: "session", p: full, session: true, tokenHash: true},
		{name: "key", p: key, apiKey: true},
		{name: "custom filling session fields", p: custom},
		{name: "custom filling key fields", p: customKey},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.p.IsSession(); got != tt.session {
				t.Errorf("IsSession() = %v, want %v", got, tt.session)
			}
			if got := tt.p.SessionTokenHash(); got.Equal(hash) != tt.tokenHash || got.IsZero() == tt.tokenHash {
				t.Errorf("SessionTokenHash() zero = %v, want zero %v", got.IsZero(), !tt.tokenHash)
			}
			if got := tt.p.IsAPIKey(); got != tt.apiKey {
				t.Errorf("IsAPIKey() = %v, want %v", got, tt.apiKey)
			}
		})
	}
	t.Run("HasScope", func(t *testing.T) {
		t.Parallel()
		p := Principal{Scopes: []string{"read", "write"}}
		if !p.HasScope("write") || p.HasScope("admin") || (Principal{}).HasScope("") {
			t.Errorf("HasScope over %v answered wrongly", p.Scopes)
		}
	})
}

type labelVerifier struct{ p Principal }

var _ Rechecker = labelVerifier{}

func (v labelVerifier) Verify(_ context.Context, r *http.Request) (Principal, bool, error) {
	if r.Header.Get("Authorization") != "Bearer label" {
		return Principal{}, false, nil
	}
	return v.p, true, nil
}

func (v labelVerifier) Recheck(context.Context, Principal) (Principal, bool, error) {
	return v.p, true, nil
}

// TestPrincipalKeyIdentity pins what marks a built-in API-key principal:
// IsAPIKey, the presented key's hash from KeyHash and the key's Label as
// KeyLabel. A session, the bypass and a custom verifier's principal that
// fills the key fields carry neither the mark nor the hash.
func TestPrincipalKeyIdentity(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	label := Principal{User: &User{ID: 900, Enabled: true}, Method: MethodAPIKey, KeyID: f.keyID, Scopes: []string{"read"}, credential: APIKeyHash(f.key)}
	a := mustAuthenticator(t, f.store, Config{Verifier: labelVerifier{p: label}})
	key := mustAuthenticate(t, a, bearerRequest(f.key))
	session := mustAuthenticate(t, a, withSession(bearerRequest(""), f.session))
	custom := mustAuthenticate(t, a, bearerRequest("label"))
	bypass := mustAuthenticate(t, mustAuthenticator(t, f.store, Config{Bypass: func() bool { return true }}), bearerRequest(""))
	for name, tc := range map[string]struct {
		p    Principal
		want bool
	}{
		"key": {p: key, want: true}, "session": {p: session}, "custom_labelled_key": {p: custom}, "bypass": {p: bypass},
	} {
		if got := tc.p.IsAPIKey(); got != tc.want {
			t.Errorf("%s: IsAPIKey() = %v, want %v", name, got, tc.want)
		}
		if got := tc.p.KeyHash(); got.Equal(APIKeyHash(f.key)) != tc.want || got.IsZero() == tc.want {
			t.Errorf("%s: KeyHash() zero = %v, want the presented key's hash %v", name, got.IsZero(), tc.want)
		}
	}
	if key.KeyLabel != "ci" {
		t.Errorf("key principal KeyLabel = %q, want the stored label ci", key.KeyLabel)
	}
	q, err := a.Recheck(t.Context(), key)
	if err != nil || !q.IsAPIKey() || q.KeyID != f.keyID || q.KeyLabel != "ci" || !q.KeyHash().Equal(APIKeyHash(f.key)) {
		t.Errorf("Recheck(key) = %+v, %v, want the key principal again", q, err)
	}
	reads := f.store.keyReads.Load()
	q, err = a.Recheck(t.Context(), custom)
	if err != nil || q.IsAPIKey() || !q.KeyHash().IsZero() || q.User.ID != 900 {
		t.Errorf("Recheck(custom labelled key) = %+v, %v, want its own verifier's principal", q, err)
	}
	if n := f.store.keyReads.Load() - reads; n != 0 {
		t.Errorf("Recheck(custom labelled key) made %d key reads, want 0", n)
	}
}

func TestRequireRecentAuth(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	now := time.Now()
	a := mustAuthenticator(t, f.store, Config{})
	r := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: f.session})
	session, err := a.Authenticate(r)
	if err != nil || !session.IsSession() {
		t.Fatalf("Authenticate(session) = (%+v, %v), want a session principal", session, err)
	}
	key, err := a.Authenticate(bearerRequest(f.key))
	if err != nil || key.KeyID == 0 {
		t.Fatalf("Authenticate(key) = (%+v, %v), want a key principal", key, err)
	}
	custom := Principal{User: &User{Enabled: true}, Method: "custom", SessionID: "sess-1", AuthTime: now}
	stale := session
	stale.AuthTime = now.Add(-2 * time.Minute)

	for _, tt := range []struct {
		name string
		p    Principal
		ok   bool
	}{
		{name: "fresh session", p: session, ok: true},
		{name: "session at exactly maxAge", p: func() Principal { s := session; s.AuthTime = now.Add(-time.Minute); return s }(), ok: true},
		{name: "stale session", p: stale},
		{name: "session at exactly now", p: func() Principal { s := session; s.AuthTime = now; return s }(), ok: true},
		{name: "session in the future", p: func() Principal { s := session; s.AuthTime = now.Add(24 * time.Hour); return s }()},
		{name: "key", p: key},
		{name: "custom filling SessionID and AuthTime", p: custom},
		{name: "zero", p: Principal{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := RequireRecentAuth(tt.p, time.Minute, now)
			if tt.ok && err != nil {
				t.Errorf("RequireRecentAuth = %v, want nil", err)
			}
			if !tt.ok && !errors.Is(err, ErrRecentAuthRequired) {
				t.Errorf("RequireRecentAuth = %v, want ErrRecentAuthRequired", err)
			}
		})
	}
}

func TestRequestMarks(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	if IsPassive(ctx) {
		t.Error("IsPassive() = true on an unmarked context")
	}
	if !IsPassive(Passive(ctx)) {
		t.Error("IsPassive(Passive(ctx)) = false")
	}
}

// TestPrincipalSecure pins Principal.Secure as the resolver's answer for the
// request Authenticate verified, whichever verifier granted it, the bypass
// included, and as Recheck's input's.
func TestPrincipalSecure(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	now := time.Now()
	plain := f.addSession(t, &Session{ID: "plain", UserID: f.user.ID, AuthMethod: MethodPassword, CreatedAt: now, LastActivity: now, AuthTime: now})
	perRequest := CookieConfig{Posture: PosturePerRequest}
	// A custom verifier's own Secure is not the request's.
	custom := Principal{User: &User{Username: "agent", Enabled: true}, Method: "agent_key", Secure: true}
	at := func(target string, r *http.Request) *http.Request {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		req.Header = r.Header
		return req
	}
	// session is the request carrying the session bound to the transport
	// of target, under its cookie name.
	session := func(target string) *http.Request {
		if strings.HasPrefix(target, "https:") {
			return withSession(bearerRequest(""), f.session)
		}
		r := bearerRequest("")
		r.AddCookie(&http.Cookie{Name: perRequest.CookieName(false), Value: plain})
		return r
	}
	targets := map[string]bool{"https://app.example/api": true, "http://app.example/api": false}
	for _, tc := range []struct {
		cfg  Config
		req  func(target string) *http.Request
		name string
	}{
		{name: "session", req: session},
		{name: "key", req: func(string) *http.Request { return bearerRequest(f.key) }},
		{name: "custom verifier", cfg: Config{Verifier: stubVerifier{p: custom, ok: true}}, req: func(string) *http.Request { return bearerRequest("") }},
		{name: "bypass", cfg: Config{Bypass: func() bool { return true }}, req: func(string) *http.Request { return bearerRequest("") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.cfg.Cookie = perRequest
			a := mustAuthenticator(t, f.store, tc.cfg)
			for target, want := range targets {
				if p := mustAuthenticate(t, a, at(target, tc.req(target))); p.Secure != want {
					t.Errorf("Authenticate(%s).Secure = %v, want %v", target, p.Secure, want)
				}
			}
		})
	}
	t.Run("recheck", func(t *testing.T) {
		t.Parallel()
		a := mustAuthenticator(t, f.store, Config{Cookie: perRequest})
		for name, req := range map[string]func(string) *http.Request{
			"session": session,
			"key":     func(string) *http.Request { return bearerRequest(f.key) },
		} {
			for target, want := range targets {
				p := mustAuthenticate(t, a, at(target, req(target)))
				q, err := a.Recheck(t.Context(), p)
				if err != nil {
					t.Fatalf("Recheck(%s over %s) = %v", name, target, err)
				}
				if q.Secure != want {
					t.Errorf("Recheck(%s over %s).Secure = %v, want the passed principal's %v", name, target, q.Secure, want)
				}
			}
		}
	})
}

// TestRequireRecentAuthSignInAgain pins the reason RequireRecentAuth's
// refusal carries: sign_in_again for a session over plain HTTP, whose
// AuthTime nothing there refreshes, and none for a secure session or for any
// principal a sign-in cannot help.
func TestRequireRecentAuthSignInAgain(t *testing.T) {
	t.Parallel()
	f := newChainFixture(t)
	now := time.Now()
	perRequest := CookieConfig{Posture: PosturePerRequest}
	// plainAt is a plain request carrying a new plain session signed in at
	// authTime.
	plainAt := func(authTime time.Time) *http.Request {
		tok := f.addSession(t, &Session{ID: "plain-" + authTime.Format(time.RFC3339Nano), UserID: f.user.ID, AuthMethod: MethodPassword, CreatedAt: now.Add(-3 * time.Hour), LastActivity: now, AuthTime: authTime})
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://app.example/api", nil)
		r.AddCookie(&http.Cookie{Name: perRequest.CookieName(false), Value: tok})
		return r
	}
	// plain is r's headers on a plain request.
	plain := func(r *http.Request) *http.Request {
		q := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://app.example/api", nil)
		q.Header = r.Header
		return q
	}
	a := mustAuthenticator(t, f.store, Config{Cookie: perRequest})
	staleSecure := mustAuthenticate(t, a, withSession(bearerRequest(""), f.session))
	staleSecure.AuthTime = now.Add(-2 * time.Hour)
	custom := Principal{User: &User{Username: "agent", Enabled: true}, Method: "agent_key", SessionID: "s", AuthTime: now.Add(-2 * time.Hour)}
	for _, tc := range []struct {
		p      Principal
		name   string
		reason string
		ok     bool
	}{
		{name: "fresh_plain_session", p: mustAuthenticate(t, a, plainAt(now)), ok: true},
		{name: "stale_plain_session", p: mustAuthenticate(t, a, plainAt(now.Add(-2*time.Hour))), reason: failreason.SignInAgain},
		{name: "future_plain_session", p: mustAuthenticate(t, a, plainAt(now.Add(time.Hour))), reason: failreason.SignInAgain},
		{name: "stale_secure_session", p: staleSecure},
		{name: "plain_key", p: mustAuthenticate(t, a, plain(bearerRequest(f.key)))},
		{name: "plain_custom_verifier", p: mustAuthenticate(t, mustAuthenticator(t, f.store, Config{Cookie: perRequest, Verifier: stubVerifier{p: custom, ok: true}}), plain(bearerRequest("")))},
		{name: "plain_bypass", p: mustAuthenticate(t, mustAuthenticator(t, f.store, Config{Cookie: perRequest, Bypass: func() bool { return true }}), plain(bearerRequest("")))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := RequireRecentAuth(tc.p, time.Minute, now)
			if tc.ok {
				if err != nil {
					t.Errorf("RequireRecentAuth = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrRecentAuthRequired) || failreason.Of(err) != tc.reason {
				t.Errorf("RequireRecentAuth(Secure %t) = %v, reason %q; want ErrRecentAuthRequired, reason %q", tc.p.Secure, err, failreason.Of(err), tc.reason)
			}
			if err != nil && err.Error() != ErrRecentAuthRequired.Error() {
				t.Errorf("refusal text = %q, want the sentinel's", err)
			}
		})
	}
}
