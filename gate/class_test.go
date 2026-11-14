package gate_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/gate"
)

var classRoutes = []gate.Route{
	{Name: "pub", Method: http.MethodGet, Path: "/pub", Class: gate.Public},
	{Name: "sess", Method: http.MethodGet, Path: "/sess", Class: gate.Session},
	{Name: "sess_post", Method: http.MethodPost, Path: "/sess", Class: gate.Session},
	{Name: "key", Method: http.MethodGet, Path: "/key", Class: gate.Key},
	{Name: "key_scoped", Method: http.MethodGet, Path: "/key/read", Class: gate.Key, Scope: "read"},
	{Name: "scoped", Method: http.MethodGet, Path: "/scoped", Class: gate.Scoped, Scope: "read"},
	{Name: "scoped_post", Method: http.MethodPost, Path: "/scoped", Class: gate.Scoped, Scope: "read"},
	{Name: "passive", Method: http.MethodGet, Path: "/passive", Class: gate.Session, Passive: true},
	{Name: "active", Method: http.MethodGet, Path: "/active", Class: gate.Session},
}

// ok is an admitted request in a class table.
const ok access.Code = ""

// TestClasses is the class table of design 2.2 for each principal, under
// the default Allow: no principal passes implicitly, and a bypass or custom
// verifier's principal passes only where Allow says so.
func TestClasses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	s := &served{}
	g := mustGate(t, gate.Config{Authenticator: f.authn}, classRoutes, s)
	bs := &served{}
	bg := mustGate(t, gate.Config{Authenticator: f.bypass}, classRoutes, bs)
	type principal struct {
		g    *gate.Gate
		cred cred
	}
	principals := map[string]principal{
		"session":  {g, sessionCred},
		"key_read": {g, keyReadCred},
		"key_none": {g, keyNoneCred},
		"bypass":   {bg, noCred},
		"agent":    {g, agentCred},
	}
	for _, tc := range []struct {
		path string
		want map[string]access.Code
	}{
		{"/pub", map[string]access.Code{"session": ok, "key_read": ok, "key_none": ok, "bypass": ok, "agent": ok}},
		{"/sess", map[string]access.Code{
			"session": ok, "key_read": access.CodeSessionRequired, "key_none": access.CodeSessionRequired,
			"bypass": access.CodeSessionRequired, "agent": access.CodeSessionRequired,
		}},
		{"/key", map[string]access.Code{
			"session": access.CodeKeyRequired, "key_read": ok, "key_none": ok,
			"bypass": access.CodeKeyRequired, "agent": access.CodeKeyRequired,
		}},
		{"/key/read", map[string]access.Code{
			"session": access.CodeKeyRequired, "key_read": ok, "key_none": access.CodeScopeRequired,
			"bypass": access.CodeKeyRequired, "agent": access.CodeKeyRequired,
		}},
		{"/scoped", map[string]access.Code{
			"session": ok, "key_read": ok, "key_none": access.CodeScopeRequired,
			"bypass": access.CodeForbidden, "agent": access.CodeForbidden,
		}},
	} {
		for who, want := range tc.want {
			t.Run(strings.TrimPrefix(strings.ReplaceAll(tc.path, "/", "_"), "_")+"_"+who, func(t *testing.T) {
				t.Parallel()
				pr := principals[who]
				a := do(t, f, pr.g, http.MethodGet, tc.path, pr.cred)
				if want == ok {
					if a.status != http.StatusOK {
						t.Errorf("GET %s as %s = %d %q, want admitted", tc.path, who, a.status, a.code)
					}
					return
				}
				if a.status != http.StatusForbidden || a.code != want {
					t.Errorf("GET %s as %s = %d %q, want 403 %s", tc.path, who, a.status, a.code, want)
				}
			})
		}
	}
}

// TestCustomAllow: Allow replaces the whole scope decision, for sessions and
// keys alike, and is asked with the row's scope.
func TestCustomAllow(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	var (
		mu     sync.Mutex
		scopes []string
	)
	allow := func(p access.Principal, scope string) bool {
		mu.Lock()
		scopes = append(scopes, scope)
		mu.Unlock()
		return p.Method == agentMethod && p.HasScope(scope)
	}
	g := mustGate(t, gate.Config{Authenticator: f.authn, Allow: allow}, classRoutes, &served{})
	for _, tc := range []struct {
		name, path string
		cred       cred
		want       access.Code
	}{
		{"scoped_agent", "/scoped", agentCred, ok},
		{"scoped_session", "/scoped", sessionCred, access.CodeForbidden},
		{"scoped_key", "/scoped", keyReadCred, access.CodeScopeRequired},
		{"key_scoped_key", "/key/read", keyReadCred, access.CodeScopeRequired},
		{"key_unscoped_key", "/key", keyReadCred, ok},
	} {
		a := do(t, f, g, http.MethodGet, tc.path, tc.cred)
		if a.code != tc.want || (tc.want == ok) != (a.status == http.StatusOK) {
			t.Errorf("%s: GET %s = %d %q, want %q", tc.name, tc.path, a.status, a.code, tc.want)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(scopes) != 4 {
		t.Fatalf("Allow asked %d times, want 4 (never for an unscoped Key row): %q", len(scopes), scopes)
	}
	for _, s := range scopes {
		if s != "read" {
			t.Errorf("Allow asked with scope %q, want the row's %q", s, "read")
		}
	}
}

// TestRefusedCredentials: what each authenticating row answers for a
// credential the Authenticator refuses or cannot judge, before the handler.
func TestRefusedCredentials(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	s := &served{}
	g := mustGate(t, gate.Config{Authenticator: f.authn}, classRoutes, s)
	for _, path := range []string{"/sess", "/key", "/key/read", "/scoped"} {
		for _, tc := range []struct {
			name      string
			cred      cred
			code      access.Code
			status    int
			challenge string
		}{
			{"no_credential", noCred, access.CodeAuthRequired, 401, `Bearer realm="access"`},
			{"session_expired", expiredCred, access.CodeSessionExpired, 401, `Bearer realm="access"`},
			{"session_gone", goneCred, access.CodeSessionExpired, 401, `Bearer realm="access"`},
			{"key_unknown", unknownKey, access.CodeKeyInvalid, 401, `Bearer realm="access", error="invalid_token"`},
			{"custom_refusal", withAgent("bad"), access.CodeInvalidCredentials, 401, `Bearer realm="access"`},
			{"recovery_cookie", recoveryCred, access.CodeSessionRequired, 403, ""},
			{"unmapped_error", withAgent("boom"), access.CodeUnavailable, 503, ""},
		} {
			t.Run(strings.TrimPrefix(strings.ReplaceAll(path, "/", "_"), "_")+"_"+tc.name, func(t *testing.T) {
				t.Parallel()
				a := do(t, f, g, http.MethodGet, path, tc.cred)
				if a.status != tc.status || a.code != tc.code {
					t.Errorf("GET %s = %d %q, want %d %s", path, a.status, a.code, tc.status, tc.code)
				}
				if got := a.header.Get("WWW-Authenticate"); got != tc.challenge {
					t.Errorf("WWW-Authenticate = %q, want %q", got, tc.challenge)
				}
				if tc.status == 503 && a.header.Get("Retry-After") != "5" {
					t.Errorf("Retry-After = %q, want 5", a.header.Get("Retry-After"))
				}
			})
		}
	}
	t.Run("handler_not_called", func(t *testing.T) {
		t.Parallel()
		h := &served{}
		g := mustGate(t, gate.Config{Authenticator: f.authn}, classRoutes, h)
		do(t, f, g, http.MethodGet, "/sess", withAgent("boom"))
		if _, ran := h.principal("sess"); ran {
			t.Error("the handler ran for a refused request")
		}
	})
	t.Run("public_ignores_credentials", func(t *testing.T) {
		t.Parallel()
		for _, c := range []cred{unknownKey, goneCred, withAgent("boom"), recoveryCred} {
			if a := do(t, f, g, http.MethodGet, "/pub", c); a.status != http.StatusOK {
				t.Errorf("GET /pub = %d %q, want 200 whatever the credential", a.status, a.code)
			}
		}
	})
}

// TestVerifierErrorLogs: an error access does not map is the verifier's own
// breakage, logged at ERROR; the same error carrying the request's ended
// context is the client walking away, logged at DEBUG.
func TestVerifierErrorLogs(t *testing.T) {
	t.Parallel()
	t.Run("unmapped", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		g := mustGate(t, gate.Config{Authenticator: f.authn, Logger: f.logger()}, classRoutes, &served{})
		a := do(t, f, g, http.MethodGet, "/sess", withAgent("boom"))
		if a.status != http.StatusServiceUnavailable || a.code != access.CodeUnavailable {
			t.Errorf("GET /sess = %d %q, want 503 %s", a.status, a.code, access.CodeUnavailable)
		}
		if logs := f.logs.String(); !strings.Contains(logs, "level=ERROR") || !strings.Contains(logs, "route=sess") || !strings.Contains(logs, "agent: verifier broke") {
			t.Errorf("logs = %q, want one ERROR naming the route and the error", logs)
		}
	})
	t.Run("request_ended", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		g := mustGate(t, gate.Config{Authenticator: f.authn, Logger: f.logger()}, classRoutes, &served{})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/sess", nil)
		withAgent("ctx")(f, r)
		a := serve(t, g, r)
		if a.status != http.StatusServiceUnavailable || a.code != access.CodeUnavailable {
			t.Errorf("GET /sess = %d %q, want 503 %s", a.status, a.code, access.CodeUnavailable)
		}
		logs := f.logs.String()
		if strings.Contains(logs, "level=ERROR") || strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "level=DEBUG") || !strings.Contains(logs, "route=sess") {
			t.Errorf("logs = %q, want one DEBUG line naming the route and no ERROR or WARN", logs)
		}
	})
}

// TestCrossOrigin: an unsafe Session or Scoped row refuses a cross-site
// browser request before reading its cookie, and a Bearer client, which
// sends no Sec-Fetch-Site or Origin, passes.
func TestCrossOrigin(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	s := &served{}
	g := mustGate(t, gate.Config{Authenticator: f.authn}, classRoutes, s)
	for _, path := range []string{"/sess", "/scoped"} {
		a := do(t, f, g, http.MethodPost, path, sessionCred, crossSite)
		if a.status != http.StatusForbidden || a.code != access.CodeCrossOrigin {
			t.Errorf("cross-site POST %s = %d %q, want 403 %s", path, a.status, a.code, access.CodeCrossOrigin)
		}
		if got := a.header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("cross-site POST %s Cache-Control = %q, want no-store", path, got)
		}
	}
	if a := do(t, f, g, http.MethodPost, "/sess", sessionCred, func(_ *fixture, r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }); a.status != http.StatusOK {
		t.Errorf("same-origin POST /sess = %d %q, want 200", a.status, a.code)
	}
	if a := do(t, f, g, http.MethodPost, "/scoped", keyReadCred); a.status != http.StatusOK {
		t.Errorf("Bearer POST /scoped = %d %q, want 200", a.status, a.code)
	}
	if a := do(t, f, g, http.MethodGet, "/sess", sessionCred, crossSite); a.status != http.StatusOK {
		t.Errorf("cross-site GET /sess = %d %q, want 200: a safe method is not checked", a.status, a.code)
	}
}

// TestPassive: a Passive row verifies the session without writing its
// activity (G4), and the same session on an ordinary row writes it.
func TestPassive(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	g := mustGate(t, gate.Config{Authenticator: f.authn}, classRoutes, &served{})
	stale := withCookie(func(f *fixture) string { return f.stale })
	before := f.lastActivity(t)
	if a := do(t, f, g, http.MethodGet, "/passive", stale); a.status != http.StatusOK {
		t.Fatalf("GET /passive = %d %q, want 200", a.status, a.code)
	}
	if got := f.lastActivity(t); !got.Equal(before) {
		t.Errorf("LastActivity after a Passive row = %v, want unchanged %v", got, before)
	}
	if a := do(t, f, g, http.MethodGet, "/active", stale); a.status != http.StatusOK {
		t.Fatalf("GET /active = %d %q, want 200", a.status, a.code)
	}
	if got := f.lastActivity(t); !got.After(before) {
		t.Errorf("LastActivity after an ordinary row = %v, want after %v", got, before)
	}
}

// TestPrincipal: the handler sees the principal the gate admitted, and a
// Public row's handler sees none.
func TestPrincipal(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	s := &served{}
	g := mustGate(t, gate.Config{Authenticator: f.authn}, classRoutes, s)
	do(t, f, g, http.MethodGet, "/sess", sessionCred)
	if p, ok := s.principal("sess"); !ok || !p.IsSession() || p.SessionID != "full" || p.User == nil || p.User.ID != f.userID {
		t.Errorf("Principal on /sess = %+v, %t, want the full session", p, ok)
	}
	do(t, f, g, http.MethodGet, "/key/read", keyReadCred)
	if p, ok := s.principal("key_scoped"); !ok || !p.IsAPIKey() || p.KeyID != f.keyID {
		t.Errorf("Principal on /key/read = %+v, %t, want key %d", p, ok, f.keyID)
	}
	do(t, f, g, http.MethodGet, "/pub", sessionCred)
	if p, ok := s.principal("pub"); ok || p.User != nil {
		t.Errorf("Principal on /pub = %+v, %t, want none", p, ok)
	}
	if p, ok := gate.Principal(t.Context()); ok || p.User != nil {
		t.Errorf("Principal(a context the gate never saw) = %+v, %t, want none", p, ok)
	}
}
