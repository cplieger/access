package access

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access/internal/printcheck"
)

func TestCanDisableMethodRemaining(t *testing.T) {
	t.Parallel()
	password := MethodAvailability{HasPassword: true}
	passkey := MethodAvailability{PasskeyCount: 1}
	oidc := MethodAvailability{OIDCEnabled: true, OIDCLinked: true}
	tests := []struct {
		name   string
		method Method
		avail  MethodAvailability
		want   bool
	}{
		{"passkey removal with one passkey left", MethodPasskey, passkey, true},
		{"passkey removal with two passkeys left", MethodPasskey, MethodAvailability{PasskeyCount: 2}, true},
		{"passkey removal with none left", MethodPasskey, MethodAvailability{}, false},
		{"password removal with only the password", MethodPassword, password, false},
		{"oidc removal with only the link", MethodOIDC, oidc, false},
		{"oidc linked but disabled server-wide", MethodPassword, MethodAvailability{OIDCLinked: true}, false},
		{"oidc enabled but not linked", MethodPassword, MethodAvailability{OIDCEnabled: true}, false},

		{"password removal kept by a passkey", MethodPassword, passkey, true},
		{"password removal kept by oidc", MethodPassword, oidc, true},
		{"passkey removal kept by the password", MethodPasskey, password, true},
		{"passkey removal kept by oidc", MethodPasskey, oidc, true},
		{"oidc removal kept by the password", MethodOIDC, password, true},
		{"oidc removal kept by a passkey", MethodOIDC, passkey, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := CanDisableMethod(tt.method, tt.avail); got != tt.want {
				t.Errorf("CanDisableMethod(%s, %+v) = %v, want %v", tt.method, tt.avail, got, tt.want)
			}
		})
	}
}

func TestHasRole_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		userRole Role
		required Role
		want     bool
	}{
		{"admin accessing admin", "admin", "admin", true},
		{"admin accessing user", "admin", "user", true},
		{"user accessing user", "user", "user", true},
		{"user accessing admin", "user", "admin", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			user := &User{Role: tt.userRole}
			if got := HasRole(user, tt.required); got != tt.want {
				t.Errorf("HasRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateRedirectURI_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		uri  string
		want string
	}{
		{"empty", "", "/"},
		{"root", "/", "/"},
		{"relative path", "/dashboard", "/dashboard"},
		{"two-char path", "/a", "/a"},
		{"absolute http", "http://evil.com", "/"},
		{"protocol-relative", "//evil.com", "/"},
		{"scheme in path", "/foo://bar", "/"},
		{"no leading slash", "evil.com", "/"},
		{"dot segments in fragment kept", "/settings#/../../admin", "/settings#/../../admin"},
		{"CR after fragment", "/#/../\r/evil.com", "/"},
		{"NUL in path", "/a\x00", "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidateRedirectURI(tt.uri); got != tt.want {
				t.Errorf("ValidateRedirectURI(%q) = %q, want %q", tt.uri, got, tt.want)
			}
		})
	}
}

func TestValidateRedirectURILength(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		n    int
		want bool
	}{
		{"2048 bytes accepted", 2048, true},
		{"2049 bytes refused", 2049, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			uri := "/" + strings.Repeat("a", tt.n-1)
			want := "/"
			if tt.want {
				want = uri
			}
			if got := ValidateRedirectURI(uri); got != want {
				t.Errorf("ValidateRedirectURI(%d-byte path) = %d bytes, want %d", tt.n, len(got), len(want))
			}
		})
	}
}

func TestAuthenticate_session_cookie_valid(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "sessuser", PasswordHash: NewHash("dummy"), Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash := GenerateSessionToken()
	now := time.Now()
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		LastIP: "127.0.0.1", CreatedAt: now, LastActivity: now,
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/api/config", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: plaintext.Reveal()})

	p, gotErr := a.Authenticate(r)
	if gotErr != nil {
		t.Fatalf("error = %v", gotErr)
	}
	if p.User.ID != user.ID {
		t.Errorf("user ID = %d, want %d", p.User.ID, user.ID)
	}
	if !p.SessionTokenHash().Equal(hash) {
		t.Errorf("hash = %q, want %q", p.SessionTokenHash().Reveal(), hash.Reveal())
	}
}

func TestAuthenticate_expired_session_falls_through(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "expuser", PasswordHash: NewHash("dummy"), Role: "user", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash := GenerateSessionToken()
	old := time.Now().Add(-25 * time.Hour)
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		LastIP: "127.0.0.1", CreatedAt: old, LastActivity: old.Add(23 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: plaintext.Reveal()})

	if _, err := a.Authenticate(r); !errors.Is(err, ErrUnauthenticated) || !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Authenticate(expired session) error = %v, want ErrUnauthenticated wrapping ErrSessionExpired", err)
	}
}

func TestAuthenticate_api_key_header(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "apiuser", PasswordHash: NewHash("dummy"), Role: "user", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix := mustAPIKey(t)
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/api/search", nil)
	r.Header.Set("Authorization", "Bearer "+plaintext)

	p, gotErr := a.Authenticate(r)
	if gotErr != nil {
		t.Fatalf("error = %v", gotErr)
	}
	if p.User.ID != user.ID {
		t.Errorf("user ID = %d, want %d", p.User.ID, user.ID)
	}
}

func TestAuthenticate_no_credentials(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	_, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrUnauthenticated) {
		t.Errorf("error = %v, want ErrUnauthenticated", gotErr)
	}
}

func TestAuthenticate_disabled_user_session(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "disabled", PasswordHash: NewHash("dummy"), Role: "user", Enabled: false}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash := GenerateSessionToken()
	now := time.Now()
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		LastIP: "127.0.0.1", CreatedAt: now, LastActivity: now,
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: plaintext.Reveal()})

	if _, err := a.Authenticate(r); !errors.Is(err, ErrUnauthenticated) || !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Authenticate(disabled user session) error = %v, want ErrUnauthenticated wrapping ErrSessionNotFound", err)
	}
}

func TestRequireAuth_unauthenticated_browser_gets_401(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/api/config", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	_, ok := a.RequireAuth(w, r)
	if ok {
		t.Fatal("expected ok=false")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want none (no browser redirect)", loc)
	}
}

func TestRequireAuth_unauthenticated_api_returns_401(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/api/config", nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	_, ok := a.RequireAuth(w, r)
	if ok {
		t.Fatal("expected ok=false")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthenticate_api_key_query_param_rejected(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "queryuser", PasswordHash: NewHash("dummy"), Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix := mustAPIKey(t)
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	// A valid key supplied only via the URL query parameter must NOT authenticate:
	// keys are accepted via Authorization: Bearer only (CWE-598: a key in the query
	// string leaks into access logs, browser history, and the Referer header).
	r, _ := http.NewRequest(http.MethodGet, "/api/search?api_key="+plaintext, nil)

	p, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrUnauthenticated) {
		t.Fatalf("Authenticate(api_key query) error = %v, want ErrUnauthenticated", gotErr)
	}
	if !isZeroPrincipal(p) {
		t.Errorf("Authenticate(api_key query) = %+v, want the zero Principal (query-param keys rejected)", p)
	}
}

func TestAuthenticate_invalid_api_key(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+"ak_invalid_key_value")

	_, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrInvalidCredential) || !errors.Is(gotErr, ErrInvalidAPIKey) {
		t.Errorf("Authenticate(invalid key) error = %v, want ErrInvalidCredential wrapping ErrInvalidAPIKey", gotErr)
	}
}

func TestAuthenticate_disabled_user_api_key(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "disabledapi", PasswordHash: NewHash("dummy"), Role: "user", Enabled: false}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix := mustAPIKey(t)
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+plaintext)

	_, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrInvalidCredential) || !errors.Is(gotErr, ErrAccountDisabled) {
		t.Errorf("Authenticate(disabled user API key) error = %v, want ErrInvalidCredential wrapping ErrAccountDisabled", gotErr)
	}
}

func TestRequireAuth_authenticated_returns_user(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "authuser", PasswordHash: NewHash("dummy"), Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix := mustAPIKey(t)
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/api/search", nil)
	r.Header.Set("Authorization", "Bearer "+plaintext)
	w := httptest.NewRecorder()

	p, ok := a.RequireAuth(w, r)
	if !ok {
		t.Fatal("RequireAuth() returned ok=false for authenticated request")
	}
	if p.User.ID != user.ID {
		t.Errorf("RequireAuth() user ID = %d, want %d", p.User.ID, user.ID)
	}
}

func TestAuthenticate_session_not_found_falls_through(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: "nonexistent-session-token"})

	if _, err := a.Authenticate(r); !errors.Is(err, ErrUnauthenticated) || !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Authenticate(unknown session cookie) error = %v, want ErrUnauthenticated wrapping ErrSessionNotFound", err)
	}
}

func TestAuthenticate_stale_session_falls_through_to_api_key(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "fallthrough_user", PasswordHash: NewHash("dummy"), Role: "user", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix := mustAPIKey(t)
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour})
	r, _ := http.NewRequest(http.MethodGet, "/api/search", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: "stale-session-token"})
	r.Header.Set("Authorization", "Bearer "+plaintext)

	p, gotErr := a.Authenticate(r)
	if gotErr != nil {
		t.Fatalf("Authenticate(stale session + valid API key) error = %v, want nil", gotErr)
	}
	if p.User.ID != user.ID {
		t.Errorf("Authenticate(stale session + valid API key) user ID = %d, want %d", p.User.ID, user.ID)
	}
}

func TestAuthenticator_Logger_used(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	db := newFakeSessionStore()
	ctx := t.Context()

	// A disabled user with an otherwise-valid session makes the default
	// session verifier emit a debug record; it must go to the injected logger.
	user := &User{Username: "disabled", Role: RoleUser, Enabled: false}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	plaintext, hash := GenerateSessionToken()
	now := time.Now()
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		LastIP: "127.0.0.1", CreatedAt: now, LastActivity: now,
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, Config{IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour, Logger: logger})
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: plaintext.Reveal()})

	if _, err := a.Authenticate(r); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate(disabled user) error = %v, want ErrUnauthenticated", err)
	}
	if !strings.Contains(buf.String(), "session user missing or disabled") {
		t.Errorf("injected logger captured no session-verifier log; got %q", buf.String())
	}
}

func TestValidateRedirectURI_rejects_backslash_and_malformed(t *testing.T) {
	t.Parallel()
	// Backslash-bearing and malformed-escape URIs are open-redirect vectors
	// (browsers fold "/\" to "//"); each must collapse to the safe root path.
	for _, tt := range []struct {
		name string
		uri  string
	}{
		{"backslash prefix", "/\\evil.com"},
		{"backslash in path", "/foo\\bar"},
		{"backslash before slash", "/\\/evil.com"},
		{"invalid percent-escape", "/%zz"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidateRedirectURI(tt.uri); got != "/" {
				t.Errorf("ValidateRedirectURI(%q) = %q, want %q", tt.uri, got, "/")
			}
		})
	}
}

func TestValidateRedirectURIRefusesControlBytes(t *testing.T) {
	t.Parallel()
	controls := []byte{0x7f}
	for c := range byte(0x20) {
		controls = append(controls, c)
	}
	for _, c := range controls {
		for _, uri := range []string{"/a" + string(c) + "b", "/a?q=" + string(c), "/a#" + string(c)} {
			if got := ValidateRedirectURI(uri); got != "/" {
				t.Errorf("ValidateRedirectURI(%q) = %q, want %q", uri, got, "/")
			}
		}
	}
	if got := ValidateRedirectURI("/a#b c"); got != "/a#b c" {
		t.Errorf("ValidateRedirectURI(%q) = %q, want it kept", "/a#b c", got)
	}
}

func TestHasRole_nilUser_failsClosed(t *testing.T) {
	t.Parallel()
	// A nil principal must fail closed (false), never panic: HasRole guards an
	// authorization decision and a nil user means "not authenticated".
	if HasRole(nil, RoleUser) {
		t.Error("HasRole(nil, RoleUser) = true, want false (fail closed)")
	}
	if HasRole(nil, RoleAdmin) {
		t.Error("HasRole(nil, RoleAdmin) = true, want false (fail closed)")
	}
}

// errVerifier is a CredentialVerifier that always returns a backend error,
// exercising the non-ErrUnauthenticated error path of Authenticate/RequireAuth.
type errVerifier struct{ err error }

func (e errVerifier) Verify(context.Context, *http.Request) (Principal, bool, error) {
	return Principal{}, false, e.err
}

func TestAuthenticator_injectedVerifierError_failsClosed(t *testing.T) {
	t.Parallel()
	// A verifier that returns a backend error must fail closed: Authenticate
	// propagates the error (not ErrUnauthenticated) and RequireAuth denies the
	// request (ok=false, 401) rather than treating the error as success.
	wantErr := errors.New("backend down")
	a := mustAuthenticator(t, newFakeSessionStore(), Config{Verifier: errVerifier{err: wantErr}})

	if _, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/api/x", nil)); !errors.Is(err, wantErr) {
		t.Fatalf("Authenticate() error = %v, want %v", err, wantErr)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	if _, ok := a.RequireAuth(w, r); ok {
		t.Fatal("RequireAuth() ok = true on verifier error, want false (fail closed)")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("RequireAuth() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthenticatorAccessors(t *testing.T) {
	t.Parallel()
	cookie := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	var src SessionTimeouts
	a := mustAuthenticator(t, newFakeSessionStore(), Config{
		Cookie:        cookie,
		IdleTimeout:   2 * time.Hour,
		AbsTimeout:    48 * time.Hour,
		TimeoutSource: func() SessionTimeouts { return src },
	})
	if got := a.Cookie(); got.Name != "s" || got.Posture != PostureInsecureLAN {
		t.Errorf("Cookie() = %+v, want the configured cookie", got)
	}
	if got, want := a.Timeouts(), (SessionTimeouts{Idle: 2 * time.Hour, Absolute: 48 * time.Hour}); got != want {
		t.Errorf("Timeouts() with a zero source = %+v, want the static %+v", got, want)
	}
	src = SessionTimeouts{Idle: time.Hour}
	if got, want := a.Timeouts(), (SessionTimeouts{Idle: time.Hour, Absolute: 48 * time.Hour}); got != want {
		t.Errorf("Timeouts() with a source idle = %+v, want %+v", got, want)
	}
}

// recheckVerifier grants nothing and rechecks every principal to its own
// fixed answer.
type recheckVerifier struct {
	err error
	p   Principal
	ok  bool
}

var _ Rechecker = recheckVerifier{}

func (recheckVerifier) Verify(context.Context, *http.Request) (Principal, bool, error) {
	return Principal{}, false, nil
}

func (v recheckVerifier) Recheck(context.Context, Principal) (Principal, bool, error) {
	return v.p, v.ok, v.err
}

func TestRecheckWritesNothing(t *testing.T) {
	t.Parallel()
	t.Run("session and key re-read with their deadlines", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{})
		sess := mustAuthenticate(t, a, withSession(bearerRequest(""), f.session))
		key := mustAuthenticate(t, a, bearerRequest(f.key))
		writes, reads := f.store.writes(), f.store.sessReads.Load()+f.store.keyReads.Load()
		for name, p := range map[string]Principal{"session": sess, "key": key} {
			for range 3 {
				q, err := a.Recheck(t.Context(), p)
				if err != nil {
					t.Fatalf("Recheck(%s) error = %v", name, err)
				}
				if q.User.ID != p.User.ID || q.SessionID != p.SessionID || q.KeyID != p.KeyID || q.IsSession() != p.IsSession() ||
					!q.IdleDeadline.Equal(p.IdleDeadline) || !q.AbsoluteDeadline.Equal(p.AbsoluteDeadline) {
					t.Errorf("Recheck(%s) = %+v, want the principal Authenticate gave, %+v", name, q, p)
				}
			}
		}
		if n := f.store.writes(); n != writes {
			t.Errorf("Recheck made %d writes, want 0", n-writes)
		}
		if n := f.store.sessReads.Load() + f.store.keyReads.Load(); n != reads+6 {
			t.Errorf("Recheck made %d credential reads, want 6 (one per call)", n-reads)
		}
	})
	t.Run("a revoked session and a disabled key owner are refused", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{})
		sess := mustAuthenticate(t, a, withSession(bearerRequest(""), f.session))
		key := mustAuthenticate(t, a, bearerRequest(f.key))
		f.store.deleteUserSessions(f.user.ID)
		if _, err := a.Recheck(t.Context(), sess); !errors.Is(err, ErrUnauthenticated) || !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("Recheck(revoked session) error = %v, want ErrUnauthenticated wrapping ErrSessionNotFound", err)
		}
		f.store.users = map[int64]userAnswer{f.user.ID: {user: &User{ID: f.user.ID}, found: true}}
		if _, err := a.Recheck(t.Context(), key); !errors.Is(err, ErrInvalidCredential) || !errors.Is(err, ErrAccountDisabled) {
			t.Errorf("Recheck(key of a disabled user) error = %v, want ErrInvalidCredential wrapping ErrAccountDisabled", err)
		}
	})
	t.Run("other principals go to the custom Rechecker", func(t *testing.T) {
		t.Parallel()
		custom := Principal{User: &User{Username: "agent", Enabled: true}, Method: "agent_key"}
		fresh := Principal{User: &User{Username: "agent", Enabled: true}, Method: "agent_key", Scopes: []string{"x"}}
		a := mustAuthenticator(t, newFakeSessionStore(), Config{Verifier: recheckVerifier{p: fresh, ok: true}})
		q, err := a.Recheck(t.Context(), custom)
		if err != nil || !q.HasScope("x") {
			t.Errorf("Recheck(custom) = (%+v, %v), want the Rechecker's answer", q, err)
		}
		if q.User == fresh.User {
			t.Error("Recheck returned the Rechecker's own User pointer, want a copy")
		}
		refusal := &InvalidCredentialError{Method: "agent_key"}
		for name, row := range map[string]struct {
			rc   recheckVerifier
			want error
		}{
			"refusal":                {rc: recheckVerifier{err: refusal}, want: refusal},
			"refusal beside ok true": {rc: recheckVerifier{p: fresh, ok: true, err: refusal}, want: refusal},
			"disabled user":          {rc: recheckVerifier{p: Principal{User: &User{}, Method: "agent_key"}, ok: true}, want: ErrAccountDisabled},
			"zero principal granted": {rc: recheckVerifier{ok: true}, want: ErrAccountDisabled},
			"not mine":               {rc: recheckVerifier{}, want: ErrNotRecheckable},
		} {
			a := mustAuthenticator(t, newFakeSessionStore(), Config{Verifier: row.rc})
			if _, err := a.Recheck(t.Context(), custom); !errors.Is(err, row.want) {
				t.Errorf("Recheck(custom answering %s) error = %v, want %v", name, err, row.want)
			}
		}
	})
	t.Run("no Rechecker is not recheckable", func(t *testing.T) {
		t.Parallel()
		custom := Principal{User: &User{Enabled: true}, Method: "agent_key"}
		for name, a := range map[string]*Authenticator{
			"no custom verifier":         mustAuthenticator(t, newFakeSessionStore(), Config{}),
			"a verifier with no Recheck": mustAuthenticator(t, newFakeSessionStore(), Config{Verifier: stubVerifier{}}),
		} {
			if _, err := a.Recheck(t.Context(), custom); !errors.Is(err, ErrNotRecheckable) {
				t.Errorf("%s: Recheck error = %v, want ErrNotRecheckable", name, err)
			}
		}
		key := Principal{User: &User{Enabled: true}, Method: MethodAPIKey, KeyID: 4}
		if _, err := mustAuthenticator(t, newFakeSessionStore(), Config{}).Recheck(t.Context(), key); !errors.Is(err, ErrNotRecheckable) {
			t.Errorf("Recheck(a custom principal claiming MethodAPIKey) error = %v, want ErrNotRecheckable", err)
		}
	})
}

// TestAuthenticatorPrinting pins that every text-capable field an
// Authenticator reaches is a reviewed non-secret one: the app's own store,
// verifier and logger, the chain of its verifiers, and the cookie's
// attributes.
func TestAuthenticatorPrinting(t *testing.T) {
	t.Parallel()
	checkTypes(t, printcheck.Allow{Fields: []string{
		"access.Authenticator.chain",
		"access.sessionVerifier.store", "access.apiKeyVerifier.store",
		"access.Config.Logger", "access.Config.Verifier",
		"access.CookieConfig.Name", "access.CookieConfig.Path", "access.CookieConfig.Domain",
	}, Types: []string{"time.Time"}}, reflect.TypeFor[*Authenticator]())
}

func TestAuthenticateSetsPrincipalIP(t *testing.T) {
	t.Parallel()
	proxy, client := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("203.0.113.9")
	// behindProxy trusts 10.0.0.1 as a proxy and takes the client from its
	// X-Forwarded-For.
	behindProxy := func(r *http.Request) ClientAddr {
		peer := netip.MustParseAddrPort(r.RemoteAddr).Addr()
		if peer == proxy {
			return ClientAddr{Peer: peer, Forwarded: netip.MustParseAddr(r.Header.Get("X-Forwarded-For")), Via: ViaProxy}
		}
		return ClientAddr{Peer: peer, Via: ViaDirect}
	}
	f := newChainFixture(t)
	custom := Principal{User: &User{Username: "agent", Enabled: true}, Method: "agent_key"}
	for _, tc := range []struct {
		name string
		cfg  Config
		req  func() *http.Request
		want netip.Addr
	}{
		{"session", Config{}, func() *http.Request { return withSession(bearerRequest(""), f.session) }, netip.MustParseAddr("192.0.2.1")},
		{"key", Config{}, func() *http.Request { return bearerRequest(f.key) }, netip.MustParseAddr("192.0.2.1")},
		{"custom_verifier", Config{Verifier: stubVerifier{p: custom, ok: true}}, func() *http.Request { return bearerRequest("") }, netip.MustParseAddr("192.0.2.1")},
		{"bypass", Config{Bypass: func() bool { return true }}, func() *http.Request { return bearerRequest("") }, netip.MustParseAddr("192.0.2.1")},
		{"session_behind_proxy", Config{ClientAddr: behindProxy}, func() *http.Request {
			r := withSession(bearerRequest(""), f.session)
			r.RemoteAddr = netip.AddrPortFrom(proxy, 4000).String()
			r.Header.Set("X-Forwarded-For", client.String())
			return r
		}, client},
		{"bypass_behind_proxy", Config{ClientAddr: behindProxy, Bypass: func() bool { return true }}, func() *http.Request {
			r := bearerRequest("")
			r.RemoteAddr = netip.AddrPortFrom(proxy, 4000).String()
			r.Header.Set("X-Forwarded-For", client.String())
			return r
		}, client},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := mustAuthenticator(t, f.store, tc.cfg)
			r := tc.req()
			p := mustAuthenticate(t, a, r)
			if want := a.ClientAddr(r).IP(); p.IP != want || p.IP != tc.want {
				t.Errorf("Principal.IP = %v, want ClientAddr(r).IP() %v (%v)", p.IP, want, tc.want)
			}
		})
	}
	t.Run("recheck_keeps_ip", func(t *testing.T) {
		t.Parallel()
		a := mustAuthenticator(t, f.store, Config{ClientAddr: behindProxy})
		for name, r := range map[string]*http.Request{
			"session": withSession(bearerRequest(""), f.session),
			"key":     bearerRequest(f.key),
		} {
			r.RemoteAddr = netip.AddrPortFrom(proxy, 4000).String()
			r.Header.Set("X-Forwarded-For", client.String())
			p := mustAuthenticate(t, a, r)
			q, err := a.Recheck(t.Context(), p)
			if err != nil {
				t.Fatalf("Recheck(%s) = %v", name, err)
			}
			if q.IP != client || q.IP != p.IP {
				t.Errorf("Recheck(%s).IP = %v, want the passed principal's %v", name, q.IP, p.IP)
			}
		}
	})
}
