package access

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultUnauthorizedResponse(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		err        error
		name       string
		code       string
		errValue   string
		retryAfter string
		status     int
		bearer     bool
	}{
		{name: "no credential", err: nil, status: http.StatusUnauthorized, code: "auth_required", errValue: "unauthenticated", bearer: true},
		{
			name: "session expired", err: fmt.Errorf("%w: %w", ErrUnauthenticated, ErrSessionExpired),
			status: http.StatusUnauthorized, code: "auth_session_expired", errValue: "unauthenticated", bearer: true,
		},
		{
			name: "session not found", err: fmt.Errorf("%w: %w", ErrUnauthenticated, ErrSessionNotFound),
			status: http.StatusUnauthorized, code: "auth_session_expired", errValue: "unauthenticated", bearer: true,
		},
		{
			name: "invalid credential", err: &InvalidCredentialError{Err: ErrInvalidAPIKey, Method: MethodAPIKey},
			status: http.StatusUnauthorized, code: "auth_required", errValue: "unauthenticated", bearer: true,
		},
		{
			name: "backend", err: fmt.Errorf("%w: %w", ErrAuthBackend, errors.New("db down")),
			status: http.StatusServiceUnavailable, code: "auth_unavailable", errValue: "unavailable", retryAfter: "5",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var cfg Config
			if tt.err != nil {
				cfg.Verifier = errVerifier{err: tt.err}
			}
			a := mustAuthenticator(t, newFakeSessionStore(), cfg)
			r := httptest.NewRequest(http.MethodGet, "/private", nil)
			r.Header.Set("Accept", "text/html")
			rec := httptest.NewRecorder()

			if p, ok := a.RequireAuth(rec, r); ok || !isZeroPrincipal(p) {
				t.Fatalf("RequireAuth = (%+v, ok=%v), want the zero Principal and false", p, ok)
			}
			if rec.Code != tt.status {
				t.Errorf("status = %d, want %d", rec.Code, tt.status)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
			}
			if want := map[string]string{"error": tt.errValue, "code": tt.code}; !maps.Equal(body, want) {
				t.Errorf("body = %v, want %v", body, want)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			wantBearer := ""
			if tt.bearer {
				wantBearer = "Bearer"
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != wantBearer {
				t.Errorf("WWW-Authenticate = %q, want %q", got, wantBearer)
			}
			if got := rec.Header().Get("Retry-After"); got != tt.retryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tt.retryAfter)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("Location = %q, want none (no browser redirect)", loc)
			}
		})
	}
}

// TestRequireAuth_UnauthorizedHook_ReceivesError confirms that a
// Config.Unauthorized hook owns the whole unauthorized response and receives
// the error Authenticate returned.
func TestRequireAuth_UnauthorizedHook_ReceivesError(t *testing.T) {
	t.Parallel()
	wantErr := fmt.Errorf("%w: %w", ErrAuthBackend, errors.New("db down"))
	var got []error
	a := mustAuthenticator(t, newFakeSessionStore(), Config{
		Verifier: errVerifier{err: wantErr},
		Unauthorized: func(w http.ResponseWriter, _ *http.Request, err error) {
			got = append(got, err)
			w.WriteHeader(http.StatusTeapot)
		},
	})

	rec := httptest.NewRecorder()
	if _, ok := a.RequireAuth(rec, httptest.NewRequest(http.MethodGet, "/private", nil)); ok {
		t.Fatal("RequireAuth ok = true, want false")
	}
	if len(got) != 1 || !errors.Is(got[0], ErrAuthBackend) {
		t.Fatalf("hook received %v, want one error matching ErrAuthBackend", got)
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d (hook-owned response)", rec.Code, http.StatusTeapot)
	}
	if h := rec.Header().Get("Retry-After"); h != "" {
		t.Errorf("Retry-After = %q, want none (the default response must not run)", h)
	}
}

// TestRequireAuth_UnauthorizedHook_NotCalledWhenAuthenticated confirms the
// hook is an unauthorized-path concern only.
func TestRequireAuth_UnauthorizedHook_NotCalledWhenAuthenticated(t *testing.T) {
	t.Parallel()
	called := 0
	a := mustAuthenticator(t, newFakeSessionStore(), Config{
		Bypass:       func() bool { return true },
		Unauthorized: func(http.ResponseWriter, *http.Request, error) { called++ },
	})

	rec := httptest.NewRecorder()
	p, ok := a.RequireAuth(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !ok || p.User == nil {
		t.Fatal("RequireAuth under bypass should authenticate")
	}
	if called != 0 {
		t.Fatalf("hook called %d times on the authenticated path, want 0", called)
	}
}
