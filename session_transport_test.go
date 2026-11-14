package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access/internal/capture"
	"github.com/cplieger/access/internal/failreason"
)

const mismatchWarnMsg = "access: a session presented on the other transport was refused but not revoked"

// fakeRevoker records every revoke and answers err.
type fakeRevoker struct {
	err   error
	got   func(ctx context.Context)
	refs  []SessionRef
	mu    sync.Mutex
	calls int
}

func (r *fakeRevoker) RevokeTransportMismatch(ctx context.Context, ref SessionRef) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.refs = append(r.refs, ref)
	if r.got != nil {
		r.got(ctx)
	}
	return r.err
}

func (r *fakeRevoker) revoked() []SessionRef {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]SessionRef(nil), r.refs...)
}

// transportRequest is a request over target carrying token under the
// session cookie name cfg gives transport secure.
func transportRequest(ctx context.Context, cfg CookieConfig, target string, secure bool, token string) *http.Request {
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	r.AddCookie(&http.Cookie{Name: cfg.CookieName(secure), Value: token})
	return r
}

// TestTransportBinding pins that a session is honoured only on the
// transport it was created on: the one cookie the request's transport
// names is read, and a session bound to the other transport is refused
// with ErrSessionTransport, revoked, and writes no activity.
func TestTransportBinding(t *testing.T) {
	t.Parallel()
	perRequest := CookieConfig{Posture: PosturePerRequest}
	secureCfg := CookieConfig{Posture: PostureSecure}
	for _, tc := range []struct {
		name       string
		cookie     CookieConfig
		target     string
		nameSecure bool // the transport whose cookie name carries the token
		session    bool // the session's Secure
		refused    bool
	}{
		{name: "secure_session_plain_name_plain_request", cookie: perRequest, target: "http://app.example/", session: true, refused: true},
		{name: "plain_session_host_name_secure_request", cookie: perRequest, target: "https://app.example/", nameSecure: true, refused: true},
		{name: "plain_session_secure_posture_secure_request", cookie: secureCfg, target: "https://app.example/", nameSecure: true, refused: true},
		{name: "plain_session_plain_request", cookie: perRequest, target: "http://app.example/"},
		{name: "secure_session_secure_request", cookie: perRequest, target: "https://app.example/", nameSecure: true, session: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &Session{ID: "s", CreatedAt: sessionT0, LastActivity: sessionT0.Add(-time.Hour / 2), Secure: tc.session}
			a, store, _, token := clockedSession(t, s, Config{Cookie: tc.cookie})
			rev := &fakeRevoker{}
			if err := a.UseSessionRevoker(rev); err != nil {
				t.Fatalf("UseSessionRevoker = %v", err)
			}
			p, err := a.Authenticate(transportRequest(t.Context(), tc.cookie, tc.target, tc.nameSecure, token))
			if !tc.refused {
				if err != nil || p.SessionID != "s" {
					t.Fatalf("Authenticate = (%q, %v), want the session", p.SessionID, err)
				}
				if got := rev.revoked(); len(got) != 0 {
					t.Errorf("revoked %v, want none", got)
				}
				return
			}
			if !errors.Is(err, ErrSessionTransport) || !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("Authenticate error = %v, want ErrSessionTransport as an invalid credential", err)
			}
			if got := failreason.Of(err); got != failreason.TransportChanged {
				t.Errorf("failreason = %q, want %q", got, failreason.TransportChanged)
			}
			if got, want := rev.revoked(), (SessionRef{ID: "s", UserID: s.UserID}); len(got) != 1 || got[0] != want {
				t.Errorf("revoked %v, want [%v]", got, want)
			}
			if n := store.activities.Load(); n != 0 {
				t.Errorf("activity writes = %d, want 0", n)
			}
		})
	}
	t.Run("plain_cookie_on_secure_request_unread", func(t *testing.T) {
		t.Parallel()
		s := &Session{ID: "s", CreatedAt: sessionT0, LastActivity: sessionT0}
		a, store, _, token := clockedSession(t, s, Config{Cookie: perRequest})
		rev := &fakeRevoker{}
		if err := a.UseSessionRevoker(rev); err != nil {
			t.Fatalf("UseSessionRevoker = %v", err)
		}
		_, err := a.Authenticate(transportRequest(t.Context(), perRequest, "https://app.example/", false, token))
		if !errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrInvalidCredential) {
			t.Errorf("Authenticate error = %v, want bare ErrUnauthenticated", err)
		}
		if got := rev.revoked(); len(got) != 0 {
			t.Errorf("revoked %v, want none", got)
		}
		if _, found, _ := store.SessionByHash(t.Context(), SessionHash(token)); !found {
			t.Error("the plain session is gone, want it kept")
		}
		if _, err := a.Authenticate(transportRequest(t.Context(), perRequest, "http://app.example/", false, token)); err != nil {
			t.Errorf("Authenticate(plain request) = %v, want the session", err)
		}
	})
}

// TestUseSessionRevoker pins its two refusals: a nil revoker and a second
// registration.
func TestUseSessionRevoker(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), Config{})
	if err := a.UseSessionRevoker(nil); err == nil {
		t.Error("UseSessionRevoker(nil) = nil, want an error")
	}
	var typedNil *fakeRevoker
	if err := a.UseSessionRevoker(typedNil); err == nil {
		t.Error("UseSessionRevoker(typed nil) = nil, want an error")
	}
	if err := a.UseSessionRevoker(&fakeRevoker{}); err != nil {
		t.Fatalf("first UseSessionRevoker = %v", err)
	}
	if err := a.UseSessionRevoker(&fakeRevoker{}); err == nil {
		t.Error("second UseSessionRevoker = nil, want an error")
	}
}

// mismatchFixture is a plain session presented on a secure request under
// PosturePerRequest's __Host- name, on a test clock, logging to h.
func mismatchFixture(t *testing.T) (a *Authenticator, clock *testClock, h *capture.Recorder, refuse func(ctx context.Context)) {
	t.Helper()
	logger, h := capture.New()
	cfg := CookieConfig{Posture: PosturePerRequest}
	a, _, clock, token := clockedSession(t, &Session{ID: "s", CreatedAt: sessionT0, LastActivity: sessionT0}, Config{Cookie: cfg, Logger: logger})
	refuse = func(ctx context.Context) {
		t.Helper()
		if _, err := a.Authenticate(transportRequest(ctx, cfg, "https://app.example/", true, token)); !errors.Is(err, ErrSessionTransport) {
			t.Fatalf("Authenticate error = %v, want ErrSessionTransport", err)
		}
	}
	return a, clock, h, refuse
}

// TestMismatchWithoutRevoker pins that with no revoker the refusal stands
// and one WARN per interval says so.
func TestMismatchWithoutRevoker(t *testing.T) {
	t.Parallel()
	_, clock, h, refuse := mismatchFixture(t)
	refuse(t.Context())
	clock.Set(sessionT0.Add(30 * time.Second))
	refuse(t.Context())
	if got := warnAttrs(h, mismatchWarnMsg); len(got) != 1 || got[0]["session_id"].String() != "s" {
		t.Fatalf("mismatch WARNs = %v, want one naming session s", got)
	}
	clock.Set(sessionT0.Add(61 * time.Second))
	refuse(t.Context())
	got := warnAttrs(h, mismatchWarnMsg)
	if len(got) != 2 || got[1]["suppressed"].Int64() != 1 {
		t.Errorf("mismatch WARNs = %v, want a second with suppressed 1", got)
	}
	for _, r := range h.Records(mismatchWarnMsg) {
		if r.Level.String() != "WARN" {
			t.Errorf("mismatch record at %v, want WARN", r.Level)
		}
	}
}

// TestRevokeContext pins the revoke's context: detached from the request's
// cancellation and bounded by revokeTimeout.
func TestRevokeContext(t *testing.T) {
	t.Parallel()
	a, _, _, refuse := mismatchFixture(t)
	var (
		ctxErr error
		left   time.Duration
		has    bool
	)
	rev := &fakeRevoker{got: func(ctx context.Context) {
		ctxErr = ctx.Err()
		var deadline time.Time
		deadline, has = ctx.Deadline()
		left = time.Until(deadline)
	}}
	if err := a.UseSessionRevoker(rev); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	refuse(ctx)
	if rev.calls != 1 {
		t.Fatalf("revoke calls = %d, want 1", rev.calls)
	}
	if ctxErr != nil {
		t.Errorf("revoke context error = %v, want a live context", ctxErr)
	}
	if !has || left <= 0 || left > revokeTimeout {
		t.Errorf("revoke deadline = (%v away, set %v), want set and at most %v away", left, has, revokeTimeout)
	}
}

// TestRevokeFailureLogged pins that a failed revoke is logged with its
// error and the refusal stands.
func TestRevokeFailureLogged(t *testing.T) {
	t.Parallel()
	a, _, h, refuse := mismatchFixture(t)
	if err := a.UseSessionRevoker(&fakeRevoker{err: errors.New("store down")}); err != nil {
		t.Fatal(err)
	}
	refuse(t.Context())
	got := warnAttrs(h, mismatchWarnMsg)
	if len(got) != 1 || got[0]["error"].String() != "store down" || got[0]["session_id"].String() != "s" {
		t.Errorf("mismatch WARNs = %v, want one with the revoke's error", got)
	}
}
