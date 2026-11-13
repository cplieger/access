package accesshttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// pausingStore holds the first SessionByHash of hash after it has read,
// until release is closed, and closes read then.
type pausingStore struct {
	account.Store
	read, release chan struct{}
	once          sync.Once
	hash          access.Hash
}

func (s *pausingStore) SessionByHash(ctx context.Context, h access.Hash) (*access.Session, bool, error) {
	sess, found, err := s.Store.SessionByHash(ctx, h)
	if h.Equal(s.hash) {
		s.once.Do(func() {
			close(s.read)
			<-s.release
		})
	}
	return sess, found, err
}

// deleteSession deletes cookie's session through the store, as an app's
// own write outside account would.
func (e *env) deleteSession(t testing.TB, cookie *http.Cookie) {
	t.Helper()
	if err := e.mem.DeleteSessionByHash(t.Context(), access.SessionHash(cookie.Value)); err != nil {
		t.Fatalf("DeleteSessionByHash: %v", err)
	}
}

// requireNoSession checks that no session is stored under cookie's token.
func (e *env) requireNoSession(t testing.TB, cookie *http.Cookie) {
	t.Helper()
	if _, found, err := e.mem.SessionByHash(t.Context(), access.SessionHash(cookie.Value)); err != nil || found {
		t.Errorf("SessionByHash after the delete = found %v, %v; want the row gone", found, err)
	}
}

// TestDirectSessionDeleteHTTP is §9.5 "Direct session delete" through
// accesshttp: a session deleted through the store outside account answers
// auth_session_expired on its next request, a request whose verification
// read the session before the delete writes no row back, and a passkey
// step-up or OIDC link begun on it cannot finish.
func TestDirectSessionDeleteHTTP(t *testing.T) {
	t.Run("next_request", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		e.createUser(t, "alice", access.RoleUser)
		cookie := e.sessionCookie(t, "alice")
		e.deleteSession(t, cookie)
		rt := e.route(t, "authSessions")
		e.requireRefused(t, do(rt, request(rt, "", cookie)), access.CodeSessionExpired)
	})
	t.Run("paused_verification", func(t *testing.T) {
		paused := &pausingStore{read: make(chan struct{}), release: make(chan struct{})}
		e := newEnv(t, envOptions{store: func(m *accesstest.MemStore) account.Store { paused.Store = m; return paused }})
		e.createUser(t, "alice", access.RoleUser)
		cookie := e.sessionCookie(t, "alice")
		paused.hash = access.SessionHash(cookie.Value)
		rt := e.route(t, "authSessions")
		done := make(chan *httptest.ResponseRecorder)
		go func() { done <- do(rt, request(rt, "", cookie)) }()
		<-paused.read
		e.deleteSession(t, cookie)
		close(paused.release)
		<-done
		e.requireNoSession(t, cookie)
		sessions, err := e.mem.SessionsByUserID(t.Context(), e.user(t, "alice").ID)
		if err != nil || len(sessions) != 0 {
			t.Errorf("alice's sessions = %d, %v; want none", len(sessions), err)
		}
	})
	t.Run("passkey_step_up", func(t *testing.T) {
		e := newEnv(t, passkeys)
		e.createUser(t, "alice", access.RoleUser)
		dev := e.enrol(t, "alice")
		cookie := e.sessionCookie(t, "alice")
		r := e.stepUpFinish(t, cookie, dev, nil, func() { e.deleteSession(t, cookie) })
		w := do(e.route(t, "authStepUpPasskeyFinish"), r)
		e.requireRefused(t, w, access.CodeSessionExpired)
		if c := cookieNamed(w, e.jarNames(testOrigin).session); c != nil {
			t.Errorf("Set-Cookie %q on a deleted session's step-up", c.Raw)
		}
		e.requireNoSession(t, cookie)
	})
	t.Run("oidc_link", func(t *testing.T) {
		e := newEnv(t, envOptions{})
		idp := e.useIdP(t, accesstest.IdPOptions{}, nil)
		b := e.signedInBrowser(t, "alice")
		cookie := e.jarSession(t, b)
		w := e.sessionFlow(t, b, idp, "authOIDCStartLink", "/settings", func() { e.deleteSession(t, cookie) })
		if loc := location(t, w); loc != "/settings?auth_error=auth_session_expired" {
			t.Errorf("link landed on %q, want /settings?auth_error=auth_session_expired", loc)
		}
		if u := e.user(t, "alice"); u.OIDC != (access.OIDCIdentity{}) {
			t.Errorf("alice linked to %+v on a deleted session", u.OIDC)
		}
		if c := cookieNamed(w, e.jarNames(testOrigin).session); c != nil && c.MaxAge >= 0 {
			t.Errorf("Set-Cookie %q on a deleted session's link", c.Raw)
		}
		e.requireNoSession(t, cookie)
	})
}
