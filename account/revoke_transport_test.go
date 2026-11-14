package account_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// revokedEntries is every session_revoked entry s holds.
func revokedEntries(t *testing.T, s account.Store) []account.LogEntry {
	t.Helper()
	var out []account.LogEntry
	for _, e := range logOf(t, s) {
		if e.Event.Kind == account.EventSessionRevoked {
			out = append(out, e)
		}
	}
	return out
}

// plainSession stores a plain full session of u and returns it with its
// token.
func (f *fixture) plainSession(t *testing.T, u *access.User) (*access.Session, access.Secret) {
	t.Helper()
	now := time.Now()
	token, hash := access.GenerateSessionToken()
	sess := &access.Session{
		ID: newSessionID(t), UserID: u.ID, TokenHash: hash, AuthMethod: access.MethodPassword,
		CreatedAt: now, LastActivity: now, AuthTime: now,
	}
	if err := f.mem.CreateSession(t.Context(), sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return sess, token
}

// TestRevokeTransportMismatch pins the Service's revoke: one Update deletes
// the session and journals its session_revoked with the transport_changed
// detail; a session already gone is nil with no event.
func TestRevokeTransportMismatch(t *testing.T) {
	t.Parallel()
	if account.LogDetailTransportChanged != "transport_changed" {
		t.Fatalf("LogDetailTransportChanged = %q, want transport_changed", account.LogDetailTransportChanged)
	}
	check := func(t *testing.T, f *fixture, sess *access.Session) {
		t.Helper()
		if _, found, _ := f.mem.SessionByHash(t.Context(), sess.TokenHash); found {
			t.Error("the session is still stored, want it deleted")
		}
		got := revokedEntries(t, f.mem)
		if len(got) != 1 {
			t.Fatalf("session_revoked entries = %d, want 1", len(got))
		}
		e := got[0]
		if e.Detail != "transport_changed" {
			t.Errorf("Detail = %q, want transport_changed", e.Detail)
		}
		if e.Event.UserID != sess.UserID || !slices.Equal(e.Event.SessionIDs, []string{sess.ID}) || e.Event.Actor != (account.EventActor{}) {
			t.Errorf("event = %+v, want user %d, session [%s], no actor", e.Event, sess.UserID, sess.ID)
		}
	}
	t.Run("deletes_and_journals", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		sess, _ := f.plainSession(t, u)
		if err := f.svc.RevokeTransportMismatch(t.Context(), access.SessionRef{ID: sess.ID, UserID: u.ID}); err != nil {
			t.Fatalf("RevokeTransportMismatch = %v", err)
		}
		check(t, f, sess)
	})
	t.Run("already_gone", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		if err := f.svc.RevokeTransportMismatch(t.Context(), access.SessionRef{ID: "gone", UserID: u.ID}); err != nil {
			t.Errorf("RevokeTransportMismatch(gone) = %v, want nil", err)
		}
		if got := revokedEntries(t, f.mem); len(got) != 0 {
			t.Errorf("session_revoked entries = %v, want none", got)
		}
	})
	t.Run("concurrent_one_event", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		sess, _ := f.plainSession(t, u)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range errs {
			wg.Go(func() {
				errs[i] = f.svc.RevokeTransportMismatch(t.Context(), access.SessionRef{ID: sess.ID, UserID: u.ID})
			})
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			t.Errorf("RevokeTransportMismatch = %v, want nil twice", err)
		}
		check(t, f, sess)
	})
	t.Run("through_authenticate", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{posture: access.PosturePerRequest})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		sess, token := f.plainSession(t, u)
		if _, err := f.authenticate(t.Context(), token); !errors.Is(err, access.ErrSessionTransport) {
			t.Fatalf("Authenticate(plain session over https) = %v, want ErrSessionTransport", err)
		}
		check(t, f, sess)
	})
	t.Run("closed", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		sess, _ := f.plainSession(t, u)
		if err := f.svc.Shutdown(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := f.svc.RevokeTransportMismatch(t.Context(), access.SessionRef{ID: sess.ID, UserID: u.ID}); !errors.Is(err, account.ErrServiceClosed) {
			t.Errorf("RevokeTransportMismatch after Shutdown = %v, want ErrServiceClosed", err)
		}
	})
}

// TestNewRegistersRevoker pins that New registers its Service as the
// Authenticator's revoker, so a second Service over one Authenticator is
// refused.
func TestNewRegistersRevoker(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	svc, err := account.New(t.Context(), f.cfg)
	if err == nil {
		_ = svc.Shutdown(t.Context())
		t.Fatal("a second New over the same Authenticator = nil, want an error")
	}
	if svc != nil {
		t.Errorf("New() = %v, want nil with the error", svc)
	}
	// A fresh Authenticator takes a Service, which then revokes its
	// mismatches.
	authn, err := access.New(f.mem, access.Config{Cookie: access.CookieConfig{Posture: access.PosturePerRequest}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.cfg
	cfg.Authenticator = authn
	other, err := account.New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("New over a fresh Authenticator = %v", err)
	}
	t.Cleanup(func() { _ = other.Shutdown(context.Background()) })
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	sess, token := f.plainSession(t, u)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", http.NoBody)
	cookie := authn.Cookie()
	req.AddCookie(&http.Cookie{Name: cookie.CookieName(true), Value: token.Reveal()})
	if _, err := authn.Authenticate(req); !errors.Is(err, access.ErrSessionTransport) {
		t.Fatalf("Authenticate = %v, want ErrSessionTransport", err)
	}
	if _, found, _ := f.mem.SessionByHash(t.Context(), sess.TokenHash); found {
		t.Error("the session survived, want the second Service to have revoked it")
	}
}
