package access

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestConfigZeroValueDefaults(t *testing.T) {
	t.Parallel()
	t.Run("timeouts", func(t *testing.T) {
		t.Parallel()
		a := mustAuthenticator(t, newFakeSessionStore(), Config{})
		if got, want := a.Timeouts(), (SessionTimeouts{Idle: time.Hour, Absolute: 24 * time.Hour}); got != want {
			t.Errorf("Timeouts() = %+v, want %+v", got, want)
		}
	})
	t.Run("each zero timeout defaults alone", func(t *testing.T) {
		t.Parallel()
		idle := mustAuthenticator(t, newFakeSessionStore(), Config{IdleTimeout: 5 * time.Hour})
		if got, want := idle.Timeouts(), (SessionTimeouts{Idle: 5 * time.Hour, Absolute: DefaultAbsTimeout}); got != want {
			t.Errorf("Timeouts() with only IdleTimeout = %+v, want %+v", got, want)
		}
		abs := mustAuthenticator(t, newFakeSessionStore(), Config{AbsTimeout: 72 * time.Hour})
		if got, want := abs.Timeouts(), (SessionTimeouts{Idle: DefaultIdleTimeout, Absolute: 72 * time.Hour}); got != want {
			t.Errorf("Timeouts() with only AbsTimeout = %+v, want %+v", got, want)
		}
	})
	t.Run("activity written on every request", func(t *testing.T) {
		t.Parallel()
		f := newChainFixture(t)
		a := mustAuthenticator(t, f.store, Config{})
		for range 3 {
			mustAuthenticate(t, a, withSession(bearerRequest(""), f.session))
		}
		if n := f.store.activities.Load(); n != 3 {
			t.Errorf("activity writes = %d, want 3 (one per request)", n)
		}
	})
	t.Run("default client resolver", func(t *testing.T) {
		t.Parallel()
		a := mustAuthenticator(t, newFakeSessionStore(), Config{})
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.5:4711"
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		peer := netip.MustParseAddr("10.0.0.5")
		if got, want := a.ClientAddr(r), (ClientAddr{IP: peer, Peer: peer, UntrustedForwarding: true}); got != want {
			t.Errorf("ClientAddr = %+v, want %+v", got, want)
		}
	})
	t.Run("default session cookie", func(t *testing.T) {
		t.Parallel()
		a := mustAuthenticator(t, newFakeSessionStore(), Config{})
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		got, want := httptest.NewRecorder(), httptest.NewRecorder()
		cookie, def := a.Cookie(), DefaultCookieConfig()
		cookie.SetCookie(got, r, "token", 60)
		def.SetCookie(want, r, "token", 60)
		if g, w := got.Header().Values("Set-Cookie"), want.Header().Values("Set-Cookie"); len(g) != 1 || len(w) != 1 || g[0] != w[0] {
			t.Errorf("Cookie() sets %q, want the default session cookie's %q", g, w)
		}
	})
	t.Run("default logger", func(t *testing.T) {
		t.Parallel()
		a := mustAuthenticator(t, newFakeSessionStore(), Config{})
		if a.cfg.log() != slog.Default() {
			t.Error("log() is not slog.Default() with a nil Logger")
		}
	})
	t.Run("hasher", func(t *testing.T) {
		t.Parallel()
		h, err := NewHasher(HasherConfig{})
		if err != nil {
			t.Fatalf("NewHasher(HasherConfig{}) error = %v", err)
		}
		stored, err := parsePHC(mustHash(t, h, "pw").Reveal())
		if err != nil || stored.params != DefaultArgon2Params() {
			t.Errorf("hash parameters = (%+v, %v), want DefaultArgon2Params()", stored.params, err)
		}
		if h.wait != 2*time.Second {
			t.Errorf("budget wait = %s, want 2s", h.wait)
		}
		permits := reserveN(t, h, 4)
		defer releaseAll(permits)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()
		if _, err := h.Reserve(ctx); !errors.Is(err, ErrHashBusy) {
			t.Errorf("fifth Reserve on the default budget: err = %v, want ErrHashBusy", err)
		}
	})
}

func TestZeroConfigGrantsSession(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "noopt_user", PasswordHash: NewHash("dummy"), Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash := GenerateSessionToken()
	now := time.Now()
	if err := db.CreateSession(ctx, &Session{
		ID: "s", TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		LastIP: "127.0.0.1", CreatedAt: now.Add(-30 * time.Minute), LastActivity: now.Add(-10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, Config{})
	r, _ := http.NewRequest(http.MethodGet, "/api/data", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: plaintext.Reveal()})

	p, gotErr := a.Authenticate(r)
	if gotErr != nil {
		t.Fatalf("Authenticate error: %v", gotErr)
	}
	if p.User.ID != user.ID {
		t.Errorf("user ID = %d, want %d", p.User.ID, user.ID)
	}
	if !p.SessionTokenHash().Equal(hash) {
		t.Errorf("hash = %q, want %q", p.SessionTokenHash().Reveal(), hash.Reveal())
	}
}
