package access

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAuthenticate_bypass(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()

	t.Run("active hook grants synthetic admin", func(t *testing.T) {
		t.Parallel()
		on := mustAuthenticator(t, db, Config{Bypass: func() bool { return true }})
		p, err := on.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
		if err != nil {
			t.Fatalf("Authenticate(bypass enabled) error = %v, want nil", err)
		}
		if p.User == nil || p.User.Role != RoleAdmin || p.User.ID != 0 || p.Method != MethodBypass {
			t.Errorf("Authenticate(bypass enabled) = %+v, want MethodBypass with a synthetic admin of ID 0", p)
		}
		if p.IsSession() || p.IsRecoverySession() {
			t.Error("bypass principal passes IsSession or IsRecoverySession, want neither")
		}
		if _, err := on.Recheck(t.Context(), p); !errors.Is(err, ErrNotRecheckable) {
			t.Errorf("Recheck(bypass principal) error = %v, want ErrNotRecheckable", err)
		}
	})
	t.Run("inactive hook does not authenticate", func(t *testing.T) {
		t.Parallel()
		off := mustAuthenticator(t, db, Config{Bypass: func() bool { return false }})
		if _, err := off.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate(bypass disabled, no credentials) error = %v, want ErrUnauthenticated", err)
		}
	})
	t.Run("each granted request gets its own principal", func(t *testing.T) {
		t.Parallel()
		on := mustAuthenticator(t, db, Config{Bypass: func() bool { return true }})
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		firstP, err := on.Authenticate(r)
		if err != nil {
			t.Fatalf("Authenticate(first) error = %v, want nil", err)
		}
		secondP, err := on.Authenticate(r)
		if err != nil {
			t.Fatalf("Authenticate(second) error = %v, want nil", err)
		}
		first, second := firstP.User, secondP.User
		if first == second {
			t.Fatal("Authenticate returned the same *User pointer twice; the granted principal is shared mutable state")
		}
		first.Role = RoleUser
		first.Username = "mutated"
		thirdP, err := on.Authenticate(r)
		if err != nil {
			t.Fatalf("Authenticate(third) error = %v, want nil", err)
		}
		if third := thirdP.User; third.Role != RoleAdmin || third.Username != string(RoleAdmin) {
			t.Errorf("after a caller mutated its own user, Authenticate() = {Role:%q Username:%q}, want {Role:%q Username:%q}",
				third.Role, third.Username, RoleAdmin, string(RoleAdmin))
		}
	})
}

// TestBypassWarnsOnEachEdge pins the bypass logging: one Info line when the
// hook is installed, and one WARN per off-to-on edge of its answer, however
// many requests race across the edge.
func TestBypassWarnsOnEachEdge(t *testing.T) {
	t.Parallel()
	var (
		on  atomic.Bool
		log strings.Builder
		mu  sync.Mutex
	)
	a := mustAuthenticator(t, newFakeSessionStore(), Config{
		Bypass: on.Load,
		Logger: slog.New(slog.NewTextHandler(lockedWriter{w: &log, mu: &mu}, nil)),
	})
	text := func() string {
		mu.Lock()
		defer mu.Unlock()
		return log.String()
	}
	warns := func() int { return strings.Count(text(), "authentication bypass is active") }
	if got := text(); !strings.Contains(got, "bypass hook installed") || !strings.Contains(got, "level=INFO") || strings.Contains(got, "level=WARN") {
		t.Errorf("construction log = %q, want the Info install line and no WARN", got)
	}
	request := func() error {
		_, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
		return err
	}
	burst := func() {
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				if err := request(); err != nil {
					t.Errorf("Authenticate(bypass on) error = %v", err)
				}
			})
		}
		wg.Wait()
	}

	if err := request(); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate(bypass off) error = %v, want ErrUnauthenticated", err)
	}
	if n := warns(); n != 0 {
		t.Fatalf("WARNs while off = %d, want 0", n)
	}
	for edge := 1; edge <= 3; edge++ {
		on.Store(true)
		burst()
		burst()
		if n := warns(); n != edge {
			t.Fatalf("WARNs after %d off-to-on edges = %d, want %d", edge, n, edge)
		}
		on.Store(false)
		if err := request(); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("Authenticate(bypass off) error = %v, want ErrUnauthenticated", err)
		}
	}

	var none strings.Builder
	mustAuthenticator(t, newFakeSessionStore(), Config{Logger: slog.New(slog.NewTextHandler(&none, nil))})
	if got := none.String(); strings.Contains(got, "bypass") {
		t.Errorf("Authenticator without Config.Bypass mentioned bypass in logs; log = %q", got)
	}
}

// lockedWriter serialises writes to w, which concurrent requests log to.
type lockedWriter struct {
	w  *strings.Builder
	mu *sync.Mutex
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
