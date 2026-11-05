package account_test

import (
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access/account"
)

func TestShutdownEveryOperation(t *testing.T) {
	t.Parallel()
	closed := func(t *testing.T, w *opWorld, name string, run func() error) {
		t.Helper()
		w.fs.resetRecord()
		start := time.Now()
		err := run()
		if d := time.Since(start); d > 10*time.Millisecond {
			t.Errorf("%s after Shutdown took %s, want at most 10ms", name, d)
		}
		if !errors.Is(err, account.ErrServiceClosed) {
			t.Errorf("%s after Shutdown = %v, want ErrServiceClosed", name, err)
		}
		if calls := w.fs.recorded(); len(calls) != 0 {
			t.Errorf("%s after Shutdown made %d store calls, first %s", name, len(calls), calls[0].name)
		}
	}
	for _, op := range operations() {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			w := newOpWorld(t, worldOptions{empty: op.empty})
			call := op.prep(t, w, w.actorFor(t, op.class))
			if err := w.svc.Shutdown(t.Context()); err != nil {
				t.Fatalf("Shutdown = %v", err)
			}
			mark := len(w.events.all())
			closed(t, w, op.name, func() error { return call.run(t.Context()) })
			if n := len(w.events.all()) - mark; n != 0 {
				t.Errorf("%s after Shutdown emitted %d events", op.name, n)
			}
		})
	}
	t.Run("guards", func(t *testing.T) {
		t.Parallel()
		w := newOpWorld(t, worldOptions{scoped: true})
		p := w.recent(t, w.root)
		if err := w.svc.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown = %v", err)
		}
		closed(t, w, "RequireRecentAuth", func() error { return w.svc.RequireRecentAuth(p) })
		closed(t, w, "RequireAdminScope", func() error { return w.svc.RequireAdminScope(p) })
		closed(t, w, "RequireKeyPermission", func() error { return w.svc.RequireKeyPermission(p, scopeUsers) })
	})
}
