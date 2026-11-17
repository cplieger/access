package account_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access/account"
)

// nameWaits counts every wait on a name's lock, by canonical name, so a test
// knows a verifier has reached the lock before it lets the holder go.
type nameWaits struct {
	n  map[string]int
	mu sync.Mutex
}

func newNameWaits() *nameWaits { return &nameWaits{n: make(map[string]int)} }

func (w *nameWaits) hooks() account.Hooks {
	return account.Hooks{NameLockWait: func(_ context.Context, canonical string) {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.n[canonical]++
	}}
}

func (w *nameWaits) count(name string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n[name]
}

// wait waits until name's lock has been waited on n times in all.
func (w *nameWaits) wait(t *testing.T, name string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for w.count(name) < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := w.count(name); got != n {
		t.Fatalf("%s's lock waited on %d times, want %d", name, got, n)
	}
}

// requireQueued fails if done answers within a moment: whatever sends on it
// should still be waiting on a name's lock another verifier holds.
func requireQueued(t *testing.T, done <-chan error, what string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("%s answered %v while another verifier held its name's lock", what, err)
	case <-time.After(100 * time.Millisecond):
	}
}

// requireNameFree fails unless name's lock can be taken now: no verifier
// holds it or waits on it, so the lock set keeps no entry for it.
func requireNameFree(t *testing.T, svc *account.Service, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	unlock, err := account.LockName(ctx, svc, name)
	if err != nil {
		t.Fatalf("%s's lock = %v, want it free", name, err)
	}
	unlock()
}

// TestNameLock: the Service's name lock holds one verifier per canonical
// username, and a context already done never takes a name. Go's select picks at random among ready cases
// (https://go.dev/ref/spec#Select_statements), so a done context on a free
// name readies both arms of a bare wait.
func TestNameLock(t *testing.T) {
	t.Parallel()
	t.Run("one_holder_per_canonical_name", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		unlock, err := account.LockName(t.Context(), f.svc, "alice")
		if err != nil {
			t.Fatalf("alice's lock = %v", err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		if second, err := account.LockName(ctx, f.svc, "ALICE"); !errors.Is(err, context.DeadlineExceeded) {
			if second != nil {
				second()
			}
			t.Errorf("ALICE's lock while alice's is held = %v, want context.DeadlineExceeded", err)
		}
		requireNameFree(t, f.svc, "bob")
		unlock()
		requireNameFree(t, f.svc, "Alice")
	})
	t.Run("done_context_on_a_free_name", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		for i := range 100 {
			if unlock, err := account.LockName(ctx, f.svc, "alice"); unlock != nil || !errors.Is(err, context.Canceled) {
				if unlock != nil {
					unlock()
				}
				t.Fatalf("lock %d on a done context = (%t, %v), want (false, context.Canceled)", i, unlock != nil, err)
			}
		}
		requireNameFree(t, f.svc, "alice")
	})
	t.Run("unknown_name_leaves_it_free", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		mustOwner(t, f.mem, "root")
		for _, name := range []string{"nobody", "Nobody2", "ghost"} {
			if _, err := f.step1(t.Context(), localClient, name, wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
				t.Errorf("step 1 for %s = %v, want ErrInvalidCredentials", name, err)
			}
			requireNameFree(t, f.svc, name)
		}
	})
}
