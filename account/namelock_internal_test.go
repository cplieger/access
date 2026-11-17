package account

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access/ratelimit"
)

// TestNameLocks checks the lock: one holder per name, waiters that
// hold nothing else, a wait that ends with its context, and an entry that
// leaves the set when its last holder or waiter does, as go/keylock's.
func TestNameLocks(t *testing.T) {
	t.Parallel()
	alice, bob := ratelimit.AccountKey("alice"), ratelimit.AccountKey("bob")
	t.Run("one_holder_per_name", func(t *testing.T) {
		t.Parallel()
		l := newNameLocks()
		unlock, err := l.lock(t.Context(), alice)
		if err != nil {
			t.Fatalf("lock = %v", err)
		}
		got := make(chan struct{})
		go func() {
			second, err := l.lock(context.Background(), alice)
			if err == nil {
				second()
			}
			close(got)
		}()
		select {
		case <-got:
			t.Fatal("a second lock of the name returned while the first was held")
		case <-time.After(50 * time.Millisecond):
		}
		other, err := l.lock(t.Context(), bob)
		if err != nil {
			t.Fatalf("another name's lock = %v, want it free while alice is held", err)
		}
		other()
		unlock()
		select {
		case <-got:
		case <-time.After(10 * time.Second):
			t.Fatal("the waiter did not get the lock after the holder released it")
		}
		if n := l.held(); n != 0 {
			t.Errorf("held = %d after every holder released, want 0", n)
		}
	})
	t.Run("cancelled_wait", func(t *testing.T) {
		t.Parallel()
		l := newNameLocks()
		unlock, err := l.lock(t.Context(), alice)
		if err != nil {
			t.Fatalf("lock = %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			_, err := l.lock(ctx, alice)
			done <- err
		}()
		deadline := time.Now().Add(10 * time.Second)
		for l.refs(alice) != 2 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if n := l.refs(alice); n != 2 {
			t.Fatalf("refs = %d, want the holder and the waiter", n)
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("a cancelled wait = %v, want context.Canceled", err)
		}
		if n := l.refs(alice); n != 1 {
			t.Errorf("refs = %d after the waiter left, want the holder's 1", n)
		}
		unlock()
		if n := l.held(); n != 0 {
			t.Errorf("held = %d, want 0", n)
		}
	})
	// After 10,000 distinct names are posted and settled, the lock set
	// is empty.
	t.Run("distinct_names_leave_nothing", func(t *testing.T) {
		t.Parallel()
		l := newNameLocks()
		var wg sync.WaitGroup
		for i := range 10000 {
			wg.Go(func() {
				unlock, err := l.lock(context.Background(), ratelimit.AccountKey("user"+strconv.Itoa(i)))
				if err != nil {
					t.Errorf("lock %d = %v", i, err)
					return
				}
				unlock()
			})
		}
		wg.Wait()
		if n := l.held(); n != 0 {
			t.Errorf("held = %d after 10,000 names settled, want 0", n)
		}
	})
}
