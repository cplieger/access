package access

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

const testShare = 1 << 20

// fullBudget returns a budget of n shares with every share held.
func fullBudget(t *testing.T, n int64) *HashBudget {
	t.Helper()
	b := mustBudget(t, n*testShare)
	for range n {
		if err := b.acquire(t.Context(), testShare, time.Hour); err != nil {
			t.Fatalf("acquire of a free share: %v", err)
		}
	}
	return b
}

// acquireAsync starts an acquire of cost and returns the channel its result
// arrives on.
func acquireAsync(ctx context.Context, b *HashBudget, cost int64) <-chan error {
	done := make(chan error, 1)
	go func() { done <- b.acquire(ctx, cost, time.Hour) }()
	return done
}

// pending reports whether no result has arrived on done, a channel from
// acquireAsync, yet; it leaves an arrived result to be read.
func pending(done <-chan error) bool { return len(done) == 0 }

func TestHashBudgetAdmission(t *testing.T) {
	t.Parallel()
	t.Run("the wait running out is a bare ErrHashBusy", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			b := fullBudget(t, 4)
			const wait = 10 * time.Millisecond
			start := time.Now()
			err := b.acquire(t.Context(), testShare, wait)
			if elapsed := time.Since(start); elapsed < wait {
				t.Errorf("refused after %v, want no sooner than its %v wait", elapsed, wait)
			}
			if !errors.Is(err, ErrHashBusy) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("err = %v, want ErrHashBusy with no context error", err)
			}
		})
	})
	t.Run("one released share admits exactly one waiter", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			b := fullBudget(t, 4)
			first, second := acquireAsync(t.Context(), b, testShare), acquireAsync(t.Context(), b, testShare)
			synctest.Wait()
			if !pending(first) || !pending(second) {
				t.Fatal("a waiter returned while the budget was full")
			}
			b.release(testShare)
			synctest.Wait()
			admitted, waiting := first, second
			if pending(first) {
				admitted, waiting = second, first
			}
			if err := <-admitted; err != nil {
				t.Fatalf("admitted waiter err = %v, want nil", err)
			}
			if !pending(waiting) {
				t.Fatal("one released share admitted both waiters")
			}
			b.release(testShare)
			if err := <-waiting; err != nil {
				t.Errorf("second waiter after a second release: err = %v, want nil", err)
			}
		})
	})
	t.Run("a cost equal to the capacity admits alone", func(t *testing.T) {
		t.Parallel()
		b := mustBudget(t, 4*testShare)
		if err := b.acquire(t.Context(), b.Capacity(), time.Millisecond); err != nil {
			t.Fatalf("acquire of the whole free capacity: %v", err)
		}
		if err := b.acquire(t.Context(), 1, time.Millisecond); !errors.Is(err, ErrHashBusy) {
			t.Errorf("acquire beside a whole-capacity holder: err = %v, want ErrHashBusy", err)
		}
		b.release(b.Capacity())
		if err := b.acquire(t.Context(), 1, time.Millisecond); err != nil {
			t.Errorf("acquire after the whole capacity was released: %v", err)
		}
	})
}

func TestHashBudgetCancelledContext(t *testing.T) {
	t.Parallel()
	b := mustBudget(t, testShare)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := b.acquire(ctx, testShare, time.Hour); !errors.Is(err, ErrHashBusy) || !errors.Is(err, context.Canceled) {
		t.Errorf("acquire on a cancelled context with the budget free: err = %v, want ErrHashBusy wrapping context.Canceled", err)
	}
	if err := b.acquire(t.Context(), testShare, time.Millisecond); err != nil {
		t.Errorf("acquire of the whole capacity after a refused acquire: %v, want nil (the refusal took nothing)", err)
	}
}

// TestHashBudgetCopyShares pins that a copied HashBudget or HashPermit shares
// the original's state, so no copy admits work past the memory bound.
func TestHashBudgetCopyShares(t *testing.T) {
	t.Parallel()
	t.Run("budget", func(t *testing.T) {
		t.Parallel()
		b := mustBudget(t, testShare)
		cp := *b
		if err := cp.acquire(t.Context(), testShare, time.Hour); err != nil {
			t.Fatalf("acquire through the copy: %v", err)
		}
		if err := b.acquire(t.Context(), testShare, time.Millisecond); !errors.Is(err, ErrHashBusy) {
			t.Errorf("original acquire while the copy holds the capacity: err = %v, want ErrHashBusy", err)
		}
		cp.release(testShare)
	})
	t.Run("permit", func(t *testing.T) {
		t.Parallel()
		h := mustHasher(t, HasherConfig{Budget: mustBudget(t, defaultCost), Wait: busyWait})
		hash := mustHash(t, h, "pw")
		p, err := h.Reserve(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		cp := *p
		if ok, _, err := p.Verify("pw", hash); err != nil || !ok {
			t.Fatalf("Verify = (%v, %v), want (true, nil)", ok, err)
		}
		cp.Release()
		held, err := h.Reserve(t.Context())
		if err != nil {
			t.Fatalf("Reserve after Verify returned the share: %v", err)
		}
		defer held.Release()
		if _, err := h.Reserve(t.Context()); !errors.Is(err, ErrHashBusy) {
			t.Errorf("second Reserve of a one-share budget: err = %v, want ErrHashBusy (the copy's Release freed a share)", err)
		}
	})
}

// TestHashBudgetFIFO pins that waiters are admitted in arrival order, so a
// grow for the whole capacity is not starved by later one-share requests.
func TestHashBudgetFIFO(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		b := fullBudget(t, 4)
		grow := acquireAsync(t.Context(), b, b.Capacity())
		synctest.Wait()
		small := acquireAsync(t.Context(), b, testShare)
		synctest.Wait()
		b.release(testShare)
		synctest.Wait()
		if !pending(small) {
			t.Fatal("a one-share waiter queued after the grow was admitted first")
		}
		for range 3 {
			b.release(testShare)
		}
		synctest.Wait()
		if pending(grow) {
			t.Fatal("the grow waiter was not admitted once the whole capacity was free")
		}
		if err := <-grow; err != nil {
			t.Fatalf("grow waiter err = %v, want nil", err)
		}
		if !pending(small) {
			t.Fatal("the one-share waiter was admitted beside a whole-capacity holder")
		}
		b.release(b.Capacity())
		if err := <-small; err != nil {
			t.Errorf("one-share waiter after the grow released: err = %v, want nil", err)
		}
	})
}

func TestHashBudgetFreeAdmitsAtOnce(t *testing.T) {
	t.Parallel()
	t.Run("a free budget admits under a wait already spent", func(t *testing.T) {
		t.Parallel()
		b := mustBudget(t, testShare)
		if err := b.acquire(t.Context(), testShare, 0); err != nil {
			t.Errorf("acquire of a free share with no wait = %v, want admission", err)
		}
	})
	t.Run("an ended context is refused on a free budget", func(t *testing.T) {
		t.Parallel()
		b := mustBudget(t, testShare)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := b.acquire(ctx, testShare, time.Hour); !errors.Is(err, ErrHashBusy) || !errors.Is(err, context.Canceled) {
			t.Errorf("acquire with an ended context = %v, want ErrHashBusy wrapping context.Canceled", err)
		}
		if err := b.acquire(t.Context(), testShare, 0); err != nil {
			t.Errorf("acquire after the refusal = %v, want the share still free", err)
		}
	})
	t.Run("a full budget with no wait is a bare ErrHashBusy", func(t *testing.T) {
		t.Parallel()
		b := fullBudget(t, 1)
		if err := b.acquire(t.Context(), testShare, 0); !errors.Is(err, ErrHashBusy) || errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("acquire of a held share with no wait = %v, want ErrHashBusy with no context error", err)
		}
	})
}
