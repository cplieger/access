package account_test

import (
	"encoding/hex"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
)

func TestPendingCache(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	user := func(id int64) access.User { return access.User{ID: id} }
	t.Run("ids", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		a, b := c.Put(account.PurposeLogin, user(1), t0), c.Put(account.PurposeLogin, user(2), t0)
		for _, id := range []string{a, b} {
			if raw, err := hex.DecodeString(id); err != nil || len(raw) != 32 {
				t.Errorf("ID %q is not 256 bits of hex", id)
			}
		}
		if a == b {
			t.Error("two entries share an ID")
		}
	})
	t.Run("single_use", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		id := c.Put(account.PurposeStepUp, user(7), t0)
		if u, ok := c.Take(id, account.PurposeStepUp, t0); !ok || u.ID != 7 {
			t.Fatalf("Take = %v, %t, want user 7", u, ok)
		}
		if _, ok := c.Take(id, account.PurposeStepUp, t0); ok {
			t.Error("a second Take of one ID succeeded")
		}
		if _, ok := c.Take("unknown", account.PurposeStepUp, t0); ok {
			t.Error("Take of an unknown ID succeeded")
		}
	})
	t.Run("purpose_mismatch", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		id := c.Put(account.PurposeRegister, user(1), t0)
		if _, ok := c.Take(id, account.PurposeRecovery, t0); ok {
			t.Error("Take of another purpose succeeded")
		}
		if _, ok := c.Take(id, account.PurposeRegister, t0); ok {
			t.Error("the entry survived a mismatched Take")
		}
	})
	t.Run("expiry_at_take", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		early := c.Put(account.PurposeLogin, user(1), t0)
		late := c.Put(account.PurposeLogin, user(2), t0)
		if _, ok := c.Take(early, account.PurposeLogin, t0.Add(webauthn.CeremonyTimeout-time.Nanosecond)); !ok {
			t.Error("Take just before the ceremony timeout failed")
		}
		if _, ok := c.Take(late, account.PurposeLogin, t0.Add(webauthn.CeremonyTimeout)); ok {
			t.Error("Take at the ceremony timeout succeeded")
		}
	})
	t.Run("expiry_at_insert", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		c.Put(account.PurposeLogin, user(1), t0)
		c.Put(account.PurposeLogin, user(2), t0.Add(time.Minute))
		c.Put(account.PurposeLogin, user(3), t0.Add(webauthn.CeremonyTimeout))
		if n := c.Len(); n != 2 {
			t.Errorf("entries after a put at the first one's expiry = %d, want 2", n)
		}
		c.Prune(t0.Add(webauthn.CeremonyTimeout + time.Minute))
		if n := c.Len(); n != 1 {
			t.Errorf("entries after a prune = %d, want 1", n)
		}
	})
	t.Run("evicts_oldest_at_max", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(3)
		ids := make([]string, 5)
		for i := range ids {
			ids[i] = c.Put(account.PurposeLogin, user(int64(i)), t0.Add(time.Duration(i)*time.Second))
			if n := c.Len(); n > 3 {
				t.Fatalf("entries = %d, above the bound 3", n)
			}
		}
		for i, id := range ids {
			_, ok := c.Take(id, account.PurposeLogin, t0.Add(5*time.Second))
			if want := i >= 2; ok != want {
				t.Errorf("entry %d present = %t, want %t: the oldest go first", i, ok, want)
			}
		}
	})
	t.Run("service_bound", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{edit: func(c *account.Config) { c.MaxPending = 2 }})
		c := account.Pending(f.svc)
		for i := range 4 {
			c.Put(account.PurposeSetup, user(int64(i)), time.Now())
		}
		if n := c.Len(); n != 2 {
			t.Errorf("a Service with MaxPending 2 holds %d entries", n)
		}
		d := account.Pending(newFixture(t, options{}).svc)
		for i := range 10001 {
			d.Put(account.PurposeSetup, user(int64(i)), t0)
		}
		if n := d.Len(); n != 10000 {
			t.Errorf("the default MaxPending holds %d entries, want 10000", n)
		}
	})
}

func TestPendingCacheConcurrent(t *testing.T) {
	t.Parallel()
	t0 := time.Now()
	t.Run("no_double_take", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(1000)
		ids := make([]string, 200)
		for i := range ids {
			ids[i] = c.Put(account.PurposeLogin, access.User{ID: int64(i)}, t0)
		}
		var taken [200]atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for i, id := range ids {
					if _, ok := c.Take(id, account.PurposeLogin, t0); ok {
						taken[i].Add(1)
					}
				}
			})
		}
		wg.Wait()
		for i := range taken {
			if n := taken[i].Load(); n != 1 {
				t.Errorf("entry %d taken %d times, want once", i, n)
			}
		}
	})
	t.Run("flood_keeps_bound", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(100)
		var wg sync.WaitGroup
		var over atomic.Bool
		for g := range 16 {
			wg.Go(func() {
				for i := range 500 {
					id := c.Put(account.PurposeLogin, access.User{ID: int64(g*1000 + i)}, t0)
					if c.Len() > 100 {
						over.Store(true)
					}
					if i%3 == 0 {
						c.Take(id, account.PurposeLogin, t0)
					}
				}
			})
		}
		wg.Wait()
		if over.Load() || c.Len() > 100 {
			t.Errorf("the cache exceeded its bound of 100 under a flood (now %d)", c.Len())
		}
	})
}
