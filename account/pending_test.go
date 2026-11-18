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

// mustPut is c.Put, failing t on a refusal.
func mustPut(t testing.TB, c account.PendingCache, purpose account.PendingPurpose, u access.User, now time.Time) string {
	t.Helper()
	id, err := c.Put(purpose, u, now)
	if err != nil {
		t.Fatalf("Put(%d, user %d) = %v", purpose, u.ID, err)
	}
	return id
}

func TestPendingCache(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	user := func(id int64) access.User { return access.User{ID: id} }
	t.Run("ids", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		a, b := mustPut(t, c, account.PurposeLogin, user(1), t0), mustPut(t, c, account.PurposeLogin, user(2), t0)
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
		id := mustPut(t, c, account.PurposeStepUp, user(7), t0)
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
		id := mustPut(t, c, account.PurposeAddPasskey, user(1), t0)
		if _, ok := c.Take(id, account.PurposeStepUp, t0); ok {
			t.Error("Take of another purpose succeeded")
		}
		if _, ok := c.Take(id, account.PurposeAddPasskey, t0); ok {
			t.Error("the entry survived a mismatched Take")
		}
	})
	t.Run("expiry_at_take", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		early := mustPut(t, c, account.PurposeLogin, user(1), t0)
		late := mustPut(t, c, account.PurposeLogin, user(2), t0)
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
		mustPut(t, c, account.PurposeLogin, user(1), t0)
		mustPut(t, c, account.PurposeLogin, user(2), t0.Add(time.Minute))
		mustPut(t, c, account.PurposeLogin, user(3), t0.Add(webauthn.CeremonyTimeout))
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
			ids[i] = mustPut(t, c, account.PurposeLogin, user(int64(i)), t0.Add(time.Duration(i)*time.Second))
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
		c := account.PendingOf(f.svc)
		for i := range 4 {
			mustPut(t, c, account.PurposeLogin, user(int64(i)), time.Now())
		}
		if n := c.Len(); n != 2 {
			t.Errorf("a Service with MaxPending 2 holds %d entries", n)
		}
		d := account.PendingOf(newFixture(t, options{}).svc)
		for i := range 10001 {
			mustPut(t, d, account.PurposeLogin, user(int64(i)), t0)
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
			ids[i] = mustPut(t, c, account.PurposeLogin, access.User{ID: int64(i)}, t0)
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
					id, _ := c.Put(account.PurposeLogin, access.User{ID: int64(g*1000 + i)}, t0)
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

// TestPendingCacheLists checks the per-purpose cache: each list has
// its own lifetime and cap, a pending sign-in replaces its user's earlier
// one, and a user's sign-in drops through the index.
func TestPendingCacheLists(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	user := func(id int64) access.User { return access.User{ID: id} }
	t.Run("ceremonies_never_evict_a_sign_in", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(2)
		signIn := mustPut(t, c, account.PurposeSignIn, user(1), t0)
		for i := range 5 {
			mustPut(t, c, account.PurposeLogin, user(0), t0.Add(time.Duration(i)*time.Second))
		}
		if _, ok := c.Take(signIn, account.PurposeSignIn, t0.Add(time.Minute)); !ok {
			t.Error("a flood of ceremonies evicted a pending sign-in")
		}
	})
	t.Run("lifetimes", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		ceremony := mustPut(t, c, account.PurposeLogin, user(0), t0)
		late := mustPut(t, c, account.PurposeSignIn, user(1), t0)
		early := mustPut(t, c, account.PurposeSignIn, user(2), t0)
		if _, ok := c.Take(ceremony, account.PurposeLogin, t0.Add(webauthn.CeremonyTimeout)); ok {
			t.Error("a ceremony outlived CeremonyTimeout")
		}
		if _, ok := c.Take(early, account.PurposeSignIn, t0.Add(10*time.Minute-time.Nanosecond)); !ok {
			t.Error("a pending sign-in died before its ten minutes")
		}
		if _, ok := c.Take(late, account.PurposeSignIn, t0.Add(10*time.Minute)); ok {
			t.Error("a pending sign-in outlived its ten minutes")
		}
	})
	t.Run("one_sign_in_per_user", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		old := mustPut(t, c, account.PurposeSignIn, user(1), t0)
		other := mustPut(t, c, account.PurposeSignIn, user(2), t0)
		fresh := mustPut(t, c, account.PurposeSignIn, user(1), t0)
		if _, ok := c.Take(old, account.PurposeSignIn, t0); ok {
			t.Error("a user's earlier pending sign-in survived a new one")
		}
		for name, id := range map[string]string{"fresh": fresh, "other user's": other} {
			if _, ok := c.Take(id, account.PurposeSignIn, t0); !ok {
				t.Errorf("the %s pending sign-in is gone", name)
			}
		}
	})
	t.Run("drop_user", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		mine := mustPut(t, c, account.PurposeSignIn, user(1), t0)
		ceremony := mustPut(t, c, account.PurposeStepUp, user(1), t0)
		theirs := mustPut(t, c, account.PurposeSignIn, user(2), t0)
		c.DropUser(1)
		if _, ok := c.Take(mine, account.PurposeSignIn, t0); ok {
			t.Error("DropUser left the user's pending sign-in")
		}
		if _, ok := c.Take(theirs, account.PurposeSignIn, t0); !ok {
			t.Error("DropUser dropped another user's pending sign-in")
		}
		if _, ok := c.Take(ceremony, account.PurposeStepUp, t0); !ok {
			t.Error("DropUser dropped a ceremony")
		}
		if n := c.Len(); n != 0 {
			t.Errorf("entries after the takes = %d, want 0", n)
		}
	})
}
