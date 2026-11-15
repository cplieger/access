package discovery

import (
	"testing"
	"time"
)

// docs/oidc.md "The key cache": a miss under a set replaced since the verify
// began re-verifies against the new set before it joins a refetch in flight
// or consults the gate. The window between the cached verify and the miss has
// no blocking point a black-box test could hold.
func TestAfterMiss_ReplacedSetFirst(t *testing.T) {
	t.Parallel()
	for name, pending := range map[string]chan struct{}{"refetch in flight": make(chan struct{}), "gate open": nil} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
			k := &KeySet{now: func() time.Time { return now }, pending: pending}
			seen, newer := &snapshot{fetched: now}, &snapshot{fetched: now}
			k.cur.Store(newer)
			got, wait := k.afterMiss(t.Context(), seen)
			if got != newer || wait != nil {
				t.Errorf("afterMiss = %p, %v; want the newer set %p and no refetch", got, wait, newer)
			}
			if !k.attempted.IsZero() {
				t.Errorf("the gate was consulted: attempted = %v", k.attempted)
			}
		})
	}
}
