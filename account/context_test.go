package account_test

import (
	"context"
	"maps"
	"slices"
	"sync"
	"testing"
)

// ctxValue is the key of the value every store call must carry.
type ctxValue struct{}

func TestContextPassthroughEveryOperation(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	seen := map[string]bool{}
	t.Run("operations", func(t *testing.T) {
		for _, op := range operations() {
			t.Run(op.name, func(t *testing.T) {
				t.Parallel()
				w := newOpWorld(t, worldOptions{empty: op.empty})
				call := op.prep(t, w, w.actorFor(t, op.class))
				w.fs.resetRecord()
				ctx := context.WithValue(t.Context(), ctxValue{}, op.name)
				if err := call.run(ctx); err != nil {
					t.Fatalf("%s = %v", op.name, err)
				}
				calls := w.fs.recorded()
				for _, c := range calls {
					if c.ctx.Value(ctxValue{}) != op.name {
						t.Errorf("%s made store call %s (Update %d) without the caller's context value", op.name, c.name, c.update)
					}
				}
				for _, c := range w.fs.committed() {
					if c.ctx.Value(ctxValue{}) != op.name {
						t.Errorf("%s committed an Update without the caller's context value", op.name)
					}
				}
				mu.Lock()
				defer mu.Unlock()
				for _, c := range calls {
					seen[c.name] = true
					if c.update > 0 && c.name != "Update" {
						seen["Tx"] = true
					}
				}
			})
		}
	})
	for _, name := range []string{"Update", "Tx", "PutAuthFailure", "CreateSession", "RotateSession"} {
		if !seen[name] {
			t.Errorf("no operation made a %s call, so the passthrough of its context is unproven; seen %v", name, slices.Sorted(maps.Keys(seen)))
		}
	}
}
