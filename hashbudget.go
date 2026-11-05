package access

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/semaphore"
)

// ErrHashBusy reports that a hash budget could not admit a derivation within
// the wait. When the caller's context ended first, the error also wraps the
// context's error.
var ErrHashBusy = errors.New("access: hash budget busy")

// errBudgetWait is the cause acquire gives its own wait timer, which tells the
// wait running out from the caller's context ending.
var errBudgetWait = errors.New("access: hash budget wait elapsed")

// HashBudget bounds the memory all Argon2 work sharing it may hold at once.
// Build one with [NewHashBudget] and share it through HasherConfig.Budget:
// one budget per process bounds every [Hasher] in it together. The zero
// value is not usable. Its state is held by pointer, so a copied HashBudget
// shares it. Waiters are admitted first in, first out.
type HashBudget struct {
	sem      *semaphore.Weighted
	capacity int64
}

// NewHashBudget returns a budget of bytes. It validates only the capacity,
// which must be positive; [NewHasher] checks that its parameters fit.
func NewHashBudget(bytes int64) (*HashBudget, error) {
	if bytes <= 0 {
		return nil, fmt.Errorf("access: hash budget must be positive, got %d bytes", bytes)
	}
	return &HashBudget{sem: semaphore.NewWeighted(bytes), capacity: bytes}, nil
}

// Capacity returns the budget's size in bytes.
func (b *HashBudget) Capacity() int64 { return b.capacity }

// HashCost returns what one derivation at p is charged against a budget, in
// bytes: max(Memory, 8 × Parallelism) KiB, an upper bound on the block matrix
// x/crypto/argon2 allocates (Memory rounded down to a multiple of
// 4 × Parallelism KiB, at least 8 KiB per lane). The derived key and the
// worker goroutines' stacks are not charged.
func HashCost(p Argon2Params) int64 {
	return int64(max(p.Memory, 8*uint32(p.Parallelism))) * 1024
}

// acquire takes cost bytes, all or nothing, waiting up to wait or until ctx
// ends.
func (b *HashBudget) acquire(ctx context.Context, cost int64, wait time.Duration) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrHashBusy, err)
	}
	// TryAcquire first keeps a free budget from being refused when a short wait expires, as Acquire
	// checks ctx.Done() first: https://github.com/golang/sync/blob/v0.24.0/semaphore/semaphore.go#L48-L56
	if b.sem.TryAcquire(cost) {
		return nil
	}
	ctx, cancel := context.WithTimeoutCause(ctx, wait, errBudgetWait)
	defer cancel()
	if err := b.sem.Acquire(ctx, cost); err != nil {
		if errors.Is(context.Cause(ctx), errBudgetWait) {
			return ErrHashBusy
		}
		return fmt.Errorf("%w: %w", ErrHashBusy, err)
	}
	return nil
}

// release returns cost bytes that acquire took.
func (b *HashBudget) release(cost int64) { b.sem.Release(cost) }
