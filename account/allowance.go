package account

import "sync/atomic"

// allowanceUsedBits is the low part of allowance.state, which holds the
// slots taken; the high part is the generation.
const allowanceUsedBits = 32

// allowance is the process-wide bound on untrusted counted password attempts
// between two failure-record prunes: MaxUntrustedCounts slots, refilled by
// reset after each prune commits. It holds no count of a name, only how many
// attempts were admitted.
type allowance struct {
	// wake gets one value when the last slot is taken; the sweep goroutine
	// runs the failure leg on it. One buffered value coalesces every wake
	// until the leg runs.
	wake chan struct{}
	// state is generation<<allowanceUsedBits | slots taken, in one word so a
	// return under an old generation can never touch the new interval.
	state atomic.Uint64
}

func newAllowance() *allowance {
	return &allowance{wake: make(chan struct{}, 1)}
}

// take takes one slot and returns the generation it was taken under, or
// false when none is left. Taking the last slot wakes the prune.
func (a *allowance) take() (gen uint64, ok bool) {
	for {
		old := a.state.Load()
		used := old & (1<<allowanceUsedBits - 1)
		if used >= MaxUntrustedCounts {
			return 0, false
		}
		if a.state.CompareAndSwap(old, old+1) {
			if used+1 == MaxUntrustedCounts {
				select {
				case a.wake <- struct{}{}:
				default:
				}
			}
			return old >> allowanceUsedBits, true
		}
	}
}

// give returns a slot taken under gen; after a reset it does nothing, since
// the prune already refilled every slot of that interval.
func (a *allowance) give(gen uint64) {
	for {
		old := a.state.Load()
		if old>>allowanceUsedBits != gen {
			return
		}
		if a.state.CompareAndSwap(old, old-1) {
			return
		}
	}
}

// reset refills every slot and starts a new generation.
func (a *allowance) reset() {
	for {
		old := a.state.Load()
		if a.state.CompareAndSwap(old, (old>>allowanceUsedBits+1)<<allowanceUsedBits) {
			return
		}
	}
}
