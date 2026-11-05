package access

import (
	"runtime"
	"runtime/metrics"
	"sync"
	"testing"
	"time"
)

func BenchmarkHasherHash(b *testing.B) {
	h := mustHasher(b, HasherConfig{})
	b.ReportAllocs()
	for b.Loop() {
		_, _ = h.Hash(b.Context(), "benchmark-password-123!")
	}
}

func BenchmarkHasherVerify(b *testing.B) {
	h := mustHasher(b, HasherConfig{})
	hash := mustHash(b, h, "benchmark-password-123!")
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = h.Verify(b.Context(), "benchmark-password-123!", hash)
	}
}

// BenchmarkHashBurst reports the peak heap-object bytes
// (/memory/classes/heap/objects:bytes, which counts unswept garbage too) above
// a no-hash baseline during 64 concurrent Hash calls on a budget of four
// default hashes. It is reported, not gated: each derivation's memory is
// garbage the moment it returns, so the peak depends on when the collector
// runs.
func BenchmarkHashBurst(b *testing.B) {
	h := mustHasher(b, HasherConfig{Budget: mustBudget(b, 4*defaultCost)})
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	var peak uint64
	for b.Loop() {
		runtime.GC()
		metrics.Read(sample)
		base := sample[0].Value.Uint64()
		stop, top := make(chan struct{}), make(chan uint64)
		go func() {
			s := []metrics.Sample{{Name: sample[0].Name}}
			var high uint64
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					top <- high
					return
				case <-tick.C:
					metrics.Read(s)
					high = max(high, s[0].Value.Uint64())
				}
			}
		}()
		var wg sync.WaitGroup
		for range 64 {
			wg.Go(func() { _, _ = h.Hash(b.Context(), "benchmark-password-123!") })
		}
		wg.Wait()
		close(stop)
		if high := <-top; high > base {
			peak = max(peak, high-base)
		}
	}
	b.ReportMetric(float64(peak), "peak-heap-bytes")
}
