package access

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type deriveCounter struct {
	calls     []Argon2Params
	mu        sync.Mutex
	inflight  int
	inflightK int64
	peak      int
	peakK     int64
}

func (c *deriveCounter) install(h *Hasher) {
	next := h.derive
	h.derive = func(pw, salt []byte, iterations, memory uint32, threads uint8, keyLen uint32) []byte {
		kib := HashCost(Argon2Params{Memory: memory, Parallelism: threads}) / 1024
		c.mu.Lock()
		c.calls = append(c.calls, Argon2Params{
			Memory: memory, Iterations: iterations, Parallelism: threads,
			SaltLength: uint32(len(salt)), KeyLength: keyLen,
		})
		c.inflight++
		c.inflightK += kib
		c.peak = max(c.peak, c.inflight)
		c.peakK = max(c.peakK, c.inflightK)
		c.mu.Unlock()
		defer func() {
			c.mu.Lock()
			c.inflight--
			c.inflightK -= kib
			c.mu.Unlock()
		}()
		return next(pw, salt, iterations, memory, threads, keyLen)
	}
}

func (c *deriveCounter) snapshot() (calls []Argon2Params, peak int, peakKiB int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Argon2Params(nil), c.calls...), c.peak, c.peakK
}

func mustHasher(t testing.TB, cfg HasherConfig) *Hasher {
	t.Helper()
	h, err := NewHasher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mustBudget(t testing.TB, bytes int64) *HashBudget {
	t.Helper()
	b, err := NewHashBudget(bytes)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustHash(t testing.TB, h *Hasher, password string) Hash {
	t.Helper()
	hash, err := h.Hash(t.Context(), password)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func reserveN(t *testing.T, h *Hasher, n int) []*HashPermit {
	t.Helper()
	permits := make([]*HashPermit, 0, n)
	for i := range n {
		p, err := h.Reserve(t.Context())
		if err != nil {
			t.Fatalf("Reserve %d of %d: %v", i+1, n, err)
		}
		permits = append(permits, p)
	}
	return permits
}

func releaseAll(permits []*HashPermit) {
	for _, p := range permits {
		p.Release()
	}
}

var defaultCost = HashCost(DefaultArgon2Params())

// busyWait is the Wait of a hasher a test both fills and refuses. A shorter
// one can run out before Acquire is called under -race on a loaded host,
// and Acquire refuses a done context even with capacity free:
// https://github.com/golang/sync/blob/v0.24.0/semaphore/semaphore.go#L48-L56
const busyWait = 250 * time.Millisecond

func TestHashCost(t *testing.T) {
	t.Parallel()
	if got, want := defaultCost, int64(19456*1024); got != want {
		t.Errorf("HashCost(default) = %d, want %d", got, want)
	}
	if got, want := HashCost(Argon2Params{Memory: 8, Parallelism: 4}), int64(32*1024); got != want {
		t.Errorf("HashCost(m=8, p=4) = %d, want %d (8 KiB per lane)", got, want)
	}
}

func TestHasherRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		params Argon2Params
	}{
		{"default params", DefaultArgon2Params()},
		{"lowest memory", Argon2Params{Memory: 7168, Iterations: 6, Parallelism: 1, SaltLength: 16, KeyLength: 32}},
		{"two lanes and long salt and key", Argon2Params{Memory: 19456, Iterations: 2, Parallelism: 2, SaltLength: 64, KeyLength: 64}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := mustHasher(t, HasherConfig{Params: tc.params})
			hash := mustHash(t, h, "correct horse battery staple")
			ok, needsRehash, err := h.Verify(t.Context(), "correct horse battery staple", hash)
			if err != nil || !ok || needsRehash {
				t.Errorf("Verify(right password) = (%v, %v, %v), want (true, false, nil)", ok, needsRehash, err)
			}
			ok, _, err = h.Verify(t.Context(), "correct horse battery stapler", hash)
			if err != nil || ok {
				t.Errorf("Verify(wrong password) = (%v, _, %v), want (false, _, nil)", ok, err)
			}
		})
	}
}

func TestHasherNFC(t *testing.T) {
	t.Parallel()
	const (
		decomposed  = "caf\u0065\u0301 au lait"
		precomposed = "caf\u00e9 au lait"
	)
	h := mustHasher(t, HasherConfig{})
	for _, tc := range []struct{ name, hashed, verified string }{
		{"decomposed at Hash, precomposed at Verify", decomposed, precomposed},
		{"precomposed at Hash, decomposed at Verify", precomposed, decomposed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, _, err := h.Verify(t.Context(), tc.verified, mustHash(t, h, tc.hashed))
			if err != nil || !ok {
				t.Errorf("Verify = (%v, %v), want (true, nil)", ok, err)
			}
		})
	}
}

func TestHasherNeedsRehash(t *testing.T) {
	t.Parallel()
	base := DefaultArgon2Params()
	h := mustHasher(t, HasherConfig{})
	hash := mustHash(t, h, "pw")
	if h.NeedsRehash(hash) {
		t.Error("NeedsRehash(own hash) = true, want false")
	}
	for _, tc := range []struct {
		name   string
		change func(*Argon2Params)
	}{
		{"memory", func(p *Argon2Params) { p.Memory = 38912 }},
		{"iterations", func(p *Argon2Params) { p.Iterations = 3 }},
		{"parallelism", func(p *Argon2Params) { p.Parallelism = 2 }},
		{"salt length", func(p *Argon2Params) { p.SaltLength = 32 }},
		{"key length", func(p *Argon2Params) { p.KeyLength = 64 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			params := base
			tc.change(&params)
			other := mustHasher(t, HasherConfig{Params: params})
			if !other.NeedsRehash(hash) {
				t.Errorf("NeedsRehash under a different %s = false, want true", tc.name)
			}
			ok, needsRehash, err := other.Verify(t.Context(), "pw", hash)
			if err != nil || !ok || !needsRehash {
				t.Errorf("Verify under a different %s = (%v, %v, %v), want (true, true, nil)", tc.name, ok, needsRehash, err)
			}
		})
	}
	t.Run("unparseable", func(t *testing.T) {
		t.Parallel()
		for _, s := range []string{"", "not-a-hash", "$argon2id$v=19$m=1024,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"} {
			if !h.NeedsRehash(NewHash(s)) {
				t.Errorf("NeedsRehash(%q) = false, want true", s)
			}
		}
	})
}

func TestNewHasher(t *testing.T) {
	t.Parallel()
	t.Run("default budget holds four derivations", func(t *testing.T) {
		t.Parallel()
		h := mustHasher(t, HasherConfig{Wait: busyWait})
		permits := reserveN(t, h, 4)
		defer releaseAll(permits)
		if _, err := h.Reserve(t.Context()); !errors.Is(err, ErrHashBusy) {
			t.Errorf("fifth Reserve on the default budget: err = %v, want ErrHashBusy", err)
		}
	})
	t.Run("budget one byte below the cost", func(t *testing.T) {
		t.Parallel()
		_, err := NewHasher(HasherConfig{Budget: mustBudget(t, defaultCost-1)})
		if !errors.Is(err, ErrHashBudgetTooSmall) {
			t.Errorf("err = %v, want ErrHashBudgetTooSmall", err)
		}
	})
	t.Run("budget of exactly the cost runs one at a time", func(t *testing.T) {
		t.Parallel()
		h := mustHasher(t, HasherConfig{Budget: mustBudget(t, defaultCost), Wait: busyWait})
		permits := reserveN(t, h, 1)
		if _, err := h.Reserve(t.Context()); !errors.Is(err, ErrHashBusy) {
			t.Errorf("second Reserve: err = %v, want ErrHashBusy", err)
		}
		releaseAll(permits)
		releaseAll(reserveN(t, h, 1))
		hash, err := h.Hash(t.Context(), "correct horse")
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		if ok, needsRehash, err := h.Verify(t.Context(), "correct horse", hash); !ok || needsRehash || err != nil {
			t.Errorf("Verify of its own hash = (%v, %v, %v), want (true, false, nil)", ok, needsRehash, err)
		}
	})
	t.Run("76 MiB budget admits the default hasher four at a time", func(t *testing.T) {
		t.Parallel()
		h := mustHasher(t, HasherConfig{Budget: mustBudget(t, 76<<20), Wait: busyWait})
		permits := reserveN(t, h, 4)
		defer releaseAll(permits)
		if _, err := h.Reserve(t.Context()); !errors.Is(err, ErrHashBusy) {
			t.Errorf("fifth Reserve: err = %v, want ErrHashBusy", err)
		}
	})
	t.Run("m=65536 p=4 fits a 256 MiB budget", func(t *testing.T) {
		t.Parallel()
		params := Argon2Params{Memory: 65536, Iterations: 1, Parallelism: 4, SaltLength: 16, KeyLength: 32}
		h := mustHasher(t, HasherConfig{Params: params, Budget: mustBudget(t, 256<<20), Wait: busyWait})
		permits := reserveN(t, h, 4)
		defer releaseAll(permits)
		if _, err := h.Reserve(t.Context()); !errors.Is(err, ErrHashBusy) {
			t.Errorf("fifth Reserve: err = %v, want ErrHashBusy", err)
		}
	})
	t.Run("zero and negative budgets", func(t *testing.T) {
		t.Parallel()
		for _, n := range []int64{0, -1} {
			if b, err := NewHashBudget(n); err == nil || b != nil {
				t.Errorf("NewHashBudget(%d) = (%v, %v), want (nil, error)", n, b, err)
			}
		}
	})
	t.Run("negative wait", func(t *testing.T) {
		t.Parallel()
		if _, err := NewHasher(HasherConfig{Wait: -time.Nanosecond}); err == nil {
			t.Error("NewHasher(Wait: -1ns) succeeded, want an error")
		}
	})
	t.Run("invalid params", func(t *testing.T) {
		t.Parallel()
		if _, err := NewHasher(HasherConfig{Params: Argon2Params{Memory: 1024, Iterations: 38, Parallelism: 1, SaltLength: 16, KeyLength: 32}}); err == nil {
			t.Error("NewHasher(m=1024) succeeded, want an error")
		}
	})
}

func TestHasherCancelledContext(t *testing.T) {
	t.Parallel()
	h := mustHasher(t, HasherConfig{})
	var c deriveCounter
	c.install(h)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := h.Hash(ctx, "pw"); !errors.Is(err, ErrHashBusy) || !errors.Is(err, context.Canceled) {
		t.Errorf("Hash(cancelled) err = %v, want ErrHashBusy wrapping context.Canceled", err)
	}
	if _, _, err := h.Verify(ctx, "pw", Hash{}); !errors.Is(err, ErrHashBusy) || !errors.Is(err, context.Canceled) {
		t.Errorf("Verify(cancelled) err = %v, want ErrHashBusy wrapping context.Canceled", err)
	}
	if calls, _, _ := c.snapshot(); len(calls) != 0 {
		t.Errorf("a cancelled context derived %d times, want 0", len(calls))
	}
}

func TestHasherBurstNeverExceedsCapacity(t *testing.T) {
	t.Parallel()
	budget := mustBudget(t, 4*defaultCost)
	h := mustHasher(t, HasherConfig{Budget: budget})
	var c deriveCounter
	c.install(h)

	hashes := make([]Hash, 64)
	errs := make([]error, 64)
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() { hashes[i], errs[i] = h.Hash(t.Context(), "burst password") })
	}
	wg.Wait()

	_, peak, _ := c.snapshot()
	if limit := int(budget.Capacity() / defaultCost); peak > limit {
		t.Errorf("peak derivations in flight = %d, want at most %d", peak, limit)
	}
	var hashed, busy int
	for i, err := range errs {
		switch {
		case errors.Is(err, ErrHashBusy):
			busy++
		case err != nil:
			t.Errorf("Hash %d: unexpected error %v", i, err)
		default:
			if ok, _, verr := h.Verify(t.Context(), "burst password", hashes[i]); verr != nil || !ok {
				t.Errorf("Hash %d does not verify: (%v, %v)", i, ok, verr)
			}
			hashed++
		}
	}
	if hashed+busy != 64 {
		t.Errorf("hashed %d + busy %d = %d, want 64", hashed, busy, hashed+busy)
	}
}

func TestSharedBudgetAcrossHashers(t *testing.T) {
	t.Parallel()
	costly := Argon2Params{Memory: 38912, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	budget := mustBudget(t, 3*defaultCost)
	var c deriveCounter
	h1 := mustHasher(t, HasherConfig{Budget: budget, Wait: time.Minute})
	h2 := mustHasher(t, HasherConfig{Params: costly, Budget: budget, Wait: time.Minute})
	c.install(h1)
	c.install(h2)

	var wg sync.WaitGroup
	for i := range 16 {
		h := h1
		if i%2 == 1 {
			h = h2
		}
		wg.Go(func() {
			if _, err := h.Hash(t.Context(), "shared"); err != nil {
				t.Errorf("Hash: %v", err)
			}
		})
	}
	wg.Wait()
	calls, _, peakKiB := c.snapshot()
	if len(calls) != 16 {
		t.Errorf("derivations = %d, want 16", len(calls))
	}
	if peakKiB*1024 > budget.Capacity() {
		t.Errorf("peak KiB in flight across both hashers = %d, want at most %d", peakKiB, budget.Capacity()/1024)
	}
}

func TestReservePermitLifecycle(t *testing.T) {
	t.Parallel()
	h := mustHasher(t, HasherConfig{Budget: mustBudget(t, 2*defaultCost), Wait: busyWait})
	hash := mustHash(t, h, "pw")

	t.Run("a second Release frees nothing", func(t *testing.T) {
		held := reserveN(t, h, 2)
		held[0].Release()
		held[0].Release()
		third := reserveN(t, h, 1)
		if _, err := h.Reserve(t.Context()); !errors.Is(err, ErrHashBusy) {
			t.Errorf("Reserve after a double Release: err = %v, want ErrHashBusy", err)
		}
		releaseAll(held[1:])
		releaseAll(third)
	})
	t.Run("Verify completes after the Reserve context is cancelled", func(t *testing.T) {
		var c deriveCounter
		c.install(h)
		ctx, cancel := context.WithCancel(t.Context())
		p, err := h.Reserve(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		if ok, _, err := p.Verify("pw", hash); err != nil || !ok {
			t.Errorf("permit Verify after cancel = (%v, %v), want (true, nil)", ok, err)
		}
		p.Release()
		if ok, _, err := p.Verify("pw", hash); err == nil || ok {
			t.Errorf("Verify of a used permit = (%v, %v), want (false, error)", ok, err)
		}
		if calls, _, _ := c.snapshot(); len(calls) != 1 {
			t.Errorf("derivations = %d, want 1 (the used permit derives nothing)", len(calls))
		}
		releaseAll(reserveN(t, h, 2))
	})
}

func TestPermitCostlierStoredHash(t *testing.T) {
	t.Parallel()
	costly := DefaultArgon2Params()
	costly.Memory *= 2
	stored := mustHash(t, mustHasher(t, HasherConfig{Params: costly}), "pw")
	budget := mustBudget(t, 4*defaultCost)

	t.Run("four concurrent Verifies stay within the capacity", func(t *testing.T) {
		h := mustHasher(t, HasherConfig{Budget: budget, Wait: time.Minute})
		var c deriveCounter
		c.install(h)
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				if ok, needsRehash, err := h.Verify(t.Context(), "pw", stored); err != nil || !ok || !needsRehash {
					t.Errorf("Verify = (%v, %v, %v), want (true, true, nil)", ok, needsRehash, err)
				}
			})
		}
		wg.Wait()
		calls, _, peakKiB := c.snapshot()
		if len(calls) != 4 {
			t.Errorf("derivations = %d, want 4", len(calls))
		}
		if peakKiB*1024 > budget.Capacity() {
			t.Errorf("peak KiB in flight = %d, want at most %d", peakKiB, budget.Capacity()/1024)
		}
		for _, p := range calls {
			if p.Memory != costly.Memory {
				t.Errorf("derived at m=%d, want the stored m=%d", p.Memory, costly.Memory)
			}
		}
	})
	t.Run("with the rest held the grow times out without deriving", func(t *testing.T) {
		h := mustHasher(t, HasherConfig{Budget: budget, Wait: busyWait})
		var c deriveCounter
		c.install(h)
		permit := reserveN(t, h, 1)[0]
		rest := reserveN(t, h, 3)
		ok, _, err := permit.Verify("pw", stored)
		if ok || !errors.Is(err, ErrHashBusy) {
			t.Errorf("Verify = (%v, %v), want (false, ErrHashBusy)", ok, err)
		}
		if calls, _, _ := c.snapshot(); len(calls) != 0 {
			t.Errorf("derivations = %d, want 0", len(calls))
		}
		releaseAll(rest)
		releaseAll(reserveN(t, h, 4))
	})
}

func TestPermitOverCapacityHash(t *testing.T) {
	t.Parallel()
	over := phcParams{
		params: Argon2Params{Memory: 131072, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		salt:   make([]byte, 16),
		key:    make([]byte, 32),
	}
	h := mustHasher(t, HasherConfig{Wait: busyWait})
	var c deriveCounter
	c.install(h)
	ok, _, err := h.Verify(t.Context(), "pw", NewHash(over.format()))
	if ok || !errors.Is(err, ErrHashInvalid) {
		t.Errorf("Verify(128 MiB hash on a 76 MiB budget) = (%v, %v), want (false, ErrHashInvalid)", ok, err)
	}
	calls, _, _ := c.snapshot()
	if len(calls) != 1 || calls[0] != DefaultArgon2Params() {
		t.Errorf("derivations = %+v, want exactly one at the hasher's parameters", calls)
	}
	releaseAll(reserveN(t, h, 4))
}

func TestVerifyEqualWork(t *testing.T) {
	t.Parallel()
	h := mustHasher(t, HasherConfig{})
	stored := mustHash(t, h, "right password")
	for _, tc := range []struct {
		stored Hash
		name   string
	}{
		{name: "wrong password for a real hash", stored: stored},
		{name: "empty", stored: Hash{}},
		{name: "malformed", stored: NewHash("not-a-hash")},
		{name: "non-canonical", stored: NewHash("$argon2id$v=19$m=019456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")},
		{name: "out of bounds", stored: NewHash("$argon2id$v=19$m=1024,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")},
		{name: "zero iterations", stored: NewHash("$argon2id$v=19$m=19456,t=0,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hc := mustHasher(t, HasherConfig{Budget: h.budget})
			var c deriveCounter
			c.install(hc)
			ok, needsRehash, err := hc.Verify(t.Context(), "wrong password", tc.stored)
			if ok || needsRehash || err != nil {
				t.Errorf("Verify = (%v, %v, %v), want (false, false, nil)", ok, needsRehash, err)
			}
			calls, _, _ := c.snapshot()
			if len(calls) != 1 || calls[0] != DefaultArgon2Params() {
				t.Errorf("derivations = %+v, want exactly one at the hasher's parameters", calls)
			}
		})
	}
}
