package access

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Argon2Params describes the Argon2id parameters for password hashing.
type Argon2Params struct {
	// Memory in KiB. Default: 19456 (19 MiB, OWASP recommendation #2).
	Memory uint32
	// Iterations (time cost). Default: 2.
	Iterations uint32
	// Parallelism (threads). Default: 1.
	Parallelism uint8
	// SaltLength in bytes. Default: 16.
	SaltLength uint32
	// KeyLength in bytes. Default: 32.
	KeyLength uint32
}

// Bounds every Argon2Params and every stored hash must meet, beside the
// memory floor.
const (
	argonMaxMemory     = 4 << 20 // 4 GiB
	argonMaxIterations = 100
	argonMaxThreads    = 16
	argonMinLength     = 16 // salt and key
	argonMaxLength     = 64 // salt and key
)

// argonFloor is OWASP's table of minimum Argon2id configurations, all at p=1,
// which it rates as equal defense
// (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id):
// row i is the least memory, in KiB, at i+1 iterations. More iterations than
// the last row's need its memory. Every row is at least 8 KiB for each of up
// to argonMaxThreads lanes, so a valid Memory is at least 8 × Parallelism and
// [HashCost] charges exactly Memory.
var argonFloor = [...]uint32{47104, 19456, 12288, 9216, 7168}

// DefaultArgon2Params returns the OWASP-recommended Argon2id parameters.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      argonMemory,
		Iterations:  argonIterations,
		Parallelism: argonParallelism,
		SaltLength:  argonSaltLen,
		KeyLength:   argonKeyLen,
	}
}

// Validate refuses parameters outside the bounds: memory at least OWASP's
// minimum for min(Iterations, 5) iterations (argonFloor) and at most 4 GiB,
// iterations 1 to 100, parallelism 1 to 16, salt and key 16 to 64 bytes.
func (p Argon2Params) Validate() error {
	switch {
	case p.Iterations < 1 || p.Iterations > argonMaxIterations:
		return fmt.Errorf("access: argon2 iterations %d is outside 1 to 100", p.Iterations)
	case p.Memory > argonMaxMemory:
		return fmt.Errorf("access: argon2 memory %d KiB is above 4 GiB", p.Memory)
	case p.Parallelism < 1 || p.Parallelism > argonMaxThreads:
		return fmt.Errorf("access: argon2 parallelism %d is outside 1 to 16", p.Parallelism)
	case p.SaltLength < argonMinLength || p.SaltLength > argonMaxLength:
		return fmt.Errorf("access: argon2 salt length %d is outside 16 to 64 bytes", p.SaltLength)
	case p.KeyLength < argonMinLength || p.KeyLength > argonMaxLength:
		return fmt.Errorf("access: argon2 key length %d is outside 16 to 64 bytes", p.KeyLength)
	}
	t := min(p.Iterations, uint32(len(argonFloor)))
	if floor := argonFloor[t-1]; p.Memory < floor {
		return fmt.Errorf("access: argon2 memory %d KiB is below %d KiB, OWASP's minimum at t=%d", p.Memory, floor, t)
	}
	return nil
}

var (
	// ErrHashBudgetTooSmall reports a budget that cannot hold one derivation
	// at the hasher's parameters.
	ErrHashBudgetTooSmall = errors.New("access: hash budget smaller than one derivation")
	// ErrHashInvalid reports a stored hash whose cost exceeds the whole
	// budget, so no wait could ever admit it.
	ErrHashInvalid = errors.New("access: stored hash exceeds the hash budget")

	errPermitUsed = errors.New("access: hash permit already used")
)

// Hasher hashes and verifies passwords with Argon2id under a [HashBudget].
// Build one with [NewHasher]; the zero value is not usable.
type Hasher struct {
	budget *HashBudget
	// derive is argon2.IDKey; tests swap it to count derivations.
	derive func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte
	params Argon2Params
	wait   time.Duration
	cost   int64
}

// defaultHashBudgetWait is HasherConfig.Wait's default.
const defaultHashBudgetWait = 2 * time.Second

// HasherConfig configures a [Hasher]. Every zero value is the default: the
// zero Params is [DefaultArgon2Params], a nil Budget is a private budget of
// 4 × [HashCost](Params), and a zero Wait is 2 s.
type HasherConfig struct {
	// Budget bounds this Hasher's derivations. Passing the same budget to
	// every Hasher makes one bound cover them all; a nil Budget gets a
	// private one.
	Budget *HashBudget
	// Params are the Argon2id parameters.
	Params Argon2Params
	// Wait is how long Hash, Verify and Reserve wait for the budget before
	// [ErrHashBusy]. The caller's context also bounds Hash and Reserve,
	// including Verify's reservation; a permit's wait for a costlier stored
	// hash is bounded by Wait alone.
	Wait time.Duration
}

// NewHasher builds a Hasher. It refuses non-zero Params that fail
// [Argon2Params.Validate], a negative Wait, and a Budget smaller than
// HashCost(Params) with [ErrHashBudgetTooSmall].
func NewHasher(cfg HasherConfig) (*Hasher, error) {
	if cfg.Params == (Argon2Params{}) {
		cfg.Params = DefaultArgon2Params()
	}
	if err := cfg.Params.Validate(); err != nil {
		return nil, err
	}
	if cfg.Wait < 0 {
		return nil, fmt.Errorf("access: hash budget wait must not be negative, got %s", cfg.Wait)
	}
	cfg.Wait = cmp.Or(cfg.Wait, defaultHashBudgetWait)
	cost := HashCost(cfg.Params)
	if cfg.Budget == nil {
		cfg.Budget, _ = NewHashBudget(4 * cost) // cost is positive once Validate passed
	}
	if cost > cfg.Budget.Capacity() {
		return nil, fmt.Errorf("%w: one derivation needs %d bytes, the budget holds %d", ErrHashBudgetTooSmall, cost, cfg.Budget.Capacity())
	}
	return &Hasher{budget: cfg.Budget, derive: argon2.IDKey, params: cfg.Params, wait: cfg.Wait, cost: cost}, nil
}

// Hash returns the PHC string of password, NFC-normalised, as a [Hash], or
// [ErrHashBusy] when the budget cannot admit it within the wait or ctx.
func (h *Hasher) Hash(ctx context.Context, password string) (Hash, error) {
	if err := h.budget.acquire(ctx, h.cost, h.wait); err != nil {
		return Hash{}, err
	}
	defer h.budget.release(h.cost)
	salt := make([]byte, h.params.SaltLength)
	rand.Read(salt) // never returns an error (Go 1.24+); it crashes instead
	p := phcParams{
		salt:   salt,
		key:    h.derive([]byte(norm.NFC.String(password)), salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength),
		params: h.params,
	}
	return NewHash(p.format()), nil
}

// Verify derives once unless it returns [ErrHashBusy]. A zero, malformed or
// out-of-bounds stored hash derives at the hasher's own parameters and
// reports (false, false, nil), so every arm costs the same. needsRehash
// reports a parsed stored hash made with parameters other than the hasher's.
// Verify is [Hasher.Reserve] followed by [HashPermit.Verify], and returns the
// error of either; ctx bounds only the reservation.
func (h *Hasher) Verify(ctx context.Context, password string, encoded Hash) (ok, needsRehash bool, err error) {
	permit, err := h.Reserve(ctx)
	if err != nil {
		return false, false, err
	}
	defer permit.Release()
	return permit.Verify(password, encoded)
}

// NeedsRehash reports whether encoded is unparseable, out of bounds, or made
// with parameters other than the hasher's.
func (h *Hasher) NeedsRehash(encoded Hash) bool {
	p, err := parsePHC(encoded.Reveal())
	return err != nil || h.differs(p)
}

func (h *Hasher) differs(p phcParams) bool {
	return p.params.Memory != h.params.Memory || p.params.Iterations != h.params.Iterations ||
		p.params.Parallelism != h.params.Parallelism || p.params.SaltLength != h.params.SaltLength ||
		p.params.KeyLength != h.params.KeyLength
}

// Reserve takes one derivation's share of the budget, [HashCost] of the
// hasher's params, waiting as Hash does, or returns [ErrHashBusy]. Callers
// defer [HashPermit.Release]; it does nothing after [HashPermit.Verify].
func (h *Hasher) Reserve(ctx context.Context) (*HashPermit, error) {
	if err := h.budget.acquire(ctx, h.cost, h.wait); err != nil {
		return nil, err
	}
	return &HashPermit{h: h, used: new(atomic.Bool)}, nil
}

// equalWork derives once at the hasher's parameters and discards the result,
// so a stored hash that cannot be compared costs what a real one does.
func (h *Hasher) equalWork(password string) {
	salt := make([]byte, h.params.SaltLength)
	h.derive([]byte(norm.NFC.String(password)), salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
}

// HashPermit is one admitted derivation's share of a [HashBudget], from
// [Hasher.Reserve]. It is used once, by Verify or Release. The zero value is
// not usable. Its used flag is held by pointer, so a copied permit shares it
// and the share is returned once.
type HashPermit struct {
	h    *Hasher
	used *atomic.Bool
}

// Verify parses encoded first. A cost at or below the share derives under the
// share; a cost above it and within Capacity() releases the share and acquires
// that cost all-or-nothing within the hasher's wait (the timer alone), else
// returns [ErrHashBusy] without deriving. A cost above Capacity() derives once
// under the share at the hasher's own parameters and returns
// [ErrHashInvalid]. Verify runs to completion whatever happens to the context
// passed to Reserve, then releases. On a used permit it derives nothing and
// returns an error.
func (p *HashPermit) Verify(password string, encoded Hash) (ok, needsRehash bool, err error) {
	if p.used.Swap(true) {
		return false, false, errPermitUsed
	}
	h := p.h
	held := h.cost
	defer func() {
		if held > 0 {
			h.budget.release(held)
		}
	}()
	stored, err := parsePHC(encoded.Reveal())
	if err != nil {
		h.equalWork(password)
		return false, false, nil
	}
	switch cost := HashCost(stored.params); {
	case cost > h.budget.Capacity():
		h.equalWork(password)
		return false, false, fmt.Errorf("%w: it needs %d bytes, the budget holds %d", ErrHashInvalid, cost, h.budget.Capacity())
	case cost > held:
		h.budget.release(held)
		held = 0
		if err := h.budget.acquire(context.Background(), cost, h.wait); err != nil {
			return false, false, err
		}
		held = cost
	}
	derived := h.derive([]byte(norm.NFC.String(password)), stored.salt,
		stored.params.Iterations, stored.params.Memory, stored.params.Parallelism, stored.params.KeyLength)
	return subtle.ConstantTimeCompare(stored.key, derived) == 1, h.differs(stored), nil
}

// Release returns an unused permit's share; after Verify or Release it does
// nothing.
func (p *HashPermit) Release() {
	if !p.used.Swap(true) {
		p.h.budget.release(p.h.cost)
	}
}
