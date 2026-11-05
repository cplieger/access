package account_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
)

const wrongPassword = "wrong-horse-battery-8" // gitleaks:allow (test fixture password)

// fastParams is OWASP's cheapest row, so a test of hundreds of counted
// attempts derives at the floor's cost.
var fastParams = access.Argon2Params{Memory: 7168, Iterations: 5, Parallelism: 1, SaltLength: 16, KeyLength: 32}

// pwFixture is a fixture whose Hasher runs at fastParams behind a counting
// wrapper, with a limiter no test run fills unless it asks to.
type pwFixture struct {
	*fixture
	// hasher shares Config.Hasher's params and budget at a minute's wait: it
	// seeds hashes uncounted and holds the budget, and never fails on a
	// short test wait.
	hasher  *access.Hasher
	limiter *ratelimit.Limiter
	counted *countingHasher
}

type pwOptions struct {
	options
	budget  *access.HashBudget      // nil: four derivations
	limiter func(*ratelimit.Config) // edits the permissive config
	wait    time.Duration           // the hasher's budget wait; 0: a minute, so a loaded host never busies failN
}

func newPW(t testing.TB, o pwOptions) *pwFixture {
	t.Helper()
	budget := o.budget
	if budget == nil {
		var err error
		if budget, err = access.NewHashBudget(4 * access.HashCost(fastParams)); err != nil {
			t.Fatalf("NewHashBudget: %v", err)
		}
	}
	wait := o.wait
	if wait == 0 {
		wait = time.Minute
	}
	h, err := access.NewHasher(access.HasherConfig{Params: fastParams, Budget: budget, Wait: wait})
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	seed, err := access.NewHasher(access.HasherConfig{Params: fastParams, Budget: budget, Wait: time.Minute})
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	lc := permissiveLimits()
	if o.limiter != nil {
		o.limiter(&lc)
	}
	l, err := ratelimit.New(t.Context(), lc)
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	t.Cleanup(func() { _ = l.Shutdown(context.Background()) })
	p := &pwFixture{hasher: seed, limiter: l, counted: &countingHasher{}}
	opts := o.options
	wrap := opts.hooks.WrapHasher
	opts.hooks.WrapHasher = func(inner account.Hashing) account.Hashing {
		if wrap != nil {
			inner = wrap(inner)
		}
		p.counted.inner = inner
		return p.counted
	}
	edit := opts.edit
	opts.edit = func(c *account.Config) {
		c.Hasher, c.Limiter = h, l
		if edit != nil {
			edit(c)
		}
	}
	p.fixture = newFixture(t, opts)
	return p
}

// permissiveLimits admits every attempt a test makes; Devices is set.
func permissiveLimits() ratelimit.Config {
	lc := ratelimit.DefaultConfig()
	wide := ratelimit.Rate{Limit: 1 << 30, Window: time.Hour}
	lc.IP, lc.Account, lc.Device, lc.Request = wide, wide, wide, wide
	lc.Devices = access.NewEphemeralSealer()
	return lc
}

// ipLimit is a limiter edit admitting n attempts per IP.
func ipLimit(n int) func(*ratelimit.Config) {
	return func(c *ratelimit.Config) { c.IP = ratelimit.Rate{Limit: n, Window: time.Hour} }
}

// countingHasher records what the Service asks of its Hasher: the hash each
// permit's Verify compared, and each Hash that derived.
type countingHasher struct {
	inner    account.Hashing
	compared []access.Hash
	mu       sync.Mutex
	reserved atomic.Int64
	hashed   atomic.Int64
}

func (h *countingHasher) Hash(ctx context.Context, password string) (access.Hash, error) {
	out, err := h.inner.Hash(ctx, password)
	if err == nil {
		h.hashed.Add(1)
	}
	return out, err
}

func (h *countingHasher) Reserve(ctx context.Context) (account.HashPermit, error) {
	p, err := h.inner.Reserve(ctx)
	if err != nil {
		return nil, err
	}
	h.reserved.Add(1)
	return &countingPermit{HashPermit: p, h: h}, nil
}

// verified returns the hashes compared so far.
func (h *countingHasher) verified() []access.Hash {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.compared)
}

// zeroCompared counts the compared hashes that were the zero Hash.
func (h *countingHasher) zeroCompared() int {
	n := 0
	for _, v := range h.verified() {
		if v.IsZero() {
			n++
		}
	}
	return n
}

type countingPermit struct {
	account.HashPermit
	h *countingHasher
}

func (p *countingPermit) Verify(password string, encoded access.Hash) (ok, needsRehash bool, err error) {
	p.h.mu.Lock()
	p.h.compared = append(p.h.compared, encoded)
	p.h.mu.Unlock()
	return p.HashPermit.Verify(password, encoded)
}

// passwordUser stores an enabled RoleUser named name whose password is pw,
// hashed by h; a nil h stores no password.
func passwordUser(t testing.TB, s account.Store, h *access.Hasher, name, pw string) *access.User {
	t.Helper()
	u := &access.User{Username: name, Role: access.RoleUser, Enabled: true, WebAuthnHandle: access.GenerateWebAuthnHandle(), CreatedAt: time.Now()}
	if h != nil {
		hash, err := h.Hash(t.Context(), pw)
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		u.PasswordHash = hash
	}
	if err := s.CreateUser(t.Context(), u); err != nil {
		t.Fatalf("CreateUser(%s): %v", name, err)
	}
	return u
}

// clientAt is an untrusted client from the i-th /64 of 2001:db8::/32.
func clientAt(i int) account.Client {
	ip := netip.MustParseAddr(fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff))
	return account.Client{IP: ip, Peer: ip, UserAgent: "test-agent"}
}

func (p *pwFixture) login(ctx context.Context, c account.Client, name, pw string) (account.SignedIn, error) {
	return p.svc.PasswordLogin(ctx, c, account.Credentials{Username: name, Password: access.NewSecret(pw)})
}

// failN makes n wrong-password attempts for name from c, eight at a time,
// and requires each to be ErrInvalidCredentials.
func (p *pwFixture) failN(t testing.TB, c account.Client, name string, n int) {
	t.Helper()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	errs := make(chan error, n)
	for range n {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			if _, err := p.login(t.Context(), c, name, wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("wrong password for %s = %v, want ErrInvalidCredentials", name, err)
	}
}

// record reads name's password record in one trust context, as svc names it.
func record(t testing.TB, s account.Store, svc *account.Service, name string, trusted bool) (account.FailureCount, bool) {
	t.Helper()
	rec, found, err := s.AuthFailure(t.Context(), account.FailureRef{
		Name: account.FailureName(svc, name), Method: access.MethodPassword, Trusted: trusted,
	})
	if err != nil {
		t.Fatalf("AuthFailure(%s): %v", name, err)
	}
	return rec, found
}

// deviceCookie signs name in with pw from c and returns the device cookie
// the sign-in issued.
func (p *pwFixture) deviceCookie(t testing.TB, c account.Client, name, pw string) access.Secret {
	t.Helper()
	in, err := p.login(t.Context(), c, name, pw)
	if err != nil {
		t.Fatalf("PasswordLogin(%s): %v", name, err)
	}
	if in.DeviceCookie.IsZero() {
		t.Fatal("a successful sign-in returned no device cookie")
	}
	return in.DeviceCookie
}

// eventsOf returns the recorded events of kind.
func eventsOf(l *eventLog, kind account.EventKind) []account.Event {
	var out []account.Event
	for _, ev := range l.all() {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

// armed is a test hook that runs f only while it is armed.
type armed struct {
	f atomic.Pointer[func(ctx context.Context)]
}

func (a *armed) arm(f func(ctx context.Context)) { a.f.Store(&f) }
func (a *armed) disarm()                         { a.f.Store(nil) }
func (a *armed) hook(ctx context.Context) {
	if f := a.f.Load(); f != nil {
		(*f)(ctx)
	}
}
