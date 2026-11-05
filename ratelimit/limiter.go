// Package ratelimit admits authentication attempts against sliding windows
// of failures per IP key, per account and per trusted device, and counts
// requests on anonymous begin routes per IP key. What it guarantees is a
// bound on failed attempts, and on begin-route requests, per window, per
// key, under the key rules of IPKey and AccountKey, for the
// Config.MaxEntries keys each dimension used most recently; its windows
// live in memory and reset on restart.
//
// Devices follow OWASP's device-cookie protocol
// (https://owasp.org/www-community/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies):
// a browser that signed in to an account carries a sealed cookie naming it,
// and its failures count against its own bucket, so locking the account for
// untrusted clients leaves that browser working.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/cplieger/access"
)

// Rate is a limit of Limit entries per sliding Window.
type Rate struct {
	Limit  int
	Window time.Duration
}

// Config configures a Limiter. Start from DefaultConfig and set Devices.
type Config struct {
	// Devices seals and opens device cookies. Required: the device protocol
	// has no off state. Pass a persisted ring so trusted devices survive a
	// restart; with access.NewEphemeralSealer() a restart makes every browser
	// untrusted until a sign-in by another method reissues its cookie.
	Devices *access.Sealer
	// Logger receives the eviction warnings; nil uses slog.Default().
	Logger *slog.Logger
	// IP bounds failed attempts per IP key.
	IP Rate
	// Account bounds failures from untrusted clients per account.
	Account Rate
	// Device bounds failures per account and device cookie.
	Device Rate
	// Request bounds every request on an anonymous begin route per IP key.
	Request Rate
	// IPv6Prefix is the IPv6 prefix length one IP key covers, 48 to 128.
	IPv6Prefix int
	// MaxEntries bounds the keys each dimension tracks, and so its memory.
	// A key's limit is exact while it is among its dimension's MaxEntries
	// most recently used keys. A new key past that is never refused for
	// capacity: it evicts the least recently used key whatever its count,
	// and that key starts over. This limiter bounds no spray across more
	// keys; docs/configuration.md names what does on each route.
	MaxEntries int
	// Prune is how often windows whose failures have all expired are
	// dropped, and how often each dimension that evicted keys at their
	// limit logs one warning with their count.
	Prune time.Duration
}

// DefaultConfig returns the default rates and bounds: 10 per 15m per IP,
// 100 per hour per account, 10 per hour per device, 60 requests per minute
// per IP, an IPv6 /64 (RFC 6177), 10000 keys per dimension and a 5m prune.
// Devices is left nil for the caller to set.
func DefaultConfig() Config {
	return Config{
		IP:         Rate{Limit: 10, Window: 15 * time.Minute},
		Account:    Rate{Limit: 100, Window: time.Hour},
		Device:     Rate{Limit: 10, Window: time.Hour},
		Request:    Rate{Limit: 60, Window: time.Minute},
		IPv6Prefix: 64,
		MaxEntries: 10000,
		Prune:      5 * time.Minute,
	}
}

var (
	// ErrRefused is matched by every *RefusedError.
	ErrRefused = errors.New("ratelimit: too many attempts")
	// ErrConfigInvalid is matched by every *ConfigError.
	ErrConfigInvalid = errors.New("ratelimit: invalid config")
)

// RefusedError is a refused Attempt or Request. Dimension is "ip",
// "account", "device" or "request", whichever waits longest, and RetryAfter
// is exactly how long until that key's oldest live entry ages out.
type RefusedError struct {
	Dimension  string
	RetryAfter time.Duration
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("ratelimit: too many attempts (%s), retry after %s", e.Dimension, e.RetryAfter)
}

// Is reports whether target is ErrRefused.
func (*RefusedError) Is(target error) bool { return target == ErrRefused }

// ConfigError names the Config field New refused, such as "IP.Limit".
type ConfigError struct{ Field string }

func (e *ConfigError) Error() string { return "ratelimit: invalid config: " + e.Field }

// Is reports whether target is ErrConfigInvalid.
func (*ConfigError) Is(target error) bool { return target == ErrConfigInvalid }

func (c *Config) validate() error {
	rates := []struct {
		name string
		rate Rate
	}{{"IP", c.IP}, {"Account", c.Account}, {"Device", c.Device}, {"Request", c.Request}}
	for _, r := range rates {
		if r.rate.Limit <= 0 {
			return &ConfigError{Field: r.name + ".Limit"}
		}
		if r.rate.Window <= 0 {
			return &ConfigError{Field: r.name + ".Window"}
		}
	}
	switch {
	case c.IPv6Prefix < 48 || c.IPv6Prefix > 128:
		return &ConfigError{Field: "IPv6Prefix"}
	case c.MaxEntries <= 0:
		return &ConfigError{Field: "MaxEntries"}
	case c.Prune <= 0:
		return &ConfigError{Field: "Prune"}
	case c.Devices == nil:
		return &ConfigError{Field: "Devices"}
	}
	return nil
}

// Limiter admits attempts and requests. Build one with New; it is safe for
// concurrent use.
type Limiter struct {
	logger     *slog.Logger
	devices    *access.Sealer
	now        func() time.Time
	cancel     context.CancelFunc
	done       chan struct{}
	ip         *dimension[netip.Addr]
	account    *dimension[Account]
	device     *dimension[deviceKey]
	request    *dimension[netip.Addr]
	prune      time.Duration
	ipv6Prefix int
	maxEntries int
	lastID     uint64
	mu         sync.Mutex // guards ip, account, device, lastID and each Reservation's settled
	// requestMu guards request alone, so a flood of begin-route requests
	// never queues sign-in admission behind its evictions.
	requestMu sync.Mutex
}

// New returns a Limiter whose prune goroutine runs until ctx ends or
// Shutdown. It refuses non-positive limits and windows, an IPv6Prefix
// outside 48 to 128, a non-positive MaxEntries or Prune, and a nil Devices,
// each with *ConfigError naming the field.
func New(ctx context.Context, cfg Config) (*Limiter, error) { //nolint:gocritic // hugeParam: by-value Config is the public signature, so a caller passes an edited DefaultConfig() copy
	return newLimiter(ctx, &cfg, time.Now)
}

func newLimiter(ctx context.Context, cfg *Config, now func() time.Time) (*Limiter, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	l := &Limiter{
		logger:     cfg.Logger,
		devices:    cfg.Devices,
		now:        now,
		cancel:     cancel,
		done:       make(chan struct{}),
		prune:      cfg.Prune,
		ipv6Prefix: cfg.IPv6Prefix,
		maxEntries: cfg.MaxEntries,
	}
	l.ip = newDimension[netip.Addr]("ip", cfg.IP, cfg.MaxEntries)
	l.account = newDimension[Account]("account", cfg.Account, cfg.MaxEntries)
	l.device = newDimension[deviceKey]("device", cfg.Device, cfg.MaxEntries)
	l.request = newDimension[netip.Addr]("request", cfg.Request, cfg.MaxEntries)
	go l.pruneLoop(ctx)
	return l, nil
}

func (l *Limiter) log() *slog.Logger {
	if l.logger != nil {
		return l.logger
	}
	return slog.Default()
}

// Attempt is one authentication attempt to admit.
type Attempt struct {
	IP IP
	// Device is the device cookie as presented; zero when absent.
	Device access.Secret
	// Account is zero for an IP-only attempt (setup and token consumption).
	Account Account
	// OmitIP leaves the IP dimension out: IP is neither checked nor charged.
	// It is for a caller already holding a full session for Account (a
	// step-up, a current-password check), and needs an Account. A zero IP
	// without OmitIP is still the shared "unknown" key.
	OmitIP bool
}

var errNoDimension = errors.New("ratelimit: an Attempt with OmitIP needs an Account")

// Attempt reserves one failure slot in every applicable dimension under the
// lock and refuses with *RefusedError when any is full: the IP dimension
// unless OmitIP, then the device bucket for a valid device cookie of the
// attempt's account, else the account's untrusted bucket. An OmitIP attempt
// with no Account is an error that is not a *RefusedError. A reservation is
// a recorded failure until Succeed or Cancel, so an abandoned one never
// leaks a free attempt.
func (l *Limiter) Attempt(a Attempt) (*Reservation, error) {
	if a.OmitIP && a.Account.isZero() {
		return nil, errNoDimension
	}
	r := &Reservation{l: l, ip: a.IP.bucket(l.ipv6Prefix), account: a.Account, ipOmitted: a.OmitIP}
	if !a.Account.isZero() {
		r.device.acct = a.Account
		r.device.id, r.trusted = l.openDevice(a.Account, a.Device, l.now())
	}
	if err := l.reserve(r); err != nil {
		return nil, err
	}
	return r, nil
}

// reserve checks every dimension that applies to r under l.mu and, when
// none refuses, adds r's entry to each.
func (l *Limiter) reserve(r *Reservation) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	ref := RefusedError{}
	refuse := func(dim string, wait time.Duration) {
		if wait > ref.RetryAfter {
			ref = RefusedError{Dimension: dim, RetryAfter: wait}
		}
	}
	if !r.ipOmitted {
		refuse(l.ip.name, l.ip.check(r.ip, now))
	}
	switch {
	case r.trusted:
		refuse(l.device.name, l.device.check(r.device, now))
	case !r.account.isZero():
		refuse(l.account.name, l.account.check(r.account, now))
	}
	if ref.RetryAfter > 0 {
		return &ref
	}
	l.lastID++
	r.id = l.lastID
	e := entry{at: now, id: r.id}
	if !r.ipOmitted {
		l.ip.add(r.ip, e)
	}
	switch {
	case r.trusted:
		l.device.add(r.device, e)
	case !r.account.isZero():
		l.account.add(r.account, e)
	}
	return nil
}

// Request counts one call on an anonymous begin route, refusing with
// *RefusedError when ip's request window is full. A refused call is not
// counted.
func (l *Limiter) Request(ip IP) error {
	key := ip.bucket(l.ipv6Prefix)
	l.requestMu.Lock()
	defer l.requestMu.Unlock()
	now := l.now()
	if wait := l.request.check(key, now); wait > 0 {
		return &RefusedError{Dimension: l.request.name, RetryAfter: wait}
	}
	l.request.add(key, entry{at: now})
	return nil
}

// Shutdown stops the prune goroutine and blocks until it has exited or ctx
// ends, returning nil in the first case and ctx.Err() in the second. Exit
// is checked before ctx, so once the goroutine is gone Shutdown returns nil
// even for an expired ctx. It is safe to call more than once.
func (l *Limiter) Shutdown(ctx context.Context) error {
	l.cancel()
	select {
	case <-l.done:
		return nil
	default:
	}
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *Limiter) pruneLoop(ctx context.Context) {
	defer close(l.done)
	ticker := time.NewTicker(l.prune)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			l.reportEvictions()
			return
		case <-ticker.C:
			l.tick()
		}
	}
}

func (l *Limiter) tick() {
	l.pruneAll()
	l.reportEvictions()
}

func (l *Limiter) pruneAll() {
	l.mu.Lock()
	now := l.now()
	l.ip.prune(now)
	l.account.prune(now)
	l.device.prune(now)
	l.mu.Unlock()
	l.requestMu.Lock()
	defer l.requestMu.Unlock()
	l.request.prune(l.now())
}

// reportEvictions logs one warning per dimension that evicted keys at their
// limit since the last report, with their count. It logs after releasing
// both locks, so a slow log handler never stalls admission.
func (l *Limiter) reportEvictions() {
	type evicted struct {
		dim string
		n   int
	}
	counts := make([]evicted, 0, 4)
	l.mu.Lock()
	counts = append(counts, evicted{l.ip.name, l.ip.drain()}, evicted{l.account.name, l.account.drain()}, evicted{l.device.name, l.device.drain()})
	l.mu.Unlock()
	l.requestMu.Lock()
	counts = append(counts, evicted{l.request.name, l.request.drain()})
	l.requestMu.Unlock()
	for _, c := range counts {
		if c.n > 0 {
			l.log().Warn("access/ratelimit: evicted keys at their limit; past max_entries keys a dimension forgets its least recently used keys, whose counts start over",
				"dimension", c.dim, "evicted", c.n, "max_entries", l.maxEntries)
		}
	}
}
