package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unicode"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/capture"
	"pgregory.net/rapid"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

type testClock struct {
	at time.Time
	mu sync.Mutex
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.Devices = access.NewEphemeralSealer()
	cfg.Logger = slog.New(slog.DiscardHandler)
	return cfg
}

func newTest(t *testing.T, cfg Config) (*Limiter, *testClock) {
	t.Helper()
	clk := &testClock{at: t0}
	l, err := newLimiter(t.Context(), &cfg, clk.now)
	if err != nil {
		t.Fatalf("newLimiter: %v", err)
	}
	t.Cleanup(func() {
		if err := l.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return l, clk
}

func ipOf(s string) IP { return IPKey(netip.MustParseAddr(s)) }

// nthIP returns a distinct IPv4 key for each n below 2^24.
func nthIP(n int) IP {
	return IPKey(netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)}))
}

func admit(t *testing.T, l *Limiter, a Attempt) *Reservation {
	t.Helper()
	r, err := l.Attempt(a)
	if err != nil {
		t.Fatalf("Attempt: %v, want admitted", err)
	}
	return r
}

func refuse(t *testing.T, l *Limiter, a Attempt) *RefusedError {
	t.Helper()
	r, err := l.Attempt(a)
	var ref *RefusedError
	if !errors.As(err, &ref) || r != nil {
		t.Fatalf("Attempt = (%v, %v), want (nil, *RefusedError)", r, err)
	}
	if !errors.Is(err, ErrRefused) {
		t.Errorf("errors.Is(%v, ErrRefused) = false", err)
	}
	return ref
}

func refuseIn(t *testing.T, l *Limiter, a Attempt, dim string) {
	t.Helper()
	if ref := refuse(t, l, a); ref.Dimension != dim {
		t.Errorf("refused in %q, want %q", ref.Dimension, dim)
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	want := Config{
		IP:         Rate{Limit: 10, Window: 15 * time.Minute},
		Account:    Rate{Limit: 100, Window: time.Hour},
		Device:     Rate{Limit: 10, Window: time.Hour},
		Request:    Rate{Limit: 60, Window: time.Minute},
		IPv6Prefix: 64,
		MaxEntries: 10000,
		Prune:      5 * time.Minute,
	}
	if cfg != want {
		t.Errorf("DefaultConfig() = %+v, want %+v", cfg, want)
	}
}

func TestNewRefusesNilDevices(t *testing.T) {
	t.Parallel()
	l, err := New(t.Context(), DefaultConfig())
	var ce *ConfigError
	if l != nil || !errors.As(err, &ce) {
		t.Fatalf("New(DefaultConfig()) = (%v, %v), want (nil, *ConfigError)", l, err)
	}
	if ce.Field != "Devices" {
		t.Errorf("Field = %q, want Devices", ce.Field)
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("errors.Is(%v, ErrConfigInvalid) = false", err)
	}
}

func TestNewRefusesInvalidConfig(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*Config){
		"IP.Limit":       func(c *Config) { c.IP.Limit = 0 },
		"IP.Window":      func(c *Config) { c.IP.Window = -time.Second },
		"Account.Limit":  func(c *Config) { c.Account.Limit = -1 },
		"Account.Window": func(c *Config) { c.Account.Window = 0 },
		"Device.Limit":   func(c *Config) { c.Device.Limit = 0 },
		"Device.Window":  func(c *Config) { c.Device.Window = 0 },
		"Request.Limit":  func(c *Config) { c.Request.Limit = 0 },
		"Request.Window": func(c *Config) { c.Request.Window = 0 },
		"IPv6Prefix":     func(c *Config) { c.IPv6Prefix = 47 },
		"MaxEntries":     func(c *Config) { c.MaxEntries = 0 },
		"Prune":          func(c *Config) { c.Prune = 0 },
	}
	for field, edit := range cases {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig()
			edit(&cfg)
			_, err := New(t.Context(), cfg)
			var ce *ConfigError
			if !errors.As(err, &ce) || ce.Field != field {
				t.Errorf("New = %v, want *ConfigError{Field: %q}", err, field)
			}
		})
	}
	t.Run("IPv6Prefix 129", func(t *testing.T) {
		t.Parallel()
		cfg := testConfig()
		cfg.IPv6Prefix = 129
		if _, err := New(t.Context(), cfg); !errors.Is(err, ErrConfigInvalid) {
			t.Errorf("New = %v, want ErrConfigInvalid", err)
		}
	})
	for _, bits := range []int{48, 128} {
		t.Run(fmt.Sprintf("IPv6Prefix %d accepted", bits), func(t *testing.T) {
			t.Parallel()
			cfg := testConfig()
			cfg.IPv6Prefix = bits
			l, err := New(t.Context(), cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := l.Shutdown(t.Context()); err != nil {
				t.Errorf("Shutdown: %v", err)
			}
		})
	}
}

func TestAttemptConcurrentExact(t *testing.T) {
	t.Parallel()
	const limit, n = 10, 500
	cfg := testConfig()
	cfg.IP = Rate{Limit: limit, Window: time.Hour}
	cfg.Account = Rate{Limit: limit, Window: time.Hour}
	cfg.Device = Rate{Limit: limit, Window: time.Hour}
	cases := map[string]func(cookie access.Secret, i int) Attempt{
		"ip": func(access.Secret, int) Attempt { return Attempt{IP: ipOf("192.0.2.1")} },
		"account": func(_ access.Secret, i int) Attempt {
			return Attempt{IP: nthIP(i), Account: AccountKey("alice")}
		},
		"device": func(cookie access.Secret, i int) Attempt {
			return Attempt{IP: nthIP(i), Account: AccountKey("alice"), Device: cookie}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l, _ := newTest(t, cfg)
			cookie := l.DeviceCookie(AccountKey("alice"), access.Secret{})
			attempts := make([]Attempt, n)
			for i := range attempts {
				attempts[i] = mk(cookie, i)
			}
			start := make(chan struct{})
			var admitted, refused atomic.Int64
			var wg sync.WaitGroup
			for i := range n {
				wg.Go(func() {
					<-start
					_, err := l.Attempt(attempts[i])
					var ref *RefusedError
					switch {
					case err == nil:
						admitted.Add(1)
					case errors.As(err, &ref) && ref.Dimension == name:
						refused.Add(1)
					default:
						t.Errorf("Attempt: %v", err)
					}
				})
			}
			close(start)
			wg.Wait()
			if got := admitted.Load(); got != limit {
				t.Errorf("admitted %d of %d, want exactly %d", got, n, limit)
			}
			if got := refused.Load(); got != n-limit {
				t.Errorf("refused in %q %d, want %d", name, got, n-limit)
			}
		})
	}
}

func TestAbandonedReservationCounts(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.IP = Rate{Limit: 3, Window: time.Hour}
	settles := map[string]func(*Reservation){
		"never settled": func(*Reservation) {},
		"failed":        (*Reservation).Fail,
	}
	for name, settle := range settles {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l, _ := newTest(t, cfg)
			a := Attempt{IP: ipOf("192.0.2.1"), Account: AccountKey("alice")}
			for range 3 {
				settle(admit(t, l, a))
			}
			refuseIn(t, l, a, "ip")
		})
	}
}

func TestSettleOnce(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.IP = Rate{Limit: 2, Window: time.Hour}
	cfg.Account = Rate{Limit: 2, Window: time.Hour}
	alice := func(ip string) Attempt { return Attempt{IP: ipOf(ip), Account: AccountKey("alice")} }

	t.Run("Succeed after Fail does nothing", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		r := admit(t, l, alice("192.0.2.1"))
		r.Fail()
		if c := r.Succeed(); !c.IsZero() {
			t.Error("Succeed after Fail returned a device cookie")
		}
		admit(t, l, alice("192.0.2.1"))
		refuseIn(t, l, alice("192.0.2.1"), "ip")
	})
	t.Run("a second Succeed returns no cookie", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		r := admit(t, l, alice("192.0.2.1"))
		if c := r.Succeed(); c.IsZero() {
			t.Fatal("first Succeed returned no device cookie")
		}
		if c := r.Succeed(); !c.IsZero() {
			t.Error("second Succeed returned a device cookie")
		}
	})
	t.Run("Succeed after Cancel clears nothing", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		admit(t, l, alice("192.0.2.1")).Fail()
		r := admit(t, l, alice("192.0.2.2"))
		r.Cancel()
		if c := r.Succeed(); !c.IsZero() {
			t.Error("Succeed after Cancel returned a device cookie")
		}
		admit(t, l, alice("192.0.2.3"))
		refuseIn(t, l, alice("192.0.2.4"), "account")
	})
	t.Run("Fail after Cancel keeps the slot free", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		r := admit(t, l, alice("192.0.2.1"))
		r.Cancel()
		r.Fail()
		admit(t, l, alice("192.0.2.1"))
		admit(t, l, alice("192.0.2.1"))
		refuseIn(t, l, alice("192.0.2.1"), "ip")
	})
}

func TestCancelDoesNotCount(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.IP = Rate{Limit: 1, Window: time.Hour}
	cfg.Account = Rate{Limit: 1, Window: time.Hour}
	cfg.Device = Rate{Limit: 1, Window: time.Hour}

	t.Run("ip", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		a := Attempt{IP: ipOf("192.0.2.1")}
		admit(t, l, a).Cancel()
		admit(t, l, a)
		refuseIn(t, l, a, "ip")
	})
	t.Run("account", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		admit(t, l, Attempt{IP: ipOf("192.0.2.1"), Account: AccountKey("alice")}).Cancel()
		admit(t, l, Attempt{IP: ipOf("192.0.2.2"), Account: AccountKey("alice")})
		refuseIn(t, l, Attempt{IP: ipOf("192.0.2.3"), Account: AccountKey("alice")}, "account")
	})
	t.Run("device", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		cookie := l.DeviceCookie(AccountKey("alice"), access.Secret{})
		trusted := func(ip string) Attempt {
			return Attempt{IP: ipOf(ip), Account: AccountKey("alice"), Device: cookie}
		}
		admit(t, l, trusted("192.0.2.1")).Cancel()
		admit(t, l, trusted("192.0.2.2"))
		refuseIn(t, l, trusted("192.0.2.3"), "device")
	})
	t.Run("keeps other failures", func(t *testing.T) {
		t.Parallel()
		c := cfg
		c.Account = Rate{Limit: 2, Window: time.Hour}
		l, _ := newTest(t, c)
		alice := func(ip string) Attempt { return Attempt{IP: ipOf(ip), Account: AccountKey("alice")} }
		admit(t, l, alice("192.0.2.1")).Fail()
		admit(t, l, alice("192.0.2.2")).Cancel()
		admit(t, l, alice("192.0.2.3"))
		refuseIn(t, l, alice("192.0.2.4"), "account")
	})
}

func TestSucceedKeepsOtherAccounts(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.IP = Rate{Limit: 10, Window: time.Hour}
	cfg.Account = Rate{Limit: 3, Window: time.Hour}
	shared := ipOf("192.0.2.1")
	// setup leaves bob's bucket full and two of alice's failures in the
	// shared IP's window, then succeeds as alice from that IP.
	setup := func(t *testing.T) *Limiter {
		t.Helper()
		l, _ := newTest(t, cfg)
		for range 3 {
			admit(t, l, Attempt{IP: shared, Account: AccountKey("bob")}).Fail()
		}
		admit(t, l, Attempt{IP: shared, Account: AccountKey("alice")}).Fail()
		admit(t, l, Attempt{IP: ipOf("192.0.2.2"), Account: AccountKey("alice")}).Fail()
		admit(t, l, Attempt{IP: shared, Account: AccountKey("alice")}).Succeed()
		return l
	}

	t.Run("other accounts' IP failures stay", func(t *testing.T) {
		t.Parallel()
		l := setup(t)
		for range 6 { // 10, less bob's 3 and alice's one earlier failure there
			admit(t, l, Attempt{IP: shared})
		}
		refuseIn(t, l, Attempt{IP: shared}, "ip")
	})
	t.Run("this account's untrusted bucket clears", func(t *testing.T) {
		t.Parallel()
		l := setup(t)
		for i := range 3 {
			admit(t, l, Attempt{IP: nthIP(i), Account: AccountKey("alice")})
		}
		refuseIn(t, l, Attempt{IP: nthIP(3), Account: AccountKey("alice")}, "account")
	})
	t.Run("other accounts' buckets stay", func(t *testing.T) {
		t.Parallel()
		l := setup(t)
		refuseIn(t, l, Attempt{IP: nthIP(0), Account: AccountKey("bob")}, "account")
	})
}

func TestIPv6Slash64(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		a, b   IP
		prefix int
		shared bool
	}{
		{"one /64", ipOf("2001:db8::1"), ipOf("2001:db8::ffff:ffff:ffff:ffff"), 64, true},
		{"next /64", ipOf("2001:db8::1"), ipOf("2001:db8:0:1::1"), 64, false},
		{"4in6", ipOf("::ffff:192.0.2.1"), ipOf("192.0.2.1"), 64, true},
		{"IPv4 /32", ipOf("192.0.2.1"), ipOf("192.0.2.2"), 64, false},
		{"zones", ipOf("fe80::1%eth0"), ipOf("fe80::2%eth1"), 64, true},
		{"unknown", IPKey(netip.Addr{}), IP{}, 64, true},
		{"unknown apart from ::", IPKey(netip.Addr{}), ipOf("::"), 64, false},
		{"one /48", ipOf("2001:db8::1"), ipOf("2001:db8:0:ffff::1"), 48, true},
		{"next /48", ipOf("2001:db8::1"), ipOf("2001:db8:1::1"), 48, false},
		{"/128", ipOf("2001:db8::1"), ipOf("2001:db8::2"), 128, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig()
			cfg.IP = Rate{Limit: 1, Window: time.Hour}
			cfg.Request = Rate{Limit: 1, Window: time.Hour}
			cfg.IPv6Prefix = tc.prefix
			l, _ := newTest(t, cfg)
			admit(t, l, Attempt{IP: tc.a})
			if err := l.Request(tc.a); err != nil {
				t.Fatalf("Request: %v", err)
			}
			_, attemptErr := l.Attempt(Attempt{IP: tc.b})
			requestErr := l.Request(tc.b)
			if got := attemptErr != nil; got != tc.shared {
				t.Errorf("Attempt from b refused = %v, want %v (%v)", got, tc.shared, attemptErr)
			}
			if got := requestErr != nil; got != tc.shared {
				t.Errorf("Request from b refused = %v, want %v (%v)", got, tc.shared, requestErr)
			}
		})
	}
}

// spellings returns every spelling of word whose letters are each lower,
// upper, fullwidth lower or fullwidth upper: 4^len(word) of them.
func spellings(word string) []string {
	out := []string{""}
	for _, r := range word {
		forms := []rune{r, unicode.ToUpper(r), r - 'a' + 'ａ', unicode.ToUpper(r) - 'A' + 'Ａ'}
		next := make([]string, 0, len(out)*len(forms))
		for _, prefix := range out {
			for _, f := range forms {
				next = append(next, prefix+string(f))
			}
		}
		out = next
	}
	return out
}

func TestAccountKeySpellings(t *testing.T) {
	t.Parallel()
	t.Run("1024 spellings of admin", func(t *testing.T) {
		t.Parallel()
		all := spellings("admin")
		distinct := map[string]bool{}
		want := AccountKey("admin")
		for _, s := range all {
			distinct[s] = true
			if got := AccountKey(s); got != want {
				t.Errorf("AccountKey(%q) = %+v, want %+v", s, got, want)
			}
		}
		if len(distinct) != 1024 {
			t.Errorf("%d distinct spellings, want 1024", len(distinct))
		}
	})
	t.Run("a refused name keys as its first 256 bytes", func(t *testing.T) {
		t.Parallel()
		long := strings.Repeat("a", 300)
		k := AccountKey(long + " x")
		if k != accountOf(true, long[:256]) {
			t.Errorf("AccountKey(refused) = %+v, want the key of raw %q", k, long[:256])
		}
		if AccountKey(strings.Repeat("a", 256)+" y") != k {
			t.Error("two refused names sharing 256 bytes keyed apart")
		}
	})
	t.Run("a refused name never equals a canonical one", func(t *testing.T) {
		t.Parallel()
		name := strings.Repeat("a", 256)
		if AccountKey(name+" ") == AccountKey(name) {
			t.Errorf("refused %q keyed as canonical %q", name+" ", name)
		}
	})
	t.Run("an accepted name is not capped", func(t *testing.T) {
		t.Parallel()
		if AccountKey(strings.Repeat("a", 300)) == AccountKey(strings.Repeat("a", 301)) {
			t.Error("two accepted names longer than 256 bytes share a key")
		}
	})
	t.Run("empty is an account, not IP-only", func(t *testing.T) {
		t.Parallel()
		if AccountKey("").isZero() {
			t.Error(`AccountKey("") is the zero Account`)
		}
	})
}

// TestLongNameCostsOneFixedEntry is not parallel: it reads the heap, which
// a concurrent test's allocations would move.
func TestLongNameCostsOneFixedEntry(t *testing.T) {
	cfg := testConfig()
	l, _ := newTest(t, cfg)
	const names, nameLen = 16, 1 << 20
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range names {
		name := string(rune('a'+i)) + strings.Repeat("a", nameLen)
		admit(t, l, Attempt{IP: nthIP(i), Account: AccountKey(name)}).Fail()
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if kept := int64(after.HeapAlloc) - int64(before.HeapAlloc); kept > nameLen/4 {
		t.Errorf("%d accounts of 1 MiB names keep %d heap bytes, want under %d", names, kept, nameLen/4)
	}
	l.mu.Lock()
	tracked := len(l.account.windows)
	l.mu.Unlock()
	if tracked != names {
		t.Errorf("tracking %d accounts, want %d", tracked, names)
	}
}

func TestDeviceBucketIsolation(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.IP = Rate{Limit: 1000, Window: time.Hour}
	cfg.Account = Rate{Limit: 3, Window: time.Hour}
	cfg.Device = Rate{Limit: 3, Window: time.Hour}
	alice := AccountKey("alice")
	browser := ipOf("198.51.100.7")
	// setup signs the browser in once, then locks alice's untrusted bucket
	// from three other addresses.
	setup := func(t *testing.T) (*Limiter, access.Secret) {
		t.Helper()
		l, _ := newTest(t, cfg)
		cookie := admit(t, l, Attempt{IP: browser, Account: alice}).Succeed()
		for i := range 3 {
			admit(t, l, Attempt{IP: nthIP(i), Account: alice}).Fail()
		}
		refuseIn(t, l, Attempt{IP: nthIP(3), Account: alice}, "account")
		return l, cookie
	}

	t.Run("a trusted device signs in while the untrusted bucket is locked", func(t *testing.T) {
		t.Parallel()
		l, cookie := setup(t)
		r := admit(t, l, Attempt{IP: browser, Account: alice, Device: cookie})
		if !r.Trusted() {
			t.Fatal("Trusted() = false for the browser's own cookie")
		}
		if c := r.Succeed(); c.IsZero() {
			t.Error("Succeed returned no device cookie")
		}
		refuseIn(t, l, Attempt{IP: nthIP(4), Account: alice}, "account")
	})
	t.Run("device failures fill only that device's bucket", func(t *testing.T) {
		t.Parallel()
		l, cookie := setup(t)
		for range 3 {
			admit(t, l, Attempt{IP: browser, Account: alice, Device: cookie}).Fail()
		}
		refuseIn(t, l, Attempt{IP: browser, Account: alice, Device: cookie}, "device")
		other := l.DeviceCookie(alice, access.Secret{})
		if !admit(t, l, Attempt{IP: browser, Account: alice, Device: other}).Trusted() {
			t.Error("a second device of alice is untrusted")
		}
	})
	t.Run("a trusted success leaves the untrusted lock", func(t *testing.T) {
		t.Parallel()
		l, cookie := setup(t)
		admit(t, l, Attempt{IP: browser, Account: alice, Device: cookie}).Fail()
		admit(t, l, Attempt{IP: browser, Account: alice, Device: cookie}).Succeed()
		refuseIn(t, l, Attempt{IP: nthIP(5), Account: alice}, "account")
		for range 3 {
			admit(t, l, Attempt{IP: browser, Account: alice, Device: cookie}).Fail()
		}
		refuseIn(t, l, Attempt{IP: browser, Account: alice, Device: cookie}, "device")
	})
	t.Run("trusted failures leave the untrusted bucket empty", func(t *testing.T) {
		t.Parallel()
		c := cfg
		c.Device = Rate{Limit: 10, Window: time.Hour}
		l, _ := newTest(t, c)
		cookie := admit(t, l, Attempt{IP: browser, Account: alice}).Succeed()
		for range 3 {
			admit(t, l, Attempt{IP: browser, Account: alice, Device: cookie}).Fail()
		}
		for range 3 {
			admit(t, l, Attempt{IP: nthIP(0), Account: alice}).Fail()
		}
		refuseIn(t, l, Attempt{IP: nthIP(0), Account: alice}, "account")
	})
	t.Run("an IP-only attempt is never trusted", func(t *testing.T) {
		t.Parallel()
		l, cookie := setup(t)
		r := admit(t, l, Attempt{IP: browser, Device: cookie})
		if r.Trusted() {
			t.Error("Trusted() = true with no account")
		}
		if c := r.Succeed(); !c.IsZero() {
			t.Error("an IP-only Succeed returned a device cookie")
		}
	})
}

func TestDeviceCookiePayloadSize(t *testing.T) {
	t.Parallel()
	l, clk := newTest(t, testConfig())
	for name, acct := range map[string]Account{
		"canonical name":     AccountKey("alice"),
		"capped raw account": AccountKey(strings.Repeat("a", 1000)),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cookie := l.DeviceCookie(acct, access.Secret{})
			if got := len(cookie.Reveal()); got != 118 {
				t.Errorf("device cookie is %d characters, want 118", got)
			}
			payload, err := l.devices.Open(devicePurpose, cookie.Reveal(), clk.now())
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if len(payload) != 48 {
				t.Errorf("device payload is %d bytes, want 48 (access.MaxSealPayload is %d)", len(payload), access.MaxSealPayload)
			}
		})
	}
}

func TestEvictionKeepsTarget(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.IP = Rate{Limit: 1 << 20, Window: time.Hour}
	cfg.Account = Rate{Limit: 100, Window: time.Hour}
	cfg.MaxEntries = 50
	target := Attempt{IP: ipOf("203.0.113.9"), Account: AccountKey("admin")}
	junk := func(i int) Attempt {
		return Attempt{IP: target.IP, Account: AccountKey(fmt.Sprintf("junk%d", i))}
	}

	t.Run("a 99-count target outlasts MaxEntries-1 new keys", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		for i := range cfg.MaxEntries {
			admit(t, l, junk(i)).Fail() // a full map, so every later new key evicts
		}
		for range 99 {
			admit(t, l, target).Fail()
		}
		for i := range cfg.MaxEntries - 1 {
			admit(t, l, junk(cfg.MaxEntries+i)).Fail()
		}
		admit(t, l, target).Fail()
		refuseIn(t, l, target, "account")
	})
	t.Run("a target that keeps trying keeps its count through any flood", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		for range 100 {
			admit(t, l, target).Fail()
		}
		for i := range 500 {
			if i%(cfg.MaxEntries-1) == 0 {
				refuseIn(t, l, target, "account")
			}
			admit(t, l, junk(i)).Fail()
		}
		refuseIn(t, l, target, "account")
	})
}

// TestEvictionForgetsLeastRecent pins the documented cost of a bounded
// map: a key evicted by newer keys starts over, and each Prune tick reports
// the at-limit evictions since the last in one warning per dimension.
func TestEvictionForgetsLeastRecent(t *testing.T) {
	t.Parallel()
	src := ipOf("203.0.113.9")
	target := Attempt{IP: src, Account: AccountKey("target")}
	filler := Attempt{IP: src, Account: AccountKey("filler")}

	t.Run("alternating keys pass the limit of a full map", func(t *testing.T) {
		t.Parallel()
		w := &warnings{}
		cfg := evictionConfig(slog.New(w))
		cfg.Account = Rate{Limit: 2, Window: time.Hour}
		l, _ := newTest(t, cfg)
		for range 3 {
			admit(t, l, target).Fail()
			admit(t, l, filler).Fail()
		}
		l.tick()
		if got := w.all(); len(got) != 0 {
			t.Errorf("warnings for evictions below the limit: %+v, want none", got)
		}
	})
	t.Run("at-limit evictions warn once per tick with their count", func(t *testing.T) {
		t.Parallel()
		w := &warnings{}
		l, _ := newTest(t, evictionConfig(slog.New(w)))
		admit(t, l, target).Fail()
		for range 2 {
			admit(t, l, filler).Fail()
			admit(t, l, target).Fail()
		}
		l.tick()
		admit(t, l, filler).Fail()
		l.tick()
		l.tick()
		want := []warning{
			{dim: "account", evicted: 4, eviction: true},
			{dim: "account", evicted: 1, eviction: true},
		}
		if got := w.all(); !slices.Equal(got, want) {
			t.Errorf("warnings over three ticks = %+v, want %+v", got, want)
		}
	})
}

func TestNewKeyNeverRefusedAtCapacity(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.IP = Rate{Limit: 1, Window: time.Hour}
	cfg.Account = Rate{Limit: 1, Window: time.Hour}
	cfg.Request = Rate{Limit: 1, Window: time.Hour}
	cfg.MaxEntries = 3

	t.Run("account", func(t *testing.T) {
		t.Parallel()
		c := cfg
		c.IP = Rate{Limit: 1 << 20, Window: time.Hour}
		l, _ := newTest(t, c)
		src := ipOf("203.0.113.9")
		for i := range c.MaxEntries + 5 {
			admit(t, l, Attempt{IP: src, Account: AccountKey(fmt.Sprintf("a%d", i))}).Fail()
		}
		checkAccounts(t, l, "a5", "a6", "a7")
	})
	t.Run("ip", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		for i := range cfg.MaxEntries + 5 {
			admit(t, l, Attempt{IP: nthIP(i)}).Fail()
		}
		refuseIn(t, l, Attempt{IP: nthIP(cfg.MaxEntries + 4)}, "ip")
	})
	t.Run("request", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		for i := range cfg.MaxEntries + 5 {
			if err := l.Request(nthIP(i)); err != nil {
				t.Errorf("Request from new IP %d at capacity: %v", i, err)
			}
		}
	})
}

func TestTouchRefreshesRecency(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.IP = Rate{Limit: 1 << 20, Window: time.Hour}
	cfg.Account = Rate{Limit: 2, Window: time.Hour}
	cfg.MaxEntries = 2
	src := ipOf("203.0.113.9")
	acct := func(name string) Attempt { return Attempt{IP: src, Account: AccountKey(name)} }

	t.Run("an admitted attempt", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		admit(t, l, acct("a")).Fail()
		admit(t, l, acct("b")).Fail()
		admit(t, l, acct("a")).Fail()
		admit(t, l, acct("c")).Fail()
		checkAccounts(t, l, "a", "c")
	})
	t.Run("a refused attempt keeps a busy at-limit key", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		admit(t, l, acct("a")).Fail()
		admit(t, l, acct("a")).Fail()
		admit(t, l, acct("b")).Fail()
		refuseIn(t, l, acct("a"), "account")
		admit(t, l, acct("c")).Fail()
		checkAccounts(t, l, "a", "c")
		refuseIn(t, l, acct("a"), "account")
	})
	t.Run("a request", func(t *testing.T) {
		t.Parallel()
		c := cfg
		c.Request = Rate{Limit: 1, Window: time.Hour}
		l, _ := newTest(t, c)
		for _, i := range []int{0, 1} {
			if err := l.Request(nthIP(i)); err != nil {
				t.Fatalf("Request %d: %v", i, err)
			}
		}
		if err := l.Request(nthIP(0)); !errors.Is(err, ErrRefused) {
			t.Fatalf("second Request from IP 0 = %v, want refused", err)
		}
		if err := l.Request(nthIP(2)); err != nil {
			t.Fatalf("Request 2: %v", err)
		}
		if err := l.Request(nthIP(0)); !errors.Is(err, ErrRefused) {
			t.Errorf("IP 0 after a new key = %v, want still refused: the refusal kept it recent", err)
		}
	})
}

func checkAccounts(t *testing.T, l *Limiter, names ...string) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.account.windows) != len(names) {
		t.Errorf("tracking %d accounts, want %d", len(l.account.windows), len(names))
	}
	for _, n := range names {
		if _, ok := l.account.windows[AccountKey(n)]; !ok {
			t.Errorf("account %q was evicted", n)
		}
	}
}

type dimState[K comparable] struct {
	entries map[K][]entry
	order   []K
}

func stateOf[K comparable](d *dimension[K]) dimState[K] {
	s := dimState[K]{entries: make(map[K][]entry, len(d.windows))}
	for k, w := range d.windows {
		s.entries[k] = slices.Clone(w.entries)
	}
	for w := d.head; w != nil; w = w.next {
		s.order = append(s.order, w.key)
	}
	return s
}

type attemptState struct {
	ip      dimState[netip.Addr]
	account dimState[Account]
	device  dimState[deviceKey]
}

func stateOfAttempts(l *Limiter) attemptState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return attemptState{ip: stateOf(l.ip), account: stateOf(l.account), device: stateOf(l.device)}
}

func checkKept[K comparable](t *testing.T, dim string, before, after dimState[K], order ...K) {
	t.Helper()
	if !maps.EqualFunc(after.entries, before.entries, slices.Equal[[]entry]) {
		t.Errorf("%s windows = %v, want unchanged %v", dim, after.entries, before.entries)
	}
	if !slices.Equal(after.order, order) {
		t.Errorf("%s recency = %v, want %v", dim, after.order, order)
	}
}

func TestRefusedAttemptAddsNothing(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.IP = Rate{Limit: 1 << 20, Window: time.Hour}
	cfg.Account = Rate{Limit: 1 << 20, Window: time.Hour}
	cfg.Device = Rate{Limit: 1 << 20, Window: time.Hour}
	cfg.MaxEntries = 2
	ipA, ipB, ipC := ipOf("192.0.2.1"), ipOf("192.0.2.2"), ipOf("192.0.2.3")
	keyA, keyB := ipA.bucket(64), ipB.bucket(64)
	alice, bob := AccountKey("alice"), AccountKey("bob")

	t.Run("refused in account from an untracked IP", func(t *testing.T) {
		t.Parallel()
		c := cfg
		c.Account.Limit = 2
		l, _ := newTest(t, c)
		admit(t, l, Attempt{IP: ipA, Account: alice}).Fail()
		admit(t, l, Attempt{IP: ipB, Account: alice}).Fail()
		admit(t, l, Attempt{IP: ipA, Account: bob}).Fail()
		before := stateOfAttempts(l)
		refuseIn(t, l, Attempt{IP: ipC, Account: alice}, "account")
		after := stateOfAttempts(l)
		checkKept(t, "ip", before.ip, after.ip, keyA, keyB)
		checkKept(t, "account", before.account, after.account, alice, bob)
		checkKept(t, "device", before.device, after.device)
	})
	t.Run("refused in device from an untracked IP", func(t *testing.T) {
		t.Parallel()
		c := cfg
		c.Device.Limit = 2
		l, _ := newTest(t, c)
		cookie := l.DeviceCookie(alice, access.Secret{})
		dev := admit(t, l, Attempt{IP: ipA, Account: alice, Device: cookie})
		dev.Fail()
		admit(t, l, Attempt{IP: ipB, Account: alice, Device: cookie}).Fail()
		before := stateOfAttempts(l)
		refuseIn(t, l, Attempt{IP: ipC, Account: alice, Device: cookie}, "device")
		after := stateOfAttempts(l)
		checkKept(t, "ip", before.ip, after.ip, keyB, keyA)
		checkKept(t, "account", before.account, after.account)
		checkKept(t, "device", before.device, after.device, dev.device)
	})
	t.Run("refused in ip for an untracked account and device", func(t *testing.T) {
		t.Parallel()
		c := cfg
		c.IP.Limit = 2
		l, _ := newTest(t, c)
		admit(t, l, Attempt{IP: ipA, Account: alice}).Fail()
		admit(t, l, Attempt{IP: ipA, Account: bob}).Fail()
		before := stateOfAttempts(l)
		refuseIn(t, l, Attempt{IP: ipA, Account: alice}, "ip")
		refuseIn(t, l, Attempt{IP: ipA, Account: AccountKey("carol")}, "ip")
		dave := AccountKey("dave")
		refuseIn(t, l, Attempt{IP: ipA, Account: dave, Device: l.DeviceCookie(dave, access.Secret{})}, "ip")
		after := stateOfAttempts(l)
		checkKept(t, "ip", before.ip, after.ip, keyA)
		checkKept(t, "account", before.account, after.account, alice, bob)
		checkKept(t, "device", before.device, after.device)
	})
}

func TestRetryAfterExact(t *testing.T) {
	t.Parallel()
	t.Run("the oldest live failure sets RetryAfter", func(t *testing.T) {
		t.Parallel()
		cfg := testConfig()
		cfg.IP = Rate{Limit: 3, Window: 15 * time.Minute}
		l, clk := newTest(t, cfg)
		a := Attempt{IP: ipOf("192.0.2.1")}
		for range 3 {
			admit(t, l, a)
			clk.advance(time.Minute)
		}
		clk.advance(2 * time.Minute) // t0+5m
		if got := refuse(t, l, a).RetryAfter; got != 10*time.Minute {
			t.Errorf("RetryAfter at t0+5m = %v, want 10m", got)
		}
		clk.advance(10*time.Minute - time.Nanosecond)
		if got := refuse(t, l, a).RetryAfter; got != time.Nanosecond {
			t.Errorf("RetryAfter at t0+15m-1ns = %v, want 1ns", got)
		}
		clk.advance(time.Nanosecond)
		admit(t, l, a)
		if got := refuse(t, l, a).RetryAfter; got != time.Minute {
			t.Errorf("RetryAfter at t0+15m = %v, want 1m", got)
		}
		l.mu.Lock()
		n := len(l.ip.windows[a.IP.bucket(64)].entries)
		l.mu.Unlock()
		if n != 3 {
			t.Errorf("window holds %d entries, want the limit, 3", n)
		}
	})
	t.Run("the longest wait names the dimension", func(t *testing.T) {
		t.Parallel()
		cfg := testConfig()
		cfg.IP = Rate{Limit: 1, Window: 10 * time.Minute}
		cfg.Account = Rate{Limit: 1, Window: 50 * time.Minute}
		l, _ := newTest(t, cfg)
		a := Attempt{IP: ipOf("192.0.2.1"), Account: AccountKey("alice")}
		admit(t, l, a)
		ref := refuse(t, l, a)
		if ref.Dimension != "account" || ref.RetryAfter != 50*time.Minute {
			t.Errorf("refused %+v, want account after 50m", *ref)
		}
		cfg.IP.Window = 2 * time.Hour
		l2, _ := newTest(t, cfg)
		admit(t, l2, a)
		if ref := refuse(t, l2, a); ref.Dimension != "ip" || ref.RetryAfter != 2*time.Hour {
			t.Errorf("refused %+v, want ip after 2h", *ref)
		}
	})
}

func TestRequest(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.Request = Rate{Limit: 2, Window: time.Minute}
	cfg.IP = Rate{Limit: 2, Window: time.Minute}
	l, clk := newTest(t, cfg)
	ip := ipOf("192.0.2.1")
	for range 2 {
		if err := l.Request(ip); err != nil {
			t.Fatalf("Request: %v", err)
		}
	}
	clk.advance(10 * time.Second)
	err := l.Request(ip)
	var ref *RefusedError
	if !errors.As(err, &ref) || !errors.Is(err, ErrRefused) {
		t.Fatalf("third Request = %v, want *RefusedError", err)
	}
	if ref.Dimension != "request" || ref.RetryAfter != 50*time.Second {
		t.Errorf("refused %+v, want request after 50s", *ref)
	}
	t.Run("a refused request is not counted", func(t *testing.T) {
		clk.advance(50 * time.Second) // the two admitted requests age out
		for i := range 2 {
			if err := l.Request(ip); err != nil {
				t.Errorf("Request %d once the window passed: %v", i, err)
			}
		}
	})
	t.Run("requests and attempts count apart", func(t *testing.T) {
		apart, _ := newTest(t, cfg)
		admit(t, apart, Attempt{IP: ip})
		admit(t, apart, Attempt{IP: ip})
		refuseIn(t, apart, Attempt{IP: ip}, "ip")
		if err := apart.Request(ip); err != nil {
			t.Errorf("Request after attempts filled the ip window: %v", err)
		}
	})
	t.Run("Request never waits on the attempt lock", func(t *testing.T) {
		l.mu.Lock()
		defer l.mu.Unlock()
		done := make(chan error, 1)
		go func() { done <- l.Request(ipOf("192.0.2.2")) }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Request: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Request blocked while the attempt lock was held")
		}
	})
}

func TestRequestConcurrentExact(t *testing.T) {
	t.Parallel()
	const limit, n, keys = 10, 500, 8
	cfg := testConfig()
	cfg.Request = Rate{Limit: limit, Window: time.Hour}
	l, _ := newTest(t, cfg)
	// One race on one key interleaves too rarely to catch a lock split
	// between check and add every run, so each of several keys gets its own.
	for k := range keys {
		ip := nthIP(k)
		start := make(chan struct{})
		var admitted, refused atomic.Int64
		var wg sync.WaitGroup
		for range n {
			wg.Go(func() {
				<-start
				err := l.Request(ip)
				var ref *RefusedError
				switch {
				case err == nil:
					admitted.Add(1)
				case errors.As(err, &ref) && ref.Dimension == "request":
					refused.Add(1)
				default:
					t.Errorf("Request: %v", err)
				}
			})
		}
		close(start)
		wg.Wait()
		if got := admitted.Load(); got != limit {
			t.Errorf("key %d admitted %d of %d, want exactly %d", k, got, n, limit)
		}
		if got := refused.Load(); got != n-limit {
			t.Errorf("key %d refused in \"request\" %d, want %d", k, got, n-limit)
		}
	}
}

func TestPrune(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.Device = Rate{Limit: 10, Window: 2 * time.Hour}
	l, clk := newTest(t, cfg)
	stale := Attempt{IP: ipOf("192.0.2.1"), Account: AccountKey("stale")}
	admit(t, l, stale).Fail()
	cookie := l.DeviceCookie(AccountKey("alice"), access.Secret{})
	admit(t, l, Attempt{IP: ipOf("192.0.2.1"), Account: AccountKey("alice"), Device: cookie}).Fail()
	if err := l.Request(stale.IP); err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Hour)
	fresh := Attempt{IP: ipOf("192.0.2.2"), Account: AccountKey("fresh")}
	admit(t, l, fresh).Fail()
	l.pruneAll()
	l.requestMu.Lock()
	if len(l.request.windows) != 0 {
		t.Errorf("tracking %d request windows, want 0", len(l.request.windows))
	}
	l.requestMu.Unlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.ip.windows[stale.IP.bucket(64)]; ok {
		t.Error("the stale IP window survived prune")
	}
	if _, ok := l.ip.windows[fresh.IP.bucket(64)]; !ok {
		t.Error("prune dropped a live IP window")
	}
	if _, ok := l.account.windows[stale.Account]; ok {
		t.Error("the stale account window survived prune")
	}
	if len(l.account.windows) != 1 {
		t.Errorf("tracking %d accounts, want 1", len(l.account.windows))
	}
	if len(l.device.windows) != 1 {
		t.Errorf("tracking %d devices, want the live one", len(l.device.windows))
	}
}

func TestPruneLoop(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		cfg := testConfig()
		cfg.IP = Rate{Limit: 10, Window: 30 * time.Second}
		cfg.Prune = time.Minute
		l, err := New(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		admit(t, l, Attempt{IP: ipOf("192.0.2.1")})
		time.Sleep(time.Minute + time.Second) // past one prune tick
		synctest.Wait()
		l.mu.Lock()
		n := len(l.ip.windows)
		l.mu.Unlock()
		if n != 0 {
			t.Errorf("tracking %d IP windows after the prune tick, want 0", n)
		}
		if err := l.Shutdown(t.Context()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
}

func TestShutdown(t *testing.T) {
	t.Parallel()
	t.Run("waits and repeats", func(t *testing.T) {
		t.Parallel()
		l, err := New(t.Context(), testConfig())
		if err != nil {
			t.Fatal(err)
		}
		for i := range 2 {
			if err := l.Shutdown(t.Context()); err != nil {
				t.Errorf("Shutdown %d: %v", i, err)
			}
		}
		ended, cancel := context.WithCancel(t.Context())
		cancel()
		if err := l.Shutdown(ended); err != nil {
			t.Errorf("Shutdown with an ended ctx after exit = %v, want nil", err)
		}
	})
	t.Run("the New context stops the goroutine", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		l, err := New(ctx, testConfig())
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		<-l.done
	})
	t.Run("an ended ctx before exit returns its error", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			// Only pruneAll reads the clock here, so the first tick parks
			// the goroutine inside it until release.
			now := func() time.Time {
				once.Do(func() { close(entered) })
				<-release
				return time.Now()
			}
			cfg := testConfig()
			l, err := newLimiter(t.Context(), &cfg, now)
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(cfg.Prune)
			<-entered
			ended, cancel := context.WithCancel(t.Context())
			cancel()
			if err := l.Shutdown(ended); !errors.Is(err, context.Canceled) {
				t.Errorf("Shutdown = %v, want context.Canceled", err)
			}
			close(release)
			if err := l.Shutdown(t.Context()); err != nil {
				t.Errorf("second Shutdown: %v", err)
			}
		})
	})
}

// warnings is a slog.Handler that keeps each record's dimension and count,
// and whether its message is the eviction warning.
type warnings struct {
	got []warning
	mu  sync.Mutex
}

type warning struct {
	dim      string
	evicted  int64
	eviction bool
}

func (*warnings) Enabled(context.Context, slog.Level) bool { return true }

func (w *warnings) Handle(_ context.Context, r slog.Record) error {
	got := warning{eviction: strings.Contains(r.Message, evictionMsg)}
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "dimension":
			got.dim = a.Value.String()
		case "evicted":
			got.evicted = a.Value.Int64()
		}
		return true
	})
	w.mu.Lock()
	defer w.mu.Unlock()
	w.got = append(w.got, got)
	return nil
}

func (w *warnings) WithAttrs([]slog.Attr) slog.Handler { return w }
func (w *warnings) WithGroup(string) slog.Handler      { return w }

func (w *warnings) all() []warning {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.got)
}

const evictionMsg = "evicted keys at their limit"

// evictAtLimit makes l's account dimension, at MaxEntries 1 and an Account
// limit of 1, evict one window at its limit.
func evictAtLimit(t *testing.T, l *Limiter) {
	t.Helper()
	admit(t, l, Attempt{IP: ipOf("192.0.2.1"), Account: AccountKey("a")}).Fail()
	admit(t, l, Attempt{IP: ipOf("192.0.2.1"), Account: AccountKey("b")}).Fail()
}

func evictionConfig(logger *slog.Logger) Config {
	cfg := testConfig()
	cfg.Logger = logger
	cfg.MaxEntries = 1
	cfg.Account = Rate{Limit: 1, Window: time.Hour}
	return cfg
}

func TestLoggerInjected(t *testing.T) {
	// Not parallel: capture.Default swaps slog's process-wide default.
	t.Run("the injected logger gets the warning", func(t *testing.T) {
		def := capture.Default(t)
		logger, rec := capture.New()
		l, _ := newTest(t, evictionConfig(logger))
		evictAtLimit(t, l)
		l.tick()
		if got := rec.CountMsg(evictionMsg); got != 1 {
			t.Errorf("injected logger got %d warnings, want 1", got)
		}
		if got := def.CountMsg(evictionMsg); got != 0 {
			t.Errorf("slog.Default got %d warnings, want 0", got)
		}
	})
	t.Run("a nil Logger falls back to slog.Default", func(t *testing.T) {
		def := capture.Default(t)
		l, _ := newTest(t, evictionConfig(nil))
		evictAtLimit(t, l)
		l.tick()
		if got := def.CountMsg(evictionMsg); got != 1 {
			t.Errorf("slog.Default got %d warnings, want 1", got)
		}
	})
	t.Run("Shutdown reports what the last tick did not", func(t *testing.T) {
		logger, rec := capture.New()
		cfg := evictionConfig(logger)
		l, err := New(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		evictAtLimit(t, l)
		if err := l.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		if got := rec.CountMsg(evictionMsg); got != 1 {
			t.Errorf("%d warnings after Shutdown, want 1", got)
		}
	})
}

func TestEvictionWarningPerDimension(t *testing.T) {
	t.Parallel()
	w := &warnings{}
	cfg := evictionConfig(slog.New(w))
	cfg.IP = Rate{Limit: 1, Window: time.Hour}
	cfg.Device = Rate{Limit: 1, Window: time.Hour}
	cfg.Request = Rate{Limit: 1, Window: time.Hour}
	l, _ := newTest(t, cfg)
	// Every attempt below uses a new IP, so each after the first evicts the
	// previous IP at its limit: three ip evictions, one of each other kind.
	admit(t, l, Attempt{IP: nthIP(1), Account: AccountKey("a")}).Fail()
	admit(t, l, Attempt{IP: nthIP(2), Account: AccountKey("b")}).Fail()
	c := AccountKey("c")
	for i, cookie := range []access.Secret{l.DeviceCookie(c, access.Secret{}), l.DeviceCookie(c, access.Secret{})} {
		r := admit(t, l, Attempt{IP: nthIP(3 + i), Account: c, Device: cookie})
		if !r.Trusted() {
			t.Fatalf("device %d untrusted", i)
		}
		r.Fail()
	}
	for i := range 2 {
		if err := l.Request(nthIP(1 + i)); err != nil {
			t.Fatalf("Request %d: %v", i, err)
		}
	}
	l.tick()
	got := map[string]int64{}
	for _, wn := range w.all() {
		if !wn.eviction {
			t.Errorf("unexpected warning %+v", wn)
		}
		got[wn.dim] += wn.evicted
	}
	want := map[string]int64{"ip": 3, "account": 1, "device": 1, "request": 1}
	if !maps.Equal(got, want) || len(w.all()) != len(want) {
		t.Errorf("warnings = %+v, want one per dimension with evicted %v", w.all(), want)
	}
}

// blockingHandler parks every log call until release closes, and closes
// entered on the first one.
type blockingHandler struct {
	entered, release chan struct{}
	once             sync.Once
}

func (*blockingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *blockingHandler) Handle(context.Context, slog.Record) error {
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return nil
}

func (h *blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *blockingHandler) WithGroup(string) slog.Handler      { return h }

func TestEvictionWarningDoesNotBlockAdmission(t *testing.T) {
	t.Parallel()
	h := &blockingHandler{entered: make(chan struct{}), release: make(chan struct{})}
	l, _ := newTest(t, evictionConfig(slog.New(h)))
	evictAtLimit(t, l)
	ticked := make(chan struct{})
	go func() {
		l.tick()
		close(ticked)
	}()
	<-h.entered
	for name, try := range map[string]func() error{
		"attempt": func() error {
			_, err := l.Attempt(Attempt{IP: ipOf("192.0.2.2"), Account: AccountKey("c")})
			return err
		},
		"request": func() error { return l.Request(ipOf("192.0.2.2")) },
	} {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- try() }()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("admission while the warning is logged: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("an admission blocked on the warning handler")
			}
		})
	}
	close(h.release)
	<-ticked
}

// TestWindowModel checks Attempt against a model of the sliding window:
// admitted while fewer than Limit uncancelled entries are younger than
// Window, refused with RetryAfter until the oldest of them ages out.
func TestWindowModel(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		limit := rapid.IntRange(1, 5).Draw(rt, "limit")
		win := time.Duration(rapid.IntRange(1, 100).Draw(rt, "window")) * time.Second
		cfg := testConfig()
		cfg.IP = Rate{Limit: limit, Window: win}
		clk := &testClock{at: t0}
		l, err := newLimiter(t.Context(), &cfg, clk.now)
		if err != nil {
			rt.Fatal(err)
		}
		defer func() {
			if err := l.Shutdown(t.Context()); err != nil {
				rt.Errorf("Shutdown: %v", err)
			}
		}()
		type held struct {
			r  *Reservation
			at time.Time
		}
		var live []held
		a := Attempt{IP: ipOf("192.0.2.1")}
		for i := range rapid.IntRange(1, 60).Draw(rt, "steps") {
			clk.advance(time.Duration(rapid.IntRange(0, 2*int(win/time.Second)).Draw(rt, fmt.Sprintf("gap%d", i))) * time.Second)
			now := clk.now()
			kept := live[:0]
			for _, h := range live {
				if now.Before(h.at.Add(win)) {
					kept = append(kept, h)
				}
			}
			live = kept
			if len(live) > 0 && rapid.Bool().Draw(rt, fmt.Sprintf("cancel%d", i)) {
				live[0].r.Cancel()
				live = live[1:]
			}
			r, err := l.Attempt(a)
			if len(live) < limit {
				if err != nil {
					rt.Fatalf("step %d: refused with %d of %d live: %v", i, len(live), limit, err)
				}
				live = append(live, held{r, now})
				continue
			}
			var ref *RefusedError
			if !errors.As(err, &ref) {
				rt.Fatalf("step %d: admitted with %d of %d live", i, len(live), limit)
			}
			if want := live[0].at.Add(win).Sub(now); ref.RetryAfter != want {
				rt.Fatalf("step %d: RetryAfter %v, want %v", i, ref.RetryAfter, want)
			}
		}
	})
}

func BenchmarkAttempt(b *testing.B) {
	cfg := testConfig()
	cfg.IP = Rate{Limit: 1 << 30, Window: time.Hour}
	l, err := New(b.Context(), cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := l.Shutdown(context.Background()); err != nil {
			b.Error(err)
		}
	})
	var next atomic.Int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		a := Attempt{IP: nthIP(int(next.Add(1))), Account: AccountKey("alice")}
		for pb.Next() {
			r, err := l.Attempt(a)
			if err != nil {
				b.Error(err)
				return
			}
			r.Succeed()
		}
	})
}

func TestAttemptOmitIP(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.IP = Rate{Limit: 1, Window: time.Hour}
	cfg.Account = Rate{Limit: 1, Window: time.Hour}
	cfg.Device = Rate{Limit: 1, Window: time.Hour}
	ip := ipOf("192.0.2.1")
	omitted := func(name string, device access.Secret) Attempt {
		return Attempt{IP: ip, Account: AccountKey(name), Device: device, OmitIP: true}
	}

	t.Run("spent IP window not checked", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		admit(t, l, Attempt{IP: ip}).Fail()
		refuseIn(t, l, Attempt{IP: ip}, "ip")
		admit(t, l, omitted("alice", access.Secret{})).Fail()
	})
	t.Run("IP not charged", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		admit(t, l, omitted("alice", access.Secret{})).Fail()
		admit(t, l, omitted("bob", access.Secret{})).Cancel()
		admit(t, l, omitted("carol", access.Secret{})).Succeed()
		admit(t, l, Attempt{IP: ip})
		refuseIn(t, l, Attempt{IP: ip}, "ip")
	})
	t.Run("zero IP is still the unknown key", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		admit(t, l, Attempt{Account: AccountKey("alice")}).Fail()
		refuseIn(t, l, Attempt{Account: AccountKey("bob")}, "ip")
		admit(t, l, Attempt{Account: AccountKey("carol"), OmitIP: true})
	})
	t.Run("account window still refuses", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		admit(t, l, omitted("alice", access.Secret{})).Fail()
		refuseIn(t, l, omitted("alice", access.Secret{}), "account")
	})
	t.Run("device window still refuses", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		cookie := l.DeviceCookie(AccountKey("alice"), access.Secret{})
		r := admit(t, l, omitted("alice", cookie))
		if !r.Trusted() {
			t.Fatal("the device cookie was not trusted")
		}
		r.Fail()
		refuseIn(t, l, omitted("alice", cookie), "device")
	})
	t.Run("no account", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		r, err := l.Attempt(Attempt{IP: ip, OmitIP: true})
		if _, refused := errors.AsType[*RefusedError](err); err == nil || refused || r != nil {
			t.Errorf("OmitIP with no Account = (%v, %v), want (nil, an error that is not a refusal)", r, err)
		}
		admit(t, l, Attempt{IP: ip})
	})
}
