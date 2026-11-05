package ratelimit

import (
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
)

// deviceOf returns the device ID cookie carries for acct, failing the test
// when the cookie is not valid for acct at clk's time.
func deviceOf(t *testing.T, l *Limiter, clk *testClock, acct Account, cookie access.Secret) deviceID {
	t.Helper()
	id, ok := l.openDevice(acct, cookie, clk.now())
	if !ok {
		t.Fatal("cookie is not a valid device cookie for its account")
	}
	return id
}

func TestDeviceCookieKeepsID(t *testing.T) {
	t.Parallel()
	alice := AccountKey("alice")
	src := ipOf("192.0.2.1")

	t.Run("a trusted Succeed keeps the device", func(t *testing.T) {
		t.Parallel()
		l, clk := newTest(t, testConfig())
		first := admit(t, l, Attempt{IP: src, Account: alice}).Succeed()
		second := admit(t, l, Attempt{IP: src, Account: alice, Device: first}).Succeed()
		if deviceOf(t, l, clk, alice, second) != deviceOf(t, l, clk, alice, first) {
			t.Error("a trusted Succeed changed the device ID")
		}
		if second.Reveal() == first.Reveal() {
			t.Error("a trusted Succeed returned the presented cookie, want a fresh seal")
		}
	})
	t.Run("an untrusted Succeed mints a new device", func(t *testing.T) {
		t.Parallel()
		l, clk := newTest(t, testConfig())
		a := admit(t, l, Attempt{IP: src, Account: alice}).Succeed()
		b := admit(t, l, Attempt{IP: src, Account: alice}).Succeed()
		if deviceOf(t, l, clk, alice, a) == deviceOf(t, l, clk, alice, b) {
			t.Error("two untrusted sign-ins share a device ID")
		}
	})
	t.Run("DeviceCookie keeps a valid cookie's device", func(t *testing.T) {
		t.Parallel()
		l, clk := newTest(t, testConfig())
		first := l.DeviceCookie(alice, access.Secret{})
		clk.advance(time.Hour)
		again := l.DeviceCookie(alice, first)
		if deviceOf(t, l, clk, alice, again) != deviceOf(t, l, clk, alice, first) {
			t.Error("DeviceCookie changed a valid cookie's device ID")
		}
	})
	t.Run("DeviceCookie replaces an unusable cookie", func(t *testing.T) {
		t.Parallel()
		l, clk := newTest(t, testConfig())
		old := l.DeviceCookie(alice, access.Secret{})
		oldID := deviceOf(t, l, clk, alice, old)
		clk.advance(deviceLifetime)
		for name, presented := range map[string]access.Secret{
			"absent":  {},
			"garbage": access.NewSecret("not-a-cookie"),
			"expired": old,
		} {
			if deviceOf(t, l, clk, alice, l.DeviceCookie(alice, presented)) == oldID {
				t.Errorf("%s: DeviceCookie kept the old device ID", name)
			}
		}
	})
	t.Run("a cookie lasts 180 days", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, testConfig())
		cookie := l.DeviceCookie(alice, access.Secret{})
		if _, ok := l.openDevice(alice, cookie, t0.Add(180*24*time.Hour-time.Nanosecond)); !ok {
			t.Error("cookie invalid before 180 days")
		}
		if _, ok := l.openDevice(alice, cookie, t0.Add(180*24*time.Hour)); ok {
			t.Error("cookie valid at 180 days")
		}
	})
	t.Run("the zero Account gets no cookie", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, testConfig())
		if c := l.DeviceCookie(Account{}, access.Secret{}); !c.IsZero() {
			t.Error("DeviceCookie(Account{}) returned a cookie")
		}
	})
}

func TestDeviceCookieOtherAccountUntrusted(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.Account = Rate{Limit: 1, Window: time.Hour}
	alice, bob := AccountKey("alice"), AccountKey("bob")

	t.Run("another account's cookie counts as untrusted", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		cookie := l.DeviceCookie(alice, access.Secret{})
		r := admit(t, l, Attempt{IP: ipOf("192.0.2.1"), Account: bob, Device: cookie})
		if r.Trusted() {
			t.Fatal("alice's cookie trusted for bob")
		}
		r.Fail()
		refuseIn(t, l, Attempt{IP: ipOf("192.0.2.2"), Account: bob, Device: cookie}, "account")
	})
	t.Run("DeviceCookie gives the other account a new device", func(t *testing.T) {
		t.Parallel()
		l, clk := newTest(t, cfg)
		cookie := l.DeviceCookie(alice, access.Secret{})
		if deviceOf(t, l, clk, bob, l.DeviceCookie(bob, cookie)) == deviceOf(t, l, clk, alice, cookie) {
			t.Error("bob's cookie kept alice's device ID")
		}
	})
	t.Run("a refused name is not its canonical twin", func(t *testing.T) {
		t.Parallel()
		l, clk := newTest(t, cfg)
		name := strings.Repeat("a", 256)
		cookie := l.DeviceCookie(AccountKey(name), access.Secret{})
		if _, ok := l.openDevice(AccountKey(name+" "), cookie, clk.now()); ok {
			t.Error("a canonical name's cookie is valid for a refused name with the same key bytes")
		}
	})
	t.Run("a value sealed for another purpose", func(t *testing.T) {
		t.Parallel()
		l, clk := newTest(t, cfg)
		id := newDeviceID()
		forged, err := cfg.Devices.Seal("oidc-flow", append(alice.digest[:], id[:]...), clk.now().Add(time.Hour))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if _, ok := l.openDevice(alice, access.NewSecret(forged), clk.now()); ok {
			t.Error("a value sealed for another purpose opened as a device cookie")
		}
	})
	t.Run("a payload of the wrong length", func(t *testing.T) {
		t.Parallel()
		l, clk := newTest(t, cfg)
		short, err := cfg.Devices.Seal(devicePurpose, alice.digest[:], clk.now().Add(time.Hour))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if _, ok := l.openDevice(alice, access.NewSecret(short), clk.now()); ok {
			t.Error("a payload without a device ID opened as a device cookie")
		}
	})
	t.Run("another sealer's cookie", func(t *testing.T) {
		t.Parallel()
		l, _ := newTest(t, cfg)
		other := testConfig()
		l2, _ := newTest(t, other)
		r := admit(t, l, Attempt{IP: ipOf("192.0.2.1"), Account: alice, Device: l2.DeviceCookie(alice, access.Secret{})})
		if r.Trusted() {
			t.Error("a cookie from another key ring is trusted")
		}
	})
}
