package ratelimit

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/cplieger/access"
)

func addr6(hi, lo uint64) netip.Addr {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], hi)
	binary.BigEndian.PutUint64(b[8:], lo)
	return netip.AddrFrom16(b)
}

func FuzzIPKey(f *testing.F) {
	f.Add(uint64(0x20010db800000000), uint64(1), uint64(0xffffffffffffffff), uint64(0x20010db800000001), uint32(0xc0000201))
	f.Add(uint64(0), uint64(0x0000ffffc0000201), uint64(2), uint64(1), uint32(0))
	f.Add(uint64(0xfe80000000000000), uint64(0), uint64(0), uint64(0xfe80000000000000), uint32(0xffffffff))
	f.Fuzz(func(t *testing.T, hi, lo, lo2, hi2 uint64, v4 uint32) {
		a, b := addr6(hi, lo), addr6(hi, lo2)
		// ::ffff:0:0/96 lies inside ::/64 but keys as IPv4.
		if !a.Is4In6() && !b.Is4In6() && IPKey(a).bucket(64) != IPKey(b).bucket(64) {
			t.Errorf("%v and %v share a /64 but key apart", a, b)
		}
		if c := addr6(hi2, lo); hi != hi2 && IPKey(a).bucket(64) == IPKey(c).bucket(64) {
			t.Errorf("%v and %v are in distinct /64s but share a key", a, c)
		}
		var four [4]byte
		binary.BigEndian.PutUint32(four[:], v4)
		plain := netip.AddrFrom4(four)
		mapped := netip.AddrFrom16(plain.As16())
		if IPKey(mapped) != IPKey(plain) || IPKey(mapped).bucket(64) != plain {
			t.Errorf("4in6 %v keys apart from %v", mapped, plain)
		}
	})
}

func FuzzAccountKey(f *testing.F) {
	for _, s := range []string{"admin", "ＡｄＭｉＮ", "Müller", "straße", "a b", "", " ", "\x00", "日本語", strings.Repeat("é", 300), strings.Repeat("a", 257) + " "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		k := AccountKey(s)
		canonical, err := access.NormalizeUsername(s)
		if err != nil {
			if k != accountOf(true, s[:min(len(s), maxRawAccountKey)]) {
				t.Fatalf("AccountKey(refused %q) = %+v, want its raw bytes capped at 256", s, k)
			}
			return
		}
		if k != accountOf(false, canonical) {
			t.Fatalf("AccountKey(%q) = %+v, want canonical %q", s, k, canonical)
		}
		for _, v := range []string{canonical, strings.ToUpper(s), strings.ToLower(s)} {
			if c, err := access.NormalizeUsername(v); err == nil && c == canonical && AccountKey(v) != k {
				t.Errorf("%q and %q normalise equal but key apart", s, v)
			}
		}
	})
}

// FuzzDeviceCookie checks that no forged cookie is trusted, and that the
// cookie DeviceCookie mints in its place is valid for the account.
func FuzzDeviceCookie(f *testing.F) {
	for _, s := range []string{"", "x", strings.Repeat("A", 118), strings.Repeat("_", 5000), "a.b\r\n"} {
		f.Add(s)
	}
	l, err := New(f.Context(), testConfig())
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() {
		if err := l.Shutdown(context.Background()); err != nil {
			f.Error(err)
		}
	})
	alice := AccountKey("alice")
	f.Fuzz(func(t *testing.T, s string) {
		presented := access.NewSecret(s)
		r, err := l.Attempt(Attempt{IP: ipOf("192.0.2.1"), Account: alice, Device: presented})
		if err == nil {
			if r.Trusted() {
				t.Fatalf("forged cookie %q trusted", s)
			}
			r.Cancel()
		}
		if _, ok := l.openDevice(alice, l.DeviceCookie(alice, presented), l.now()); !ok {
			t.Fatal("DeviceCookie minted a cookie invalid for its account")
		}
	})
}
