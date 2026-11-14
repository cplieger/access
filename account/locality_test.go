package account_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

func noForwarder(netip.Addr) bool { return false }

// direct is a client that reached the app from peer with no forwarding
// header.
func direct(peer string) access.ClientAddr {
	return access.ClientAddr{Peer: netip.MustParseAddr(peer), Via: access.ViaDirect}
}

func TestLocalityLocal(t *testing.T) {
	t.Parallel()
	lan := netip.MustParseAddr("192.168.1.5")
	bridge := netip.MustParseAddr("172.17.0.1")
	isBridge := func(a netip.Addr) bool { return a == bridge }
	ula := netip.MustParseAddr("fd00::1")
	isULA := func(a netip.Addr) bool { return a == ula }
	cases := []struct {
		name string
		l    account.Locality
		c    access.ClientAddr
		want bool
	}{
		{"via_direct", account.Locality{Forwarder: noForwarder}, access.ClientAddr{Peer: lan, Via: access.ViaDirect}, true},
		{"via_unknown", account.Locality{Forwarder: noForwarder}, access.ClientAddr{Peer: lan, Via: access.ViaUnknown}, false},
		{"via_untrusted_forwarding", account.Locality{Forwarder: noForwarder}, access.ClientAddr{Peer: lan, Via: access.ViaUntrustedForwarding}, false},
		{"via_proxy_private_client", account.Locality{Forwarder: noForwarder}, access.ClientAddr{Peer: netip.MustParseAddr("10.0.0.1"), Forwarded: lan, Via: access.ViaProxy}, false},
		{"via_proxy_loopback_both", account.Locality{Forwarder: noForwarder}, access.ClientAddr{Peer: netip.MustParseAddr("127.0.0.1"), Forwarded: netip.MustParseAddr("127.0.0.1"), Via: access.ViaProxy}, false},
		{"via_proxy_no_client", account.Locality{Forwarder: noForwarder}, access.ClientAddr{Peer: lan, Via: access.ViaProxyNoClient}, false},
		{"via_out_of_range", account.Locality{Forwarder: noForwarder}, access.ClientAddr{Peer: lan, Via: access.Via(99)}, false},
		{"direct_no_peer", account.Locality{Forwarder: noForwarder}, access.ClientAddr{Via: access.ViaDirect}, false},
		{"forwarder_match", account.Locality{Forwarder: isBridge}, direct("172.17.0.1"), false},
		{"forwarder_other_peer", account.Locality{Forwarder: isBridge}, direct("172.17.0.2"), true},
		{"forwarder_gets_unmapped", account.Locality{Forwarder: isBridge}, direct("::ffff:172.17.0.1"), false},
		{"forwarder_gets_no_zone", account.Locality{Forwarder: isULA}, access.ClientAddr{Peer: ula.WithZone("eth0"), Via: access.ViaDirect}, false},
		{"nil_forwarder_loopback", account.Locality{}, direct("127.0.0.1"), false},
		{"nil_forwarder_private", account.Locality{Hosts: []string{"nas.lan"}}, direct("192.168.1.5"), false},
		// No address rule sees these peers' remote clients; each is local
		// by design, and docs/configuration.md names the limit.
		{"limit_loopback_relay", account.Locality{Forwarder: noForwarder}, direct("127.0.0.1"), true},
		{"limit_unseen_nat", account.Locality{Forwarder: isBridge}, direct("192.168.1.9"), true},
		{"limit_ipv6_overlay", account.Locality{Forwarder: noForwarder}, direct("fd7a:115c:a1e0::1"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.l.Local(tc.c); got != tc.want {
				t.Errorf("Local(%+v) with Forwarder set %t = %t, want %t", tc.c, tc.l.Forwarder != nil, got, tc.want)
			}
		})
	}
}

func TestLocalityAddressClasses(t *testing.T) {
	t.Parallel()
	l := account.Locality{Forwarder: noForwarder}
	for _, tc := range []struct {
		peer string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		{"::1", true},
		{"10.0.0.0", true},
		{"10.255.255.255", true},
		{"172.16.0.0", true},
		{"172.31.255.255", true},
		{"192.168.0.0", true},
		{"192.168.255.255", true},
		{"fc00::", true},
		{"fd00::1", true},
		{"fd7a:115c:a1e0::1", true},
		{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"::ffff:127.0.0.1", true},
		{"::ffff:192.168.1.5", true},
		{"9.255.255.255", false},
		{"11.0.0.0", false},
		{"172.15.255.255", false},
		{"172.32.0.0", false},
		{"192.167.255.255", false},
		{"192.169.0.0", false},
		{"100.64.0.1", false},
		{"169.254.1.1", false},
		{"fe80::1", false},
		{"fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"fe00::", false},
		{"8.8.8.8", false},
		{"2001:db8::1", false},
		{"0.0.0.0", false},
		{"::", false},
		{"::ffff:100.64.0.1", false},
		{"::ffff:8.8.8.8", false},
	} {
		t.Run(tc.peer, func(t *testing.T) {
			t.Parallel()
			if got := l.Local(direct(tc.peer)); got != tc.want {
				t.Errorf("Local(direct %s) = %t, want %t", tc.peer, got, tc.want)
			}
		})
	}
}

func TestLocalityTokenRequired(t *testing.T) {
	t.Parallel()
	proxied := access.ClientAddr{Peer: netip.MustParseAddr("10.0.0.1"), Forwarded: netip.MustParseAddr("192.168.1.5"), Via: access.ViaProxy}
	cases := []struct {
		name string
		l    account.Locality
		c    access.ClientAddr
		host string
		want bool
	}{
		{"zero_locality_bridge_peer", account.Locality{}, direct("172.17.0.1"), "172.17.0.1:8080", true},
		{"zero_locality_loopback", account.Locality{}, direct("127.0.0.1"), "localhost", true},
		{"nil_forwarder_listed_host", account.Locality{Hosts: []string{"nas.lan"}}, direct("192.168.1.5"), "nas.lan", true},
		{"forwarder_peer", account.Locality{Forwarder: func(netip.Addr) bool { return true }}, direct("172.17.0.1"), "172.17.0.1:8080", true},
		{"forwarded_private_client", account.Locality{Forwarder: noForwarder}, proxied, "localhost", true},
		{"public_peer", account.Locality{Forwarder: noForwarder}, direct("203.0.113.9"), "203.0.113.9", true},
		{"local_peer", account.Locality{Forwarder: noForwarder}, direct("172.17.0.1"), "172.17.0.1:8080", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.l.TokenRequired(t.Context(), account.Client{ClientAddr: tc.c, Host: tc.host}); got != tc.want {
				t.Errorf("TokenRequired(%+v, Host %q) = %t, want %t", tc.c, tc.host, got, tc.want)
			}
		})
	}
}

// TestGuardLocalityHostRule holds the Host rule for a local client: only an
// IP literal with no zone, "localhost" or a canonicalised Hosts entry skips
// the token.
func TestGuardLocalityHostRule(t *testing.T) {
	t.Parallel()
	loopback, loopback6, private := direct("127.0.0.1"), direct("::1"), direct("192.168.1.5")
	l := account.Locality{Forwarder: noForwarder}
	withHosts := func(hosts ...string) account.Locality {
		return account.Locality{Forwarder: noForwarder, Hosts: hosts}
	}
	cases := []struct {
		name string
		l    account.Locality
		c    access.ClientAddr
		host string
		want bool // token required
	}{
		{"localhost", l, loopback, "localhost", false},
		{"localhost_port", l, loopback, "localhost:9847", false},
		{"localhost_upper_dot", l, loopback, "LOCALHOST.", false},
		{"ipv4_literal_port", l, loopback, "127.0.0.1:8080", false},
		{"ipv6_literal_port", l, loopback6, "[::1]:9847", false},
		{"ipv6_literal", l, loopback6, "[::1]", false},
		{"private_literal", l, private, "192.168.1.5:8374", false},
		{"rebound_host", l, loopback, "evil.example", true},
		{"rebound_host_private", l, private, "evil.example", true},
		{"unlisted_name", l, loopback, "nas.lan", true},
		{"empty", l, loopback, "", true},
		{"port_only", l, loopback, ":8080", true},
		{"zoned_literal", l, loopback6, "fe80::1%eth0", true},
		{"zoned_literal_port", l, loopback6, "[fe80::1%eth0]:80", true},
		{"open_bracket", l, loopback6, "[::1", true},
		{"close_bracket", l, loopback6, "::1]", true},
		{"hosts_entry_canonical", withHosts("nas.lan"), loopback, "NAS.LAN.:8374", false},
		{"hosts_entry_canonicalised", withHosts("NAS.lan."), loopback, "nas.lan", false},
		{"hosts_entry_case", withHosts("az.lan"), loopback, "AZ.lan", false},
		{"hosts_entry_suffix", withHosts("nas.lan"), loopback, "nas.lan.evil", true},
		{"hosts_empty_entry", withHosts(""), loopback, ".", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.l.TokenRequired(t.Context(), account.Client{ClientAddr: tc.c, Host: tc.host}); got != tc.want {
				t.Errorf("TokenRequired(hosts %q, %s, Host %q) = %t, want %t", tc.l.Hosts, tc.c.Peer, tc.host, got, tc.want)
			}
		})
	}
}

func TestLocalityAsSetupRule(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{rules: rulesWith(func(r *account.Rules) {
		r.SetupTokenRequired = account.Locality{Forwarder: noForwarder}.TokenRequired
	}), edit: withBusyHasher(t)})
	in := account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)}
	secure := direct("127.0.0.1")
	secure.Secure = true
	if _, err := f.svc.SetupWithPassword(t.Context(), account.Client{ClientAddr: secure, Host: "localhost:8080"}, in); !errors.Is(err, access.ErrHashBusy) {
		t.Errorf("a local setup = %v, want it past the token rule", err)
	}
	if _, err := f.svc.SetupWithPassword(t.Context(), account.Client{ClientAddr: secure, Host: "rebound.example"}, in); !errors.Is(err, account.ErrSetupTokenRequired) {
		t.Errorf("a rebound Host = %v, want ErrSetupTokenRequired", err)
	}
}
