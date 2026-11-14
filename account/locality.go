package account

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/cplieger/access"
)

// Locality is the library's rule for a local client, one a decision may
// trust more. TokenRequired, passed as Rules.SetupTokenRequired, lets a
// local client set up the first user with no token, and an app calls Local
// for any other such decision. The zero value makes no client local, and a
// nil Rules.SetupTokenRequired still means a token is always required.
type Locality struct {
	// Forwarder reports whether a direct peer relays others' connections
	// into this network namespace: a container bridge's gateway, the host's
	// own addresses seen through a port proxy. It is the app's, since only
	// the app can read its routes and interfaces, and it gets the peer with
	// no zone and unmapped. Nil means it cannot tell, so no client is local.
	// An app with no forwarder at all passes
	// func(netip.Addr) bool { return false } and says so in its code.
	Forwarder func(netip.Addr) bool
	// Hosts lists the host names, besides IP literals and "localhost", that
	// a token-free setup may send as its Host.
	Hosts []string
}

// Local reports whether c is a local client: c.Via is ViaDirect, Forwarder
// is set, and c.Peer is valid, loopback or private (127.0.0.0/8, ::1,
// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7), and not a
// Forwarder. An IPv4-mapped peer is judged as IPv4, so ::ffff:192.168.1.5
// is local and ::ffff:100.64.0.1 is not. A forwarded address is never
// local. A remote client behind a loopback relay, a NAT outside the
// namespace or an IPv6 overlay inside fc00::/7 reads as local.
func (l Locality) Local(c access.ClientAddr) bool {
	if c.Via != access.ViaDirect || l.Forwarder == nil || !c.Peer.IsValid() {
		return false
	}
	peer := c.Peer.WithZone("").Unmap()
	return (peer.IsLoopback() || peer.IsPrivate()) && !l.Forwarder(peer)
}

// TokenRequired requires a setup token unless Local(c.ClientAddr) holds and
// c.Host, with its port removed, ASCII lower-cased and one trailing dot
// dropped, is an IP literal with no zone, "localhost", or a Hosts entry
// canonicalised the same way. An empty or unparsable Host requires one.
// The Host rule closes DNS rebinding: a page that rebinds its own name to
// the server sends that name from a local peer.
func (l Locality) TokenRequired(_ context.Context, c Client) bool { //nolint:gocritic // hugeParam: Rules.SetupTokenRequired's signature
	if !l.Local(c.ClientAddr) {
		return true
	}
	host, ok := canonicalHost(c.Host)
	if !ok {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() != ""
	}
	if host == "localhost" {
		return false
	}
	return !slices.ContainsFunc(l.Hosts, func(h string) bool {
		allowed, ok := canonicalHost(h)
		return ok && allowed == host
	})
}

// canonicalHost removes host's port (and an IPv6 literal's brackets),
// lower-cases ASCII and drops one trailing dot. It refuses an empty result
// and a malformed bracket or port.
func canonicalHost(host string) (string, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.ContainsAny(host, "[]") {
		inner, found := strings.CutPrefix(host, "[")
		inner, closed := strings.CutSuffix(inner, "]")
		if !found || !closed || strings.ContainsAny(inner, "[]") {
			return "", false
		}
		host = inner
	}
	host = strings.TrimSuffix(strings.Map(asciiLower, host), ".")
	return host, host != ""
}

func asciiLower(r rune) rune {
	if 'A' <= r && r <= 'Z' {
		return r + 'a' - 'A'
	}
	return r
}
