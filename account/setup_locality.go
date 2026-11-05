package account

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/cplieger/access"
)

// SetupLocality is the library's rule for token-free first-run setup, for
// an app that passes TokenRequired as Rules.SetupTokenRequired. A nil
// SetupTokenRequired still means a token is always required.
type SetupLocality struct {
	// Local reports whether the resolved client counts as local. Nil means
	// no client is local, so the zero SetupLocality always requires a token:
	// which peers are local depends on a proxy topology only the app knows,
	// and behind a same-host reverse proxy that adds no forwarding header
	// the app's resolver sees, every client arrives as a loopback peer.
	Local func(access.ClientAddr) bool
	// Hosts lists the host names, besides IP literals and "localhost",
	// that a token-free setup may send as its Host.
	Hosts []string
}

// TokenRequired requires a setup token unless Local is set,
// Local(c.ClientAddr) holds and c.Host, with its port removed, ASCII
// lower-cased and one trailing dot dropped, is an IP literal with no zone,
// "localhost", or a Hosts entry canonicalised the same way. An empty or
// unparsable Host requires one. The Host rule closes DNS rebinding: a page
// that rebinds its own name to the server sends that name from a local
// peer.
func (l SetupLocality) TokenRequired(_ context.Context, c Client) bool { //nolint:gocritic // hugeParam: Rules.SetupTokenRequired's signature
	if l.Local == nil || !l.Local(c.ClientAddr) {
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
