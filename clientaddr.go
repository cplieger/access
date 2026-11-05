package access

import (
	"net/http"
	"net/netip"
)

// ClientAddr is how the app resolved the caller's address. The app's
// proxy-aware resolver (Config.ClientAddr) fills it; the library never reads
// a forwarding header to decide an address.
type ClientAddr struct {
	// IP is the resolved client address; the limiter keys on it.
	IP netip.Addr
	// Peer is the connection's remote address.
	Peer netip.Addr
	// Proxied reports that IP came from a forwarding header sent by a peer
	// the app trusts as a proxy.
	Proxied bool
	// UntrustedForwarding reports that the request carried a forwarding
	// header (Forwarded, X-Forwarded-For, X-Real-IP) from a peer the app
	// does not trust, which the resolver ignored.
	UntrustedForwarding bool
}

// ClientAddr resolves r's client through the Config.ClientAddr resolver, the
// one resolver behind [SessionActivity.IP], the limiter's IP key and the
// setup rule.
func (a *Authenticator) ClientAddr(r *http.Request) ClientAddr { return a.cfg.ClientAddr(r) }

// defaultClientAddr treats no peer as a proxy: IP and Peer are r.RemoteAddr's
// address, unmapped, or the zero Addr when it does not parse.
func defaultClientAddr(r *http.Request) ClientAddr {
	var peer netip.Addr
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		peer = ap.Addr().Unmap()
	} else if addr, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		peer = addr.Unmap()
	}
	forwarded := false
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Real-Ip"} {
		if len(r.Header.Values(name)) > 0 {
			forwarded = true
		}
	}
	return ClientAddr{IP: peer, Peer: peer, UntrustedForwarding: forwarded}
}

// activityIP is addr in [Session.LastIP]'s form, or "" when unknown.
func activityIP(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}
