package access

import (
	"fmt"
	"net/http"
	"net/netip"
)

// Via is how the request reached the app, as the app's resolver saw it.
type Via uint8

// The Via values a resolver answers.
const (
	ViaUnknown             Via = iota // the zero value: the resolver did not say
	ViaDirect                         // the peer is the client; no forwarding header
	ViaUntrustedForwarding            // a peer the app does not trust sent a forwarding header, which was ignored
	ViaProxy                          // a trusted proxy forwarded the client, in Forwarded
	ViaProxyNoClient                  // a trusted proxy forwarded no client address
)

// String returns the constant's name ("ViaUnknown", "ViaDirect",
// "ViaUntrustedForwarding", "ViaProxy", "ViaProxyNoClient"), and "Via(N)"
// for a value out of range.
func (v Via) String() string {
	switch v {
	case ViaUnknown:
		return "ViaUnknown"
	case ViaDirect:
		return "ViaDirect"
	case ViaUntrustedForwarding:
		return "ViaUntrustedForwarding"
	case ViaProxy:
		return "ViaProxy"
	case ViaProxyNoClient:
		return "ViaProxyNoClient"
	default:
		return fmt.Sprintf("Via(%d)", uint8(v))
	}
}

// ClientAddr is how the app's resolver ([Config.ClientAddr]) answered for the
// caller; the library never reads a forwarding header to decide an address.
// The zero value is ViaUnknown and plain.
type ClientAddr struct {
	Peer      netip.Addr // the connection's remote address, unmapped
	Forwarded netip.Addr // the client a trusted proxy forwarded; read only under ViaProxy
	Via       Via
	// Secure reports that the request crossed no network in clear: TLS
	// ended at this server or at a proxy the resolver trusts.
	Secure bool
}

// IP is the client address: Forwarded under ViaProxy, else Peer.
func (c ClientAddr) IP() netip.Addr {
	if c.Via == ViaProxy {
		return c.Forwarded
	}
	return c.Peer
}

// ClientAddr returns the Config.ClientAddr resolver's answer for r as it
// is, Via included; every address the library records or limits on comes
// from it.
func (a *Authenticator) ClientAddr(r *http.Request) ClientAddr { return a.cfg.ClientAddr(r) }

// defaultClientAddr is the resolver a nil Config.ClientAddr means; Peer is
// the zero Addr when r.RemoteAddr does not parse.
func defaultClientAddr(r *http.Request) ClientAddr {
	var peer netip.Addr
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		peer = ap.Addr().Unmap()
	} else if addr, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		peer = addr.Unmap()
	}
	secure := r.TLS != nil
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Real-Ip", "X-Forwarded-Proto"} {
		if len(r.Header.Values(name)) > 0 {
			return ClientAddr{Peer: peer, Via: ViaUntrustedForwarding, Secure: secure}
		}
	}
	return ClientAddr{Peer: peer, Via: ViaDirect, Secure: secure}
}

// activityIP is addr in [Session.LastIP]'s form, or "" when unknown.
func activityIP(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}
