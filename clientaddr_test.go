package access

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestDefaultClientAddr(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		header     http.Header
		name       string
		remoteAddr string
		want       ClientAddr
	}{
		{
			name: "forwarded-for from an untrusted peer", remoteAddr: "10.0.0.5:4711",
			header: http.Header{"X-Forwarded-For": {"203.0.113.9"}},
			want:   ClientAddr{Peer: netip.MustParseAddr("10.0.0.5"), Via: ViaUntrustedForwarding},
		},
		{
			name: "Forwarded", remoteAddr: "10.0.0.5:4711", header: http.Header{"Forwarded": {"for=203.0.113.9"}},
			want: ClientAddr{Peer: netip.MustParseAddr("10.0.0.5"), Via: ViaUntrustedForwarding},
		},
		{
			name: "X-Real-IP", remoteAddr: "10.0.0.5:4711", header: http.Header{"X-Real-Ip": {"203.0.113.9"}},
			want: ClientAddr{Peer: netip.MustParseAddr("10.0.0.5"), Via: ViaUntrustedForwarding},
		},
		{
			name: "direct peer", remoteAddr: "192.0.2.1:80",
			want: ClientAddr{Peer: netip.MustParseAddr("192.0.2.1"), Via: ViaDirect},
		},
		{
			name: "4in6 is unmapped", remoteAddr: "[::ffff:10.0.0.5]:4711",
			want: ClientAddr{Peer: netip.MustParseAddr("10.0.0.5"), Via: ViaDirect},
		},
		{
			name: "IPv6", remoteAddr: "[2001:db8::1]:443",
			want: ClientAddr{Peer: netip.MustParseAddr("2001:db8::1"), Via: ViaDirect},
		},
		{
			name: "address without a port", remoteAddr: "192.0.2.1",
			want: ClientAddr{Peer: netip.MustParseAddr("192.0.2.1"), Via: ViaDirect},
		},
		{name: "unparseable", remoteAddr: "@pipe", want: ClientAddr{Via: ViaDirect}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := mustAuthenticator(t, newFakeSessionStore(), Config{})
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			maps.Copy(r.Header, tt.header)
			if got := a.ClientAddr(r); got != tt.want {
				t.Errorf("ClientAddr(%q, %v) = %+v, want %+v", tt.remoteAddr, tt.header, got, tt.want)
			}
		})
	}
}

var (
	testPeer      = netip.MustParseAddr("192.0.2.1")
	testForwarded = netip.MustParseAddr("203.0.113.9")
)

type clientAddrCase struct {
	wantIP          netip.Addr
	name            string
	c               ClientAddr
	wantClientKnown bool
}

// clientAddrTable is every Via value × {valid, invalid} Peer × {Forwarded
// set, unset}, with the IP and ClientKnown answers their definitions give.
var clientAddrTable = []clientAddrCase{
	{name: "unknown peer forwarded", c: ClientAddr{Peer: testPeer, Forwarded: testForwarded, Via: ViaUnknown}, wantIP: testPeer},
	{name: "unknown peer", c: ClientAddr{Peer: testPeer, Via: ViaUnknown}, wantIP: testPeer},
	{name: "unknown forwarded", c: ClientAddr{Forwarded: testForwarded, Via: ViaUnknown}},
	{name: "unknown empty", c: ClientAddr{Via: ViaUnknown}},
	{name: "direct peer forwarded", c: ClientAddr{Peer: testPeer, Forwarded: testForwarded, Via: ViaDirect}, wantIP: testPeer, wantClientKnown: true},
	{name: "direct peer", c: ClientAddr{Peer: testPeer, Via: ViaDirect}, wantIP: testPeer, wantClientKnown: true},
	{name: "direct forwarded", c: ClientAddr{Forwarded: testForwarded, Via: ViaDirect}},
	{name: "direct empty", c: ClientAddr{Via: ViaDirect}},
	{name: "untrusted peer forwarded", c: ClientAddr{Peer: testPeer, Forwarded: testForwarded, Via: ViaUntrustedForwarding}, wantIP: testPeer},
	{name: "untrusted peer", c: ClientAddr{Peer: testPeer, Via: ViaUntrustedForwarding}, wantIP: testPeer},
	{name: "untrusted forwarded", c: ClientAddr{Forwarded: testForwarded, Via: ViaUntrustedForwarding}},
	{name: "untrusted empty", c: ClientAddr{Via: ViaUntrustedForwarding}},
	{name: "proxy peer forwarded", c: ClientAddr{Peer: testPeer, Forwarded: testForwarded, Via: ViaProxy}, wantIP: testForwarded, wantClientKnown: true},
	{name: "proxy peer", c: ClientAddr{Peer: testPeer, Via: ViaProxy}},
	{name: "proxy forwarded", c: ClientAddr{Forwarded: testForwarded, Via: ViaProxy}, wantIP: testForwarded, wantClientKnown: true},
	{name: "proxy empty", c: ClientAddr{Via: ViaProxy}},
	{name: "proxy no client peer forwarded", c: ClientAddr{Peer: testPeer, Forwarded: testForwarded, Via: ViaProxyNoClient}, wantIP: testPeer},
	{name: "proxy no client peer", c: ClientAddr{Peer: testPeer, Via: ViaProxyNoClient}, wantIP: testPeer},
	{name: "proxy no client forwarded", c: ClientAddr{Forwarded: testForwarded, Via: ViaProxyNoClient}},
	{name: "proxy no client empty", c: ClientAddr{Via: ViaProxyNoClient}},
}

func TestClientAddrIP(t *testing.T) {
	t.Parallel()
	for _, tt := range clientAddrTable {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.c.IP(); got != tt.wantIP {
				t.Errorf("%+v.IP() = %v, want %v", tt.c, got, tt.wantIP)
			}
		})
	}
}

func TestClientKnown(t *testing.T) {
	t.Parallel()
	for _, tt := range clientAddrTable {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.c.ClientKnown(); got != tt.wantClientKnown {
				t.Errorf("%+v.ClientKnown() = %v, want %v", tt.c, got, tt.wantClientKnown)
			}
		})
	}
}

func TestViaString(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		want string
		via  Via
	}{
		{via: ViaUnknown, want: "ViaUnknown"},
		{via: ViaDirect, want: "ViaDirect"},
		{via: ViaUntrustedForwarding, want: "ViaUntrustedForwarding"},
		{via: ViaProxy, want: "ViaProxy"},
		{via: ViaProxyNoClient, want: "ViaProxyNoClient"},
		{via: Via(5), want: "Via(5)"},
	} {
		if got := tt.via.String(); got != tt.want {
			t.Errorf("Via(%d).String() = %q, want %q", uint8(tt.via), got, tt.want)
		}
	}
}

// TestConfigClientAddrServed pins the resolver as the one source of the
// address: Authenticator.ClientAddr returns it, and the session activity
// write records its IP as LastIP.
func TestConfigClientAddrServed(t *testing.T) {
	t.Parallel()
	want := ClientAddr{Peer: netip.MustParseAddr("10.0.0.5"), Forwarded: netip.MustParseAddr("203.0.113.9"), Via: ViaProxy}
	f := newChainFixture(t)
	a := mustAuthenticator(t, f.store, Config{ClientAddr: func(*http.Request) ClientAddr { return want }})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: f.session})
	if got := a.ClientAddr(r); got != want {
		t.Errorf("ClientAddr = %+v, want the resolver's %+v", got, want)
	}
	if _, err := a.Authenticate(r); err != nil {
		t.Fatalf("Authenticate(session) error = %v", err)
	}
	sess, _, _ := f.store.SessionByHash(t.Context(), SessionHash(f.session))
	if sess.LastIP != "203.0.113.9" {
		t.Errorf("LastIP = %q, want the resolver's IP 203.0.113.9", sess.LastIP)
	}
	if time.Since(sess.LastActivity) > time.Minute {
		t.Errorf("LastActivity = %v, want the activity just written", sess.LastActivity)
	}
}
