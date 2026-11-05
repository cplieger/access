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
			want:   ClientAddr{IP: netip.MustParseAddr("10.0.0.5"), Peer: netip.MustParseAddr("10.0.0.5"), UntrustedForwarding: true},
		},
		{
			name: "Forwarded", remoteAddr: "10.0.0.5:4711", header: http.Header{"Forwarded": {"for=203.0.113.9"}},
			want: ClientAddr{IP: netip.MustParseAddr("10.0.0.5"), Peer: netip.MustParseAddr("10.0.0.5"), UntrustedForwarding: true},
		},
		{
			name: "X-Real-IP", remoteAddr: "10.0.0.5:4711", header: http.Header{"X-Real-Ip": {"203.0.113.9"}},
			want: ClientAddr{IP: netip.MustParseAddr("10.0.0.5"), Peer: netip.MustParseAddr("10.0.0.5"), UntrustedForwarding: true},
		},
		{
			name: "direct peer", remoteAddr: "192.0.2.1:80",
			want: ClientAddr{IP: netip.MustParseAddr("192.0.2.1"), Peer: netip.MustParseAddr("192.0.2.1")},
		},
		{
			name: "4in6 is unmapped", remoteAddr: "[::ffff:10.0.0.5]:4711",
			want: ClientAddr{IP: netip.MustParseAddr("10.0.0.5"), Peer: netip.MustParseAddr("10.0.0.5")},
		},
		{
			name: "IPv6", remoteAddr: "[2001:db8::1]:443",
			want: ClientAddr{IP: netip.MustParseAddr("2001:db8::1"), Peer: netip.MustParseAddr("2001:db8::1")},
		},
		{
			name: "address without a port", remoteAddr: "192.0.2.1",
			want: ClientAddr{IP: netip.MustParseAddr("192.0.2.1"), Peer: netip.MustParseAddr("192.0.2.1")},
		},
		{name: "unparseable", remoteAddr: "@pipe", want: ClientAddr{}},
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

// TestConfigClientAddrServed pins the resolver as the one source of the
// address: Authenticator.ClientAddr returns it, and the session activity
// write records its IP as LastIP.
func TestConfigClientAddrServed(t *testing.T) {
	t.Parallel()
	want := ClientAddr{IP: netip.MustParseAddr("203.0.113.9"), Peer: netip.MustParseAddr("10.0.0.5"), Proxied: true}
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
