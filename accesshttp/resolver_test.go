package accesshttp

import (
	"context"
	"net/http"
	"net/netip"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// fixedResolver answers addr for every request.
func fixedResolver(addr access.ClientAddr) func(*http.Request) access.ClientAddr {
	return func(*http.Request) access.ClientAddr { return addr }
}

// recordingSetupRule records every Client the setup rule receives and
// answers rule's verdict for it.
func recordingSetupRule(seen *recorded[account.Client], rule func(context.Context, account.Client) bool) func(*account.Rules) {
	return func(r *account.Rules) {
		r.SetupTokenRequired = func(ctx context.Context, c account.Client) bool {
			seen.add(c)
			return rule(ctx, c)
		}
	}
}

func tokenless(context.Context, account.Client) bool { return false }

// lastIPs are the LastIP of every session name holds. A test reads them
// before requireSignedIn, whose own authenticated request records activity
// that would overwrite the IP the minting request stored.
func (e *env) lastIPs(t testing.TB, name string) []string {
	t.Helper()
	sessions, err := e.mem.SessionsByUserID(t.Context(), e.user(t, name).ID)
	if err != nil {
		t.Fatalf("SessionsByUserID: %v", err)
	}
	ips := make([]string, 0, len(sessions))
	for i := range sessions {
		ips = append(ips, sessions[i].LastIP)
	}
	return ips
}

func TestOneResolver(t *testing.T) {
	// Forwarded, Peer and httptest's RemoteAddr all differ, so each
	// consumer shows which of them it read.
	resolved := access.ClientAddr{Peer: netip.MustParseAddr("10.0.0.1"), Forwarded: netip.MustParseAddr("203.0.113.9"), Via: access.ViaProxy}
	resolver := func(_ *env, c *access.Config) { c.ClientAddr = fixedResolver(resolved) }

	t.Run("setup_rule_and_session", func(t *testing.T) {
		seen := &recorded[account.Client]{}
		e := newEnv(t, envOptions{authn: resolver, rules: recordingSetupRule(seen, tokenless)})
		w := do(e.route(t, "authSetupPassword"), e.post(t, "authSetupPassword", setupPasswordBody(t, "")))
		if got := seen.all(); len(got) != 1 || got[0].ClientAddr != resolved {
			t.Errorf("setup rule received %+v, want one Client carrying %+v", got, resolved)
		}
		if ips := e.lastIPs(t, "owner"); len(ips) != 1 || ips[0] != "203.0.113.9" {
			t.Errorf("setup session LastIP %v, want the resolved 203.0.113.9", ips)
		}
		e.requireSignedIn(t, w, "owner")
	})
	t.Run("sign_in_session", func(t *testing.T) {
		e := newEnv(t, envOptions{authn: resolver})
		e.createUser(t, "alice", access.RoleUser)
		w := do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", signInBody(t, "alice")))
		if ips := e.lastIPs(t, "alice"); len(ips) != 1 || ips[0] != "203.0.113.9" {
			t.Errorf("sign-in session LastIP %v, want the resolved 203.0.113.9", ips)
		}
		e.requireSignedIn(t, w, "alice")
	})
	t.Run("limiter_ip_key", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			spent netip.Addr
			want  int
		}{
			{"resolved_ip_spent", resolved.IP(), http.StatusTooManyRequests},
			{"peer_spent", resolved.Peer, http.StatusOK},
			{"remote_addr_spent", testClientIP, http.StatusOK},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := newEnv(t, envOptions{authn: resolver, limits: ipLimit})
				e.createUser(t, "alice", access.RoleUser)
				e.spendAttemptOf(t, tc.spent)
				if w := do(e.route(t, "authLoginPassword"), e.post(t, "authLoginPassword", signInBody(t, "alice"))); w.Code != tc.want {
					t.Errorf("sign-in after spending %s's attempt answered %d, errors %+v; want %d", tc.spent, w.Code, e.errs.all(), tc.want)
				}
			})
		}
	})
	t.Run("default_resolver", func(t *testing.T) {
		seen := &recorded[account.Client]{}
		e := newEnv(t, envOptions{rules: recordingSetupRule(seen, tokenless)})
		r := e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
		r.RemoteAddr = "10.0.0.5:4711"
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		w := do(e.route(t, "authSetupPassword"), r)
		peer := netip.MustParseAddr("10.0.0.5")
		want := access.ClientAddr{Peer: peer, Via: access.ViaUntrustedForwarding}
		if got := seen.all(); len(got) != 1 || got[0].ClientAddr != want {
			t.Errorf("setup rule received %+v, want one Client carrying %+v", got, want)
		}
		if ips := e.lastIPs(t, "owner"); len(ips) != 1 || ips[0] != "10.0.0.5" {
			t.Errorf("setup session LastIP %v, want the socket peer 10.0.0.5", ips)
		}
		e.requireSignedIn(t, w, "owner")
	})
}

// proxyResolver trusts proxy alone: its X-Forwarded-For names the client,
// and any other peer's forwarding header is ignored and reported.
func proxyResolver(proxy netip.Addr) func(*http.Request) access.ClientAddr {
	return func(r *http.Request) access.ClientAddr {
		peer := netip.MustParseAddrPort(r.RemoteAddr).Addr()
		forwarded := r.Header.Get("X-Forwarded-For")
		c := access.ClientAddr{Peer: peer}
		switch {
		case peer == proxy && forwarded != "":
			c.Via, c.Forwarded = access.ViaProxy, netip.MustParseAddr(forwarded)
		case peer == proxy:
			c.Via = access.ViaProxyNoClient
		case forwarded != "":
			c.Via = access.ViaUntrustedForwarding
		default:
			c.Via = access.ViaDirect
		}
		return c
	}
}

// privateOnly asks for a token whenever the client is unknown or its
// address is public.
func privateOnly(_ context.Context, c account.Client) bool {
	return !c.ClientKnown() || !c.IP().IsPrivate() && !c.IP().IsLoopback()
}

// directLoopback is local for a direct loopback peer.
func directLoopback(a access.ClientAddr) bool {
	return a.Via == access.ViaDirect && a.IP().IsLoopback()
}

// everyoneLocal is local for every client, leaving the refusal to
// SetupLocality.
func everyoneLocal(access.ClientAddr) bool { return true }

func TestSetupProvenanceHTTP(t *testing.T) {
	proxy := netip.MustParseAddr("10.0.0.1")
	// unconsulted answers true like everyoneLocal, and fails the test if
	// called: an unknown client is refused before Local runs.
	unconsulted := func(a access.ClientAddr) bool {
		t.Errorf("Local consulted for %+v, want the unknown client refused first", a)
		return true
	}
	cases := []struct {
		name      string
		rule      func(context.Context, account.Client) bool
		remote    string
		host      string
		forwarded string
		refused   bool
	}{
		{"unlisted_private_peer_forwarded", privateOnly, "10.0.0.7:4711", testRPID, "192.168.1.20", true},
		{"direct_private_peer", privateOnly, "10.0.0.7:4711", testRPID, "", false},
		{"proxied_public_client", privateOnly, "10.0.0.1:4711", testRPID, "203.0.113.9", true},
		{"proxied_private_client", privateOnly, "10.0.0.1:4711", testRPID, "192.168.1.20", false},
		{"locality_rebound_host", account.SetupLocality{Local: directLoopback}.TokenRequired, "127.0.0.1:4711", "evil.example", "", true},
		{"locality_localhost", account.SetupLocality{Local: directLoopback}.TokenRequired, "127.0.0.1:4711", "localhost", "", false},
		{"zero_locality_localhost", account.SetupLocality{}.TokenRequired, "127.0.0.1:4711", "localhost", "", true},
		{"listed_proxy_no_forwarding", account.SetupLocality{Local: unconsulted}.TokenRequired, "10.0.0.1:4711", "localhost", "", true},
		{"listed_proxy_loopback_client", account.SetupLocality{Local: everyoneLocal}.TokenRequired, "10.0.0.1:4711", "localhost", "127.0.0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := &recorded[account.Client]{}
			returned := &recorded[access.ClientAddr]{}
			resolve := proxyResolver(proxy)
			e := newEnv(t, envOptions{
				authn: func(_ *env, c *access.Config) {
					c.ClientAddr = func(r *http.Request) access.ClientAddr {
						a := resolve(r)
						returned.add(a)
						return a
					}
				},
				rules: recordingSetupRule(seen, tc.rule),
			})
			r := e.post(t, "authSetupPassword", setupPasswordBody(t, ""))
			r.RemoteAddr, r.Host = tc.remote, tc.host
			if tc.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tc.forwarded)
			}
			if tc.refused {
				// With the hash budget held, a hash would answer auth_busy.
				e.holdBudget(t)
			}
			w := do(e.route(t, "authSetupPassword"), r)
			got, addrs := seen.all(), returned.all()
			if len(got) != 1 || len(addrs) != 1 || got[0].ClientAddr != addrs[0] || got[0].Host != tc.host {
				t.Errorf("setup rule received %+v, resolver returned %+v; want one Client carrying the resolver's answer and Host %q", got, addrs, tc.host)
			}
			if tc.refused {
				if errs := e.errs.all(); w.Code != http.StatusUnauthorized || len(errs) != 1 || errs[0].Code != CodeSetupTokenRequired {
					t.Errorf("status %d errors %+v, want 401 auth_setup_token_required before any hash", w.Code, errs)
				}
				if _, found, err := e.mem.UserByUsername(t.Context(), "owner"); err != nil || found {
					t.Errorf("owner stored = %t, %v after a refused setup", found, err)
				}
				return
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status %d errors %+v, want a token-free setup", w.Code, e.errs.all())
			}
			if u := e.user(t, "owner"); u.Role != access.RoleAdmin {
				t.Errorf("owner role %s, want admin", u.Role)
			}
		})
	}
}
