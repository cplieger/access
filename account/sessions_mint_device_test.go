package account_test

import (
	"testing"

	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
)

// TestDeviceCookieEveryFullSessionPath holds every path that creates a
// full session to returning a device cookie the limiter trusts for the
// signed-in account, whatever its limiter reservation was: an IP-only one
// (password setup, invite acceptance) included.
func TestDeviceCookieEveryFullSessionPath(t *testing.T) {
	t.Parallel()
	for _, p := range creationPaths() {
		if p.name == "recovery_start" {
			// A recovery session is restricted and account.Recovery carries
			// no device cookie: recovery is not an authentication.
			continue
		}
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			f := newOIDCFixture(t, rigFor(t, "subject-"+p.name), pwOptions{rules: func() account.Rules {
				return account.Rules{SetupTokenRequired: tokenless, Provisioning: oidc.Provisioning{Enabled: true}}
			}})
			in, _, err := p.run(t, f, localClient)
			if err != nil || in.User == nil {
				t.Fatalf("creating call = %+v, %v; want a session", in, err)
			}
			if in.DeviceCookie.IsZero() {
				t.Fatal("no device cookie returned")
			}
			res, err := f.limiter.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(localClient.IP()), Account: ratelimit.AccountKey(in.User.Username), Device: in.DeviceCookie})
			if err != nil {
				t.Fatalf("Attempt: %v", err)
			}
			defer res.Cancel()
			if !res.Trusted() {
				t.Errorf("the device cookie is not trusted for %s", in.User.Username)
			}
		})
	}
}
