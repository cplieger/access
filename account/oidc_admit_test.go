package account_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
)

// admitFixture is a Service under posture whose limiter admits one request
// per IP an hour, with OIDC resolving to provider (nil: OIDC off).
func admitFixture(t *testing.T, posture access.CookiePosture, provider *oidc.Provider) (*fixture, *ratelimit.Limiter) {
	t.Helper()
	lcfg := ratelimit.DefaultConfig()
	lcfg.Devices = access.NewEphemeralSealer()
	lcfg.Request = ratelimit.Rate{Limit: 1, Window: time.Hour}
	limiter, err := ratelimit.New(t.Context(), lcfg)
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	t.Cleanup(func() { _ = limiter.Shutdown(context.Background()) })
	f := newFixture(t, options{posture: posture, edit: func(c *account.Config) {
		c.Limiter = limiter
		c.OIDC = func() *oidc.Provider { return provider }
	}})
	return f, limiter
}

// requireUncharged fails unless c's IP still has its one request: a call
// that charged it leaves this one refused.
func requireUncharged(t *testing.T, l *ratelimit.Limiter, c account.Client) {
	t.Helper()
	if err := l.Request(ratelimit.IPKey(c.IP())); err != nil {
		t.Errorf("Limiter.Request after the refusal = %v, want admitted: the refusal charged the IP", err)
	}
}

func TestAdmitOIDC(t *testing.T) {
	t.Parallel()
	rig := newOIDCRig(t, accesstest.IdPOptions{})
	t.Run("closed", func(t *testing.T) {
		t.Parallel()
		f, limiter := admitFixture(t, access.PostureSecure, rig.provider)
		if err := f.svc.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		p, err := f.svc.AdmitOIDC(localClient)
		if !errors.Is(err, account.ErrServiceClosed) || p != nil {
			t.Errorf("AdmitOIDC after Shutdown = %p, %v, want nil, ErrServiceClosed", p, err)
		}
		requireUncharged(t, limiter, localClient)
	})
	t.Run("no_provider", func(t *testing.T) {
		t.Parallel()
		f, limiter := admitFixture(t, access.PostureSecure, nil)
		p, err := f.svc.AdmitOIDC(localClient)
		if !errors.Is(err, account.ErrOIDCUnavailable) || p != nil {
			t.Errorf("AdmitOIDC with OIDC off = %p, %v, want nil, ErrOIDCUnavailable", p, err)
		}
		requireUncharged(t, limiter, localClient)
	})
	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		for _, posture := range []access.CookiePosture{access.PosturePerRequest, access.PostureSecure} {
			for _, provider := range []*oidc.Provider{rig.provider, nil} {
				f, limiter := admitFixture(t, posture, provider)
				plain := plainClientOf()
				p, err := f.svc.AdmitOIDC(plain)
				if !errors.Is(err, access.ErrHTTPSRequired) || p != nil {
					t.Errorf("%s, OIDC on %t: plain AdmitOIDC = %p, %v, want nil, ErrHTTPSRequired", posture, provider != nil, p, err)
				}
				requireUncharged(t, limiter, plain)
			}
		}
	})
	t.Run("window_refusal", func(t *testing.T) {
		t.Parallel()
		f, _ := admitFixture(t, access.PostureSecure, rig.provider)
		if _, err := f.svc.AdmitOIDC(localClient); err != nil {
			t.Fatalf("first AdmitOIDC = %v, want admitted", err)
		}
		p, err := f.svc.AdmitOIDC(localClient)
		if _, refused := errors.AsType[*ratelimit.RefusedError](err); !refused || p != nil {
			t.Errorf("second AdmitOIDC from one IP = %p, %v, want nil, *ratelimit.RefusedError", p, err)
		}
		if _, err := f.svc.AdmitOIDC(clientAt(1)); err != nil {
			t.Errorf("AdmitOIDC from another IP = %v, want admitted", err)
		}
	})
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		f, limiter := admitFixture(t, access.PostureSecure, rig.provider)
		p, err := f.svc.AdmitOIDC(localClient)
		if err != nil || p != rig.provider {
			t.Fatalf("AdmitOIDC = %p, %v, want the configured provider %p", p, err, rig.provider)
		}
		if err := limiter.Request(ratelimit.IPKey(localClient.IP())); !errors.Is(err, ratelimit.ErrRefused) {
			t.Errorf("Limiter.Request after an admission = %v, want refused: AdmitOIDC charged nothing", err)
		}
	})
}

func TestAdmitOIDCSession(t *testing.T) {
	t.Parallel()
	rig := newOIDCRig(t, accesstest.IdPOptions{})
	// session is a secure full session's principal in f, and f's
	// limiter.
	session := func(t *testing.T, posture access.CookiePosture, provider *oidc.Provider) (*fixture, *ratelimit.Limiter, access.Principal) {
		t.Helper()
		f, limiter := admitFixture(t, posture, provider)
		u := mustUser(t, f.mem, "alice", access.RoleUser)
		return f, limiter, f.sessionPrincipal(t, u, access.SessionFull, time.Now())
	}
	t.Run("closed", func(t *testing.T) {
		t.Parallel()
		f, _, sess := session(t, access.PosturePerRequest, rig.provider)
		if err := f.svc.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		plain := sess
		plain.Secure = false
		for _, c := range []account.Client{localClient, plainClientOf()} {
			p, err := f.svc.AdmitOIDCSession(c, plain)
			if !errors.Is(err, account.ErrServiceClosed) || p != nil {
				t.Errorf("AdmitOIDCSession(Secure %t) after Shutdown = %p, %v, want nil, ErrServiceClosed", c.Secure, p, err)
			}
		}
	})
	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		for _, posture := range []access.CookiePosture{access.PosturePerRequest, access.PostureSecure} {
			for _, provider := range []*oidc.Provider{rig.provider, nil} {
				f, limiter, sess := session(t, posture, provider)
				plainSession := sess
				plainSession.Secure = false
				for _, in := range []struct {
					name string
					c    account.Client
					p    access.Principal
				}{
					{"plain_client", plainClientOf(), sess},
					{"plain_principal", localClient, plainSession},
					{"both_plain", plainClientOf(), plainSession},
				} {
					p, err := f.svc.AdmitOIDCSession(in.c, in.p)
					if !errors.Is(err, access.ErrHTTPSRequired) || p != nil {
						t.Errorf("%s, OIDC on %t, %s: AdmitOIDCSession = %p, %v, want nil, ErrHTTPSRequired", posture, provider != nil, in.name, p, err)
					}
				}
				requireUncharged(t, limiter, localClient)
			}
		}
	})
	t.Run("no_provider", func(t *testing.T) {
		t.Parallel()
		f, _, sess := session(t, access.PosturePerRequest, nil)
		p, err := f.svc.AdmitOIDCSession(localClient, sess)
		if !errors.Is(err, account.ErrOIDCUnavailable) || p != nil {
			t.Errorf("AdmitOIDCSession with OIDC off = %p, %v, want nil, ErrOIDCUnavailable", p, err)
		}
	})
	t.Run("success", func(t *testing.T) {
		t.Parallel()
		f, limiter, sess := session(t, access.PostureSecure, rig.provider)
		p, err := f.svc.AdmitOIDCSession(localClient, sess)
		if err != nil || p != rig.provider {
			t.Fatalf("AdmitOIDCSession = %p, %v, want the configured provider %p", p, err, rig.provider)
		}
		requireUncharged(t, limiter, localClient)
	})
}
