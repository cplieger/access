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

// admitFixture is a Service whose limiter admits one request per IP an
// hour, with OIDC resolving to provider (nil: OIDC off).
func admitFixture(t *testing.T, provider *oidc.Provider) (*fixture, *ratelimit.Limiter) {
	t.Helper()
	lcfg := ratelimit.DefaultConfig()
	lcfg.Devices = access.NewEphemeralSealer()
	lcfg.Request = ratelimit.Rate{Limit: 1, Window: time.Hour}
	limiter, err := ratelimit.New(t.Context(), lcfg)
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	t.Cleanup(func() { _ = limiter.Shutdown(context.Background()) })
	f := newFixture(t, options{edit: func(c *account.Config) {
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
		f, limiter := admitFixture(t, rig.provider)
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
		f, limiter := admitFixture(t, nil)
		p, err := f.svc.AdmitOIDC(localClient)
		if !errors.Is(err, account.ErrOIDCUnavailable) || p != nil {
			t.Errorf("AdmitOIDC with OIDC off = %p, %v, want nil, ErrOIDCUnavailable", p, err)
		}
		requireUncharged(t, limiter, localClient)
	})
	t.Run("window_refusal", func(t *testing.T) {
		t.Parallel()
		f, _ := admitFixture(t, rig.provider)
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
		f, limiter := admitFixture(t, rig.provider)
		p, err := f.svc.AdmitOIDC(localClient)
		if err != nil || p != rig.provider {
			t.Fatalf("AdmitOIDC = %p, %v, want the configured provider %p", p, err, rig.provider)
		}
		if err := limiter.Request(ratelimit.IPKey(localClient.IP())); !errors.Is(err, ratelimit.ErrRefused) {
			t.Errorf("Limiter.Request after an admission = %v, want refused: AdmitOIDC charged nothing", err)
		}
	})
}
