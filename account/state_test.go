package account_test

import (
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/webauthn"
)

const stateOrigin = "https://grelot.example"

// stateConfig is what a State fixture offers.
type stateConfig struct {
	timeouts   *access.SessionTimeouts // nil: the Authenticator's default
	posture    access.CookiePosture
	noPassword bool // Rules.DisablePasswordLogin
	passkeys   bool
	oidc       bool
	setupDone  bool // a user exists
}

func stateFixture(t *testing.T, sc stateConfig) *fixture {
	t.Helper()
	o := options{posture: sc.posture, rules: func() account.Rules {
		return account.Rules{DisablePasswordLogin: sc.noPassword, HTTPSOrigin: stateOrigin}
	}}
	if sc.timeouts != nil {
		o.timeouts = func() access.SessionTimeouts { return *sc.timeouts }
	}
	rp := newRP(t)
	o.edit = func(c *account.Config) {
		if sc.passkeys {
			c.RP = func() *webauthn.RelyingParty { return rp }
		}
		if sc.oidc {
			c.OIDC = func() *oidc.Provider { return &oidc.Provider{} }
		}
	}
	f := newFixture(t, o)
	if sc.setupDone {
		mustUser(t, f.mem, "root", access.RoleAdmin)
	}
	return f
}

// requireState fails unless got equals want, HTTPSRequired compared as a
// list so nil and empty agree.
func requireState(t *testing.T, got, want account.State) {
	t.Helper()
	gotList, wantList := got.HTTPSRequired, want.HTTPSRequired
	got.HTTPSRequired, want.HTTPSRequired = nil, nil
	if !slices.Equal(gotList, wantList) || !reflect.DeepEqual(got, want) {
		got.HTTPSRequired, want.HTTPSRequired = gotList, wantList
		t.Errorf("State = %+v (plain session %v), want %+v (plain session %v)", got, got.PlainSession, want, want.PlainSession)
	}
}

// TestStateTransport is State's answer per posture and transport:
// docs/plain-http.md's sign-in screen states.
func TestStateTransport(t *testing.T) {
	t.Parallel()
	plain, secure := localClient, localClient
	plain.Secure = false
	everything := stateConfig{passkeys: true, oidc: true}
	defaultPlain := &access.SessionTimeouts{Idle: access.PlainSessionIdle, Absolute: access.PlainSessionAbsolute}
	all := []account.HTTPSFeature{account.HTTPSPassword, account.HTTPSSetup, account.HTTPSPasskeys, account.HTTPSOIDC}
	for name, tc := range map[string]struct {
		config stateConfig
		client account.Client
		want   account.State
	}{
		"per_request_secure": {
			config: underPosture(everything, access.PosturePerRequest), client: secure,
			want: account.State{SetupRequired: true, PasswordLogin: true, Passkeys: true, OIDC: true, Secure: true},
		},
		"posture_secure_secure": {
			config: underPosture(everything, access.PostureSecure), client: secure,
			want: account.State{SetupRequired: true, PasswordLogin: true, Passkeys: true, OIDC: true, Secure: true},
		},
		"per_request_plain": {
			config: underPosture(everything, access.PosturePerRequest), client: plain,
			want: account.State{
				SetupRequired: true, PasswordLogin: true, PlainSession: defaultPlain,
				HTTPSRequired: []account.HTTPSFeature{account.HTTPSPasskeys, account.HTTPSOIDC}, HTTPSOrigin: stateOrigin,
			},
		},
		"per_request_plain_oidc_unconfigured": {
			config: stateConfig{posture: access.PosturePerRequest, passkeys: true}, client: plain,
			want: account.State{
				SetupRequired: true, PasswordLogin: true, PlainSession: defaultPlain,
				HTTPSRequired: []account.HTTPSFeature{account.HTTPSPasskeys}, HTTPSOrigin: stateOrigin,
			},
		},
		"per_request_plain_password_only": {
			config: stateConfig{posture: access.PosturePerRequest, setupDone: true}, client: plain,
			want: account.State{PasswordLogin: true, PlainSession: defaultPlain, HTTPSOrigin: stateOrigin},
		},
		"per_request_plain_password_off": {
			config: stateConfig{posture: access.PosturePerRequest, noPassword: true, passkeys: true, setupDone: true}, client: plain,
			want: account.State{
				PlainSession: defaultPlain, HTTPSRequired: []account.HTTPSFeature{account.HTTPSPasskeys}, HTTPSOrigin: stateOrigin,
			},
		},
		"per_request_plain_15_minute_idle": {
			config: stateConfig{posture: access.PosturePerRequest, timeouts: &access.SessionTimeouts{Idle: 15 * time.Minute, Absolute: 7 * 24 * time.Hour}},
			client: plain,
			want: account.State{
				SetupRequired: true, PasswordLogin: true, HTTPSOrigin: stateOrigin,
				PlainSession: &access.SessionTimeouts{Idle: 15 * time.Minute, Absolute: access.PlainSessionAbsolute},
			},
		},
		"per_request_plain_short_absolute": {
			config: stateConfig{posture: access.PosturePerRequest, timeouts: &access.SessionTimeouts{Idle: time.Hour, Absolute: 2 * time.Hour}},
			client: plain,
			want: account.State{
				SetupRequired: true, PasswordLogin: true, HTTPSOrigin: stateOrigin,
				PlainSession: &access.SessionTimeouts{Idle: access.PlainSessionIdle, Absolute: 2 * time.Hour},
			},
		},
		"posture_secure_plain_setup_required": {
			config: underPosture(everything, access.PostureSecure), client: plain,
			want: account.State{SetupRequired: true, HTTPSRequired: all, HTTPSOrigin: stateOrigin},
		},
		"posture_secure_plain_setup_done": {
			config: stateConfig{posture: access.PostureSecure, setupDone: true, oidc: true}, client: plain,
			want: account.State{
				HTTPSRequired: []account.HTTPSFeature{account.HTTPSPassword, account.HTTPSOIDC}, HTTPSOrigin: stateOrigin,
			},
		},
		"posture_secure_plain_password_off": {
			config: stateConfig{posture: access.PostureSecure, setupDone: true, noPassword: true, passkeys: true}, client: plain,
			want: account.State{HTTPSRequired: []account.HTTPSFeature{account.HTTPSPasskeys}, HTTPSOrigin: stateOrigin},
		},
		"posture_secure_plain_setup_password_off": {
			config: stateConfig{posture: access.PostureSecure, noPassword: true}, client: plain,
			want: account.State{SetupRequired: true, HTTPSRequired: []account.HTTPSFeature{account.HTTPSSetup}, HTTPSOrigin: stateOrigin},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := stateFixture(t, tc.config).svc.State(t.Context(), tc.client)
			if err != nil {
				t.Fatalf("State: %v", err)
			}
			requireState(t, got, tc.want)
		})
	}
}

// underPosture is sc under posture.
func underPosture(sc stateConfig, posture access.CookiePosture) stateConfig {
	sc.posture = posture
	return sc
}

// TestStateRulesSwap: State reads Rules.HTTPSOrigin on every call, so a
// swapped Rules answers its origin on the next plain request.
func TestStateRulesSwap(t *testing.T) {
	t.Parallel()
	var origin atomic.Value
	origin.Store("https://first.example")
	f := newFixture(t, options{posture: access.PosturePerRequest, rules: func() account.Rules {
		return account.Rules{HTTPSOrigin: origin.Load().(string)}
	}})
	plain := localClient
	plain.Secure = false
	for _, want := range []string{"https://first.example", "https://second.example:8443"} {
		origin.Store(want)
		st, err := f.svc.State(t.Context(), plain)
		if err != nil || st.HTTPSOrigin != want {
			t.Errorf("plain State().HTTPSOrigin = %q, %v; want %q", st.HTTPSOrigin, err, want)
		}
	}
	if st, err := f.svc.State(t.Context(), localClient); err != nil || st.HTTPSOrigin != "" {
		t.Errorf("secure State().HTTPSOrigin = %q, %v; want none", st.HTTPSOrigin, err)
	}
}
