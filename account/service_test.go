package account_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/printcheck"
	"github.com/cplieger/access/oidc"
)

func TestNewRefuses(t *testing.T) {
	t.Parallel()
	base := newFixture(t, options{}).cfg
	var nilStore *accesstest.MemStore
	cases := []struct {
		edit  func(*account.Config)
		name  string
		field string
	}{
		{name: "nil_store", field: "Store", edit: func(c *account.Config) { c.Store = nil }},
		{name: "typed_nil_store", field: "Store", edit: func(c *account.Config) { c.Store = nilStore }},
		{name: "nil_policy", field: "Policy", edit: func(c *account.Config) { c.Policy = nil }},
		{name: "nil_authenticator", field: "Authenticator", edit: func(c *account.Config) { c.Authenticator = nil }},
		{name: "nil_hasher", field: "Hasher", edit: func(c *account.Config) { c.Hasher = nil }},
		{name: "nil_limiter", field: "Limiter", edit: func(c *account.Config) { c.Limiter = nil }},
		{name: "nil_rules", field: "Rules", edit: func(c *account.Config) { c.Rules = nil }},
		{name: "failure_key_31", field: "FailureKey", edit: func(c *account.Config) { c.FailureKey = c.FailureKey[:31] }},
		{name: "failure_key_33", field: "FailureKey", edit: func(c *account.Config) { c.FailureKey = append(c.FailureKey, 'x') }},
		{name: "failure_key_nil", field: "FailureKey", edit: func(c *account.Config) { c.FailureKey = nil }},
		{name: "users_equals_keys", field: "CreateKeysScope", edit: func(c *account.Config) {
			c.ManageUsersScope, c.CreateKeysScope = "delegate", "delegate"
		}},
		{name: "users_equals_admin", field: "ManageUsersScope", edit: func(c *account.Config) {
			c.AdminScope, c.ManageUsersScope = "admin", "admin"
		}},
		{name: "keys_equals_admin", field: "CreateKeysScope", edit: func(c *account.Config) {
			c.AdminScope, c.CreateKeysScope = "admin", "admin"
		}},
		{name: "negative_interval", field: "CleanupInterval", edit: func(c *account.Config) { c.CleanupInterval = -time.Second }},
		{name: "negative_max_pending", field: "MaxPending", edit: func(c *account.Config) { c.MaxPending = -1 }},
		{name: "invalid_rules", field: "RecentAuth", edit: func(c *account.Config) {
			c.Rules = func() account.Rules { return account.Rules{RecentAuth: 30 * time.Second} }
		}},
		{name: "breach_fail_open_without_client", field: "Breach", edit: func(c *account.Config) {
			c.Rules = func() account.Rules { return account.Rules{Breach: account.BreachFailOpen} }
		}},
		{name: "breach_fail_closed_without_client", field: "Breach", edit: func(c *account.Config) {
			c.Rules = func() account.Rules { return account.Rules{Breach: account.BreachFailClosed} }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := base
			cfg.FailureKey = bytes.Clone(base.FailureKey)
			tc.edit(&cfg)
			svc, err := account.New(t.Context(), cfg)
			if err == nil {
				_ = svc.Shutdown(t.Context())
				t.Fatal("New() error = nil, want a refusal")
			}
			if svc != nil {
				t.Errorf("New() = %v, want nil with the error", svc)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("New() error = %q, want it to name %s", err, tc.field)
			}
			if printcheck.Leak(err.Error(), string(testFailureKey[:31])) {
				t.Errorf("New() error = %q holds the failure key", err)
			}
		})
	}
	t.Run("breach_mode_with_client", func(t *testing.T) {
		t.Parallel()
		cfg := base
		cfg.Rules = func() account.Rules { return account.Rules{Breach: account.BreachFailOpen} }
		cfg.Breach = &http.Client{}
		svc, err := account.New(t.Context(), cfg)
		if err != nil {
			t.Fatalf("New(BreachFailOpen with a client) error = %v, want nil", err)
		}
		_ = svc.Shutdown(t.Context())
	})
	t.Run("rules_error_matches", func(t *testing.T) {
		t.Parallel()
		cfg := base
		cfg.Rules = func() account.Rules { return account.Rules{Breach: account.BreachFailOpen} }
		_, err := account.New(t.Context(), cfg)
		var re *account.RulesError
		if !errors.Is(err, account.ErrRulesInvalid) || !errors.As(err, &re) || re.Field != "Breach" {
			t.Errorf("New(BreachFailOpen, nil client) error = %v, want a *RulesError for Breach matching ErrRulesInvalid", err)
		}
	})
	t.Run("caller_key_slice_not_kept", func(t *testing.T) {
		t.Parallel()
		cfg := base
		cfg.FailureKey = bytes.Clone(testFailureKey)
		svc, err := account.New(t.Context(), cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
		names := []string{"alice", "bob", ""}
		before := make([]string, len(names))
		for i, n := range names {
			before[i] = account.FailureName(svc, n)
		}
		clear(cfg.FailureKey)
		for i, n := range names {
			if got := account.FailureName(svc, n); got != before[i] {
				t.Errorf("FailureName(%q) after zeroing the caller's key = %s, want %s", n, got, before[i])
			}
		}
		other, err := account.New(t.Context(), cfg)
		if err != nil {
			t.Fatalf("New(zeroed key): %v", err)
		}
		t.Cleanup(func() { _ = other.Shutdown(context.Background()) })
		if account.FailureName(other, "alice") == before[0] {
			t.Error("a Service under another key names alice's records the same")
		}
	})
}

func TestServicePrinting(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{edit: func(c *account.Config) {
		c.OIDC = func() *oidc.Provider { return nil }
	}})
	if got := account.FailureName(f.svc, "alice"); len(got) != 64 {
		t.Fatalf("FailureName = %q, want 64 hex characters", got)
	}
	t.Run("routes", func(t *testing.T) {
		t.Parallel()
		// %p and the value form reach the fields by reflection, without any
		// Format; reflect copies the value, which no direct dereference may.
		value := reflect.ValueOf(f.svc).Elem().Interface()
		routes := map[string]string{}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%p"} {
			routes["pointer "+verb] = fmt.Sprintf(verb, f.svc)
			routes["value "+verb] = fmt.Sprintf(verb, value)
		}
		var text, js strings.Builder
		slog.New(slog.NewTextHandler(&text, nil)).Info("s", "svc", f.svc, "value", value)
		slog.New(slog.NewJSONHandler(&js, nil)).Info("s", "svc", f.svc, "value", value)
		routes["slog text"], routes["slog json"] = text.String(), js.String()
		for route, got := range routes {
			if printcheck.Leak(got, string(testFailureKey)) {
				t.Errorf("%s printed the failure key in a KeyForms form: %s", route, got)
			}
		}
	})
	t.Run("type_graph", func(t *testing.T) {
		t.Parallel()
		allow := printcheck.Allow{
			Masked: []reflect.Type{reflect.TypeFor[access.Secret](), reflect.TypeFor[access.Hash]()},
			// Each has its own printing test, or holds no secret: the app's
			// store and policy, the shared collaborators, and the pending
			// ceremonies' public challenge state and user records.
			Types: []string{
				"access.Authenticator", "ratelimit.Limiter", "http.Client",
				"slog.Logger", "webauthn.Ceremony", "access.User", "time.Time",
			},
			Fields: []string{
				"account.Service.store", "account.Service.policy",
				// Config.Hasher behind the hashing interface: Argon2
				// parameters and a budget, no secret.
				"account.Service.hasher",
				"account.Service.adminScope", "account.Service.usersScope", "account.Service.keysScope",
				// The 256-bit ceremony ID only names an entry, as the map key
				// and on the entry; finishing a ceremony still needs the
				// authenticator's signature.
				"account.pendingEntry.id", "account.pendingCache.byID",
			},
		}
		for _, line := range printcheck.Unmasked(allow, reflect.TypeFor[*account.Service]()) {
			t.Error(line)
		}
	})
}

func TestRulesValidate(t *testing.T) {
	t.Parallel()
	valid := []account.Rules{
		{},
		{RecentAuth: time.Minute, MaxSessionsPerUser: 50, Breach: account.BreachFailClosed},
		{Provisioning: oidc.Provisioning{Enabled: true, Claim: "groups", AllowedValues: []string{"staff"}}},
	}
	for i, r := range valid {
		if err := r.Validate(); err != nil {
			t.Errorf("valid rules %d: Validate() = %v, want nil", i, err)
		}
	}
	for name, tc := range map[string]struct {
		field string
		r     account.Rules
	}{
		"recent_auth_below_1m":  {field: "RecentAuth", r: account.Rules{RecentAuth: time.Minute - time.Nanosecond}},
		"recent_auth_negative":  {field: "RecentAuth", r: account.Rules{RecentAuth: -time.Minute}},
		"breach_unknown":        {field: "Breach", r: account.Rules{Breach: account.BreachFailClosed + 1}},
		"breach_negative":       {field: "Breach", r: account.Rules{Breach: -1}},
		"max_sessions_negative": {field: "MaxSessionsPerUser", r: account.Rules{MaxSessionsPerUser: -1}},
		"provisioning":          {field: "Provisioning", r: account.Rules{Provisioning: oidc.Provisioning{Enabled: true, Claim: "groups"}}},
	} {
		err := tc.r.Validate()
		var re *account.RulesError
		if !errors.As(err, &re) || re.Field != tc.field || !errors.Is(err, account.ErrRulesInvalid) {
			t.Errorf("%s: Validate() = %v, want a *RulesError for %s matching ErrRulesInvalid", name, err, tc.field)
		}
	}
}

func TestRulesReadOncePerOperation(t *testing.T) {
	t.Parallel()
	var breach bool
	var calls int
	f := newFixture(t, options{rules: func() account.Rules {
		calls++
		if breach {
			return account.Rules{Breach: account.BreachFailOpen}
		}
		return account.Rules{RecentAuth: 2 * time.Minute}
	}})
	u := mustUser(t, f.mem, "alice", access.RoleAdmin)
	p := f.sessionPrincipal(t, u, access.SessionFull, time.Now().Add(-90*time.Second))
	calls = 0
	if err := f.svc.RequireRecentAuth(p); err != nil {
		t.Errorf("RequireRecentAuth(a 90s-old sign-in, RecentAuth 2m) = %v, want nil", err)
	}
	if calls != 1 {
		t.Errorf("one RequireRecentAuth read Rules() %d times, want 1", calls)
	}
	r, err := account.Begin(f.svc)
	if err != nil || r.RecentAuth != 2*time.Minute {
		t.Errorf("Begin() = %v, %v, want RecentAuth 2m and nil", r.RecentAuth, err)
	}
	breach = true
	err = f.svc.RequireRecentAuth(p)
	var re *account.RulesError
	if !errors.Is(err, account.ErrRulesInvalid) || !errors.As(err, &re) || re.Field != "Breach" {
		t.Errorf("RequireRecentAuth under BreachFailOpen with no client = %v, want ErrRulesInvalid naming Breach", err)
	}
	if n := errorLogs(f.logs); n != 1 {
		t.Errorf("the invalid rules logged %d ERROR lines, want 1", n)
	}
	breach = false
	if r, err := account.Begin(f.svc); err != nil || r.RecentAuth != 2*time.Minute {
		t.Errorf("Begin() after a valid reload = %v, %v, want 2m and nil", r.RecentAuth, err)
	}
}

func TestRulesDefaults(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{rules: func() account.Rules { return account.Rules{} }})
	r, err := account.Begin(f.svc)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if r.RecentAuth != 10*time.Minute {
		t.Errorf("the zero RecentAuth reads as %v, want 10m", r.RecentAuth)
	}
	u := mustUser(t, f.mem, "alice", access.RoleAdmin)
	if err := f.svc.RequireRecentAuth(f.sessionPrincipal(t, u, access.SessionFull, time.Now().Add(-9*time.Minute))); err != nil {
		t.Errorf("RequireRecentAuth(9 minutes old) under the default = %v, want nil", err)
	}
	if err := f.svc.RequireRecentAuth(f.sessionPrincipal(t, u, access.SessionFull, time.Now().Add(-11*time.Minute))); !errors.Is(err, access.ErrRecentAuthRequired) {
		t.Errorf("RequireRecentAuth(11 minutes old) under the default = %v, want ErrRecentAuthRequired", err)
	}
}

func TestPasswordLoginDefault(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		rules account.Rules
		want  bool
	}{
		"zero_rules_allow": {want: true},
		"disabled":         {rules: account.Rules{DisablePasswordLogin: true}},
	} {
		f := newFixture(t, options{rules: func() account.Rules { return tc.rules }})
		st, err := f.svc.State(t.Context())
		if err != nil || st.PasswordLogin != tc.want {
			t.Errorf("%s: State().PasswordLogin = %t, %v, want %t", name, st.PasswordLogin, err, tc.want)
		}
	}
}

func TestAccessors(t *testing.T) {
	t.Parallel()
	first, second := &oidc.Provider{}, &oidc.Provider{}
	var current atomic.Pointer[oidc.Provider]
	current.Store(first)
	f := newFixture(t, options{edit: func(c *account.Config) {
		c.AdminScope, c.ManageUsersScope, c.CreateKeysScope = "admin", "manage_users", "create_keys"
		c.OIDC = current.Load
	}})
	if f.svc.Authenticator() != f.authn {
		t.Error("Authenticator() is not Config.Authenticator")
	}
	if got := []string{f.svc.AdminScope(), f.svc.ManageUsersScope(), f.svc.CreateKeysScope()}; got[0] != "admin" || got[1] != "manage_users" || got[2] != "create_keys" {
		t.Errorf("scope accessors = %q, want the Config fields", got)
	}
	if f.svc.OIDCProvider() != first {
		t.Error("OIDCProvider() is not Config.OIDC's provider")
	}
	current.Store(second)
	if f.svc.OIDCProvider() != second {
		t.Error("OIDCProvider() after the app swapped its provider is not the new one")
	}
	current.Store(nil)
	if f.svc.OIDCProvider() != nil {
		t.Error("OIDCProvider() with a nil result is not nil")
	}
	none := newFixture(t, options{})
	if none.svc.OIDCProvider() != nil {
		t.Error("OIDCProvider() with a nil Config.OIDC is not nil")
	}
}
