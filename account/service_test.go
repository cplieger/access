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
	"github.com/cplieger/access/webauthn"
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
		// RFC 6750 §3: each scope is quoted bare in a WWW-Authenticate
		// scope attribute, so only a scope-token is a scope.
		{name: "admin_scope_space", field: "AdminScope", edit: func(c *account.Config) { c.AdminScope = "all admin" }},
		{name: "users_scope_dquote", field: "ManageUsersScope", edit: func(c *account.Config) { c.ManageUsersScope = `manage"users` }},
		{name: "keys_scope_backslash", field: "CreateKeysScope", edit: func(c *account.Config) { c.CreateKeysScope = `create\keys` }},
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
		// Config.TOTP is optional, and a half-set value is refused.
		{name: "totp_sealer_without_issuer", field: "TOTP.Issuer", edit: func(c *account.Config) {
			c.TOTP = account.TOTPConfig{Sealer: access.NewEphemeralSealer()}
		}},
		{name: "totp_issuer_without_sealer", field: "TOTP.Sealer", edit: func(c *account.Config) { c.TOTP = account.TOTPConfig{Issuer: "Example"} }},
		{name: "totp_zero_sealer", field: "TOTP.Sealer", edit: func(c *account.Config) {
			c.TOTP = account.TOTPConfig{Sealer: &access.Sealer{}, Issuer: "Example"}
		}},
		// Key Uri Format: the issuer prefixes the label, where a colon is the separator.
		{name: "totp_issuer_colon", field: "TOTP.Issuer", edit: func(c *account.Config) {
			c.TOTP = account.TOTPConfig{Sealer: access.NewEphemeralSealer(), Issuer: "Ex:ample"}
		}},
		// RequireSecondFactor with no wired second factor.
		{name: "require_second_factor_unwired", field: "RequireSecondFactor", edit: func(c *account.Config) {
			c.Rules = func() account.Rules { return account.Rules{RequireSecondFactor: true} }
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
		cfg := ownAuthenticator(t, base)
		cfg.Rules = func() account.Rules { return account.Rules{Breach: account.BreachFailOpen} }
		cfg.Breach = &http.Client{}
		svc, err := account.New(t.Context(), cfg)
		if err != nil {
			t.Fatalf("New(BreachFailOpen with a client) error = %v, want nil", err)
		}
		_ = svc.Shutdown(t.Context())
	})
	t.Run("second_factor_wired", func(t *testing.T) {
		t.Parallel()
		for name, edit := range map[string]func(*account.Config){
			"totp": func(c *account.Config) {
				c.TOTP = account.TOTPConfig{Sealer: access.NewEphemeralSealer(), Issuer: "Example"}
			},
			"passkeys": func(c *account.Config) { c.RP = func() *webauthn.RelyingParty { return nil } },
		} {
			cfg := ownAuthenticator(t, base)
			cfg.Rules = func() account.Rules { return account.Rules{RequireSecondFactor: true} }
			edit(&cfg)
			svc, err := account.New(t.Context(), cfg)
			if err != nil {
				t.Errorf("%s: New(RequireSecondFactor) = %v, want nil", name, err)
				continue
			}
			_ = svc.Shutdown(t.Context())
		}
	})
	t.Run("require_second_factor_error_matches", func(t *testing.T) {
		t.Parallel()
		cfg := base
		cfg.Rules = func() account.Rules { return account.Rules{RequireSecondFactor: true} }
		_, err := account.New(t.Context(), cfg)
		var re *account.RulesError
		if !errors.Is(err, account.ErrRulesInvalid) || !errors.As(err, &re) || re.Field != "RequireSecondFactor" {
			t.Errorf("New(RequireSecondFactor, nothing wired) = %v, want a *RulesError for RequireSecondFactor", err)
		}
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
		cfg := ownAuthenticator(t, base)
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
		other, err := account.New(t.Context(), ownAuthenticator(t, cfg))
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
				"access.Sealer",
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
				// The app's name in an authenticator, shown in every otpauth URI.
				"account.TOTPConfig.Issuer",
				// A pending sign-in's step and methods are its public answer;
				// the digest and the matched recovery code's key are HashKeys,
				// which show no more than the Hash.
				"account.ticket.next", "account.ticket.methods", "account.ticket.digest", "account.ticket.recovered",
				// A draft's creation path is a public route's name for it.
				"account.draftOf.via",
				// A session ID names a session, as Principal.SessionID does;
				// only its token, which the store holds as a hash, signs in.
				"account.enrolment.sessionID",
				// The name lock's keys: canonical usernames, as access.User
				// holds them, each kept only while its verifier runs.
				"keylock.Set[string].m",
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
		{Provisioning: account.Provisioning{Enabled: true}, OIDCAdmission: account.OIDCAdmission{Claim: "groups", AllowedValues: []string{"staff"}}},
		{Provisioning: account.Provisioning{Role: access.RoleAdmin, RoleClaim: "groups", AdminValues: []string{"ops"}, SyncRole: true}},
		{Scopes: []string{"read", "manage_users", "files:write"}},
		{KeyRotationOverlap: time.Minute},
		{KeyRotationOverlap: 24 * time.Hour},
		{HTTPSOrigin: "https://grelot.example"},
		{HTTPSOrigin: "https://grelot.example:8443"},
		{HTTPSOrigin: "https://[2001:db8::1]:8443"},
		{HTTPSOrigin: "https://[::1]"},
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
		"recent_auth_below_1m":      {field: "RecentAuth", r: account.Rules{RecentAuth: time.Minute - time.Nanosecond}},
		"recent_auth_negative":      {field: "RecentAuth", r: account.Rules{RecentAuth: -time.Minute}},
		"breach_unknown":            {field: "Breach", r: account.Rules{Breach: account.BreachFailClosed + 1}},
		"breach_negative":           {field: "Breach", r: account.Rules{Breach: -1}},
		"max_sessions_negative":     {field: "MaxSessionsPerUser", r: account.Rules{MaxSessionsPerUser: -1}},
		"registration_unknown":      {field: "Registration", r: account.Rules{Registration: account.RegistrationApproval + 1}},
		"registration_negative":     {field: "Registration", r: account.Rules{Registration: -1}},
		"max_waiting_negative":      {field: "MaxWaitingRegistrations", r: account.Rules{MaxWaitingRegistrations: -1}},
		"overlap_below_1m":          {field: "KeyRotationOverlap", r: account.Rules{KeyRotationOverlap: time.Minute - time.Nanosecond}},
		"overlap_negative":          {field: "KeyRotationOverlap", r: account.Rules{KeyRotationOverlap: -time.Hour}},
		"overlap_above_24h":         {field: "KeyRotationOverlap", r: account.Rules{KeyRotationOverlap: 24*time.Hour + time.Nanosecond}},
		"admission_claim_no_values": {field: "OIDCAdmission", r: account.Rules{OIDCAdmission: account.OIDCAdmission{Claim: "groups"}}},
		"admission_values_no_claim": {field: "OIDCAdmission", r: account.Rules{OIDCAdmission: account.OIDCAdmission{AllowedValues: []string{"staff"}}}},
		"provisioning_role":         {field: "Provisioning", r: account.Rules{Provisioning: account.Provisioning{Enabled: true, Role: "owner"}}},
		"admin_values_no_claim":     {field: "Provisioning", r: account.Rules{Provisioning: account.Provisioning{AdminValues: []string{"ops"}}}},
		"sync_role_no_claim":        {field: "Provisioning", r: account.Rules{Provisioning: account.Provisioning{SyncRole: true}}},
		"key_prefix_invalid":        {field: "KeyPrefix", r: account.Rules{KeyPrefix: "ak-"}},
		"scope_space":               {field: "Scopes", r: account.Rules{Scopes: []string{"read", "read write"}}},
		"scope_empty":               {field: "Scopes", r: account.Rules{Scopes: []string{""}}},
		"scope_dquote":              {field: "Scopes", r: account.Rules{Scopes: []string{`re"ad`}}},
		"scope_non_ascii":           {field: "Scopes", r: account.Rules{Scopes: []string{"caf\u00e9"}}},
		"origin_http":               {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "http://grelot.example"}},
		"origin_root_path":          {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example/"}},
		"origin_path":               {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example/x"}},
		"origin_query":              {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example?q"}},
		"origin_fragment":           {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example#f"}},
		"origin_bare_query":         {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example?"}},
		"origin_bare_fragment":      {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example#"}},
		"origin_user_info":          {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://u@grelot.example"}},
		"origin_no_host":            {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://"}},
		"origin_upper_scheme":       {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "HTTPS://grelot.example"}},
		"origin_unparsable":         {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example:port"}},
		"origin_no_scheme":          {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "grelot.example"}},
		"origin_host_dquote":        {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: `https://grelot.example"x`}},
		"origin_host_angle":         {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example<x"}},
		"origin_host_bracket":       {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example]x"}},
		"origin_port_zero":          {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example:0"}},
		"origin_port_range":         {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example:99999"}},
		"origin_empty_port":         {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example:"}},
		"origin_default_port":       {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://grelot.example:443"}},
		"origin_dot_host":           {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://."}},
		"origin_upper_host":         {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://Grelot.example"}},
		"origin_ipv4_out_of_range":  {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://256.1.1.1"}},
		"origin_ipv4_short":         {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://1.2.3"}},
		"origin_ipv6_uncompressed":  {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://[0:0:0:0:0:0:0:1]"}},
		"origin_ipv6_mapped_dotted": {field: "HTTPSOrigin", r: account.Rules{HTTPSOrigin: "https://[::ffff:1.2.3.4]"}},
	} {
		err := tc.r.Validate()
		var re *account.RulesError
		if !errors.As(err, &re) || re.Field != tc.field || !errors.Is(err, account.ErrRulesInvalid) {
			t.Errorf("%s: Validate() = %v, want a *RulesError for %s matching ErrRulesInvalid", name, err, tc.field)
		}
	}
	if err := (account.Rules{KeyPrefix: "ak-"}).Validate(); !errors.Is(err, access.ErrInvalidKeyPrefix) {
		t.Errorf("Validate() of KeyPrefix \"ak-\" = %v, want it to match access.ErrInvalidKeyPrefix", err)
	}
	if err := (account.Rules{KeyPrefix: "ak_"}).Validate(); err != nil {
		t.Errorf("Validate() of KeyPrefix \"ak_\" = %v, want nil", err)
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
	p := f.sessionPrincipal(t, u, time.Now().Add(-90*time.Second))
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
	if err := f.svc.RequireRecentAuth(f.sessionPrincipal(t, u, time.Now().Add(-9*time.Minute))); err != nil {
		t.Errorf("RequireRecentAuth(9 minutes old) under the default = %v, want nil", err)
	}
	if err := f.svc.RequireRecentAuth(f.sessionPrincipal(t, u, time.Now().Add(-11*time.Minute))); !errors.Is(err, access.ErrRecentAuthRequired) {
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
		st, err := f.svc.State(t.Context(), localClient)
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
	// admitted is the provider a secure session-bound start is admitted
	// with, nil when OIDC is off.
	admitted := func(t *testing.T, f *fixture) *oidc.Provider {
		t.Helper()
		p, err := f.svc.AdmitOIDCSession(account.Client{Secure: true}, access.Principal{Secure: true})
		if err != nil && !errors.Is(err, account.ErrOIDCUnavailable) {
			t.Fatalf("AdmitOIDCSession: %v", err)
		}
		return p
	}
	if admitted(t, f) != first {
		t.Error("the admitted provider is not Config.OIDC's")
	}
	current.Store(second)
	if admitted(t, f) != second {
		t.Error("the admitted provider after the app swapped its provider is not the new one")
	}
	current.Store(nil)
	if admitted(t, f) != nil {
		t.Error("the admitted provider with a nil result is not nil")
	}
	none := newFixture(t, options{})
	if admitted(t, none) != nil {
		t.Error("the admitted provider with a nil Config.OIDC is not nil")
	}
}
