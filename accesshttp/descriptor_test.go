package accesshttp

import (
	"net/http"
	"reflect"
	"slices"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// designClasses is each route's specified class. A route with a scope takes
// the scoped class and the scope when that scope is set, else open.
var designClasses = map[string]struct {
	open   Class
	scoped Class
	scope  string // "admin", "users" or "keys"
}{
	"authState": {open: ClassPublic}, "authSetupPassword": {open: ClassPublic}, "authSetupPasskeyBegin": {open: ClassPublic},
	"authSetupPasskeyFinish": {open: ClassPublic}, "authLoginPassword": {open: ClassPublic}, "authLoginPasskeyBegin": {open: ClassPublic},
	"authLoginPasskeyFinish": {open: ClassPublic}, "authLogout": {open: ClassPublic}, "authOIDCStartSignIn": {open: ClassPublic},
	"authOIDCStartLink": {open: ClassRecentAuth}, "authOIDCStartStepUp": {open: ClassSession}, "authOIDCCallback": {open: ClassPublic},
	"authOIDCPending": {open: ClassPublic}, "authOIDCLinkPending": {open: ClassRecentAuth}, "authOIDCUnlink": {open: ClassRecentAuth},
	"authRecoveryStart": {open: ClassPublic}, "authRecoveryPassword": {open: ClassRecovery}, "authRecoveryPasskeyBegin": {open: ClassRecovery},
	"authRecoveryPasskeyFinish": {open: ClassRecovery}, "authInviteAcceptPassword": {open: ClassPublic}, "authMe": {open: ClassSession},
	"authProfile": {open: ClassSession}, "authMethodReenable": {open: ClassRecentAuth}, "authStepUpPassword": {open: ClassSession},
	"authStepUpPasskeyBegin": {open: ClassSession}, "authStepUpPasskeyFinish": {open: ClassSession}, "authPasswordSet": {open: ClassRecentAuth},
	"authPasswordRemove": {open: ClassRecentAuth}, "authPasskeys": {open: ClassSession}, "authPasskeyRegisterBegin": {open: ClassRecentAuth},
	"authPasskeyRegisterFinish": {open: ClassRecentAuth}, "authPasskeyRename": {open: ClassSession}, "authPasskeyRemove": {open: ClassRecentAuth},
	"authWebAuthnSignals": {open: ClassSession}, "authSessions": {open: ClassSession}, "authSessionRename": {open: ClassSession},
	"authSessionRevoke": {open: ClassSession}, "authSessionsRevokeOthers": {open: ClassRecentAuth}, "authKeys": {open: ClassSession},
	"authKeyCreate":        {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "keys"},
	"authKeyRevoke":        {open: ClassSession},
	"authAdminUsers":       {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminUserCreate":  {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminUserUpdate":  {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminUserDelete":  {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminRecovery":    {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminInvite":      {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminKeys":        {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminKeyRevoke":   {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminTokens":      {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminSecurityLog": {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
}

// scopeSets is each of the three scopes empty and set.
func scopeSets() []DescriptorConfig {
	var out []DescriptorConfig
	for mask := range 8 {
		dc := DescriptorConfig{Prefix: "/p", OIDCPrefix: "/o"}
		if mask&1 != 0 {
			dc.AdminScope = "admin_scope"
		}
		if mask&2 != 0 {
			dc.ManageUsersScope = "manage_users"
		}
		if mask&4 != 0 {
			dc.CreateKeysScope = "create_keys"
		}
		out = append(out, dc)
	}
	return out
}

func TestDescriptorClassesFromScopes(t *testing.T) {
	for _, dc := range scopeSets() {
		ds := Descriptors(dc)
		if len(ds) != len(designClasses) {
			t.Fatalf("%d descriptors, want section 7.4's %d routes", len(ds), len(designClasses))
		}
		for _, d := range ds {
			want, ok := designClasses[d.Name]
			if !ok {
				t.Fatalf("route %s is not a section 7.4 route", d.Name)
			}
			set := map[string]string{"admin": dc.AdminScope, "users": dc.ManageUsersScope, "keys": dc.CreateKeysScope}[want.scope]
			wantClass, wantScope := want.open, ""
			if set != "" {
				wantClass, wantScope = want.scoped, set
			}
			if d.Class != wantClass || d.Scope != wantScope {
				t.Errorf("config %+v: %s is %s %q, want %s %q", dc, d.Name, d.Class, d.Scope, wantClass, wantScope)
			}
		}
	}
}

func TestDescriptorQueryTable(t *testing.T) {
	want := map[string]reflect.Type{
		"authLoginPasskeyBegin":     reflect.TypeFor[PasskeyBeginQuery](),
		"authOIDCStartSignIn":       reflect.TypeFor[OIDCSignInQuery](),
		"authOIDCCallback":          reflect.TypeFor[OIDCCallbackQuery](),
		"authRecoveryPasskeyFinish": reflect.TypeFor[RecoveryPasskeyFinishQuery](),
		"authAdminUsers":            reflect.TypeFor[AdminUsersQuery](),
		"authAdminSecurityLog":      reflect.TypeFor[AdminSecurityLogQuery](),
	}
	for i := range specs {
		d := specs[i].descriptor(&DescriptorConfig{Prefix: "/p", OIDCPrefix: "/o"})
		if d.Query != want[d.Name] {
			t.Errorf("%s Query = %v, want %v", d.Name, d.Query, want[d.Name])
		}
	}
	for _, name := range []string{"authSetupPassword", "authSetupPasskeyBegin", "authRecoveryStart", "authInviteAcceptPassword", "authOIDCStartLink", "authOIDCStartStepUp"} {
		if d := specNamed(t, name).descriptor(&DescriptorConfig{Prefix: "/p", OIDCPrefix: "/o"}); d.Query != nil {
			t.Errorf("%s Query = %v, want nil", name, d.Query)
		}
	}
}

func TestCodesOrder(t *testing.T) {
	authCodes := []access.Code{access.CodeAuthRequired, access.CodeSessionExpired, access.CodeInvalidCredentials, access.CodeKeyInvalid, access.CodeUnavailable}
	refusals := map[Class][]access.Code{
		ClassSession:       {access.CodeSessionRequired},
		ClassRecentAuth:    {access.CodeSessionRequired, access.CodeRecentAuthRequired},
		ClassKeyScope:      {access.CodeScopeRequired, access.CodeSessionRequired},
		ClassKeyPermission: {access.CodeRecentAuthRequired, access.CodeScopeRequired, access.CodeSessionRequired},
		ClassRecovery:      {access.CodeSessionRequired},
	}
	order := access.Codes()
	for _, dc := range []DescriptorConfig{{}, {Prefix: "/p", OIDCPrefix: "/o", AdminScope: "a", ManageUsersScope: "u", CreateKeysScope: "k"}} {
		for i := range specs {
			s := &specs[i]
			d := s.descriptor(&dc)
			last := -1
			for _, c := range d.Codes {
				idx := slices.Index(order, c)
				if idx <= last {
					t.Errorf("%s Codes %v are not a subset of Codes() in its order", d.Name, d.Codes)
					break
				}
				last = idx
			}
			var want []access.Code
			if d.Class != ClassPublic {
				want = append(slices.Clone(authCodes), refusals[d.Class]...)
			}
			want = append(want, access.CodeMethodNotAllowed)
			if d.Method != http.MethodGet {
				want = append(want, access.CodeCrossOrigin)
			}
			body := d.Request != nil || s.cer != ceremonyNone
			if body {
				want = append(want, access.CodeBodyTooLarge, access.CodeBadRequest)
			}
			if s.pathID != pathNone || (d.Query != nil && d.Kind == KindJSON) {
				want = append(want, access.CodeBadRequest)
			}
			for _, c := range want {
				if !slices.Contains(d.Codes, c) {
					t.Errorf("%s (%s) Codes %v lack %s", d.Name, d.Class, d.Codes, c)
				}
			}
		}
	}
	noBody := []string{"authAdminUsers", "authLoginPasskeyBegin", "authMethodReenable", "authPasskeyRemove", "authSessionRevoke", "authKeyRevoke", "authAdminUserDelete", "authAdminKeyRevoke", "authOIDCStartSignIn", "authOIDCCallback"}
	for _, name := range noBody {
		d := specNamed(t, name).descriptor(&DescriptorConfig{Prefix: "/p", OIDCPrefix: "/o"})
		if slices.Contains(d.Codes, access.CodeBodyTooLarge) {
			t.Errorf("%s lists auth_body_too_large with no body", name)
		}
	}
	for _, name := range []string{"authOIDCStartSignIn", "authOIDCCallback"} {
		d := specNamed(t, name).descriptor(&DescriptorConfig{Prefix: "/p", OIDCPrefix: "/o"})
		if slices.Contains(d.Codes, access.CodeBadRequest) || !slices.Contains(d.Codes, access.CodeRateLimited) {
			t.Errorf("%s Codes %v: want no auth_bad_request and auth_rate_limited", name, d.Codes)
		}
	}
}

// TestDescriptorsEqualsNewRoutes holds the store-free Descriptors to New's
// Routes for the same prefixes and scopes, so an app's boot-time endpoint
// table and OpenAPI document list exactly the routes it mounts.
func TestDescriptorsEqualsNewRoutes(t *testing.T) {
	type place struct{ path, scope string }
	cases := map[string]struct {
		dc   DescriptorConfig
		want map[string]place // section 7.4's path and scope for a few routes
	}{
		"default": {want: map[string]place{
			"authMe": {path: "/me"}, "authOIDCCallback": {path: "/callback"},
			"authAdminUsers": {path: "/users"}, "authAdminInvite": {path: "/invites"}, "authKeyCreate": {path: "/apikeys"},
		}},
		"every field set": {
			dc: DescriptorConfig{Prefix: "/api/auth", OIDCPrefix: "/sso", AdminScope: "admin_scope", ManageUsersScope: "manage_users", CreateKeysScope: "create_keys"},
			want: map[string]place{
				"authMe": {path: "/api/auth/me"}, "authOIDCCallback": {path: "/sso/callback"},
				"authAdminUsers":  {path: "/api/auth/users", scope: "admin_scope"},
				"authAdminInvite": {path: "/api/auth/invites", scope: "manage_users"},
				"authKeyCreate":   {path: "/api/auth/apikeys", scope: "create_keys"},
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, envOptions{edit: func(c *account.Config) {
				c.AdminScope, c.ManageUsersScope, c.CreateKeysScope = tc.dc.AdminScope, tc.dc.ManageUsersScope, tc.dc.CreateKeysScope
			}})
			h, err := New(Config{
				Account: e.svc, Errors: func(http.ResponseWriter, *http.Request, access.Error) {},
				Prefix: tc.dc.Prefix, OIDCPrefix: tc.dc.OIDCPrefix,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			routes := h.Routes()
			got := Descriptors(tc.dc)
			if len(got) != len(routes) {
				t.Fatalf("Descriptors lists %d routes, New's Routes %d", len(got), len(routes))
			}
			for i := range routes {
				if !reflect.DeepEqual(got[i], routes[i].Descriptor) {
					t.Errorf("Descriptors[%d] = %+v, New's Routes[%d] = %+v", i, got[i], i, routes[i].Descriptor)
				}
			}
			seen := 0
			for _, d := range got {
				w, ok := tc.want[d.Name]
				if !ok {
					continue
				}
				seen++
				if d.Path != w.path || d.Scope != w.scope {
					t.Errorf("%s at %s scope %q, want %s scope %q", d.Name, d.Path, d.Scope, w.path, w.scope)
				}
			}
			if seen != len(tc.want) {
				t.Errorf("Descriptors lists %d of the %d routes the case names", seen, len(tc.want))
			}
		})
	}
}
