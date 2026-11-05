package accesshttp

import (
	"net/http"
	"reflect"
	"slices"
	"testing"
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
	"authKeyCreate":       {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "keys"},
	"authKeyRevoke":       {open: ClassSession},
	"authAdminUsers":      {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminUserCreate": {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminUserUpdate": {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminUserDelete": {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminRecovery":   {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminInvite":     {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminKeys":       {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminKeyRevoke":  {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminTokens":     {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
}

// scopeSets is each of the three scopes empty and set.
func scopeSets() []scopes {
	var out []scopes
	for mask := range 8 {
		var sc scopes
		if mask&1 != 0 {
			sc.admin = "admin_scope"
		}
		if mask&2 != 0 {
			sc.users = "manage_users"
		}
		if mask&4 != 0 {
			sc.keys = "create_keys"
		}
		out = append(out, sc)
	}
	return out
}

func TestDescriptorClassesFromScopes(t *testing.T) {
	if len(specs) != len(designClasses) {
		t.Fatalf("%d specs, want section 7.4's %d routes", len(specs), len(designClasses))
	}
	for _, sc := range scopeSets() {
		for i := range specs {
			s := &specs[i]
			want, ok := designClasses[s.name]
			if !ok {
				t.Fatalf("spec %s is not a section 7.4 route", s.name)
			}
			set := map[string]string{"admin": sc.admin, "users": sc.users, "keys": sc.keys}[want.scope]
			wantClass, wantScope := want.open, ""
			if set != "" {
				wantClass, wantScope = want.scoped, set
			}
			d := s.descriptor("/p", "/o", sc)
			if d.Class != wantClass || d.Scope != wantScope {
				t.Errorf("scopes %+v: %s is %s %q, want %s %q", sc, s.name, d.Class, d.Scope, wantClass, wantScope)
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
	}
	for i := range specs {
		d := specs[i].descriptor("/p", "/o", scopes{})
		if d.Query != want[d.Name] {
			t.Errorf("%s Query = %v, want %v", d.Name, d.Query, want[d.Name])
		}
	}
	for _, name := range []string{"authSetupPassword", "authSetupPasskeyBegin", "authRecoveryStart", "authInviteAcceptPassword", "authOIDCStartLink", "authOIDCStartStepUp"} {
		if d := specNamed(t, name).descriptor("/p", "/o", scopes{}); d.Query != nil {
			t.Errorf("%s Query = %v, want nil", name, d.Query)
		}
	}
}

func TestCodesOrder(t *testing.T) {
	authCodes := []Code{CodeAuthRequired, CodeSessionExpired, CodeInvalidCredentials, CodeKeyInvalid, CodeUnavailable}
	refusals := map[Class][]Code{
		ClassSession:       {CodeSessionRequired},
		ClassRecentAuth:    {CodeSessionRequired, CodeRecentAuthRequired},
		ClassKeyScope:      {CodeScopeRequired, CodeSessionRequired},
		ClassKeyPermission: {CodeRecentAuthRequired, CodeScopeRequired, CodeSessionRequired},
		ClassRecovery:      {CodeSessionRequired},
	}
	order := Codes()
	for _, sc := range []scopes{{}, {admin: "a", users: "u", keys: "k"}} {
		for i := range specs {
			s := &specs[i]
			d := s.descriptor("/p", "/o", sc)
			last := -1
			for _, c := range d.Codes {
				idx := slices.Index(order, c)
				if idx <= last {
					t.Errorf("%s Codes %v are not a subset of Codes() in its order", d.Name, d.Codes)
					break
				}
				last = idx
			}
			var want []Code
			if d.Class != ClassPublic {
				want = append(slices.Clone(authCodes), refusals[d.Class]...)
			}
			want = append(want, CodeMethodNotAllowed)
			if d.Method != http.MethodGet {
				want = append(want, CodeCrossOrigin)
			}
			body := d.Request != nil || s.cer != ceremonyNone
			if body {
				want = append(want, CodeBodyTooLarge, CodeBadRequest)
			}
			if s.pathID != pathNone || (d.Query != nil && d.Kind == KindJSON) {
				want = append(want, CodeBadRequest)
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
		d := specNamed(t, name).descriptor("/p", "/o", scopes{})
		if slices.Contains(d.Codes, CodeBodyTooLarge) {
			t.Errorf("%s lists auth_body_too_large with no body", name)
		}
	}
	for _, name := range []string{"authOIDCStartSignIn", "authOIDCCallback"} {
		d := specNamed(t, name).descriptor("/p", "/o", scopes{})
		if slices.Contains(d.Codes, CodeBadRequest) || !slices.Contains(d.Codes, CodeRateLimited) {
			t.Errorf("%s Codes %v: want no auth_bad_request and auth_rate_limited", name, d.Codes)
		}
	}
}
