package accesshttp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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
	"authOIDCPending": {open: ClassPublic}, "authOIDCCreatePending": {open: ClassPublic}, "authOIDCLinkByAdmin": {open: ClassPublic}, "authOIDCLinkPending": {open: ClassRecentAuth}, "authOIDCUnlink": {open: ClassRecentAuth},
	"authInviteAcceptPassword": {open: ClassPublic}, "authInviteAcceptOIDC": {open: ClassPublic},
	"authRegisterPassword": {open: ClassPublic}, "authRegisterPasskeyBegin": {open: ClassPublic}, "authRegisterPasskeyFinish": {open: ClassPublic}, "authMe": {open: ClassSession},
	"authProfile": {open: ClassSession}, "authMethodReenable": {open: ClassRecentAuth}, "authStepUpPassword": {open: ClassSession},
	"authStepUpPasskeyBegin": {open: ClassSession}, "authStepUpPasskeyFinish": {open: ClassSession}, "authPasswordSet": {open: ClassRecentAuth},
	"authPasswordRemove":    {open: ClassRecentAuth},
	"authLoginRecoveryCode": {open: ClassPublic}, "authPendingTOTPBegin": {open: ClassPublic}, "authPendingTOTPFinish": {open: ClassPublic},
	"authPendingPasskeyBegin": {open: ClassPublic}, "authPendingPasskeyFinish": {open: ClassPublic},
	"authLoginSetPassword": {open: ClassPublic}, "authLoginSetPasskeyBegin": {open: ClassPublic}, "authLoginSetPasskeyFinish": {open: ClassPublic},
	"authLoginCode": {open: ClassPublic}, "authLoginSecondPasskeyBegin": {open: ClassPublic}, "authLoginSecondPasskeyFinish": {open: ClassPublic},
	"authStepUpCode": {open: ClassSession}, "authTOTPBegin": {open: ClassRecentAuth}, "authTOTPFinish": {open: ClassRecentAuth}, "authRecoveryCodeRegenerate": {open: ClassRecentAuth},
	"authTOTPRemove": {open: ClassSession}, "authPasskeys": {open: ClassSession}, "authPasskeyRegisterBegin": {open: ClassRecentAuth},
	"authPasskeyRegisterFinish": {open: ClassRecentAuth}, "authPasskeyRename": {open: ClassSession}, "authPasskeyRemove": {open: ClassRecentAuth},
	"authWebAuthnSignals": {open: ClassSession}, "authSessions": {open: ClassSession}, "authSessionRename": {open: ClassSession},
	"authSessionRevoke": {open: ClassSession}, "authSessionsRevokeOthers": {open: ClassRecentAuth},
	"authKeys":                   {open: ClassSession, scoped: ClassKeyScope, scope: "keys"},
	"authKeyCreate":              {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "keys"},
	"authKeyRename":              {open: ClassSession, scoped: ClassKeyScope, scope: "keys"},
	"authKeyRotate":              {open: ClassRecentAuth},
	"authKeyRevoke":              {open: ClassSession, scoped: ClassKeyScope, scope: "keys"},
	"authAdminUsers":             {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminUserCreate":        {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminUserUpdate":        {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminUserDelete":        {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminOIDCUnlink":        {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminOIDCRelink":        {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminTemporaryPassword": {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminSecondFactorReset": {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminOwner":             {open: ClassRecentAuth, scoped: ClassRecentAuth},
	"authAdminSSOReadiness":      {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminSSOApply":          {open: ClassRecentAuth, scoped: ClassRecentAuth},
	"authAdminInvite":            {open: ClassRecentAuth, scoped: ClassKeyPermission, scope: "users"},
	"authAdminKeys":              {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminKeyRevoke":         {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminTokens":            {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
	"authAdminSecurityLog":       {open: ClassSession, scoped: ClassKeyScope, scope: "admin"},
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
			t.Fatalf("%d descriptors, want the %d specified routes", len(ds), len(designClasses))
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
		"authLoginPasskeyBegin": reflect.TypeFor[PasskeyBeginQuery](),
		"authOIDCStartSignIn":   reflect.TypeFor[OIDCSignInQuery](),
		"authOIDCCallback":      reflect.TypeFor[OIDCCallbackQuery](),
		"authAdminUsers":        reflect.TypeFor[AdminUsersQuery](),
		"authAdminSecurityLog":  reflect.TypeFor[AdminSecurityLogQuery](),
		"authAdminSSOReadiness": reflect.TypeFor[SSOReadinessQuery](),
	}
	for i := range specs {
		d := specs[i].descriptor(&DescriptorConfig{Prefix: "/p", OIDCPrefix: "/o"})
		if d.Query != want[d.Name] {
			t.Errorf("%s Query = %v, want %v", d.Name, d.Query, want[d.Name])
		}
	}
	for _, name := range []string{"authSetupPassword", "authSetupPasskeyBegin", "authInviteAcceptPassword", "authInviteAcceptOIDC", "authOIDCStartLink", "authOIDCStartStepUp"} {
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
		ClassKeyScope:      {access.CodeScopeRequired},
		ClassKeyPermission: {access.CodeRecentAuthRequired, access.CodeScopeRequired},
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
	noBody := []string{"authAdminUsers", "authLoginPasskeyBegin", "authMethodReenable", "authSessionRevoke", "authKeyRevoke", "authAdminUserDelete", "authAdminOIDCUnlink", "authAdminSecondFactorReset", "authAdminKeyRevoke", "authOIDCStartSignIn", "authOIDCCallback"}
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

// TestRouteSuccess holds each route's success status: present on every
// route, 302 Found on a redirect (RFC 9110 §15.4.3), 201 Created where the
// answer describes the resource the request created (§15.3.2: a user, an
// invite, an API key, a passkey added from Account), 204 No
// Content where no body is sent (§15.3.5), else 200 OK (§15.3.1).
func TestRouteSuccess(t *testing.T) {
	created := []string{"authAdminUserCreate", "authAdminInvite", "authKeyCreate", "authPasskeyRegisterFinish"}
	for i := range specs {
		s := &specs[i]
		want := http.StatusOK
		switch {
		case s.redirect:
			want = http.StatusFound
		case slices.Contains(created, s.name):
			want = http.StatusCreated
		case s.response == nil:
			want = http.StatusNoContent
		}
		if s.success != want {
			t.Errorf("%s success status %d, want %d", s.name, s.success, want)
		}
		if s.success == http.StatusCreated && s.method != http.MethodPost {
			t.Errorf("%s answers 201 to %s; only a POST creates", s.name, s.method)
		}
	}
}

// TestSuccessWrittenFromSpec: every success status accesshttp writes is
// its route's spec's, so a route answers exactly the status it states.
// The status writers pass on their status argument; every other caller
// passes c.spec.success with c the request's *call. Refusals are written
// by internal/refusal.
func TestSuccessWrittenFromSpec(t *testing.T) {
	writers := map[string]int{"WriteHeader": 0, "writeJSON": 1, "redirect": 1}
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	writes := 0
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			_, isWriter := writers[fn.Name.Name]
			isWriter = isWriter && fn.Recv == nil
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				callee := ""
				switch fun := ce.Fun.(type) {
				case *ast.Ident:
					callee = fun.Name
				case *ast.SelectorExpr:
					if fun.Sel.Name == "WriteHeader" {
						callee = fun.Sel.Name
					}
				}
				idx, ok := writers[callee]
				if !ok || callee == "" || len(ce.Args) <= idx {
					return true
				}
				writes++
				arg := types.ExprString(ce.Args[idx])
				passed := arg == "status" && isWriter
				if fromSpec := arg == "c.spec.success" && takesCall(fn); !passed && !fromSpec {
					t.Errorf("%s: %s writes status %s, want its route's c.spec.success", fset.Position(ce.Pos()), fn.Name.Name, arg)
				}
				return true
			})
		}
	}
	if writes == 0 {
		t.Error("found no status write; the check reads nothing")
	}
}

// takesCall reports whether fn's receiver or a parameter is c *call.
func takesCall(fn *ast.FuncDecl) bool {
	var fields []*ast.Field
	if fn.Recv != nil {
		fields = fn.Recv.List
	}
	fields = append(fields, fn.Type.Params.List...)
	for _, f := range fields {
		star, ok := f.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		if id, ok := star.X.(*ast.Ident); ok && id.Name == "call" && len(f.Names) == 1 && f.Names[0].Name == "c" {
			return true
		}
	}
	return false
}

// TestRoutePathParams holds each route's path parameter to its ServeMux
// pattern's one {name} wildcard, typed as the ID the wire names that
// resource by in its view, or as a sign-in method.
func TestRoutePathParams(t *testing.T) {
	idType := func(v any) reflect.Type {
		f, _ := reflect.TypeOf(v).FieldByName("ID")
		return f.Type
	}
	byCollection := map[string]reflect.Type{
		"users": idType(UserView{}), "passkeys": idType(PasskeyView{}), "apikeys": idType(KeyView{}),
		"sessions": idType(SessionView{}), "methods": reflect.TypeFor[access.Method](),
	}
	for i := range specs {
		s := &specs[i]
		var wildcards []string
		collection := ""
		segments := strings.Split(s.path, "/")
		for j, seg := range segments {
			if name, ok := strings.CutPrefix(seg, "{"); ok {
				wildcards = append(wildcards, strings.TrimSuffix(name, "}"))
				collection = segments[j-1]
			}
		}
		if s.pathID == pathNone {
			if len(wildcards) != 0 {
				t.Errorf("%s path %s has wildcards %v and no path parameter", s.name, s.path, wildcards)
			}
			continue
		}
		if len(wildcards) != 1 || wildcards[0] != s.pathID.key() {
			t.Errorf("%s path %s has wildcards %v, want its parameter %q alone", s.name, s.path, wildcards, s.pathID.key())
			continue
		}
		want := byCollection[collection]
		if got := s.pathID.typ(); got == nil || got != want {
			t.Errorf("%s parameter %s is typed %v, want %v", s.name, s.pathID.key(), got, want)
		}
	}
}

// reasons merges as by code: the union of the listed reasons, sorted, and
// open when any part marks the code open.
func (as answers) reasons() map[access.Code]reasonSet {
	out := make(map[access.Code]reasonSet, len(as))
	for _, a := range as {
		rs := out[a.code]
		rs.listed = append(rs.listed, a.listed...)
		rs.open = rs.open || a.open
		out[a.code] = rs
	}
	for code, rs := range out {
		slices.Sort(rs.listed)
		rs.listed = slices.Compact(rs.listed)
		out[code] = rs
	}
	return out
}

// TestRouteReasons: under both key-scope settings, every
// code a route answers carries a listed Reason ("" for none) or an open
// mark, every listed one is a Reason access fixes (Reasons), and only the
// three families a route cannot fix are open: auth_bad_request on a route
// that names a refused field, path value or query key, auth_oidc_failed on
// the callback, and auth_forbidden.
func TestRouteReasons(t *testing.T) {
	for _, dc := range scopeConfigs {
		for i := range specs {
			s := &specs[i]
			class, _ := s.classFor(&dc)
			d := s.descriptor(&dc)
			reasons := s.answers(class).reasons()
			if got := inCodesOrder(slices.Collect(maps.Keys(reasons))); !slices.Equal(got, d.Codes) {
				t.Errorf("%s: reasons for %v, Codes %v", s.name, got, d.Codes)
			}
			for _, code := range d.Codes {
				rs := reasons[code]
				if len(rs.listed) == 0 && !rs.open {
					t.Errorf("%s: %s has no listed reason and no open mark", s.name, code)
				}
				for _, r := range rs.listed {
					if !fixedReasons[r] {
						t.Errorf("%s: %s lists %q, which Reasons does not hold", s.name, code, r)
					}
				}
			}
			namesField := s.request != nil || s.pathID != pathNone || s.query != nil && !s.redirect
			want := map[access.Code]bool{
				access.CodeBadRequest: namesField,
				access.CodeOIDCFailed: s.name == "authOIDCCallback",
			}
			for code, rs := range reasons {
				if code != access.CodeForbidden && rs.open != want[code] {
					t.Errorf("%s: %s open %t, want %t", s.name, code, rs.open, want[code])
				}
			}
		}
	}
}

// TestDescriptorDocs holds every route to one present-tense sentence of its
// own, since Descriptors ships Doc to an app's generated client and API
// reference.
func TestDescriptorDocs(t *testing.T) {
	seen := map[string]string{}
	for _, d := range Descriptors(DescriptorConfig{}) {
		doc := d.Doc
		switch {
		case doc == "":
			t.Errorf("%s has no Doc", d.Name)
			continue
		case !strings.HasSuffix(doc, "."), strings.Contains(strings.TrimSuffix(doc, "."), ". "):
			t.Errorf("%s Doc %q is not one sentence ending in a period", d.Name, doc)
		case doc[0] < 'A' || doc[0] > 'Z':
			t.Errorf("%s Doc %q does not start with a capital", d.Name, doc)
		case strings.TrimSpace(doc) != doc, strings.Contains(doc, "\n"):
			t.Errorf("%s Doc %q has surrounding space or a line break", d.Name, doc)
		}
		verb, _, _ := strings.Cut(doc, " ")
		if !strings.HasSuffix(verb, "s") {
			t.Errorf("%s Doc %q does not open with a present-tense verb", d.Name, doc)
		}
		if other, dup := seen[doc]; dup {
			t.Errorf("%s and %s share the Doc %q", other, d.Name, doc)
		}
		seen[doc] = d.Name
	}
}
