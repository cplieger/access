package accesshttp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// accountSentinels is §7.2's code table read from its From column: each
// error an account call returns, with the code the table gives it; code ""
// is an error the table does not name, a WebAuthn finish's own failure.
// accesshttp's own refusals and the Authenticator's are boundary cases, and
// so is webauthn.ErrResponseTooLarge: readCredential refuses a body past
// webauthn.MaxResponseBytes before account reads it.
var accountSentinels = []struct {
	err  error
	name string
	code Code
}{
	{name: "invalid_credentials", err: account.ErrInvalidCredentials, code: CodeInvalidCredentials},
	{name: "recent_auth", err: access.ErrRecentAuthRequired, code: CodeRecentAuthRequired},
	{name: "session_required", err: account.ErrSessionRequired, code: CodeSessionRequired},
	{name: "scope_required", err: account.ErrScopeRequired, code: CodeScopeRequired},
	{name: "policy", err: &account.PolicyError{Op: account.OpCreateUser, Reason: account.ReasonAdminTarget}, code: CodeForbidden},
	{name: "sso_governed", err: account.ErrSSOGoverned, code: CodeForbidden},
	{name: "rate_limited", err: &ratelimit.RefusedError{Dimension: "ip", RetryAfter: time.Second}, code: CodeRateLimited},
	{name: "hash_busy", err: access.ErrHashBusy, code: CodeBusy},
	{name: "backend", err: access.ErrAuthBackend, code: CodeUnavailable},
	{name: "service_closed", err: account.ErrServiceClosed, code: CodeUnavailable},
	{name: "rules_invalid", err: &account.RulesError{Field: "Breach", Reason: "no client"}, code: CodeUnavailable},
	{name: "ttl_too_long", err: account.ErrTTLTooLong, code: CodeBadRequest},
	{name: "ttl_negative", err: account.ErrTTLNegative, code: CodeBadRequest},
	{name: "no_change", err: account.ErrNoChange, code: CodeBadRequest},
	{name: "expiry_invalid", err: account.ErrKeyExpiryInvalid, code: CodeBadRequest},
	{name: "redirect_too_long", err: oidc.ErrRedirectTooLong, code: CodeBadRequest},
	{name: "current_password_required", err: account.ErrCurrentPasswordRequired, code: CodeBadRequest},
	{name: "text", err: &account.TextError{Field: account.TextFieldLabel, Reason: account.ReasonTooLong}, code: CodeBadRequest},
	{name: "log_filter", err: &account.LogFilterError{Reason: account.ReasonLogKind}, code: CodeBadRequest},
	{name: "username_invalid", err: &account.UsernameError{Reason: account.ReasonTooLong}, code: CodeUsernameInvalid},
	{name: "username_taken", err: account.ErrUsernameTaken, code: CodeUsernameTaken},
	{name: "password_rejected", err: &access.PasswordError{Reason: access.PasswordCommon}, code: CodePasswordRejected},
	{name: "breach_unavailable", err: account.ErrBreachCheckUnavailable, code: CodeBreachCheckUnavailable},
	{name: "password_login_disabled", err: account.ErrPasswordLoginDisabled, code: CodePasswordLoginDisabled},
	{name: "setup_complete", err: account.ErrSetupComplete, code: CodeSetupComplete},
	{name: "setup_token_required", err: account.ErrSetupTokenRequired, code: CodeSetupTokenRequired},
	{name: "token_invalid", err: access.ErrTokenInvalid, code: CodeTokenInvalid},
	{name: "last_method", err: account.ErrLastMethod, code: CodeLastMethod},
	{name: "identity_taken", err: account.ErrOIDCIdentityTaken, code: CodeIdentityTaken},
	{name: "already_linked", err: account.ErrAlreadyLinked, code: CodeAlreadyLinked},
	{name: "method_not_locked", err: account.ErrMethodNotLocked, code: CodeMethodNotLocked},
	{name: "duplicate_credential", err: account.ErrDuplicateCredential, code: CodeDuplicateCredential},
	{name: "unknown_scope", err: account.ErrUnknownScope, code: CodeUnknownScope},
	{name: "passkeys_unavailable", err: account.ErrPasskeysUnavailable, code: CodePasskeysUnavailable},
	{name: "origin_refused", err: &webauthn.OriginError{Reason: webauthn.RejectNotAllowlisted}, code: CodeOriginRefused},
	{name: "ceremony_invalid", err: account.ErrCeremonyInvalid, code: CodeCeremonyInvalid},
	{name: "not_discoverable", err: webauthn.ErrNotDiscoverable, code: CodeNotDiscoverable},
	{name: "unknown_credential", err: webauthn.ErrUnknownCredential, code: CodeUnknownCredential},
	{name: "unclassified", err: errStubbed},
	{name: "oidc_unavailable", err: account.ErrOIDCUnavailable, code: CodeOIDCUnavailable},
	{name: "oidc_exchange", err: oidc.ErrExchange, code: CodeOIDCFailed},
	{name: "oidc_provider_error", err: &oidc.ProviderError{Code: "access_denied"}, code: CodeOIDCFailed},
	{name: "oidc_stale", err: oidc.ErrStaleAuthentication, code: CodeOIDCFailed},
	{name: "session_gone", err: account.ErrSessionGone, code: CodeSessionExpired},
	{name: "not_found", err: account.ErrNotFound, code: CodeNotFound},
}

// finishFailure is §7.2's code for a WebAuthn finish failure the table does
// not otherwise name.
var finishFailure = map[ceremony]Code{ceremonyAssertion: CodeAssertionFailed, ceremonyRegistration: CodeRegistrationFailed}

// TestAccountSentinelsCoverAccount parses account's non-test files for its
// exported Err* values and the types whose Is method matches one, and this
// file for accountSentinels' rows. Each Err* has a row, as itself or as a
// type matching it, whose §7.2 code classify gives, so a new account
// sentinel cannot reach the census unlisted and answer auth_unavailable.
func TestAccountSentinelsCoverAccount(t *testing.T) {
	t.Parallel()
	names, err := filepath.Glob("../account/*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var sentinels []string
	matchedBy := map[string]string{} // a type with an Is method: the Err* it matches
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					for _, n := range spec.(*ast.ValueSpec).Names {
						if strings.HasPrefix(n.Name, "Err") && n.IsExported() {
							sentinels = append(sentinels, n.Name)
						}
					}
				}
			case *ast.FuncDecl:
				if d.Name.Name != "Is" || d.Recv == nil || len(d.Body.List) != 1 {
					continue
				}
				ret, ok := d.Body.List[0].(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 1 {
					continue
				}
				if cmp, ok := ret.Results[0].(*ast.BinaryExpr); ok && cmp.Op == token.EQL {
					if target, ok := cmp.Y.(*ast.Ident); ok {
						if star, ok := d.Recv.List[0].Type.(*ast.StarExpr); ok {
							matchedBy[star.X.(*ast.Ident).Name] = target.Name
						}
					}
				}
			}
		}
	}
	if len(sentinels) == 0 {
		t.Fatal("found no exported Err* in account")
	}
	f, err := parser.ParseFile(fset, "codes_test.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]int{} // a covered Err*: its accountSentinels index
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "accountSentinels" {
			return true
		}
		for i, row := range vs.Values[0].(*ast.CompositeLit).Elts {
			for _, kv := range row.(*ast.CompositeLit).Elts {
				kv := kv.(*ast.KeyValueExpr)
				if !isIdentNamed(kv.Key, "err") {
					continue
				}
				if name, ok := accountSelector(kv.Value); ok {
					rows[name] = i
				} else if u, ok := kv.Value.(*ast.UnaryExpr); ok {
					if lit, ok := u.X.(*ast.CompositeLit); ok {
						if typ, ok := accountSelector(lit.Type); ok && matchedBy[typ] != "" {
							rows[matchedBy[typ]] = i
						}
					}
				}
			}
		}
		return false
	})
	if len(rows) == 0 {
		t.Fatal("found no account rows in accountSentinels")
	}
	for _, name := range sentinels {
		i, ok := rows[name]
		if !ok {
			t.Errorf("account.%s has no accountSentinels row", name)
			continue
		}
		row := accountSentinels[i]
		if !slices.Contains(Codes(), row.code) {
			t.Errorf("account.%s: row %s names code %q, not a §7.2 code", name, row.name, row.code)
			continue
		}
		if e, ok := classify(row.err, ceremonyNone); !ok || e.Code != row.code {
			t.Errorf("account.%s: classify gives %q, %t; want %s", name, e.Code, ok, row.code)
		}
	}
}

// accountSelector reports the name x in account.x.
func accountSelector(e ast.Expr) (string, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || !isIdentNamed(sel.X, "account") {
		return "", false
	}
	return sel.Sel.Name, true
}

// answer serves r on rt and returns the code it refused with, from the
// ErrorWriter or a redirect's auth_error, and the contract breaks it logged.
func (e *env) answer(t *testing.T, rt Route, r *http.Request) (code Code, breaks int) {
	t.Helper()
	errsBefore, breaksBefore := len(e.errs.all()), e.logs.CountMsg("contract break")
	w := do(rt, r)
	errs := e.errs.all()[errsBefore:]
	breaks = e.logs.CountMsg("contract break") - breaksBefore
	switch {
	case len(errs) == 1:
		return errs[0].Code, breaks
	case len(errs) == 0 && w.Code == http.StatusFound:
		return redirectedCode(t, w), breaks
	default:
		t.Errorf("status %d with %d ErrorWriter calls, want one refusal", w.Code, len(errs))
		return "", breaks
	}
}

// boundaryCase is one request the guard or the transport refuses before
// any account operation runs.
type boundaryCase struct {
	// build returns the env and route that serve the case and its request.
	build func(t *testing.T) (*env, Route, *http.Request)
	name  string
	want  Code
}

// run serves the case and returns the code it answered and the contract
// breaks it logged.
func (bc *boundaryCase) run(t *testing.T) (got Code, breaks int) {
	t.Helper()
	e, rt, r := bc.build(t)
	return e.answer(t, rt, r)
}

// boundaryCases are rt's guard cases, one per census and fault principal
// the guard refuses, and its transport cases, each on a principal that
// passes the guard: a wrong method, a cross-origin request, a body that is
// not JSON and one past its cap, a malformed path value, a token in the
// query, a repeated declared query key, and a limiter refusal, where rt
// has each.
func (c *census) boundaryCases(t *testing.T, rt Route) []boundaryCase {
	t.Helper()
	s := specNamed(t, rt.Name)
	path, body := censusPathValue(t, rt), censusBody(t, rt)
	var cases []boundaryCase
	add := func(name string, want Code, build func() *http.Request) {
		cases = append(cases, boundaryCase{name: name, want: want, build: func(*testing.T) (*env, Route, *http.Request) {
			return c.env, rt, build()
		}})
	}
	as := func(p *censusPrincipal, path, body string) *http.Request {
		r := requestFor(rt, path, body)
		p.send(r)
		return r
	}
	for _, p := range slices.Concat(c.principals, c.faults) {
		if want := p.guardAnswer(&rt.Descriptor); want != "" {
			add(p.name, want, func() *http.Request { return as(&p, path, body) })
		}
	}
	pass := c.passing(t, rt)
	add("wrong_method", CodeMethodNotAllowed, func() *http.Request {
		r := as(pass, path, body)
		r.Method = http.MethodPatch
		return r
	})
	if rt.Method != http.MethodGet {
		add("cross_origin", CodeCrossOrigin, func() *http.Request {
			r := as(pass, path, body)
			r.Header.Set("Origin", evilOrigin)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			return r
		})
	}
	if limit := bodyLimit(s); limit > 0 {
		add("body_not_json", CodeBadRequest, func() *http.Request {
			r := as(pass, path, body)
			r.Header.Set("Content-Type", "text/plain")
			return r
		})
		add("body_too_large", CodeBodyTooLarge, func() *http.Request { return as(pass, path, longBody(limit+1)) })
	}
	if bad, ok := malformedPathValue[s.pathID]; ok {
		add("path_value", CodeBadRequest, func() *http.Request { return as(pass, bad, body) })
	}
	if s.tokenBody {
		add("token_in_query", CodeBadRequest, func() *http.Request {
			r := as(pass, path, body)
			r.URL.RawQuery = "token=" + "not-a-token"
			return r
		})
	}
	if rt.Query != nil && rt.Kind == KindJSON {
		key, _, _ := strings.Cut(rt.Query.Field(0).Tag.Get("json"), ",")
		add("query_repeated", CodeBadRequest, func() *http.Request {
			r := as(pass, path, body)
			r.URL.RawQuery = key + "=1&" + key + "=2"
			return r
		})
	}
	if s.limited {
		cases = append(cases, boundaryCase{name: "limiter", want: CodeRateLimited, build: func(t *testing.T) (*env, Route, *http.Request) {
			e := newEnv(t, limited)
			e.useIdP(t, accesstest.IdPOptions{}, nil)
			e.spendRequest(t)
			lrt := e.route(t, rt.Name)
			return e, lrt, get(lrt, "")
		}})
	}
	return cases
}

// malformedPathValue is a path value each path kind refuses.
var malformedPathValue = map[pathID]string{pathInt: "0", pathSession: "zz", pathMethod: string(access.MethodAPIKey)}

// bodyLimit is the body cap s reads under, 0 for a bodiless route.
func bodyLimit(s *routeSpec) int {
	switch {
	case s.cer != ceremonyNone:
		return webauthn.MaxResponseBytes
	case s.request != nil:
		return maxBodyBytes
	default:
		return 0
	}
}

// passing is a census principal rt's guard admits.
func (c *census) passing(t *testing.T, rt Route) *censusPrincipal {
	t.Helper()
	name := "recent_session"
	if rt.Class == ClassRecovery {
		name = "recovery_session"
	}
	p := c.principal(t, name)
	if want := p.guardAnswer(&rt.Descriptor); want != "" {
		t.Fatalf("%s's guard refuses %s with %s", rt.Name, name, want)
	}
	return p
}

// TestDescriptorCodes is §9.5 "Per-route codes" over the fake account,
// under the key scopes all empty and all set: every route answers its
// boundary cases with their codes, every bypass principal it refuses, and,
// on a principal its guard admits, its account call answering each
// sentinel in turn; a sentinel whose code the route lists answers it, and
// one it does not comes back auth_unavailable with one contract-break log.
// The codes it answers with no contract break are its Codes exactly.
func TestDescriptorCodes(t *testing.T) {
	for _, set := range []bool{false, true} {
		t.Run(scopeLabel(set), func(t *testing.T) {
			t.Parallel()
			c, bypass := newCensus(t, set, false), newCensus(t, set, true)
			c.stub.Store(true)
			bypass.stub.Store(true)
			for i, rt := range c.h.Routes() {
				t.Run(rt.Name, func(t *testing.T) {
					answered := map[Code]bool{}
					expect := func(t *testing.T, want, got Code, breaks int) {
						t.Helper()
						if breaks == 0 {
							answered[got] = true
						}
						if got != want || breaks != 0 {
							t.Errorf("answered %s with %d contract-break logs, want %s and none", got, breaks, want)
						}
					}
					for _, bc := range c.boundaryCases(t, rt) {
						t.Run(bc.name, func(t *testing.T) {
							got, breaks := bc.run(t)
							expect(t, bc.want, got, breaks)
						})
					}
					brt := bypass.h.Routes()[i]
					for _, p := range bypass.principals {
						if want := p.guardAnswer(&brt.Descriptor); want != "" {
							t.Run(p.name, func(t *testing.T) {
								got, breaks := bypass.answer(t, brt, requestFor(brt, censusPathValue(t, brt), censusBody(t, brt)))
								expect(t, want, got, breaks)
							})
						}
					}
					t.Run("sentinels", func(t *testing.T) { c.sweepSentinels(t, rt, answered) })
					if got := inCodesOrder(slices.Collect(maps.Keys(answered))); !slices.Equal(got, rt.Codes) {
						t.Errorf("answered %v, Codes %v", got, rt.Codes)
					}
				})
			}
		})
	}
}

// sweepSentinels has rt's account call answer each sentinel in turn and
// adds what rt answers with no contract break to answered. A route whose
// only account call is OIDCProvider has one failure, a nil provider, and
// one that makes no account call answers from its own state.
func (c *census) sweepSentinels(t *testing.T, rt Route, answered map[Code]bool) {
	t.Helper()
	s := specNamed(t, rt.Name)
	pass := c.passing(t, rt)
	path, body := censusPathValue(t, rt), censusBody(t, rt)
	defer c.fault.Store(nil)
	for _, sentinel := range accountSentinels {
		c.fault.Store(&sentinel.err)
		reachedBefore := c.reached.Load()
		r := requestFor(rt, path, body)
		pass.send(r)
		got, breaks := c.answer(t, rt, r)
		if breaks == 0 {
			answered[got] = true
		}
		switch {
		case c.reached.Load() == reachedBefore:
			if breaks != 0 {
				t.Errorf("with no account call: answered %s with %d contract-break logs, want none", got, breaks)
			}
			return
		case *c.lastOp.Load() == "OIDCProvider":
			if got != CodeOIDCUnavailable || breaks != 0 {
				t.Errorf("with a nil provider: answered %s with %d contract-break logs, want auth_oidc_unavailable and none", got, breaks)
			}
			return
		default:
		}
		want := sentinel.code
		if want == "" {
			want = finishFailure[s.cer]
		}
		switch {
		case want != "" && slices.Contains(rt.Codes, want):
			if got != want || breaks != 0 {
				t.Errorf("%s: answered %s with %d contract-break logs, want %s and none", sentinel.name, got, breaks, want)
			}
		case got != CodeUnavailable || breaks != 1:
			t.Errorf("%s (unlisted %q): answered %s with %d contract-break logs, want auth_unavailable and one", sentinel.name, want, got, breaks)
		default:
		}
	}
}

// TestDescriptorCodesReached is §9.5 "Per-route codes" over the real
// Service: every route's boundary cases, generated per class and route
// shape, and the operation scenarios written with its handler, hold one
// scenario per code its Codes lists under the key scopes all empty and all
// set, and none for a code it does not list; the operation scenarios hold
// its operation's codes exactly. Each scenario answers exactly its code
// with no contract break.
func TestDescriptorCodesReached(t *testing.T) {
	ops := operationScenarios()
	for _, set := range []bool{false, true} {
		t.Run(scopeLabel(set), func(t *testing.T) {
			t.Parallel()
			c := newCensus(t, set, false)
			for _, rt := range c.h.Routes() {
				t.Run(rt.Name, func(t *testing.T) {
					boundary := map[Code]boundaryCase{}
					for _, bc := range c.boundaryCases(t, rt) {
						if _, written := ops[scenarioKey{rt.Name, bc.want}]; !written && boundary[bc.want].build == nil {
							boundary[bc.want] = bc
						}
					}
					scenarios := slices.Collect(maps.Keys(boundary))
					for k := range ops {
						if k.route == rt.Name {
							scenarios = append(scenarios, k.code)
						}
					}
					if got := inCodesOrder(scenarios); !slices.Equal(got, rt.Codes) {
						t.Errorf("scenario codes %v, Codes %v", got, rt.Codes)
					}
					for _, code := range inCodesOrder(slices.Collect(maps.Keys(boundary))) {
						t.Run(string(code), func(t *testing.T) {
							bc := boundary[code]
							if got, breaks := bc.run(t); got != code || breaks != 0 {
								t.Errorf("%s answered %s with %d contract-break logs, want %s and none", bc.name, got, breaks, code)
							}
						})
					}
				})
			}
		})
	}
	t.Run("operation", func(t *testing.T) {
		byRoute := map[string][]Code{}
		for k := range ops {
			byRoute[k.route] = append(byRoute[k.route], k.code)
		}
		for i := range specs {
			route := specs[i].name
			if got, want := inCodesOrder(byRoute[route]), inCodesOrder(opCodes[specs[i].op]); !slices.Equal(got, want) {
				t.Errorf("%s: scenario codes %v, operation codes %v", route, got, want)
			}
			delete(byRoute, route)
			t.Run(route, func(t *testing.T) {
				for _, code := range Codes() {
					if sc, ok := ops[scenarioKey{route, code}]; ok {
						t.Run(string(code), func(t *testing.T) {
							t.Parallel()
							runScenario(t, route, code, sc)
						})
					}
				}
			})
		}
		for route := range byRoute {
			t.Errorf("scenarios for %s, which no spec names", route)
		}
	})
}

// runScenario runs sc on its own env: route answers exactly code, at its
// table status or as a redirect's auth_error, with no contract break.
func runScenario(t *testing.T, route string, code Code, sc scenario) {
	t.Helper()
	e := newEnv(t, sc.opts)
	r := sc.arrange(t, e)
	errsBefore, breaksBefore := len(e.errs.all()), e.logs.CountMsg("contract break")
	w := do(e.route(t, route), r)
	errs := e.errs.all()[errsBefore:]
	if w.Code == http.StatusFound {
		if got := redirectedCode(t, w); len(errs) != 0 || got != code {
			t.Errorf("redirect auth_error %q, errors %+v, want %s and no ErrorWriter call", got, errs, code)
		}
	} else if len(errs) != 1 || errs[0].Code != code || w.Code != codeTable[codeIndex[code]].status {
		t.Errorf("status %d, errors %+v, want one %s", w.Code, errs, code)
	}
	if n := e.logs.CountMsg("contract break") - breaksBefore; n != 0 {
		t.Errorf("%d contract-break logs, want none", n)
	}
}
