package accesshttp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// TestOpCodesFromProducers holds opCodes against the code that answers each
// route: every error chain its serve function can return or hand
// (*Handler).refusal, followed through accesshttp, account, access, oidc,
// webauthn, ratelimit and accesstest's reference store, mapped through
// classify. A code the producers can answer is in the route's Codes or
// refuted; every opCodes code is one they can answer; every producer error
// they return has a producerErrors row, and the error table names it or
// refuted does; and every refuted row still describes such a path.
func TestOpCodesFromProducers(t *testing.T) {
	t.Parallel()
	p := loadProducers(t)
	used := make([]bool, len(refuted))
	refutedAt := func(route string, code Code, leaf string) bool {
		for i, r := range refuted {
			if r.route == route && r.code == code && r.leaf == leaf {
				used[i] = true
				return true
			}
		}
		return false
	}
	for i := range specs {
		s := &specs[i]
		produced := map[Code]string{}
		for _, c := range p.routeErrors(p.serveFunc(t, s)) {
			vals, ok := values(c)
			if !ok || len(vals) == 0 && s.cer == ceremonyNone {
				continue
			}
			e, ok := classify(errors.Join(vals...), s.cer)
			if ok {
				produced[e.Code] = chainString(c)
				continue
			}
			named := false
			for _, tm := range c {
				named = tm.kind == termLeaf && refutedAt(s.name, "", qualified(tm.obj)) || named
			}
			if !named {
				t.Errorf("%s can return %s, which the error table does not name", s.name, chainString(c))
			}
		}
		listed := map[Code]bool{}
		for _, dc := range []DescriptorConfig{{}, {AdminScope: "a", ManageUsersScope: "u", CreateKeysScope: "k"}} {
			class, _ := s.classFor(&dc)
			for _, c := range slices.Concat(guardCodes(class), s.transportCodes(), opCodes[s.op]) {
				listed[c] = true
			}
		}
		for code, from := range produced {
			if !listed[code] && !refutedAt(s.name, code, "") {
				t.Errorf("%s can answer %s from %s, which opCodes[%q] does not list", s.name, code, from, s.op)
			}
		}
		for _, code := range opCodes[s.op] {
			if _, ok := produced[code]; !ok {
				t.Errorf("%s: opCodes[%q] lists %s, which no producer answers", s.name, s.op, code)
			}
		}
		for _, r := range refuted {
			if r.route == s.name && r.leaf == "" && listed[r.code] {
				t.Errorf("refuted %s %s is listed in its Codes", r.route, r.code)
			}
		}
	}
	for i, r := range refuted {
		if !used[i] {
			t.Errorf("refuted %s %s%s: no producer path reaches it", r.route, r.code, r.leaf)
		}
	}
	for name := range p.unregistered {
		t.Errorf("%s is a producer error with no producerErrors row", name)
	}
}

// oidcConfigRefuted is why no validated configuration reaches an
// oidc.ErrConfigInvalid arm of Begin or Finish.
const oidcConfigRefuted = "Begin's and Finish's session cookie arms (oidc/flow.go:113, :166) are ruled out by access.New validating the Authenticator's cookie config (options.go:86); Begin's seal and size arms (oidc/flow.go:141, :145) by NewProvider's checkFlowFits (oidc/config.go:134), which sizes the largest flow under a cookie Name of at most access.MaxCookieNameBytes (cookie_config.go:303)"

// refuted is each path the analysis follows that the runtime rules out: a
// code the route's producers seem to answer, or, with leaf set, an error
// the error table does not name, each with the invariant that rules it out.
var refuted = []struct {
	route, leaf, invariant string
	code                   Code
}{
	{route: "authKeyCreate", code: CodeNotFound, invariant: "serveKeyCreate passes account.As(c.p), which is never out of band, so admitMinter picks OpCreateOwnKey (account/keys.go:105) and the ErrNotFound arm for OpCreateKeyFor (account/keys.go:168) cannot run"},
	{route: "authOIDCStartSignIn", code: CodeBadRequest, invariant: "the sign-in query decode replaces a redirect over oidc.MaxRedirectBytes with / (accesshttp/query.go:161), so Begin's ErrRedirectTooLong (oidc/flow.go:110) cannot fire"},
	{route: "authOIDCStartSignIn", code: CodeOIDCFailed, invariant: "serveOIDCStartSignIn begins IntentSignIn with no session or user, which BeginRequest.check accepts (oidc/flow.go:49-53), and Begin skips its Sec-Fetch-Site check for a sign-in (oidc/flow.go:118)"},
	{route: "authOIDCStartLink", code: CodeOIDCFailed, invariant: "startSessionFlow refuses a Sec-Fetch-Site other than same-origin before Begin (accesshttp/routes_oidc.go:60) and passes the guard's session ID, 32 hex characters under maxSessionIDBytes, and user ID, which BeginRequest.check accepts (oidc/flow.go:51-53)"},
	{route: "authOIDCStartStepUp", code: CodeOIDCFailed, invariant: "startSessionFlow refuses a Sec-Fetch-Site other than same-origin before Begin (accesshttp/routes_oidc.go:60) and passes the guard's session ID, 32 hex characters under maxSessionIDBytes, and user ID, which BeginRequest.check accepts (oidc/flow.go:51-53)"},
	{route: "authKeyCreate", leaf: modulePath + ".ErrInvalidKeyPrefix", invariant: "begin validates the Rules value CreateAPIKey mints under (account/service.go:319), and Rules.Validate refuses a KeyPrefix access.ValidateKeyPrefix refuses (account/rules.go:136), so GenerateAPIKey (account/keys.go:54) cannot"},
	{route: "authOIDCStartSignIn", leaf: modulePath + "/oidc.ErrConfigInvalid", invariant: oidcConfigRefuted},
	{route: "authOIDCStartLink", leaf: modulePath + "/oidc.ErrConfigInvalid", invariant: oidcConfigRefuted},
	{route: "authOIDCStartStepUp", leaf: modulePath + "/oidc.ErrConfigInvalid", invariant: oidcConfigRefuted},
	{route: "authOIDCCallback", leaf: modulePath + "/oidc.ErrConfigInvalid", invariant: oidcConfigRefuted},
}

const modulePath = "github.com/cplieger/access"

var producerErrors = map[string]error{
	modulePath + "/accesshttp.errMethodNotAllowed":     errMethodNotAllowed,
	modulePath + "/accesshttp.errCrossOrigin":          errCrossOrigin,
	modulePath + "/accesshttp.errPendingTooLarge":      errPendingTooLarge,
	modulePath + "/accesshttp.requestError":            &requestError{reason: "x"},
	modulePath + ".ErrRecentAuthRequired":              access.ErrRecentAuthRequired,
	modulePath + ".ErrHashBusy":                        access.ErrHashBusy,
	modulePath + ".ErrBreachCheckUnavailable":          access.ErrBreachCheckUnavailable,
	modulePath + ".ErrAuthBackend":                     access.ErrAuthBackend,
	modulePath + ".ErrTokenInvalid":                    access.ErrTokenInvalid,
	modulePath + ".PasswordError":                      &access.PasswordError{Reason: access.PasswordCommon},
	modulePath + "/account.ErrSessionRequired":         account.ErrSessionRequired,
	modulePath + "/account.ErrScopeRequired":           account.ErrScopeRequired,
	modulePath + "/account.ErrSSOGoverned":             account.ErrSSOGoverned,
	modulePath + "/account.ErrBreachCheckUnavailable":  account.ErrBreachCheckUnavailable,
	modulePath + "/account.ErrServiceClosed":           account.ErrServiceClosed,
	modulePath + "/account.ErrRulesInvalid":            account.ErrRulesInvalid,
	modulePath + "/account.ErrTTLTooLong":              account.ErrTTLTooLong,
	modulePath + "/account.ErrTTLNegative":             account.ErrTTLNegative,
	modulePath + "/account.ErrNoChange":                account.ErrNoChange,
	modulePath + "/account.ErrKeyExpiryInvalid":        account.ErrKeyExpiryInvalid,
	modulePath + "/account.ErrCurrentPasswordRequired": account.ErrCurrentPasswordRequired,
	modulePath + "/account.ErrUsernameTaken":           account.ErrUsernameTaken,
	modulePath + "/account.ErrPasswordLoginDisabled":   account.ErrPasswordLoginDisabled,
	modulePath + "/account.ErrSetupComplete":           account.ErrSetupComplete,
	modulePath + "/account.ErrSetupTokenRequired":      account.ErrSetupTokenRequired,
	modulePath + "/account.ErrLastMethod":              account.ErrLastMethod,
	modulePath + "/account.ErrOIDCIdentityTaken":       account.ErrOIDCIdentityTaken,
	modulePath + "/account.ErrAlreadyLinked":           account.ErrAlreadyLinked,
	modulePath + "/account.ErrMethodNotLocked":         account.ErrMethodNotLocked,
	modulePath + "/account.ErrDuplicateCredential":     account.ErrDuplicateCredential,
	modulePath + "/account.ErrUnknownScope":            account.ErrUnknownScope,
	modulePath + "/account.ErrPasskeysUnavailable":     account.ErrPasskeysUnavailable,
	modulePath + "/account.ErrCeremonyInvalid":         account.ErrCeremonyInvalid,
	modulePath + "/account.ErrOIDCUnavailable":         account.ErrOIDCUnavailable,
	modulePath + "/account.ErrSessionGone":             account.ErrSessionGone,
	modulePath + "/account.ErrNotFound":                account.ErrNotFound,
	modulePath + "/account.ErrInvalidCredentials":      account.ErrInvalidCredentials,
	modulePath + "/account.ErrPolicyRefused":           account.ErrPolicyRefused,
	modulePath + "/account.PolicyError":                &account.PolicyError{Op: account.OpCreateUser, Reason: account.ReasonAdminTarget},
	modulePath + "/account.RulesError":                 &account.RulesError{Field: "Breach", Reason: "no client"},
	modulePath + "/account.UsernameError":              &account.UsernameError{Reason: account.ReasonTooLong},
	modulePath + "/account.TextError":                  &account.TextError{Field: account.TextFieldLabel, Reason: account.ReasonTooLong},
	modulePath + "/webauthn.ErrResponseTooLarge":       webauthn.ErrResponseTooLarge,
	modulePath + "/webauthn.ErrNotDiscoverable":        webauthn.ErrNotDiscoverable,
	modulePath + "/webauthn.ErrUnknownCredential":      webauthn.ErrUnknownCredential,
	modulePath + "/webauthn.OriginError":               &webauthn.OriginError{Reason: webauthn.RejectNotAllowlisted},
	modulePath + "/ratelimit.RefusedError":             &ratelimit.RefusedError{Dimension: "ip", RetryAfter: time.Second},
	modulePath + "/oidc.ErrRedirectTooLong":            oidc.ErrRedirectTooLong,
	modulePath + "/oidc.ErrStaleAuthentication":        oidc.ErrStaleAuthentication,
	modulePath + "/oidc.ErrFlowInvalid":                oidc.ErrFlowInvalid,
	modulePath + "/oidc.ErrDiscovery":                  oidc.ErrDiscovery,
	modulePath + "/oidc.ErrExchange":                   oidc.ErrExchange,
	modulePath + "/oidc.ErrTokenInvalid":               oidc.ErrTokenInvalid,
	modulePath + "/oidc.ErrNonceMismatch":              oidc.ErrNonceMismatch,
	modulePath + "/oidc.ErrNoUsername":                 oidc.ErrNoUsername,
	modulePath + "/oidc.ErrProvisioningDisabled":       oidc.ErrProvisioningDisabled,
	modulePath + "/oidc.ErrNotAdmitted":                oidc.ErrNotAdmitted,
	modulePath + "/oidc.ProviderError":                 &oidc.ProviderError{Code: "access_denied"},
	modulePath + "/oidc.UsernameError":                 &oidc.UsernameError{},
	modulePath + "/oidc.ErrConfigInvalid":              oidc.ErrConfigInvalid,
	modulePath + ".ErrSealTooLarge":                    access.ErrSealTooLarge,
	modulePath + "/webauthn.ErrCeremonyUnbound":        webauthn.ErrCeremonyUnbound,
	modulePath + ".ErrHashInvalid":                     access.ErrHashInvalid,
	modulePath + ".ErrInvalidKeyPrefix":                access.ErrInvalidKeyPrefix,
	modulePath + ".ErrSealExpired":                     access.ErrSealExpired,
	modulePath + ".ErrSealInvalid":                     access.ErrSealInvalid,
}

// termKind is what one part of an error chain is.
type termKind int

const (
	termLeaf      termKind = iota // a registered error: obj is its var or type name
	termOpaque                    // an error no module producer names
	termParam                     // the error parameter obj holds, bound at the call
	termParamCall                 // what calling parameter obj, or its field at path, returns
	termWrapper                   // an unregistered wrapper type obj, for errors.AsType
	termDeclared                  // refused when it matches a sentinel bound to the slice parameter obj
)

type term struct {
	obj    types.Object
	guards *guardList // the filters a parameter's value passes, applied at its binding
	path   string
	kind   termKind
}

func (t term) key() string {
	k := fmt.Sprintf("%d:%p:%s", t.kind, t.obj, t.path)
	if t.guards != nil {
		k += ":" + t.guards.key
	}
	return k
}

// guardStep is one errors.Is or errors.AsType test a value passed, or
// failed when holds is false.
type guardStep struct {
	test  errTest
	holds bool
}

// guardList is an interned sequence of guard steps, so equal lists are one
// pointer and terms stay comparable.
type guardList struct {
	key   string
	steps []guardStep
}

// chain is the errors one returned value matches: what errors.Is and
// errors.As find in it.
type chain []term

// errValue is every chain an expression can hold, by key.
type errValue map[string]chain

func valueOf(c chain) errValue {
	c = slices.Clone(c)
	slices.SortFunc(c, func(a, b term) int { return strings.Compare(a.key(), b.key()) })
	c = slices.CompactFunc(c, func(a, b term) bool { return a == b })
	keys := make([]string, len(c))
	for i := range c {
		keys[i] = c[i].key()
	}
	return errValue{strings.Join(keys, ","): c}
}

var opaqueValue = valueOf(chain{{kind: termOpaque}})

func (v errValue) add(w errValue) errValue {
	if v == nil {
		v = errValue{}
	}
	maps.Copy(v, w)
	return v
}

// cross is every chain made of one chain of each part; an empty part holds
// no error and adds nothing.
func cross(parts ...errValue) errValue {
	out := valueOf(nil)
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		next := errValue{}
		for _, a := range out {
			for _, b := range part {
				next.add(valueOf(slices.Concat(a, b)))
			}
		}
		out = next
	}
	return out
}

// channel is which errors of a function a summary holds.
type channel int

const (
	chReturned channel = iota // its error result
	chAnswered                // the errors it hands (*Handler).refusal
)

type summaryKey struct {
	n  ast.Node
	ch channel
}

type funcPath struct {
	x    ast.Expr
	path string
}

// varDef is one assignment to a local variable.
type varDef struct {
	at    ast.Node // the defining identifier, or the case clause of a type switch
	rhs   ast.Expr
	index int  // the result of a tuple rhs v takes; -1 for a single value
	rng   bool // v ranges over rhs
}

// producers is the module's non-test code, type-checked from source, and
// the summaries of what its functions return or answer.
type producers struct {
	fset         *token.FileSet
	info         *types.Info
	refusal      *types.Func
	pkgs         map[string]*types.Package
	decls        map[*types.Func]*ast.FuncDecl
	defs         map[*types.Var][]varDef
	inits        map[*types.Var]ast.Expr
	sums         map[summaryKey]errValue
	round        map[summaryKey]int
	stack        map[summaryKey]bool
	parent       map[ast.Node]ast.Node
	guardLists   map[string]*guardList
	evaluating   map[*types.Var]bool
	resolving    map[funcPath]bool
	impls        map[*types.Func][]*types.Func
	unregistered map[string]bool
	module       string
	root         string
	concrete     []types.Type
	iter         int
	changed      bool
}

var errorType = types.Universe.Lookup("error").Type()

func isError(t types.Type) bool {
	return t != nil && types.Implements(t, errorType.Underlying().(*types.Interface))
}

func loadProducers(t *testing.T) *producers {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	module, _, _ := strings.Cut(strings.TrimPrefix(string(mod), "module "), "\n")
	cmd := exec.CommandContext(t.Context(), "go", "list", "-export", "-deps", "-f", "{{.ImportPath}}\t{{.Export}}", "./account", "./accesstest", "./accesshttp")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	exports := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		path, file, _ := strings.Cut(sc.Text(), "\t")
		exports[path] = file
	}
	p := &producers{
		fset: token.NewFileSet(),
		info: &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Defs:       map[*ast.Ident]types.Object{},
			Uses:       map[*ast.Ident]types.Object{},
			Implicits:  map[ast.Node]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
			Instances:  map[*ast.Ident]types.Instance{},
		},
		pkgs:         map[string]*types.Package{},
		decls:        map[*types.Func]*ast.FuncDecl{},
		defs:         map[*types.Var][]varDef{},
		inits:        map[*types.Var]ast.Expr{},
		sums:         map[summaryKey]errValue{},
		round:        map[summaryKey]int{},
		stack:        map[summaryKey]bool{},
		parent:       map[ast.Node]ast.Node{},
		guardLists:   map[string]*guardList{},
		evaluating:   map[*types.Var]bool{},
		resolving:    map[funcPath]bool{},
		impls:        map[*types.Func][]*types.Func{},
		unregistered: map[string]bool{},
		module:       module,
		root:         root,
	}
	gc := importer.ForCompiler(p.fset, "gc", func(path string) (io.ReadCloser, error) {
		file := exports[path]
		if file == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file)
	})
	imp := &moduleImporter{p: p, t: t, gc: gc}
	for _, path := range []string{"account", "accesstest", "accesshttp"} {
		if _, err := imp.Import(module + "/" + path); err != nil {
			t.Fatal(err)
		}
	}
	for _, pkg := range p.pkgs {
		for _, name := range pkg.Scope().Names() {
			tn, ok := pkg.Scope().Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() || types.IsInterface(tn.Type()) {
				continue
			}
			if _, generic := tn.Type().(*types.Named); !generic || tn.Type().(*types.Named).TypeParams().Len() > 0 {
				continue
			}
			p.concrete = append(p.concrete, tn.Type(), types.NewPointer(tn.Type()))
		}
	}
	h, _ := p.accesshttp().Scope().Lookup("Handler").(*types.TypeName)
	m, _, _ := types.LookupFieldOrMethod(types.NewPointer(h.Type()), false, p.accesshttp(), "refusal")
	if p.refusal, _ = m.(*types.Func); p.refusal == nil {
		t.Fatal("no (*Handler).refusal")
	}
	return p
}

type moduleImporter struct {
	p  *producers
	t  *testing.T
	gc types.Importer
}

func (m *moduleImporter) Import(path string) (*types.Package, error) {
	p := m.p
	if path != p.module && !strings.HasPrefix(path, p.module+"/") {
		return m.gc.Import(path)
	}
	if pkg, ok := p.pkgs[path]; ok {
		return pkg, nil
	}
	dir := filepath.Join(p.root, strings.TrimPrefix(path, p.module))
	bp, err := build.Default.ImportDir(dir, 0)
	if err != nil {
		return nil, err
	}
	var files []*ast.File
	for _, name := range bp.GoFiles {
		f, err := parser.ParseFile(p.fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	conf := types.Config{Importer: m}
	pkg, err := conf.Check(path, p.fset, files, p.info)
	if err != nil {
		return nil, err
	}
	p.pkgs[path] = pkg
	for _, f := range files {
		p.index(f)
	}
	return pkg, nil
}

// index records f's function bodies, package initializers and every
// assignment to a variable.
func (p *producers) index(f *ast.File) {
	def := func(lhs, rhs ast.Expr, index int) {
		id, ok := ast.Unparen(lhs).(*ast.Ident)
		if !ok {
			return
		}
		if v, ok := p.info.ObjectOf(id).(*types.Var); ok {
			p.defs[v] = append(p.defs[v], varDef{at: id, rhs: rhs, index: index})
		}
	}
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			p.parent[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		switch n := n.(type) {
		case *ast.FuncDecl:
			if fn, ok := p.info.Defs[n.Name].(*types.Func); ok && n.Body != nil {
				p.decls[fn] = n
			}
		case *ast.AssignStmt:
			switch {
			case len(n.Lhs) == len(n.Rhs):
				for i := range n.Lhs {
					def(n.Lhs[i], n.Rhs[i], -1)
				}
			case len(n.Rhs) == 1:
				for i := range n.Lhs {
					def(n.Lhs[i], n.Rhs[0], i)
				}
			}
		case *ast.ValueSpec:
			for i, name := range n.Names {
				v, ok := p.info.Defs[name].(*types.Var)
				if !ok {
					continue
				}
				switch {
				case len(n.Values) == len(n.Names) && v.Kind() == types.PackageVar:
					p.inits[v] = n.Values[i]
				case len(n.Values) == len(n.Names):
					def(name, n.Values[i], -1)
				case len(n.Values) == 1:
					def(name, n.Values[0], i)
				}
			}
		case *ast.RangeStmt:
			for _, x := range []ast.Expr{n.Key, n.Value} {
				if id, ok := x.(*ast.Ident); ok {
					if v, ok := p.info.ObjectOf(id).(*types.Var); ok {
						p.defs[v] = append(p.defs[v], varDef{at: id, rhs: n.X, rng: true})
					}
				}
			}
		case *ast.TypeSwitchStmt:
			assign, ok := n.Assign.(*ast.AssignStmt)
			if !ok {
				return true
			}
			x := assign.Rhs[0].(*ast.TypeAssertExpr).X
			for _, cc := range n.Body.List {
				if v, ok := p.info.Implicits[cc].(*types.Var); ok {
					p.defs[v] = append(p.defs[v], varDef{at: cc, rhs: x, index: -1})
				}
			}
		}
		return true
	})
}

func (p *producers) inModule(pkg *types.Package) bool {
	return pkg != nil && (pkg.Path() == p.module || strings.HasPrefix(pkg.Path(), p.module+"/"))
}

func qualified(obj types.Object) string { return obj.Pkg().Path() + "." + obj.Name() }

// serveFunc is s.serve's declaration in the loaded accesshttp.
func (p *producers) serveFunc(t *testing.T, s *routeSpec) *ast.FuncDecl {
	t.Helper()
	full := runtime.FuncForPC(reflect.ValueOf(s.serve).Pointer()).Name()
	fn, ok := p.accesshttp().Scope().Lookup(full[strings.LastIndex(full, ".")+1:]).(*types.Func)
	if !ok || p.decls[fn] == nil {
		t.Fatalf("%s: no declaration of %s", s.name, full)
	}
	return p.decls[fn]
}

func (p *producers) accesshttp() *types.Package { return p.pkgs[p.module+"/accesshttp"] }

// routeErrors is every chain s's route can answer from its serve function:
// what it returns, and what it hands (*Handler).refusal itself. It iterates
// to a fixed point over recursive calls.
func (p *producers) routeErrors(fn *ast.FuncDecl) errValue {
	for {
		p.iter++
		p.changed = false
		v := errValue{}.add(p.summary(fn, chReturned)).add(p.summary(fn, chAnswered))
		if !p.changed {
			return v
		}
	}
}

func (p *producers) signature(n ast.Node) (*ast.BlockStmt, *types.Signature) {
	switch n := n.(type) {
	case *ast.FuncDecl:
		return n.Body, p.info.Defs[n.Name].Type().(*types.Signature)
	case *ast.FuncLit:
		return n.Body, p.info.TypeOf(n).(*types.Signature)
	}
	panic(fmt.Sprintf("no function: %T", n))
}

// summary is what n returns in its last error result, or hands refusal,
// with its parameters left as terms.
func (p *producers) summary(n ast.Node, ch channel) errValue {
	k := summaryKey{n: n, ch: ch}
	if p.round[k] == p.iter || p.stack[k] {
		return p.sums[k]
	}
	p.stack[k] = true
	var out errValue
	if ch == chReturned {
		out = p.returned(n)
	} else {
		out = p.answered(n)
	}
	delete(p.stack, k)
	p.round[k] = p.iter
	if len(out) != len(p.sums[k]) {
		p.changed = true
	}
	p.sums[k] = out
	return out
}

func (p *producers) returned(n ast.Node) errValue {
	body, sig := p.signature(n)
	idx := -1
	for i := range sig.Results().Len() {
		if types.Identical(sig.Results().At(i).Type(), errorType) {
			idx = i
		}
	}
	if idx < 0 {
		return nil
	}
	var out errValue
	ast.Inspect(body, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			switch {
			case len(x.Results) == 0:
				out = out.add(p.evalVar(sig.Results().At(idx)))
			case len(x.Results) == sig.Results().Len():
				out = out.add(p.eval(x.Results[idx]))
			case len(x.Results) == 1:
				out = out.add(p.evalCall(x.Results[0], idx))
			}
		}
		return true
	})
	return out
}

// answered is what n's body, closures included, hands refusal, directly or
// through another accesshttp function.
func (p *producers) answered(n ast.Node) errValue {
	body, _ := p.signature(n)
	var out errValue
	ast.Inspect(body, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := p.callee(call.Fun).(*types.Func)
		if !ok || fn.Pkg() != p.accesshttp() {
			return true
		}
		if fn == p.refusal {
			out = out.add(p.eval(call.Args[1]))
		} else if decl := p.decls[fn.Origin()]; decl != nil {
			out = out.add(p.bind(p.summary(decl, chAnswered), decl, call))
		}
		return true
	})
	return out
}

func (p *producers) eval(e ast.Expr) errValue {
	e = ast.Unparen(e)
	if tv, ok := p.info.Types[e]; ok && (tv.IsNil() || !isError(tv.Type)) {
		return nil
	}
	switch e := e.(type) {
	case *ast.Ident:
		v, ok := p.info.Uses[e].(*types.Var)
		if ok && v.Kind() != types.PackageVar {
			return p.guarded(e, v, p.evalLocal(v, e))
		}
		return p.evalObj(p.info.Uses[e])
	case *ast.SelectorExpr:
		sel, ok := p.info.Selections[e]
		switch {
		case !ok:
			return p.evalObj(p.info.Uses[e.Sel])
		case sel.Kind() == types.FieldVal && isError(p.info.TypeOf(e.X)):
			return p.eval(e.X)
		}
	case *ast.CallExpr:
		return p.evalCall(e, -1)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return p.evalAddr(e.X)
		}
	case *ast.CompositeLit:
		return p.evalLit(e)
	case *ast.TypeAssertExpr:
		return p.eval(e.X)
	}
	return opaqueValue
}

func registered(obj types.Object) bool {
	_, ok := producerErrors[qualified(obj)]
	return ok
}

// leaf is obj as a chain's leaf; an exported one with no producerErrors
// row is recorded, for the test to name.
func (p *producers) leaf(obj types.Object) errValue {
	if !registered(obj) {
		p.unregistered[qualified(obj)] = true
	}
	return valueOf(chain{{kind: termLeaf, obj: obj}})
}

func (p *producers) evalObj(obj types.Object) errValue {
	v, ok := obj.(*types.Var)
	if !ok {
		return opaqueValue
	}
	switch v.Kind() {
	case types.PackageVar:
		switch {
		case !p.inModule(v.Pkg()):
			return opaqueValue
		case registered(v) || v.Exported():
			return p.leaf(v)
		case p.inits[v] != nil:
			return p.eval(p.inits[v])
		}
		return opaqueValue
	case types.ParamVar, types.RecvVar:
		return valueOf(chain{{kind: termParam, obj: v}}).add(p.evalVar(v))
	default:
		return p.evalVar(v)
	}
}

// evalLocal is what local or parameter v holds where ref reads it: the
// definitions before ref from the last one in a block enclosing ref, or,
// when none precedes it, every definition and the parameter's own value.
func (p *producers) evalLocal(v *types.Var, ref ast.Node) errValue {
	var before []varDef
	kill := -1
	for _, d := range p.defs[v] {
		if d.at.Pos() >= ref.Pos() {
			continue
		}
		if p.encloses(p.block(d.at), ref) {
			kill = len(before)
		}
		before = append(before, d)
	}
	if len(before) == 0 {
		return p.evalObj(v)
	}
	if kill < 0 && (v.Kind() == types.ParamVar || v.Kind() == types.RecvVar) {
		return valueOf(chain{{kind: termParam, obj: v}}).add(p.evalDefs(v, before))
	}
	return p.evalDefs(v, before[max(kill, 0):])
}

// block is the statement list n sits in.
func (p *producers) block(n ast.Node) ast.Node {
	for n = p.parent[n]; n != nil; n = p.parent[n] {
		switch n.(type) {
		case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause:
			return n
		}
	}
	return nil
}

func (p *producers) encloses(outer, n ast.Node) bool {
	for ; n != nil; n = p.parent[n] {
		if n == outer {
			return true
		}
	}
	return false
}

func (p *producers) evalVar(v *types.Var) errValue { return p.evalDefs(v, p.defs[v]) }

func (p *producers) evalDefs(v *types.Var, defs []varDef) errValue {
	if p.evaluating[v] {
		return nil
	}
	p.evaluating[v] = true
	defer delete(p.evaluating, v)
	var out errValue
	for _, d := range defs {
		switch {
		case d.rng:
			out = out.add(p.elements(d.rhs))
		case d.index >= 0:
			out = out.add(p.evalCall(d.rhs, d.index))
		default:
			out = out.add(p.eval(d.rhs))
		}
	}
	return out
}

// elements is what ranging over x yields: a package slice literal's
// elements.
func (p *producers) elements(x ast.Expr) errValue {
	if id, ok := ast.Unparen(x).(*ast.Ident); ok {
		if v, ok := p.info.Uses[id].(*types.Var); ok {
			if lit, ok := p.inits[v].(*ast.CompositeLit); ok {
				var out errValue
				for _, elt := range lit.Elts {
					out = out.add(p.eval(elt))
				}
				return out
			}
		}
	}
	return opaqueValue
}

// evalLit is an error literal: a registered or exported type is a leaf
// over its error fields, any other is its error fields alone.
func (p *producers) evalLit(lit *ast.CompositeLit) errValue {
	var fields []errValue
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			elt = kv.Value
		}
		fields = append(fields, p.eval(elt))
	}
	children := cross(fields...)
	named, ok := p.info.TypeOf(lit).(*types.Named)
	switch {
	case !ok || !p.inModule(named.Obj().Pkg()):
		return opaqueValue
	case registered(named.Obj()) || named.Obj().Exported():
		return cross(p.leaf(named.Obj()), children)
	}
	if c, ok := children[""]; ok && len(c) == 0 {
		children = opaqueValue
	}
	return cross(valueOf(chain{{kind: termWrapper, obj: named.Obj()}}), children)
}

// evalAddr is &x for an x whose pointer is the error: a literal, or a
// variable of a registered or exported type, or else what its literals hold.
func (p *producers) evalAddr(x ast.Expr) errValue {
	x = ast.Unparen(x)
	if lit, ok := x.(*ast.CompositeLit); ok {
		return p.evalLit(lit)
	}
	named, ok := p.info.TypeOf(x).(*types.Named)
	switch {
	case !ok || !p.inModule(named.Obj().Pkg()):
		return opaqueValue
	case registered(named.Obj()) || named.Obj().Exported():
		return p.leaf(named.Obj())
	}
	id, ok := x.(*ast.Ident)
	if !ok {
		return opaqueValue
	}
	v, _ := p.info.Uses[id].(*types.Var)
	var out errValue
	for _, d := range p.defs[v] {
		if lit, ok := ast.Unparen(d.rhs).(*ast.CompositeLit); ok && d.index < 0 {
			out = out.add(p.evalLit(lit))
		}
	}
	if out == nil {
		return opaqueValue
	}
	return out
}

// callee is the object fun names, through an instantiation.
func (p *producers) callee(fun ast.Expr) types.Object {
	switch f := ast.Unparen(fun).(type) {
	case *ast.Ident:
		return p.info.Uses[f]
	case *ast.SelectorExpr:
		return p.info.Uses[f.Sel]
	case *ast.IndexExpr:
		return p.callee(f.X)
	case *ast.IndexListExpr:
		return p.callee(f.X)
	}
	return nil
}

// evalCall is the error e's call returns in result index, or in its only
// result when index is -1.
func (p *producers) evalCall(e ast.Expr, index int) errValue {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		if ta, ok := ast.Unparen(e).(*ast.TypeAssertExpr); ok && index == 0 {
			return p.eval(ta.X)
		}
		return opaqueValue
	}
	if p.info.Types[call.Fun].IsType() {
		return p.eval(call.Args[0])
	}
	sig, ok := p.info.TypeOf(call.Fun).Underlying().(*types.Signature)
	index = max(index, 0)
	if !ok || index >= sig.Results().Len() || !isError(sig.Results().At(index).Type()) {
		return nil
	}
	fn, ok := p.callee(call.Fun).(*types.Func)
	if !ok {
		return p.callValue(call.Fun, "")
	}
	switch qualified(fn.Origin()) {
	case "errors.New":
		return opaqueValue
	case "fmt.Errorf":
		return p.wrap(call.Args[1:])
	case "errors.Join":
		return p.wrap(call.Args)
	case "errors.AsType":
		return p.filter(p.eval(call.Args[0]), asTypeTest(p.info.TypeOf(call)), true)
	case "errors.Unwrap":
		return p.eval(call.Args[0])
	case p.module + "/account.refusedBy":
		return p.declare(p.eval(call.Args[0]), call.Args[1:], call.Ellipsis.IsValid())
	}
	return p.callFunc(fn, call)
}

// declare is account.refusedBy(val, sentinels...): each chain of val that
// matches a sentinel among args gains the refusal wrapper. A forwarded
// parameter slice leaves the decision to its binding.
func (p *producers) declare(val errValue, args []ast.Expr, ellipsis bool) errValue {
	if ellipsis && len(args) == 1 {
		if id, ok := ast.Unparen(args[0]).(*ast.Ident); ok {
			if v, ok := p.info.Uses[id].(*types.Var); ok && v.Kind() == types.ParamVar {
				return cross(val, valueOf(chain{{kind: termDeclared, obj: v}}))
			}
		}
		return val
	}
	var sentinels []types.Object
	for _, a := range args {
		if obj := p.callee(a); obj != nil {
			sentinels = append(sentinels, obj)
		}
	}
	return p.refuseMatching(val, sentinels)
}

func (p *producers) refuseMatching(val errValue, sentinels []types.Object) errValue {
	refusal := p.pkgs[p.module+"/account"].Scope().Lookup("refusal")
	out := errValue{}
	for _, c := range val {
		matched := false
		for _, s := range sentinels {
			if m, _ := matches(c, errTest{sentinel: s}); m {
				matched = true
			}
		}
		if matched {
			c = append(slices.Clone(c), term{kind: termWrapper, obj: refusal})
		}
		out.add(valueOf(c))
	}
	return out
}

// wrap is fmt.Errorf's or errors.Join's error over args: every error
// argument's chains joined, or an opaque error when none is an error.
func (p *producers) wrap(args []ast.Expr) errValue {
	var parts []errValue
	for _, a := range args {
		if isError(p.info.TypeOf(a)) {
			parts = append(parts, p.eval(a))
		}
	}
	out := cross(parts...)
	if c, ok := out[""]; ok && len(c) == 0 {
		delete(out, "")
		out.add(opaqueValue)
	}
	return out
}

// callFunc is what calling fn returns: its summary bound to call's
// arguments, over every module implementation of an interface method.
func (p *producers) callFunc(fn *types.Func, call *ast.CallExpr) errValue {
	fn = fn.Origin()
	if decl := p.decls[fn]; decl != nil {
		return p.bind(p.summary(decl, chReturned), decl, call)
	}
	var out errValue
	for _, m := range p.implementations(fn) {
		decl := p.decls[m]
		out = out.add(p.bind(p.summary(decl, chReturned), decl, call))
	}
	if out == nil {
		return opaqueValue
	}
	return out
}

// implementations is every module method an interface method fn
// dispatches to.
func (p *producers) implementations(fn *types.Func) []*types.Func {
	if impls, ok := p.impls[fn]; ok {
		return impls
	}
	var impls []*types.Func
	if recv := fn.Signature().Recv(); recv != nil && types.IsInterface(recv.Type()) {
		iface := recv.Type().Underlying().(*types.Interface)
		for _, typ := range p.concrete {
			if !types.Implements(typ, iface) {
				continue
			}
			m, _, _ := types.LookupFieldOrMethod(typ, false, fn.Pkg(), fn.Name())
			if mf, ok := m.(*types.Func); ok && p.decls[mf.Origin()] != nil && !slices.Contains(impls, mf.Origin()) {
				impls = append(impls, mf.Origin())
			}
		}
	}
	p.impls[fn] = impls
	return impls
}

// callValue is what calling the function value x, or its field at path,
// returns, the function's own parameters unbound.
func (p *producers) callValue(x ast.Expr, path string) errValue {
	x = ast.Unparen(x)
	k := funcPath{x: x, path: path}
	if p.resolving[k] {
		return nil
	}
	p.resolving[k] = true
	defer delete(p.resolving, k)
	switch x := x.(type) {
	case *ast.FuncLit:
		if path == "" {
			return p.bind(p.summary(x, chReturned), x, nil)
		}
	case *ast.UnaryExpr:
		return p.callValue(x.X, path)
	case *ast.CompositeLit:
		field, rest, _ := strings.Cut(path, ".")
		for _, elt := range x.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok && isIdentNamed(kv.Key, field) {
				return p.callValue(kv.Value, rest)
			}
		}
		return nil
	case *ast.SelectorExpr:
		if sel, ok := p.info.Selections[x]; ok && sel.Kind() == types.FieldVal {
			return p.callValue(x.X, strings.TrimSuffix(x.Sel.Name+"."+path, "."))
		}
	case *ast.CallExpr:
		return p.returnedFuncs(x, path)
	}
	switch obj := p.callee(x).(type) {
	case *types.Func:
		if path != "" {
			break
		}
		if decl := p.decls[obj.Origin()]; decl != nil {
			return p.bind(p.summary(decl, chReturned), decl, nil)
		}
		var out errValue
		for _, m := range p.implementations(obj.Origin()) {
			out = out.add(p.bind(p.summary(p.decls[m], chReturned), p.decls[m], nil))
		}
		if out != nil {
			return out
		}
	case *types.Var:
		switch obj.Kind() {
		case types.ParamVar, types.RecvVar:
			return valueOf(chain{{kind: termParamCall, obj: obj, path: path}})
		case types.PackageVar:
			if init := p.inits[obj]; init != nil {
				return p.callValue(init, path)
			}
		default:
			var out errValue
			for _, d := range p.defs[obj] {
				if d.index < 0 && !d.rng {
					out = out.add(p.callValue(d.rhs, path))
				}
			}
			return out
		}
	}
	return opaqueValue
}

// returnedFuncs is what calling the function value call returns, or its
// field at path: the values its callee's return statements give.
func (p *producers) returnedFuncs(call *ast.CallExpr, path string) errValue {
	fn, ok := p.callee(call.Fun).(*types.Func)
	if !ok || p.decls[fn.Origin()] == nil {
		return opaqueValue
	}
	var out errValue
	ast.Inspect(p.decls[fn.Origin()].Body, func(x ast.Node) bool {
		switch x := x.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(x.Results) == 1 {
				out = out.add(p.callValue(x.Results[0], path))
			}
		}
		return true
	})
	return out
}

// bind replaces fn's parameter terms in sum with call's arguments; with no
// call, it drops them.
func (p *producers) bind(sum errValue, fn ast.Node, call *ast.CallExpr) errValue {
	_, sig := p.signature(fn)
	args := map[*types.Var][]ast.Expr{}
	params := sig.Params()
	for v := range params.Variables() {
		args[v] = nil
	}
	if recv := sig.Recv(); recv != nil {
		args[recv] = nil
		if call != nil {
			if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && p.info.Selections[sel] != nil {
				args[recv] = []ast.Expr{sel.X}
			}
		}
	}
	if call != nil && params.Len() > 0 {
		for i, a := range call.Args {
			v := params.At(min(i, params.Len()-1))
			args[v] = append(args[v], a)
		}
	}
	var out errValue
	for _, c := range sum {
		var fixed chain
		var parts []errValue
		var markers [][]ast.Expr
		for _, tm := range c {
			v, _ := tm.obj.(*types.Var)
			bound, isArg := args[v]
			if tm.kind == termDeclared && isArg {
				markers = append(markers, bound)
				continue
			}
			if !isArg || tm.kind == termLeaf || tm.kind == termOpaque || tm.kind == termWrapper || tm.kind == termDeclared {
				fixed = append(fixed, tm)
				continue
			}
			part := errValue{}
			for _, a := range bound {
				if tm.kind == termParam {
					part.add(p.eval(a))
				} else {
					part.add(p.callValue(a, tm.path))
				}
			}
			if tm.guards != nil {
				for _, st := range tm.guards.steps {
					part = p.filter(part, st.test, st.holds)
				}
			}
			if len(part) == 0 {
				parts = nil
				fixed = nil
				break
			}
			parts = append(parts, part)
		}
		if fixed == nil && parts == nil {
			continue
		}
		joinedAll := cross(append(parts, valueOf(fixed))...)
		for _, bound := range markers {
			joinedAll = p.declare(joinedAll, bound, call != nil && call.Ellipsis.IsValid())
		}
		for _, joined := range joinedAll {
			if len(joined) > 0 {
				out = out.add(valueOf(joined))
			}
		}
	}
	return out
}

// values is c's registered errors, false when c holds an unregistered one.
func values(c chain) ([]error, bool) {
	var vals []error
	for _, tm := range c {
		if tm.kind != termLeaf {
			continue
		}
		v, ok := producerErrors[qualified(tm.obj)]
		if !ok {
			return nil, false
		}
		vals = append(vals, v)
	}
	return vals, true
}

func chainString(c chain) string {
	parts := make([]string, len(c))
	for i, tm := range c {
		switch tm.kind {
		case termLeaf:
			parts[i] = strings.TrimPrefix(strings.Replace(qualified(tm.obj), modulePath+".", "access.", 1), modulePath+"/")
		case termOpaque:
			parts[i] = "opaque"
		case termWrapper:
			parts[i] = "wrapper " + tm.obj.Name()
		case termDeclared:
			parts[i] = "declared " + tm.obj.Name()
		default:
			parts[i] = "param " + tm.obj.Name() + " " + tm.path
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// errTest is a guard's test of one error: errors.Is against a sentinel, or
// errors.AsType for a type.
type errTest struct {
	sentinel types.Object
	typ      *types.TypeName
}

func asTypeTest(result types.Type) errTest {
	tuple, ok := result.(*types.Tuple)
	if !ok || tuple.Len() == 0 {
		return errTest{}
	}
	typ := tuple.At(0).Type()
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	named, ok := typ.(*types.Named)
	if !ok {
		return errTest{}
	}
	return errTest{typ: named.Obj()}
}

// matches reports whether test holds for c, and false for known when the
// chain or the test is not one the registry can decide.
func matches(c chain, test errTest) (match, known bool) {
	params := false
	for _, tm := range c {
		if tm.obj != nil && (tm.obj == test.sentinel || tm.obj == test.typ) && (tm.kind == termLeaf || tm.kind == termWrapper) {
			return true, true
		}
		params = params || isParamTerm(tm)
	}
	vals, ok := values(c)
	if !ok {
		return false, false
	}
	if params {
		match, known := matchValues(vals, test)
		return match, known && match
	}
	return matchValues(vals, test)
}

func matchValues(vals []error, test errTest) (match, known bool) {
	joined := errors.Join(vals...)
	switch {
	case test.sentinel != nil:
		target, ok := producerErrors[qualified(test.sentinel)]
		return ok && errors.Is(joined, target), ok
	case test.typ != nil:
		target, ok := producerErrors[qualified(test.typ)]
		if !ok {
			return false, !registered(test.typ) && !test.typ.Exported()
		}
		ptr := reflect.New(reflect.TypeOf(target))
		return errors.As(joined, ptr.Interface()), true
	}
	return false, false
}

// filter keeps the chains of val for which test holds, or, when holds is
// false, those for which it does not; a chain it cannot decide stays.
func (p *producers) filter(val errValue, test errTest, holds bool) errValue {
	if test.sentinel == nil && test.typ == nil {
		return val
	}
	out := errValue{}
	for k, c := range val {
		match, known := matches(c, test)
		switch {
		case known && match == holds:
			out[k] = c
		case known:
		case slices.ContainsFunc(c, isParamTerm) && !match:
			out.add(valueOf(p.deferGuard(c, guardStep{test: test, holds: holds})))
		default:
			out[k] = c
		}
	}
	return out
}

func isParamTerm(t term) bool { return t.kind == termParam || t.kind == termParamCall }

// deferGuard adds step to each parameter term of c, for its binding.
func (p *producers) deferGuard(c chain, step guardStep) chain {
	out := slices.Clone(c)
	for i, t := range out {
		if !isParamTerm(t) {
			continue
		}
		var steps []guardStep
		if t.guards != nil {
			steps = slices.Clone(t.guards.steps)
		}
		steps = append(steps, step)
		key := ""
		for _, st := range steps {
			key += fmt.Sprintf("%p/%p/%t;", st.test.sentinel, st.test.typ, st.holds)
		}
		if p.guardLists[key] == nil {
			p.guardLists[key] = &guardList{key: key, steps: steps}
		}
		out[i].guards = p.guardLists[key]
	}
	return out
}

// guard is the test cond makes of v: errors.Is(v, S), v == S, or the ok of
// an errors.AsType[T](v) its init assigns; holds is false under a negation.
func (p *producers) guard(v *types.Var, init ast.Stmt, cond ast.Expr) (test errTest, holds bool) {
	isV := func(e ast.Expr) bool {
		id, ok := ast.Unparen(e).(*ast.Ident)
		return ok && p.info.Uses[id] == v
	}
	switch c := ast.Unparen(cond).(type) {
	case *ast.UnaryExpr:
		if c.Op == token.NOT {
			test, holds = p.guard(v, init, c.X)
			return test, !holds
		}
	case *ast.BinaryExpr:
		if (c.Op == token.EQL || c.Op == token.NEQ) && isV(c.X) {
			if obj := p.callee(c.Y); obj != nil && obj.Name() != "nil" {
				return errTest{sentinel: obj}, c.Op == token.EQL
			}
		}
	case *ast.CallExpr:
		if fn, ok := p.callee(c.Fun).(*types.Func); ok && qualified(fn) == "errors.Is" && isV(c.Args[0]) {
			if obj, ok := p.callee(c.Args[1]).(*types.Var); ok && obj.Kind() == types.PackageVar {
				return errTest{sentinel: obj}, true
			}
		}
	case *ast.Ident:
		assign, ok := init.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 || p.info.ObjectOf(c) != p.info.ObjectOf(assign.Lhs[1].(*ast.Ident)) {
			break
		}
		if call, ok := assign.Rhs[0].(*ast.CallExpr); ok && len(call.Args) == 1 && isV(call.Args[0]) {
			if fn, ok := p.callee(call.Fun).(*types.Func); ok && qualified(fn) == "errors.AsType" {
				return asTypeTest(p.info.TypeOf(call)), true
			}
		}
	}
	return errTest{}, false
}

// guarded filters val, the value of v read at id, by the errors.Is and
// errors.AsType tests control passed to reach id: the if or case it sits
// in, the cases before that, and every terminating if before it in an
// enclosing block.
func (p *producers) guarded(id *ast.Ident, v *types.Var, val errValue) errValue {
	apply := func(init ast.Stmt, cond ast.Expr, taken bool) {
		if test, holds := p.guard(v, init, cond); test.sentinel != nil || test.typ != nil {
			val = p.filter(val, test, holds == taken)
		}
	}
	for child, n := ast.Node(id), p.parent[id]; n != nil; child, n = n, p.parent[n] {
		switch n := n.(type) {
		case *ast.FuncLit, *ast.FuncDecl:
			return val
		case *ast.IfStmt:
			switch child {
			case n.Body:
				apply(n.Init, n.Cond, true)
			case n.Else:
				apply(n.Init, n.Cond, false)
			}
		case *ast.CaseClause:
			sw, ok := p.parent[p.parent[n]].(*ast.SwitchStmt)
			if !ok || sw.Tag != nil || slices.ContainsFunc(n.List, func(e ast.Expr) bool { return e == child }) {
				break
			}
			for _, prior := range sw.Body.List {
				if prior == n {
					break
				}
				for _, cond := range prior.(*ast.CaseClause).List {
					apply(nil, cond, false)
				}
			}
			if len(n.List) == 1 {
				apply(nil, n.List[0], true)
			}
		case *ast.BlockStmt:
			for _, st := range n.List {
				if st == child {
					break
				}
				if is, ok := st.(*ast.IfStmt); ok && is.Else == nil && terminates(is.Body) {
					apply(is.Init, is.Cond, false)
				}
			}
		}
	}
	return val
}

// terminates reports whether b ends in a return or a panic.
func terminates(b *ast.BlockStmt) bool {
	if len(b.List) == 0 {
		return false
	}
	switch last := b.List[len(b.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.ExprStmt:
		call, ok := last.X.(*ast.CallExpr)
		return ok && isIdentNamed(call.Fun, "panic")
	}
	return false
}
