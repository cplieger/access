package accesshttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
)

const regenerateGolden = "UPDATE_GOLDEN=1 go test ./accesshttp/ -run '^TestGoldenWire$'"

// wireDir is where the TypeScript half reads the fixtures; the module
// cache holds no web/, so a run there has nothing to compare against.
const wireDir = "../web/testdata/wire"

// fixture is one wire file: a request or response value, written as the
// browser sends or receives it.
type fixture struct {
	value any
	// shown is the plaintext writeShownOnce puts in a show-once response.
	shown access.Secret
	name  string
	// absent is the JSON key a variant leaves out; such a variant is not a
	// type's main fixture and is not walked for zero fields.
	absent  string
	request bool
}

var (
	goldenTime  = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	goldenLater = time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	goldenRole  = access.RoleAdmin
	goldenTrue  = true
)

func goldenUser() UserView {
	return UserView{
		ID: 7, Username: "alice", DisplayName: "Alice", Role: access.RoleUser, Enabled: true, OIDCLinked: true,
		CreatedAt: goldenTime, KeyLineage: []int64{3, 5}, Methods: &UserMethodsView{Password: true, PasskeyCount: 2},
	}
}

func goldenMethods() MethodsView {
	return MethodsView{
		Locks:    []MethodLockView{{Method: access.MethodPassword, Untrusted: true, Trusted: true}},
		Password: true, PasskeyCount: 1, OIDCLinked: true, OIDCAvailable: true, PasskeysAvailable: true, PasswordLogin: true,
	}
}

func goldenKey() KeyView {
	return KeyView{
		ID: 5, UserID: 7, Owner: "alice", Label: "ci", Prefix: "ak_7", Suffix: "wxyz", Scopes: []string{"read"},
		CreatedAt: goldenTime, ExpiresAt: goldenLater, LastUsedAt: goldenTime, ParentKeyID: 3,
	}
}

// fixtures is every wire file the tests write, request fixtures first.
func fixtures() []fixture {
	signals := webauthn.Signals{
		CurrentUserDetails: webauthn.SignalCurrentUserDetails{RPID: testRPID, Name: "alice", DisplayName: "Alice", UserID: webauthn.Base64URL("handle")},
		AllAcceptedCredentials: webauthn.SignalAllAcceptedCredentials{
			RPID: testRPID, UserID: webauthn.Base64URL("handle"), AllAcceptedCredentialIDs: []webauthn.Base64URL{webauthn.Base64URL("credential")},
		},
	}
	return []fixture{
		{name: "SetupPasswordRequest", request: true, value: SetupPasswordRequest{Token: "fixture-setup-token", Username: "owner", Password: "fixture-password"}},
		{name: "SetupPasswordRequest.noToken", absent: "token", request: true, value: SetupPasswordRequest{Username: "owner", Password: "fixture-password"}},
		{name: "SetupPasskeyBeginRequest", request: true, value: SetupPasskeyBeginRequest{Token: "fixture-setup-token", Username: "owner"}},
		{name: "SetupPasskeyBeginRequest.noToken", absent: "token", request: true, value: SetupPasskeyBeginRequest{Username: "owner"}},
		{name: "LoginRequest", request: true, value: LoginRequest{Username: "alice", Password: "fixture-password"}},
		{name: "RedirectRequest", request: true, value: RedirectRequest{Redirect: "/settings"}},
		{name: "TokenRequest", request: true, value: TokenRequest{Token: "fixture-recovery-token"}},
		{name: "RecoverPasswordRequest", request: true, value: RecoverPasswordRequest{Password: "fixture-password", KeepSessions: true, KeepKeys: true}},
		{name: "InviteAcceptRequest", request: true, value: InviteAcceptRequest{Token: "fixture-invite-token", Username: "bob", Password: "fixture-password"}},
		{name: "ProfileRequest", request: true, value: ProfileRequest{DisplayName: "Alice"}},
		{name: "PasswordRequest", request: true, value: PasswordRequest{Password: "fixture-password"}},
		{name: "PasswordChangeRequest", request: true, value: PasswordChangeRequest{CurrentPassword: "fixture-old-password", Password: "fixture-password"}},
		{name: "PasswordChangeRequest.noCurrent", absent: "current_password", request: true, value: PasswordChangeRequest{Password: "fixture-password"}},
		{name: "PasswordRemoveRequest", request: true, value: PasswordRemoveRequest{CurrentPassword: "fixture-password"}},
		{name: "NameRequest", request: true, value: NameRequest{Name: "laptop"}},
		{name: "NewKeyRequest", request: true, value: NewKeyRequest{Label: "ci", Scopes: []string{"read"}, ExpiresInDays: 30}},
		{name: "NewUserRequest", request: true, value: NewUserRequest{Username: "bob", Password: "fixture-password", Role: access.RoleUser}},
		{name: "NewUserRequest.noPassword", absent: "password", request: true, value: NewUserRequest{Username: "bob", Role: access.RoleUser}},
		{name: "UserUpdateRequest", request: true, value: UserUpdateRequest{Role: &goldenRole, Enabled: &goldenTrue}},
		{name: "TTLRequest", request: true, value: TTLRequest{Hours: 24}},
		{name: "InviteRequest", request: true, value: InviteRequest{Role: access.RoleUser, Hours: 72}},

		{name: "StateResponse", value: StateResponse{SetupRequired: true, PasswordLogin: true, Passkeys: true, OIDC: true}},
		{name: "SignedInResponse", value: SignedInResponse{SessionID: "s1", User: goldenUser(), CloneWarning: true}},
		{name: "CeremonyResponse", value: CeremonyResponse{Ceremony: "c1", PublicKey: json.RawMessage(`{"publicKey":{"challenge":"Y2hhbGxlbmdl"},"mediation":"conditional"}`)}},
		{name: "OIDCStartResponse", value: OIDCStartResponse{URL: "https://idp.example.com/authorize?state=x"}},
		{name: "PendingLinkResponse", value: PendingLinkResponse{Issuer: "https://idp.example.com", UsernameHint: "alice", Email: "alice@example.com"}},
		{name: "MeResponse", value: MeResponse{
			User: goldenUser(), Methods: goldenMethods(), CanLinkOIDC: true, SSOGoverned: true,
			Session: CurrentSessionView{ID: "s1", Method: access.MethodPasskey, AuthTime: goldenTime, IdleDeadline: goldenTime, AbsoluteDeadline: goldenLater},
		}},
		{name: "RecoveryResponse", value: RecoveryResponse{Username: "alice", Methods: goldenMethods()}},
		{name: "PasskeyView", value: PasskeyView{
			ID: 2, Name: "laptop", RPID: testRPID, CreatedAt: goldenTime, LastUsedAt: goldenLater,
			BackupEligible: true, BackedUp: true, CloneWarning: true,
		}},
		{name: "Signals", value: signals},
		{name: "SessionView", value: SessionView{
			ID: "s1", Label: "laptop", UserAgent: "Firefox", LastIP: "192.0.2.1", Method: access.MethodPassword, Current: true,
			CreatedAt: goldenTime, LastActivity: goldenTime, AuthTime: goldenTime, IdleDeadline: goldenLater, AbsoluteDeadline: goldenLater,
		}},
		{name: "KeyView", value: goldenKey()},
		{name: "KeyCreatedResponse", value: KeyCreatedResponse{Details: goldenKey()}, shown: access.NewSecret("fixture-api-key")},
		{name: "UserView", value: goldenUser()},
		{name: "TokenResponse", value: TokenResponse{ExpiresAt: goldenLater}, shown: access.NewSecret("fixture-token")},
		{name: "TokenView", value: TokenView{
			CreatedAt: goldenTime, ExpiresAt: goldenLater, Purpose: access.PurposeRecovery, Role: access.RoleUser,
			IssuerLineage: []int64{3, 5}, Subject: 7, IssuedByKey: 5,
		}},
		{name: "SecurityLogView", value: SecurityLogView{
			Entries: []LogEntryView{{
				Seq: 42, At: goldenLater, OccurredAt: goldenTime, Class: account.LogClassChange, Kind: string(account.EventPasskeyAdded),
				UserID: 7, IP: "192.0.2.1", SessionIDs: []string{"s1", "s2"}, KeyID: 5, PasskeyID: 2,
				Method: access.MethodPasskey, Role: access.RoleUser, Trusted: true, Detail: "fixture-detail",
				Actor: LogActorView{
					UserID: 7, SessionID: "s1", KeyID: 5, OutOfBand: "cli",
					Label: "laptop", UserAgent: "Firefox", KeySuffix: "wxyz",
				},
			}},
			Classes: []LogClassView{
				{Class: account.LogClassChange, Count: 12, Evicted: 3},
				{Class: account.LogClassSession, Count: 40, Evicted: 9},
			},
		}},
	}
}

// fixtureBytes is f as it crosses the wire: a request as the client
// encodes it, a response through the writer its handler uses.
func fixtureBytes(t *testing.T, f *fixture) []byte {
	t.Helper()
	if f.request {
		b, err := json.Marshal(f.value)
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		return append(b, '\n')
	}
	w := httptest.NewRecorder()
	switch v := f.value.(type) {
	case KeyCreatedResponse:
		writeShownOnce(w, http.StatusCreated, v, f.shown)
	case TokenResponse:
		writeShownOnce(w, http.StatusCreated, v, f.shown)
	default:
		writeJSON(w, http.StatusOK, v)
	}
	return w.Body.Bytes()
}

func indexedJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent: %v", err)
	}
	return append(b, '\n')
}

// goldenPrefix and goldenOIDCPrefix are the prefixes TestGoldenWire mounts
// its routes under; neither starts the other, so routes.json can put its
// placeholder back on each path.
const (
	goldenPrefix     = "/p"
	goldenOIDCPrefix = "/o"
)

// wireRoute is one row of routes.json: a route's Descriptor as the
// TypeScript client calls it, its path under {prefix} or {oidcPrefix}.
type wireRoute struct {
	Request  *string `json:"request"`
	Response *string `json:"response"`
	Name     string  `json:"name"`
	Method   string  `json:"method"`
	Path     string  `json:"path"`
	Kind     Kind    `json:"kind"`
	Array    bool    `json:"array"`
}

// wireField is one JSON key of a wire type in types.json; Optional is a
// key the encoder may leave out (omitempty, omitzero) or send as null (a
// pointer). Values are the constants of a field whose type is a named
// string type with constants, and Open says the type also takes values
// outside them; Fields are the keys of a struct-typed field, or of each
// element of a struct list.
type wireField struct {
	Name     string      `json:"name"`
	Values   []string    `json:"values,omitempty"`
	Fields   []wireField `json:"fields,omitempty"`
	Optional bool        `json:"optional,omitempty"`
	Open     bool        `json:"open,omitempty"`
}

func wireTypeName(typ reflect.Type) *string {
	if typ == nil {
		return nil
	}
	name := typ.Name()
	return &name
}

func wireRoutes(t *testing.T, routes []Route) []wireRoute {
	t.Helper()
	out := make([]wireRoute, 0, len(routes))
	for _, rt := range routes {
		path, ok := strings.CutPrefix(rt.Path, goldenOIDCPrefix+"/")
		if ok {
			path = "{oidcPrefix}/" + path
		} else if path, ok = strings.CutPrefix(rt.Path, goldenPrefix+"/"); ok {
			path = "{prefix}/" + path
		} else {
			t.Fatalf("%s: path %s under neither prefix", rt.Name, rt.Path)
		}
		out = append(out, wireRoute{
			Name: rt.Name, Method: rt.Method, Path: path, Kind: rt.Kind,
			Request: wireTypeName(rt.Request), Response: wireTypeName(rt.Response), Array: rt.Array,
		})
	}
	return out
}

func wireFields(t *testing.T, typ reflect.Type) []wireField {
	t.Helper()
	var out []wireField
	for f := range typ.Fields() {
		if !f.IsExported() {
			continue
		}
		if f.Anonymous {
			t.Fatalf("%s embeds %s; types.json lists no promoted keys", typ.Name(), f.Name)
		}
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" && opts == "" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		optional := f.Type.Kind() == reflect.Pointer || slices.Contains(strings.Split(opts, ","), "omitempty") || slices.Contains(strings.Split(opts, ","), "omitzero")
		row := wireField{Name: name, Optional: optional}
		elem := f.Type
		for elem.Kind() == reflect.Pointer || elem.Kind() == reflect.Slice {
			elem = elem.Elem()
		}
		switch {
		case elem.Kind() == reflect.String && elem.Name() != "string":
			row.Values, row.Open = enumValues(t, elem)
		case elem.Kind() == reflect.Struct && elem != reflect.TypeFor[time.Time]():
			row.Fields = wireFields(t, elem)
		}
		out = append(out, row)
	}
	return out
}

// openDoc is the phrase a type's doc comment carries when the type takes
// values outside its constants (types.go's Method, Role, TokenPurpose).
const openDoc = "are app-defined"

// enumValues is the values of typ's constants, read from the non-test files
// of the package that declares it, in declaration order, and whether typ's
// doc comment says values outside them are app-defined; nil for a named
// string type with no constants (any string, such as webauthn.Base64URL).
func enumValues(t *testing.T, typ reflect.Type) (values []string, open bool) {
	t.Helper()
	const module = "github.com/cplieger/access"
	rel, ok := strings.CutPrefix(typ.PkgPath(), module)
	if !ok {
		t.Fatalf("%v is declared outside %s", typ, module)
	}
	names, err := filepath.Glob(filepath.Join("..", filepath.FromSlash(rel), "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		for _, d := range f.Decls {
			if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.CONST {
				values = append(values, typedConsts(t, fset, g, typ.Name())...)
			}
		}
	}
	if len(values) == 0 {
		return nil, false
	}
	pkg, err := doc.NewFromFiles(fset, files, typ.PkgPath(), doc.PreserveAST)
	if err != nil {
		t.Fatal(err)
	}
	for _, dt := range pkg.Types {
		if dt.Name == typ.Name() {
			return values, strings.Contains(strings.Join(strings.Fields(dt.Doc), " "), openDoc)
		}
	}
	t.Fatalf("%v has no type declaration in %s", typ, rel)
	return nil, false
}

// typedConsts is the values of g's constants of type typeName. A spec with
// neither type nor values repeats the previous spec's (the Go spec's
// implicit repetition), so its names are typeName's constants too.
func typedConsts(t *testing.T, fset *token.FileSet, g *ast.GenDecl, typeName string) []string {
	t.Helper()
	var typ ast.Expr
	var exprs []ast.Expr
	var out []string
	for _, s := range g.Specs {
		spec := s.(*ast.ValueSpec)
		if spec.Type != nil || len(spec.Values) > 0 {
			typ, exprs = spec.Type, spec.Values
		}
		if id, ok := typ.(*ast.Ident); !ok || id.Name != typeName {
			continue
		}
		for i, name := range spec.Names {
			if i >= len(exprs) {
				t.Fatalf("%s: %s has no value", fset.Position(name.Pos()), name.Name)
			}
			lit, ok := exprs[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Fatalf("%s: a %s constant that is not a string literal", fset.Position(name.Pos()), typeName)
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
	}
	return out
}

// wireFiles is every file TestGoldenWire owns, by file name.
func wireFiles(t *testing.T, routes []Route) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, f := range fixtures() {
		out[f.name+".json"] = fixtureBytes(t, &f)
	}
	var types []string
	fields := map[string][]wireField{}
	queries := map[string][]string{}
	for _, rt := range routes {
		for _, typ := range []reflect.Type{rt.Request, rt.Response} {
			if typ != nil && !slices.Contains(types, typ.Name()) {
				types = append(types, typ.Name())
				fields[typ.Name()] = wireFields(t, typ)
			}
		}
		if rt.Query != nil {
			var keys []string
			for f := range rt.Query.Fields() {
				key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				keys = append(keys, key)
			}
			slices.Sort(keys)
			queries[rt.Name] = keys
		}
	}
	slices.Sort(types)
	out["index.json"] = indexedJSON(t, types)
	out["queries.json"] = indexedJSON(t, queries)
	out["codes.json"] = indexedJSON(t, access.Codes())
	out["reasons.json"] = indexedJSON(t, Reasons())
	out["routes.json"] = indexedJSON(t, wireRoutes(t, routes))
	out["types.json"] = indexedJSON(t, fields)
	return out
}

func TestGoldenWire(t *testing.T) {
	if _, err := os.Stat("../web/go.mod"); errors.Is(err, fs.ErrNotExist) {
		t.Skip("no web/ beside the module: a module-cache run")
	}
	routes := newEnv(t, envOptions{handler: func(c *Config) { c.Prefix, c.OIDCPrefix = goldenPrefix, goldenOIDCPrefix }}).h.Routes()
	want := wireFiles(t, routes)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		writeWireDir(t, want)
	}
	t.Run("files", func(t *testing.T) {
		entries, err := os.ReadDir(wireDir)
		if err != nil {
			t.Fatalf("read %s: %v; run %s", wireDir, err, regenerateGolden)
		}
		for _, e := range entries {
			if _, ok := want[e.Name()]; !ok {
				t.Errorf("%s/%s is no fixture this test writes; run %s", wireDir, e.Name(), regenerateGolden)
			}
		}
		for _, name := range slices.Sorted(maps.Keys(want)) {
			got, err := os.ReadFile(filepath.Join(wireDir, name))
			if err != nil {
				t.Errorf("%s: %v; run %s", name, err, regenerateGolden)
				continue
			}
			if !bytes.Equal(got, want[name]) {
				t.Errorf("%s differs from what the Go types write; run %s and check web/src/wire.node.test.ts", name, regenerateGolden)
			}
		}
	})
	t.Run("every_descriptor_type_has_a_fixture", func(t *testing.T) {
		for _, rt := range routes {
			for _, typ := range []reflect.Type{rt.Request, rt.Response} {
				if typ != nil && !slices.ContainsFunc(fixtures(), func(f fixture) bool { return f.name == typ.Name() && reflect.TypeOf(f.value) == typ }) {
					t.Errorf("%s: no fixture of %v", rt.Name, typ)
				}
			}
		}
	})
	t.Run("routes_json_lists_every_route", func(t *testing.T) {
		var rows []wireRoute
		readWire(t, "routes.json", &rows)
		if len(rows) != len(routes) {
			t.Errorf("routes.json has %d rows, Routes() %d", len(rows), len(routes))
		}
		for i, rt := range routes {
			if i >= len(rows) {
				break
			}
			row := rows[i]
			path := strings.NewReplacer("{oidcPrefix}", goldenOIDCPrefix, "{prefix}", goldenPrefix).Replace(row.Path)
			if row.Name != rt.Name || row.Method != rt.Method || path != rt.Path || row.Kind != rt.Kind || row.Array != rt.Array ||
				!sameTypeName(row.Request, rt.Request) || !sameTypeName(row.Response, rt.Response) {
				t.Errorf("routes.json row %d = %+v, want route %s %s %s", i, row, rt.Name, rt.Method, rt.Path)
			}
		}
	})
	t.Run("types_json_lists_every_key", func(t *testing.T) {
		var types map[string][]wireField
		readWire(t, "types.json", &types)
		for _, f := range fixtures() {
			if f.absent != "" {
				continue
			}
			typ := reflect.TypeOf(f.value)
			rows, ok := types[typ.Name()]
			if !ok {
				t.Errorf("types.json lacks %s", typ.Name())
				continue
			}
			full := jsonKeys(t, fixtureBytes(t, &f))
			zero := jsonKeys(t, fixtureBytes(t, &fixture{value: reflect.Zero(typ).Interface(), request: f.request}))
			listed := map[string]bool{}
			for _, row := range rows {
				listed[row.Name] = true
				raw, sent := zero[row.Name]
				if row.Optional != (!sent || string(raw) == "null" && typ.Field(fieldIndex(t, typ, row.Name)).Type.Kind() == reflect.Pointer) {
					t.Errorf("%s.%s optional %t, but its zero value encodes as %q", typ.Name(), row.Name, row.Optional, raw)
				}
			}
			for key := range full {
				if !listed[key] {
					t.Errorf("types.json lacks %s.%s", typ.Name(), key)
				}
			}
			if len(rows) != len(full) {
				t.Errorf("types.json lists %d keys of %s, its fixture sends %d", len(rows), typ.Name(), len(full))
			}
		}
	})
	for _, f := range fixtures() {
		t.Run(f.name, func(t *testing.T) { checkFixture(t, &f) })
	}
}

func readWire(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(wireDir, name))
	if err != nil {
		t.Fatalf("%v; run %s", err, regenerateGolden)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func sameTypeName(name *string, typ reflect.Type) bool {
	if typ == nil || name == nil {
		return typ == nil && name == nil
	}
	return *name == typ.Name()
}

func jsonKeys(t *testing.T, b []byte) map[string]json.RawMessage {
	t.Helper()
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return keys
}

// fieldIndex is the index of typ's field whose JSON key is key.
func fieldIndex(t *testing.T, typ reflect.Type, key string) int {
	t.Helper()
	for i := range typ.NumField() {
		if name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ","); name == key {
			return i
		}
	}
	t.Fatalf("%s has no field %s", typ.Name(), key)
	return -1
}

func writeWireDir(t *testing.T, files map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(wireDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	entries, err := os.ReadDir(wireDir)
	if err != nil {
		t.Fatalf("read %s: %v", wireDir, err)
	}
	for _, e := range entries {
		if _, ok := files[e.Name()]; !ok {
			if err := os.Remove(filepath.Join(wireDir, e.Name())); err != nil {
				t.Fatalf("remove stale %s: %v", e.Name(), err)
			}
		}
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(wireDir, name), b, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

// checkFixture decodes f's wire bytes strictly back into its type: a
// request equals the value that wrote it, a show-once response carries its
// plaintext, a variant lacks its absent key, and every main fixture sets
// every field, so no omitempty key is missing from the file.
func checkFixture(t *testing.T, f *fixture) {
	t.Helper()
	b := fixtureBytes(t, f)
	typ := reflect.TypeOf(f.value)
	got := reflect.New(typ)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(got.Interface()); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	if f.request && !reflect.DeepEqual(got.Elem().Interface(), f.value) {
		t.Errorf("decodes to %+v, want %+v", got.Elem().Interface(), f.value)
	}
	switch v := got.Elem().Interface().(type) {
	case KeyCreatedResponse:
		if v.Key != f.shown.Reveal() {
			t.Errorf("key %q, want the plaintext", v.Key)
		}
	case TokenResponse:
		if v.Token != f.shown.Reveal() {
			t.Errorf("token %q, want the plaintext", v.Token)
		}
	}
	if f.absent != "" {
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(b, &keys); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, ok := keys[f.absent]; ok {
			t.Errorf("%s present in %s", f.absent, b)
		}
		return
	}
	for _, path := range zeroFields(got.Elem(), typ.Name()) {
		t.Errorf("%s is zero in the fixture", path)
	}
}

// zeroFields names every exported field under v left at its zero value.
func zeroFields(v reflect.Value, path string) []string {
	if v.Type() == reflect.TypeFor[time.Time]() || v.Type() == reflect.TypeFor[json.RawMessage]() {
		if v.IsZero() {
			return []string{path}
		}
		return nil
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return []string{path}
		}
		return zeroFields(v.Elem(), path)
	case reflect.Slice:
		if v.Len() == 0 {
			return []string{path}
		}
		var out []string
		for i := range v.Len() {
			out = append(out, zeroFields(v.Index(i), path+"[]")...)
		}
		return out
	case reflect.Struct:
		var out []string
		for i := range v.NumField() {
			if f := v.Type().Field(i); f.IsExported() {
				out = append(out, zeroFields(v.Field(i), path+"."+f.Name)...)
			}
		}
		return out
	default:
		if v.IsZero() {
			return []string{path}
		}
		return nil
	}
}

// Method, Role and TokenPurpose take app-defined values (types.go), so
// types.json must mark them open or the TypeScript client refuses a server's
// real answer.
func TestGoldenWireOpenEnums(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[access.Method](), reflect.TypeFor[access.Role](), reflect.TypeFor[access.TokenPurpose]()} {
		t.Run(typ.Name(), func(t *testing.T) {
			values, open := enumValues(t, typ)
			if len(values) == 0 || !open {
				t.Errorf("enumValues(%v) = %q, open %t; want its constants, open (its doc comment must say values outside them %s)", typ, values, open, openDoc)
			}
		})
	}
}

func TestTypedConstsImplicitRepetition(t *testing.T) {
	const src = `package p
const (
	A M = "a"
	B
	C, D M = "c", "d"
	E, F
	G = "untyped"
	H
)`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	got := typedConsts(t, fset, f.Decls[0].(*ast.GenDecl), "M")
	if want := []string{"a", "a", "c", "d", "c", "d"}; !slices.Equal(got, want) {
		t.Errorf("typedConsts = %q, want %q", got, want)
	}
}
