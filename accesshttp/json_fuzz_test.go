package accesshttp

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// fuzzCodeHeader carries the refusal code the fuzz ErrorWriter answers, so
// a run keeps nothing per request.
const fuzzCodeHeader = "X-Test-Code"

// specBodyCap is §7.4's JSON body cap, the oracle maxBodyBytes must meet.
const specBodyCap = 4 << 10

// proofBodyCap is a SecondFactorProof body's cap: it may carry a WebAuthn
// assertion, whose cap is webauthn.MaxResponseBytes.
const proofBodyCap = 64 << 10

// jsonFuzz serves bodies on every route decodeJSON reads, as a principal
// each route's guard admits, over an account whose every operation is
// stubbed, so no body changes what the next one finds.
type jsonFuzz struct {
	e        *env
	session  *http.Cookie
	minted   time.Time
	routes   []Route
	fixtures map[string]string // route name: its request fixture
	caps     map[string]int    // route name: its body cap
	reached  atomic.Int64      // account operations called
}

func newJSONFuzz(tb testing.TB) *jsonFuzz {
	tb.Helper()
	z := &jsonFuzz{fixtures: map[string]string{}, caps: map[string]int{}}
	z.e = newEnv(tb, envOptions{
		wrap: func(_ *env, s *account.Service) accountAPI {
			return stubAccount{accountAPI: s, answer: func(string) (bool, error) {
				z.reached.Add(1)
				return true, errStubbed
			}}
		},
		handler: func(c *Config) {
			c.Errors = func(w http.ResponseWriter, _ *http.Request, er access.Error) {
				w.Header().Set(fuzzCodeHeader, string(er.Code))
				w.WriteHeader(er.Status)
			}
			c.Audit = nil
			c.Logger = slog.New(slog.DiscardHandler)
		},
	})
	z.e.createUser(tb, "root", access.RoleAdmin)
	for _, rt := range z.e.h.Routes() {
		if rt.Request != nil {
			z.routes = append(z.routes, rt)
			z.fixtures[rt.Name] = censusBody(tb, rt)
			z.caps[rt.Name] = specBodyCap
			if rt.Request == reflect.TypeFor[SecondFactorProof]() {
				z.caps[rt.Name] = proofBodyCap
			}
		}
	}
	z.mint(tb)
	return z
}

// mint signs root in. A run longer than account's recent-auth window would
// otherwise have the guard refuse every body after it, so serve re-mints
// once a minute.
func (z *jsonFuzz) mint(tb testing.TB) {
	tb.Helper()
	z.session = z.e.storedSession(tb, "root", 0, 0)
	z.minted = time.Now()
}

// serve sends body on rt and returns the status, the code the ErrorWriter
// answered ("" for none) and whether an account operation ran.
func (z *jsonFuzz) serve(t *testing.T, rt Route, body []byte) (status int, code access.Code, reached bool) {
	t.Helper()
	if time.Since(z.minted) > time.Minute {
		z.mint(t)
	}
	before := z.reached.Load()
	w := do(rt, requestFor(rt, censusPathValue(t, rt), string(body), z.session))
	return w.Code, access.Code(w.Header().Get(fuzzCodeHeader)), z.reached.Load() != before
}

// wantRefused fails t unless rt refuses body before its operation: 413
// auth_body_too_large past its cap, 400 auth_bad_request otherwise.
func (z *jsonFuzz) wantRefused(t *testing.T, arm string, rt Route, body []byte) {
	t.Helper()
	want, wantCode := http.StatusBadRequest, access.CodeBadRequest
	if len(body) > z.caps[rt.Name] {
		want, wantCode = http.StatusRequestEntityTooLarge, access.CodeBodyTooLarge
	}
	if status, code, reached := z.serve(t, rt, body); status != want || code != wantCode || reached {
		t.Fatalf("%s on %s: %d %q, operation called %v; want %d %s before the operation; body %q", arm, rt.Name, status, code, reached, want, wantCode, body)
	}
}

// jsonNames are rt's request members' exact JSON names.
func jsonNames(rt Route) []string {
	var names []string
	for f := range rt.Request.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		names = append(names, name)
	}
	return names
}

// withMember is the JSON object obj with the member name: value first.
func withMember(obj, name string, value []byte) []byte {
	member, _ := json.Marshal(name)
	out := append([]byte{'{'}, member...)
	out = append(out, ':')
	out = append(out, value...)
	if rest := obj[1:]; rest != "}" {
		out = append(out, ',')
	}
	return append(out, obj[1:]...)
}

// FuzzAccesshttpJSON is §9.3's property over every route decodeJSON reads:
// any body either reaches the route's operation or is refused with 400
// auth_bad_request, a body past its cap (4 KiB, or a proof's 64 KiB) is
// refused with 413
// auth_body_too_large, and the route's own fixture with an unknown member
// or trailing data is refused with 400, each before the operation runs and
// never with a 5xx.
func FuzzAccesshttpJSON(f *testing.F) {
	z := newJSONFuzz(f)
	for i, rt := range z.routes {
		f.Add(uint8(i), "Password", []byte(z.fixtures[rt.Name]))
	}
	for _, body := range []string{
		``, `{}`, `{} {}`, `[]`, `null`, `"x"`, `{"password":1}`, `{"username":"a","username":"b"}`,
		"{\"\xff\":1}", `{"a":` + strings.Repeat(`[`, 2000), `{`, `{"password":"x",}`, strings.Repeat(" ", specBodyCap+1), `{"id":1e999}`,
	} {
		f.Add(uint8(0), "unknown", []byte(body))
	}
	f.Fuzz(func(t *testing.T, route uint8, key string, body []byte) {
		rt := z.routes[int(route)%len(z.routes)]
		fixture := z.fixtures[rt.Name]

		padded, limit := body, z.caps[rt.Name]
		if len(body) <= limit {
			if status, code, reached := z.serve(t, rt, body); !reached && (status != http.StatusBadRequest || code != access.CodeBadRequest) {
				t.Fatalf("on %s: %d %q with no operation called, want 400 %s; body %q", rt.Name, status, code, access.CodeBadRequest, body)
			}
			padded = append(slices.Clone(body), strings.Repeat(" ", limit+1-len(body))...)
		}
		z.wantRefused(t, "oversized", rt, padded)

		var seen string
		if raw, _ := json.Marshal(key); json.Unmarshal(raw, &seen) == nil && !slices.Contains(jsonNames(rt), seen) {
			value := []byte("null")
			if json.Valid(body) {
				value = body
			}
			z.wantRefused(t, "unknown member", rt, withMember(fixture, key, value))
		}

		if strings.Trim(string(body), " \t\r\n") != "" {
			z.wantRefused(t, "trailing data", rt, append([]byte(fixture), body...))
		}
	})
}
