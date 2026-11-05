package accesshttp

import (
	"encoding/json"
	"log/slog"
	"net/http"
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

// jsonFuzz serves bodies on every route decodeJSON reads, as a principal
// each route's guard admits, over an account whose every operation is
// stubbed, so no body changes what the next one finds.
type jsonFuzz struct {
	e                 *env
	session, recovery *http.Cookie
	minted            time.Time
	routes            []Route
	fixtures          map[string]string // route name: its request fixture
	reached           atomic.Int64      // account operations called
}

func newJSONFuzz(tb testing.TB) *jsonFuzz {
	tb.Helper()
	z := &jsonFuzz{fixtures: map[string]string{}}
	z.e = newEnv(tb, envOptions{
		wrap: func(_ *env, s *account.Service) accountAPI {
			return stubAccount{accountAPI: s, answer: func(string) (bool, error) {
				z.reached.Add(1)
				return true, errStubbed
			}}
		},
		handler: func(c *Config) {
			c.Errors = func(w http.ResponseWriter, _ *http.Request, er Error) {
				w.Header().Set(fuzzCodeHeader, string(er.Code))
				w.WriteHeader(er.Status)
			}
			c.Audit = nil
			c.Logger = slog.New(slog.DiscardHandler)
		},
	})
	z.e.createUser(tb, "root", access.RoleAdmin)
	z.e.createUser(tb, "alice", access.RoleUser)
	for _, rt := range z.e.h.Routes() {
		if rt.Request != nil {
			z.routes = append(z.routes, rt)
			z.fixtures[rt.Name] = censusBody(tb, rt)
		}
	}
	z.mint(tb)
	return z
}

// mint signs root in and opens a recovery session for alice. A run longer
// than account's recent-auth window or RecoverySessionLifetime would
// otherwise have the guard refuse every body after it, so serve re-mints
// once a minute.
func (z *jsonFuzz) mint(tb testing.TB) {
	tb.Helper()
	z.session = z.e.storedSession(tb, "root", 0, 0)
	z.recovery = z.e.recoveryCookie(tb, "alice")
	z.minted = time.Now()
}

// serve sends body on rt and returns the status, the code the ErrorWriter
// answered ("" for none) and whether an account operation ran.
func (z *jsonFuzz) serve(t *testing.T, rt Route, body []byte) (status int, code Code, reached bool) {
	t.Helper()
	if time.Since(z.minted) > time.Minute {
		z.mint(t)
	}
	cookie := z.session
	if rt.Class == ClassRecovery {
		cookie = z.recovery
	}
	before := z.reached.Load()
	w := do(rt, requestFor(rt, censusPathValue(t, rt), string(body), cookie))
	return w.Code, Code(w.Header().Get(fuzzCodeHeader)), z.reached.Load() != before
}

// wantRefused fails t unless rt refuses body before its operation: 413
// auth_body_too_large past 4 KiB, 400 auth_bad_request otherwise.
func (z *jsonFuzz) wantRefused(t *testing.T, arm string, rt Route, body []byte) {
	t.Helper()
	want, wantCode := http.StatusBadRequest, CodeBadRequest
	if len(body) > specBodyCap {
		want, wantCode = http.StatusRequestEntityTooLarge, CodeBodyTooLarge
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

// FuzzAuthhttpJSON is §9.3's property over every route decodeJSON reads:
// any body either reaches the route's operation or is refused with 400
// auth_bad_request, a body past 4 KiB is refused with 413
// auth_body_too_large, and the route's own fixture with an unknown member
// or trailing data is refused with 400, each before the operation runs and
// never with a 5xx.
func FuzzAuthhttpJSON(f *testing.F) {
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

		padded := body
		if len(body) <= specBodyCap {
			if status, code, reached := z.serve(t, rt, body); !reached && (status != http.StatusBadRequest || code != CodeBadRequest) {
				t.Fatalf("on %s: %d %q with no operation called, want 400 %s; body %q", rt.Name, status, code, CodeBadRequest, body)
			}
			padded = append(slices.Clone(body), strings.Repeat(" ", specBodyCap+1-len(body))...)
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
