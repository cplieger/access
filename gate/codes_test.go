package gate_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/gate"
)

// authenticating is what every authenticating row answers, from design 2.2
// "The codes are fixed", in access.Codes() order.
var authenticating = []access.Code{
	access.CodeAuthRequired, access.CodeSessionExpired, access.CodeInvalidCredentials, access.CodeKeyInvalid,
	access.CodeSessionRequired,
}

func codesWith(extra ...access.Code) []access.Code {
	set := append(slices.Clone(authenticating), access.CodeUnavailable, access.CodeMethodNotAllowed)
	set = append(set, extra...)
	var out []access.Code
	for _, c := range access.Codes() {
		if slices.Contains(set, c) {
			out = append(out, c)
		}
	}
	return out
}

// TestCodes pins each row's Codes to the design's list, then drives every
// row through every request a client can send and checks that the answers
// are exactly its Codes, each with Cache-Control: no-store.
func TestCodes(t *testing.T) {
	t.Parallel()
	want := map[string][]access.Code{
		"pub":         {access.CodeMethodNotAllowed},
		"sess":        codesWith(),
		"sess_post":   codesWith(access.CodeCrossOrigin),
		"key":         codesWith(access.CodeKeyRequired),
		"key_scoped":  codesWith(access.CodeKeyRequired, access.CodeScopeRequired),
		"scoped":      codesWith(access.CodeScopeRequired, access.CodeForbidden),
		"scoped_post": codesWith(access.CodeScopeRequired, access.CodeForbidden, access.CodeCrossOrigin),
		"passive":     codesWith(),
		"active":      codesWith(),
	}
	for _, r := range classRoutes {
		if got := gate.Codes(r); !slices.Equal(got, want[r.Name]) {
			t.Errorf("Codes(%s) = %v, want %v", r.Name, got, want[r.Name])
		}
	}
	if got := gate.MountCodes(); !slices.Equal(got, []access.Code{access.CodeNotFound}) {
		t.Errorf("MountCodes() = %v, want [auth_not_found]", got)
	}

	f := newFixture(t)
	g := mustGate(t, gate.Config{Authenticator: f.authn}, classRoutes, &served{})
	bg := mustGate(t, gate.Config{Authenticator: f.bypass}, classRoutes, &served{})
	type scenario struct {
		g      *gate.Gate
		method string // "" is the row's own
		creds  []cred
	}
	scenarios := []scenario{
		{g: g, method: http.MethodDelete},
		{g: g, creds: []cred{noCred}},
		{g: g, creds: []cred{expiredCred}},
		{g: g, creds: []cred{goneCred}},
		{g: g, creds: []cred{withAgent("bad")}},
		{g: g, creds: []cred{unknownKey}},
		{g: g, creds: []cred{recoveryCred}},
		{g: g, creds: []cred{withAgent("boom")}},
		{g: g, creds: []cred{sessionCred}},
		{g: g, creds: []cred{keyReadCred}},
		{g: g, creds: []cred{keyNoneCred}},
		{g: g, creds: []cred{agentCred}},
		{g: bg},
		{g: g, creds: []cred{sessionCred, crossSite}},
	}
	for _, r := range classRoutes {
		t.Run(r.Name, func(t *testing.T) {
			t.Parallel()
			codes := gate.Codes(r)
			reached := map[access.Code]bool{}
			for _, sc := range scenarios {
				method := sc.method
				if method == "" {
					method = r.Method
				}
				a := do(t, f, sc.g, method, r.Path, sc.creds...)
				if a.status == http.StatusOK {
					continue
				}
				reached[a.code] = true
				if !slices.Contains(codes, a.code) {
					t.Errorf("%s %s answered %d %q, not in Codes %v", method, r.Path, a.status, a.code, codes)
				}
				if got := a.header.Get("Cache-Control"); got != "no-store" {
					t.Errorf("%s %s %q: Cache-Control = %q, want no-store", method, r.Path, a.code, got)
				}
				if a.status == http.StatusUnauthorized && a.header.Get("WWW-Authenticate") == "" {
					t.Errorf("%s %s %q: a 401 with no challenge", method, r.Path, a.code)
				}
			}
			for _, c := range codes {
				if !reached[c] {
					t.Errorf("Codes(%s) lists %s, which no request reached", r.Name, c)
				}
			}
		})
	}
	t.Run("key_challenges", func(t *testing.T) {
		t.Parallel()
		// RFC 6750 §3: a request with no Bearer token gets the bare
		// challenge; §3.1: a token lacking the scope gets
		// insufficient_scope naming it.
		if a := do(t, f, g, http.MethodGet, "/key", sessionCred); a.header.Get("WWW-Authenticate") != `Bearer realm="access"` {
			t.Errorf("auth_key_required challenge = %q", a.header.Get("WWW-Authenticate"))
		}
		if a := do(t, f, g, http.MethodGet, "/key/read", keyNoneCred); a.header.Get("WWW-Authenticate") != `Bearer realm="access", error="insufficient_scope", scope="read"` {
			t.Errorf("auth_scope_required challenge = %q", a.header.Get("WWW-Authenticate"))
		}
		if a := do(t, f, g, http.MethodGet, "/scoped", agentCred); a.header.Get("WWW-Authenticate") != "" {
			t.Errorf("auth_forbidden challenge = %q, want none", a.header.Get("WWW-Authenticate"))
		}
	})
}
