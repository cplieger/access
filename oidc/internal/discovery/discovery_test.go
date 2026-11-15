package discovery_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access/oidc/internal/discovery"
	"github.com/cplieger/access/oidc/internal/jwk"
)

// refusedDocument fails unless err is a document refusal, not a fetch
// failure.
func refusedDocument(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, discovery.ErrDocument) || errors.Is(err, discovery.ErrFetch) {
		t.Errorf("%s: err = %v, want ErrDocument alone", what, err)
	}
}

// refusedFetch fails unless err is a fetch failure, not a document refusal.
func refusedFetch(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, discovery.ErrFetch) || errors.Is(err, discovery.ErrDocument) {
		t.Errorf("%s: err = %v, want ErrFetch alone", what, err)
	}
}

// OpenID Connect Discovery 1.0 §4.1: the document is at the issuer, less
// a terminating "/", followed by /.well-known/openid-configuration.
func TestFetch_WellKnownURL(t *testing.T) {
	t.Parallel()
	for issuer, want := range map[string]string{
		"https://idp.example":              "https://idp.example/.well-known/openid-configuration",
		"https://idp.example/":             "https://idp.example/.well-known/openid-configuration",
		"https://idp.example/realms/main":  "https://idp.example/realms/main/.well-known/openid-configuration",
		"https://idp.example/realms/main/": "https://idp.example/realms/main/.well-known/openid-configuration",
		"https://tenant.auth0.com/":        "https://tenant.auth0.com/.well-known/openid-configuration",
		"https://idp.example:8443/x":       "https://idp.example:8443/x/.well-known/openid-configuration",
		"https://idp.example//":            "https://idp.example//.well-known/openid-configuration",
	} {
		t.Run(issuer, func(t *testing.T) {
			t.Parallel()
			body := docFor(t, issuer, nil)
			idp := &fakeIdP{serve: func(*http.Request) *http.Response { return answer(http.StatusOK, bytes.NewReader(body)) }}
			var asked atomic.Int32
			doc, err := discovery.Fetch(t.Context(), idp.client(&asked), issuer)
			if err != nil {
				t.Fatalf("Fetch = %v, want nil", err)
			}
			if got := idp.requested(); !slices.Equal(got, []string{want}) {
				t.Errorf("requested %q, want [%q]", got, want)
			}
			base := strings.TrimSuffix(issuer, "/")
			wantDoc := discovery.Document{
				AuthorizationEndpoint: base + "/authorize",
				TokenEndpoint:         base + "/token",
				JWKSURI:               base + "/jwks",
				Algs:                  []jwk.Alg{jwk.RS256},
			}
			if !reflect.DeepEqual(doc, wantDoc) {
				t.Errorf("Fetch = %+v, want %+v", doc, wantDoc)
			}
		})
	}
}

// OpenID Connect Discovery 1.0 §4.3: the document's issuer is identical
// to the issuer it was fetched for; no normalisation makes two equal.
func TestParse_Issuer(t *testing.T) {
	t.Parallel()
	const issuer = "https://idp.example/x"
	if _, err := discovery.Parse(issuer, docFor(t, issuer, nil)); err != nil {
		t.Fatalf("the identical issuer: Parse = %v, want nil", err)
	}
	for name, got := range map[string]any{
		"trailing slash": issuer + "/",
		"host case":      "https://IDP.example/x",
		"path case":      "https://idp.example/X",
		"scheme":         "http://idp.example/x",
		"default port":   "https://idp.example:443/x",
		"prefix":         "https://idp.example",
		"longer":         issuer + "/y",
		"empty query":    issuer + "?",
		"empty":          "",
		"number":         5,
		"null":           nil,
		"array":          []string{issuer},
	} {
		_, err := discovery.Parse(issuer, docFor(t, issuer, map[string]any{"issuer": got}))
		refusedDocument(t, name, err)
	}
	_, err := discovery.Parse(issuer, docFor(t, issuer, nil, "issuer"))
	refusedDocument(t, "absent", err)
	for configured, served := range map[string]string{
		"https://idp.example/": "https://idp.example",
		"https://idp.example":  "https://idp.example/",
	} {
		_, err := discovery.Parse(configured, docFor(t, configured, map[string]any{"issuer": served}))
		refusedDocument(t, fmt.Sprintf("issuer %q fetched for %q", served, configured), err)
	}
}

var endpointFields = []string{"authorization_endpoint", "token_endpoint", "jwks_uri"}

// OpenID Connect Discovery 1.0 §3: authorization_endpoint, token_endpoint
// and jwks_uri are https URLs; http is allowed only on a loopback host while
// the issuer is itself loopback http. A refusal names the field and never
// the URL, whose query may carry a secret.
func TestParse_Endpoints(t *testing.T) {
	t.Parallel()
	const secret = "query-secret"
	for _, field := range endpointFields {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			endpoints(t, field, secret)
		})
	}
}

func endpoints(t *testing.T, field, secret string) {
	refused := func(issuer string, v any) {
		t.Helper()
		_, err := discovery.Parse(issuer, docFor(t, issuer, map[string]any{field: v}))
		what := fmt.Sprintf("%s %v under %s", field, v, issuer)
		refusedDocument(t, what, err)
		if msg := fmt.Sprint(err); !strings.Contains(msg, field) || strings.Contains(msg, secret) {
			t.Errorf("%s: err = %q, want it to name the field and not the URL", what, msg)
		}
	}
	accepted := func(issuer, v string) {
		t.Helper()
		doc, err := discovery.Parse(issuer, docFor(t, issuer, map[string]any{field: v}))
		if err != nil {
			t.Errorf("%s %s under %s: Parse = %v, want nil", field, v, issuer, err)
			return
		}
		if got := map[string]string{
			"authorization_endpoint": doc.AuthorizationEndpoint,
			"token_endpoint":         doc.TokenEndpoint,
			"jwks_uri":               doc.JWKSURI,
		}[field]; got != v {
			t.Errorf("%s = %q, want %q", field, got, v)
		}
	}
	const https, loopback = "https://idp.example", "http://127.0.0.1:8080"
	q := "?q=" + secret
	for _, v := range []string{
		"http://idp.example/x" + q,
		"http://127.0.0.1:1/x" + q,
		"http://localhost/x" + q,
		"/x" + q,
		"https:///x" + q,
		"https:idp.example/x" + q,
		"https://u:p@idp.example/x" + q,
		"https://u@idp.example/x" + q,
		"ftp://idp.example/x" + q,
		" https://idp.example/x" + q,
		"",
	} {
		refused(https, v)
	}
	for _, v := range []any{5, nil, true, []string{https + "/x"}, map[string]string{}} {
		refused(https, v)
	}
	_, err := discovery.Parse(https, docFor(t, https, nil, field))
	refusedDocument(t, field+" absent", err)
	accepted(https, "https://idp.example/x?y=1")
	accepted(https, "https://other.example:8443/p")

	for _, v := range []string{
		"http://idp.example/x" + q,
		"http://127.0.0.1.example/x" + q,
		"http://localhost.example/x" + q,
		// Authlib CVE-2026-114614: userinfo must not reach the loopback rule.
		"http://user@127.0.0.1/x" + q,
		"http://u:p@localhost/x" + q,
	} {
		refused(loopback, v)
	}
	for _, v := range []string{"http://127.0.0.1:9/x", "http://[::1]:9/x", "http://localhost/x", "http://LocalHost/x", "https://idp.example/x"} {
		accepted(loopback, v)
	}
	refused("https://localhost", "http://localhost/x"+q)
}

// OpenID Connect Discovery 1.0 §3 and Core 1.0 §3.1.3.7 step 7: the
// provider's algorithms are id_token_signing_alg_values_supported, RS256
// when absent, intersected with the accepted rows (RFC 7518 §3.1; RFC 9864
// §2.2 names one row EdDSA and Ed25519). An empty intersection, or a list
// that is not an array of strings, refuses the document.
func TestParse_Algorithms(t *testing.T) {
	t.Parallel()
	const issuer = "https://idp.example"
	const field = "id_token_signing_alg_values_supported"
	doc, err := discovery.Parse(issuer, docFor(t, issuer, nil, field))
	if err != nil || !slices.Equal(doc.Algs, []jwk.Alg{jwk.RS256}) {
		t.Errorf("absent: Parse = %v, %v; want [RS256]", doc.Algs, err)
	}
	all := []jwk.Alg{jwk.RS256, jwk.RS384, jwk.RS512, jwk.PS256, jwk.PS384, jwk.PS512, jwk.ES256, jwk.ES384, jwk.ES512, jwk.EdDSA}
	for _, tc := range []struct {
		list []string
		want []jwk.Alg
	}{
		{[]string{"RS256"}, []jwk.Alg{jwk.RS256}},
		{[]string{"RS256", "HS256"}, []jwk.Alg{jwk.RS256}},
		{[]string{"EdDSA"}, []jwk.Alg{jwk.EdDSA}},
		{[]string{"Ed25519"}, []jwk.Alg{jwk.EdDSA}},
		{[]string{"Ed25519", "EdDSA", "RS256", "RS256"}, []jwk.Alg{jwk.RS256, jwk.EdDSA}},
		{[]string{"ES512", "none", "PS256", "Ed448", "ES256K"}, []jwk.Alg{jwk.PS256, jwk.ES512}},
		{[]string{"EdDSA", "ES512", "ES384", "ES256", "PS512", "PS384", "PS256", "RS512", "RS384", "RS256", "Ed25519"}, all},
	} {
		doc, err := discovery.Parse(issuer, docFor(t, issuer, map[string]any{field: tc.list}))
		got := slices.Clone(doc.Algs)
		slices.Sort(got)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%q: Parse = %v, %v; want the set %v", tc.list, doc.Algs, err, tc.want)
		}
	}
	for name, v := range map[string]any{
		"HS256 and none":    []string{"HS256", "none"},
		"case":              []string{"rs256"},
		"empty":             []string{},
		"null":              nil,
		"string":            "RS256",
		"object":            map[string]string{"alg": "RS256"},
		"number entry":      []any{"RS256", 5},
		"null entry":        []any{"RS256", nil},
		"nested array":      []any{"RS256", []string{"RS384"}},
		"only unknown rows": []string{"HS512", "Ed448"},
	} {
		_, err := discovery.Parse(issuer, docFor(t, issuer, map[string]any{field: v}))
		refusedDocument(t, name, err)
	}
}

// RFC 8259 §4 and §8.1: the whole document is decoded strictly, so a
// duplicate name, invalid UTF-8 or deep nesting refuses it whether Parse
// reads the member or not, and a member is found by its exact name.
func TestParse_JSON(t *testing.T) {
	t.Parallel()
	const issuer = "https://idp.example"
	doc := docFor(t, issuer, nil)
	with := func(member string) []byte {
		return slices.Concat(doc[:len(doc)-1], []byte(","+member+"}"))
	}
	deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	if _, err := discovery.Parse(issuer, with(`"x":{"a":[1,"b",null,{"c":true}]}`)); err != nil {
		t.Fatalf("an unread nested member: Parse = %v, want nil", err)
	}
	for name, data := range map[string][]byte{
		"duplicate issuer":     with(`"issuer":"https://idp.example"`),
		"duplicate jwks_uri":   with(`"jwks_uri":"https://idp.example/other"`),
		"duplicate unread":     with(`"x":1,"x":1`),
		"invalid UTF-8 unread": with("\"x\":\"\xff\""),
		"20,000-deep unread":   with(`"x":` + deep),
		"ISSUER is not issuer": bytes.Replace(doc, []byte(`"issuer"`), []byte(`"ISSUER"`), 1),
	} {
		_, err := discovery.Parse(issuer, data)
		refusedDocument(t, name, err)
	}
}

// OpenID Connect Discovery 1.0 §4.2 and RFC 9110 §15.4: the document is a
// 200 answer at the well-known URL, so a redirect is a failed fetch, its
// target is never requested and the caller's CheckRedirect is never asked,
// whatever it would allow (PyJWT CVE-2026-102267, CVE-2026-48522).
func TestFetch_Redirects(t *testing.T) {
	t.Parallel()
	const issuer = "https://idp.example"
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, target := range []string{"/moved", "http://idp.example" + wellKnown, "https://evil.example" + wellKnown} {
			body := docFor(t, issuer, nil)
			idp := &fakeIdP{serve: func(r *http.Request) *http.Response {
				if r.URL.String() == issuer+wellKnown {
					resp := answer(status, strings.NewReader(""))
					resp.Header.Set("Location", target)
					return resp
				}
				return answer(http.StatusOK, bytes.NewReader(body))
			}}
			var asked atomic.Int32
			_, err := discovery.Fetch(t.Context(), idp.client(&asked), issuer)
			what := fmt.Sprintf("%d to %s", status, target)
			refusedFetch(t, what, err)
			if got := idp.requested(); len(got) != 1 || asked.Load() != 0 {
				t.Errorf("%s: requested %q and asked CheckRedirect %d times, want the well-known URL alone and 0", what, got, asked.Load())
			}
		}
	}
}

// OpenID Connect Discovery 1.0 §4.2: a successful answer is 200 OK, so any
// other is a failed fetch whose body is never read.
func TestFetch_Status(t *testing.T) {
	t.Parallel()
	const issuer = "https://idp.example"
	fetch := func(status int) (*countingBody, error) {
		body := &countingBody{r: bytes.NewReader(docFor(t, issuer, nil))}
		idp := &fakeIdP{serve: func(*http.Request) *http.Response { return answer(status, body) }}
		var asked atomic.Int32
		_, err := discovery.Fetch(t.Context(), idp.client(&asked), issuer)
		return body, err
	}
	body, err := fetch(http.StatusOK)
	if err != nil || body.reads.Load() == 0 || !body.closed.Load() {
		t.Fatalf("200: Fetch = %v after %d reads, closed %v; want nil, read and closed", err, body.reads.Load(), body.closed.Load())
	}
	for _, status := range []int{http.StatusCreated, http.StatusNonAuthoritativeInfo, http.StatusNoContent, http.StatusPartialContent, http.StatusNotModified, http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		body, err := fetch(status)
		refusedFetch(t, fmt.Sprint(status), err)
		if body.reads.Load() != 0 || !body.closed.Load() {
			t.Errorf("%d: the body was read %d times, closed %v; want unread and closed", status, body.reads.Load(), body.closed.Load())
		}
	}
}

var errBodyCap = errors.New("body past the cap")

// failingBody yields data, then err.
type failingBody struct {
	err  error
	data []byte
}

func (b *failingBody) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, b.err
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

// The fetch goes through the given client's transport, so its body cap,
// guard and dialer apply, and a body read error is a failed fetch.
func TestFetch_BodyError(t *testing.T) {
	t.Parallel()
	const issuer = "https://idp.example"
	doc := docFor(t, issuer, nil)
	idp := &fakeIdP{serve: func(*http.Request) *http.Response {
		return answer(http.StatusOK, &failingBody{data: doc[:len(doc)/2], err: errBodyCap})
	}}
	var asked atomic.Int32
	_, err := discovery.Fetch(t.Context(), idp.client(&asked), issuer)
	refusedFetch(t, "a body that fails", err)
	if !errors.Is(err, errBodyCap) {
		t.Errorf("err = %v, want it to wrap the body's error", err)
	}
}

// Fetch copies the client: the caller's is never changed, and the copy
// keeps its Timeout.
func TestFetch_ClientCopy(t *testing.T) {
	t.Parallel()
	const issuer = "https://idp.example"
	idp := &fakeIdP{serve: func(r *http.Request) *http.Response {
		<-r.Context().Done()
		return answer(http.StatusGatewayTimeout, strings.NewReader(""))
	}}
	var asked atomic.Int32
	c := idp.client(&asked)
	c.Timeout = 50 * time.Millisecond
	check := c.CheckRedirect
	start := time.Now()
	_, err := discovery.Fetch(t.Context(), c, issuer)
	refusedFetch(t, "a hung answer", err)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Fetch returned after %v, want the client's 50 ms timeout to end it", elapsed)
	}
	if c.Transport != idp || c.Timeout != 50*time.Millisecond || reflect.ValueOf(c.CheckRedirect).Pointer() != reflect.ValueOf(check).Pointer() {
		t.Errorf("Fetch changed the caller's client: %+v", c)
	}
}

// roundTrip is a transport that, as net/http's does, fails a request whose
// context is done.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The request carries the caller's context.
func TestFetch_Context(t *testing.T) {
	t.Parallel()
	const issuer = "https://idp.example"
	body := docFor(t, issuer, nil)
	c := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if err := r.Context().Err(); err != nil {
			return nil, err
		}
		return answer(http.StatusOK, bytes.NewReader(body)), nil
	})}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := discovery.Fetch(ctx, c, issuer)
	refusedFetch(t, "a cancelled context", err)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if _, err := discovery.Fetch(t.Context(), c, issuer); err != nil {
		t.Errorf("a live context: Fetch = %v, want nil", err)
	}
}

// http is allowed only on localhost (RFC 6761 §6.3) and a loopback address
// (RFC 1122 §3.2.1.3, RFC 4291 §2.5.3).
func TestLoopbackHost(t *testing.T) {
	t.Parallel()
	for _, h := range []string{"localhost", "LOCALHOST", "LocalHost", "127.0.0.1", "127.255.255.254", "::1"} {
		if !discovery.LoopbackHost(h) {
			t.Errorf("LoopbackHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"", "localhost.example", "127.0.0.1.example", "0.0.0.0", "::", "10.0.0.1", "example.com", "[::1]", "128.0.0.1"} {
		if discovery.LoopbackHost(h) {
			t.Errorf("LoopbackHost(%q) = true, want false", h)
		}
	}
}
