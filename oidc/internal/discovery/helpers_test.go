package discovery_test

import (
	"bytes"
	json "encoding/json/v2"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const wellKnown = "/.well-known/openid-configuration"

// docFor is a document Parse accepts for issuer, with set's members added
// or replaced and drop's removed.
func docFor(t testing.TB, issuer string, set map[string]any, drop ...string) []byte {
	t.Helper()
	base := strings.TrimSuffix(issuer, "/")
	m := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"jwks_uri":                              base + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	maps.Copy(m, set)
	for _, name := range drop {
		delete(m, name)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// padded is the JSON value b followed by spaces to size bytes, still one
// valid JSON value (RFC 8259 §2 allows trailing whitespace).
func padded(b []byte, size int) []byte {
	return append(b, bytes.Repeat([]byte{' '}, size-len(b))...)
}

// fakeIdP is an http.RoundTripper standing in for the network: it records
// every request's URL and answers with serve's response.
type fakeIdP struct {
	serve func(*http.Request) *http.Response
	urls  []string
	mu    sync.Mutex
}

func (f *fakeIdP) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.urls = append(f.urls, r.URL.String())
	f.mu.Unlock()
	resp := f.serve(r)
	resp.Request = r
	return resp, nil
}

func (f *fakeIdP) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.urls...)
}

// client is a client over f whose CheckRedirect counts its calls and allows
// every redirect, as a caller's permissive policy would.
func (f *fakeIdP) client(asked *atomic.Int32) *http.Client {
	return &http.Client{Transport: f, CheckRedirect: func(*http.Request, []*http.Request) error {
		asked.Add(1)
		return nil
	}}
}

func answer(status int, body io.Reader) *http.Response {
	rc, ok := body.(io.ReadCloser)
	if !ok {
		rc = io.NopCloser(body)
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"application/json"}},
		Body:   rc,
	}
}

// countingBody counts its reads and its Close.
type countingBody struct {
	r      io.Reader
	reads  atomic.Int32
	closed atomic.Bool
}

func (b *countingBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return b.r.Read(p)
}

func (b *countingBody) Close() error {
	b.closed.Store(true)
	return nil
}
