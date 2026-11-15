package discovery_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access/oidc/internal/discovery"
	"github.com/cplieger/access/oidc/internal/jwk"
	"github.com/cplieger/access/oidc/internal/jws"
)

const (
	jwksURI = "https://idp.example/jwks"
	payload = `{"sub":"u"}`
)

// testAlgs is the provider's set the key-set tests use: ES256 and EdDSA,
// whose keys generate fast.
var testAlgs = []jwk.Alg{jwk.ES256, jwk.EdDSA}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signer is a private key and the public JWK it publishes under kid.
type signer struct {
	priv any
	kid  string
}

func ecSigner(t testing.TB, kid string) signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	return signer{priv: priv, kid: kid}
}

func edSigner(t testing.TB, kid string) signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	return signer{priv: priv, kid: kid}
}

// jwk is the public key as RFC 7518 §6.2.1 or RFC 8037 §2 writes it.
func (s signer) jwk(t testing.TB) map[string]any {
	t.Helper()
	switch k := s.priv.(type) {
	case *ecdsa.PrivateKey:
		pt, err := k.PublicKey.Bytes()
		if err != nil {
			t.Fatalf("ec point: %v", err)
		}
		return map[string]any{"kty": "EC", "crv": "P-256", "kid": s.kid, "x": b64(pt[1:33]), "y": b64(pt[33:])}
	case ed25519.PrivateKey:
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": s.kid, "x": b64(k.Public().(ed25519.PublicKey))}
	}
	t.Fatalf("jwk: unknown key %T", s.priv)
	return nil
}

// token mints a compact JWS (RFC 7515 §7.1) whose header names s's kid,
// signed as ES256 (R ‖ S, RFC 7518 §3.4) or EdDSA (RFC 8037 §3.1), and
// parses it under testAlgs.
func (s signer) token(t testing.TB) *jws.Token {
	t.Helper()
	alg := "EdDSA"
	if _, ok := s.priv.(*ecdsa.PrivateKey); ok {
		alg = "ES256"
	}
	header, err := json.Marshal(map[string]string{"alg": alg, "kid": s.kid})
	if err != nil {
		t.Fatal(err)
	}
	input := b64(header) + "." + b64([]byte(payload))
	var sig []byte
	switch k := s.priv.(type) {
	case *ecdsa.PrivateKey:
		d := sha256.Sum256([]byte(input))
		r, ss, err := ecdsa.Sign(rand.Reader, k, d[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		ss.FillBytes(sig[32:])
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(input))
	}
	tok, err := jws.Parse(input+"."+b64(sig), testAlgs)
	if err != nil {
		t.Fatalf("jws.Parse: %v", err)
	}
	return tok
}

// clock is the provider's Config.Now under the test's control.
type clock struct {
	t  time.Time
	mu sync.Mutex
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// jwksIdP is an http.RoundTripper standing in for a provider's jwks_uri. It
// answers each request with the state at the moment it answers, so a test
// can publish a new set while a request is held.
type jwksIdP struct {
	reply   *reply
	hold    chan struct{}
	keys    []map[string]any
	headers []http.Header
	mu      sync.Mutex
}

func newJWKSIdP(t testing.TB, keys ...signer) *jwksIdP {
	t.Helper()
	f := &jwksIdP{}
	f.publish(t, keys...)
	return f
}

// publish replaces the served set with keys and serves it with a 200.
func (f *jwksIdP) publish(t testing.TB, keys ...signer) {
	t.Helper()
	jwks := make([]map[string]any, len(keys))
	for i, k := range keys {
		jwks[i] = k.jwk(t)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys, f.reply = jwks, nil
}

// reply is an answer jwksIdP gives in place of its published set.
type reply struct {
	err      error
	location string
	body     string
	status   int
	// cutBody makes the body fail after its first bytes.
	cutBody bool
}

// serve answers every request with r.
func (f *jwksIdP) serve(r reply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reply = &r
}

// jsonText is v as JSON.
func jsonText(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// holdRequests makes every request wait, until release is called or the
// request's context ends.
func (f *jwksIdP) holdRequests() (release func()) {
	ch := make(chan struct{})
	f.mu.Lock()
	f.hold = ch
	f.mu.Unlock()
	return sync.OnceFunc(func() {
		f.mu.Lock()
		f.hold = nil
		f.mu.Unlock()
		close(ch)
	})
}

func (f *jwksIdP) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.headers)
}

func (f *jwksIdP) requestHeaders() []http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]http.Header(nil), f.headers...)
}

func (f *jwksIdP) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.headers = append(f.headers, r.Header.Clone())
	hold := f.hold
	f.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	f.mu.Lock()
	rep, keys := f.reply, f.keys
	f.mu.Unlock()
	if rep == nil {
		rep = &reply{status: http.StatusOK, body: jsonText(map[string]any{"keys": keys})}
	}
	if rep.err != nil {
		return nil, rep.err
	}
	var body io.Reader = strings.NewReader(rep.body)
	if rep.cutBody {
		body = &failingReader{}
	}
	resp := answer(rep.status, body)
	if rep.location != "" {
		resp.StatusCode, resp.Status = http.StatusFound, http.StatusText(http.StatusFound)
		resp.Header.Set("Location", rep.location)
	}
	resp.Request = r
	return resp, nil
}

// client is the capped client NewProvider hands discovery, whose Timeout
// is 10 seconds (docs/oidc.md "Outbound calls").
func (f *jwksIdP) client() *http.Client {
	return &http.Client{Transport: f, Timeout: 10 * time.Second}
}

// logSink records every log record a logger built on it handles.
type logSink struct {
	recs []slog.Record
	mu   sync.Mutex
}

func (s *logSink) Enabled(context.Context, slog.Level) bool { return true }
func (s *logSink) WithAttrs([]slog.Attr) slog.Handler       { return s }
func (s *logSink) WithGroup(string) slog.Handler            { return s }

func (s *logSink) Handle(_ context.Context, r slog.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, r.Clone())
	return nil
}

// warns is each WARN record's message and attributes as text.
func (s *logSink) warns() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.recs {
		if r.Level != slog.LevelWarn {
			continue
		}
		var b strings.Builder
		b.WriteString(r.Message)
		r.Attrs(func(a slog.Attr) bool {
			fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
			return true
		})
		out = append(out, b.String())
	}
	return out
}

// fixture is a KeySet over a jwksIdP, with its clock and log.
type fixture struct {
	idp   *jwksIdP
	clock *clock
	log   *logSink
	keys  *discovery.KeySet
}

func newFixture(t testing.TB, keys ...signer) *fixture {
	t.Helper()
	f := &fixture{idp: newJWKSIdP(t, keys...), clock: newClock(), log: &logSink{}}
	ks, err := discovery.NewKeySet(t.Context(), f.idp.client(), discovery.Document{JWKSURI: jwksURI, Algs: testAlgs}, f.clock.now, slog.New(f.log))
	if err != nil {
		t.Fatalf("NewKeySet = %v, want nil", err)
	}
	f.keys = ks
	return f
}

func (f *fixture) verifies(t testing.TB, s signer) {
	t.Helper()
	got, err := f.keys.Verify(t.Context(), s.token(t))
	if err != nil || string(got) != payload {
		t.Fatalf("Verify(kid %q) = %q, %v; want the payload", s.kid, got, err)
	}
}

func (f *fixture) misses(t testing.TB, s signer) {
	t.Helper()
	got, err := f.keys.Verify(t.Context(), s.token(t))
	if !errors.Is(err, jws.ErrNoKey) || got != nil {
		t.Fatalf("Verify(kid %q) = %q, %v; want ErrNoKey", s.kid, got, err)
	}
}

func (f *fixture) wantRequests(t testing.TB, want int) {
	t.Helper()
	if got := f.idp.requests(); got != want {
		t.Fatalf("the JWKS saw %d requests, want %d", got, want)
	}
}

type failingReader struct{ sent bool }

func (r *failingReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, `{"keys":[`), nil
	}
	return 0, errors.New("connection reset mid-body")
}
