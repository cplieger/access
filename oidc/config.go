package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc/internal/discovery"
	"github.com/cplieger/access/oidc/internal/jwk"
	"golang.org/x/oauth2"
)

// Config is a Provider's settings. Every optional field's zero value is its
// default.
type Config struct {
	// HTTPClient is the client for discovery, JWKS and token calls; nil
	// means a default client. The provider uses a copy: a zero Timeout
	// becomes 10s, and the transport is wrapped so a response body past 1
	// MiB is refused, whatever length it declares. A negative Timeout is
	// refused. CheckRedirect, Jar and the transport's dialer and TLS
	// settings are kept as given.
	HTTPClient *http.Client
	// FlowSealer seals the flow cookie; nil means a new ephemeral sealer
	// per Provider, so a flow begun under one Provider value cannot finish
	// under a rebuilt one; an app that rebuilds providers passes one sealer
	// that outlives them.
	FlowSealer *access.Sealer
	// Now is the clock for the flow cookie, the ID token's time claims, and
	// the key set's age and refetch gate; nil means time.Now.
	Now func() time.Time
	// Logger receives the key set's WARNs; nil means slog.Default() at
	// each call.
	Logger       *slog.Logger
	ClientSecret access.Secret
	IssuerURL    string
	ClientID     string
	RedirectURL  string
	// Scopes is the requested scope list, which must include "openid"; nil
	// means openid, profile and email.
	Scopes []string
}

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// scopeOpenID is the scope every OpenID Connect request carries (OpenID
// Connect Core 1.0 §3.1.2.1).
const scopeOpenID = "openid"

var defaultScopes = []string{scopeOpenID, "profile", "email"}

// Validate requires an https issuer and redirect URL, except http on a
// loopback host, each absolute with a host and no userinfo or fragment,
// and the issuer with no query (OpenID Connect Discovery 1.0 section 3); a
// client ID; a Scopes list that includes "openid" when one is given; and a
// non-negative HTTPClient.Timeout. Every refusal matches ErrConfigInvalid.
func (c Config) Validate() error { //nolint:gocritic // hugeParam: a value receiver keeps it callable on a non-addressable config
	if err := checkSettingURL("IssuerURL", c.IssuerURL, true); err != nil {
		return err
	}
	if c.ClientID == "" {
		return fmt.Errorf("%w: ClientID is required", ErrConfigInvalid)
	}
	if err := checkSettingURL("RedirectURL", c.RedirectURL, false); err != nil {
		return err
	}
	if c.Scopes != nil && !slices.Contains(c.Scopes, scopeOpenID) {
		return fmt.Errorf("%w: Scopes must include %q", ErrConfigInvalid, scopeOpenID)
	}
	if c.HTTPClient != nil && c.HTTPClient.Timeout < 0 {
		return fmt.Errorf("%w: HTTPClient.Timeout must not be negative", ErrConfigInvalid)
	}
	return nil
}

func checkSettingURL(field, raw string, issuer bool) error {
	if raw == "" {
		return fmt.Errorf("%w: %s is required", ErrConfigInvalid, field)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil, u.Host == "", u.User != nil:
		return fmt.Errorf("%w: %s must be an absolute URL with a host and no userinfo", ErrConfigInvalid, field)
	case u.Scheme != schemeHTTPS && (u.Scheme != schemeHTTP || !discovery.LoopbackHost(u.Hostname())):
		return fmt.Errorf("%w: %s must use https, or http on a loopback host", ErrConfigInvalid, field)
	case strings.Contains(raw, "#"):
		return fmt.Errorf("%w: %s must not carry a fragment", ErrConfigInvalid, field)
	case issuer && strings.Contains(raw, "?"):
		return fmt.Errorf("%w: %s must not carry a query", ErrConfigInvalid, field)
	}
	return nil
}

// Provider is an OpenID Connect provider discovered by NewProvider. It is
// immutable; an app swaps its pointer when settings change.
type Provider struct {
	keys     *discovery.KeySet
	endpoint oauth2.Endpoint
	algs     []jwk.Alg
	cfg      Config
}

// NewProvider validates cfg, refuses with ErrConfigInvalid one whose
// largest flow would not seal or fit its cookie, and fetches discovery and
// the JWK Set through cfg's client, following no redirect. It refuses with
// ErrDiscovery, never naming a URL, a failed fetch or non-200 answer,
// another issuer, no accepted algorithm, no usable key, or, naming the
// field, an endpoint outside the https rule (http only under a loopback
// http issuer).
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) { //nolint:gocritic // hugeParam: by value, so the caller's config stays its own while NewProvider fills defaults
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.HTTPClient = providerClient(cfg.HTTPClient)
	cfg.Scopes = slices.Clone(cfg.Scopes)
	if cfg.Scopes == nil {
		cfg.Scopes = slices.Clone(defaultScopes)
	}
	if cfg.FlowSealer == nil {
		cfg.FlowSealer = access.NewEphemeralSealer()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if err := checkFlowFits(&cfg); err != nil {
		return nil, err
	}
	doc, err := discovery.Fetch(ctx, cfg.HTTPClient, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	keys, err := discovery.NewKeySet(ctx, cfg.HTTPClient, doc, cfg.Now, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	return &Provider{
		keys:     keys,
		algs:     doc.Algs,
		endpoint: oauth2.Endpoint{AuthURL: doc.AuthorizationEndpoint, TokenURL: doc.TokenEndpoint},
		cfg:      cfg,
	}, nil
}

// Issuer returns cfg.IssuerURL, the issuer every ID token this provider
// verifies carries.
func (p *Provider) Issuer() string { return p.cfg.IssuerURL }

// LogValue prints the issuer and client ID. Provider has no Format: its
// config holds ClientSecret as an access.Secret, and no field stores an
// oauth2.Config, which would hold the secret in clear.
func (p *Provider) LogValue() slog.Value {
	return slog.GroupValue(slog.String("issuer", p.cfg.IssuerURL), slog.String("client_id", p.cfg.ClientID))
}

// oauth2Config builds the per-call client config without the secret; only
// Finish's code exchange sets it.
func (p *Provider) oauth2Config() oauth2.Config {
	return oauth2.Config{
		ClientID:    p.cfg.ClientID,
		RedirectURL: p.cfg.RedirectURL,
		Endpoint:    p.endpoint,
		Scopes:      p.cfg.Scopes,
	}
}

// defaultHTTPTimeout is the Timeout a client without one gets; tests shorten
// it through export_test.go.
var defaultHTTPTimeout = 10 * time.Second

// maxResponseBytes caps every response body the provider's client reads.
const maxResponseBytes = 1 << 20

var errResponseTooLarge = errors.New("oidc: response body larger than 1 MiB")

// providerClient copies given, so the caller's client is never mutated, and
// wraps its transport in cappedTransport.
func providerClient(given *http.Client) *http.Client {
	c := &http.Client{}
	if given != nil {
		*c = *given
	}
	if c.Timeout == 0 {
		c.Timeout = defaultHTTPTimeout
	}
	next := c.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	c.Transport = cappedTransport{next: next}
	return c
}

// cappedTransport caps the response body, not the dial, so it sits outside
// an SSRF-guarding transport without weakening it.
type cappedTransport struct{ next http.RoundTripper }

func (t cappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &cappedBody{rc: resp.Body}
	return resp, nil
}

// cappedBody hands out at most maxResponseBytes and fails with
// errResponseTooLarge once the body holds a byte beyond them, reading at
// most that one byte past the cap. The error that ends the body at the cap
// is returned by every later Read.
type cappedBody struct {
	rc  io.ReadCloser
	err error
	n   int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if room := maxResponseBytes - b.n; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := b.rc.Read(p)
	b.n += int64(n)
	if b.n == maxResponseBytes {
		if err == nil {
			// x/oauth2 reads the token body through its own 1 MiB limit and
			// never asks for the byte past the cap, so it is looked for now:
			// https://github.com/golang/oauth2/blob/v0.37.0/internal/token.go#L263
			err = b.pastCap()
		}
		b.err = err
	}
	return n, err
}

// pastCap reads one byte past the cap: errResponseTooLarge when there is
// one, else the body's own end or error, or io.ErrNoProgress after
// maxEmptyReads reads of no byte and no error.
func (b *cappedBody) pastCap() error {
	var one [1]byte
	for range maxEmptyReads {
		n, err := b.rc.Read(one[:])
		if n > 0 {
			return errResponseTooLarge
		}
		if err != nil {
			return err
		}
	}
	return io.ErrNoProgress
}

// maxEmptyReads bounds pastCap's consecutive empty reads, so a body that
// answers no byte and no error forever cannot hang the read.
const maxEmptyReads = 100

func (b *cappedBody) Close() error { return b.rc.Close() }
