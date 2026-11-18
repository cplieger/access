package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc/internal/bodycap"
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
	// refused. Jar and the transport's dialer and TLS settings are kept as
	// given; CheckRedirect applies to the token exchange only, since
	// discovery and the key set follow no redirect.
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
// client ID; a Scopes list that includes "openid" when one is given; a
// non-negative HTTPClient.Timeout; and a largest flow that seals and fits
// its cookie. It makes no request. Every refusal matches ErrConfigInvalid,
// and NewProvider refuses no other config with it.
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
	filled := c.withDefaults()
	return checkFlowFits(&filled)
}

// withDefaults is c with the Scopes, FlowSealer and Now NewProvider uses
// when they are unset. A sealed value's length depends only on its
// payload's, so Validate's fit check under a new ephemeral sealer holds for
// the one NewProvider keeps.
func (c Config) withDefaults() Config { //nolint:gocritic // hugeParam: returns a filled copy, leaving c the caller's
	c.Scopes = slices.Clone(c.Scopes)
	if c.Scopes == nil {
		c.Scopes = slices.Clone(defaultScopes)
	}
	if c.FlowSealer == nil {
		c.FlowSealer = access.NewEphemeralSealer()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
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

// NewProvider refuses a cfg that fails Validate, then fetches discovery
// and the JWK Set through cfg's client, following no redirect; no error
// names a URL. It fails with ErrDiscovery when either could not be fetched
// or answered other than 200, and with ErrProviderInvalid when the provider
// answered with a body past 1 MiB, a document that is not one JSON object,
// names another issuer, has no accepted algorithm or, naming the field, an
// endpoint outside the https rule (http only under a loopback http
// issuer), or a JWK Set that is malformed or holds no usable key.
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) { //nolint:gocritic // hugeParam: by value, so the caller's config stays its own while NewProvider fills defaults
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	cfg.HTTPClient = providerClient(cfg.HTTPClient)
	doc, err := discovery.Fetch(ctx, cfg.HTTPClient, cfg.IssuerURL)
	if err != nil {
		return nil, providerFailure(err)
	}
	keys, err := discovery.NewKeySet(ctx, cfg.HTTPClient, doc, cfg.Now, cfg.Logger)
	if err != nil {
		return nil, providerFailure(err)
	}
	return &Provider{
		keys:     keys,
		algs:     doc.Algs,
		endpoint: oauth2.Endpoint{AuthURL: doc.AuthorizationEndpoint, TokenURL: doc.TokenEndpoint},
		cfg:      cfg,
	}, nil
}

// providerFailure is err from discovery under ErrProviderInvalid when the
// provider answered with what discovery refuses, else under ErrDiscovery.
func providerFailure(err error) error {
	if errors.Is(err, discovery.ErrDocument) || errors.Is(err, discovery.ErrKeys) {
		return fmt.Errorf("%w: %w", ErrProviderInvalid, err)
	}
	return fmt.Errorf("%w: %w", ErrDiscovery, err)
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

// providerClient copies given, so the caller's client is never mutated, and
// caps every response body it reads (bodycap.Transport).
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
	c.Transport = bodycap.Transport{Next: next}
	return c
}
