package accesstest

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The ID-token signing algorithms IdPOptions.Algorithm accepts. The IdP
// advertises only the two it signs with keys from its JWKS; AlgNone and
// AlgHS256 produce tokens a correct relying party refuses.
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
	AlgNone  = "none"
	AlgHS256 = "HS256"
)

// The defaults NewIdP fills for an empty field of IdPOptions, and the user
// claims every ID token carries.
//
//nolint:revive // IdP is the usual spelling of identity provider, as in OpenID Connect Core 1.0 section 1.2.
const (
	DefaultIdPClientID     = "authtest-client"
	DefaultIdPClientSecret = "authtest-secret"
	DefaultIdPSubject      = "authtest-subject"
	DefaultIdPEmail        = "authtest@example.com"
	DefaultIdPUsername     = "authtest"
	defaultIDTokenLifetime = 5 * time.Minute
)

const (
	idpKeyIDRS256    = "authtest-rs256"
	idpKeyIDES256    = "authtest-es256"
	maxTokenFormBody = 64 << 10
	pkceS256         = "S256"
	// maxAgeCeiling is the largest max_age, in seconds, a time.Duration
	// holds; a larger value means the same "never too old".
	maxAgeCeiling = math.MaxInt64 / int64(time.Second)
)

// The OAuth error codes the IdP answers with (RFC 6749 sections 4.1.2.1 and
// 5.2; login_required is OpenID Connect Core 1.0 section 3.1.2.6).
const (
	errInvalidRequest          = "invalid_request"
	errUnsupportedResponseType = "unsupported_response_type"
	errLoginRequired           = "login_required"
	errInvalidClient           = "invalid_client"
	errInvalidGrant            = "invalid_grant"
	errUnsupportedGrantType    = "unsupported_grant_type"
)

// IdPEndpoint shapes the responses of one IdP endpoint, for tests of a
// relying party's outbound-HTTP bounds.
//
//nolint:revive // IdP is the usual spelling of identity provider, as in OpenID Connect Core 1.0 section 1.2.
type IdPEndpoint struct {
	// Delay is waited, in wall time whatever IdPOptions.Now says, before the
	// response is written. The wait ends early when the request's context
	// ends or the IdP closes, so a hung endpoint never blocks the test's
	// cleanup.
	Delay time.Duration
	// BodyBytes, when larger than the response's JSON, pads the JSON with
	// trailing spaces to exactly this many bytes, so the body stays valid
	// JSON and only a size cap refuses it.
	BodyBytes int
	// Streamed sends the response with no Content-Length, so a client
	// learns the body's length only by reading it (chunked transfer coding,
	// RFC 9112 section 7.1).
	Streamed bool
}

// IdPOptions configures NewIdP. Every zero value is the default, and each
// other field changes one thing about what the IdP serves. NewIdP copies
// every value, so a later write to the options, or to a slice or string
// they point at, never reaches the running IdP.
//
//nolint:revive // IdP is the usual spelling of identity provider, as in OpenID Connect Core 1.0 section 1.2.
type IdPOptions struct {
	// Now is the IdP's clock for iat, exp, auth_time and max_age; nil is
	// time.Now.
	Now func() time.Time
	// Nonce, when non-nil, is the nonce claim, an empty string included;
	// nil echoes the authorize request's nonce, and omits the claim when the
	// request carried none.
	Nonce *string
	// Subject, when non-nil, is the sub claim, an empty string included; nil
	// is DefaultIdPSubject.
	Subject *string
	// EmailVerified, when non-nil, is written as the email_verified claim
	// as given, so a string "true" tests a relying party's tolerance; nil
	// is the boolean true. NewIdP fails the test when it does not encode as
	// JSON.
	EmailVerified any
	// Groups, when non-nil, is written as the groups claim as given, a
	// string or a []string; nil omits the claim. NewIdP fails the test when
	// it does not encode as JSON.
	Groups any
	// URL, when non-empty, is the issuer in place of the listener's URL:
	// discovery's issuer, the iss claim and the authorization response's
	// iss, and, less any final "/", the base of every endpoint (OpenID
	// Connect Discovery 1.0 section 4.1). It is https with a DNS host
	// httptest's certificate covers (example.com or one label below it), an
	// optional port and path, and no query, fragment or userinfo; NewIdP
	// fails the test on any other. The IdP then serves HTTPS, reached only by
	// a client that dials IdP.Addr for URL's host and port, as IdP.Client does.
	URL string
	// AuthorizedParty, when non-empty, is the azp claim; empty omits it.
	AuthorizedParty string
	// Algorithm is the ID token's alg header, one of the Alg constants;
	// empty is AlgRS256. AlgHS256 signs with ClientSecret, AlgNone writes
	// an empty signature.
	Algorithm string
	// ClientID is the one client /authorize and /token accept, and the
	// default aud; empty is DefaultIdPClientID.
	ClientID string
	// ClientSecret authenticates ClientID at /token; empty is
	// DefaultIdPClientSecret.
	ClientSecret string
	// AuthorizationEndpoint, TokenEndpoint and JWKSURI, when non-empty, are
	// advertised by discovery as given instead of the IdP's own endpoints.
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	// Audience, when non-nil, is the aud claim: one entry is written as a
	// string, any other count as an array. Nil is ClientID as a string.
	Audience []string
	// Discovery, JWKS and Token shape those endpoints' responses.
	Discovery IdPEndpoint
	JWKS      IdPEndpoint
	Token     IdPEndpoint
	// Lifetime is exp minus iat; zero is five minutes, and a negative value
	// issues a token that expired before it was issued.
	Lifetime time.Duration
	// AuthTimeOffset is added to the auth_time the IdP would write, so a
	// negative value backdates the sign-in.
	AuthTimeOffset time.Duration
	// OmitAuthTime leaves auth_time out of the ID token, even after a
	// max_age request, whose token OpenID Connect Core 1.0 section 2
	// requires it in.
	OmitAuthTime bool
	// TLS serves the IdP over HTTPS with httptest's certificate, which only
	// a client trusting IdP.RootCAs, such as IdP.Client, trusts; false
	// serves plain HTTP on loopback unless URL is set.
	TLS bool
}

// IdP is an OpenID Connect provider on an httptest server for one client and
// one user, signed in at NewIdP. /authorize approves each valid request at
// once, honours prompt and max_age (OpenID Connect Core 1.0 section 3.1.2.1),
// takes PKCE as S256 only (RFC 7636), and answers a bad client_id or
// redirect_uri with 400, not a redirect. Every IdP of a test binary signs with
// the same keys, so a token one issues verifies against another's JWKS.
//
//nolint:revive // IdP is the usual spelling of identity provider, as in OpenID Connect Core 1.0 section 1.2.
type IdP struct {
	srv    *httptest.Server
	keys   *idpKeys
	done   chan struct{}
	cfg    *idpConfig
	codes  map[string]idpGrant
	client *http.Client
	login  time.Time
	issuer string
	addr   netip.AddrPort
	auth   []url.Values
	mu     sync.Mutex
}

// idpConfig is IdPOptions frozen by NewIdP. Handlers read it without the
// lock, so nothing writes it after NewIdP returns, and it shares no slice,
// map or pointer with the caller's options.
type idpConfig struct {
	now                   func() time.Time
	claims                map[string]json.RawMessage
	url                   string
	urlHost               string
	dialAddr              string
	pathPrefix            string
	algorithm             string
	clientID              string
	clientSecret          string
	authorizationEndpoint string
	tokenEndpoint         string
	jwksURI               string
	discovery             IdPEndpoint
	jwks                  IdPEndpoint
	token                 IdPEndpoint
	lifetime              time.Duration
	authTimeOffset        time.Duration
	omitAuthTime          bool
}

type idpGrant struct {
	authTime    time.Time
	redirectURI string
	nonce       string
	challenge   string
}

type idpKeys struct {
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

// Key generation dominates an IdP's start-up, RSA under -race especially,
// so every IdP of a test binary shares one key pair.
var sharedSigningKeys = sync.OnceValues(func() (*idpKeys, error) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &idpKeys{rsa: rk, ec: ek}, nil
})

// NewIdP starts an IdP for the test and closes it at the test's cleanup. It
// fails the test on an unknown IdPOptions.Algorithm, a URL outside its
// rule, or an EmailVerified or Groups value that does not encode as JSON.
//
//nolint:revive,gocritic // IdP is the usual spelling of identity provider (OpenID Connect Core 1.0 section 1.2); options by value let a call site pass a literal, and freezeOptions keeps no reference into them.
func NewIdP(t testing.TB, opts IdPOptions) *IdP {
	t.Helper()
	cfg, err := freezeOptions(&opts)
	if err != nil {
		t.Fatalf("accesstest: %v", err)
	}
	keys, err := sharedSigningKeys()
	if err != nil {
		t.Fatalf("accesstest: IdP keys: %v", err)
	}
	p := &IdP{cfg: cfg, keys: keys, done: make(chan struct{}), codes: map[string]idpGrant{}, login: cfg.now()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.endpoint(cfg.discovery, p.discovery))
	mux.HandleFunc("GET /jwks", p.endpoint(cfg.jwks, p.jwks))
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.endpoint(cfg.token, p.token))
	p.srv = httptest.NewUnstartedServer(http.StripPrefix(cfg.pathPrefix, mux))
	secure := opts.TLS || cfg.url != ""
	scheme := "http"
	if secure {
		scheme = "https"
	}
	addr, err := netip.ParseAddrPort(p.srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("accesstest: IdP listener: %v", err)
	}
	p.addr = addr
	p.issuer = cmp.Or(cfg.url, scheme+"://"+addr.String())
	if secure {
		p.srv.StartTLS()
	} else {
		p.srv.Start()
	}
	p.client = p.newClient()
	t.Cleanup(func() {
		close(p.done)
		p.client.CloseIdleConnections()
		p.srv.Close()
	})
	if cfg.url != "" {
		if err := p.srv.Certificate().VerifyHostname(cfg.urlHost); err != nil {
			t.Fatalf("accesstest: IdP URL %q: %v", cfg.url, err)
		}
	}
	return p
}

// newClient builds Client from Addr and RootCAs alone, so a caller's own
// client built from the same two values reaches the IdP exactly as Client
// does.
func (p *IdP) newClient() *http.Client {
	listener := p.addr.String()
	var d net.Dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if p.cfg.dialAddr != "" && strings.EqualFold(addr, p.cfg.dialAddr) {
				addr = listener
			}
			return d.DialContext(ctx, network, addr)
		},
	}
	if roots := p.RootCAs(); roots != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr}
}

func freezeOptions(o *IdPOptions) (*idpConfig, error) {
	switch o.Algorithm {
	case "", AlgRS256, AlgES256, AlgNone, AlgHS256:
	default:
		return nil, fmt.Errorf("unknown IdP algorithm %q", o.Algorithm)
	}
	u, err := parseIssuerURL(o.URL)
	if err != nil {
		return nil, err
	}
	cfg := &idpConfig{
		now:                   o.Now,
		url:                   o.URL,
		urlHost:               u.Hostname(),
		pathPrefix:            strings.TrimSuffix(u.Path, "/"),
		algorithm:             cmp.Or(o.Algorithm, AlgRS256),
		clientID:              cmp.Or(o.ClientID, DefaultIdPClientID),
		clientSecret:          cmp.Or(o.ClientSecret, DefaultIdPClientSecret),
		authorizationEndpoint: o.AuthorizationEndpoint,
		tokenEndpoint:         o.TokenEndpoint,
		jwksURI:               o.JWKSURI,
		discovery:             o.Discovery,
		jwks:                  o.JWKS,
		token:                 o.Token,
		lifetime:              cmp.Or(o.Lifetime, defaultIDTokenLifetime),
		authTimeOffset:        o.AuthTimeOffset,
		omitAuthTime:          o.OmitAuthTime,
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if o.URL != "" {
		cfg.dialAddr = net.JoinHostPort(u.Hostname(), cmp.Or(u.Port(), "443"))
	}
	claims, err := frozenClaims(o, cfg.clientID)
	if err != nil {
		return nil, err
	}
	cfg.claims = claims
	return cfg, nil
}

// parseIssuerURL applies IdPOptions.URL's rule short of the certificate, which
// NewIdP checks once the server has one. An empty URL is the zero URL.
func parseIssuerURL(raw string) (*url.URL, error) {
	if raw == "" {
		return &url.URL{}, nil
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return nil, fmt.Errorf("IdP URL %q: %w", raw, err)
	case u.Scheme != "https" || u.Host == "" || strings.HasSuffix(u.Host, ":"):
		return nil, fmt.Errorf("IdP URL %q is not an https URL with a host", raw)
	case u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#"):
		return nil, fmt.Errorf("IdP URL %q carries userinfo, a query or a fragment", raw)
	}
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		return nil, fmt.Errorf("IdP URL %q has an IP address for a host, not a DNS name", raw)
	}
	return u, nil
}

// frozenClaims encodes every claim that is the same in each ID token. The
// encoding is the deep copy: it is the one form that copies whatever an
// any-typed knob holds.
func frozenClaims(o *IdPOptions, clientID string) (map[string]json.RawMessage, error) {
	set := map[string]any{
		"sub":                DefaultIdPSubject,
		"aud":                clientID,
		"email":              DefaultIdPEmail,
		"email_verified":     true,
		"preferred_username": DefaultIdPUsername,
	}
	if o.Nonce != nil {
		set["nonce"] = *o.Nonce
	}
	if o.Subject != nil {
		set["sub"] = *o.Subject
	}
	if len(o.Audience) == 1 {
		set["aud"] = o.Audience[0]
	} else if o.Audience != nil {
		set["aud"] = o.Audience
	}
	if o.AuthorizedParty != "" {
		set["azp"] = o.AuthorizedParty
	}
	if o.EmailVerified != nil {
		set["email_verified"] = o.EmailVerified
	}
	if o.Groups != nil {
		set["groups"] = o.Groups
	}
	out := make(map[string]json.RawMessage, len(set))
	for name, v := range set {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("IdP claim %s: %w", name, err)
		}
		out[name] = b
	}
	return out, nil
}

// Issuer returns the IdP's issuer, IdPOptions.URL when set and its
// listener's URL otherwise; it is the base of every default endpoint.
func (p *IdP) Issuer() string { return p.issuer }

// ClientID returns the one client ID the IdP accepts.
func (p *IdP) ClientID() string { return p.cfg.clientID }

// ClientSecret returns ClientID's secret.
func (p *IdP) ClientSecret() string { return p.cfg.clientSecret }

// Client returns an HTTP client for the IdP, built from Addr and RootCAs
// alone: it trusts RootCAs and, under IdPOptions.URL, dials Addr for URL's
// host and port. A test whose own outbound client must reach the IdP builds
// it from the same two values.
func (p *IdP) Client() *http.Client { return p.client }

// Addr returns the address the IdP listens on.
func (p *IdP) Addr() netip.AddrPort { return p.addr }

// RootCAs returns a new pool holding only the IdP's certificate on each
// call, so a write to it reaches neither the IdP nor Client; it is nil when
// the IdP serves plain HTTP.
func (p *IdP) RootCAs() *x509.CertPool {
	cert := p.srv.Certificate()
	if cert == nil {
		return nil
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return roots
}

// Authorizations returns a copy of the query of every /authorize request
// received so far, refused ones included, in arrival order.
func (p *IdP) Authorizations() []url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]url.Values, len(p.auth))
	for i, q := range p.auth {
		out[i] = cloneValues(q)
	}
	return out
}

func cloneValues(q url.Values) url.Values {
	out := make(url.Values, len(q))
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// omitEmpty returns q without its empty values, and without a parameter
// left with none: RFC 6749 sections 3.1 and 3.2 treat a parameter sent
// without a value as omitted.
func omitEmpty(q url.Values) url.Values {
	out := make(url.Values, len(q))
	for k, v := range q {
		if v = slices.DeleteFunc(slices.Clone(v), func(s string) bool { return s == "" }); len(v) > 0 {
			out[k] = v
		}
	}
	return out
}

// repeated reports whether a parameter appears more than once, which RFC
// 6749 section 3.1 forbids in a request.
func repeated(q url.Values) bool {
	for _, v := range q {
		if len(v) > 1 {
			return true
		}
	}
	return false
}

type jsonHandler func(r *http.Request) (status int, body any)

func (p *IdP) endpoint(ep IdPEndpoint, h jsonHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ep.Delay > 0 {
			timer := time.NewTimer(ep.Delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-r.Context().Done():
				return
			case <-p.done:
				return
			}
		}
		status, v := h(r)
		body, err := json.Marshal(v)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if pad := ep.BodyBytes - len(body); pad > 0 {
			body = append(body, bytes.Repeat([]byte{' '}, pad)...)
		}
		w.Header().Set("Content-Type", "application/json")
		if !ep.Streamed {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.WriteHeader(status)
		if ep.Streamed {
			// net/http computes a Content-Length for a body written in full
			// before the handler returns; headers sent first commit to none.
			_ = http.NewResponseController(w).Flush()
		}
		_, _ = w.Write(body)
	}
}

func (p *IdP) discovery(*http.Request) (status int, body any) {
	base := strings.TrimSuffix(p.issuer, "/")
	return http.StatusOK, map[string]any{
		"issuer":                                         p.issuer,
		"authorization_endpoint":                         cmp.Or(p.cfg.authorizationEndpoint, base+"/authorize"),
		"token_endpoint":                                 cmp.Or(p.cfg.tokenEndpoint, base+"/token"),
		"jwks_uri":                                       cmp.Or(p.cfg.jwksURI, base+"/jwks"),
		"response_types_supported":                       []string{"code"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{AlgRS256, AlgES256},
		"code_challenge_methods_supported":               []string{pkceS256},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post"},
		"scopes_supported":                               []string{"openid", "email", "profile"},
		"authorization_response_iss_parameter_supported": true,
	}
}

func (p *IdP) jwks(*http.Request) (status int, body any) {
	ecPub, err := p.keys.ec.PublicKey.Bytes()
	if err != nil {
		return http.StatusInternalServerError, map[string]string{"error": err.Error()}
	}
	// Bytes is the uncompressed point 0x04 || X || Y (SEC 1, section 2.3.3).
	x, y := ecPub[1:33], ecPub[33:65]
	rsaPub := p.keys.rsa.PublicKey
	return http.StatusOK, map[string]any{"keys": []map[string]string{
		{"kty": "RSA", "use": "sig", "alg": AlgRS256, "kid": idpKeyIDRS256, "n": b64(rsaPub.N.Bytes()), "e": b64(big.NewInt(int64(rsaPub.E)).Bytes())},
		{"kty": "EC", "use": "sig", "alg": AlgES256, "kid": idpKeyIDES256, "crv": "P-256", "x": b64(x), "y": b64(y)},
	}}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// authRequest is one /authorize request, parsed and checked once by
// parseAuthorize; grant reads nothing else.
type authRequest struct {
	redirect    *url.URL
	prompt      map[string]bool
	redirectURI string
	state       string
	nonce       string
	challenge   string
	errCode     string
	maxAge      time.Duration
	hasMaxAge   bool
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.mu.Lock()
	p.auth = append(p.auth, cloneValues(q))
	p.mu.Unlock()
	req, ok := p.parseAuthorize(q)
	if !ok {
		http.Error(w, "accesstest: unknown client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	back := req.redirect.Query()
	if req.state != "" {
		back.Set("state", req.state)
	}
	back.Set("iss", p.issuer)
	if req.errCode == "" {
		var code string
		code, req.errCode = p.grant(&req)
		if code != "" {
			back.Set("code", code)
		}
	}
	if req.errCode != "" {
		back.Set("error", req.errCode)
	}
	req.redirect.RawQuery = back.Encode()
	http.Redirect(w, r, req.redirect.String(), http.StatusFound)
}

// parseAuthorize reports false when the request cannot be answered by a
// redirect: the client_id is not the IdP's or the redirect_uri is not one
// absolute, fragment-free URI (RFC 6749 sections 3.1.2 and 4.1.2.1). Any
// other fault is set as errCode, for the redirect to carry.
func (p *IdP) parseAuthorize(q url.Values) (authRequest, bool) {
	var req authRequest
	q = omitEmpty(q)
	if len(q["client_id"]) != 1 || q.Get("client_id") != p.cfg.clientID || len(q["redirect_uri"]) != 1 {
		return req, false
	}
	req.redirectURI = q.Get("redirect_uri")
	redirect, err := url.Parse(req.redirectURI)
	if err != nil || !redirect.IsAbs() || strings.Contains(req.redirectURI, "#") {
		return req, false
	}
	req.redirect = redirect
	req.state, req.nonce = q.Get("state"), q.Get("nonce")
	req.errCode = req.parseParams(q)
	return req, true
}

// parseParams returns the error code of the first fault in q, or "". Of
// prompt's set, none beside another value is a fault; consent,
// select_account and unknown values are approved as given (OpenID Connect
// Core 1.0 section 3.1.2.1 lets an OP ignore an unknown value).
func (req *authRequest) parseParams(q url.Values) string {
	switch {
	case repeated(q), !q.Has("response_type"):
		return errInvalidRequest
	case q.Get("response_type") != "code":
		return errUnsupportedResponseType
	}
	req.prompt = map[string]bool{}
	for v := range strings.FieldsSeq(q.Get("prompt")) {
		req.prompt[v] = true
	}
	if req.prompt["none"] && len(req.prompt) > 1 {
		return errInvalidRequest
	}
	if q.Has("max_age") {
		var ok bool
		if req.maxAge, ok = parseMaxAge(q.Get("max_age")); !ok {
			return errInvalidRequest
		}
		req.hasMaxAge = true
	}
	if q.Has("code_challenge") || q.Has("code_challenge_method") {
		req.challenge = q.Get("code_challenge")
		if q.Get("code_challenge_method") != pkceS256 || !isS256Challenge(req.challenge) {
			return errInvalidRequest
		}
	}
	return ""
}

func parseMaxAge(v string) (time.Duration, bool) {
	n, err := strconv.ParseUint(v, 10, 64)
	switch {
	case errors.Is(err, strconv.ErrSyntax):
		return 0, false
	case err != nil || n > uint64(maxAgeCeiling):
		// ParseUint refuses a sign and every non-digit, so err here is
		// strconv.ErrRange: digits beyond uint64.
		return time.Duration(maxAgeCeiling) * time.Second, true
	}
	return time.Duration(n) * time.Second, true
}

// isS256Challenge reports whether c can be an S256 code_challenge: the
// unpadded base64url of a SHA-256 digest (RFC 7636 section 4.2).
func isS256Challenge(c string) bool {
	sum, err := base64.RawURLEncoding.Strict().DecodeString(c)
	return err == nil && len(sum) == sha256.Size
}

// signInAgain applies OpenID Connect Core 1.0 section 3.1.2.1: prompt=login,
// and a max_age the sign-in at login has outlived; max_age=0 is
// prompt=login.
func (req *authRequest) signInAgain(now, login time.Time) bool {
	return req.prompt["login"] || req.hasMaxAge && (req.maxAge == 0 || now.Sub(login) > req.maxAge)
}

// grant issues a code for a checked request. A prompt=none request that
// needs a sign-in gets login_required, since none forbids the sign-in
// itself (OpenID Connect Core 1.0 section 3.1.2.1).
func (p *IdP) grant(req *authRequest) (code, errCode string) {
	now := p.cfg.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if req.signInAgain(now, p.login) {
		if req.prompt["none"] {
			return "", errLoginRequired
		}
		p.login = now
	}
	code = rand.Text()
	p.codes[code] = idpGrant{
		authTime:    p.login,
		redirectURI: req.redirectURI,
		nonce:       req.nonce,
		challenge:   req.challenge,
	}
	return code, ""
}

func (p *IdP) token(r *http.Request) (status int, body any) {
	r.Body = http.MaxBytesReader(nil, r.Body, maxTokenFormBody)
	err := r.ParseForm()
	r.PostForm = omitEmpty(r.PostForm)
	if err != nil || repeated(r.PostForm) {
		return http.StatusBadRequest, oauthError(errInvalidRequest)
	}
	if refused, code := p.authenticateClient(r); code != "" {
		return refused, oauthError(code)
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		return http.StatusBadRequest, oauthError(errUnsupportedGrantType)
	}
	g, ok := p.redeem(r.PostForm.Get("code"))
	if !ok || g.redirectURI != r.PostForm.Get("redirect_uri") || !g.verifierMatches(r.PostForm.Get("code_verifier")) {
		return http.StatusBadRequest, oauthError(errInvalidGrant)
	}
	idToken, err := p.idToken(&g)
	if err != nil {
		return http.StatusInternalServerError, oauthError("server_error")
	}
	return http.StatusOK, map[string]any{
		"access_token": rand.Text(),
		"token_type":   "Bearer",
		"expires_in":   int(defaultIDTokenLifetime / time.Second),
		"id_token":     idToken,
	}
}

func oauthError(code string) map[string]string {
	return map[string]string{"error": code}
}

// authenticateClient accepts exactly one of client_secret_basic, whose
// credentials are form-encoded before the base64 step (RFC 6749 section
// 2.3.1), and client_secret_post; two methods at once are invalid_request
// (section 2.3). It returns the status and error code of a refusal, or an
// empty code.
func (p *IdP) authenticateClient(r *http.Request) (status int, code string) {
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if user, pass, ok := r.BasicAuth(); ok {
		if r.PostForm.Has("client_secret") {
			return http.StatusBadRequest, errInvalidRequest
		}
		var errID, errSecret error
		id, errID = url.QueryUnescape(user)
		secret, errSecret = url.QueryUnescape(pass)
		if errID != nil || errSecret != nil {
			return http.StatusUnauthorized, errInvalidClient
		}
	}
	if id != p.cfg.clientID || !hmac.Equal([]byte(secret), []byte(p.cfg.clientSecret)) {
		return http.StatusUnauthorized, errInvalidClient
	}
	return http.StatusOK, ""
}

func (p *IdP) redeem(code string) (idpGrant, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	g, ok := p.codes[code]
	delete(p.codes, code)
	return g, ok
}

// verifierMatches applies RFC 7636 section 4.6 to a verifier of section
// 4.1's form; a grant with no challenge takes no verifier.
func (g *idpGrant) verifierMatches(verifier string) bool {
	if g.challenge == "" {
		return verifier == ""
	}
	if !isCodeVerifier(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return b64(sum[:]) == g.challenge
}

// isCodeVerifier checks RFC 7636 section 4.1: 43 to 128 characters of
// ALPHA, DIGIT, "-", ".", "_" and "~".
func isCodeVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range []byte(v) {
		if !unreserved(c) {
			return false
		}
	}
	return true
}

func unreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("-._~", c) >= 0
}

func (p *IdP) idToken(g *idpGrant) (string, error) {
	now := p.cfg.now()
	claims := make(map[string]any, len(p.cfg.claims)+5)
	for name, v := range p.cfg.claims {
		claims[name] = v
	}
	claims["iss"] = p.issuer
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(p.cfg.lifetime).Unix()
	if _, fixed := p.cfg.claims["nonce"]; !fixed && g.nonce != "" {
		claims["nonce"] = g.nonce
	}
	if !p.cfg.omitAuthTime {
		claims["auth_time"] = g.authTime.Add(p.cfg.authTimeOffset).Unix()
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return p.sign(payload)
}

type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ"`
}

func (p *IdP) sign(payload []byte) (string, error) {
	hdr := jwsHeader{Alg: p.cfg.algorithm, Typ: "JWT"}
	switch hdr.Alg {
	case AlgRS256:
		hdr.Kid = idpKeyIDRS256
	case AlgES256:
		hdr.Kid = idpKeyIDES256
	}
	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	input := b64(hb) + "." + b64(payload)
	sig, err := p.signature(hdr.Alg, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

// signature signs a JWS signing input per RFC 7518 section 3; ES256 is the
// fixed-width R || S, not ASN.1.
func (p *IdP) signature(alg string, input []byte) ([]byte, error) {
	digest := sha256.Sum256(input)
	switch alg {
	case AlgRS256:
		return rsa.SignPKCS1v15(rand.Reader, p.keys.rsa, crypto.SHA256, digest[:])
	case AlgES256:
		r, s, err := ecdsa.Sign(rand.Reader, p.keys.ec, digest[:])
		if err != nil {
			return nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	case AlgHS256:
		mac := hmac.New(sha256.New, []byte(p.cfg.clientSecret))
		mac.Write(input)
		return mac.Sum(nil), nil
	case AlgNone:
		return nil, nil
	}
	return nil, fmt.Errorf("accesstest: unknown IdP algorithm %q", alg)
}
