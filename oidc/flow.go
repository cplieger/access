package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"slices"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/cplieger/access"
	"golang.org/x/oauth2"
)

// Intent is what a flow is for.
type Intent string

// The three intents. Link and step-up start from a session and make the
// provider authenticate the user again.
const (
	IntentSignIn Intent = "signin"
	IntentLink   Intent = "link"   // started from a session; links on return
	IntentStepUp Intent = "stepup" // started from a session; re-proves on return
)

func (i Intent) valid() bool { return i == IntentSignIn || i == IntentLink || i == IntentStepUp }

// BeginRequest names what the flow is for. SessionID, at most 64 bytes, and
// a positive UserID are required for IntentLink and IntentStepUp and must be
// empty for IntentSignIn.
type BeginRequest struct {
	Intent    Intent
	SessionID string
	// Redirect is the app's relative return path, at most MaxRedirectBytes,
	// passed through access.ValidateRedirectURI, so an unsafe one becomes "/".
	Redirect string
	UserID   int64
}

func (req *BeginRequest) check() error {
	switch {
	case !req.Intent.valid():
		return fmt.Errorf("%w: unknown intent %q", ErrFlowInvalid, req.Intent)
	case req.Intent == IntentSignIn && (req.SessionID != "" || req.UserID != 0):
		return fmt.Errorf("%w: a sign-in carries no session or user", ErrFlowInvalid)
	case req.Intent != IntentSignIn && (req.SessionID == "" || req.UserID <= 0):
		return fmt.Errorf("%w: intent %q needs a session ID and a positive user ID", ErrFlowInvalid, req.Intent)
	case len(req.SessionID) > maxSessionIDBytes:
		return fmt.Errorf("%w: a session ID over %d bytes", ErrFlowInvalid, maxSessionIDBytes)
	}
	return nil
}

// MaxRedirectBytes is the longest BeginRequest.Redirect Begin accepts.
const MaxRedirectBytes = 512

// maxSessionIDBytes bounds BeginRequest.SessionID, so NewProvider can size
// the largest flow: twice the 32 hex characters account mints.
const maxSessionIDBytes = 64

// maxFlowCookieName is the longest flow cookie name: __Host- and the
// longest session cookie Name access.CookieConfig.Validate accepts, derived
// with flowCookieSuffix.
const maxFlowCookieName = len("__Host-") + access.MaxCookieNameBytes + len("_") + len(flowCookieSuffix)

const (
	flowPurpose      = "oidc-flow"
	flowLifetime     = 10 * time.Minute
	flowCookieSuffix = "oidc"
	// maxCookieBytes bounds a cookie's name plus value: a user agent drops
	// a longer one (RFC 6265bis section 5.6).
	maxCookieBytes = 4096
	// authTimeSkew is the clock difference the freshness check tolerates
	// between the provider and this host.
	authTimeSkew = 60 * time.Second
)

// Flow is what Finish recovers from the flow cookie.
type Flow struct {
	BeganAt   time.Time
	Intent    Intent
	SessionID string
	Redirect  string
	UserID    int64
}

// Callback is what the provider sent on its redirect to the callback (RFC
// 6749 sections 4.1.2 and 4.1.2.1), decoded once by the caller.
type Callback struct {
	State string
	Code  string
	Error string
}

// Begin seals the flow into the flow cookie, session.Derive("oidc", Lax),
// and returns the authorization URL, with max_age=0 and prompt=login for
// IntentLink and IntentStepUp. Before any Set-Cookie it refuses a Redirect
// over MaxRedirectBytes with ErrRedirectTooLong, first; with ErrConfigInvalid,
// a session config that fails Validate; with ErrFlowInvalid, an unknown intent
// or IDs that do not fit it, and a link or step-up whose Sec-Fetch-Site is
// present and not same-origin. NewProvider owns the flow cookie's size.
func (p *Provider) Begin(w http.ResponseWriter, r *http.Request, session access.CookieConfig, req BeginRequest) (authURL string, err error) { //nolint:gocritic // hugeParam: the session config is plain data, passed as the caller holds it
	if len(req.Redirect) > MaxRedirectBytes {
		return "", ErrRedirectTooLong
	}
	if verr := session.Validate(); verr != nil {
		return "", fmt.Errorf("%w: session cookie: %w", ErrConfigInvalid, verr)
	}
	if cerr := req.check(); cerr != nil {
		return "", cerr
	}
	if req.Intent != IntentSignIn {
		if site, sent := r.Header["Sec-Fetch-Site"]; sent && !slices.Equal(site, []string{"same-origin"}) {
			return "", fmt.Errorf("%w: intent %q from a request that is not same-origin", ErrFlowInvalid, req.Intent)
		}
	}
	now := p.cfg.Now()
	st := flowState{
		state:    rand.Text(),
		nonce:    rand.Text(),
		verifier: oauth2.GenerateVerifier(),
		flow: Flow{
			Intent:    req.Intent,
			SessionID: req.SessionID,
			UserID:    req.UserID,
			BeganAt:   now,
			Redirect:  access.ValidateRedirectURI(req.Redirect),
		},
		issuer:      p.cfg.IssuerURL,
		clientID:    p.cfg.ClientID,
		redirectURL: p.cfg.RedirectURL,
	}
	sealed, err := p.cfg.FlowSealer.Seal(flowPurpose, st.encode(), now.Add(flowLifetime))
	if err != nil {
		return "", fmt.Errorf("%w: flow cookie: %w", ErrConfigInvalid, err)
	}
	cookie := session.Derive(flowCookieSuffix, http.SameSiteLaxMode)
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(st.verifier), oauth2.SetAuthURLParam("nonce", st.nonce)}
	if req.Intent != IntentSignIn {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", "0"), oauth2.SetAuthURLParam("prompt", "login"))
	}
	cfg := p.oauth2Config()
	authURL = cfg.AuthCodeURL(st.state, opts...)
	cookie.SetCookie(w, r, sealed, int(flowLifetime/time.Second))
	return authURL, nil
}

// Finish reads and clears the flow cookie derived from session on every
// outcome past session.Validate, checks cb.State, exchanges cb.Code and
// verifies the ID token. It reads the request only for the cookie and its
// context, never its URL. A session config that fails Validate is
// ErrConfigInvalid with no Set-Cookie. An error after the cookie opened, for
// this provider, comes with the opened Flow, so the caller can return the
// browser to the page the flow began on; before that, Flow is zero.
func (p *Provider) Finish(w http.ResponseWriter, r *http.Request, session access.CookieConfig, cb Callback) (Flow, Claims, error) { //nolint:gocritic // hugeParam: the session config is plain data, passed as the caller holds it
	if err := session.Validate(); err != nil {
		return Flow{}, Claims{}, fmt.Errorf("%w: session cookie: %w", ErrConfigInvalid, err)
	}
	cookie := session.Derive(flowCookieSuffix, http.SameSiteLaxMode)
	sealed := cookie.ReadCookie(r)
	cookie.ClearCookie(w, r)
	st, err := p.openFlow(sealed)
	if err != nil {
		return Flow{}, Claims{}, err
	}
	claims, err := p.complete(r.Context(), &st, cb)
	if err != nil {
		return st.flow, Claims{}, err
	}
	return st.flow, claims, nil
}

// openFlow opens the flow cookie and requires it sealed for this provider's
// issuer, client ID and redirect URL, so a provider edited mid-flight fails
// closed.
func (p *Provider) openFlow(sealed string) (flowState, error) {
	if sealed == "" {
		return flowState{}, fmt.Errorf("%w: no single flow cookie", ErrFlowInvalid)
	}
	payload, err := p.cfg.FlowSealer.Open(flowPurpose, sealed, p.cfg.Now())
	if err != nil {
		return flowState{}, fmt.Errorf("%w: %w", ErrFlowInvalid, err)
	}
	st, ok := decodeFlowState(payload)
	if !ok {
		return flowState{}, fmt.Errorf("%w: malformed flow cookie", ErrFlowInvalid)
	}
	if st.issuer != p.cfg.IssuerURL || st.clientID != p.cfg.ClientID || st.redirectURL != p.cfg.RedirectURL {
		return flowState{}, fmt.Errorf("%w: the provider changed since Begin", ErrFlowInvalid)
	}
	return st, nil
}

// complete runs Finish past the cookie: the state, then the provider's
// error, the code exchange, the token checks and, for a link or step-up,
// the auth_time freshness.
func (p *Provider) complete(ctx context.Context, st *flowState, cb Callback) (Claims, error) {
	if subtle.ConstantTimeCompare([]byte(st.state), []byte(cb.State)) != 1 {
		return Claims{}, fmt.Errorf("%w: state mismatch", ErrFlowInvalid)
	}
	if cb.Error != "" {
		return Claims{}, providerError(cb.Error)
	}
	if cb.Code == "" {
		return Claims{}, fmt.Errorf("%w: no code", ErrExchange)
	}
	oc := p.oauth2Config()
	oc.ClientSecret = p.cfg.ClientSecret.Reveal()
	tok, err := oc.Exchange(context.WithValue(ctx, oauth2.HTTPClient, p.cfg.HTTPClient), cb.Code, oauth2.VerifierOption(st.verifier))
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrExchange, err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Claims{}, fmt.Errorf("%w: no id_token in the token response", ErrTokenInvalid)
	}
	idt, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}
	claims, err := p.verifiedClaims(idt, st.nonce)
	if err != nil {
		return Claims{}, err
	}
	claims.Identity = access.OIDCIdentity{Issuer: idt.Issuer, Subject: idt.Subject}
	if st.flow.Intent != IntentSignIn && (claims.AuthTime.IsZero() || claims.AuthTime.Before(st.flow.BeganAt.Add(-authTimeSkew))) {
		return Claims{}, ErrStaleAuthentication
	}
	return claims, nil
}

// verifiedClaims checks a token go-oidc verified and decodes its claims.
func (p *Provider) verifiedClaims(idt *gooidc.IDToken, nonce string) (Claims, error) {
	var raw map[string]json.RawMessage
	if err := idt.Claims(&raw); err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}
	if err := p.checkToken(idt, raw, nonce); err != nil {
		return Claims{}, err
	}
	return decodeClaims(raw)
}

// checkToken applies the checks go-oidc leaves to its caller: every audience
// is this client and a present azp equals it whatever the audience count
// (OpenID Connect Core 1.0 section 3.1.3.7 steps 3 to 5), the nonce is the
// sealed one, and the subject is not empty.
func (p *Provider) checkToken(idt *gooidc.IDToken, raw map[string]json.RawMessage, nonce string) error {
	for _, aud := range idt.Audience {
		if aud != p.cfg.ClientID {
			return fmt.Errorf("%w: aud holds another client", ErrTokenInvalid)
		}
	}
	if azpRaw, present := raw["azp"]; present {
		var azp string
		if err := json.Unmarshal(azpRaw, &azp); err != nil || azp != p.cfg.ClientID {
			return fmt.Errorf("%w: azp is not the client ID", ErrTokenInvalid)
		}
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 {
		return ErrNonceMismatch
	}
	if idt.Subject == "" {
		return fmt.Errorf("%w: empty sub", ErrTokenInvalid)
	}
	return nil
}

// flowState is the sealed payload of the flow cookie.
type flowState struct {
	state       string
	nonce       string
	verifier    string
	issuer      string
	clientID    string
	redirectURL string
	flow        Flow
}

const flowFrameVersion = 1

// checkFlowFits refuses a cfg whose largest flow would not seal, or whose
// sealed value would not fit a flow cookie under the longest cookie name.
// Begin has no size check of its own, so a flowState field Begin fills must
// be filled at its largest here too, or Begin sets a cookie browsers drop.
func checkFlowFits(cfg *Config) error {
	now := cfg.Now()
	largest := flowState{
		state: rand.Text(), nonce: rand.Text(), verifier: oauth2.GenerateVerifier(),
		flow: Flow{
			Intent: IntentStepUp, SessionID: string(make([]byte, maxSessionIDBytes)), UserID: math.MaxInt64,
			BeganAt: now, Redirect: string(make([]byte, MaxRedirectBytes)),
		},
		issuer: cfg.IssuerURL, clientID: cfg.ClientID, redirectURL: cfg.RedirectURL,
	}
	sealed, err := cfg.FlowSealer.Seal(flowPurpose, largest.encode(), now.Add(flowLifetime))
	if err != nil {
		return fmt.Errorf("%w: the largest flow cookie: %w", ErrConfigInvalid, err)
	}
	if maxFlowCookieName+len(sealed) > maxCookieBytes {
		return fmt.Errorf("%w: the largest flow cookie's name and value pass %d bytes", ErrConfigInvalid, maxCookieBytes)
	}
	return nil
}

// encode writes the fixed binary frame: a version byte, then state, nonce,
// verifier, intent, session ID, user ID, began-at, redirect, issuer, client
// ID and redirect URL, each string as a uvarint length and its raw bytes,
// the user ID as a uvarint and began-at as 8 bytes of Unix milliseconds.
// Nothing is escaped, so the frame's size depends only on the lengths.
func (s *flowState) encode() []byte {
	b := []byte{flowFrameVersion}
	for _, v := range []string{s.state, s.nonce, s.verifier, string(s.flow.Intent), s.flow.SessionID} {
		b = appendString(b, v)
	}
	b = binary.AppendUvarint(b, uint64(s.flow.UserID)) //nolint:gosec // G115: check refuses a negative UserID before any flow is sealed
	b = binary.BigEndian.AppendUint64(b, uint64(s.flow.BeganAt.UnixMilli()))
	for _, v := range []string{s.flow.Redirect, s.issuer, s.clientID, s.redirectURL} {
		b = appendString(b, v)
	}
	return b
}

func appendString(b []byte, s string) []byte {
	return append(binary.AppendUvarint(b, uint64(len(s))), s...)
}

// decodeFlowState reverses encode, refusing a frame with another version,
// a short or overlong field, trailing bytes, or a flow BeginRequest.check
// would refuse.
func decodeFlowState(b []byte) (flowState, bool) {
	if len(b) == 0 || b[0] != flowFrameVersion {
		return flowState{}, false
	}
	r := frameReader{b: b[1:]}
	var s flowState
	s.state, s.nonce, s.verifier = r.str(), r.str(), r.str()
	s.flow.Intent, s.flow.SessionID = Intent(r.str()), r.str()
	userID, beganAt := r.uvarint(), r.fixed64()
	s.flow.Redirect, s.issuer, s.clientID, s.redirectURL = r.str(), r.str(), r.str(), r.str()
	if r.bad || len(r.b) != 0 || userID > math.MaxInt64 {
		return flowState{}, false
	}
	s.flow.UserID = int64(userID)
	s.flow.BeganAt = time.UnixMilli(int64(beganAt)) //nolint:gosec // G115: encode wrote a signed millisecond count
	req := BeginRequest{Intent: s.flow.Intent, SessionID: s.flow.SessionID, UserID: s.flow.UserID}
	if req.check() != nil {
		return flowState{}, false
	}
	return s, true
}

// frameReader reads the frame's fields; the first short field sets bad, and
// every later read returns a zero value.
type frameReader struct {
	b   []byte
	bad bool
}

func (r *frameReader) uvarint() uint64 {
	if r.bad {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.bad = true
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *frameReader) fixed64() uint64 {
	if r.bad || len(r.b) < 8 {
		r.bad = true
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

func (r *frameReader) str() string {
	n := r.uvarint()
	if r.bad || n > uint64(len(r.b)) {
		r.bad = true
		return ""
	}
	s := string(r.b[:n])
	r.b = r.b[n:]
	return s
}
