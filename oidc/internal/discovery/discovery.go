// Package discovery fetches and checks an OpenID Connect provider's
// discovery document (OpenID Connect Discovery 1.0).
package discovery

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/cplieger/access/oidc/internal/jsonmember"
	"github.com/cplieger/access/oidc/internal/jwk"
)

var (
	// ErrFetch is the error Fetch and NewKeySet wrap when the provider could
	// not be reached: a transport error, a redirect, an answer other than
	// 200 or a body read error other than the body cap.
	ErrFetch = errors.New("discovery: fetch failed")
	// ErrDocument is the error Parse and Fetch wrap when they refuse a
	// document, one past the body cap included.
	ErrDocument = errors.New("discovery: document refused")
)

// Document is the part of a provider's discovery document oidc uses.
type Document struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	// Algs is the provider's set of accepted rows, distinct and never empty.
	Algs []jwk.Alg
}

// Fetch GETs issuer's document from the issuer less one terminating "/"
// followed by /.well-known/openid-configuration (Discovery 1.0 §4.1), with
// ctx, through a copy of client that follows no redirect, and parses it.
func Fetch(ctx context.Context, client *http.Client, issuer string) (Document, error) {
	body, err := get(ctx, client, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return Document{}, refusedPastCap(ErrDocument, err)
	}
	return Parse(issuer, body)
}

// Parse checks a document fetched for issuer, which must already pass oidc's
// Config.Validate: its issuer is identical to issuer (Discovery 1.0 §4.3),
// its endpoints meet the https rule, and its
// id_token_signing_alg_values_supported, RS256 when absent, shares a row with
// package jwk's table. Every refusal wraps ErrDocument and names the field,
// never its value.
func Parse(issuer string, data []byte) (Document, error) {
	m, err := jsonmember.Object(data)
	if err != nil {
		return Document{}, fmt.Errorf("%w: %w", ErrDocument, err)
	}
	if got, ok := jsonmember.String(m["issuer"]); !ok || got != issuer {
		return Document{}, fmt.Errorf("%w: issuer is not the configured issuer", ErrDocument)
	}
	loopbackIssuer := loopbackHTTP(issuer)
	var d Document
	for _, e := range [...]struct {
		dst  *string
		name string
	}{
		{&d.AuthorizationEndpoint, "authorization_endpoint"},
		{&d.TokenEndpoint, "token_endpoint"},
		{&d.JWKSURI, "jwks_uri"},
	} {
		raw, ok := jsonmember.String(m[e.name])
		if !ok || !endpointAllowed(raw, loopbackIssuer) {
			return Document{}, fmt.Errorf("%w: %s must be an absolute https URL with a host and no userinfo", ErrDocument, e.name)
		}
		*e.dst = raw
	}
	if d.Algs, err = algs(m); err != nil {
		return Document{}, fmt.Errorf("%w: id_token_signing_alg_values_supported %w", ErrDocument, err)
	}
	return d, nil
}

// algs is the provider's set of rows. Discovery 1.0 §3 requires the list;
// when it is absent, OIDC Core 1.0 §3.1.3.7 step 7's default, RS256, stands
// for it.
func algs(m map[string]jsontext.Value) ([]jwk.Alg, error) {
	v, found := m["id_token_signing_alg_values_supported"]
	if !found {
		return []jwk.Alg{jwk.RS256}, nil
	}
	names, ok := jsonmember.Strings(v)
	if !ok {
		return nil, errors.New("is not an array of strings")
	}
	var set []jwk.Alg
	for _, name := range names {
		if a, ok := jwk.ParseAlg(name); ok && !slices.Contains(set, a) {
			set = append(set, a)
		}
	}
	if len(set) == 0 {
		return nil, errors.New("names no accepted algorithm")
	}
	return set, nil
}

// endpointAllowed is the https rule. url.Parse reports "https:///token"
// and the opaque "https:idp.example/token" as https URLs with no host,
// hence the Host check; userinfo is refused before the loopback rule
// (Authlib CVE-2026-114614).
func endpointAllowed(raw string, loopbackIssuer bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http" && loopbackIssuer && LoopbackHost(u.Hostname())
}

func loopbackHTTP(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "http" && LoopbackHost(u.Hostname())
}

// LoopbackHost reports whether host, as url.URL.Hostname returns it, is
// localhost in any case or a loopback IP literal: the only hosts where http
// stands in for https.
func LoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
