package discovery_test

import (
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/access/oidc/internal/discovery"
	"github.com/cplieger/access/oidc/internal/jwk"
)

// FuzzParseDocument holds Parse to its contract over any bytes (go-jose
// CVE-2026-116586, Nimbus CVE-2019-17195): it never panics, and a document
// it accepts has endpoints that meet Discovery 1.0 §3's https rule and a
// non-empty set of distinct accepted rows.
func FuzzParseDocument(f *testing.F) {
	const https, loopback = "https://idp.example", "http://127.0.0.1:8080"
	for _, issuer := range []string{https, loopback} {
		f.Add(issuer == loopback, docFor(f, issuer, nil))
		f.Add(issuer == loopback, docFor(f, issuer, map[string]any{"id_token_signing_alg_values_supported": []string{"EdDSA", "Ed25519", "HS256"}}))
		f.Add(issuer == loopback, docFor(f, issuer, nil, "id_token_signing_alg_values_supported"))
		f.Add(issuer == loopback, docFor(f, issuer, map[string]any{"jwks_uri": "http://localhost/jwks"}))
		f.Add(issuer == loopback, docFor(f, issuer, map[string]any{"token_endpoint": "http://user@127.0.0.1/t"}))
		f.Add(issuer == loopback, docFor(f, issuer, map[string]any{"authorization_endpoint": nil}))
	}
	f.Add(false, []byte(`{"issuer":"https://idp.example","issuer":"https://idp.example"}`))
	f.Add(false, []byte(`{"issuer":"https://idp.example","x":`+strings.Repeat("[", 10001)))
	f.Add(false, []byte("{\"issuer\":\"\xff\"}"))
	f.Add(false, []byte(`null`))
	f.Fuzz(func(t *testing.T, loopbackIssuer bool, data []byte) {
		issuer := https
		if loopbackIssuer {
			issuer = loopback
		}
		doc, err := discovery.Parse(issuer, data)
		if err != nil {
			return
		}
		for _, e := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI} {
			if !meetsHTTPSRule(e, loopbackIssuer) {
				t.Errorf("accepted endpoint %q under %s", e, issuer)
			}
		}
		if len(doc.Algs) == 0 {
			t.Error("accepted a document with no algorithm")
		}
		sorted := slices.Clone(doc.Algs)
		slices.Sort(sorted)
		if len(slices.Compact(sorted)) != len(doc.Algs) {
			t.Errorf("algorithms %v repeat a row", doc.Algs)
		}
		for _, a := range doc.Algs {
			if _, ok := jwk.ParseAlg(a.String()); !ok {
				t.Errorf("algorithm %d is not an accepted row", a)
			}
		}
	})
}

// meetsHTTPSRule is Discovery 1.0 §3's https URL with a host, with http
// only on localhost (RFC 6761 §6.3) or a loopback address under a loopback
// issuer.
func meetsHTTPSRule(raw string, loopbackIssuer bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	addr, err := netip.ParseAddr(u.Hostname())
	loopbackHost := strings.EqualFold(u.Hostname(), "localhost") || err == nil && addr.IsLoopback()
	return u.Scheme == "http" && loopbackIssuer && loopbackHost
}
