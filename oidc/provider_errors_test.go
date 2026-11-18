package oidc_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/oidc"
)

// unreached fails unless err is ErrDiscovery and not ErrProviderInvalid:
// a provider that could not be reached, which a retry can fix.
func unreached(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, oidc.ErrDiscovery) || errors.Is(err, oidc.ErrProviderInvalid) || errors.Is(err, oidc.ErrConfigInvalid) {
		t.Errorf("%s: NewProvider = %v, want ErrDiscovery alone", what, err)
	}
}

// refusedProvider fails unless err is ErrProviderInvalid and not
// ErrDiscovery: the provider that answered with what access will
// not use.
func refusedProvider(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, oidc.ErrProviderInvalid) || errors.Is(err, oidc.ErrDiscovery) || errors.Is(err, oidc.ErrConfigInvalid) {
		t.Errorf("%s: NewProvider = %v, want ErrProviderInvalid alone", what, err)
	}
}

// TestNewProviderReachedOrRefused checks the split of a failed NewProvider,
// for the discovery document's arms the flow tests do not reach: a connection
// or TLS failure, a timeout or an answer other than 200
// (OpenID Connect Discovery 1.0 §4.2) is ErrDiscovery; a body that is not a
// JSON object (§4.2, RFC 8259), one with a duplicate member (RFC 8259 §4) and
// one naming another issuer (Discovery 1.0 §4.3) are ErrProviderInvalid. The
// app's own configuration stays ErrConfigInvalid, matching neither.
func TestNewProviderReachedOrRefused(t *testing.T) {
	t.Parallel()
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	var doc map[string]any
	resp, err := idp.Client().Get(idp.Issuer() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("fetch the IdP's discovery: %v", err)
	}
	err = json.NewDecoder(resp.Body).Decode(&doc)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("decode the IdP's discovery: %v", err)
	}
	// front serves body at the well-known URL, with %ISSUER% replaced by
	// its own URL, after waiting for the request's end when hang is set.
	front := func(t *testing.T, status int, body []byte, hang bool) oidc.Config {
		t.Helper()
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hang {
				<-r.Context().Done()
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(bytes.ReplaceAll(body, []byte("%ISSUER%"), []byte(srv.URL)))
		}))
		t.Cleanup(srv.Close)
		cfg := configFor(idp)
		cfg.IssuerURL = srv.URL
		return cfg
	}
	document := func(t *testing.T, issuer string) []byte {
		t.Helper()
		m := maps.Clone(doc)
		m["issuer"] = issuer
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Run("connection_refused", func(t *testing.T) {
		t.Parallel()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		_ = l.Close()
		cfg := configFor(idp)
		cfg.IssuerURL = "http://" + addr
		_, err = oidc.NewProvider(t.Context(), cfg)
		unreached(t, "a closed port", err)
	})
	t.Run("tls_failure", func(t *testing.T) {
		t.Parallel()
		_, err := oidc.NewProvider(t.Context(), configFor(accesstest.NewIdP(t, accesstest.IdPOptions{TLS: true})))
		unreached(t, "an https IdP whose certificate the client does not trust", err)
	})
	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		cfg := front(t, http.StatusOK, nil, true)
		cfg.HTTPClient = &http.Client{Timeout: 200 * time.Millisecond}
		_, err := oidc.NewProvider(t.Context(), cfg)
		unreached(t, "a discovery that never answers", err)
	})
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			_, err := oidc.NewProvider(t.Context(), front(t, status, document(t, "%ISSUER%"), false))
			unreached(t, "a discovery answering "+http.StatusText(status), err)
		})
	}
	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		if _, err := oidc.NewProvider(t.Context(), front(t, http.StatusOK, document(t, "%ISSUER%"), false)); err != nil {
			t.Errorf("the IdP's own document from the front: NewProvider = %v, want nil", err)
		}
	})
	for name, body := range map[string][]byte{
		"array":            []byte(`[]`),
		"string":           []byte(`"x"`),
		"html":             []byte(`<html></html>`),
		"empty":            nil,
		"duplicate_member": append([]byte(`{"issuer":"%ISSUER%",`), document(t, "%ISSUER%")[1:]...),
		"another_issuer":   document(t, "https://other.example"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := oidc.NewProvider(t.Context(), front(t, http.StatusOK, body, false))
			refusedProvider(t, "a "+name+" document", err)
		})
	}
	t.Run("config_invalid", func(t *testing.T) {
		t.Parallel()
		cfg := configFor(idp)
		cfg.ClientID = ""
		_, err := oidc.NewProvider(t.Context(), cfg)
		if !errors.Is(err, oidc.ErrConfigInvalid) || errors.Is(err, oidc.ErrDiscovery) || errors.Is(err, oidc.ErrProviderInvalid) {
			t.Errorf("no client ID: NewProvider = %v, want ErrConfigInvalid alone", err)
		}
	})
}
