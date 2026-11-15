package accesstest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access/accesstest"
)

// callerClient is the client an application builds from Addr and RootCAs
// when its own outbound client, not IdP.Client, must reach the IdP: it
// dials the listener for host, a host:port, and trusts the IdP's roots.
func callerClient(t *testing.T, idp *accesstest.IdP, host string) *http.Client {
	t.Helper()
	listener := idp.Addr().String()
	var d net.Dialer
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: idp.RootCAs(), MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == host {
				addr = listener
			}
			return d.DialContext(ctx, network, addr)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, CheckRedirect: noRedirect}
}

func TestIdPCallerOwnClient(t *testing.T) {
	const issuer = "https://idp.example.com"
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{URL: issuer})
	c := callerClient(t, idp, "idp.example.com:443")

	resp, err := c.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	var doc map[string]any
	err = json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if err != nil || doc["issuer"] != issuer {
		t.Fatalf("discovery: issuer %v, err %v; want %q", doc["issuer"], err, issuer)
	}

	resp, err = c.Get(issuer + "/authorize?" + authParams(idp, nil).Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("authorize: status %d, Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	req, err := http.NewRequest(http.MethodPost, issuer+"/token", strings.NewReader(codeForm(loc.Query().Get("code")).Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(idp.ClientID(), idp.ClientSecret())
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("token: status %d, err %v", resp.StatusCode, err)
	}
	if tok, _ := body["id_token"].(string); tok == "" {
		t.Errorf("token body has no id_token: %v", body)
	}
}

// handshake runs a TLS handshake with the IdP's listener as a client asking
// for serverName and trusting roots, nil meaning the system pool.
func handshake(t *testing.T, idp *accesstest.IdP, serverName string, roots *x509.CertPool) (tls.ConnectionState, error) {
	t.Helper()
	d := tls.Dialer{Config: &tls.Config{ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(t.Context(), "tcp", idp.Addr().String())
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("tls.Dialer returned %T", conn)
	}
	return tc.ConnectionState(), nil
}

// TestIdPServesItsOwnCertificate checks IdPOptions.URL's and RootCAs'
// contract with crypto/tls's default verification (RFC 5280 section 6.1
// path validation, RFC 6125 section 6 host matching).
func TestIdPServesItsOwnCertificate(t *testing.T) {
	for _, tc := range []struct {
		name, url, host string
	}{
		{name: "google", url: googleIssuer, host: "accounts.google.com"},
		{name: "port_and_path", url: "https://idp.example.org:9443/realms/main", host: "idp.example.org"},
		{name: "two_labels_below_example_com", url: "https://a.idp.example.com", host: "a.idp.example.com"},
		{name: "single_label", url: "https://localhost:8443", host: "localhost"},
		// RFC 4343 section 3: DNS names compare case-insensitively.
		{name: "mixed_case", url: "https://Login.Example.NET", host: "login.example.net"},
		{name: "label_63_octets", url: "https://" + strings.Repeat("a", 63) + ".example.com", host: strings.Repeat("a", 63) + ".example.com"},
		{name: "name_253_characters", url: "https://" + strings.Repeat("a.", 124) + "abcde", host: strings.Repeat("a.", 124) + "abcde"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := accesstest.NewIdP(t, accesstest.IdPOptions{URL: tc.url})
			resp, err := idp.Client().Get(strings.TrimSuffix(tc.url, "/") + "/.well-known/openid-configuration")
			if err != nil {
				t.Fatalf("discovery through Client: %v", err)
			}
			var doc map[string]any
			err = json.NewDecoder(resp.Body).Decode(&doc)
			resp.Body.Close()
			if err != nil || doc["issuer"] != tc.url {
				t.Errorf("discovery issuer = %v (err %v), want %q", doc["issuer"], err, tc.url)
			}
			state, err := handshake(t, idp, tc.host, idp.RootCAs())
			if err != nil {
				t.Fatalf("handshake for %s trusting RootCAs: %v", tc.host, err)
			}
			if chains := state.VerifiedChains; len(chains) != 1 || len(chains[0]) != 2 || !chains[0][1].IsCA || chains[0][0].IsCA {
				t.Errorf("verified chains %v, want one leaf issued by a CA in RootCAs", chains)
			}
		})
	}
}

func TestIdPCertificateRefusedOutsideItsContract(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{URL: googleIssuer})
	t.Run("system_pool", func(t *testing.T) {
		var unknown x509.UnknownAuthorityError
		if _, err := handshake(t, idp, "accounts.google.com", nil); !errors.As(err, &unknown) {
			t.Errorf("handshake trusting the system pool = %v, want x509.UnknownAuthorityError", err)
		}
	})
	t.Run("other_server_name", func(t *testing.T) {
		var mismatch x509.HostnameError
		if _, err := handshake(t, idp, "accounts.google.com.example", idp.RootCAs()); !errors.As(err, &mismatch) {
			t.Errorf("handshake for another name = %v, want x509.HostnameError", err)
		}
	})
	t.Run("another_idps_roots", func(t *testing.T) {
		other := accesstest.NewIdP(t, accesstest.IdPOptions{URL: googleIssuer})
		var unknown x509.UnknownAuthorityError
		if _, err := handshake(t, idp, "accounts.google.com", other.RootCAs()); !errors.As(err, &unknown) {
			t.Errorf("handshake trusting another IdP's RootCAs = %v, want x509.UnknownAuthorityError", err)
		}
	})
}

func TestIdPTLSServesTheListenerAddress(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{TLS: true})
	if want := "https://" + idp.Addr().String(); idp.Issuer() != want {
		t.Fatalf("Issuer() = %q, want %q", idp.Issuer(), want)
	}
	resp, err := idp.Client().Get(idp.Issuer() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery through Client: %v", err)
	}
	resp.Body.Close()
	if _, err := handshake(t, idp, idp.Addr().Addr().String(), idp.RootCAs()); err != nil {
		t.Errorf("handshake for the listener's address trusting RootCAs: %v", err)
	}
	var unknown x509.UnknownAuthorityError
	if _, err := handshake(t, idp, idp.Addr().Addr().String(), nil); !errors.As(err, &unknown) {
		t.Errorf("handshake trusting the system pool = %v, want x509.UnknownAuthorityError", err)
	}
}

func TestIdPRootCAsIsFresh(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{URL: testIdPURL})
	want := idp.RootCAs().Clone()
	idp.RootCAs().AddCert(unrelatedCert(t))
	if !idp.RootCAs().Equal(want) {
		t.Error("a write to one returned pool reached the next RootCAs")
	}
	tr, ok := idp.Client().Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatalf("Client transport %T has no TLS config", idp.Client().Transport)
	}
	if !tr.TLSClientConfig.RootCAs.Equal(want) {
		t.Error("Client does not trust exactly RootCAs after a write to a returned pool")
	}
}

func TestIdPAddrPlainHTTP(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	if want := "http://" + idp.Addr().String(); idp.Issuer() != want {
		t.Errorf("Issuer() = %q, want %q", idp.Issuer(), want)
	}
	if idp.RootCAs() != nil {
		t.Error("RootCAs() is non-nil for a plain-HTTP IdP")
	}
}

// unrelatedCert is a self-signed certificate the IdP never presents.
func unrelatedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "unrelated.example"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
