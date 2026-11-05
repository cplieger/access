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
