package accesstest_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/oidc"
)

const (
	testRedirectURI = "https://app.example/callback"
	// testIdPURL carries a port so a test that passes proves IdP.Client
	// routes URL's own port, not 443, to the listener.
	testIdPURL = "https://idp.example.com:8443"
	// googleIssuer is Google's issuer, from Google Identity's "Validating
	// an ID token" (https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken).
	googleIssuer = "https://accounts.google.com"
)

var idpT0 = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// testClock is an IdP clock a test moves; the IdP reads it from its
// handler goroutines.
type testClock struct{ ns atomic.Int64 }

func newTestClock(t0 time.Time) *testClock {
	c := &testClock{}
	c.ns.Store(t0.UnixNano())
	return c
}

func (c *testClock) now() time.Time                   { return time.Unix(0, c.ns.Load()).UTC() }
func (c *testClock) advance(d time.Duration)          { c.ns.Add(int64(d)) }
func fixedClock(t time.Time) func() time.Time         { return func() time.Time { return t } }
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func authParams(idp *accesstest.IdP, set url.Values, drop ...string) url.Values {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {idp.ClientID()},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid email"},
		"state":         {"state-1"},
	}
	maps.Copy(q, set)
	for _, k := range drop {
		q.Del(k)
	}
	return q
}

func authorize(t *testing.T, idp *accesstest.IdP, set url.Values) url.Values {
	t.Helper()
	return authorizeRaw(t, idp, authParams(idp, set))
}

func authorizeRaw(t *testing.T, idp *accesstest.IdP, q url.Values) url.Values {
	t.Helper()
	status, location := getNoRedirect(t, idp, idp.Issuer()+"/authorize?"+q.Encode())
	if status != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", status)
	}
	loc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("authorize Location: %v", err)
	}
	return loc.Query()
}

func getNoRedirect(t *testing.T, idp *accesstest.IdP, u string) (status int, location string) {
	t.Helper()
	c := *idp.Client()
	c.CheckRedirect = noRedirect
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

func exchange(t *testing.T, idp *accesstest.IdP, form url.Values) (int, map[string]any) {
	t.Helper()
	return postToken(t, idp, form, &basicAuth{idp.ClientID(), idp.ClientSecret()})
}

type basicAuth struct{ id, secret string }

// postToken sends no Authorization header when basic is nil.
func postToken(t *testing.T, idp *accesstest.IdP, form url.Values, basic *basicAuth) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, idp.Issuer()+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic != nil {
		req.SetBasicAuth(url.QueryEscape(basic.id), url.QueryEscape(basic.secret))
	}
	resp, err := idp.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("token body: %v", err)
	}
	return resp.StatusCode, body
}

func codeForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}}
}

func issue(t *testing.T, idp *accesstest.IdP, set url.Values) string {
	t.Helper()
	q := url.Values{"nonce": {"nonce-1"}}
	maps.Copy(q, set)
	cb := authorize(t, idp, q)
	status, body := exchange(t, idp, codeForm(cb.Get("code")))
	if status != http.StatusOK {
		t.Fatalf("token status = %d, body %v", status, body)
	}
	raw, ok := body["id_token"].(string)
	if !ok {
		t.Fatalf("token body has no id_token: %v", body)
	}
	return raw
}

// decodeJWS splits a compact JWS and decodes its header and claims, keeping
// numbers as json.Number.
func decodeJWS(t *testing.T, raw string) (header, claims map[string]any, input string, sig []byte) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("JWS has %d parts, want 3", len(parts))
	}
	header, claims = decodeSegment(t, parts[0]), decodeSegment(t, parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("JWS signature: %v", err)
	}
	return header, claims, parts[0] + "." + parts[1], sig
}

func decodeSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("JWS segment: %v", err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		t.Fatalf("JWS segment JSON: %v", err)
	}
	return m
}

func unix(t *testing.T, v any) int64 {
	t.Helper()
	n, ok := v.(json.Number)
	if !ok {
		t.Fatalf("claim %v is %T, want a number", v, v)
	}
	i, err := n.Int64()
	if err != nil {
		t.Fatal(err)
	}
	return i
}

// signInAtProvider runs one sign-in through an oidc.Provider configured
// for idp: Begin, the IdP's authorize, Finish.
func signInAtProvider(t *testing.T, idp *accesstest.IdP) (claims oidc.Claims, callback *url.URL, err error) {
	t.Helper()
	p, err := oidc.NewProvider(t.Context(), oidc.Config{
		IssuerURL: idp.Issuer(), ClientID: idp.ClientID(), ClientSecret: access.NewSecret(idp.ClientSecret()),
		RedirectURL: testRedirectURI, HTTPClient: idp.Client(),
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	session := access.DefaultCookieConfig()
	began := httptest.NewRecorder()
	authURL, err := p.Begin(began, httptest.NewRequest(http.MethodPost, "https://app.example/auth/start", nil), session, oidc.BeginRequest{Intent: oidc.IntentSignIn, Redirect: "/"})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	_, location := getNoRedirect(t, idp, authURL)
	callback, err = url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, callback.String(), nil)
	for _, c := range began.Result().Cookies() {
		r.AddCookie(c)
	}
	q := callback.Query()
	_, claims, err = p.Finish(httptest.NewRecorder(), r, session, oidc.Callback{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error")})
	return claims, callback, err
}

// TestIdPSignInVerifiesAtProvider: each signing option yields a code flow a
// relying party completes (OpenID Connect Core 1.0 §3.1.3.7), with the
// issuer in the callback (RFC 9207 §2) and the IdP's default claims.
func TestIdPSignInVerifiesAtProvider(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts accesstest.IdPOptions
	}{
		{"default_rs256", accesstest.IdPOptions{}},
		{"es256", accesstest.IdPOptions{Algorithm: accesstest.AlgES256}},
		{"tls", accesstest.IdPOptions{TLS: true}},
		{"url", accesstest.IdPOptions{URL: testIdPURL}},
		{"url_with_path", accesstest.IdPOptions{URL: testIdPURL + "/realms/main"}},
		{"url_with_final_slash", accesstest.IdPOptions{URL: testIdPURL + "/app/"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := accesstest.NewIdP(t, tc.opts)
			claims, cb, err := signInAtProvider(t, idp)
			if err != nil {
				t.Fatalf("Finish: %v", err)
			}
			if got := cb.Scheme + "://" + cb.Host + cb.Path; got != testRedirectURI {
				t.Errorf("redirect target = %q, want %q", got, testRedirectURI)
			}
			if got := cb.Query().Get("iss"); got != idp.Issuer() {
				t.Errorf("callback iss = %q, want %q", got, idp.Issuer())
			}
			if want := (access.OIDCIdentity{Issuer: idp.Issuer(), Subject: accesstest.DefaultIdPSubject}); claims.Identity != want {
				t.Errorf("Identity = %+v, want %+v", claims.Identity, want)
			}
			if claims.Email != accesstest.DefaultIdPEmail || claims.PreferredUsername != accesstest.DefaultIdPUsername || !claims.EmailVerified || claims.AuthTime.IsZero() {
				t.Errorf("claims = email %q, username %q, verified %v, auth_time %v", claims.Email, claims.PreferredUsername, claims.EmailVerified, claims.AuthTime)
			}
			auths := idp.Authorizations()
			if len(auths) != 1 || auths[0].Get("nonce") == "" || auths[0].Get("code_challenge_method") != "S256" {
				t.Fatalf("Authorizations() = %v, want one request with a nonce and an S256 challenge", auths)
			}
			nonce := auths[0].Get("nonce")
			auths[0].Set("nonce", "mutated")
			if idp.Authorizations()[0].Get("nonce") != nonce {
				t.Error("mutating Authorizations' result changed the record")
			}
		})
	}
}

func TestIdPsShareSigningKeys(t *testing.T) {
	jwks := func(idp *accesstest.IdP) string {
		resp, err := idp.Client().Get(idp.Issuer() + "/jwks")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	a, b := accesstest.NewIdP(t, accesstest.IdPOptions{}), accesstest.NewIdP(t, accesstest.IdPOptions{URL: testIdPURL})
	if ja, jb := jwks(a), jwks(b); ja != jb {
		t.Errorf("two IdPs serve different key sets:\n%s\n%s", ja, jb)
	}
}

// TestIdPRefusedAlgorithmsFailAtProvider: a token under alg none or HS256
// fails at a relying party (RFC 8725 §2.1, §3.1), so these options exercise
// its refusals.
func TestIdPRefusedAlgorithmsFailAtProvider(t *testing.T) {
	for _, alg := range []string{accesstest.AlgNone, accesstest.AlgHS256} {
		t.Run(alg, func(t *testing.T) {
			idp := accesstest.NewIdP(t, accesstest.IdPOptions{Algorithm: alg})
			claims, _, err := signInAtProvider(t, idp)
			if !errors.Is(err, oidc.ErrTokenInvalid) {
				t.Errorf("Finish under an %s IdP = %v, want ErrTokenInvalid", alg, err)
			}
			if !claims.Identity.IsZero() {
				t.Errorf("Identity = %+v on a refusal, want zero", claims.Identity)
			}
		})
	}
}

func TestIdPClaimKnobs(t *testing.T) {
	empty, wrong, username := "", "wrong-nonce", "other-user"
	cases := []struct {
		check func(t *testing.T, idp *accesstest.IdP, header, claims map[string]any, input string, sig []byte)
		name  string
		opts  accesstest.IdPOptions
	}{
		{name: "default", check: func(t *testing.T, idp *accesstest.IdP, h, c map[string]any, _ string, _ []byte) {
			if h["alg"] != accesstest.AlgRS256 || h["typ"] != "JWT" || h["kid"] == nil {
				t.Errorf("header = %v", h)
			}
			if c["iss"] != idp.Issuer() || c["aud"] != idp.ClientID() || c["nonce"] != "nonce-1" || c["sub"] != accesstest.DefaultIdPSubject {
				t.Errorf("claims = %v", c)
			}
			if c["email_verified"] != true || c["azp"] != nil || c["groups"] != nil {
				t.Errorf("claims = %v", c)
			}
			if unix(t, c["iat"]) != idpT0.Unix() || unix(t, c["exp"]) != idpT0.Add(5*time.Minute).Unix() || unix(t, c["auth_time"]) != idpT0.Unix() {
				t.Errorf("times = iat %v exp %v auth_time %v", c["iat"], c["exp"], c["auth_time"])
			}
		}},
		{name: "nonce_wrong", opts: accesstest.IdPOptions{Nonce: &wrong}, check: claimIs("nonce", "wrong-nonce")},
		{name: "nonce_empty", opts: accesstest.IdPOptions{Nonce: &empty}, check: claimIs("nonce", "")},
		{name: "aud_one", opts: accesstest.IdPOptions{Audience: []string{"other-client"}}, check: claimIs("aud", "other-client")},
		{name: "aud_many", opts: accesstest.IdPOptions{Audience: []string{accesstest.DefaultIdPClientID, "foreign"}}, check: func(t *testing.T, _ *accesstest.IdP, _, c map[string]any, _ string, _ []byte) {
			aud, ok := c["aud"].([]any)
			if !ok || len(aud) != 2 || aud[0] != accesstest.DefaultIdPClientID || aud[1] != "foreign" {
				t.Errorf("aud = %v", c["aud"])
			}
		}},
		{name: "azp", opts: accesstest.IdPOptions{AuthorizedParty: "other-party"}, check: claimIs("azp", "other-party")},
		{name: "exp", opts: accesstest.IdPOptions{Lifetime: -time.Minute}, check: func(t *testing.T, _ *accesstest.IdP, _, c map[string]any, _ string, _ []byte) {
			if got := unix(t, c["exp"]); got != idpT0.Add(-time.Minute).Unix() {
				t.Errorf("exp = %d", got)
			}
		}},
		{name: "sub_empty", opts: accesstest.IdPOptions{Subject: &empty}, check: claimIs("sub", "")},
		{name: "issuer_claim", opts: accesstest.IdPOptions{IssuerClaim: "accounts.google.com"}, check: claimIs("iss", "accounts.google.com")},
		{name: "preferred_username", opts: accesstest.IdPOptions{PreferredUsername: &username}, check: claimIs("preferred_username", "other-user")},
		{name: "preferred_username_empty", opts: accesstest.IdPOptions{PreferredUsername: &empty}, check: claimIs("preferred_username", "")},
		{name: "email_verified_string", opts: accesstest.IdPOptions{EmailVerified: "true"}, check: claimIs("email_verified", "true")},
		{name: "auth_time_absent", opts: accesstest.IdPOptions{OmitAuthTime: true}, check: func(t *testing.T, _ *accesstest.IdP, _, c map[string]any, _ string, _ []byte) {
			if _, ok := c["auth_time"]; ok {
				t.Errorf("auth_time = %v, want absent", c["auth_time"])
			}
		}},
		{name: "auth_time_early", opts: accesstest.IdPOptions{AuthTimeOffset: -2 * time.Minute}, check: authTimeIs(idpT0.Add(-2 * time.Minute))},
		{name: "auth_time_inside_skew", opts: accesstest.IdPOptions{AuthTimeOffset: -30 * time.Second}, check: authTimeIs(idpT0.Add(-30 * time.Second))},
		{name: "groups_string", opts: accesstest.IdPOptions{Groups: "admins"}, check: claimIs("groups", "admins")},
		{name: "groups_array", opts: accesstest.IdPOptions{Groups: []string{"admins", "users"}}, check: func(t *testing.T, _ *accesstest.IdP, _, c map[string]any, _ string, _ []byte) {
			g, ok := c["groups"].([]any)
			if !ok || len(g) != 2 || g[0] != "admins" || g[1] != "users" {
				t.Errorf("groups = %v", c["groups"])
			}
		}},
		{name: "alg_es256", opts: accesstest.IdPOptions{Algorithm: accesstest.AlgES256}, check: func(t *testing.T, _ *accesstest.IdP, h, _ map[string]any, _ string, sig []byte) {
			if h["alg"] != accesstest.AlgES256 || len(sig) != 64 {
				t.Errorf("header = %v, signature %d bytes", h, len(sig))
			}
		}},
		{name: "alg_none", opts: accesstest.IdPOptions{Algorithm: accesstest.AlgNone}, check: func(t *testing.T, _ *accesstest.IdP, h, _ map[string]any, _ string, sig []byte) {
			if h["alg"] != accesstest.AlgNone || h["kid"] != nil || len(sig) != 0 {
				t.Errorf("header = %v, signature %d bytes", h, len(sig))
			}
		}},
		{name: "alg_hs256_keyed_by_client_secret", opts: accesstest.IdPOptions{Algorithm: accesstest.AlgHS256, ClientSecret: "s2"}, check: func(t *testing.T, _ *accesstest.IdP, h, _ map[string]any, input string, sig []byte) {
			mac := hmac.New(sha256.New, []byte("s2"))
			mac.Write([]byte(input))
			if h["alg"] != accesstest.AlgHS256 || !hmac.Equal(sig, mac.Sum(nil)) {
				t.Errorf("header = %v, signature not HMAC-SHA256 under the client secret", h)
			}
		}},
		{name: "client_id_is_aud", opts: accesstest.IdPOptions{ClientID: "c2", ClientSecret: "s2"}, check: claimIs("aud", "c2")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Now = fixedClock(idpT0)
			idp := accesstest.NewIdP(t, tc.opts)
			h, c, input, sig := decodeJWS(t, issue(t, idp, nil))
			tc.check(t, idp, h, c, input, sig)
		})
	}
}

func claimIs(name string, want any) func(*testing.T, *accesstest.IdP, map[string]any, map[string]any, string, []byte) {
	return func(t *testing.T, _ *accesstest.IdP, _, c map[string]any, _ string, _ []byte) {
		t.Helper()
		if got, ok := c[name]; !ok || got != want {
			t.Errorf("%s = %#v (present %v), want %#v", name, got, ok, want)
		}
	}
}

func authTimeIs(want time.Time) func(*testing.T, *accesstest.IdP, map[string]any, map[string]any, string, []byte) {
	return func(t *testing.T, _ *accesstest.IdP, _, c map[string]any, _ string, _ []byte) {
		t.Helper()
		if got := unix(t, c["auth_time"]); got != want.Unix() {
			t.Errorf("auth_time = %d, want %d", got, want.Unix())
		}
	}
}

func TestIdPEndpointBodyBytes(t *testing.T) {
	const size = 2 << 20
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{
		Discovery: accesstest.IdPEndpoint{BodyBytes: size},
		JWKS:      accesstest.IdPEndpoint{BodyBytes: size},
		Token:     accesstest.IdPEndpoint{BodyBytes: size},
	})
	read := func(t *testing.T, resp *http.Response) []byte {
		t.Helper()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != size || !json.Valid(b) {
			t.Errorf("body is %d bytes (valid JSON %v), want %d", len(b), json.Valid(b), size)
		}
		return b
	}
	for _, path := range []string{"/.well-known/openid-configuration", "/jwks"} {
		t.Run(strings.Trim(path, "/."), func(t *testing.T) {
			resp, err := idp.Client().Get(idp.Issuer() + path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			read(t, resp)
		})
	}
	t.Run("token", func(t *testing.T) {
		form := codeForm(authorize(t, idp, nil).Get("code"))
		form.Set("client_id", idp.ClientID())
		form.Set("client_secret", idp.ClientSecret())
		resp, err := idp.Client().PostForm(idp.Issuer()+"/token", form)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		if err := json.Unmarshal(read(t, resp), &body); err != nil || body["id_token"] == nil {
			t.Errorf("padded token body = %v, %v", body, err)
		}
	})
}

func TestIdPEndpointStreamed(t *testing.T) {
	const size = 2 << 20
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{
		Discovery: accesstest.IdPEndpoint{BodyBytes: size, Streamed: true},
		JWKS:      accesstest.IdPEndpoint{Streamed: true},
		Token:     accesstest.IdPEndpoint{BodyBytes: size, Streamed: true},
	})
	declared := accesstest.NewIdP(t, accesstest.IdPOptions{JWKS: accesstest.IdPEndpoint{BodyBytes: size}})
	check := func(t *testing.T, do func() (*http.Response, error), wantLen int64, wantSize int) {
		t.Helper()
		resp, err := do()
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.ContentLength != wantLen {
			t.Errorf("ContentLength = %d, want %d", resp.ContentLength, wantLen)
		}
		if wantLen < 0 && !slices.Equal(resp.TransferEncoding, []string{"chunked"}) {
			t.Errorf("TransferEncoding = %q, want chunked", resp.TransferEncoding)
		}
		if wantSize > 0 && len(b) != wantSize || !json.Valid(b) {
			t.Errorf("body is %d bytes (valid JSON %v), want %d", len(b), json.Valid(b), wantSize)
		}
	}
	t.Run("discovery", func(t *testing.T) {
		check(t, func() (*http.Response, error) {
			return idp.Client().Get(idp.Issuer() + "/.well-known/openid-configuration")
		}, -1, size)
	})
	t.Run("jwks_small_body", func(t *testing.T) {
		check(t, func() (*http.Response, error) { return idp.Client().Get(idp.Issuer() + "/jwks") }, -1, 0)
	})
	t.Run("token", func(t *testing.T) {
		form := codeForm(authorize(t, idp, nil).Get("code"))
		form.Set("client_id", idp.ClientID())
		form.Set("client_secret", idp.ClientSecret())
		check(t, func() (*http.Response, error) { return idp.Client().PostForm(idp.Issuer()+"/token", form) }, -1, size)
	})
	t.Run("default_declares_length", func(t *testing.T) {
		check(t, func() (*http.Response, error) { return declared.Client().Get(declared.Issuer() + "/jwks") }, size, size)
	})
}

func TestIdPEndpointDelay(t *testing.T) {
	t.Run("delay_waits", func(t *testing.T) {
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{Discovery: accesstest.IdPEndpoint{Delay: 50 * time.Millisecond}})
		start := time.Now()
		resp, err := idp.Client().Get(idp.Issuer() + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if elapsed := time.Since(start); elapsed < 50*time.Millisecond || resp.StatusCode != http.StatusOK {
			t.Errorf("status %d after %v, want 200 after at least 50ms", resp.StatusCode, elapsed)
		}
	})
	for _, ep := range []struct {
		opts accesstest.IdPOptions
		name string
		path string
	}{
		{name: "jwks_hung", path: "/jwks", opts: accesstest.IdPOptions{JWKS: accesstest.IdPEndpoint{Delay: time.Hour}}},
		{name: "discovery_hung", path: "/.well-known/openid-configuration", opts: accesstest.IdPOptions{Discovery: accesstest.IdPEndpoint{Delay: time.Hour}}},
	} {
		t.Run(ep.name, func(t *testing.T) {
			idp := accesstest.NewIdP(t, ep.opts)
			c := *idp.Client()
			c.Timeout = 100 * time.Millisecond
			resp, err := c.Get(idp.Issuer() + ep.path)
			if err == nil {
				defer resp.Body.Close()
				t.Fatal("a hung endpoint answered")
			}
			var ne interface{ Timeout() bool }
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Errorf("error = %v, want a client timeout", err)
			}
		})
	}
	t.Run("token_hung_cleanup_does_not_block", func(t *testing.T) {
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{Token: accesstest.IdPEndpoint{Delay: time.Hour}})
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		form := codeForm(authorize(t, idp, nil).Get("code"))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, idp.Issuer()+"/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := idp.Client().Do(req)
		if err == nil {
			defer resp.Body.Close()
			t.Fatal("a hung endpoint answered")
		}
	})
}

func TestIdPDiscoveryOverrides(t *testing.T) {
	read := func(t *testing.T, idp *accesstest.IdP) map[string]any {
		t.Helper()
		resp, err := idp.Client().Get(idp.Issuer() + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var doc map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	t.Run("default", func(t *testing.T) {
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
		doc := read(t, idp)
		for k, want := range map[string]string{"issuer": "", "authorization_endpoint": "/authorize", "token_endpoint": "/token", "jwks_uri": "/jwks"} {
			if doc[k] != idp.Issuer()+want {
				t.Errorf("%s = %v", k, doc[k])
			}
		}
	})
	t.Run("overridden", func(t *testing.T) {
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{
			AuthorizationEndpoint: "http://idp.example/authorize",
			TokenEndpoint:         "/token",
			JWKSURI:               "https://u:p@idp.example/jwks",
		})
		doc := read(t, idp)
		if doc["authorization_endpoint"] != "http://idp.example/authorize" || doc["token_endpoint"] != "/token" || doc["jwks_uri"] != "https://u:p@idp.example/jwks" {
			t.Errorf("discovery = %v", doc)
		}
		if doc["issuer"] != idp.Issuer() {
			t.Errorf("issuer = %v, want the IdP's URL whatever the endpoints", doc["issuer"])
		}
	})
}

func TestIdPAuthorizationsRecordsEveryRequest(t *testing.T) {
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	getNoRedirect(t, idp, idp.Issuer()+"/authorize?"+authParams(idp, url.Values{"client_id": {"other"}}).Encode())
	authorize(t, idp, url.Values{"response_type": {"token"}})
	authorize(t, idp, nil)
	got := idp.Authorizations()
	if len(got) != 3 || got[0].Get("client_id") != "other" || got[1].Get("response_type") != "token" || got[2].Get("response_type") != "code" {
		t.Errorf("Authorizations() = %v, want the three requests in order, refused ones included", got)
	}
}

func TestNewIdPCopiesOptions(t *testing.T) {
	nonce, sub := "nonce-before", "sub-before"
	aud, groups, verified := []string{"aud-before"}, []string{"group-before"}, []string{"verified-before"}
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{Nonce: &nonce, Subject: &sub, Audience: aud, Groups: groups, EmailVerified: verified})
	nonce, sub = "after", "after"
	aud[0], groups[0], verified[0] = "after", "after", "after"
	_, c, _, _ := decodeJWS(t, issue(t, idp, nil))
	for name, want := range map[string]string{"nonce": "nonce-before", "sub": "sub-before", "aud": "aud-before"} {
		if c[name] != want {
			t.Errorf("%s = %v, want %q", name, c[name], want)
		}
	}
	for name, want := range map[string]string{"groups": "group-before", "email_verified": "verified-before"} {
		if got, ok := c[name].([]any); !ok || len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want [%q]", name, c[name], want)
		}
	}
}

// fatalRecorder stands in for a test so NewIdP's refusal can be observed:
// Fatalf records the message and ends the goroutine, as testing's does.
type fatalRecorder struct {
	testing.TB
	msg string
}

func (*fatalRecorder) Helper() {}

func (f *fatalRecorder) Fatalf(format string, args ...any) {
	f.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func TestNewIdPRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
		opts accesstest.IdPOptions
	}{
		{name: "unknown_algorithm", opts: accesstest.IdPOptions{Algorithm: "RS512"}, want: `unknown IdP algorithm "RS512"`},
		{name: "groups_not_json", opts: accesstest.IdPOptions{Groups: make(chan int)}, want: "IdP claim groups"},
		{name: "email_verified_not_json", opts: accesstest.IdPOptions{EmailVerified: func() {}}, want: "IdP claim email_verified"},
		{name: "url_http", opts: accesstest.IdPOptions{URL: "http://idp.example.com:8443"}, want: "is not an https URL with a host"},
		{name: "url_relative", opts: accesstest.IdPOptions{URL: "idp.example.com"}, want: "is not an https URL with a host"},
		{name: "url_opaque", opts: accesstest.IdPOptions{URL: "https:idp.example.com"}, want: "is not an https URL with a host"},
		{name: "url_empty_port", opts: accesstest.IdPOptions{URL: "https://idp.example.com:"}, want: "is not an https URL with a host"},
		{name: "url_query", opts: accesstest.IdPOptions{URL: testIdPURL + "?a=1"}, want: "userinfo, a query or a fragment"},
		{name: "url_empty_query", opts: accesstest.IdPOptions{URL: testIdPURL + "?"}, want: "userinfo, a query or a fragment"},
		{name: "url_fragment", opts: accesstest.IdPOptions{URL: testIdPURL + "#f"}, want: "userinfo, a query or a fragment"},
		{name: "url_empty_fragment", opts: accesstest.IdPOptions{URL: testIdPURL + "#"}, want: "userinfo, a query or a fragment"},
		{name: "url_userinfo", opts: accesstest.IdPOptions{URL: "https://u:p@idp.example.com"}, want: "userinfo, a query or a fragment"},
		{name: "url_loopback_v4", opts: accesstest.IdPOptions{URL: "https://127.0.0.1:8443"}, want: "not a DNS name"},
		{name: "url_loopback_v6", opts: accesstest.IdPOptions{URL: "https://[::1]:8443"}, want: "not a DNS name"},
		{name: "url_ip_v4", opts: accesstest.IdPOptions{URL: "https://203.0.113.1"}, want: "not a DNS name"},
		{name: "url_ip_v6", opts: accesstest.IdPOptions{URL: "https://[::1]"}, want: "not a DNS name"},
		// RFC 1123 section 2.1 and RFC 1035 section 2.3.1: letters, digits
		// and inner hyphens, labels of 1 to 63 octets.
		{name: "url_label_leading_hyphen", opts: accesstest.IdPOptions{URL: "https://-idp.example.com"}, want: "not a DNS name"},
		{name: "url_label_trailing_hyphen", opts: accesstest.IdPOptions{URL: "https://idp-.example.com"}, want: "not a DNS name"},
		{name: "url_label_empty", opts: accesstest.IdPOptions{URL: "https://idp..example.com"}, want: "not a DNS name"},
		{name: "url_final_dot", opts: accesstest.IdPOptions{URL: "https://idp.example.com."}, want: "not a DNS name"},
		{name: "url_label_64_octets", opts: accesstest.IdPOptions{URL: "https://" + strings.Repeat("a", 64) + ".example.com"}, want: "not a DNS name"},
		{name: "url_underscore", opts: accesstest.IdPOptions{URL: "https://i_p.example.com"}, want: "not a DNS name"},
		{name: "url_non_ascii", opts: accesstest.IdPOptions{URL: "https://idp.exämple.com"}, want: "not a DNS name"},
		// RFC 1035 section 2.3.4: a name is at most 255 octets on the wire,
		// 253 characters as text.
		{name: "url_name_254_characters", opts: accesstest.IdPOptions{URL: "https://" + strings.Repeat("a.", 125) + "abcd"}, want: "not a DNS name"},
		// RFC 3696 section 2: an all-numeric top-level label reads as an
		// IPv4 address to some resolvers.
		{name: "url_numeric_top_label", opts: accesstest.IdPOptions{URL: "https://idp.123"}, want: "not a DNS name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &fatalRecorder{TB: t}
			done := make(chan *accesstest.IdP)
			go func() {
				var idp *accesstest.IdP
				defer func() { done <- idp }()
				idp = accesstest.NewIdP(rec, tc.opts)
			}()
			if idp := <-done; idp != nil || !strings.Contains(rec.msg, tc.want) {
				t.Errorf("NewIdP returned %v, recorded %q; want a fatal refusal naming %q", idp, rec.msg, tc.want)
			}
		})
	}
}

func TestIdPRotateKey(t *testing.T) {
	kids := func(t *testing.T, idp *accesstest.IdP) []string {
		t.Helper()
		keys := servedKeys(t, idp)
		out := make([]string, 0, len(keys))
		for _, k := range keys {
			out = append(out, k.Kid)
		}
		return out
	}
	kid := func(t *testing.T, raw string) string {
		t.Helper()
		header, _, _, _ := decodeJWS(t, raw)
		s, _ := header["kid"].(string)
		return s
	}
	for _, alg := range []string{accesstest.AlgRS256, accesstest.AlgES256} {
		t.Run(alg, func(t *testing.T) {
			idp := accesstest.NewIdP(t, accesstest.IdPOptions{Algorithm: alg})
			before := kids(t, idp)
			old := issue(t, idp, nil)
			oldKid := kid(t, old)
			if !slices.Contains(before, oldKid) {
				t.Fatalf("the first token's kid %q is not in the JWKS %v", oldKid, before)
			}
			idp.RotateKey()
			rotated := issue(t, idp, nil)
			newKid := kid(t, rotated)
			if newKid == "" || slices.Contains(before, newKid) {
				t.Fatalf("after RotateKey the token's kid is %q, want one the JWKS %v did not hold", newKid, before)
			}
			if got, want := kids(t, idp), append(slices.Clone(before), newKid); !slices.Equal(got, want) {
				t.Errorf("JWKS after RotateKey = %v, want %v: the old keys stay until RetireOldKeys", got, want)
			}
			for name, raw := range map[string]string{"old": old, "rotated": rotated} {
				if err := verifyAgainstJWKS(t, idp, raw); err != nil {
					t.Errorf("after RotateKey the %s token: Verify = %v, want nil", name, err)
				}
			}
			idp.RetireOldKeys()
			if got := kids(t, idp); !slices.Equal(got, []string{newKid}) {
				t.Errorf("JWKS after RetireOldKeys = %v, want only %q", got, newKid)
			}
			if err := verifyAgainstJWKS(t, idp, rotated); err != nil {
				t.Errorf("after RetireOldKeys the rotated token: Verify = %v, want nil", err)
			}
			if err := verifyAgainstJWKS(t, idp, old); err == nil {
				t.Error("after RetireOldKeys a token under the retired kid verified")
			}
			if got := kid(t, issue(t, idp, nil)); got != newKid {
				t.Errorf("after RetireOldKeys the token's kid = %q, want %q", got, newKid)
			}
		})
	}
	t.Run("idps_share_keys_until_rotated", func(t *testing.T) {
		a, b := accesstest.NewIdP(t, accesstest.IdPOptions{}), accesstest.NewIdP(t, accesstest.IdPOptions{})
		a.RotateKey()
		if ka, kb := kids(t, a), kids(t, b); slices.Equal(ka, kb) {
			t.Errorf("a rotated IdP serves the JWKS %v of one never rotated", ka)
		}
	})
	for _, alg := range []string{accesstest.AlgNone, accesstest.AlgHS256} {
		for op, call := range map[string]func(*accesstest.IdP){"RotateKey": (*accesstest.IdP).RotateKey, "RetireOldKeys": (*accesstest.IdP).RetireOldKeys} {
			t.Run(alg+"_"+op, func(t *testing.T) {
				rec := &fatalRecorder{TB: t}
				idp := accesstest.NewIdP(rec, accesstest.IdPOptions{Algorithm: alg})
				done := make(chan bool)
				go func() {
					returned := false
					defer func() { done <- returned }()
					call(idp)
					returned = true
				}()
				if <-done || !strings.Contains(rec.msg, "signs with no JWKS key") {
					t.Errorf("%s under %s recorded %q; want a fatal refusal", op, alg, rec.msg)
				}
			})
		}
	}
}

// servedKey is one JWK of the set the IdP serves (RFC 7517 §4;
// RFC 7518 §6.2.1, §6.3.1).
type servedKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func servedKeys(t *testing.T, idp *accesstest.IdP) []servedKey {
	t.Helper()
	resp, err := idp.Client().Get(idp.Issuer() + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var set struct {
		Keys []servedKey `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	return set.Keys
}

// verifyAgainstJWKS checks raw's signature (RFC 7515 §5.2) under the key
// its kid names in the set the IdP serves now, by RFC 7518 §3.3 (RS256)
// or RFC 7518 §3.4 (ES256).
func verifyAgainstJWKS(t *testing.T, idp *accesstest.IdP, raw string) error {
	t.Helper()
	header, _, input, sig := decodeJWS(t, raw)
	kid, _ := header["kid"].(string)
	digest := sha256.Sum256([]byte(input))
	b64 := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("JWK member %q: %v", s, err)
		}
		return b
	}
	for _, k := range servedKeys(t, idp) {
		if k.Kid != kid {
			continue
		}
		switch {
		case header["alg"] == accesstest.AlgRS256 && k.Kty == "RSA":
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(b64(k.N)), E: int(new(big.Int).SetBytes(b64(k.E)).Int64())}
			return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
		case header["alg"] == accesstest.AlgES256 && k.Kty == "EC" && k.Crv == "P-256":
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, b64(k.X)...), b64(k.Y)...))
			if err != nil {
				return err
			}
			if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				return errors.New("the ES256 signature does not verify")
			}
			return nil
		}
		return fmt.Errorf("the key of kid %q (kty %q) does not fit alg %v", kid, k.Kty, header["alg"])
	}
	return fmt.Errorf("the served JWKS holds no key of kid %q", kid)
}
