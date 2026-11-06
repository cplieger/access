package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"pgregory.net/rapid"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	valid := Config{IssuerURL: "https://idp.example", ClientID: "client", RedirectURL: "https://app.example/callback"}
	accepted := map[string]func(*Config){
		"https":               func(*Config) {},
		"issuer with path":    func(c *Config) { c.IssuerURL = "https://idp.example/realms/main" },
		"loopback http v4":    func(c *Config) { c.IssuerURL, c.RedirectURL = "http://127.0.0.1:8080", "http://127.0.0.1:9000/cb" },
		"loopback http v6":    func(c *Config) { c.IssuerURL = "http://[::1]:8080" },
		"localhost http":      func(c *Config) { c.IssuerURL, c.RedirectURL = "http://localhost:8080", "http://LOCALHOST/cb" },
		"redirect with query": func(c *Config) { c.RedirectURL = "https://app.example/callback?x=1" },
		"scopes with openid":  func(c *Config) { c.Scopes = []string{"email", "openid"} },
		"positive timeout":    func(c *Config) { c.HTTPClient = &http.Client{Timeout: time.Second} },
		"no client secret":    func(c *Config) { c.ClientSecret = access.Secret{} },
	}
	for name, mod := range accepted {
		c := valid
		mod(&c)
		if err := c.Validate(); err != nil {
			t.Errorf("%s: Validate() = %v, want nil", name, err)
		}
	}
	refused := map[string]func(*Config){
		"no issuer":               func(c *Config) { c.IssuerURL = "" },
		"http issuer":             func(c *Config) { c.IssuerURL = "http://idp.example" },
		"http loopback lookalike": func(c *Config) { c.IssuerURL = "http://127.0.0.1.example" },
		"relative issuer":         func(c *Config) { c.IssuerURL = "/idp" },
		"hostless issuer":         func(c *Config) { c.IssuerURL = "https:///idp" },
		"opaque issuer":           func(c *Config) { c.IssuerURL = "https:idp.example" },
		"issuer userinfo":         func(c *Config) { c.IssuerURL = "https://u:p@idp.example" },
		"issuer query":            func(c *Config) { c.IssuerURL = "https://idp.example?tenant=a" },
		"issuer empty query":      func(c *Config) { c.IssuerURL = "https://idp.example?" },
		"issuer fragment":         func(c *Config) { c.IssuerURL = "https://idp.example#a" },
		"other scheme":            func(c *Config) { c.IssuerURL = "ftp://idp.example" },
		"no client":               func(c *Config) { c.ClientID = "" },
		"no redirect":             func(c *Config) { c.RedirectURL = "" },
		"http redirect":           func(c *Config) { c.RedirectURL = "http://app.example/callback" },
		"redirect fragment":       func(c *Config) { c.RedirectURL = "https://app.example/callback#x" },
		"relative redirect":       func(c *Config) { c.RedirectURL = "/callback" },
		"scopes without openid":   func(c *Config) { c.Scopes = []string{"email"} },
		"empty scopes":            func(c *Config) { c.Scopes = []string{} },
		"negative timeout":        func(c *Config) { c.HTTPClient = &http.Client{Timeout: -time.Second} },
	}
	for name, mod := range refused {
		c := valid
		mod(&c)
		if err := c.Validate(); !errors.Is(err, ErrConfigInvalid) {
			t.Errorf("%s: Validate() = %v, want ErrConfigInvalid", name, err)
		}
	}
}

func sampleFlowState() flowState {
	return flowState{
		state: "state", nonce: "nonce", verifier: "verifier",
		flow: Flow{
			Intent: IntentStepUp, SessionID: "session", UserID: 42,
			BeganAt: time.UnixMilli(1_760_000_000_123), Redirect: "/settings?tab=keys",
		},
		issuer: "https://idp.example", clientID: "client", redirectURL: "https://app.example/cb",
	}
}

func TestFlowFrame(t *testing.T) {
	t.Parallel()
	t.Run("round_trip", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			intent := rapid.SampledFrom([]Intent{IntentSignIn, IntentLink, IntentStepUp}).Draw(t, "intent")
			s := flowState{
				state:       rapid.String().Draw(t, "state"),
				nonce:       rapid.String().Draw(t, "nonce"),
				verifier:    rapid.String().Draw(t, "verifier"),
				issuer:      rapid.String().Draw(t, "issuer"),
				clientID:    rapid.String().Draw(t, "clientID"),
				redirectURL: rapid.String().Draw(t, "redirectURL"),
				flow: Flow{
					Intent:   intent,
					Redirect: rapid.String().Draw(t, "redirect"),
					BeganAt:  time.UnixMilli(rapid.Int64().Draw(t, "beganAt")),
				},
			}
			if intent != IntentSignIn {
				s.flow.SessionID = rapid.StringN(1, -1, maxSessionIDBytes).Draw(t, "sessionID")
				s.flow.UserID = rapid.Int64Range(1, math.MaxInt64).Draw(t, "userID")
			}
			got, ok := decodeFlowState(s.encode())
			if !ok {
				t.Fatalf("decodeFlowState(encode(%+v)) refused", s)
			}
			if got != s {
				t.Fatalf("decodeFlowState(encode(s)) = %+v, want %+v", got, s)
			}
		})
	})
	t.Run("size_depends_on_lengths_only", func(t *testing.T) {
		t.Parallel()
		a, b := sampleFlowState(), sampleFlowState()
		a.flow.Redirect = "/" + strings.Repeat("a", 511)
		b.flow.Redirect = "/" + strings.Repeat("&", 511)
		if la, lb := len(a.encode()), len(b.encode()); la != lb {
			t.Errorf("frames of equal-length redirects are %d and %d bytes", la, lb)
		}
	})
	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		good := sampleFlowState()
		frame := good.encode()
		for i := range frame {
			if _, ok := decodeFlowState(frame[:i]); ok {
				t.Errorf("the frame cut to %d of %d bytes decoded", i, len(frame))
			}
		}
		cases := map[string][]byte{
			"trailing byte": append(slices.Clone(frame), 0),
			"version 2":     append([]byte{2}, frame[1:]...),
		}
		for name, mod := range map[string]func(*flowState){
			"unknown intent":      func(s *flowState) { s.flow.Intent = "admin" },
			"step-up no session":  func(s *flowState) { s.flow.SessionID = "" },
			"step-up no user":     func(s *flowState) { s.flow.UserID = 0 },
			"sign-in with a user": func(s *flowState) { s.flow.Intent = IntentSignIn },
		} {
			s := sampleFlowState()
			mod(&s)
			cases[name] = s.encode()
		}
		overflow := []byte{flowFrameVersion}
		for _, v := range []string{"s", "n", "v", string(IntentLink), "sid"} {
			overflow = appendString(overflow, v)
		}
		overflow = append(overflow, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01)
		cases["user ID past int64"] = overflow
		for name, b := range cases {
			if _, ok := decodeFlowState(b); ok {
				t.Errorf("%s: decoded", name)
			}
		}
	})
}

// stubTransport answers every request with its body and declared length.
type stubTransport struct {
	body   []byte
	length int64
}

func (s stubTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(s.body)), ContentLength: s.length}, nil
}

type stalledTransport struct{}

func (stalledTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(&stalledBody{left: maxResponseBytes}), ContentLength: -1}, nil
}

type stalledBody struct{ left int }

func (s *stalledBody) Read(p []byte) (int, error) {
	n := min(len(p), s.left)
	s.left -= n
	return n, nil
}

// countingBody counts the bytes read through the cap from the body below it.
type countingBody struct {
	io.ReadCloser
	n *int64
}

func (c countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	*c.n += int64(n)
	return n, err
}

func TestCappedTransport(t *testing.T) {
	t.Parallel()
	// open returns a body through the cap and the count of bytes the cap has
	// pulled from the body below it.
	open := func(t *testing.T, body []byte, length int64) (io.ReadCloser, *int64) {
		t.Helper()
		resp, err := cappedTransport{next: stubTransport{body: body, length: length}}.RoundTrip(&http.Request{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		pulled := new(int64)
		capped := resp.Body.(*cappedBody)
		capped.rc = countingBody{ReadCloser: capped.rc, n: pulled}
		return capped, pulled
	}
	// get reads a body through the cap, under a consumer's own 1 MiB limit
	// when limited (cappedBody.Read).
	get := func(t *testing.T, body []byte, length int64, limited bool) (got []byte, pulled int64, err error) {
		t.Helper()
		rc, n := open(t, body, length)
		var r io.Reader = rc
		if limited {
			r = io.LimitReader(r, maxResponseBytes)
		}
		got, err = io.ReadAll(r)
		return got, *n, err
	}
	big := bytes.Repeat([]byte{'x'}, 2<<20)
	for _, tc := range []struct {
		name    string
		length  int64
		limited bool
	}{
		{name: "declared_over_cap", length: int64(len(big))},
		{name: "undeclared_over_cap", length: -1},
		{name: "declared_over_cap_under_consumer_limit", length: int64(len(big)), limited: true},
		{name: "undeclared_over_cap_under_consumer_limit", length: -1, limited: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, pulled, err := get(t, big, tc.length, tc.limited)
			if !errors.Is(err, errResponseTooLarge) {
				t.Errorf("reading a 2 MiB body = %v, want errResponseTooLarge", err)
			}
			if len(got) > maxResponseBytes {
				t.Errorf("handed out %d bytes, want at most %d", len(got), maxResponseBytes)
			}
			if pulled > maxResponseBytes+1 {
				t.Errorf("pulled %d bytes from the transport, want at most %d", pulled, maxResponseBytes+1)
			}
		})
	}
	t.Run("empty_reads_at_cap_under_consumer_limit", func(t *testing.T) {
		t.Parallel()
		resp, err := cappedTransport{next: stalledTransport{}}.RoundTrip(&http.Request{})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if _, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes)); !errors.Is(err, io.ErrNoProgress) {
			t.Errorf("a body that answers nothing at the cap = %v, want io.ErrNoProgress", err)
		}
	})
	t.Run("verdict_sticky", func(t *testing.T) {
		t.Parallel()
		for _, size := range []int{maxResponseBytes + 1, maxResponseBytes + 3} {
			body, pulled := open(t, big[:size], -1)
			if _, err := io.ReadAll(body); !errors.Is(err, errResponseTooLarge) {
				t.Fatalf("reading a %d-byte body = %v, want errResponseTooLarge", size, err)
			}
			for i := range 3 {
				if n, err := body.Read(make([]byte, 8)); n != 0 || !errors.Is(err, errResponseTooLarge) {
					t.Errorf("a %d-byte body, read %d after the refusal = %d, %v; want 0, errResponseTooLarge", size, i+1, n, err)
				}
			}
			if *pulled != maxResponseBytes+1 {
				t.Errorf("a %d-byte body: pulled %d bytes from the transport, want %d", size, *pulled, maxResponseBytes+1)
			}
		}
	})
	t.Run("at_cap", func(t *testing.T) {
		t.Parallel()
		for _, length := range []int64{maxResponseBytes, -1} {
			for _, limited := range []bool{false, true} {
				got, _, err := get(t, big[:maxResponseBytes], length, limited)
				if err != nil || len(got) != maxResponseBytes {
					t.Errorf("a 1 MiB body declared %d, limited %t: read %d bytes, %v; want all of it", length, limited, len(got), err)
				}
			}
		}
	})
}

func raw(t *testing.T, claims map[string]any) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}
	for k, v := range claims {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out[k] = b
	}
	return out
}

func TestDecodeClaims(t *testing.T) {
	t.Parallel()
	c, err := decodeClaims(raw(t, map[string]any{
		"email": "a@example.com", "preferred_username": "alice", "name": "Alice",
		"email_verified": "true", "auth_time": 1_760_000_000, "groups": []string{"g"},
	}))
	if err != nil {
		t.Fatalf("decodeClaims = %v", err)
	}
	if c.Email != "a@example.com" || c.PreferredUsername != "alice" || c.Name != "Alice" || !c.EmailVerified {
		t.Errorf("decodeClaims = %+v", c)
	}
	if want := time.Unix(1_760_000_000, 0); !c.AuthTime.Equal(want) {
		t.Errorf("AuthTime = %v, want %v", c.AuthTime, want)
	}
	if _, ok := c.Raw["groups"]; !ok {
		t.Error("Raw lost the groups claim")
	}
	none, err := decodeClaims(raw(t, map[string]any{"email": nil, "auth_time": nil}))
	if err != nil || none.Email != "" || !none.AuthTime.IsZero() || none.EmailVerified {
		t.Errorf("decodeClaims of null claims = %+v, %v; want zero fields", none, err)
	}
	for name, claims := range map[string]map[string]any{
		"numeric email":         {"email": 1},
		"array username":        {"preferred_username": []string{"a"}},
		"object name":           {"name": map[string]string{}},
		"string auth_time":      {"auth_time": "1760000000"},
		"negative auth_time":    {"auth_time": -1},
		"auth_time past 9999":   {"auth_time": 253402300800},
		"email_verified number": {"email_verified": 1},
	} {
		if _, err := decodeClaims(raw(t, claims)); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("%s: decodeClaims = %v, want ErrTokenInvalid", name, err)
		}
	}
}

func TestDecodeEmailVerified(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{"true": true, "false": false, `"true"`: true, `"false"`: false, "null": false} {
		got, err := decodeEmailVerified(json.RawMessage(in))
		if err != nil || got != want {
			t.Errorf("decodeEmailVerified(%s) = %t, %v; want %t, nil", in, got, err, want)
		}
	}
	for _, in := range []string{`"TRUE"`, `"yes"`, `1`, `0`, `[]`, `{}`, `"True"`, ``} {
		if _, err := decodeEmailVerified(json.RawMessage(in)); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("decodeEmailVerified(%s) = %v, want ErrTokenInvalid", in, err)
		}
	}
}

func TestClaimsStrings(t *testing.T) {
	t.Parallel()
	c := Claims{Raw: map[string]json.RawMessage{
		"one": json.RawMessage(`"admins"`), "many": json.RawMessage(`["a","b"]`), "empty": json.RawMessage(`[]`),
		"null": json.RawMessage(`null`), "number": json.RawMessage(`3`), "mixed": json.RawMessage(`["a",1]`),
		"null element": json.RawMessage(`["a",null]`),
	}}
	for name, want := range map[string][]string{"one": {"admins"}, "many": {"a", "b"}, "empty": {}} {
		if got, ok := c.Strings(name); !ok || !slices.Equal(got, want) {
			t.Errorf("Strings(%q) = %q, %t; want %q, true", name, got, ok, want)
		}
	}
	for _, name := range []string{"absent", "null", "number", "mixed", "null element"} {
		if got, ok := c.Strings(name); ok {
			t.Errorf("Strings(%q) = %q, true; want false", name, got)
		}
	}
}

func TestUsernameCandidate(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		c    Claims
		want string
	}{
		"preferred_username":     {Claims{PreferredUsername: "Alice", Email: "b@example.com", EmailVerified: true}, "alice"},
		"verified email":         {Claims{Email: "Bob@Example.com", EmailVerified: true}, "bob@example.com"},
		"username without email": {Claims{PreferredUsername: "carol"}, "carol"},
	} {
		if got, err := UsernameCandidate(tc.c); err != nil || got != tc.want {
			t.Errorf("%s: UsernameCandidate = %q, %v; want %q", name, got, err, tc.want)
		}
	}
	for name, c := range map[string]Claims{"nothing": {}, "unverified email": {Email: "b@example.com"}} {
		if _, err := UsernameCandidate(c); !errors.Is(err, ErrNoUsername) {
			t.Errorf("%s: UsernameCandidate = %v, want ErrNoUsername", name, err)
		}
	}
	for name, tc := range map[string]struct {
		c     Claims
		claim string
	}{
		"username with a space": {Claims{PreferredUsername: "a b", Email: "b@example.com", EmailVerified: true}, "preferred_username"},
		"email with a space":    {Claims{Email: "a b@example.com", EmailVerified: true}, "email"},
	} {
		_, err := UsernameCandidate(tc.c)
		var ue *UsernameError
		if !errors.As(err, &ue) || ue.Claim != tc.claim || !errors.Is(err, access.ErrUsernameInvalid) {
			t.Errorf("%s: UsernameCandidate = %v, want *UsernameError{Claim: %q} matching access.ErrUsernameInvalid", name, err, tc.claim)
		}
	}
}

func TestProvisioningAdmit(t *testing.T) {
	t.Parallel()
	groups := func(v string) Claims { return Claims{Raw: map[string]json.RawMessage{"groups": json.RawMessage(v)}} }
	gate := Provisioning{Enabled: true, Claim: "groups", AllowedValues: []string{"staff", "admins"}}
	t.Run("validate", func(t *testing.T) {
		t.Parallel()
		for name, p := range map[string]Provisioning{
			"claim without values":  {Enabled: true, Claim: "groups"},
			"values without claim":  {Enabled: true, AllowedValues: []string{"staff"}},
			"unknown role":          {Enabled: true, Role: "owner"},
			"disabled, still wrong": {Claim: "groups"},
		} {
			if err := p.Validate(); !errors.Is(err, ErrConfigInvalid) {
				t.Errorf("%s: Validate() = %v, want ErrConfigInvalid", name, err)
			}
		}
		for name, p := range map[string]Provisioning{
			"zero": {}, "any identity": {Enabled: true}, "gate": gate,
			"user role": {Enabled: true, Role: access.RoleUser}, "admin role": {Enabled: true, Role: access.RoleAdmin},
		} {
			if err := p.Validate(); err != nil {
				t.Errorf("%s: Validate() = %v, want nil", name, err)
			}
		}
	})
	t.Run("admit", func(t *testing.T) {
		t.Parallel()
		if err := (Provisioning{}).Admit(groups(`"staff"`)); !errors.Is(err, ErrProvisioningDisabled) {
			t.Errorf("zero Provisioning: Admit = %v, want ErrProvisioningDisabled", err)
		}
		if err := (Provisioning{Enabled: true, Claim: "groups"}).Admit(groups(`"staff"`)); !errors.Is(err, ErrConfigInvalid) {
			t.Errorf("a claim with no AllowedValues: Admit = %v, want ErrConfigInvalid", err)
		}
		if err := (Provisioning{Enabled: true, AllowedValues: []string{"staff"}}).Admit(groups(`"x"`)); !errors.Is(err, ErrConfigInvalid) {
			t.Errorf("AllowedValues with no claim: Admit = %v, want ErrConfigInvalid", err)
		}
		if err := (Provisioning{Enabled: true}).Admit(Claims{}); err != nil {
			t.Errorf("no claim gate: Admit = %v, want nil", err)
		}
		for name, c := range map[string]Claims{
			"string":        groups(`"admins"`),
			"array":         groups(`["guests","staff"]`),
			"array of many": groups(`["staff","admins"]`),
		} {
			if err := gate.Admit(c); err != nil {
				t.Errorf("%s: Admit = %v, want nil", name, err)
			}
		}
		for name, c := range map[string]Claims{
			"missing claim":  {},
			"other string":   groups(`"guests"`),
			"other array":    groups(`["guests","users"]`),
			"empty array":    groups(`[]`),
			"wrong case":     groups(`"Staff"`),
			"number":         groups(`7`),
			"array with num": groups(`["guests",7,"staff"]`),
		} {
			if err := gate.Admit(c); !errors.Is(err, ErrNotAdmitted) {
				t.Errorf("%s: Admit = %v, want ErrNotAdmitted", name, err)
			}
		}
	})
}

func TestProviderError(t *testing.T) {
	t.Parallel()
	for _, code := range providerErrorCodes {
		if got := providerError(code).Code; got != code {
			t.Errorf("providerError(%q).Code = %q", code, got)
		}
	}
	for _, code := range []string{"login_required", "ACCESS_DENIED", "access_denied ", "x"} {
		if got := providerError(code).Code; got != "other" {
			t.Errorf("providerError(%q).Code = %q, want other", code, got)
		}
	}
}

// TestNewProviderRefusesAFlowThatCannotFit is NewProvider sizing the largest
// flow before discovery: a client ID long enough that the flow payload
// passes access.MaxSealPayload is ErrConfigInvalid matching
// access.ErrSealTooLarge, the longest one that still seals is ErrConfigInvalid
// for the cookie, whose name under the longest session cookie Name and
// value pass 4096 bytes, and a short one reaches discovery.
func TestNewProviderRefusesAFlowThatCannotFit(t *testing.T) {
	t.Parallel()
	newWith := func(clientID string) error {
		_, err := NewProvider(t.Context(), Config{IssuerURL: "http://127.0.0.1:1", ClientID: clientID, RedirectURL: "http://127.0.0.1:1/cb"})
		return err
	}
	if err := newWith("client"); !errors.Is(err, ErrDiscovery) {
		t.Errorf("NewProvider with a short client ID = %v, want ErrDiscovery from the unreachable issuer", err)
	}
	if err := newWith(strings.Repeat("c", access.MaxSealPayload)); !errors.Is(err, ErrConfigInvalid) || !errors.Is(err, access.ErrSealTooLarge) {
		t.Errorf("NewProvider with a %d-byte client ID = %v, want ErrConfigInvalid matching access.ErrSealTooLarge", access.MaxSealPayload, err)
	}
	longest := sort.Search(access.MaxSealPayload, func(n int) bool {
		return errors.Is(newWith(strings.Repeat("c", n)), access.ErrSealTooLarge)
	}) - 1
	if err := newWith(strings.Repeat("c", longest)); !errors.Is(err, ErrConfigInvalid) || errors.Is(err, access.ErrSealTooLarge) {
		t.Errorf("NewProvider with the longest client ID that seals (%d bytes) = %v, want ErrConfigInvalid for the cookie", longest, err)
	}
}

// TestBeginFitsTheFlowNewProviderSized is Begin's largest flow, under the
// longest client ID checkFlowFits accepts and the longest session cookie
// Name, setting a flow cookie whose name and value fit 4096 bytes (RFC
// 6265bis section 5.6).
func TestBeginFitsTheFlowNewProviderSized(t *testing.T) {
	t.Parallel()
	configWith := func(clientID string) Config {
		return Config{IssuerURL: "https://idp.example", ClientID: clientID, RedirectURL: "https://app.example/cb", FlowSealer: access.NewEphemeralSealer(), Now: time.Now}
	}
	longest := sort.Search(access.MaxSealPayload, func(n int) bool {
		cfg := configWith(strings.Repeat("c", n))
		return checkFlowFits(&cfg) != nil
	}) - 1
	p := &Provider{cfg: configWith(strings.Repeat("c", longest))}
	session := access.CookieConfig{Name: strings.Repeat("n", access.MaxCookieNameBytes)}
	req := BeginRequest{Intent: IntentStepUp, SessionID: strings.Repeat("f", maxSessionIDBytes), UserID: math.MaxInt64, Redirect: "/" + strings.Repeat("a", MaxRedirectBytes-1)}
	rec := httptest.NewRecorder()
	if _, err := p.Begin(rec, httptest.NewRequest(http.MethodPost, "https://app.example/auth/start", nil), session, req); err != nil {
		t.Fatalf("Begin under a %d-byte client ID: %v", longest, err)
	}
	set := rec.Result().Cookies()
	if len(set) != 1 {
		t.Fatalf("Begin set %d cookies, want the flow cookie alone", len(set))
	}
	if n := len(set[0].Name) + len(set[0].Value); n > 4096 {
		t.Errorf("Begin under a %d-byte client ID set a %d-byte flow cookie name and value, want at most 4096", longest, n)
	}
}

func TestBeginRequestSessionIDBound(t *testing.T) {
	t.Parallel()
	for n, ok := range map[int]bool{64: true, 65: false} {
		req := BeginRequest{Intent: IntentLink, SessionID: strings.Repeat("f", n), UserID: 1}
		if err := req.check(); (err == nil) != ok || err != nil && !errors.Is(err, ErrFlowInvalid) {
			t.Errorf("check() of a %d-byte session ID = %v, want ok %t, else ErrFlowInvalid", n, err, ok)
		}
	}
}
