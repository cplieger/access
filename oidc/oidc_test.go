package oidc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
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
		// Authlib CVE-2026-114614: userinfo must not reach the loopback rule.
		"loopback issuer userinfo":   func(c *Config) { c.IssuerURL = "http://user@127.0.0.1" },
		"loopback redirect userinfo": func(c *Config) { c.RedirectURL = "http://user@127.0.0.1/cb" },
		"issuer query":               func(c *Config) { c.IssuerURL = "https://idp.example?tenant=a" },
		"issuer empty query":         func(c *Config) { c.IssuerURL = "https://idp.example?" },
		"issuer fragment":            func(c *Config) { c.IssuerURL = "https://idp.example#a" },
		"other scheme":               func(c *Config) { c.IssuerURL = "ftp://idp.example" },
		"no client":                  func(c *Config) { c.ClientID = "" },
		"no redirect":                func(c *Config) { c.RedirectURL = "" },
		"http redirect":              func(c *Config) { c.RedirectURL = "http://app.example/callback" },
		"redirect fragment":          func(c *Config) { c.RedirectURL = "https://app.example/callback#x" },
		"relative redirect":          func(c *Config) { c.RedirectURL = "/callback" },
		"scopes without openid":      func(c *Config) { c.Scopes = []string{"email"} },
		"empty scopes":               func(c *Config) { c.Scopes = []string{} },
		"negative timeout":           func(c *Config) { c.HTTPClient = &http.Client{Timeout: -time.Second} },
		// The largest flow cookie must fit (RFC 6265bis §5.6).
		"client ID past the flow cookie":    func(c *Config) { c.ClientID = strings.Repeat("c", 4096) },
		"redirect URL past the flow cookie": func(c *Config) { c.RedirectURL = "https://app.example/" + strings.Repeat("a", 3000) },
		"issuer past the flow cookie":       func(c *Config) { c.IssuerURL = "https://idp.example/" + strings.Repeat("i", 3000) },
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
			intent := rapid.SampledFrom([]Intent{IntentSignIn, IntentLink, IntentStepUp, IntentInvite}).Draw(t, "intent")
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
			switch intent {
			case IntentLink, IntentStepUp:
				s.flow.SessionID = rapid.StringN(1, -1, maxSessionIDBytes).Draw(t, "sessionID")
				s.flow.UserID = rapid.Int64Range(1, math.MaxInt64).Draw(t, "userID")
			case IntentInvite:
				s.flow.InviteHash = rapid.SliceOfN(rapid.Byte(), 1, MaxInviteHashBytes).Draw(t, "inviteHash")
			}
			got, ok := decodeFlowState(s.encode())
			if !ok {
				t.Fatalf("decodeFlowState(encode(%+v)) refused", s)
			}
			if !reflect.DeepEqual(got, s) {
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
			"version 3":     append([]byte{3}, frame[1:]...),
			"version 1":     version1Frame(&good),
		}
		hash := []byte(strings.Repeat("ab", MaxInviteHashBytes/2))
		for name, mod := range map[string]func(*flowState){
			"unknown intent":          func(s *flowState) { s.flow.Intent = "admin" },
			"step-up no session":      func(s *flowState) { s.flow.SessionID = "" },
			"step-up no user":         func(s *flowState) { s.flow.UserID = 0 },
			"sign-in with a user":     func(s *flowState) { s.flow.Intent = IntentSignIn },
			"step-up with a hash":     func(s *flowState) { s.flow.InviteHash = hash },
			"sign-in with a hash":     func(s *flowState) { s.flow = Flow{Intent: IntentSignIn, InviteHash: hash} },
			"invite without a hash":   func(s *flowState) { s.flow = Flow{Intent: IntentInvite} },
			"invite with a session":   func(s *flowState) { s.flow.Intent, s.flow.InviteHash = IntentInvite, hash },
			"invite with a long hash": func(s *flowState) { s.flow = Flow{Intent: IntentInvite, InviteHash: append(hash, 'f')} },
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

// version1Frame is s in the frame before the invite hash: version byte 1
// and no trailing hash field, which a provider must refuse once the frame
// moved, so a flow begun under the old layout fails closed.
func version1Frame(s *flowState) []byte {
	b := []byte{1}
	for _, v := range []string{s.state, s.nonce, s.verifier, string(s.flow.Intent), s.flow.SessionID} {
		b = appendString(b, v)
	}
	b = binary.AppendUvarint(b, uint64(s.flow.UserID))
	b = binary.BigEndian.AppendUint64(b, uint64(s.flow.BeganAt.UnixMilli()))
	for _, v := range []string{s.flow.Redirect, s.issuer, s.clientID, s.redirectURL} {
		b = appendString(b, v)
	}
	return b
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
	if err := newWith("client"); !errors.Is(err, ErrDiscovery) || errors.Is(err, ErrProviderInvalid) {
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

// TestValidateSizesTheFlow: Validate refuses, with no
// network, every config whose largest flow cookie would not fit, so
// NewProvider refuses nothing Validate accepted on the cookie's account. The
// size is the same with the ephemeral sealer Validate fills in and with an
// app's own, since a sealed value's length depends only on the payload's.
func TestValidateSizesTheFlow(t *testing.T) {
	t.Parallel()
	appSealer, err := access.NewSealer(access.GenerateSealerKey(), access.GenerateSealerKey())
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC) }
	configWith := func(clientID string, own bool) Config {
		c := Config{IssuerURL: "http://127.0.0.1:1", ClientID: clientID, RedirectURL: "http://127.0.0.1:1/cb"}
		if own {
			c.FlowSealer, c.Now = appSealer, clock
		}
		return c
	}
	longest := func(own bool) int {
		return sort.Search(access.MaxSealPayload, func(n int) bool {
			return configWith(strings.Repeat("c", n), own).Validate() != nil
		}) - 1
	}
	filled, own := longest(false), longest(true)
	if filled != own {
		t.Errorf("the longest client ID Validate accepts is %d bytes with the ephemeral sealer and %d with the app's, want them equal", filled, own)
	}
	for _, withOwn := range []bool{false, true} {
		fits := configWith(strings.Repeat("c", filled), withOwn)
		if err := fits.Validate(); err != nil {
			t.Errorf("own sealer %t: Validate of the longest that fits = %v, want nil", withOwn, err)
		}
		if _, err := NewProvider(t.Context(), fits); !errors.Is(err, ErrDiscovery) {
			t.Errorf("own sealer %t: NewProvider of the longest that fits = %v, want ErrDiscovery from the unreachable issuer", withOwn, err)
		}
		over := configWith(strings.Repeat("c", filled+1), withOwn)
		if err := over.Validate(); !errors.Is(err, ErrConfigInvalid) {
			t.Errorf("own sealer %t: Validate one byte past the longest = %v, want ErrConfigInvalid", withOwn, err)
		}
		if _, err := NewProvider(t.Context(), over); !errors.Is(err, ErrConfigInvalid) {
			t.Errorf("own sealer %t: NewProvider one byte past the longest = %v, want ErrConfigInvalid", withOwn, err)
		}
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
	redirect := "/" + strings.Repeat("a", MaxRedirectBytes-1)
	for name, req := range map[string]BeginRequest{
		"step_up": {Intent: IntentStepUp, SessionID: strings.Repeat("f", maxSessionIDBytes), UserID: math.MaxInt64, Redirect: redirect},
		"invite":  {Intent: IntentInvite, InviteHash: []byte(strings.Repeat("f", MaxInviteHashBytes)), Redirect: redirect},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
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
		})
	}
}

// TestBeginRequestInviteHash is BeginRequest.check's invite arm: a hash of
// 1 to MaxInviteHashBytes bytes, and no session or user.
func TestBeginRequestInviteHash(t *testing.T) {
	t.Parallel()
	for n, ok := range map[int]bool{0: false, 1: true, MaxInviteHashBytes: true, MaxInviteHashBytes + 1: false} {
		req := BeginRequest{Intent: IntentInvite, InviteHash: make([]byte, n)}
		if err := req.check(); (err == nil) != ok || err != nil && !errors.Is(err, ErrFlowInvalid) {
			t.Errorf("check() of a %d-byte invite hash = %v, want ok %t, else ErrFlowInvalid", n, err, ok)
		}
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
