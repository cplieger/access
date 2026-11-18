package oidc

import (
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
)

const (
	testIssuer  = "https://idp.example/realms/main"
	testClient  = "client"
	testNonce   = "sealed-nonce"
	testSubject = "user-1"
	googleIss   = "https://accounts.google.com"
)

var tokenNow = time.Unix(1_760_000_000, 0)

func rulesFor(intent Intent) *claimRules {
	return &claimRules{
		now:      tokenNow,
		flow:     Flow{Intent: intent, BeganAt: tokenNow.Add(-30 * time.Second)},
		issuer:   testIssuer,
		clientID: testClient,
		nonce:    testNonce,
	}
}

// idToken is a payload holding the claims OpenID Connect Core 1.0 §2 makes
// required, with set's members in place, a json.RawMessage written as
// given, and drop's members removed.
func idToken(t *testing.T, set map[string]any, drop ...string) []byte {
	t.Helper()
	claims := map[string]any{
		"iss": testIssuer, "sub": testSubject, "aud": testClient, "nonce": testNonce,
		"iat": tokenNow.Add(-time.Second).Unix(), "exp": tokenNow.Add(5 * time.Minute).Unix(),
	}
	maps.Copy(claims, set)
	for _, k := range drop {
		delete(claims, k)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// withMember writes member, raw JSON text, as payload's first member, for
// text json.Marshal would refuse or rewrite.
func withMember(payload []byte, member string) []byte {
	return []byte("{" + member + "," + string(payload[1:]))
}

func raw(s string) json.RawMessage { return json.RawMessage(s) }

func mustAccept(t *testing.T, payload []byte, r *claimRules) Claims {
	t.Helper()
	c, err := checkIDToken(payload, r)
	if err != nil {
		t.Fatalf("checkIDToken(%.200s) = %v, want nil", payload, err)
	}
	return c
}

func wantRefused(t *testing.T, payload []byte, r *claimRules, want error) {
	t.Helper()
	c, err := checkIDToken(payload, r)
	if !errors.Is(err, want) {
		t.Errorf("checkIDToken(%.200s) = %v, want %v", payload, err, want)
	}
	if !reflect.DeepEqual(c, Claims{}) {
		t.Errorf("checkIDToken(%.200s) Claims = %+v on a refusal, want zero", payload, c)
	}
}

// OpenID Connect Core 1.0 §2 and §3.1.3.7: a token carrying every required
// claim, each of its type and rule, is accepted; the identity is the
// configured issuer and the subject, and Raw holds every claim.
func TestIDToken_Accepted(t *testing.T) {
	t.Parallel()
	payload := idToken(t, map[string]any{
		"email": "a@example.com", "email_verified": true, "preferred_username": "alice", "name": "Alice",
		"auth_time": tokenNow.Add(-10 * time.Second).Unix(), "groups": []string{"g"}, "azp": testClient,
		"nbf": tokenNow.Add(-time.Minute).Unix(),
	})
	c := mustAccept(t, payload, rulesFor(IntentSignIn))
	if want := (access.OIDCIdentity{Issuer: testIssuer, Subject: testSubject}); c.Identity != want {
		t.Errorf("Identity = %+v, want %+v", c.Identity, want)
	}
	if c.Email != "a@example.com" || !c.EmailVerified || c.PreferredUsername != "alice" || c.Name != "Alice" {
		t.Errorf("Claims = %+v, want the profile claims read", c)
	}
	if want := tokenNow.Add(-10 * time.Second); !c.AuthTime.Equal(want) {
		t.Errorf("AuthTime = %v, want %v", c.AuthTime, want)
	}
	for _, name := range []string{"iss", "sub", "aud", "nonce", "iat", "exp", "nbf", "azp", "auth_time", "email", "groups"} {
		if _, ok := c.Raw[name]; !ok {
			t.Errorf("Raw lacks %s", name)
		}
	}
	if got := string(c.Raw["groups"]); got != `["g"]` {
		t.Errorf(`Raw["groups"] = %s, want ["g"]`, got)
	}
}

// OpenID Connect Core 1.0 §3.1.3.7 step 2 and §14: iss is a string equal
// to the configured issuer code point for code point, so a prefix, an
// extension, a trailing slash, a case or scheme variant is another issuer
// (PyJWT CVE-2024-53861, a partial issuer match).
func TestIDToken_Issuer(t *testing.T) {
	t.Parallel()
	mustAccept(t, idToken(t, nil), rulesFor(IntentSignIn))
	for name, iss := range map[string]any{
		"a number":       5,
		"null":           raw(`null`),
		"an array":       []string{testIssuer},
		"a prefix":       "https://idp.example/realms",
		"an extension":   testIssuer + "x",
		"a child path":   testIssuer + "/x",
		"trailing slash": testIssuer + "/",
		"host case":      "https://IDP.example/realms/main",
		"path case":      "https://idp.example/realms/Main",
		"http":           "http://idp.example/realms/main",
		"empty":          "",
		"a NUL suffix":   testIssuer + "\x00",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, idToken(t, map[string]any{"iss": iss}), rulesFor(IntentSignIn), ErrTokenInvalid)
		})
	}
	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		wantRefused(t, idToken(t, nil, "iss"), rulesFor(IntentSignIn), ErrTokenInvalid)
	})
}

// OpenID Connect Core 1.0 §2: sub is a string of at most 255 ASCII characters
// (RFC 20), required and never empty; a control character (RFC 20 §5.2, 0x00
// to 0x1F and 0x7F) is refused too.
func TestIDToken_Subject(t *testing.T) {
	t.Parallel()
	for _, sub := range []string{"a", strings.Repeat("a", 255), "a b", "!~", "248289761001"} {
		if c := mustAccept(t, idToken(t, map[string]any{"sub": sub}), rulesFor(IntentSignIn)); c.Identity.Subject != sub {
			t.Errorf("Identity.Subject = %q, want %q", c.Identity.Subject, sub)
		}
	}
	for name, sub := range map[string]any{
		"empty":            "",
		"256 characters":   strings.Repeat("a", 256),
		"NUL":              "a\x00b",
		"a newline":        "a\nb",
		"0x1F":             "a\x1fb",
		"DEL":              "a\x7fb",
		"non-ASCII":        "é",
		"non-ASCII in 255": strings.Repeat("a", 253) + "é",
		"a number":         5,
		"null":             raw(`null`),
		"an array":         []string{"a"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, idToken(t, map[string]any{"sub": sub}), rulesFor(IntentSignIn), ErrTokenInvalid)
		})
	}
	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		wantRefused(t, idToken(t, nil, "sub"), rulesFor(IntentSignIn), ErrTokenInvalid)
	})
}

// OpenID Connect Core 1.0 §2 and §3.1.3.7 step 3, RFC 7519 §4.1.3: aud is
// a string or an array of strings, and every entry must be this client, so
// no other audience is trusted; an empty array names no audience
// (golang-jwt CVE-2020-26160).
func TestIDToken_Audience(t *testing.T) {
	t.Parallel()
	for name, aud := range map[string]any{
		"a string":            testClient,
		"an array of one":     []string{testClient},
		"the client repeated": []string{testClient, testClient},
	} {
		t.Run("accepted "+name, func(t *testing.T) {
			t.Parallel()
			mustAccept(t, idToken(t, map[string]any{"aud": aud}), rulesFor(IntentSignIn))
		})
	}
	for name, aud := range map[string]any{
		"an empty array":      []string{},
		"a number in array":   []any{5},
		"a null in array":     []any{testClient, nil},
		"another client too":  []string{testClient, "other"},
		"another client":      "other",
		"another in an array": []string{"other"},
		"null":                raw(`null`),
		"a number":            5,
		"an object":           map[string]string{"a": testClient},
		"empty":               "",
		"case variant":        "Client",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, idToken(t, map[string]any{"aud": aud}), rulesFor(IntentSignIn), ErrTokenInvalid)
		})
	}
	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		wantRefused(t, idToken(t, nil, "aud"), rulesFor(IntentSignIn), ErrTokenInvalid)
	})
}

// OpenID Connect Core 1.0 §3.1.3.7 steps 4 and 5: azp, when present, is a
// string equal to the client ID, whatever the audience count.
func TestIDToken_AuthorizedParty(t *testing.T) {
	t.Parallel()
	mustAccept(t, idToken(t, map[string]any{"azp": testClient}), rulesFor(IntentSignIn))
	mustAccept(t, idToken(t, map[string]any{"azp": testClient, "aud": []string{testClient, testClient}}), rulesFor(IntentSignIn))
	for name, azp := range map[string]any{
		"another client": "other",
		"empty":          "",
		"null":           raw(`null`),
		"a number":       5,
		"an array":       []string{testClient},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, idToken(t, map[string]any{"azp": azp}), rulesFor(IntentSignIn), ErrTokenInvalid)
		})
	}
}

// numericDateRefusals are values RFC 7519 §2 does not make a NumericDate
// in [0, 253402300799], judged on the number before any truncation.
var numericDateRefusals = map[string]json.RawMessage{
	"a string":     raw(`"1760000000"`),
	"null":         raw(`null`),
	"-0.1":         raw(`-0.1`),
	"1e300":        raw(`1e300`),
	"253402300800": raw(`253402300800`),
	"a boolean":    raw(`true`),
	"an array":     raw(`[1760000000]`),
}

// OpenID Connect Core 1.0 §3.1.3.7 step 9, RFC 7519 §4.1.4: now must be
// before exp; the 5-minute skew extends exp, so a token 4 minutes 59
// seconds past it is accepted and one at 5 minutes is not.
func TestIDToken_Expiry(t *testing.T) {
	t.Parallel()
	mustAccept(t, idToken(t, map[string]any{"exp": tokenNow.Add(-4*time.Minute - 59*time.Second).Unix()}), rulesFor(IntentSignIn))
	mustAccept(t, idToken(t, map[string]any{"exp": raw(`1760000000.5`), "iat": tokenNow.Add(-time.Hour).Unix()}), rulesFor(IntentSignIn))
	for name, exp := range map[string]int64{
		"5 minutes past":          tokenNow.Add(-5 * time.Minute).Unix(),
		"5 minutes 1 second past": tokenNow.Add(-5*time.Minute - time.Second).Unix(),
		"the epoch":               0,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, idToken(t, map[string]any{"exp": exp, "iat": exp - 60}), rulesFor(IntentSignIn), ErrTokenInvalid)
		})
	}
	for name, exp := range numericDateRefusals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, idToken(t, map[string]any{"exp": exp}), rulesFor(IntentSignIn), ErrTokenInvalid)
		})
	}
	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		wantRefused(t, idToken(t, nil, "exp"), rulesFor(IntentSignIn), ErrTokenInvalid)
	})
}

// OpenID Connect Core 1.0 §3.1.3.7 step 10, RFC 7519 §4.1.6: iat is
// required and not after now plus the 5-minute skew.
func TestIDToken_IssuedAt(t *testing.T) {
	t.Parallel()
	for _, ahead := range []time.Duration{4*time.Minute + 59*time.Second, 5 * time.Minute} {
		mustAccept(t, idToken(t, map[string]any{"iat": tokenNow.Add(ahead).Unix(), "exp": tokenNow.Add(time.Hour).Unix()}), rulesFor(IntentSignIn))
	}
	wantRefused(t, idToken(t, map[string]any{"iat": tokenNow.Add(5*time.Minute + time.Second).Unix(), "exp": tokenNow.Add(time.Hour).Unix()}), rulesFor(IntentSignIn), ErrTokenInvalid)
	for name, iat := range numericDateRefusals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, idToken(t, map[string]any{"iat": iat}), rulesFor(IntentSignIn), ErrTokenInvalid)
		})
	}
	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		wantRefused(t, idToken(t, nil, "iat"), rulesFor(IntentSignIn), ErrTokenInvalid)
	})
}

// RFC 7519 §4.1.5: nbf, when present, is not after now plus the 5-minute
// skew. null reads as absent, as go-oidc's *jsonTime read it.
func TestIDToken_NotBefore(t *testing.T) {
	t.Parallel()
	for _, nbf := range []any{tokenNow.Add(4*time.Minute + 59*time.Second).Unix(), tokenNow.Add(5 * time.Minute).Unix(), raw(`null`), 0} {
		mustAccept(t, idToken(t, map[string]any{"nbf": nbf}), rulesFor(IntentSignIn))
	}
	wantRefused(t, idToken(t, map[string]any{"nbf": tokenNow.Add(5*time.Minute + time.Second).Unix()}), rulesFor(IntentSignIn), ErrTokenInvalid)
	refusals := maps.Clone(numericDateRefusals)
	delete(refusals, "null")
	for name, nbf := range refusals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, idToken(t, map[string]any{"nbf": nbf}), rulesFor(IntentSignIn), ErrTokenInvalid)
		})
	}
}

// OpenID Connect Core 1.0 §3.1.3.7 step 11: the nonce sent in the
// authentication request must be present and equal, on every flow, and no
// claim switches the check off (Authlib CVE-2026-114617). A nonce that is
// missing or not a string is a malformed token (Core 1.0 §2), refused before
// any comparison; a string other than the sealed one is a mismatch.
func TestIDToken_Nonce(t *testing.T) {
	t.Parallel()
	fresh := tokenNow.Unix()
	for _, intent := range []Intent{IntentSignIn, IntentLink, IntentStepUp} {
		for name, tc := range map[string]struct {
			want    error
			payload []byte
		}{
			"missing":                       {ErrTokenInvalid, idToken(t, map[string]any{"auth_time": fresh}, "nonce")},
			"null":                          {ErrTokenInvalid, idToken(t, map[string]any{"nonce": raw(`null`), "auth_time": fresh})},
			"a number":                      {ErrTokenInvalid, idToken(t, map[string]any{"nonce": 5, "auth_time": fresh})},
			"an array":                      {ErrTokenInvalid, idToken(t, map[string]any{"nonce": []string{testNonce}, "auth_time": fresh})},
			"nonce_supported false, absent": {ErrTokenInvalid, idToken(t, map[string]any{"nonce_supported": false, "auth_time": fresh}, "nonce")},
			"empty":                         {ErrNonceMismatch, idToken(t, map[string]any{"nonce": "", "auth_time": fresh})},
			"another":                       {ErrNonceMismatch, idToken(t, map[string]any{"nonce": "other-nonce", "auth_time": fresh})},
			"a prefix":                      {ErrNonceMismatch, idToken(t, map[string]any{"nonce": testNonce[:5], "auth_time": fresh})},
			"case variant":                  {ErrNonceMismatch, idToken(t, map[string]any{"nonce": strings.ToUpper(testNonce), "auth_time": fresh})},
			"nonce_supported false, wrong":  {ErrNonceMismatch, idToken(t, map[string]any{"nonce_supported": false, "nonce": "x", "auth_time": fresh})},
		} {
			t.Run(string(intent)+" "+name, func(t *testing.T) {
				t.Parallel()
				wantRefused(t, tc.payload, rulesFor(intent), tc.want)
			})
		}
	}
}

// Every claim is type-checked before any is compared
// (Core 1.0 §2 and §3.1.3.7), so a token that also carries another nonce is
// refused as malformed.
func TestIDToken_TypesBeforeComparisons(t *testing.T) {
	t.Parallel()
	for name, set := range map[string]map[string]any{
		"exp a string":       {"exp": "1760000300"},
		"iat null":           {"iat": raw(`null`)},
		"email a number":     {"email": 5},
		"auth_time a string": {"auth_time": "x"},
		"aud empty":          {"aud": []string{}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			set["nonce"] = "other-nonce"
			wantRefused(t, idToken(t, set), rulesFor(IntentSignIn), ErrTokenInvalid)
		})
	}
}

// OpenID Connect Core 1.0 §5.1: email, preferred_username and name are
// strings and email_verified a boolean; auth_time is a NumericDate
// (Core 1.0 §2). null reads as absent on each, and email_verified also takes
// the strings "true" and "false", as providers send and go-oidc's
// stringAsBool read.
func TestIDToken_ProfileClaims(t *testing.T) {
	t.Parallel()
	c := mustAccept(t, idToken(t, map[string]any{
		"email": raw(`null`), "preferred_username": raw(`null`), "name": raw(`null`),
		"email_verified": raw(`null`), "auth_time": raw(`null`),
	}), rulesFor(IntentSignIn))
	if c.Email != "" || c.PreferredUsername != "" || c.Name != "" || c.EmailVerified || !c.AuthTime.IsZero() {
		t.Errorf("Claims of null profile claims = %+v, want zero fields", c)
	}
	for v, want := range map[string]bool{`true`: true, `false`: false, `"true"`: true, `"false"`: false, `null`: false} {
		if c := mustAccept(t, idToken(t, map[string]any{"email_verified": raw(v)}), rulesFor(IntentSignIn)); c.EmailVerified != want {
			t.Errorf("email_verified %s: EmailVerified = %v, want %v", v, c.EmailVerified, want)
		}
	}
	if c := mustAccept(t, idToken(t, nil), rulesFor(IntentSignIn)); c.EmailVerified || c.Email != "" || !c.AuthTime.IsZero() {
		t.Errorf("Claims without profile claims = %+v, want zero fields", c)
	}
	for name, set := range map[string]map[string]any{
		"email a number":              {"email": 5},
		"preferred_username an array": {"preferred_username": []string{"a"}},
		"name an object":              {"name": map[string]string{}},
		"name a boolean":              {"name": true},
		`email_verified "yes"`:        {"email_verified": "yes"},
		`email_verified "TRUE"`:       {"email_verified": "TRUE"},
		"email_verified a number":     {"email_verified": 1},
		"email_verified an array":     {"email_verified": []bool{true}},
		"email_verified an object":    {"email_verified": map[string]bool{}},
		`email_verified "True"`:       {"email_verified": "True"},
		"auth_time a string":          {"auth_time": "1760000000"},
		"auth_time negative":          {"auth_time": -1},
		"auth_time past 9999":         {"auth_time": 253402300800},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, idToken(t, set), rulesFor(IntentSignIn), ErrTokenInvalid)
		})
	}
}

// RFC 7519 §4: claims an implementation does not understand must be
// ignored, so a null at_hash, picture, groups or custom claim is never
// type-checked; it stays in Raw, where Strings reports false for null.
func TestIDToken_UnreadClaims(t *testing.T) {
	t.Parallel()
	c := mustAccept(t, idToken(t, map[string]any{
		"at_hash": raw(`null`), "picture": raw(`null`), "groups": raw(`null`), "x-custom": raw(`null`),
		"amr": raw(`5`), "hd": raw(`{"a":[1,{"b":null}]}`),
	}), rulesFor(IntentSignIn))
	if got, ok := c.Strings("groups"); ok {
		t.Errorf(`Strings("groups") = %q, true for null; want false`, got)
	}
	for _, name := range []string{"at_hash", "picture", "groups", "x-custom", "amr", "hd"} {
		if _, ok := c.Raw[name]; !ok {
			t.Errorf("Raw lacks %s", name)
		}
	}
}

// OpenID Connect Core 1.0 §3.1.3.8: at_hash is optional under the code
// flow and the access token is never used, so a wrong one is not checked.
func TestIDToken_AccessTokenHashUnchecked(t *testing.T) {
	t.Parallel()
	mustAccept(t, idToken(t, map[string]any{"at_hash": "not-the-hash"}), rulesFor(IntentSignIn))
}

// RFC 7519 §7.2 step 10 and RFC 8259 §4, §8.1: the payload is one JSON
// object with unique names and valid UTF-8 at every depth, unread claims
// included, and bounded nesting (PyJWT CVE-2026-102265, CVE-2026-101918,
// Nimbus CVE-2025-53864).
func TestIDToken_Payload(t *testing.T) {
	t.Parallel()
	base := idToken(t, nil)
	deep := strings.Repeat("[", 20_000) + strings.Repeat("]", 20_000)
	for name, payload := range map[string][]byte{
		"a duplicate custom claim":         withMember(withMember(base, `"x":1`), `"x":2`),
		"a duplicate sub":                  withMember(base, `"sub":"other"`),
		"a duplicate nested name":          withMember(base, `"x":{"a":1,"a":2}`),
		"invalid UTF-8 in an unread claim": withMember(base, "\"x\":[\"\xff\"]"),
		"invalid UTF-8 in sub":             withMember(idToken(t, nil, "sub"), "\"sub\":\"\xc3\x28\""),
		"a 20,000-deep unread claim":       withMember(base, `"x":`+deep),
		"an array":                         []byte(`[` + string(base) + `]`),
		"a string":                         []byte(`"x"`),
		"null":                             []byte(`null`),
		"empty":                            nil,
		"a trailing value":                 append(slices.Clone(base), ` {}`...),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, payload, rulesFor(IntentSignIn), ErrTokenInvalid)
		})
	}
}

// Google documents both https://accounts.google.com and accounts.google.com
// as its ID tokens' iss
// (https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken),
// an exception to OpenID Connect Core 1.0 §3.1.3.7 step 2 for that issuer
// alone. Either form is one identity, the configured issuer's.
func TestIDToken_GoogleIssuer(t *testing.T) {
	t.Parallel()
	google := rulesFor(IntentSignIn)
	google.issuer = googleIss
	for _, iss := range []string{googleIss, "accounts.google.com"} {
		c := mustAccept(t, idToken(t, map[string]any{"iss": iss}), google)
		if want := (access.OIDCIdentity{Issuer: googleIss, Subject: testSubject}); c.Identity != want {
			t.Errorf("iss %s: Identity = %+v, want %+v", iss, c.Identity, want)
		}
	}
	for _, iss := range []string{"http://accounts.google.com", "accounts.google.com/", "ACCOUNTS.GOOGLE.COM", "https://accounts.google.com/", "www.accounts.google.com"} {
		wantRefused(t, idToken(t, map[string]any{"iss": iss}), google, ErrTokenInvalid)
	}
	slash := rulesFor(IntentSignIn)
	slash.issuer = googleIss + "/"
	for name, r := range map[string]*claimRules{"another issuer": rulesFor(IntentSignIn), "Google with a slash": slash} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantRefused(t, idToken(t, map[string]any{"iss": "accounts.google.com"}), r, ErrTokenInvalid)
		})
	}
}

// OpenID Connect Core 1.0 §3.1.3.7 step 12: a link, step-up or invite asked
// for max_age=0, so auth_time is required and must not be before the flow
// began, less 60 seconds of skew; a sign-in needs none.
func TestIDToken_AuthTime(t *testing.T) {
	t.Parallel()
	began := rulesFor(IntentLink).flow.BeganAt
	for _, intent := range []Intent{IntentLink, IntentStepUp, IntentInvite} {
		t.Run(string(intent), func(t *testing.T) {
			t.Parallel()
			for _, before := range []time.Duration{59 * time.Second, 60 * time.Second, 0, -10 * time.Second} {
				mustAccept(t, idToken(t, map[string]any{"auth_time": began.Add(-before).Unix()}), rulesFor(intent))
			}
			for name, payload := range map[string][]byte{
				"absent":        idToken(t, nil),
				"null":          idToken(t, map[string]any{"auth_time": raw(`null`)}),
				"61 s before":   idToken(t, map[string]any{"auth_time": began.Add(-61 * time.Second).Unix()}),
				"an hour ago":   idToken(t, map[string]any{"auth_time": began.Add(-time.Hour).Unix()}),
				"the epoch (0)": idToken(t, map[string]any{"auth_time": 0}),
			} {
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					wantRefused(t, payload, rulesFor(intent), ErrStaleAuthentication)
				})
			}
		})
	}
	mustAccept(t, idToken(t, nil), rulesFor(IntentSignIn))
	mustAccept(t, idToken(t, map[string]any{"auth_time": began.Add(-time.Hour).Unix()}), rulesFor(IntentSignIn))
}
