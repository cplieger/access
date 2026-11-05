package accesstest_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access/accesstest"
	"golang.org/x/oauth2"
)

type protocolClause struct {
	check  func(t *testing.T, idp *accesstest.IdP, clock *testClock)
	name   string
	clause string
	opts   accesstest.IdPOptions
}

func TestIdPProtocolClauses(t *testing.T) {
	var rows []protocolClause
	rows = append(rows, authorizeClientClauses()...)
	rows = append(rows, authorizeResponseClauses()...)
	rows = append(rows, promptClauses()...)
	rows = append(rows, maxAgeClauses()...)
	rows = append(rows, pkceClauses()...)
	rows = append(rows, tokenClauses()...)
	rows = append(rows, urlClauses()...)
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("clause: %s", row.clause)
				}
			})
			clock := newTestClock(idpT0)
			row.opts.Now = clock.now
			row.check(t, accesstest.NewIdP(t, row.opts), clock)
		})
	}
}

func answered(set url.Values, drop ...string) func(*testing.T, *accesstest.IdP, *testClock) {
	return func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
		t.Helper()
		answeredQuery(t, idp, authParams(idp, set, drop...))
	}
}

func answeredQuery(t *testing.T, idp *accesstest.IdP, q url.Values) {
	t.Helper()
	status, location := getNoRedirect(t, idp, idp.Issuer()+"/authorize?"+q.Encode())
	if status != http.StatusBadRequest || location != "" {
		t.Errorf("status %d, Location %q; want 400 and no redirect", status, location)
	}
}

func redirectsError(want string, set url.Values, drop ...string) func(*testing.T, *accesstest.IdP, *testClock) {
	return func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
		t.Helper()
		errorRedirect(t, idp, authParams(idp, set, drop...), want)
	}
}

func errorRedirect(t *testing.T, idp *accesstest.IdP, q url.Values, want string) {
	t.Helper()
	cb := authorizeRaw(t, idp, q)
	if cb.Get("error") != want || cb.Has("code") {
		t.Errorf("callback = %v, want error %q and no code", cb, want)
	}
}

func authTimeOf(t *testing.T, idp *accesstest.IdP, set url.Values) time.Time {
	t.Helper()
	_, c, _, _ := decodeJWS(t, issue(t, idp, set))
	return time.Unix(unix(t, c["auth_time"]), 0).UTC()
}

func signInAt(advance time.Duration, set url.Values, want time.Time) func(*testing.T, *accesstest.IdP, *testClock) {
	return func(t *testing.T, idp *accesstest.IdP, clock *testClock) {
		t.Helper()
		clock.advance(advance)
		if got := authTimeOf(t, idp, set); !got.Equal(want) {
			t.Errorf("auth_time = %v, want %v", got, want)
		}
	}
}

func authorizeClientClauses() []protocolClause {
	return []protocolClause{
		{
			name: "client_id_unknown_is_answered", clause: "RFC 6749 section 4.1.2.1: an invalid client_id is not redirected to",
			check: answered(url.Values{"client_id": {"other"}}),
		},
		{
			name: "client_id_repeated_is_answered", clause: "RFC 6749 sections 3.1 and 4.1.2.1: a repeated client_id leaves the client unknown",
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				answeredQuery(t, idp, authParams(idp, url.Values{"client_id": {idp.ClientID(), idp.ClientID()}}))
			},
		},
		{
			name: "redirect_uri_missing_is_answered", clause: "RFC 6749 section 4.1.2.1: a missing redirect_uri is not redirected to",
			check: answered(nil, "redirect_uri"),
		},
		{
			name: "redirect_uri_relative_is_answered", clause: "RFC 6749 section 3.1.2: the redirection endpoint is an absolute URI",
			check: answered(url.Values{"redirect_uri": {"/callback"}}),
		},
		{
			name: "redirect_uri_fragment_is_answered", clause: "RFC 6749 section 3.1.2: the redirection endpoint has no fragment",
			check: answered(url.Values{"redirect_uri": {testRedirectURI + "#frag"}}),
		},
		{
			name: "redirect_uri_repeated_is_answered", clause: "RFC 6749 sections 3.1 and 4.1.2.1: a repeated redirect_uri leaves the target unknown",
			check: answered(url.Values{"redirect_uri": {testRedirectURI, testRedirectURI}}),
		},
		{
			name: "configured_client_id_replaces_default", clause: "IdPOptions.ClientID is the one client /authorize accepts",
			opts: accesstest.IdPOptions{ClientID: "c2", ClientSecret: "s2"},
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				answeredQuery(t, idp, authParams(idp, url.Values{"client_id": {accesstest.DefaultIdPClientID}}))
				if cb := authorize(t, idp, url.Values{"client_id": {"c2"}}); cb.Get("code") == "" {
					t.Errorf("callback for c2 = %v, want a code", cb)
				}
			},
		},
	}
}

func authorizeResponseClauses() []protocolClause {
	return []protocolClause{
		{
			name: "success_carries_code_state_and_iss", clause: "RFC 6749 section 4.1.2 and RFC 9207 section 2",
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				cb := authorize(t, idp, nil)
				if cb.Get("code") == "" || cb.Get("state") != "state-1" || cb.Get("iss") != idp.Issuer() || cb.Has("error") {
					t.Errorf("callback = %v", cb)
				}
			},
		},
		{
			name: "error_carries_state_and_iss", clause: "RFC 6749 section 4.1.2.1 and RFC 9207 section 2: an error response echoes state and names the issuer",
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				cb := authorizeRaw(t, idp, authParams(idp, url.Values{"response_type": {"token"}}))
				if cb.Get("state") != "state-1" || cb.Get("iss") != idp.Issuer() {
					t.Errorf("callback = %v", cb)
				}
			},
		},
		{
			name: "redirect_uri_query_is_kept", clause: "RFC 6749 section 3.1.2: the redirection URI's query is retained",
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				cb := authorize(t, idp, url.Values{"redirect_uri": {testRedirectURI + "?keep=1"}})
				if cb.Get("keep") != "1" || cb.Get("code") == "" {
					t.Errorf("callback = %v", cb)
				}
			},
		},
		{
			name: "parameter_repeated_is_invalid_request", clause: "RFC 6749 sections 3.1 and 4.1.2.1: no parameter is sent twice",
			check: redirectsError("invalid_request", url.Values{"scope": {"openid", "email"}}),
		},
		{
			name: "empty_parameter_is_omitted", clause: "RFC 6749 section 3.1: a parameter sent without a value is treated as omitted",
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				for name, set := range map[string]url.Values{
					"max_age":              {"max_age": {""}},
					"code_challenge":       {"code_challenge": {""}},
					"challenge_and_method": {"code_challenge": {""}, "code_challenge_method": {""}},
					"beside_a_value":       {"max_age": {"", "3600"}},
				} {
					t.Run(name, func(t *testing.T) {
						if cb := authorize(t, idp, set); cb.Get("code") == "" || cb.Has("error") {
							t.Errorf("callback = %v, want a code", cb)
						}
					})
				}
			},
		},
		{
			name: "response_type_missing_is_invalid_request", clause: "RFC 6749 section 4.1.2.1: response_type is required",
			check: redirectsError("invalid_request", nil, "response_type"),
		},
		{
			name: "response_type_token_is_unsupported", clause: "RFC 6749 section 4.1.2.1: the IdP serves the code flow only",
			check: redirectsError("unsupported_response_type", url.Values{"response_type": {"token"}}),
		},
		{
			name: "nonce_is_echoed", clause: "OpenID Connect Core 1.0 section 2: the request's nonce is the ID token's",
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				if _, c, _, _ := decodeJWS(t, issue(t, idp, url.Values{"nonce": {"nonce-2"}})); c["nonce"] != "nonce-2" {
					t.Errorf("nonce = %v, want nonce-2", c["nonce"])
				}
			},
		},
		{
			name: "nonce_absent_when_not_requested", clause: "OpenID Connect Core 1.0 section 2: no nonce claim without a request nonce",
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				_, body := exchange(t, idp, codeForm(authorize(t, idp, nil).Get("code")))
				raw, _ := body["id_token"].(string)
				if _, c, _, _ := decodeJWS(t, raw); c["nonce"] != nil {
					t.Errorf("nonce = %v, want absent", c["nonce"])
				}
			},
		},
	}
}

func promptClauses() []protocolClause {
	const later = 10 * time.Minute
	return []protocolClause{
		{
			name: "prompt_absent_keeps_sign_in", clause: "OpenID Connect Core 1.0 section 3.1.2.1: without prompt or max_age the sign-in stands",
			check: signInAt(later, nil, idpT0),
		},
		{
			name: "prompt_login_signs_in_again", clause: "OpenID Connect Core 1.0 section 3.1.2.1: prompt=login re-authenticates",
			check: signInAt(later, url.Values{"prompt": {"login"}}, idpT0.Add(later)),
		},
		{
			name: "prompt_set_with_login_signs_in_again", clause: "OpenID Connect Core 1.0 section 3.1.2.1: prompt is a space-delimited list",
			check: signInAt(later, url.Values{"prompt": {"consent login"}}, idpT0.Add(later)),
		},
		{
			name: "prompt_consent_select_account_keep_sign_in", clause: "OpenID Connect Core 1.0 section 3.1.2.1: consent and select_account do not re-authenticate",
			check: signInAt(later, url.Values{"prompt": {"consent select_account"}}, idpT0),
		},
		{
			name: "prompt_unknown_value_is_ignored", clause: "OpenID Connect Core 1.0 section 3.1.2.1: an OP may ignore a prompt value it does not understand",
			check: signInAt(later, url.Values{"prompt": {"create"}}, idpT0),
		},
		{
			name: "prompt_none_beside_another_is_invalid_request", clause: "OpenID Connect Core 1.0 section 3.1.2.1: none with any other value is an error",
			check: redirectsError("invalid_request", url.Values{"prompt": {"none login"}}),
		},
		{
			name: "prompt_none_signed_in_grants", clause: "OpenID Connect Core 1.0 section 3.1.2.1: prompt=none succeeds for a signed-in user",
			check: signInAt(later, url.Values{"prompt": {"none"}}, idpT0),
		},
		{
			name: "prompt_none_needing_sign_in_is_login_required", clause: "OpenID Connect Core 1.0 sections 3.1.2.1 and 3.1.2.6: prompt=none cannot re-authenticate",
			check: func(t *testing.T, idp *accesstest.IdP, clock *testClock) {
				clock.advance(later)
				errorRedirect(t, idp, authParams(idp, url.Values{"prompt": {"none"}, "max_age": {"300"}}), "login_required")
				if got := authTimeOf(t, idp, nil); !got.Equal(idpT0) {
					t.Errorf("auth_time after the refusal = %v, want the unchanged %v", got, idpT0)
				}
			},
		},
	}
}

func maxAgeClauses() []protocolClause {
	const later = 10 * time.Minute
	return []protocolClause{
		{
			name: "max_age_outlived_signs_in_again", clause: "OpenID Connect Core 1.0 section 3.1.2.1: an elapsed time greater than max_age re-authenticates",
			check: signInAt(later, url.Values{"max_age": {"300"}}, idpT0.Add(later)),
		},
		{
			name: "max_age_within_keeps_sign_in", clause: "OpenID Connect Core 1.0 section 3.1.2.1: a sign-in younger than max_age stands",
			check: signInAt(time.Minute, url.Values{"max_age": {"3600"}}, idpT0),
		},
		{
			name: "max_age_equal_to_elapsed_keeps_sign_in", clause: "OpenID Connect Core 1.0 section 3.1.2.1: only an elapsed time greater than max_age re-authenticates",
			check: signInAt(300*time.Second, url.Values{"max_age": {"300"}}, idpT0),
		},
		{
			name: "max_age_zero_is_prompt_login", clause: "OpenID Connect Core 1.0 section 3.1.2.1: max_age=0 is equivalent to prompt=login",
			check: redirectsError("login_required", url.Values{"prompt": {"none"}, "max_age": {"0"}}),
		},
		{
			name: "max_age_beyond_int64_keeps_sign_in", clause: "OpenID Connect Core 1.0 section 3.1.2.1: max_age is a count of seconds, however large",
			check: signInAt(later, url.Values{"max_age": {"99999999999999999999"}}, idpT0),
		},
		{
			name: "max_age_beyond_duration_keeps_sign_in", clause: "OpenID Connect Core 1.0 section 3.1.2.1: max_age is a count of seconds, however large",
			check: signInAt(later, url.Values{"max_age": {"10000000000"}}, idpT0),
		},
		{
			name: "max_age_malformed_is_invalid_request", clause: "OpenID Connect Core 1.0 section 3.1.2.1: max_age is a non-negative count of seconds",
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				for name, v := range map[string]string{"letters": "abc", "negative": "-1", "plus_sign": "+5", "fraction": "1.5", "space": " 5"} {
					t.Run(name, func(t *testing.T) {
						errorRedirect(t, idp, authParams(idp, url.Values{"max_age": {v}}), "invalid_request")
					})
				}
			},
		},
	}
}

func s256(verifier string) url.Values {
	return url.Values{"code_challenge": {oauth2.S256ChallengeFromVerifier(verifier)}, "code_challenge_method": {"S256"}}
}

func redeemsWith(set url.Values, verifier string, wantStatus int, wantError string) func(*testing.T, *accesstest.IdP, *testClock) {
	return func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
		t.Helper()
		form := codeForm(authorize(t, idp, set).Get("code"))
		if verifier != "" {
			form.Set("code_verifier", verifier)
		}
		status, body := exchange(t, idp, form)
		if status != wantStatus || (wantError != "" && body["error"] != wantError) {
			t.Errorf("token = %d %v, want %d %q", status, body, wantStatus, wantError)
		}
	}
}

func pkceClauses() []protocolClause {
	verifier := oauth2.GenerateVerifier()
	short := "short-verifier"
	plus := strings.Repeat("a", 42) + "+"
	longest := strings.Repeat("aB3-_", 25) + "xyz"
	long := longest + "q"
	dotTilde := strings.Repeat("a", 41) + ".~"
	return []protocolClause{
		{
			name: "pkce_s256_verifier_redeems", clause: "RFC 7636 sections 4.3 and 4.6: S256 of the verifier matches the challenge",
			check: redeemsWith(s256(verifier), verifier, http.StatusOK, ""),
		},
		{
			name: "pkce_plain_is_invalid_request", clause: "RFC 7636 section 4.3: the IdP supports S256 only, so plain is refused",
			check: redirectsError("invalid_request", url.Values{"code_challenge": {verifier}, "code_challenge_method": {"plain"}}),
		},
		{
			name: "pkce_challenge_without_method_is_invalid_request", clause: "RFC 7636 section 4.3: a challenge without a method is plain, which the IdP refuses",
			check: redirectsError("invalid_request", url.Values{"code_challenge": {oauth2.S256ChallengeFromVerifier(verifier)}}),
		},
		{
			name: "pkce_method_without_challenge_is_invalid_request", clause: "RFC 7636 section 4.3: code_challenge is required with a method",
			check: redirectsError("invalid_request", url.Values{"code_challenge_method": {"S256"}}),
		},
		{
			name: "pkce_unknown_method_is_invalid_request", clause: "RFC 7636 section 4.3: S256 is the one method",
			check: redirectsError("invalid_request", url.Values{"code_challenge": {oauth2.S256ChallengeFromVerifier(verifier)}, "code_challenge_method": {"S512"}}),
		},
		{
			name: "pkce_malformed_challenge_is_invalid_request", clause: "RFC 7636 section 4.2: an S256 challenge is the base64url of a SHA-256 digest",
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				for name, c := range map[string]string{"short": "abc", "not_base64url": strings.Repeat("!", 43), "padded": oauth2.S256ChallengeFromVerifier(verifier) + "="} {
					t.Run(name, func(t *testing.T) {
						errorRedirect(t, idp, authParams(idp, url.Values{"code_challenge": {c}, "code_challenge_method": {"S256"}}), "invalid_request")
					})
				}
			},
		},
		{
			name: "pkce_wrong_verifier_is_invalid_grant", clause: "RFC 7636 section 4.6: a verifier whose S256 differs is invalid_grant",
			check: redeemsWith(s256(verifier), oauth2.GenerateVerifier(), http.StatusBadRequest, "invalid_grant"),
		},
		{
			name: "pkce_missing_verifier_is_invalid_grant", clause: "RFC 7636 sections 4.5 and 4.6: a PKCE code needs its verifier",
			check: redeemsWith(s256(verifier), "", http.StatusBadRequest, "invalid_grant"),
		},
		{
			name: "pkce_verifier_without_challenge_is_invalid_grant", clause: "RFC 7636 section 4.6: a code granted without a challenge takes no verifier",
			check: redeemsWith(nil, verifier, http.StatusBadRequest, "invalid_grant"),
		},
		{
			name: "pkce_short_verifier_is_invalid_grant", clause: "RFC 7636 section 4.1: a verifier has 43 to 128 characters",
			check: redeemsWith(s256(short), short, http.StatusBadRequest, "invalid_grant"),
		},
		{
			name: "pkce_long_verifier_is_invalid_grant", clause: "RFC 7636 section 4.1: a verifier has at most 128 characters",
			check: redeemsWith(s256(long), long, http.StatusBadRequest, "invalid_grant"),
		},
		{
			name: "pkce_128_character_verifier_redeems", clause: "RFC 7636 section 4.1: a 128-character verifier is in range",
			check: redeemsWith(s256(longest), longest, http.StatusOK, ""),
		},
		{
			name: "pkce_verifier_with_dot_and_tilde_redeems", clause: "RFC 7636 section 4.1: unreserved includes \".\" and \"~\"",
			check: redeemsWith(s256(dotTilde), dotTilde, http.StatusOK, ""),
		},
		{
			name: "pkce_verifier_outside_alphabet_is_invalid_grant", clause: "RFC 7636 section 4.1: a verifier is unreserved characters only",
			check: redeemsWith(s256(plus), plus, http.StatusBadRequest, "invalid_grant"),
		},
		{
			name: "discovery_advertises_s256_only", clause: "RFC 8414 section 2: code_challenge_methods_supported lists what the IdP accepts",
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				resp, err := idp.Client().Get(idp.Issuer() + "/.well-known/openid-configuration")
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				var doc struct {
					Methods []string `json:"code_challenge_methods_supported"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || len(doc.Methods) != 1 || doc.Methods[0] != "S256" {
					t.Errorf("code_challenge_methods_supported = %v, %v; want [S256]", doc.Methods, err)
				}
			},
		},
	}
}

func tokenAnswer(edit func(url.Values), basic func(*accesstest.IdP) *basicAuth, wantStatus int, wantError string) func(*testing.T, *accesstest.IdP, *testClock) {
	return func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
		t.Helper()
		form := codeForm(authorize(t, idp, nil).Get("code"))
		if edit != nil {
			edit(form)
		}
		status, body := postToken(t, idp, form, basic(idp))
		if status != wantStatus || (wantError != "" && body["error"] != wantError) {
			t.Errorf("token = %d %v, want %d %q", status, body, wantStatus, wantError)
		}
	}
}

func ownClient(idp *accesstest.IdP) *basicAuth { return &basicAuth{idp.ClientID(), idp.ClientSecret()} }
func noBasic(*accesstest.IdP) *basicAuth       { return nil }

func postCredentials(idp *accesstest.IdP, secret string) func(url.Values) {
	return func(form url.Values) {
		form.Set("client_id", idp.ClientID())
		form.Set("client_secret", secret)
	}
}

func tokenClauses() []protocolClause {
	return []protocolClause{
		{
			name: "code_is_single_use", clause: "RFC 6749 section 4.1.2: a code is used once",
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				code := authorize(t, idp, nil).Get("code")
				if status, _ := exchange(t, idp, codeForm(code)); status != http.StatusOK {
					t.Fatalf("first redemption status = %d", status)
				}
				if status, body := exchange(t, idp, codeForm(code)); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
					t.Errorf("second redemption = %d %v", status, body)
				}
			},
		},
		{
			name: "code_unknown_is_invalid_grant", clause: "RFC 6749 section 5.2: an unknown code is invalid_grant",
			check: tokenAnswer(func(f url.Values) { f.Set("code", "nope") }, ownClient, http.StatusBadRequest, "invalid_grant"),
		},
		{
			name: "redirect_uri_mismatch_is_invalid_grant", clause: "RFC 6749 section 4.1.3: redirect_uri is identical to the authorization request's",
			check: tokenAnswer(func(f url.Values) { f.Set("redirect_uri", "https://app.example/other") }, ownClient, http.StatusBadRequest, "invalid_grant"),
		},
		{
			name: "grant_type_other_is_unsupported", clause: "RFC 6749 section 5.2: the IdP grants authorization_code only",
			check: tokenAnswer(func(f url.Values) { f.Set("grant_type", "refresh_token") }, ownClient, http.StatusBadRequest, "unsupported_grant_type"),
		},
		{
			name: "token_parameter_repeated_is_invalid_request", clause: "RFC 6749 sections 3.2 and 5.2: no parameter is sent twice",
			check: tokenAnswer(func(f url.Values) { f.Add("redirect_uri", testRedirectURI) }, ownClient, http.StatusBadRequest, "invalid_request"),
		},
		{
			name: "client_secret_basic_is_form_encoded", clause: "RFC 6749 section 2.3.1: basic credentials are form-encoded before base64",
			opts:  accesstest.IdPOptions{ClientID: "client:1", ClientSecret: "s 2%/"},
			check: tokenAnswer(nil, ownClient, http.StatusOK, ""),
		},
		{
			name: "client_secret_post_authenticates", clause: "RFC 6749 section 2.3.1: credentials in the request body",
			check: func(t *testing.T, idp *accesstest.IdP, c *testClock) {
				tokenAnswer(postCredentials(idp, idp.ClientSecret()), noBasic, http.StatusOK, "")(t, idp, c)
			},
		},
		{
			name: "wrong_secret_is_invalid_client", clause: "RFC 6749 section 5.2: failed client authentication is invalid_client",
			check: func(t *testing.T, idp *accesstest.IdP, c *testClock) {
				tokenAnswer(postCredentials(idp, "wrong"), noBasic, http.StatusUnauthorized, "invalid_client")(t, idp, c)
			},
		},
		{
			name: "no_client_authentication_is_invalid_client", clause: "RFC 6749 sections 4.1.3 and 5.2: a confidential client authenticates",
			check: tokenAnswer(nil, noBasic, http.StatusUnauthorized, "invalid_client"),
		},
		{
			name: "empty_client_secret_beside_basic_is_omitted", clause: "RFC 6749 section 3.2: a parameter sent without a value is treated as omitted",
			check: tokenAnswer(func(f url.Values) { f.Set("client_secret", "") }, ownClient, http.StatusOK, ""),
		},
		{
			name: "two_client_auth_methods_are_invalid_request", clause: "RFC 6749 section 2.3: one authentication method per request",
			check: func(t *testing.T, idp *accesstest.IdP, c *testClock) {
				tokenAnswer(postCredentials(idp, idp.ClientSecret()), ownClient, http.StatusBadRequest, "invalid_request")(t, idp, c)
			},
		},
		{
			name: "configured_client_secret_replaces_default", clause: "IdPOptions.ClientSecret is the one secret /token accepts",
			opts: accesstest.IdPOptions{ClientID: "c2", ClientSecret: "s2"},
			check: func(t *testing.T, idp *accesstest.IdP, c *testClock) {
				tokenAnswer(nil, func(*accesstest.IdP) *basicAuth { return &basicAuth{"c2", accesstest.DefaultIdPClientSecret} }, http.StatusUnauthorized, "invalid_client")(t, idp, c)
				tokenAnswer(nil, func(*accesstest.IdP) *basicAuth { return &basicAuth{"c2", "s2"} }, http.StatusOK, "")(t, idp, c)
			},
		},
	}
}

// discoveryUnder fetches discovery under base and requires issuer and the
// three endpoints under base.
func discoveryUnder(issuer, base string) func(*testing.T, *accesstest.IdP, *testClock) {
	return func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
		t.Helper()
		if idp.Issuer() != issuer {
			t.Errorf("Issuer() = %q, want %q", idp.Issuer(), issuer)
		}
		resp, err := idp.Client().Get(base + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var doc map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("discovery under %s: status %d, %v", base, resp.StatusCode, err)
		}
		if doc["issuer"] != issuer {
			t.Errorf("issuer = %v, want %q", doc["issuer"], issuer)
		}
		for k, path := range map[string]string{"authorization_endpoint": "/authorize", "token_endpoint": "/token", "jwks_uri": "/jwks"} {
			if doc[k] != base+path {
				t.Errorf("%s = %v, want %q", k, doc[k], base+path)
			}
		}
	}
}

func urlClauses() []protocolClause {
	withURL := accesstest.IdPOptions{URL: testIdPURL}
	return []protocolClause{
		{
			name: "url_is_discovery_issuer_and_endpoint_base", clause: "OpenID Connect Discovery 1.0 sections 3 and 4.3: issuer is the URL discovery is fetched under",
			opts: withURL, check: discoveryUnder(testIdPURL, testIdPURL),
		},
		{
			name: "url_path_prefixes_every_endpoint", clause: "OpenID Connect Discovery 1.0 section 4.1: an issuer's path precedes /.well-known",
			opts: accesstest.IdPOptions{URL: testIdPURL + "/realms/main"}, check: discoveryUnder(testIdPURL+"/realms/main", testIdPURL+"/realms/main"),
		},
		{
			name: "url_final_slash_is_removed_before_endpoints", clause: "OpenID Connect Discovery 1.0 section 4.1: a terminating / is removed before appending",
			opts: accesstest.IdPOptions{URL: testIdPURL + "/app/"}, check: discoveryUnder(testIdPURL+"/app/", testIdPURL+"/app"),
		},
		{
			name: "url_is_iss_claim", clause: "OpenID Connect Core 1.0 section 2: iss is the issuer identifier",
			opts: withURL,
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				if _, c, _, _ := decodeJWS(t, issue(t, idp, nil)); c["iss"] != testIdPURL {
					t.Errorf("iss = %v, want %q", c["iss"], testIdPURL)
				}
			},
		},
		{
			name: "url_is_authorization_response_iss", clause: "RFC 9207 section 2: the authorization response names the issuer",
			opts: withURL,
			check: func(t *testing.T, idp *accesstest.IdP, _ *testClock) {
				if cb := authorize(t, idp, nil); cb.Get("iss") != testIdPURL {
					t.Errorf("callback iss = %q, want %q", cb.Get("iss"), testIdPURL)
				}
			},
		},
		{
			name: "url_shared_by_two_fakes_each_reached_by_its_client", clause: "IdPOptions.URL: IdP.Client dials its own listener for URL",
			opts: withURL,
			check: func(t *testing.T, idp *accesstest.IdP, clock *testClock) {
				other := accesstest.NewIdP(t, accesstest.IdPOptions{URL: testIdPURL, ClientID: "other-client", Now: clock.now})
				authorize(t, idp, nil)
				authorize(t, other, nil)
				authorize(t, other, nil)
				if a, b := len(idp.Authorizations()), len(other.Authorizations()); a != 1 || b != 2 {
					t.Errorf("Authorizations: %d and %d, want 1 and 2", a, b)
				}
			},
		},
	}
}
