package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cplieger/access"
)

// Claims are the claims of an ID token Finish verified.
type Claims struct {
	// AuthTime is the auth_time claim, zero when the token has none.
	AuthTime time.Time
	// Raw holds every verified claim, by name.
	Raw               map[string]json.RawMessage
	Identity          access.OIDCIdentity
	Email             string
	PreferredUsername string
	Name              string
	// EmailVerified is decoded from a JSON boolean or the strings "true"
	// and "false", which some providers send.
	EmailVerified bool
}

// Strings reads a claim that is a string or an array of strings, the two
// shapes providers use for groups. It reports false for an absent claim
// and for any other shape.
func (c Claims) Strings(name string) ([]string, bool) { //nolint:gocritic // hugeParam: a value receiver keeps it callable on a non-addressable Claims
	raw, present := c.Raw[name]
	if !present {
		return nil, false
	}
	var one string
	if !isNull(raw) && json.Unmarshal(raw, &one) == nil {
		return []string{one}, true
	}
	var elems []json.RawMessage
	if json.Unmarshal(raw, &elems) != nil || elems == nil {
		return nil, false
	}
	out := make([]string, len(elems))
	for i, e := range elems {
		if isNull(e) || json.Unmarshal(e, &out[i]) != nil {
			return nil, false
		}
	}
	return out, true
}

// isNull reports a JSON null, which json.Unmarshal accepts into any type
// without error.
func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// The claims UsernameCandidate reads.
const (
	claimEmail             = "email"
	claimPreferredUsername = "preferred_username"
)

// largestUnixSecond is 9999-12-31T23:59:59Z, the last instant time.Time
// formats as a four-digit year.
const largestUnixSecond = 253402300799

// decodeClaims reads Claims' typed fields from raw. A string claim that is
// present and not null must be a JSON string, auth_time a non-negative
// number of seconds; the identity is the caller's, from the verified token.
func decodeClaims(raw map[string]json.RawMessage) (Claims, error) {
	c := Claims{Raw: raw}
	for name, dst := range map[string]*string{claimEmail: &c.Email, claimPreferredUsername: &c.PreferredUsername, "name": &c.Name} {
		if v, present := raw[name]; present && !isNull(v) {
			if err := json.Unmarshal(v, dst); err != nil {
				return Claims{}, fmt.Errorf("%w: claim %s is not a string", ErrTokenInvalid, name)
			}
		}
	}
	if v, present := raw["email_verified"]; present {
		verified, err := decodeEmailVerified(v)
		if err != nil {
			return Claims{}, err
		}
		c.EmailVerified = verified
	}
	if v, present := raw["auth_time"]; present && !isNull(v) {
		var sec float64
		if err := json.Unmarshal(v, &sec); err != nil || sec < 0 || sec > largestUnixSecond {
			return Claims{}, fmt.Errorf("%w: auth_time is not a time", ErrTokenInvalid)
		}
		c.AuthTime = time.Unix(int64(sec), 0)
	}
	return c, nil
}

// decodeEmailVerified accepts null as false, a JSON boolean, and the strings
// "true" and "false"; anything else is a token fault.
func decodeEmailVerified(raw json.RawMessage) (bool, error) {
	if isNull(raw) {
		return false, nil
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && (s == "true" || s == "false") {
		return s == "true", nil
	}
	return false, fmt.Errorf("%w: email_verified is neither a boolean nor \"true\" or \"false\"", ErrTokenInvalid)
}

// UsernameCandidate is preferred_username when present, else email when
// email_verified, normalised by access.NormalizeUsername. It returns
// ErrNoUsername when neither applies, and a *UsernameError naming the claim
// when the chosen one does not normalise; it never falls back from a refused
// preferred_username to the email.
func UsernameCandidate(c Claims) (string, error) { //nolint:gocritic // hugeParam: Claims is plain data, passed as the caller holds it
	claim, value := claimPreferredUsername, c.PreferredUsername
	if value == "" {
		if c.Email == "" || !c.EmailVerified {
			return "", ErrNoUsername
		}
		claim, value = claimEmail, c.Email
	}
	name, err := access.NormalizeUsername(value)
	if err != nil {
		return "", &UsernameError{Claim: claim, Err: err}
	}
	return name, nil
}
