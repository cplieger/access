package oidc

import (
	"encoding/json"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc/internal/jsonmember"
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
// and for any other shape, null included.
func (c Claims) Strings(name string) ([]string, bool) { //nolint:gocritic // hugeParam: a value receiver keeps it callable on a non-addressable Claims
	v := c.Raw[name]
	if one, ok := jsonmember.String(v); ok {
		return []string{one}, true
	}
	return jsonmember.Strings(v)
}

// The claims UsernameCandidate reads.
const (
	claimEmail             = "email"
	claimPreferredUsername = "preferred_username"
)

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
