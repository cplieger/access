package oidc

import (
	"crypto/subtle"
	"encoding/json/jsontext"
	"fmt"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc/internal/jsonmember"
)

// claimRules are what an ID token's claims are checked against.
type claimRules struct {
	now      time.Time
	issuer   string
	clientID string
	nonce    string
	flow     Flow
}

const (
	// tokenSkew is the clock difference exp, iat and nbf tolerate between
	// the provider and this host: go-oidc's nbf leeway and
	// Microsoft.IdentityModel's default ClockSkew.
	tokenSkew = 5 * time.Minute
	// authTimeSkew is the clock difference the freshness check tolerates.
	authTimeSkew = 60 * time.Second
	// maxSubjectBytes is OpenID Connect Core 1.0 §2's bound on sub.
	maxSubjectBytes = 255
)

// Google documents both forms as its ID tokens' iss:
// https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken
const (
	googleIssuer         = "https://accounts.google.com"
	googleIssuerNoScheme = "accounts.google.com"
)

// idClaims are the claims checkIDToken compares, each read by its kind.
type idClaims struct {
	exp, iat, nbf   time.Time
	iss, sub, nonce string
	azp             string
	aud             []string
	hasAZP, hasNBF  bool
}

// checkIDToken checks payload, a verified JWS payload, as an ID token
// (OpenID Connect Core 1.0 §2, §3.1.3.7 steps 2 to 12) and decodes its
// Claims. Every claim is read and type-checked before any is compared. A
// malformed or failing claim is ErrTokenInvalid, a nonce that is a string
// other than the sealed one ErrNonceMismatch, and any intent but sign-in whose
// auth_time is absent or before the flow began ErrStaleAuthentication.
func checkIDToken(payload []byte, r *claimRules) (Claims, error) {
	m, err := jsonmember.Object(payload)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: payload: %w", ErrTokenInvalid, err)
	}
	ic, err := readIDClaims(m)
	if err != nil {
		return Claims{}, err
	}
	c, err := decodeClaims(m)
	if err != nil {
		return Claims{}, err
	}
	if err := r.compare(&ic); err != nil {
		return Claims{}, err
	}
	if r.flow.Intent != IntentSignIn && (c.AuthTime.IsZero() || c.AuthTime.Before(r.flow.BeganAt.Add(-authTimeSkew))) {
		return Claims{}, ErrStaleAuthentication
	}
	c.Identity = access.OIDCIdentity{Issuer: r.issuer, Subject: ic.sub}
	return c, nil
}

// readIDClaims reads, by kind, the claims Core 1.0 §2 and §3.1.3.7 require or
// bound: a missing required claim, or one of the wrong kind, null included
// except on nbf, is ErrTokenInvalid.
func readIDClaims(m map[string]jsontext.Value) (idClaims, error) {
	var ic idClaims
	if err := ic.readParties(m); err != nil {
		return idClaims{}, err
	}
	var ok bool
	if ic.exp, ok = jsonmember.NumericDate(m["exp"]); !ok {
		return idClaims{}, fmt.Errorf("%w: exp is not a NumericDate", ErrTokenInvalid)
	}
	if ic.iat, ok = jsonmember.NumericDate(m["iat"]); !ok {
		return idClaims{}, fmt.Errorf("%w: iat is not a NumericDate", ErrTokenInvalid)
	}
	if v, present := nonNull(m, "nbf"); present {
		if ic.nbf, ok = jsonmember.NumericDate(v); !ok {
			return idClaims{}, fmt.Errorf("%w: nbf is not a NumericDate", ErrTokenInvalid)
		}
		ic.hasNBF = true
	}
	return ic, nil
}

// readParties reads iss, sub, aud, azp and nonce.
func (ic *idClaims) readParties(m map[string]jsontext.Value) error {
	var ok bool
	if ic.iss, ok = jsonmember.String(m["iss"]); !ok {
		return fmt.Errorf("%w: iss is not a string", ErrTokenInvalid)
	}
	if ic.sub, ok = jsonmember.String(m["sub"]); !ok || !validSubject(ic.sub) {
		return fmt.Errorf("%w: sub is not 1 to %d printable ASCII characters", ErrTokenInvalid, maxSubjectBytes)
	}
	if one, isString := jsonmember.String(m["aud"]); isString {
		ic.aud = []string{one}
	} else if ic.aud, ok = jsonmember.Strings(m["aud"]); !ok || len(ic.aud) == 0 {
		return fmt.Errorf("%w: aud is not a string or a non-empty array of strings", ErrTokenInvalid)
	}
	if v, present := m["azp"]; present {
		if ic.azp, ok = jsonmember.String(v); !ok {
			return fmt.Errorf("%w: azp is not a string", ErrTokenInvalid)
		}
		ic.hasAZP = true
	}
	if ic.nonce, ok = jsonmember.String(m["nonce"]); !ok {
		return fmt.Errorf("%w: nonce is not a string", ErrTokenInvalid)
	}
	return nil
}

// nonNull is m's member name when it is present and not null, the claims
// that read null as absent.
func nonNull(m map[string]jsontext.Value, name string) (jsontext.Value, bool) {
	v, present := m[name]
	return v, present && v.Kind() != 'n'
}

// compare runs steps 2 to 5 and 9 to 11 on claims readIDClaims read. Every
// audience must be this client, so no other audience is trusted.
func (r *claimRules) compare(ic *idClaims) error {
	if ic.iss != r.issuer && (r.issuer != googleIssuer || ic.iss != googleIssuerNoScheme) {
		return fmt.Errorf("%w: iss is not the issuer", ErrTokenInvalid)
	}
	for _, a := range ic.aud {
		if a != r.clientID {
			return fmt.Errorf("%w: aud holds another client", ErrTokenInvalid)
		}
	}
	if ic.hasAZP && ic.azp != r.clientID {
		return fmt.Errorf("%w: azp is not the client ID", ErrTokenInvalid)
	}
	latest := r.now.Add(tokenSkew)
	switch {
	case !r.now.Before(ic.exp.Add(tokenSkew)):
		return fmt.Errorf("%w: exp is past", ErrTokenInvalid)
	case ic.iat.After(latest):
		return fmt.Errorf("%w: iat is ahead", ErrTokenInvalid)
	case ic.hasNBF && ic.nbf.After(latest):
		return fmt.Errorf("%w: nbf is ahead", ErrTokenInvalid)
	}
	if subtle.ConstantTimeCompare([]byte(ic.nonce), []byte(r.nonce)) != 1 {
		return ErrNonceMismatch
	}
	return nil
}

// validSubject reports a sub of 1 to 255 ASCII characters with no control
// character (Core §2; RFC 20 §5.2).
func validSubject(sub string) bool {
	if sub == "" || len(sub) > maxSubjectBytes {
		return false
	}
	for i := range len(sub) {
		if sub[i] < 0x20 || sub[i] > 0x7e {
			return false
		}
	}
	return true
}

// decodeClaims reads Claims' profile fields and auth_time from m, each
// null reading as absent, and keeps m as Raw.
func decodeClaims(m map[string]jsontext.Value) (Claims, error) {
	c := Claims{Raw: m}
	for name, dst := range map[string]*string{claimEmail: &c.Email, claimPreferredUsername: &c.PreferredUsername, "name": &c.Name} {
		v, present := nonNull(m, name)
		var ok bool
		if *dst, ok = jsonmember.String(v); present && !ok {
			return Claims{}, fmt.Errorf("%w: claim %s is not a string", ErrTokenInvalid, name)
		}
	}
	var ok bool
	if v, present := nonNull(m, "email_verified"); present {
		if c.EmailVerified, ok = emailVerified(v); !ok {
			return Claims{}, fmt.Errorf("%w: email_verified is neither a boolean nor \"true\" or \"false\"", ErrTokenInvalid)
		}
	}
	if v, present := nonNull(m, "auth_time"); present {
		if c.AuthTime, ok = jsonmember.NumericDate(v); !ok {
			return Claims{}, fmt.Errorf("%w: auth_time is not a NumericDate", ErrTokenInvalid)
		}
	}
	return c, nil
}

// emailVerified reads a JSON boolean, or the string "true" or "false",
// which some providers send (Google's own example ID token does).
func emailVerified(v jsontext.Value) (verified, ok bool) {
	if b, ok := jsonmember.Bool(v); ok {
		return b, true
	}
	s, _ := jsonmember.String(v)
	return s == "true", s == "true" || s == "false"
}
