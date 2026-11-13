package access

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// apiKeyVerifier authenticates a request by its Authorization: Bearer key.
// [New] builds it over the Authenticator's own configuration.
type apiKeyVerifier struct {
	store AuthenticatorStore
	cfg   *Config
	// now is the verifier's only clock.
	now  func() time.Time
	warn warnLimiter
}

// Verify grants the key in r's one Authorization: Bearer header. Another
// scheme, or no single Authorization header, is not its credential. A key it
// cannot use is [ErrInvalidCredential] with [MethodAPIKey]; a value
// [GenerateAPIKey] cannot return is refused so with no store read. A store
// error is [ErrAuthBackend]. Keys are never read from a URL query parameter,
// which leaks into access logs, browser history and the Referer header
// (CWE-598).
func (v *apiKeyVerifier) Verify(ctx context.Context, r *http.Request) (Principal, bool, error) {
	key, ok := bearerToken(r)
	if !ok {
		return Principal{}, false, nil
	}
	if !parseAPIKey(key) {
		v.cfg.log().Debug("access: Bearer value is not an API key")
		return Principal{}, false, &InvalidCredentialError{Err: ErrInvalidAPIKey, Method: MethodAPIKey}
	}
	now := v.now()
	hash := APIKeyHash(key)
	k, user, err := v.resolve(ctx, hash, now)
	if err != nil {
		return Principal{}, false, err
	}
	// The stored LastUsedAt is the throttle's only state, so a failed touch
	// is retried by the next request.
	if !IsPassive(ctx) && now.Sub(k.LastUsedAt) >= v.cfg.ActivityThrottle {
		if err := v.store.TouchAPIKey(ctx, k.ID, hash, now); err != nil {
			v.warn.log(v.cfg.log(), "access: API key touch failed", "key_id", k.ID, "error", err)
		}
	}
	return keyPrincipal(k, user, hash), true, nil
}

// recheck re-reads p's key and user and returns its principal anew, writing
// nothing.
func (v *apiKeyVerifier) recheck(ctx context.Context, p *Principal) (Principal, error) {
	k, user, err := v.resolve(ctx, p.credential, v.now())
	if err != nil {
		return Principal{}, err
	}
	return keyPrincipal(k, user, p.credential), nil
}

// resolve reads the key stored under hash and its user, and refuses either
// at now. A refusal names the key by its KeyID only once the store found it.
func (v *apiKeyVerifier) resolve(ctx context.Context, hash Hash, now time.Time) (*Key, *User, error) {
	key, err := findAPIKey(ctx, v.store, hash)
	if errors.Is(err, ErrInvalidAPIKey) {
		v.cfg.log().Debug("access: API key not found")
		return nil, nil, &InvalidCredentialError{Err: ErrInvalidAPIKey, Method: MethodAPIKey}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrAuthBackend, err)
	}
	if keyExpired(key, now) {
		v.cfg.log().Debug("access: API key expired", "key_id", key.ID)
		return nil, nil, &InvalidCredentialError{Err: ErrInvalidAPIKey, Method: MethodAPIKey, KeyID: key.ID}
	}
	user, found, err := v.store.UserByID(ctx, key.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrAuthBackend, err)
	}
	if !found || user == nil || !user.Enabled {
		v.cfg.log().Debug("access: API key resolved to missing or disabled user", "key_id", key.ID, "user_id", key.UserID)
		return nil, nil, &InvalidCredentialError{Err: ErrAccountDisabled, Method: MethodAPIKey, KeyID: key.ID}
	}
	return key, user, nil
}

func keyPrincipal(key *Key, user *User, hash Hash) Principal {
	return Principal{
		User:             user,
		Method:           MethodAPIKey,
		KeyID:            key.ID,
		Scopes:           key.Scopes,
		AbsoluteDeadline: key.ExpiresAt,
		credential:       hash,
		source:           sourceAPIKey,
	}
}

// findAPIKey returns the key stored under hash, or [ErrInvalidAPIKey] when
// the store finds none, answers found with a nil key, or holds another hash.
// A store error is returned as is.
func findAPIKey(ctx context.Context, store APIKeyReader, hash Hash) (*Key, error) {
	key, found, err := store.APIKeyByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	if !found || key == nil {
		return nil, ErrInvalidAPIKey
	}
	// A store doing a loose or prefix lookup cannot match another key.
	if !hash.Equal(key.KeyHash) {
		return nil, ErrInvalidAPIKey
	}
	return key, nil
}

// keyExpired reports a key whose ExpiresAt is set and not after now.
func keyExpired(key *Key, now time.Time) bool {
	return !key.ExpiresAt.IsZero() && !now.Before(key.ExpiresAt)
}

// bearerToken returns the credential of r's one Authorization header when
// its scheme is Bearer, compared case-insensitively (RFC 9110 §11.1,
// RFC 6750 §2.1).
func bearerToken(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	token = strings.TrimLeft(token, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}
