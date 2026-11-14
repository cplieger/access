package access

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cplieger/access/internal/failreason"
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
		return Principal{}, false, failreason.Wrap(&InvalidCredentialError{Err: ErrInvalidAPIKey, Method: MethodAPIKey}, failreason.KeyUnknown)
	}
	now := v.now()
	hash := APIKeyHash(key)
	k, user, previous, err := v.resolve(ctx, hash, now)
	if err != nil {
		return Principal{}, false, err
	}
	if !previous {
		if err := v.touch(ctx, k, hash, now); err != nil {
			return Principal{}, false, err
		}
	}
	return keyPrincipal(k, user, hash, previous), true, nil
}

// touch records a use of k's current secret once the stored LastUsedAt is
// the throttle old; the stored time is the throttle's only state, so a
// failed touch is retried by the next request. A first use is written
// whatever the throttle and [Passive] say, because it ends a rotation's
// overlap. While the previous secret still verifies, a failed first touch
// refuses the request, so no client sees the new secret work while the old
// one still does.
func (v *apiKeyVerifier) touch(ctx context.Context, k *Key, hash Hash, now time.Time) error {
	if !k.LastUsedAt.IsZero() && (IsPassive(ctx) || now.Sub(k.LastUsedAt) < v.cfg.ActivityThrottle) {
		return nil
	}
	err := v.store.TouchAPIKey(ctx, k.ID, hash, now)
	switch {
	case err == nil:
		return nil
	case k.PreviousSecretUsable(now):
		return fmt.Errorf("%w: %w", ErrAuthBackend, err)
	default:
		v.warn.log(v.cfg.log(), "access: API key touch failed", "key_id", k.ID, "error", err)
		return nil
	}
}

// recheck re-reads p's key and user and returns its principal anew by the
// presented hash, writing nothing.
func (v *apiKeyVerifier) recheck(ctx context.Context, p *Principal) (Principal, error) {
	k, user, previous, err := v.resolve(ctx, p.credential, v.now())
	if err != nil {
		return Principal{}, err
	}
	return keyPrincipal(k, user, p.credential, previous), nil
}

// resolve reads the key stored under hash and its user, and refuses either
// at now; previous reports that hash is the key's previous secret. A refusal
// names the key by its KeyID only once the store found it, and carries its
// audit reason.
func (v *apiKeyVerifier) resolve(ctx context.Context, hash Hash, now time.Time) (key *Key, user *User, previous bool, err error) {
	key, previous, err = findAPIKey(ctx, v.store, hash)
	if errors.Is(err, ErrInvalidAPIKey) {
		v.cfg.log().Debug("access: API key not found")
		return nil, nil, false, failreason.Wrap(&InvalidCredentialError{Err: ErrInvalidAPIKey, Method: MethodAPIKey}, failreason.KeyUnknown)
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrAuthBackend, err)
	}
	refuse := func(cause error, reason string) error {
		return failreason.Wrap(&InvalidCredentialError{Err: cause, Method: MethodAPIKey, KeyID: key.ID}, reason)
	}
	if keyExpired(key, now) {
		v.cfg.log().Debug("access: API key expired", "key_id", key.ID)
		return nil, nil, false, refuse(ErrInvalidAPIKey, failreason.KeyExpired)
	}
	if previous && !key.PreviousSecretUsable(now) {
		v.cfg.log().Debug("access: API key previous secret retired", "key_id", key.ID)
		return nil, nil, false, refuse(ErrInvalidAPIKey, failreason.KeyRetired)
	}
	user, found, err := v.store.UserByID(ctx, key.UserID)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrAuthBackend, err)
	}
	if !found || user == nil || !user.Enabled {
		v.cfg.log().Debug("access: API key resolved to missing or disabled user", "key_id", key.ID, "user_id", key.UserID)
		return nil, nil, false, refuse(ErrAccountDisabled, failreason.AccountDisabled)
	}
	return key, user, previous, nil
}

// keyPrincipal is key's principal for the presented hash. A previous
// secret lapses at PreviousUntil, so its principal's AbsoluteDeadline is the
// earlier of that and a set ExpiresAt.
func keyPrincipal(key *Key, user *User, hash Hash, previous bool) Principal {
	deadline := key.ExpiresAt
	if previous && (deadline.IsZero() || key.PreviousUntil.Before(deadline)) {
		deadline = key.PreviousUntil
	}
	return Principal{
		User:             user,
		Method:           MethodAPIKey,
		KeyID:            key.ID,
		KeyLabel:         key.Label,
		Scopes:           key.Scopes,
		AbsoluteDeadline: deadline,
		credential:       hash,
		source:           sourceAPIKey,
	}
}

// findAPIKey returns the key stored under hash, and whether hash is its
// non-zero PreviousHash rather than its KeyHash. It is [ErrInvalidAPIKey]
// when the store finds none, answers found with a nil key, or holds a key
// with neither hash. A store error is returned as is.
func findAPIKey(ctx context.Context, store APIKeyReader, hash Hash) (key *Key, previous bool, err error) {
	key, found, err := store.APIKeyByHash(ctx, hash)
	if err != nil {
		return nil, false, err
	}
	if !found || key == nil {
		return nil, false, ErrInvalidAPIKey
	}
	// A store doing a loose or prefix lookup cannot match another key.
	switch {
	case hash.Equal(key.KeyHash):
		return key, false, nil
	case !key.PreviousHash.IsZero() && hash.Equal(key.PreviousHash):
		return key, true, nil
	default:
		return nil, false, ErrInvalidAPIKey
	}
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
