package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// AuthenticatorStore is the store [New] takes: the session, user and API-key
// reads, the session activity write and the key touch.
type AuthenticatorStore interface {
	SessionReader
	SessionActivityUpdater
	UserReader
	APIKeyReader
	APIKeyToucher
}

// Authenticator resolves an HTTP request to a [Principal].
// Create with [New].
type Authenticator struct {
	sessions *sessionVerifier
	keys     *apiKeyVerifier
	// chain is sessions, Config.Verifier if set, then keys, which refuses
	// every Bearer value it cannot find, so nothing after it would see a
	// Bearer credential.
	chain []CredentialVerifier
	cfg   Config
	// bypassOn is the bypass hook's answer on the last request that asked
	// it, so each off-to-on edge warns once.
	bypassOn atomic.Bool
}

// New builds the one session configuration (cookie, timeouts, throttle) and
// the chain: the session verifier, cfg.Verifier if set, then the API-key
// verifier. Every zero field of cfg means its default (see [Config]). A nil
// store, or an interface holding a nil pointer, map, slice, func or chan, is
// refused, and so is such a cfg.Verifier, before any verifier is built, so a
// miswired app fails at startup and not at its first request. So are a
// negative timeout or throttle, a throttle not below the idle timeout, and a
// Cookie [CookieConfig.Validate] refuses.
func New(store AuthenticatorStore, cfg Config) (*Authenticator, error) { //nolint:gocritic // hugeParam: by-value Config is the public signature, so a caller builds it inline
	if isNilInterface(store) {
		return nil, errors.New("access: New: nil AuthenticatorStore")
	}
	cfg, err := cfg.resolve()
	if err != nil {
		return nil, err
	}
	a := &Authenticator{cfg: cfg}
	a.sessions = &sessionVerifier{store: store, cfg: &a.cfg, now: time.Now, warn: warnLimiter{now: time.Now}}
	a.keys = &apiKeyVerifier{store: store, cfg: &a.cfg, now: time.Now, warn: warnLimiter{now: time.Now}}
	a.chain = []CredentialVerifier{a.sessions}
	if cfg.Verifier != nil {
		a.chain = append(a.chain, cfg.Verifier)
	}
	a.chain = append(a.chain, a.keys)
	if cfg.Bypass != nil {
		a.cfg.log().Info("access: authentication bypass hook installed; requests are bypassed only while it reports true")
	}
	return a, nil
}

// syntheticAdminUser is the VALUE copied for each request the configured
// bypass function (see Config.Bypass) grants. It is deliberately not a *User:
// handing every bypassed request one shared pointer makes the granted
// principal process-global mutable state, so a consumer that annotates "its"
// user (an audit field, a role downgrade) silently rewrites the principal
// every later bypassed request receives. Authenticate copies it per call.
var syntheticAdminUser = User{
	ID:       0,
	Username: string(RoleAdmin),
	Role:     RoleAdmin,
	Enabled:  true,
}

// Authenticate runs the chain on r. It returns the first [Principal] a
// verifier grants; else the first error matching
// [ErrUnauthenticated] a verifier returned; else bare ErrUnauthenticated. Any
// other verifier error is returned at once. A granted principal whose User
// is nil or disabled, or whose Method is empty, is refused with an
// [*InvalidCredentialError]. The principal's User and Scopes are copies the
// caller may keep and change.
func (a *Authenticator) Authenticate(r *http.Request) (Principal, error) {
	if a.bypassed() {
		// A deep copy per request, so no consumer can mutate the principal
		// handed to any other request: User holds a slice.
		return Principal{User: syntheticAdminUser.Clone(), Method: MethodBypass, IP: a.ClientAddr(r).IP()}, nil
	}

	ctx := r.Context()
	var unusable error
	for _, v := range a.chain {
		p, ok, err := v.Verify(ctx, r)
		switch {
		case err == nil:
		case errors.Is(err, ErrInvalidCredential), errors.Is(err, ErrAuthBackend):
			// Checked before ErrUnauthenticated: an error matching both
			// must stop the chain, so it never falls through to a weaker
			// credential.
			return Principal{}, err
		case errors.Is(err, ErrUnauthenticated):
			if unusable == nil {
				unusable = err
			}
			continue
		default:
			return Principal{}, err
		}
		if !ok {
			continue
		}
		p.IP = a.ClientAddr(r).IP()
		return grant(p)
	}
	if unusable != nil {
		return Principal{}, unusable
	}
	return Principal{}, ErrUnauthenticated
}

// Recheck re-validates p for a long-lived connection and returns it with
// its deadlines re-read, writing no activity. A session principal re-reads
// its session and user, a key principal its key and user, and any other
// principal goes to Config.Verifier when it implements [Rechecker]; a
// Rechecker's ok false with a nil error, and any principal no verifier can
// recheck, is [ErrNotRecheckable]. Its errors and its refusal of a granted
// principal are Authenticate's.
func (a *Authenticator) Recheck(ctx context.Context, p Principal) (Principal, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	var (
		q   Principal
		ok  = true
		err error
	)
	switch p.source {
	case sourceSession:
		q, err = a.sessions.recheck(ctx, &p)
	case sourceAPIKey:
		q, err = a.keys.recheck(ctx, &p)
	case sourceExternal:
		rc, custom := a.cfg.Verifier.(Rechecker)
		if !custom {
			return Principal{}, ErrNotRecheckable
		}
		q, ok, err = rc.Recheck(ctx, p)
	}
	if err != nil {
		return Principal{}, err
	}
	if !ok {
		return Principal{}, ErrNotRecheckable
	}
	q.IP = p.IP
	return grant(q)
}

// grant refuses p if no request may act as it, and otherwise returns it
// with its User and Scopes copied: a verifier or store may hand every
// request the same pointer or slice, and without the copies one handler's
// change would reach the next.
func grant(p Principal) (Principal, error) { //nolint:gocritic // hugeParam: p is the caller's copy, returned changed
	if err := refuseGrant(&p); err != nil {
		return Principal{}, err
	}
	p.User = p.User.Clone()
	p.Scopes = slices.Clone(p.Scopes)
	return p, nil
}

// bypassed asks the Config.Bypass hook, if any, and warns on each off-to-on
// edge of its answer.
func (a *Authenticator) bypassed() bool {
	if a.cfg.Bypass == nil {
		return false
	}
	if a.cfg.Bypass() {
		if !a.bypassOn.Swap(true) {
			a.cfg.log().Warn("access: authentication bypass is active; matching requests are granted synthetic admin access and must never be enabled in production")
		}
		return true
	}
	// Loaded first so the common off path writes no shared cache line.
	if a.bypassOn.Load() {
		a.bypassOn.Store(false)
	}
	return false
}

// refuseGrant returns the refusal of a granted principal no request may act
// as, or nil.
func refuseGrant(p *Principal) error {
	switch {
	case p.User == nil, !p.User.Enabled:
		return &InvalidCredentialError{Method: p.Method, Err: ErrAccountDisabled}
	case p.Method == "":
		return &InvalidCredentialError{Method: p.Method}
	default:
		return nil
	}
}

// RequireAuth authenticates r and returns its principal. If r is not
// authenticated, it writes the Config.Unauthorized response, or the
// default one that field describes, and returns ok=false.
func (a *Authenticator) RequireAuth(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	p, err := a.Authenticate(r)
	if err == nil {
		return p, true
	}
	if !errors.Is(err, ErrUnauthenticated) && !errors.Is(err, ErrInvalidCredential) {
		a.cfg.log().Warn("access: authentication failed", "error", err)
	}
	if a.cfg.Unauthorized != nil {
		a.cfg.Unauthorized(w, r, err)
	} else {
		writeUnauthorized(w, err)
	}
	return Principal{}, false
}

// Cookie returns the session cookie configuration the session verifier
// reads.
func (a *Authenticator) Cookie() CookieConfig { return a.cfg.Cookie }

// Timeouts returns the session timeouts in force now: the
// Config.TimeoutSource value, each non-positive field replaced by the static
// configured one.
func (a *Authenticator) Timeouts() SessionTimeouts { return a.cfg.timeouts() }

// HasRole reports whether the user is authorized for the given role. A nil
// user has no role.
func HasRole(user *User, role Role) bool {
	if user == nil {
		return false
	}
	return user.Role == role || user.Role == RoleAdmin
}

// maxRedirectURILength is the largest path, in bytes, ValidateRedirectURI
// returns.
const maxRedirectURILength = 2048

// ValidateRedirectURI returns uri when it is a safe relative path of at most
// 2048 bytes holding no ASCII control byte (0x00 to 0x1F, 0x7F) anywhere, its
// fragment included, and "/" otherwise.
func ValidateRedirectURI(uri string) string {
	if uri == "/" || len(uri) > maxRedirectURILength {
		return "/"
	}
	if len(uri) < 2 || uri[0] != '/' || uri[1] == '/' || uri[1] == '\\' {
		return "/"
	}
	if strings.Contains(uri, "://") {
		return "/"
	}
	if strings.Contains(uri, "\\") {
		return "/"
	}
	// url.Parse refuses control bytes only before the '#'.
	if strings.ContainsFunc(uri, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "/"
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return "/"
	}
	return uri
}

// MethodAvailability describes the authentication methods one user keeps
// after a removal: what can sign in now and remains, not what is held. A
// caller removing a passkey who passes the held passkey count counts the
// removed passkey as remaining. The three method signals would otherwise sit
// as adjacent same-typed bool parameters, where a silent swap flips which
// method counts as remaining. The zero value reports no method available, so
// [CanDisableMethod] refuses every removal; an omitted field undercounts the
// remaining methods and can only make the answer more conservative.
type MethodAvailability struct {
	// PasskeyCount is the number of the user's passkeys, leaving out one
	// being removed.
	PasskeyCount int
	// HasPassword reports whether the user has a password set.
	HasPassword bool
	// OIDCEnabled reports whether OIDC login is enabled server-wide.
	OIDCEnabled bool
	// OIDCLinked reports whether the user has a linked OIDC identity.
	OIDCLinked bool
}

// CanDisableMethod reports whether the user keeps at least one way to sign in
// after removing method, given avail as the availability after that removal
// (see [MethodAvailability]). The password and OIDC signals of the method
// being removed are ignored; PasskeyCount counts whatever the method, so a
// passkey removal is allowed while another passkey remains.
func CanDisableMethod(method Method, avail MethodAvailability) bool {
	remaining := 0
	if method != MethodPassword && avail.HasPassword {
		remaining++
	}
	if avail.PasskeyCount > 0 {
		remaining++
	}
	if method != MethodOIDC && avail.OIDCEnabled && avail.OIDCLinked {
		remaining++
	}
	return remaining > 0
}

// writeUnauthorized writes the default unauthorized response for err; see
// Config.Unauthorized.
func writeUnauthorized(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	body := map[string]string{"error": ErrUnauthenticated.Error(), "code": "auth_required"}
	switch {
	case errors.Is(err, ErrAuthBackend):
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		body = map[string]string{"error": "unavailable", "code": "auth_unavailable"}
	case errors.Is(err, ErrSessionExpired), errors.Is(err, ErrSessionNotFound):
		body["code"] = "auth_session_expired"
		fallthrough
	default:
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
	}
	_ = json.NewEncoder(w).Encode(body)
}
