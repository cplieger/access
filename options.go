package access

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"time"
)

// DefaultIdleTimeout and DefaultAbsTimeout are what a zero Config.IdleTimeout
// and Config.AbsTimeout mean.
const (
	DefaultIdleTimeout = 1 * time.Hour
	DefaultAbsTimeout  = 24 * time.Hour
)

// DefaultRealm is what an empty Config.Realm means.
const DefaultRealm = "access"

// Config configures an [Authenticator]. Every zero value is the default: a
// nil Logger is slog.Default() at call time, a nil Bypass is none, a nil
// TimeoutSource is the static timeouts, a nil ClientAddr is the default
// resolver, a nil Verifier is none, the zero Cookie is the default session
// cookie, an empty Realm is [DefaultRealm], zero IdleTimeout and AbsTimeout
// are [DefaultIdleTimeout] and [DefaultAbsTimeout], and a zero
// ActivityThrottle writes activity on every request.
type Config struct {
	// Logger receives the warnings and debug lines.
	Logger *slog.Logger
	// Realm is the realm of every challenge [Authenticator.Challenge] writes.
	// [New] refuses one holding '"', '\' or a control character, so it
	// quotes as it is.
	Realm string
	// Bypass reports whether authentication is bypassed. While it returns
	// true, [Authenticator.Authenticate] grants every request [MethodBypass]
	// with its own copy of a synthetic admin user whose ID is 0, which names
	// no stored user. [New] logs one Info line when it is set; each request
	// that finds it on after one that found it off, the first included, logs
	// a WARN.
	Bypass func() bool
	// TimeoutSource is read on every verification, so a hot-reloaded value
	// applies without a new Authenticator. Each non-positive field it
	// returns falls back to IdleTimeout or AbsTimeout, and ActivityThrottle's
	// clamp applies to the idle timeout it returns.
	TimeoutSource func() SessionTimeouts
	// ClientAddr is the app's one client resolver, served by
	// [Authenticator.ClientAddr]. Its answer's Via says how the request
	// arrived, and one left zero ([ViaUnknown]) is no known client. Nil
	// treats no peer as a proxy: Peer is r.RemoteAddr's address, unmapped,
	// and Via is [ViaDirect], or [ViaUntrustedForwarding] when Forwarded,
	// X-Forwarded-For or X-Real-IP is present.
	ClientAddr func(*http.Request) ClientAddr
	// Verifier runs between the built-in session and API-key verifiers. The
	// API-key verifier refuses every Bearer value it cannot find, so a
	// Verifier for another Bearer credential answers ok false and a nil error
	// for every value not its own. It may grant an app-synthesised User with
	// no stored row: non-nil, enabled and with a non-empty Method, never
	// looked up in the store, and refused by every account operation that
	// needs a stored user, because IsSession() is false.
	Verifier CredentialVerifier
	// Cookie is the session cookie, checked by [CookieConfig.Validate].
	Cookie CookieConfig
	// IdleTimeout is how long a session may sit unused.
	IdleTimeout time.Duration
	// AbsTimeout is how long a session may live at most.
	AbsTimeout time.Duration
	// ActivityThrottle is how old a key's stored LastUsedAt must be before a
	// request writes it again through [APIKeyToucher.TouchAPIKey]; a key's
	// first use, LastUsedAt zero, is written whatever the throttle. A
	// session's activity is written once its stored LastActivity is the
	// lesser of it and half the session's idle limit old (that limit lowered
	// by its IdleCap and, for a recovery session, [RecoverySessionLifetime]),
	// so a session in use never expires between two writes. [New] refuses a
	// negative throttle and one at or above the idle timeout.
	ActivityThrottle time.Duration
}

// resolve returns cfg with its defaults filled in, or the reason [New]
// refuses it.
func (cfg Config) resolve() (Config, error) { //nolint:gocritic // hugeParam: the value receiver is the copy resolve fills and returns
	if cfg.Verifier != nil && isNilInterface(cfg.Verifier) {
		return Config{}, errors.New("access: New: nil Verifier")
	}
	if err := cfg.Cookie.Validate(); err != nil {
		return Config{}, err
	}
	cfg.Realm = cmp.Or(cfg.Realm, DefaultRealm)
	if !quotable(cfg.Realm) {
		return Config{}, fmt.Errorf("access: realm %q holds a quote, a backslash or a control character", cfg.Realm)
	}
	cfg.IdleTimeout = cmp.Or(cfg.IdleTimeout, DefaultIdleTimeout)
	cfg.AbsTimeout = cmp.Or(cfg.AbsTimeout, DefaultAbsTimeout)
	if cfg.ClientAddr == nil {
		cfg.ClientAddr = defaultClientAddr
	}
	// A negative idle timeout expires every session at once, so the cmp.Or
	// above, which replaces only zero, must not be the last word.
	if cfg.IdleTimeout < 0 {
		return Config{}, fmt.Errorf("access: idle timeout must be positive, got %s", cfg.IdleTimeout)
	}
	if cfg.AbsTimeout < 0 {
		return Config{}, fmt.Errorf("access: absolute timeout must be positive, got %s", cfg.AbsTimeout)
	}
	if cfg.ActivityThrottle < 0 {
		return Config{}, fmt.Errorf("access: activity throttle must not be negative, got %s", cfg.ActivityThrottle)
	}
	// The stored last activity lags real use by up to one throttle window, so
	// a window at or above the idle timeout expires sessions in use.
	if cfg.ActivityThrottle >= cfg.IdleTimeout {
		return Config{}, fmt.Errorf("access: activity throttle (%s) must be less than the idle timeout (%s)", cfg.ActivityThrottle, cfg.IdleTimeout)
	}
	return cfg, nil
}

// timeouts returns the effective session timeouts for one verification: the
// static ones, or the TimeoutSource value with each non-positive field
// replaced by the static one, so a misbehaving source can never produce the
// always-expired sessions a non-positive timeout would.
func (cfg *Config) timeouts() SessionTimeouts {
	ts := SessionTimeouts{Idle: cfg.IdleTimeout, Absolute: cfg.AbsTimeout}
	if cfg.TimeoutSource == nil {
		return ts
	}
	src := cfg.TimeoutSource()
	if src.Idle > 0 {
		ts.Idle = src.Idle
	}
	if src.Absolute > 0 {
		ts.Absolute = src.Absolute
	}
	return ts
}

// log returns the configured logger or slog.Default().
func (cfg *Config) log() *slog.Logger {
	if cfg.Logger != nil {
		return cfg.Logger
	}
	return slog.Default()
}

// quotable reports whether s goes inside an RFC 9110 §5.6.4 quoted-string
// with no quoted-pair: no '"', no '\' and no control character.
func quotable(s string) bool {
	for i := range len(s) {
		if c := s[i]; c < 0x20 || c == 0x7f || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// isNilInterface reports a nil v, or one holding a nil pointer, map, slice,
// func or chan: the one nil rule [New] applies to its store and to
// Config.Verifier.
func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}
