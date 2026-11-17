package account

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// Config configures a Service. It has no LogValue or Format: it is a
// construction input holding the caller's own key bytes, which New copies
// into masked state.
type Config struct {
	Store  Store
	Policy Policy // RolePolicy or SingleOwnerPolicy, or the app's own
	// Authenticator owns the session cookie and timeouts; account reads both
	// from it and holds no copy.
	Authenticator *access.Authenticator
	Hasher        *access.Hasher
	Limiter       *ratelimit.Limiter
	RP            func() *webauthn.RelyingParty // nil func or nil result: passkeys off
	OIDC          func() *oidc.Provider         // likewise for OIDC
	Rules         func() Rules                  // read once per operation (hot reload)
	// TOTP wires authenticator-app codes; the zero value wires none, and
	// New refuses a half-set value.
	TOTP TOTPConfig
	// OnEvent receives every Event after its commit, in Seq order,
	// synchronously in the committing goroutine. It must not block. Delivery
	// is at most once; the security log, appended in the same Update, is
	// the durable record.
	OnEvent func(Event)
	// Breach is the client for the breached-password check. A Rules value
	// whose Breach is not BreachOff is invalid while it is nil, at New and
	// at every later Rules() call.
	Breach *http.Client
	Logger *slog.Logger     // nil: slog.Default() at each log call
	Now    func() time.Time // nil: time.Now
	// AdminScope, when set, lets a key carrying it list users, every user's
	// keys and the live invite tokens, read the security log and
	// revoke any key, where Policy allows. Empty: session only.
	AdminScope string
	// ManageUsersScope, when set, lets a key carrying this scope create,
	// update and delete RoleUser accounts and invite RoleUser accounts;
	// never an admin. Empty: session only, under recent auth.
	ManageUsersScope string
	// CreateKeysScope, when set, lets a key carrying this scope mint keys
	// for its own user, each no broader and no longer-lived than itself.
	// Empty: session only, under recent auth.
	CreateKeysScope string
	// FailureKey is the HMAC-SHA256 key that names failure records: exactly
	// 32 bytes, required, persisted by the app beside its device-cookie key
	// ring. A new key orphans every record, which the next sweep prunes, so
	// rotating it resets every count and clears every lock with no
	// EventMethodLocked or EventMethodReenabled for them; keep it for the
	// store's lifetime. New copies it and keeps no reference to the slice.
	FailureKey []byte
	// CleanupInterval is how often expired sessions, tokens, pending
	// ceremonies, failure records of names that are not users and
	// security-log entries past LogMaxAge are swept, and locks reported;
	// zero means 5m.
	CleanupInterval time.Duration
	// MaxPending bounds each of the two lists of pending WebAuthn
	// ceremonies, anonymous begins and a user's or setup's own; zero means
	// 10000. Pending sign-ins, enrolments and drafts have caps of their own.
	MaxPending int
	// LogMaxAge is how long a security-log entry is kept; zero means
	// DefaultLogMaxAge. Each sweep removes older entries, so one may stay up
	// to a CleanupInterval longer.
	LogMaxAge time.Duration
	// LogMaxChanges and LogMaxSessions cap the entries of LogClassChange and
	// LogClassSession; zero means DefaultLogMaxChanges and
	// DefaultLogMaxSessions. Every append removes its class's oldest entries
	// beyond the cap in the same Update, counted in LogClassStats.Evicted,
	// and New first drains a log already past a cap.
	LogMaxChanges  int
	LogMaxSessions int
}

// TOTPConfig wires TOTP. A set value needs both fields.
type TOTPConfig struct {
	// Sealer seals each TOTP secret at rest; keep its ring for the store's
	// lifetime, since a record no key opens cannot verify a code.
	Sealer *access.Sealer
	// Issuer names the app in an authenticator, the otpauth label's
	// prefix; it holds no colon, the Key Uri Format's label separator.
	Issuer string
}

// validate refuses a set value missing a field, a zero Sealer and an
// Issuer holding a colon.
func (t TOTPConfig) validate() error {
	switch {
	case t == TOTPConfig{}:
		return nil
	case t.Sealer.IsZero():
		return errors.New("account: Config.TOTP.Sealer is nil or holds no key; leave Config.TOTP zero to wire no TOTP")
	case t.Issuer == "":
		return errors.New("account: Config.TOTP.Issuer is empty; leave Config.TOTP zero to wire no TOTP")
	case strings.Contains(t.Issuer, ":"):
		return fmt.Errorf("account: Config.TOTP.Issuer %q holds a colon, the otpauth label's separator", t.Issuer)
	}
	return nil
}

const (
	defaultCleanupInterval = 5 * time.Minute
	failureKeySize         = 32
)
