package account

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/scopetoken"
	"github.com/cplieger/access/webauthn"
)

// BreachMode is what a password set does with the breached-password check.
type BreachMode int

const (
	// BreachOff runs no breach check.
	BreachOff BreachMode = iota
	// BreachFailOpen refuses a breached password and accepts one the check
	// could not judge, logging one WARN; a caller whose context ended gets
	// that context's error instead.
	BreachFailOpen
	// BreachFailClosed refuses a breached password, and one the check could
	// not judge with ErrBreachCheckUnavailable.
	BreachFailClosed
)

// RegistrationMode is who may create their own account. It is an app
// setting, read from Rules on every operation.
type RegistrationMode int

const (
	// RegistrationOff lets no one sign up.
	RegistrationOff RegistrationMode = iota
	// RegistrationOpen creates an enabled regular account.
	RegistrationOpen
	// RegistrationApproval creates a regular account that waits, disabled,
	// until an admin enables it.
	RegistrationApproval
)

// RegistrationModeName is a RegistrationMode's wire name.
type RegistrationModeName string

// The wire names, in RegistrationMode order.
const (
	RegistrationNameOff      RegistrationModeName = "off"
	RegistrationNameOpen     RegistrationModeName = "open"
	RegistrationNameApproval RegistrationModeName = "approval"
)

var registrationModeNames = [...]RegistrationModeName{
	RegistrationOff: RegistrationNameOff, RegistrationOpen: RegistrationNameOpen, RegistrationApproval: RegistrationNameApproval,
}

// Name is the mode's wire name; empty for a value outside the modes.
func (m RegistrationMode) Name() RegistrationModeName {
	if m.valid() {
		return registrationModeNames[m]
	}
	return ""
}

// String is the mode's wire name, and "RegistrationMode(n)" for a value
// outside the modes.
func (m RegistrationMode) String() string {
	if m.valid() {
		return string(registrationModeNames[m])
	}
	return fmt.Sprintf("RegistrationMode(%d)", int(m))
}

// ParseRegistrationMode is the mode a wire name names; false for any other
// name.
func ParseRegistrationMode(name RegistrationModeName) (RegistrationMode, bool) {
	for m, n := range registrationModeNames {
		if n == name {
			return RegistrationMode(m), true
		}
	}
	return 0, false
}

func (m RegistrationMode) valid() bool { return m >= RegistrationOff && m <= RegistrationApproval }

// Rules is the app's policy as data. Config.Rules is read once per
// operation, so a reloaded value applies from the next operation on.
//
// An app may refuse a sign-in method in its own gate before account sees
// the attempt; Rules has no sign-in hook for it, and MethodUsable keeps the
// last-method guard from counting such a method.
type Rules struct {
	// SetupTokenRequired reports whether a setup from c needs a token. It
	// gets the request context and the resolved client with its
	// provenance. Nil means always; [Locality.TokenRequired] is the
	// library's rule for a local client.
	SetupTokenRequired func(ctx context.Context, c Client) bool
	// MethodUsable reports whether m can sign u in now under the app's own
	// rules: the last-method guard and UsableMethods AND it into every method
	// they count, and tickets and second factors ask it for passkeys. tx is
	// what the check reads: the deciding Update, the Store for a pre-check,
	// Me and Passkeys, or the caller's tx in UsableMethods; an app may
	// type-assert it. MethodUsable must not block or call the Store outside
	// tx. Config.RP() and Config.OIDC() are read as published. Nil means
	// every held method is usable.
	MethodUsable func(ctx context.Context, tx Tx, u *access.User, m access.Method) bool
	// SessionCaps returns per-session limits for a session about to be
	// created for c by sign-in method m, read once before the change that
	// creates it, so a password sign-in that then pends wastes one call; a
	// step-up never calls it. A positive value caps that limit for the
	// session's whole life (Session.IdleCap, Session.AbsoluteCap; kept on
	// rotation); zero or less, or a nil func, means no cap.
	SessionCaps func(ctx context.Context, c Client, m access.Method) (idle, absolute time.Duration)
	// KeyPrefix starts every minted key's plaintext; see access.GenerateAPIKey.
	KeyPrefix string
	// HTTPSOrigin is the app's HTTPS origin ("https://host[:port]"), which
	// State answers a plain request so its screen can link there. It is a
	// link only, and nothing trusts it. Empty means none.
	HTTPSOrigin string
	// ForbiddenWords join the username in the password context check.
	ForbiddenWords []string
	// Scopes is the key-scope vocabulary; CreateAPIKey refuses any other.
	// Each is one RFC 6750 scope-token: printable ASCII but space, '"' and '\'.
	Scopes []string
	// OIDCAdmission gates every OIDC sign-in, link, invite acceptance and
	// step-up, owners' included. The zero value admits every identity.
	OIDCAdmission OIDCAdmission
	// Provisioning creates an account at an admitted identity's first
	// OIDC sign-in, and maps its role. The zero value is off; a
	// single-user Policy refuses it on.
	Provisioning Provisioning
	// RecentAuth is how recent a sign-in or step-up must be for an
	// operation that requires recent authentication. Zero means 10m; a
	// value below 1m is invalid.
	RecentAuth time.Duration
	// KeyRotationOverlap is how long RotateAPIKey lets a key's superseded
	// secret verify while its new one is unused. Zero means 1h; a value
	// below 1m or above 24h is invalid.
	KeyRotationOverlap time.Duration
	// Breach is the breached-password check's mode; the zero value is off.
	Breach BreachMode
	// Registration is who may create their own account; the zero value is
	// off. A single-user Policy refuses it on, and so does
	// CheckRules while the stored SSO mode is SSOOnly.
	Registration RegistrationMode
	// MaxWaitingRegistrations bounds the accounts waiting for approval: at
	// it, a registration under RegistrationApproval is ErrRegistrationFull.
	// Zero means DefaultMaxWaitingRegistrations; negative is invalid.
	MaxWaitingRegistrations int
	// MaxSessionsPerUser bounds each user's sessions; creating one past it
	// ends the user's least recently active. Zero is unlimited.
	MaxSessionsPerUser int
	// DisablePasswordLogin refuses password step-up with
	// ErrPasswordLoginDisabled; a password sign-in then verifies only a live
	// temporary password, answering any other value as a wrong password. The
	// zero value allows them.
	DisablePasswordLogin bool
	// DisableTOTP turns TOTP enrolment and the code step off; a stored
	// record is kept, reads as absent, and works again once this is off.
	// The zero value offers TOTP where Config.TOTP wires it.
	DisableTOTP bool
	// RequireSecondFactor makes every password sign-in prove a second
	// factor, or bind one first; passkey and OIDC sign-ins meet it already.
	// It needs Config.TOTP or Config.RP set. The zero value is off.
	RequireSecondFactor bool
	// RevokeKeysOnCredentialChange deletes the user's API keys and their
	// tokens when SetPassword sets or changes the password. Disable and
	// delete always delete keys, whatever this says.
	RevokeKeysOnCredentialChange bool
}

// MethodState is the configuration UsableMethods counts under, in place of
// the published Config.Rules(), Config.RP() and Config.OIDC(), so an app
// can check values before it publishes them.
type MethodState struct {
	// RPID is the relying party ID a counted passkey is registered under;
	// empty means passkeys are off.
	RPID string
	// OIDCIssuer is the issuer a counted OIDC link carries; empty means
	// OIDC is off.
	OIDCIssuer string
	Rules      Rules
}

const (
	// MaxUsernameLength is the longest username, in runes after
	// access.NormalizeUsername, that any creation path accepts.
	MaxUsernameLength = 64
	// FailureCap is the consecutive-failure count, per (name, method) and
	// trust context, at which the method locks for that context.
	FailureCap = 100
	// MaxUntrustedCounts is how many untrusted attempts the whole process
	// counts between two failure-record prunes; spending it wakes a prune,
	// and untrusted counted attempts are refused until it commits.
	MaxUntrustedCounts = 10000
	// MaxKeyLineage is the most IDs a Key.LineageIDs holds: a root and seven
	// generations of keys minted by keys. Minting below a key whose path is
	// full is *PolicyError{Reason: "lineage_too_deep"}.
	MaxKeyLineage = 8
	// MaxSweepBatch is the most sessions one CleanupExpiredSessions call
	// deletes, and so the most IDs one call's EventSessionsExpired events
	// carry together, the most keys one ClearRetiredAPIKeySecrets call
	// clears, the most entries one PruneLog call of New's log drain or
	// the sweep removes, and the most waiting accounts one UsersWaiting call
	// of the sweep reads; each calls again until a call removes fewer.
	MaxSweepBatch = 1000
	// DefaultLogMaxAge is Config.LogMaxAge's default.
	DefaultLogMaxAge = 365 * 24 * time.Hour
	// DefaultLogMaxChanges is Config.LogMaxChanges's default.
	DefaultLogMaxChanges = 10000
	// DefaultLogMaxSessions is Config.LogMaxSessions's default.
	DefaultLogMaxSessions = 10000
	// DefaultMaxWaitingRegistrations is Rules.MaxWaitingRegistrations's
	// default.
	DefaultMaxWaitingRegistrations = 50
	// WaitingRegistrationLifetime is how long an account waits for
	// approval before the sweep deletes it, freeing its name.
	WaitingRegistrationLifetime = 30 * 24 * time.Hour
)

const (
	defaultRecentAuth         = 10 * time.Minute
	minRecentAuth             = time.Minute
	defaultKeyRotationOverlap = time.Hour
	minKeyRotationOverlap     = time.Minute
	maxKeyRotationOverlap     = 24 * time.Hour
)

// Validate checks every bounded field, KeyPrefix, Scopes, OIDCAdmission,
// Provisioning, Registration and HTTPSOrigin. The error is a *RulesError
// naming the field, which matches ErrRulesInvalid.
func (r Rules) Validate() error { //nolint:gocritic // hugeParam: Rules is the value Config.Rules returns
	switch {
	case r.RecentAuth != 0 && r.RecentAuth < minRecentAuth:
		return &RulesError{Field: "RecentAuth", Reason: "below 1m"}
	case r.Breach < BreachOff || r.Breach > BreachFailClosed:
		return &RulesError{Field: "Breach", Reason: "unknown mode"}
	case r.MaxSessionsPerUser < 0:
		return &RulesError{Field: "MaxSessionsPerUser", Reason: "negative"}
	case r.KeyRotationOverlap != 0 && r.KeyRotationOverlap < minKeyRotationOverlap:
		return &RulesError{Field: "KeyRotationOverlap", Reason: "below 1m"}
	case r.KeyRotationOverlap > maxKeyRotationOverlap:
		return &RulesError{Field: "KeyRotationOverlap", Reason: "above 24h"}
	}
	if err := access.ValidateKeyPrefix(r.KeyPrefix); err != nil {
		return &RulesError{Field: "KeyPrefix", Reason: err.Error(), Err: err}
	}
	for _, scope := range r.Scopes {
		if !scopetoken.Valid(scope) {
			return &RulesError{Field: "Scopes", Reason: fmt.Sprintf("%q is not an RFC 6750 scope-token", scope)}
		}
	}
	if err := r.validateOIDC(); err != nil {
		return err
	}
	if err := r.validateRegistration(); err != nil {
		return err
	}
	return r.validateOrigin()
}

// validateOrigin is Validate's HTTPSOrigin check.
func (r *Rules) validateOrigin() error {
	if r.HTTPSOrigin != "" && !isHTTPSOrigin(r.HTTPSOrigin) {
		return &RulesError{Field: "HTTPSOrigin", Reason: fmt.Sprintf("%q is not an https origin in its canonical form, https://host or https://host:port", r.HTTPSOrigin)}
	}
	return nil
}

// validateOIDC is Validate's OIDCAdmission and Provisioning checks.
func (r *Rules) validateOIDC() error {
	if err := r.OIDCAdmission.Validate(); err != nil {
		return &RulesError{Field: "OIDCAdmission", Reason: err.Error(), Err: err}
	}
	if err := r.Provisioning.Validate(); err != nil {
		return &RulesError{Field: "Provisioning", Reason: err.Error(), Err: err}
	}
	return nil
}

// fieldRegistration is the RulesError Field of every Registration refusal.
const fieldRegistration = "Registration"

// validateRegistration is Validate's Registration and
// MaxWaitingRegistrations checks.
func (r *Rules) validateRegistration() error {
	switch {
	case !r.Registration.valid():
		return &RulesError{Field: fieldRegistration, Reason: "unknown mode"}
	case r.MaxWaitingRegistrations < 0:
		return &RulesError{Field: "MaxWaitingRegistrations", Reason: "negative"}
	}
	return nil
}

// isHTTPSOrigin reports whether s is an https origin's canonical
// serialisation (RFC 6454 section 6.2): lowercase, with no default port, path,
// query or fragment.
func isHTTPSOrigin(s string) bool {
	o, err := webauthn.ParseOrigin(s)
	return err == nil && strings.HasPrefix(s, "https://") && o.String() == s
}

// withDefaults returns r with each zero field that has a default set to it.
func (r Rules) withDefaults() Rules { //nolint:gocritic // hugeParam: Rules is the value Config.Rules returns
	if r.RecentAuth == 0 {
		r.RecentAuth = defaultRecentAuth
	}
	if r.KeyRotationOverlap == 0 {
		r.KeyRotationOverlap = defaultKeyRotationOverlap
	}
	if r.MaxWaitingRegistrations == 0 {
		r.MaxWaitingRegistrations = DefaultMaxWaitingRegistrations
	}
	return r
}
