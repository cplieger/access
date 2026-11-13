package account

import (
	"context"
	"errors"
	"fmt"

	"github.com/cplieger/access"
)

// Errors a store returns for caller faults. An operation answers one only
// where it is that operation's own refusal; any other store error is a
// backend failure, which account wraps as access.ErrAuthBackend.
var (
	ErrNotFound            = errors.New("account: not found")
	ErrUsernameTaken       = errors.New("account: username taken")
	ErrOIDCIdentityTaken   = errors.New("account: identity provider account already linked")
	ErrDuplicateCredential = errors.New("account: passkey already registered")
	ErrSetupComplete       = errors.New("account: setup already completed")
)

// Errors of the account operations. Errors of access, ratelimit, webauthn and
// oidc pass through unchanged and match with errors.Is.
var (
	ErrInvalidCredentials    = errors.New("account: invalid credentials")
	ErrPasswordLoginDisabled = errors.New("account: password sign-in is disabled")
	ErrAlreadyLinked         = errors.New("account: an identity provider account is already linked")
	// ErrMethodNotLocked is ReenableMethod on a method locked in neither
	// trust context.
	ErrMethodNotLocked = errors.New("account: method is not locked")
	// ErrSessionRequired is an operation for a full or a recovery session
	// reached by any other principal, and RequireAdminScope or
	// RequireKeyPermission refusing a recovery session or an empty scope.
	ErrSessionRequired = errors.New("account: a signed-in session is required")
	// ErrScopeRequired is RequireAdminScope or RequireKeyPermission under a
	// set scope, for a principal that is no full session and no key carrying
	// that scope.
	ErrScopeRequired = errors.New("account: a key scope is required")
	// ErrNoChange is an UpdateUser with no field set.
	ErrNoChange = errors.New("account: no change requested")
	// ErrCurrentPasswordRequired is a SetPassword with a zero current for a
	// user who holds a password, or a RemovePassword with a zero current.
	ErrCurrentPasswordRequired = errors.New("account: the current password is required")
	ErrKeyExpiryInvalid        = errors.New("account: key expiry must not be negative")
	// ErrRulesInvalid is matched by every *RulesError: New refusing the
	// Rules() value, and an operation refusing a later invalid one.
	ErrRulesInvalid = errors.New("account: rules invalid")
	// ErrServiceClosed is every operation called after Shutdown began; it
	// matches access.ErrAuthBackend.
	ErrServiceClosed = fmt.Errorf("account: service closed: %w", access.ErrAuthBackend)
	// ErrTTLTooLong is a token lifetime above 7 times its kind's default.
	ErrTTLTooLong = errors.New("account: token lifetime too long")
	// ErrTTLNegative is a negative token lifetime given to IssueRecovery,
	// CreateInvite or IssueSetupToken.
	ErrTTLNegative        = errors.New("account: token lifetime must not be negative")
	ErrSetupTokenRequired = errors.New("account: a setup token is required")
	// ErrPolicyRefused is matched by every *PolicyError.
	ErrPolicyRefused = errors.New("account: refused by policy")
	// ErrLastMethod is a removal that would leave the user no method that
	// can sign in now.
	ErrLastMethod          = errors.New("account: the last sign-in method cannot be removed")
	ErrSSOGoverned         = errors.New("account: the account is governed by its identity provider")
	ErrPasskeysUnavailable = errors.New("account: passkeys are not available")
	ErrOIDCUnavailable     = errors.New("account: OIDC is not available")
	ErrCeremonyInvalid     = errors.New("account: ceremony unknown, expired or of another kind")
	ErrSessionGone         = errors.New("account: the session no longer exists")
	// ErrUnknownScope is a key scope outside Rules.Scopes.
	ErrUnknownScope = errors.New("account: unknown key scope")
	// ErrBreachCheckUnavailable is access's sentinel, so either name matches
	// the refusal under BreachFailClosed.
	ErrBreachCheckUnavailable = access.ErrBreachCheckUnavailable
)

// The PolicyError Reasons, in PolicyReasons order. RolePolicy and
// SingleOwnerPolicy give the role and owner reasons; ReasonNotPrincipal,
// ReasonUnknownOperation, ReasonUnknownVia and ReasonViaWithActor answer a
// Decision no account operation builds.
const (
	ReasonOutOfBandOnly      = "out_of_band_only"
	ReasonKeyNotCurrent      = "key_not_current"
	ReasonAdminTarget        = "admin_target"
	ReasonScopesNotSubset    = "scopes_not_subset"
	ReasonExpiryAfterParent  = "expiry_after_parent"
	ReasonLineageTooDeep     = "lineage_too_deep"
	ReasonPermissionNotAdmin = "permission_not_admin"
	ReasonSelfRecovery       = "self_recovery"
	ReasonOtherUser          = "other_user"
	ReasonTargetNotEligible  = "target_not_eligible"
	ReasonNotPrincipal       = "not_principal"
	ReasonUnknownOperation   = "unknown_operation"
	ReasonNotEnabledUser     = "not_enabled_user"
	ReasonNotAdmin           = "not_admin"
	ReasonSelfDelete         = "self_delete"
	ReasonLastAdmin          = "last_admin"
	ReasonLastLocalAdmin     = "last_local_admin"
	ReasonSingleOwner        = "single_owner"
	ReasonNotOwner           = "not_owner"
	ReasonUnknownVia         = "unknown_via"
	ReasonViaWithActor       = "via_with_actor"
)

// PolicyReasons returns every Reason account's own rules and policies put
// in a PolicyError, in a stable order.
func PolicyReasons() []string {
	return []string{
		ReasonOutOfBandOnly,
		ReasonKeyNotCurrent,
		ReasonAdminTarget,
		ReasonScopesNotSubset,
		ReasonExpiryAfterParent,
		ReasonLineageTooDeep,
		ReasonPermissionNotAdmin,
		ReasonSelfRecovery,
		ReasonOtherUser,
		ReasonTargetNotEligible,
		ReasonNotPrincipal,
		ReasonUnknownOperation,
		ReasonNotEnabledUser,
		ReasonNotAdmin,
		ReasonSelfDelete,
		ReasonLastAdmin,
		ReasonLastLocalAdmin,
		ReasonSingleOwner,
		ReasonNotOwner,
		ReasonUnknownVia,
		ReasonViaWithActor,
	}
}

// PolicyError is a refusal by a Policy, or by a rule account applies
// itself. Reason is one of PolicyReasons for account's own rules and
// policies, or whatever an app's own Policy sets. It matches
// ErrPolicyRefused.
type PolicyError struct {
	Op     Operation
	Reason string
}

func (e *PolicyError) Error() string {
	return "account: " + string(e.Op) + " refused by policy: " + e.Reason
}

// Is reports ErrPolicyRefused.
func (*PolicyError) Is(target error) bool { return target == ErrPolicyRefused }

// ErrLogFilterInvalid is matched by every *LogFilterError.
var ErrLogFilterInvalid = errors.New("account: log filter invalid")

// The LogFilterError Reasons, in LogFilterReasons order.
const (
	ReasonLogLimit = "log_limit" // Limit negative or above MaxLogPage
	ReasonLogRange = "log_range" // a Seq bound above 2^53 - 1, or no Seq between AfterSeq and BeforeSeq
	ReasonLogKind  = "log_kind"  // a kind that is neither an EventKinds value nor an app kind
	ReasonLogID    = "log_id"    // a negative user or key ID
)

// LogFilterReasons returns every LogFilterError Reason, in a stable order.
func LogFilterReasons() []string {
	return []string{ReasonLogLimit, ReasonLogRange, ReasonLogKind, ReasonLogID}
}

// LogFilterError is a LogFilter SecurityLog refuses, before any store
// read. Reason is one of LogFilterReasons. It matches ErrLogFilterInvalid.
type LogFilterError struct {
	Reason string
}

func (e *LogFilterError) Error() string { return "account: invalid log filter: " + e.Reason }

// Is reports ErrLogFilterInvalid.
func (*LogFilterError) Is(target error) bool { return target == ErrLogFilterInvalid }

// The AppEntryError Reasons, in AppEntryReasons order.
const (
	ReasonAppKind   = "app_kind"
	ReasonAppDetail = "app_detail"
	ReasonAppMethod = "app_method"
)

// AppEntryReasons returns every AppEntryError Reason, in a stable order.
func AppEntryReasons() []string { return []string{ReasonAppKind, ReasonAppDetail, ReasonAppMethod} }

// AppEntryError reports why AppendLog refused an entry. Reason is one of
// AppEntryReasons.
type AppEntryError struct {
	Reason string
}

func (e *AppEntryError) Error() string { return "account: invalid app log entry: " + e.Reason }

// RulesError names the Rules field that is invalid. It matches
// ErrRulesInvalid, and unwraps to Err when a check of another package
// refused the field.
type RulesError struct {
	Err    error
	Field  string
	Reason string
}

func (e *RulesError) Error() string {
	return "account: invalid rules: " + e.Field + ": " + e.Reason
}

// Is reports ErrRulesInvalid.
func (*RulesError) Is(target error) bool { return target == ErrRulesInvalid }

func (e *RulesError) Unwrap() error { return e.Err }

// The UsernameError and TextError Reasons.
const (
	ReasonEmpty               = "empty"
	ReasonDisallowedCharacter = "disallowed_character"
	ReasonTooLong             = "too_long"
)

// The TextError Fields.
const (
	TextFieldLabel       = "label" // a key or session label, or a passkey name
	TextFieldDisplayName = "display_name"
)

// UsernameReasons returns every UsernameError Reason, in a stable order.
func UsernameReasons() []string {
	return []string{ReasonEmpty, ReasonDisallowedCharacter, ReasonTooLong}
}

// TextErrorFields returns every TextError Field, in a stable order.
func TextErrorFields() []string { return []string{TextFieldLabel, TextFieldDisplayName} }

// TextErrorReasons returns every TextError Reason, in a stable order.
func TextErrorReasons() []string { return []string{ReasonDisallowedCharacter, ReasonTooLong} }

// UsernameError is a username a creation path refuses, before any limiter
// call or hash. Reason is one of UsernameReasons.
type UsernameError struct {
	Reason string
}

func (e *UsernameError) Error() string { return "account: invalid username: " + e.Reason }

// TextError is a display text an operation refuses before any write. Field
// is one of TextErrorFields and Reason one of TextErrorReasons:
// disallowed_character is invalid UTF-8, a control, bidi control or line
// separator character.
type TextError struct {
	Field  string
	Reason string
}

func (e *TextError) Error() string { return "account: invalid " + e.Field + ": " + e.Reason }

// backend wraps a store error that is not one of this package's sentinels.
func backend(err error) error {
	return fmt.Errorf("%w: %w", access.ErrAuthBackend, err)
}

// storeSentinels are the caller faults a store reports.
var storeSentinels = []error{ErrNotFound, ErrUsernameTaken, ErrOIDCIdentityTaken, ErrDuplicateCredential, ErrSetupComplete}

// storeErr wraps a store error as access.ErrAuthBackend, a store sentinel
// reduced to its text (withoutSentinel).
func storeErr(err error) error {
	return backend(withoutSentinel(err))
}

// withoutSentinel is err with a store sentinel reduced to its text. A
// sentinel that reaches it is one refusedBy did not declare, so the store
// broke its contract there: the answer never matches a refusal the
// operation does not give.
func withoutSentinel(err error) error {
	for _, sentinel := range storeSentinels {
		if errors.Is(err, sentinel) {
			return errors.New(err.Error())
		}
	}
	return err
}

// refusedBy is a store call's error as the operation's own refusal when it
// matches one of sentinels, the store refusals that call answers; any other
// error comes back as it is, for storeErr.
func refusedBy(err error, sentinels ...error) error {
	for _, sentinel := range sentinels {
		if errors.Is(err, sentinel) {
			return refuse(err)
		}
	}
	return err
}

// refusal carries an operation's own answer out of an Update callback, so
// update can tell it from a store error.
type refusal struct{ err error }

func (r *refusal) Error() string { return r.err.Error() }
func (r *refusal) Unwrap() error { return r.err }

// refuse is how a callback ends its Update with err as the operation's
// answer; every other callback error is the store's.
func refuse(err error) error { return &refusal{err: err} }

// update runs fn in one Store.Update and answers a refusal's error as it
// is, and any other error through storeErr.
func (s *Service) update(ctx context.Context, fn func(tx Tx) error) error {
	return answer(s.store.Update(ctx, fn))
}

// answer is a check's result as the operation returns it: a refusal's
// error as it is, any other error through storeErr.
func answer(err error) error {
	if err == nil {
		return nil
	}
	if r, ok := errors.AsType[*refusal](err); ok {
		return r.err
	}
	return storeErr(err)
}
