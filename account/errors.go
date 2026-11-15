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
	// ErrSessionRequired is an operation for a session reached by any other
	// principal, and RequireAdminScope or RequireKeyPermission refusing an
	// empty scope.
	ErrSessionRequired = errors.New("account: a signed-in session is required")
	// ErrScopeRequired is RequireAdminScope or RequireKeyPermission under a
	// set scope, for a principal that is no session and no key carrying
	// that scope.
	ErrScopeRequired = errors.New("account: a key scope is required")
	// ErrNoChange is an UpdateUser with no field set.
	ErrNoChange = errors.New("account: no change requested")
	// ErrCurrentPasswordRequired is a SetPassword with a zero current for a
	// user who holds a password, or a RemovePassword with a zero current.
	ErrCurrentPasswordRequired = errors.New("account: the current password is required")
	ErrKeyExpiryInvalid        = errors.New("account: key expiry must not be negative")
	// ErrKeyLabelTaken is a key label another unexpired key of the same
	// owner already carries, compared after NFC and Unicode case folding.
	ErrKeyLabelTaken = errors.New("account: a key with this label already exists")
	// ErrRulesInvalid is matched by every *RulesError: New refusing the
	// Rules() value, and an operation refusing a later invalid one.
	ErrRulesInvalid = errors.New("account: rules invalid")
	// ErrServiceClosed is every operation called after Shutdown began; it
	// matches access.ErrAuthBackend.
	ErrServiceClosed = fmt.Errorf("account: service closed: %w", access.ErrAuthBackend)
	// ErrTTLTooLong is a token lifetime above 7 times its kind's default.
	ErrTTLTooLong = errors.New("account: token lifetime too long")
	// ErrTTLNegative is a negative token lifetime given to CreateInvite or
	// IssueSetupToken.
	ErrTTLNegative        = errors.New("account: token lifetime must not be negative")
	ErrSetupTokenRequired = errors.New("account: a setup token is required")
	// ErrPolicyRefused is matched by every *PolicyError.
	ErrPolicyRefused = errors.New("account: refused by policy")
	// ErrLastMethod is a removal that would leave the user no method that
	// can sign in now.
	ErrLastMethod          = errors.New("account: the last sign-in method cannot be removed")
	ErrPasskeysUnavailable = errors.New("account: passkeys are not available")
	ErrOIDCUnavailable     = errors.New("account: OIDC is not available")
	ErrCeremonyInvalid     = errors.New("account: ceremony unknown, expired or of another kind")
	ErrSessionGone         = errors.New("account: the session no longer exists")
	// ErrUnknownScope is a key scope outside Rules.Scopes.
	ErrUnknownScope = errors.New("account: unknown key scope")
	// ErrBreachCheckUnavailable is access's sentinel, so either name matches
	// the refusal under BreachFailClosed.
	ErrBreachCheckUnavailable = access.ErrBreachCheckUnavailable
	// ErrCodeInvalid is matched by every *CodeError: a TOTP or recovery
	// code that does not match, or a match refused as reused or locked.
	ErrCodeInvalid = errors.New("account: the code is not valid")
	// ErrCodeMalformed is matched by every *MalformedError.
	ErrCodeMalformed = errors.New("account: the code is malformed")
	// ErrSecondFactorProofRequired is a change that needs a current second
	// factor, sent with no proof; nothing is counted for it.
	ErrSecondFactorProofRequired = errors.New("account: a current second factor is required")
	// ErrLastSecondFactor is a removal Rules.RequireSecondFactor refuses,
	// since it leaves a user who holds a second factor none they can use;
	// it matches ErrLastMethod.
	ErrLastSecondFactor = fmt.Errorf("account: the last second factor cannot be removed: %w", ErrLastMethod)
	// ErrSecondFactorHeld is a password step-up of a user who holds a
	// second factor, who steps up with it; it matches
	// ErrSecondFactorRequired.
	ErrSecondFactorHeld = fmt.Errorf("account: a user holding a second factor steps up with it: %w", ErrSecondFactorRequired)
	// ErrPasswordRequired is a TOTP enrolment of a user who holds no
	// password, the only sign-in a code protects.
	ErrPasswordRequired = errors.New("account: an authenticator app needs a password to protect")
	// ErrSecondFactorRequired is a password sign-in or a setting that needs
	// a second factor the user cannot bind or does not hold.
	ErrSecondFactorRequired = errors.New("account: a second factor is required")
	// ErrNoUsableMethod is a sign-in whose next step the app's rules allow
	// no method for, so the account can take no step this app allows.
	ErrNoUsableMethod = errors.New("account: this app allows no method this sign-in's next step needs")
	// ErrEnrolNeedsKnownDevice is a password sign-in that would bind the
	// account's first second factor from a device no secure sign-in of it
	// has used; it matches ErrSecondFactorRequired.
	ErrEnrolNeedsKnownDevice = fmt.Errorf("account: a first second factor is bound only from a known device: %w", ErrSecondFactorRequired)
	// ErrEnableWithoutSecondFactor is CheckSecondFactorReady's refusal of an
	// admin who holds no usable second factor; it matches
	// ErrSecondFactorRequired.
	ErrEnableWithoutSecondFactor = fmt.Errorf("account: set up your own second factor before requiring one: %w", ErrSecondFactorRequired)
	// ErrSecondFactorUnavailable is a TOTP record no Sealer key opens; it
	// counts as no wrong code.
	ErrSecondFactorUnavailable = errors.New("account: the second factor cannot be opened")
	// ErrTOTPDisabled is a TOTP operation under Rules.DisableTOTP.
	ErrTOTPDisabled = errors.New("account: authenticator apps are turned off")
	// ErrRegistrationClosed is a registration while Rules.Registration is
	// off.
	ErrRegistrationClosed = errors.New("account: registration is closed")
	// ErrRegistrationFull is a registration while the waiting accounts are
	// at Rules.MaxWaitingRegistrations.
	ErrRegistrationFull = errors.New("account: registration is full")
	// ErrNoOwner is New refusing a store that holds users and no enabled
	// admin, and Service.Owner on a single-user store whose owner flag is
	// not on its one enabled admin alone. Its text names the repair.
	ErrNoOwner = errors.New("account: no owner")
	// ErrNotSingleUser is Service.Owner under a multi-user Policy.
	ErrNotSingleUser = errors.New("account: the policy admits more than one account")
	// ErrUnknownSSOMode is a mode outside the SSOMode constants.
	ErrUnknownSSOMode = errors.New("account: unknown SSO mode")
	// ErrSSOOnly is a local-method operation the stored SSO mode forbids
	// for the user.
	ErrSSOOnly = errors.New("account: the identity provider is this account's only sign-in")
)

// The PolicyError Reasons, in PolicyReasons order. RolePolicy and
// SingleOwnerPolicy give the role and owner reasons; ReasonUnknownOperation,
// ReasonUnknownVia and ReasonViaWithActor answer a Decision no account
// operation builds. ReasonKeyRetiring is a key principal presenting a secret
// a rotation superseded, which an operation that creates or restores a way
// in refuses.
const (
	ReasonOutOfBandOnly      = "out_of_band_only"
	ReasonKeyNotCurrent      = "key_not_current"
	ReasonKeyRetiring        = "key_retiring"
	ReasonKeyExpired         = "key_expired"
	ReasonAdminTarget        = "admin_target"
	ReasonScopesNotSubset    = "scopes_not_subset"
	ReasonExpiryAfterParent  = "expiry_after_parent"
	ReasonLineageTooDeep     = "lineage_too_deep"
	ReasonPermissionNotAdmin = "permission_not_admin"
	ReasonOtherUser          = "other_user"
	ReasonTargetNotEligible  = "target_not_eligible"
	ReasonUnknownOperation   = "unknown_operation"
	ReasonNotEnabledUser     = "not_enabled_user"
	ReasonNotAdmin           = "not_admin"
	ReasonSelfDelete         = "self_delete"
	ReasonSingleOwner        = "single_owner"
	ReasonNotOwner           = "not_owner"
	ReasonUnknownVia         = "unknown_via"
	ReasonViaWithActor       = "via_with_actor"
	// The owner protections account applies after the Policy, for every
	// Policy.
	ReasonOwnerTarget           = "owner_target"             // a principal that is no owner acting on an owner
	ReasonOwnerRole             = "owner_role"               // a role change of an owner
	ReasonLastOwner             = "last_owner"               // a change that leaves no enabled owner
	ReasonOwnerNeedsLocalMethod = "owner_needs_local_method" // an owner must be an enabled admin with a usable password or passkey
)

// PolicyReasons returns every Reason account's own rules and policies put
// in a PolicyError, in a stable order.
func PolicyReasons() []string {
	return []string{
		ReasonOutOfBandOnly,
		ReasonKeyNotCurrent,
		ReasonKeyRetiring,
		ReasonKeyExpired,
		ReasonAdminTarget,
		ReasonScopesNotSubset,
		ReasonExpiryAfterParent,
		ReasonLineageTooDeep,
		ReasonPermissionNotAdmin,
		ReasonOtherUser,
		ReasonTargetNotEligible,
		ReasonUnknownOperation,
		ReasonNotEnabledUser,
		ReasonNotAdmin,
		ReasonSelfDelete,
		ReasonSingleOwner,
		ReasonNotOwner,
		ReasonUnknownVia,
		ReasonViaWithActor,
		ReasonOwnerTarget,
		ReasonOwnerRole,
		ReasonLastOwner,
		ReasonOwnerNeedsLocalMethod,
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

// The CodeError Reasons, in CodeReasons order.
const (
	ReasonCodeInvalid  = "code_invalid"
	ReasonCodeReused   = "code_reused" // a code whose step was already accepted
	ReasonMethodLocked = "method_locked"
	// ReasonCurrentCodeInvalid is a replacement's current code, from the
	// old secret, that does not match.
	ReasonCurrentCodeInvalid = "current_code_invalid"
)

// CodeReasons returns every CodeError Reason, in a stable order.
func CodeReasons() []string {
	return []string{ReasonCodeInvalid, ReasonCodeReused, ReasonMethodLocked, ReasonCurrentCodeInvalid}
}

// CodeError is a code an operation refused, with why. Reason is one of
// CodeReasons. It matches ErrCodeInvalid.
type CodeError struct {
	Reason string
}

func (e *CodeError) Error() string { return "account: code refused: " + e.Reason }

// Is reports ErrCodeInvalid.
func (*CodeError) Is(target error) bool { return target == ErrCodeInvalid }

// MalformedError is a code that cannot be one: not six ASCII digits once
// spaces are removed. Field names the input that held it. Nothing is
// counted for it. It matches ErrCodeMalformed.
type MalformedError struct {
	Field string
}

func (e *MalformedError) Error() string { return "account: malformed code: " + e.Field }

// Is reports ErrCodeMalformed.
func (*MalformedError) Is(target error) bool { return target == ErrCodeMalformed }

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

// The UsernameError and TextError Reasons. A TextError is ReasonEmpty only
// for a key label: every other display text may be empty.
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
func TextErrorReasons() []string {
	return []string{ReasonEmpty, ReasonDisallowedCharacter, ReasonTooLong}
}

// TextErrors returns every {Field, Reason} pair an operation returns as a
// *TextError, in a stable order: a label is refused empty, a display name
// never is.
func TextErrors() []TextError {
	return []TextError{
		{Field: TextFieldLabel, Reason: ReasonEmpty},
		{Field: TextFieldLabel, Reason: ReasonDisallowedCharacter},
		{Field: TextFieldLabel, Reason: ReasonTooLong},
		{Field: TextFieldDisplayName, Reason: ReasonDisallowedCharacter},
		{Field: TextFieldDisplayName, Reason: ReasonTooLong},
	}
}

// UsernameError is a username a creation path refuses, before any limiter
// call or hash. Reason is one of UsernameReasons.
type UsernameError struct {
	Reason string
}

func (e *UsernameError) Error() string { return "account: invalid username: " + e.Reason }

// TextError is a display text an operation refuses before any write. Field
// is one of TextErrorFields, Reason one of TextErrorReasons, and the pair
// one of TextErrors: disallowed_character is invalid UTF-8, a control, bidi
// control or line separator character.
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
