package account

import (
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn"
)

// SignedIn is a new session for a sign-in, a setup or an invite acceptance.
type SignedIn struct {
	User         *access.User
	Token        access.Secret // the session cookie value
	DeviceCookie access.Secret // set when non-zero
	Session      access.Session
	CloneWarning bool
}

// Issued is a rotated or restricted session.
type Issued struct {
	Token        access.Secret
	DeviceCookie access.Secret // set after a step-up or a verified current password; zero otherwise
	Session      access.Session
}

// State is what an anonymous caller may learn: whether setup is needed, which
// sign-in methods the request's transport admits, and what HTTPS would add.
type State struct {
	// PlainSession is the longest a session signed in by this request may
	// last; set only on a plain request under access.PosturePerRequest.
	PlainSession *access.SessionTimeouts
	// HTTPSOrigin is Rules.HTTPSOrigin on a plain request, else empty.
	HTTPSOrigin string
	// HTTPSRequired is each offered feature the request's transport
	// withholds, in the HTTPSFeature constants' order; empty when secure.
	HTTPSRequired []HTTPSFeature
	// SSO is the stored SSO mode.
	SSO SSOMode
	// PasswordLogin, Passkeys and OIDC are each offered and admitted over
	// the request's transport.
	SetupRequired, PasswordLogin, Passkeys, OIDC bool
	// Secure is the request's Client.Secure.
	Secure bool
	// TOTP is whether the app offers TOTP: wired, and Rules.DisableTOTP off.
	TOTP bool
}

// HTTPSFeature is a sign-in feature a plain request is refused.
type HTTPSFeature string

// The features, in State.HTTPSRequired's order.
const (
	HTTPSPassword HTTPSFeature = "password"
	HTTPSSetup    HTTPSFeature = "setup"
	HTTPSPasskeys HTTPSFeature = "passkeys"
	HTTPSOIDC     HTTPSFeature = "oidc"
)

// PendingCeremony is a begun WebAuthn ceremony, held by the service until
// its finish call takes it.
type PendingCeremony struct {
	Creation  *webauthn.CredentialCreation  // registration ceremonies
	Assertion *webauthn.CredentialAssertion // login, step-up
	ID        string                        // 256-bit random hex; the X-Auth-Ceremony value
}

// PendingLink is an OIDC identity no account is linked to yet.
type PendingLink struct {
	// Provision is set when provisioning admitted the identity but its name
	// was taken, so CreatePendingOIDC may create an account with this role.
	Provision *Provision
	// Invite is set instead, to the invite's stored hash, when an invite's
	// callback found its name taken, so CreatePendingOIDC may accept it.
	Invite       access.Hash
	UsernameHint string // preferred_username as sent, display only
	Email        string // only when email_verified
	// SuggestedUsername is the default name for CreatePendingOIDC, set only
	// when CanCreate; it may be taken too.
	SuggestedUsername string
	Identity          access.OIDCIdentity
}

// CanCreate reports whether CreatePendingOIDC may create an account for p.
func (p *PendingLink) CanCreate() bool { return p.Provision != nil || !p.Invite.IsZero() }

// Provision is what the callback that admitted a pending identity decided
// for its account.
type Provision struct {
	Role access.Role
}

// OIDCOutcomeKind is which arm of an OIDCOutcome is set.
type OIDCOutcomeKind int

// The outcome kinds.
const (
	OutcomeSignedIn OIDCOutcomeKind = iota
	OutcomeNotLinked
	OutcomeLinked
	OutcomeSteppedUp
)

// OIDCOutcome is what an OIDC callback did.
type OIDCOutcome struct {
	Redirect string      // the sealed redirect, already validated
	Pending  PendingLink // OutcomeNotLinked
	Issued   Issued      // OutcomeLinked, OutcomeSteppedUp: the rotated session
	SignedIn SignedIn    // OutcomeSignedIn
	Kind     OIDCOutcomeKind
}

// Registered is an enrolled passkey and the rotated session.
type Registered struct {
	// RecoveryCode is the recovery code the registration issued, shown
	// only here; zero when it issued none.
	RecoveryCode access.Secret
	Issued       Issued
	Passkey      Passkey
}

// PasswordSet is SetPassword's answer: the rotated session, and the
// recovery code a first password issued, shown only here; zero when it
// issued none.
type PasswordSet struct {
	RecoveryCode access.Secret
	Issued       Issued
}

// Passkey is one of a user's own passkeys, with whether RemovePasskey would
// remove it: false when the last-method or the second-factor guard would
// refuse.
type Passkey struct {
	Credential access.PasskeyCredential
	Removable  bool
}

// CreatedKey is a minted key; Plaintext is shown once.
type CreatedKey struct {
	Plaintext access.Secret
	Key       access.Key
	Issued    Issued // zero for an out-of-band or a key actor
}

// RotatedKey is a key RotateAPIKey gave a new secret; Plaintext is shown
// once.
type RotatedKey struct {
	Plaintext access.Secret
	Key       access.Key // PreviousUntil set, LastUsedAt zero
	Issued    Issued     // zero for an out-of-band actor
}

// IssuedToken is a minted invite token; Plaintext is shown once.
type IssuedToken struct {
	ExpiresAt time.Time // the stored expiry, capped at an issuing key's
	Plaintext access.Secret
}

// MethodLock is a method locked by the failure cap, per trust context.
type MethodLock struct {
	Method             access.Method
	Untrusted, Trusted bool
}

// Methods is what a user can sign in with.
type Methods struct {
	TOTP              TOTPState
	Locks             []MethodLock // locked methods only
	PasskeyCount      int
	HasPassword       bool
	OIDCLinked        bool
	OIDCAvailable     bool
	PasskeysAvailable bool
	PasswordLogin     bool // !Rules.DisablePasswordLogin
	RecoveryCode      bool // a recovery code is stored
	// SecondFactorHeld is secondFactorHeld: adding or removing a passkey
	// needs a current second factor while it is true.
	SecondFactorHeld bool
	// PasswordStepUp is whether step-up may offer the password: the user
	// holds one, no second factor is held, and neither DisablePasswordLogin
	// nor the stored SSO mode refuses it.
	PasswordStepUp bool
}

// TOTPState is a user's TOTP record as their own view reads it.
type TOTPState struct {
	Since    time.Time // the record's CreatedAt; zero with none
	Enrolled bool      // a record is stored
	// Usable is a record that reads as present: TOTP wired and not turned
	// off by Rules.DisableTOTP.
	Usable bool
	// Removable is whether RemoveTOTP would remove it: false with no
	// record, and while the second-factor guard would refuse.
	Removable bool
}

// CurrentSession is the caller's own session.
type CurrentSession struct {
	AuthTime, IdleDeadline, AbsoluteDeadline time.Time
	ID                                       string
	Method                                   access.Method
	Secure                                   bool // the session's transport, access.Principal.Secure
}

// Me is the signed-in user's own view.
type Me struct {
	User        *access.User
	Current     CurrentSession
	Methods     Methods
	CanLinkOIDC bool // OIDCAvailable and not OIDCLinked
	// SingleUser is the Policy's declaration as New kept it.
	SingleUser bool
	// SSOOnly is the stored SSO mode keeping the user's local methods
	// dormant: adding a password or passkey answers ErrSSOOnly, as does a
	// step-up by either.
	SSOOnly bool
}

// ListedUser is one row of the admin user list.
type ListedUser struct {
	// KeyLineage is the KeyLineage of the user's most recent KeyAttribution
	// that the filter matched (of its most recent one, unfiltered), derived
	// at read; nil when no key has acted on the user.
	KeyLineage []int64
	User       access.User
	// PasskeyCount is how many passkeys the user holds, read with the list;
	// with User.PasswordHash and User.OIDC it is the user's sign-in methods
	// on the admin list.
	PasskeyCount int
	// LocalMethodsDormant is the stored SSO mode, read once for the list,
	// keeping the user's password and passkeys dormant.
	LocalMethodsDormant bool
	// RoleFromProvider is whether Rules.Provisioning.SyncRole, read once for
	// the list, sets the user's role at each OIDC sign-in.
	RoleFromProvider bool
}

// ListedKey is one row of the admin key list.
type ListedKey struct {
	Owner string // the owner's username; empty when its user row is gone
	Key   access.Key
}

// ListedToken is one row of the admin token list.
type ListedToken struct {
	// IssuerLineage is the LineageIDs of the key named by Token.IssuedByKey,
	// read with the list; nil for a token no key issued.
	IssuerLineage []int64
	Token         access.OneTimeToken
}
