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

// State is what an anonymous caller may learn: whether setup is needed,
// and which sign-in methods are offered.
type State struct{ SetupRequired, PasswordLogin, Passkeys, OIDC bool }

// PendingCeremony is a begun WebAuthn ceremony, held by the service until
// its finish call takes it.
type PendingCeremony struct {
	Creation  *webauthn.CredentialCreation  // registration ceremonies
	Assertion *webauthn.CredentialAssertion // login, step-up
	ID        string                        // 256-bit random hex; the X-Auth-Ceremony value
}

// PendingLink is an OIDC identity no account is linked to yet.
type PendingLink struct {
	UsernameHint string // preferred_username as sent, display only
	Email        string // only when email_verified
	Identity     access.OIDCIdentity
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
	Issued  Issued
	Passkey access.PasskeyCredential
}

// CreatedKey is a minted key; Plaintext is shown once.
type CreatedKey struct {
	Plaintext access.Secret
	Key       access.Key
	Issued    Issued // zero for an out-of-band or a key actor
}

// IssuedToken is a minted invite or recovery token; Plaintext is shown
// once.
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
	Locks             []MethodLock // locked methods only
	PasskeyCount      int
	HasPassword       bool
	OIDCLinked        bool
	OIDCAvailable     bool
	PasskeysAvailable bool
	PasswordLogin     bool // !Rules.DisablePasswordLogin
}

// CurrentSession is the caller's own session.
type CurrentSession struct {
	AuthTime, IdleDeadline, AbsoluteDeadline time.Time
	ID                                       string
	Method                                   access.Method
}

// Me is the signed-in user's own view.
type Me struct {
	User        *access.User
	Current     CurrentSession
	Methods     Methods
	CanLinkOIDC bool // OIDCAvailable and not OIDCLinked
}

// Recovery is a started recovery: the restricted session and what the
// user holds.
type Recovery struct {
	Username string
	Methods  Methods
	Issued   Issued
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
