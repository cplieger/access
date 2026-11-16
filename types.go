package access

import (
	"log/slog"
	"slices"
	"time"
)

// Method names how a principal was authenticated. Values outside the
// constants below are app-defined and opaque to the library.
type Method string

// Auth method identifiers stored in sessions and used for method guards.
const (
	MethodPassword     Method = "password"
	MethodPasskey      Method = "passkey"
	MethodOIDC         Method = "oidc"
	MethodTOTP         Method = "totp"
	MethodRecoveryCode Method = "recovery_code"
	MethodAPIKey       Method = "api_key"
	MethodBypass       Method = "bypass"
)

// Role is a typed string identifying a user's authorization level.
// Values outside the constants are app-defined.
type Role string

// User role constants.
const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// OIDCIdentity is an account's link to an identity provider. The zero
// value means unlinked.
type OIDCIdentity struct {
	Issuer  string
	Subject string
}

// IsZero reports whether i links no identity.
func (i OIDCIdentity) IsZero() bool { return i == OIDCIdentity{} }

// User represents an authenticated user account. It carries no key
// attribution: what a key did to a user is a [KeyAttribution] record.
type User struct {
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	Username     string       `json:"username"` // canonical form; see NormalizeUsername
	Email        string       `json:"email,omitempty"`
	DisplayName  string       `json:"display_name,omitempty"`
	PasswordHash Hash         `json:"-"`
	Role         Role         `json:"role"`
	OIDC         OIDCIdentity `json:"-"`

	// WebAuthnHandle is the account's WebAuthn user handle, which an
	// authenticator returns during a discoverable login. Set it once with
	// [GenerateWebAuthnHandle] and never change it: every registered passkey is
	// bound to it, so a new handle orphans them all. It is derived from no other
	// field, because an authenticator may reveal it without verifying the user.
	WebAuthnHandle []byte `json:"-"`

	ID      int64 `json:"id"`
	Enabled bool  `json:"-"`
	// Owner marks a break-glass account; an owner always has RoleAdmin.
	Owner bool `json:"-"`
	// WaitingApproval marks a registration an admin has not approved yet;
	// such an account is also not Enabled.
	WaitingApproval bool `json:"-"`
}

// Clone returns a deep copy, or nil for a nil u.
func (u *User) Clone() *User {
	if u == nil {
		return nil
	}
	c := *u
	c.WebAuthnHandle = slices.Clone(u.WebAuthnHandle)
	return &c
}

// LogValue emits the id, username, role, owner and waiting flags, and
// presence markers for the password hash, the WebAuthn handle and the OIDC
// link.
func (u User) LogValue() slog.Value { //nolint:gocritic // hugeParam: a value receiver applies LogValue to a User value too
	return slog.GroupValue(
		slog.Int64("id", u.ID),
		slog.String("username", u.Username),
		slog.String("role", string(u.Role)),
		slog.Bool("owner", u.Owner),
		slog.Bool("waiting_approval", u.WaitingApproval),
		slog.Bool("has_password", !u.PasswordHash.IsZero()),
		slog.Bool("has_webauthn_handle", len(u.WebAuthnHandle) > 0),
		slog.Bool("has_oidc", !u.OIDC.IsZero()),
	)
}

// Session is a server-side session record. Its wire view is the HTTP
// layer's, so it carries no JSON tags beyond keeping the hash out.
type Session struct {
	CreatedAt    time.Time
	LastActivity time.Time
	// AuthTime is the last primary sign-in or step-up.
	AuthTime   time.Time
	ID         string // 128-bit random hex; stable across a token rotation
	TokenHash  Hash   `json:"-"`
	AuthMethod Method
	UserAgent  string // sanitised and capped at 256 bytes by its writer
	Label      string // user-editable, at most 64 runes
	LastIP     string // netip.Addr.String() of the client, as its writer last recorded it
	UserID     int64
	// IdleCap and AbsoluteCap are this session's own idle and absolute
	// limits; a zero or negative cap is none. [SessionDeadlines] applies them.
	IdleCap     time.Duration
	AbsoluteCap time.Duration
	// Secure is the transport of the request that created the session, set at
	// creation from [ClientAddr.Secure]. The zero value is plain, the weakest
	// binding, so a store that drops the field fails closed.
	Secure bool
}

// LogValue emits the session's identity, transport and times, never the
// hash.
func (s Session) LogValue() slog.Value { //nolint:gocritic // hugeParam: a value receiver applies LogValue to a Session value too
	return slog.GroupValue(
		slog.String("id", s.ID),
		slog.Int64("user_id", s.UserID),
		slog.String("auth_method", string(s.AuthMethod)),
		slog.Bool("secure", s.Secure),
		slog.Time("created_at", s.CreatedAt),
		slog.Time("last_activity", s.LastActivity),
		slog.Time("auth_time", s.AuthTime),
	)
}

// SessionRef names one session of one user; the zero value matches nothing.
type SessionRef struct {
	ID     string
	UserID int64
}

// SessionActivity is what an active verified request writes back.
type SessionActivity struct {
	At time.Time
	IP string
}

// AuthenticatorAttachment reports how the authenticator that created a
// credential is attached to the client device.
type AuthenticatorAttachment string

// The attachment modalities defined by WebAuthn §5.4.5. The zero value means
// the client did not report one, which is legal.
const (
	AttachmentPlatform      AuthenticatorAttachment = "platform"
	AttachmentCrossPlatform AuthenticatorAttachment = "cross-platform"
)

// PasskeyCredential represents a WebAuthn/FIDO2 credential registered to a user.
//
// The field set is the credential record of WebAuthn §Credential Record. Every
// item that specification lists as RECOMMENDED is here, so a store persisting
// all of it can execute both the registration and the assertion algorithms.
type PasskeyCredential struct {
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at,omitzero"`

	// Discoverable is the credProps.rk extension output; nil means the client
	// did not report it. Registration requests credProps and refuses a reported
	// false, so a stored false should not occur. It is the only extension output
	// stored, because credProps is the only extension requested.
	Discoverable *bool `json:"-"`

	// RPID is the relying-party ID the credential was registered against. It
	// decides where the credential can be used, so a change to the relying
	// party's ID can be audited against it rather than silently orphaning every
	// passkey.
	RPID string `json:"-"`

	Transport string `json:"transport,omitempty"`
	Name      string `json:"name"`

	// Attachment is how the authenticator was attached at registration. Empty
	// when the client did not report it.
	Attachment AuthenticatorAttachment `json:"-"`

	CredentialID []byte `json:"-"`
	PublicKey    []byte `json:"-"`
	AAGUID       []byte `json:"-"`

	ID     int64 `json:"id"`
	UserID int64 `json:"user_id"`

	SignCount uint32 `json:"-"`

	// RawFlags is the authenticator-data flags octet, written at registration
	// and by each login's [PasskeyLoginUpdate]; it is the only flag input this
	// library reads, and it keeps the AT and ED bits the booleans below drop.
	// Those booleans are a decoded view nothing here reads back. A store MUST
	// persist the octet: a real registration sets user presence, so a zero
	// octet means the store dropped it, and the webauthn package then refuses
	// the next login whose authenticator asserts backup eligibility (rule 8 of
	// the account package's store contract).
	RawFlags uint8 `json:"-"`

	BackupEligible bool `json:"backup_eligible"`
	BackupState    bool `json:"-"`
	UserPresent    bool `json:"-"`

	// UserVerified is the specification's uvInitialized: it latches true once
	// any assertion has verified the user. To decide whether one PARTICULAR
	// ceremony verified the user, read that ceremony's own authenticator data.
	UserVerified bool `json:"-"`

	CloneWarning bool `json:"-"`
}

// Clone returns a deep copy, or nil for a nil c.
func (c *PasskeyCredential) Clone() *PasskeyCredential {
	if c == nil {
		return nil
	}
	cp := *c
	if c.Discoverable != nil {
		cp.Discoverable = new(*c.Discoverable)
	}
	cp.CredentialID = slices.Clone(c.CredentialID)
	cp.PublicKey = slices.Clone(c.PublicKey)
	cp.AAGUID = slices.Clone(c.AAGUID)
	return &cp
}

// PasskeyLoginUpdate is the custody write after an assertion. It carries the
// flags octet, which the store decodes with [DecodePasskeyFlags], so the
// octet and the booleans cannot diverge.
type PasskeyLoginUpdate struct {
	At           time.Time
	SignCount    uint32
	RawFlags     uint8
	CloneWarning bool
}

// Authenticator-data flag bits (WebAuthn §6.1, "flags").
const (
	flagUserPresent    = 1 << 0
	flagUserVerified   = 1 << 2
	flagBackupEligible = 1 << 3
	flagBackupState    = 1 << 4
)

// DecodePasskeyFlags is the one decoder of the authenticator-data flags
// octet.
func DecodePasskeyFlags(octet uint8) (userPresent, userVerified, backupEligible, backupState bool) {
	return octet&flagUserPresent != 0, octet&flagUserVerified != 0,
		octet&flagBackupEligible != 0, octet&flagBackupState != 0
}

// PasskeyRef identifies one passkey credential together with the user who
// must own it. Rename/delete operations take the pair as one value so the
// ownership check cannot be silently disarmed by swapping two adjacent int64
// arguments: the field names make each value's role explicit at the call site.
// The zero value identifies nothing: no stored credential has ID or UserID
// zero, so an operation given a zero or partial ref affects no row (fails
// closed).
type PasskeyRef struct {
	// ID is the credential row ID (PasskeyCredential.ID).
	ID int64
	// UserID is the owning user; an operation must affect the credential only
	// when it belongs to this user.
	UserID int64
}

// KeyRef identifies one API key together with the user who must own it.
// See [PasskeyRef] for why the pair travels as one value. The zero value
// identifies nothing: no stored key has ID or UserID zero, so an operation
// given a zero or partial ref affects no row (fails closed).
type KeyRef struct {
	// ID is the key row ID (Key.ID).
	ID int64
	// UserID is the owning user; an operation must affect the key only when
	// it belongs to this user.
	UserID int64
}

// Key represents a machine-to-machine API key for a user.
type Key struct {
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"` // zero = never
	// LastUsedAt is the current secret's last use, as the Authenticator's
	// touch records it; a rotation zeroes it, so zero after a rotation means
	// the new secret is unused.
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
	// PreviousUntil bounds the overlap in which PreviousHash still verifies.
	PreviousUntil time.Time `json:"previous_until,omitzero"`
	KeyHash       Hash      `json:"-"`
	// PreviousHash is the secret the last rotation superseded, zero when
	// none; it verifies while [Key.PreviousSecretUsable].
	PreviousHash Hash     `json:"-"`
	KeyPrefix    string   `json:"key_prefix"`
	KeySuffix    string   `json:"key_suffix"`
	Label        string   `json:"label"`
	Scopes       []string `json:"scopes"` // opaque to the library; the app's vocabulary
	// LineageIDs is the key's ancestor path, fixed at mint: root first, the
	// key's own ID last. A key minted by a key has its parent's path plus its
	// own ID; a key a session or an out-of-band actor minted has its own ID
	// alone. Revoking a key revokes every key whose path contains it, and
	// every KeyAttribution records the acting key's path. Store key IDs are
	// never reused, so a path names its keys for the life of the store.
	LineageIDs []int64 `json:"lineage_ids"`
	ID         int64   `json:"id"`
	UserID     int64   `json:"user_id"`
}

// KeySecret is the part of a [Key] a rotation replaces: the new secret's
// hash and display parts, and the superseded secret with its overlap bound.
type KeySecret struct {
	PreviousUntil time.Time
	KeyHash       Hash
	PreviousHash  Hash
	KeyPrefix     string
	KeySuffix     string
}

// ParentKeyID is the key that minted k (the second-last ID of LineageIDs),
// or 0 for a key a session or an out-of-band actor minted.
func (k Key) ParentKeyID() int64 { //nolint:gocritic // hugeParam: a value receiver keeps it callable on a non-addressable Key
	if n := len(k.LineageIDs); n >= 2 {
		return k.LineageIDs[n-2]
	}
	return 0
}

// PreviousSecretUsable reports whether k's previous secret verifies at now:
// PreviousHash is set, now is before PreviousUntil, and the current secret
// is unused (LastUsedAt zero).
func (k *Key) PreviousSecretUsable(now time.Time) bool {
	return !k.PreviousHash.IsZero() && now.Before(k.PreviousUntil) && k.LastUsedAt.IsZero()
}

// Clone returns a deep copy, or nil for a nil k.
func (k *Key) Clone() *Key {
	if k == nil {
		return nil
	}
	c := *k
	c.Scopes = slices.Clone(k.Scopes)
	c.LineageIDs = slices.Clone(k.LineageIDs)
	return &c
}

// LogValue emits the id, user, prefix, suffix and scopes, never KeyHash.
func (k Key) LogValue() slog.Value { //nolint:gocritic // hugeParam: a value receiver applies LogValue to a Key value too
	return slog.GroupValue(
		slog.Int64("id", k.ID),
		slog.Int64("user_id", k.UserID),
		slog.String("prefix", k.KeyPrefix),
		slog.String("suffix", k.KeySuffix),
		slog.Any("scopes", k.Scopes),
	)
}

// TokenPurpose names what a one-time token unlocks. Values outside the
// constants are app-defined.
type TokenPurpose string

// One-time token purposes.
const (
	PurposeSetup  TokenPurpose = "setup"
	PurposeInvite TokenPurpose = "invite"
)

// OneTimeToken is the stored record of a single-use token.
type OneTimeToken struct {
	CreatedAt time.Time
	ExpiresAt time.Time
	Hash      Hash `json:"-"`
	Purpose   TokenPurpose
	Role      Role // PurposeInvite only: the role the invited account receives
	// IssuedByKey is the API key whose principal issued this invite; 0 when
	// a session or an out-of-band actor issued it. A key-issued token
	// expires no later than that key, dies with it, and is re-checked
	// against it when used.
	IssuedByKey int64
}

// LogValue emits the purpose, issuer key and expiry, never Hash.
func (t OneTimeToken) LogValue() slog.Value { //nolint:gocritic // hugeParam: a value receiver applies LogValue to a token value too
	return slog.GroupValue(
		slog.String("purpose", string(t.Purpose)),
		slog.Int64("issued_by_key", t.IssuedByKey),
		slog.Time("expires_at", t.ExpiresAt),
	)
}

// NewOneTimeToken mints a 256-bit token expiring ttl after now. Store only
// the record; hand out only the plaintext. IssuedByKey and Role are left
// for the issuer to set.
func NewOneTimeToken(purpose TokenPurpose, ttl time.Duration, now time.Time) (plaintext Secret, rec OneTimeToken) {
	plaintext, hash := GenerateOpaqueToken()
	return plaintext, OneTimeToken{
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Hash:      hash,
		Purpose:   purpose,
	}
}

// AttributionAction names what a key did to a user.
type AttributionAction string

// Attribution actions.
const (
	AttributionCreated        AttributionAction = "created"         // CreateUser by a key
	AttributionInviteAccepted AttributionAction = "invite_accepted" // a key-issued invite created the user
	AttributionEnabled        AttributionAction = "enabled"         // UpdateUser by a key re-enabled the user
	AttributionDisabled       AttributionAction = "disabled"        // UpdateUser by a key disabled the user
	// AttributionTemporaryPasswordSet is SetTemporaryPassword by a key.
	AttributionTemporaryPasswordSet AttributionAction = "temporary_password_set"
)

// KeyAttribution is one append-only record that a key acted on a user. It
// is written in the same store update as the act, never updated, and
// deleted only with its user; revoking or deleting the key, or disabling
// the user, leaves it.
type KeyAttribution struct {
	At     time.Time         `json:"at"`
	Action AttributionAction `json:"action"`
	// KeyLineage is the acting or issuing key's LineageIDs as read inside
	// the writing update: root first, that key last.
	KeyLineage []int64 `json:"key_lineage"`
	ID         int64   `json:"id"` // assigned by the store, increasing in append order
	UserID     int64   `json:"user_id"`
}

// Clone returns a deep copy, or nil for a nil a.
func (a *KeyAttribution) Clone() *KeyAttribution {
	if a == nil {
		return nil
	}
	c := *a
	c.KeyLineage = slices.Clone(a.KeyLineage)
	return &c
}

// Contains reports whether keyID is in KeyLineage.
func (a KeyAttribution) Contains(keyID int64) bool { //nolint:gocritic // hugeParam: a value receiver keeps it callable on a non-addressable record
	return slices.Contains(a.KeyLineage, keyID)
}

// TOTP is a user's authenticator-app record, one per user. Sealed is the
// secret sealed with [Sealer.SealAtRest] for the purpose "totp:" and the
// user's ID, so a record copied onto another user's row does not open.
// LastStep is the highest time step accepted, which no later code may
// reuse.
type TOTP struct {
	CreatedAt time.Time
	Sealed    string `json:"-"`
	UserID    int64
	LastStep  int64
}

// LogValue emits the user, creation time and last step, never Sealed.
func (t TOTP) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int64("user_id", t.UserID),
		slog.Time("created_at", t.CreatedAt),
		slog.Int64("last_step", t.LastStep),
	)
}

// RecoveryCode is a user's saved recovery code, one per user, stored only
// as the password hasher's salted hash (NIST SP 800-63B-4 §4.2.1.1).
type RecoveryCode struct {
	CreatedAt time.Time
	Hash      Hash `json:"-"`
	UserID    int64
}

// LogValue emits the user and creation time, never Hash.
func (c RecoveryCode) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int64("user_id", c.UserID),
		slog.Time("created_at", c.CreatedAt),
	)
}

// TemporaryPassword is an admin-issued, single-use password, one per user,
// kept apart from [User.PasswordHash], so a store that drops it fails
// closed. IssuedByUser is the issuing admin and IssuedByKey the issuing API
// key; both are zero for an out-of-band issue. Dormant marks one issued
// while the user's local methods were dormant, whose one use is the admin
// link.
type TemporaryPassword struct {
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Hash         Hash `json:"-"`
	UserID       int64
	IssuedByUser int64
	IssuedByKey  int64
	Dormant      bool
}

// LogValue emits every field but Hash.
func (p TemporaryPassword) LogValue() slog.Value { //nolint:gocritic // hugeParam: a value receiver applies LogValue to a TemporaryPassword value too
	return slog.GroupValue(
		slog.Int64("user_id", p.UserID),
		slog.Int64("issued_by_user", p.IssuedByUser),
		slog.Int64("issued_by_key", p.IssuedByKey),
		slog.Bool("dormant", p.Dormant),
		slog.Time("created_at", p.CreatedAt),
		slog.Time("expires_at", p.ExpiresAt),
	)
}
