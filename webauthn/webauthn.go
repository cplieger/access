// Package webauthn wraps go-webauthn/webauthn to provide WebAuthn/FIDO2
// passkey ceremony helpers. It imports the core access package for types
// but never the reverse.
package webauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/cplieger/access"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

const (
	// CeremonyTimeout is the maximum duration a user has to complete an auth ceremony.
	CeremonyTimeout = 5 * time.Minute
	// MaxResponseBytes is the largest authenticator response a Finish or
	// Complete call reads; a larger one is refused with [ErrResponseTooLarge].
	MaxResponseBytes = 64 << 10
)

// ErrResponseTooLarge reports an authenticator response longer than
// [MaxResponseBytes]. At most MaxResponseBytes+1 bytes are read to decide it.
var ErrResponseTooLarge = errors.New("access/webauthn: the authenticator response is larger than MaxResponseBytes")

// Store is the store interface [CompleteLogin] and [CompleteReauthentication]
// consume: the account and its passkeys by user handle, and the post-login
// custody write. An [github.com/cplieger/access/account.Store] satisfies it.
type Store interface {
	PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error)
	UpdatePasskeyAfterLogin(ctx context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error
	UserByWebAuthnHandle(ctx context.Context, handle []byte) (user *access.User, found bool, err error)
}

// User adapts access.User + credentials to the gowebauthn.User interface.
type User struct {
	AuthUser    *access.User
	Credentials []access.PasskeyCredential
}

// NewUser returns a User with the given user and credentials.
func NewUser(user *access.User, creds []access.PasskeyCredential) (*User, error) {
	if user == nil {
		return nil, errors.New("access/webauthn: NewUser called with nil user")
	}
	return &User{AuthUser: user, Credentials: creds}, nil
}

// WebAuthnID returns the account's stored WebAuthn user handle.
//
// The store sets it with [access.GenerateWebAuthnHandle] at account creation and
// never changes it; every passkey is bound to the value in force at its
// registration. An empty handle violates the specification's MUST NOT-be-empty
// rule, so a store that returns one is misconfigured.
func (u *User) WebAuthnID() []byte {
	return u.AuthUser.WebAuthnHandle
}

// WebAuthnName returns the username.
func (u *User) WebAuthnName() string {
	return u.AuthUser.Username
}

// WebAuthnDisplayName returns the display name, falling back to username.
func (u *User) WebAuthnDisplayName() string {
	if u.AuthUser.DisplayName != "" {
		return u.AuthUser.DisplayName
	}
	return u.AuthUser.Username
}

// userAdapter satisfies gowebauthn.User on behalf of [User].
//
// Three of the interface's four methods return first-party types and live on the
// exported User. The fourth returns []gowebauthn.Credential, so putting it there
// would leak an upstream type onto this package's surface for the sake of an
// interface only this package implements. The adapter carries that one method
// and nothing else.
type userAdapter struct {
	*User
}

var _ gowebauthn.User = (*userAdapter)(nil)

// WebAuthnCredentials converts the stored credentials to gowebauthn.Credential.
func (u *userAdapter) WebAuthnCredentials() []gowebauthn.Credential {
	creds := make([]gowebauthn.Credential, len(u.Credentials))
	for i := range u.Credentials {
		creds[i] = credentialFromAPI(&u.Credentials[i])
	}
	return creds
}

// aaguidEntry maps an authenticator AAGUID to a friendly name.
type aaguidEntry struct {
	UUID string
	Name string
}

var knownAAGUIDMap = func() map[string]string {
	m := make(map[string]string, len(knownAAGUIDTable))
	for _, e := range knownAAGUIDTable {
		m[e.UUID] = e.Name
	}
	return m
}()

// formatAAGUID formats a 16-byte AAGUID as a UUID string (8-4-4-4-12).
//
// An AAGUID is an opaque 128-bit identifier, not a conformant RFC 9562 UUID;
// [uuid.UUID.String] neither validates nor rewrites the version and variant
// bits, so it formats any 16 bytes.
func formatAAGUID(aaguid []byte) string {
	if len(aaguid) != 16 {
		return ""
	}
	return uuid.UUID(aaguid).String()
}

// AuthenticatorName returns the passkey provider name for a 16-byte AAGUID,
// from the community list at
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids. It
// reports false for an unknown AAGUID or one that is not 16 bytes long. The
// AAGUID is self-asserted by the authenticator under "none" attestation, so
// the name is a display label, never evidence of the authenticator's make.
func AuthenticatorName(aaguid []byte) (string, bool) {
	name, ok := knownAAGUIDMap[formatAAGUID(aaguid)]
	return name, ok
}

// nameSuffix reports whether name is a label PasskeyFriendlyName derives from
// base -- the bare base (which counts as suffix 1) or "base N" for a positive
// integer N -- and returns that suffix. ok is false for any other name,
// including one like "YubiKey 5 NFC" that merely shares a "base "-prefixed
// string with a different known base ("YubiKey 5"). nextNameSuffix routes
// through this helper so the suffix classification lives in exactly one place.
func nameSuffix(name, base string) (suffix int, ok bool) {
	if name == base {
		return 1, true
	}
	if rest, found := strings.CutPrefix(name, base+" "); found {
		if n, err := strconv.Atoi(rest); err == nil && n >= 1 {
			return n, true
		}
	}
	return 0, false
}

// nextNameSuffix returns one past the highest numeric suffix already in use
// among names derived from base: a name equal to base counts as suffix 1 (the
// bare form) and a name "base N" for a positive integer N counts as N. The
// result is 1 when no name matches. Deriving the suffix from the maximum in use
// -- rather than from a count of matches -- keeps generated names unique after
// a non-tail deletion leaves a numbering gap: deleting "Passkey 1" from
// ["Passkey 1", "Passkey 2"] still yields "Passkey 3", not a duplicate
// "Passkey 2".
func nextNameSuffix(existingNames []string, base string) int {
	highest := 0
	for _, name := range existingNames {
		if n, ok := nameSuffix(name, base); ok {
			highest = max(highest, n)
		}
	}
	return highest + 1
}

// PasskeyFriendlyName returns a display-only label for a newly registered
// passkey that duplicates no entry in existingNames. A known AAGUID gets its
// registry name ("Chrome on Mac"), numbered from the second of its kind ("Chrome
// on Mac 2"); an unknown one is always numbered ("Passkey 1"). The number is one
// past the highest in use, so a gap left by a deletion never yields a duplicate.
func PasskeyFriendlyName(aaguid []byte, existingNames []string) string {
	baseName, known := AuthenticatorName(aaguid)
	if !known {
		return fmt.Sprintf("Passkey %d", nextNameSuffix(existingNames, "Passkey"))
	}
	// nextNameSuffix returns 1 only when no derived name exists yet, so a
	// suffix of 1 marks the first of its kind and earns the bare base name.
	suffix := nextNameSuffix(existingNames, baseName)
	if suffix == 1 {
		return baseName
	}
	return fmt.Sprintf("%s %d", baseName, suffix)
}

// credentialFromAPI converts a stored PasskeyCredential to the gowebauthn
// form an assertion verifies against. RawAttestation is not decoded:
// go-webauthn@v0.18.2 reads Credential.Attestation only in Credential.Verify
// (webauthn/credential.go:286,328), never in a login.
func credentialFromAPI(c *access.PasskeyCredential) gowebauthn.Credential {
	var transports []protocol.AuthenticatorTransport
	if c.Transport != "" {
		for t := range strings.SplitSeq(c.Transport, ",") {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
	}

	return gowebauthn.Credential{
		ID:                c.CredentialID,
		PublicKey:         c.PublicKey,
		AttestationType:   c.AttestationType,
		AttestationFormat: c.AttestationFormat,
		Transport:         transports,
		Flags:             credentialFlags(c),
		Authenticator: gowebauthn.Authenticator{
			AAGUID:       c.AAGUID,
			SignCount:    c.SignCount,
			CloneWarning: c.CloneWarning,
			Attachment:   protocol.AuthenticatorAttachment(c.Attachment),
		},
		Extensions: gowebauthn.CredentialExtensions{RK: c.Discoverable},
	}
}

// credentialFlags rebuilds the upstream flag set from the stored raw octet,
// which is authoritative and preserves the AT and ED bits that the four decoded
// booleans drop.
func credentialFlags(c *access.PasskeyCredential) gowebauthn.CredentialFlags {
	return gowebauthn.NewCredentialFlags(protocol.AuthenticatorFlags(c.RawFlags))
}

// credentialToAPI converts a gowebauthn.Credential to a PasskeyCredential.
func credentialToAPI(c *gowebauthn.Credential, userID int64, name string) (*access.PasskeyCredential, error) {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}

	var rawAttestation []byte
	if len(c.Attestation.Object) > 0 || len(c.Attestation.ClientDataJSON) > 0 {
		var err error
		if rawAttestation, err = json.Marshal(c.Attestation); err != nil {
			return nil, fmt.Errorf("access/webauthn: encode the attestation: %w", err)
		}
	}

	return &access.PasskeyCredential{
		UserID:            userID,
		CredentialID:      c.ID,
		PublicKey:         c.PublicKey,
		AAGUID:            c.Authenticator.AAGUID,
		AttestationType:   c.AttestationType,
		AttestationFormat: c.AttestationFormat,
		Attachment:        access.AuthenticatorAttachment(c.Authenticator.Attachment),
		Transport:         strings.Join(transports, ","),
		SignCount:         c.Authenticator.SignCount,
		Name:              name,
		RawFlags:          uint8(c.Flags.ProtocolValue()),
		BackupEligible:    c.Flags.BackupEligible,
		BackupState:       c.Flags.BackupState,
		UserPresent:       c.Flags.UserPresent,
		UserVerified:      c.Flags.UserVerified,
		CloneWarning:      c.Authenticator.CloneWarning,
		Discoverable:      c.Extensions.RK,
		RawAttestation:    rawAttestation,
	}, nil
}

// RelyingParty is a configured relying party, and the value every ceremony
// function takes. It replaces the upstream handle on this package's exported
// surface so a consumer needs no go-webauthn import to run a ceremony.
//
// Construct one with [New]. The zero value is not usable.
type RelyingParty struct {
	id          string
	displayName string
	// origins is the exact set CheckOrigin accepts; empty only under
	// RPConfig.AllowSubdomains, where the host rule decides alone.
	origins []Origin
}

// ID returns the relying party identifier ceremonies are bound to. A stored
// credential records the ID it was registered against, so comparing the two is
// how a relying-party rename is detected rather than silently orphaning every
// passkey.
func (rp *RelyingParty) ID() string {
	return rp.id
}

// CheckOrigin returns nil when a ceremony may run at o, else a *[OriginError].
// The host rule comes first: https, or http on localhost, at the relying-party
// ID or a subdomain of it, on any port. Unless RPConfig.AllowSubdomains is set,
// o must then equal on scheme, host and port an RPConfig.Origins entry, or by
// default https://<ID> on the default port (plus http://localhost for the ID
// localhost); a miss is [RejectNotAllowlisted].
func (rp *RelyingParty) CheckOrigin(o Origin) error {
	if err := rp.policy(o); err != nil {
		return err
	}
	if len(rp.origins) == 0 || slices.Contains(rp.origins, o) {
		return nil
	}
	return &OriginError{Origin: o.String(), RPID: rp.id, Reason: RejectNotAllowlisted}
}

// policy is CheckOrigin's host rule. The IP rule runs before the
// scheme rule and is otherwise redundant with the host rule (New refuses an IP
// relying-party ID): it exists so an address that can never carry a passkey is
// reported as that, rather than as a missing scheme or an uncovered host.
func (rp *RelyingParty) policy(o Origin) *OriginError {
	refuse := func(reason OriginRejection) *OriginError {
		return &OriginError{Origin: o.String(), RPID: rp.id, Reason: reason}
	}
	switch {
	case o.IsZero():
		return refuse(RejectNoOrigin)
	case o.isIPHost():
		return refuse(RejectIPHost)
	case o.scheme == schemeHTTP && o.host != "localhost":
		return refuse(RejectInsecureScheme)
	case o.host != rp.id && !strings.HasSuffix(o.host, "."+rp.id):
		return refuse(RejectHostNotCovered)
	}
	return nil
}

// handleFor builds the upstream handle for one ceremony, whose only expected
// origin is the one that ceremony is bound to.
func (rp *RelyingParty) handleFor(origin string) (*gowebauthn.WebAuthn, error) {
	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPID:          rp.id,
		RPDisplayName: rp.displayName,
		RPOrigins:     []string{origin},
		Timeouts: gowebauthn.TimeoutsConfig{
			Login: gowebauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    CeremonyTimeout,
				TimeoutUVD: CeremonyTimeout,
			},
			Registration: gowebauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    CeremonyTimeout,
				TimeoutUVD: CeremonyTimeout,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("access/webauthn: relying party %q at origin %q: %w", rp.id, origin, err)
	}
	return wa, nil
}

// boundHandle builds the upstream handle for finishing ceremony, from the
// origin it was begun at.
func (rp *RelyingParty) boundHandle(ceremony Ceremony) (*gowebauthn.WebAuthn, error) {
	origin := ceremony.origin()
	if origin == "" {
		return nil, ErrCeremonyUnbound
	}
	return rp.handleFor(origin)
}

// Ceremony is the server-side state of one in-flight WebAuthn ceremony: the
// challenge and the parameters its Finish step verifies the response against.
// Keep it server-side, unmodified, from Begin to Finish, then discard it; a
// ceremony store needs only [Ceremony.Expires]. Copies share one immutable
// ceremony. The zero value is unusable and reports a zero deadline, so a lookup
// reports absence with a separate boolean.
type Ceremony struct {
	data *gowebauthn.SessionData
}

// Expires reports when the ceremony stops being verifiable. A ceremony store
// evicts on this rather than tracking its own creation time, so the deadline
// the authenticator was given and the deadline the store enforces cannot drift
// apart.
func (c Ceremony) Expires() time.Time {
	if c.data == nil {
		return time.Time{}
	}
	return c.data.Expires
}

// origin returns the origin the ceremony was begun at, or "" for a ceremony
// that did not come from a Begin function.
func (c Ceremony) origin() string {
	if c.data == nil {
		return ""
	}
	return c.data.Origin
}

// RPConfig identifies the relying party that a [New]-constructed
// [RelyingParty] serves. The ID and display name would otherwise sit as
// adjacent same-typed string parameters, where a silent swap ships a broken
// RP ID; the field names make each value's role explicit at the call site.
//
// The origin a ceremony expects is the origin it is begun at, judged by
// [RelyingParty.CheckOrigin]. By default only the relying party's exact origin
// is accepted; Origins replaces that set and AllowSubdomains widens it.
type RPConfig struct {
	// ID is the relying party identifier, an effective domain
	// (e.g. "example.com"), spelled in lowercase. See [ValidateRPID].
	ID string
	// DisplayName is the human-readable relying party name shown by
	// authenticators.
	DisplayName string
	// Origins, when set, is the exact list of origins ceremonies may run at
	// (scheme, host and port), e.g. "https://app.example.com". Each must be
	// the ID or a subdomain of it: New refuses an entry the host rule rejects.
	Origins []string
	// AllowSubdomains widens the default (empty Origins) from the exact origin
	// to every subdomain and port of ID. It cannot be combined with Origins,
	// and is unsafe wherever another host under ID can run script.
	AllowSubdomains bool
}

// ErrIllegalRPID reports a value that cannot be a relying-party ID. Every
// error [ValidateRPID] returns matches it with errors.Is and also carries the
// upstream validator's reason.
var ErrIllegalRPID = errors.New("access/webauthn: illegal relying-party ID")

// ErrCeremonyUnbound reports a ceremony carrying no origin, which a ceremony
// from a Begin function always does. It is a fail-closed guard against a
// Ceremony assembled some other way, never a condition a caller can reach.
var ErrCeremonyUnbound = errors.New("access/webauthn: the ceremony is not bound to an origin")

// ValidateRPID reports whether id is a legal relying-party ID: a lowercase
// domain name with no scheme, port or path, not an IP address, and not a
// single label other than localhost. A refusal matches [ErrIllegalRPID].
//
// The lowercase requirement is this package's own: the upstream validator
// accepts "Example.COM", but the relying-party hash is computed over the
// configured bytes, so whether a mixed-case ID ever verifies depends on the
// client, and a configured value must not.
func ValidateRPID(id string) error {
	if err := protocol.ValidateRPID(id); err != nil {
		return fmt.Errorf("%w %q: %w", ErrIllegalRPID, id, err)
	}
	if lower := strings.ToLower(id); id != lower {
		return fmt.Errorf("%w %q: the value must be spelled in lowercase, as %q", ErrIllegalRPID, id, lower)
	}
	return nil
}

// New creates a configured [RelyingParty]. An RPConfig with an empty ID is
// rejected here with an error naming the field, an illegal ID with one
// matching [ErrIllegalRPID], and Origins set beside AllowSubdomains with an
// error naming both, so a misconfigured relying party surfaces at construction
// rather than as a failed ceremony. An Origins entry that is not a usable
// origin, or that the host rule would refuse, is rejected with a
// *[OriginsError] naming the entry.
func New(rp RPConfig) (*RelyingParty, error) {
	if rp.ID == "" {
		return nil, errors.New("access/webauthn: RPConfig.ID is required")
	}
	if err := ValidateRPID(rp.ID); err != nil {
		return nil, err
	}
	if rp.AllowSubdomains && len(rp.Origins) > 0 {
		return nil, errors.New("access/webauthn: RPConfig.Origins and RPConfig.AllowSubdomains cannot be set together")
	}
	r := &RelyingParty{id: rp.ID, displayName: rp.DisplayName}
	for i, entry := range rp.Origins {
		o, err := parseOrigin(entry)
		if err == nil {
			err = r.policy(o)
		}
		if err != nil {
			return nil, &OriginsError{Err: err, Entry: entry, RPID: rp.ID, Index: i}
		}
		r.origins = append(r.origins, o)
	}
	if len(r.origins) == 0 && !rp.AllowSubdomains {
		r.origins = defaultOrigins(rp.ID)
	}
	return r, nil
}

// ErrNotDiscoverable reports a registration whose client stated the new
// credential is not client-side discoverable. Matchable with errors.Is so a
// caller can tell it apart from a verification failure and tell the user their
// authenticator cannot store a passkey.
var ErrNotDiscoverable = errors.New("access/webauthn: authenticator did not create a discoverable credential")

// ErrUnknownCredential reports a login whose asserted credential this relying
// party has no record of, which is what a passkey deleted server-side looks
// like from the client's side. Matchable with errors.Is, so a caller can tell it
// apart from a verification failure and signal the client to forget the stale
// passkey rather than telling the user their sign-in failed. It wraps nothing:
// no go-webauthn error is reachable through it.
var ErrUnknownCredential = errors.New("access/webauthn: the asserted credential is not registered")

// BeginRegistration starts a WebAuthn registration ceremony at origin, the
// browser origin the request arrived from (see [ParseOrigin]). An origin that
// fails [RelyingParty.CheckOrigin] returns its *[OriginError] unchanged; the
// ceremony verifies the response against exactly that origin. The three ML-DSA
// parameter sets are offered ahead of EdDSA, ES256 and RS256, so a post-quantum
// authenticator registers a post-quantum credential and every other one still
// registers.
func BeginRegistration(rp *RelyingParty, user *User, origin Origin) (*CredentialCreation, Ceremony, error) {
	if err := rp.CheckOrigin(origin); err != nil {
		return nil, Ceremony{}, err
	}
	wa, err := rp.handleFor(origin.String())
	if err != nil {
		return nil, Ceremony{}, err
	}
	options, session, err := wa.BeginRegistration(&userAdapter{User: user},
		gowebauthn.WithRegistrationOrigin(origin.String()),
		gowebauthn.WithCredentialParameters(gowebauthn.CredentialParametersPQCRecommendedL3()),
		gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		gowebauthn.WithExclusions(gowebauthn.Credentials((&userAdapter{User: user}).WebAuthnCredentials()).CredentialDescriptors()),
		gowebauthn.WithExtensions(gowebauthn.WithExtensionCredProps()),
	)
	if err != nil {
		return nil, Ceremony{}, err
	}
	return creationFromUpstream(options, user.WebAuthnID()), Ceremony{data: session}, nil
}

// FinishRegistration completes a registration from the PublicKeyCredential
// JSON in response, reading at most [MaxResponseBytes] ([ErrResponseTooLarge]
// past it), verified against the ceremony's bound origin ([ErrCeremonyUnbound]
// without one). A credential the client's credProps output reports as not
// discoverable is [ErrNotDiscoverable], since no discoverable login can use
// it; a missing report is accepted, so forward clientExtensionResults for the
// check to fire.
func FinishRegistration(rp *RelyingParty, user *User, ceremony Ceremony, response io.Reader) (*access.PasskeyCredential, error) {
	wa, err := rp.boundHandle(ceremony)
	if err != nil {
		return nil, err
	}
	body, err := readResponse(response)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return nil, err
	}
	cred, err := wa.CreateCredential(&userAdapter{User: user}, *ceremony.data, parsed)
	if err != nil {
		return nil, err
	}
	if err := rejectNonDiscoverable(cred); err != nil {
		return nil, err
	}
	return registrationRecord(rp, user, cred)
}

// registrationRecord builds the stored credential record for a completed
// registration. The Name is left empty: a friendly name is derived from the
// AAGUID against the user's EXISTING passkey names (see [PasskeyFriendlyName]),
// which only the caller's store can supply.
func registrationRecord(rp *RelyingParty, user *User, cred *gowebauthn.Credential) (*access.PasskeyCredential, error) {
	record, err := credentialToAPI(cred, user.AuthUser.ID, "")
	if err != nil {
		return nil, err
	}
	record.RPID = rp.ID()
	return record, nil
}

// rejectNonDiscoverable reports [ErrNotDiscoverable] when the credProps output
// states the credential is not client-side discoverable. An absent report is
// accepted: the client sets rk to false only when the relying party did not ask
// for a resident key, and [BeginRegistration] always asks.
func rejectNonDiscoverable(cred *gowebauthn.Credential) error {
	if cred.Extensions.RK != nil && !*cred.Extensions.RK {
		return ErrNotDiscoverable
	}
	return nil
}

// BeginLogin starts a WebAuthn assertion ceremony (discoverable login) at
// origin, which must pass [RelyingParty.CheckOrigin] and is bound into the
// ceremony exactly as in [BeginRegistration].
func BeginLogin(rp *RelyingParty, origin Origin) (*CredentialAssertion, Ceremony, error) {
	wa, err := rp.loginHandle(origin)
	if err != nil {
		return nil, Ceremony{}, err
	}
	return beganCeremony(wa.BeginDiscoverableLogin(
		gowebauthn.WithLoginOrigin(origin.String()),
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
	))
}

// loginHandle is the shared front half of the two login flavours: the origin
// check, then the handle for that one origin.
func (rp *RelyingParty) loginHandle(origin Origin) (*gowebauthn.WebAuthn, error) {
	if err := rp.CheckOrigin(origin); err != nil {
		return nil, err
	}
	return rp.handleFor(origin.String())
}

// beganCeremony wraps an upstream Begin* result so each ceremony function stays
// a single expression rather than repeating the same four-line unwrap.
func beganCeremony(options *protocol.CredentialAssertion, session *gowebauthn.SessionData, err error) (*CredentialAssertion, Ceremony, error) {
	if err != nil {
		return nil, Ceremony{}, err
	}
	return assertionFromUpstream(options), Ceremony{data: session}, nil
}

// BeginConditionalLogin starts a WebAuthn assertion ceremony with conditional
// mediation, enabling browser autofill UI for passkeys, at origin, which must
// pass [RelyingParty.CheckOrigin] and is bound into the ceremony exactly as in
// [BeginRegistration].
func BeginConditionalLogin(rp *RelyingParty, origin Origin) (*CredentialAssertion, Ceremony, error) {
	wa, err := rp.loginHandle(origin)
	if err != nil {
		return nil, Ceremony{}, err
	}
	return beganCeremony(wa.BeginDiscoverableMediatedLogin(protocol.MediationConditional,
		gowebauthn.WithLoginOrigin(origin.String()),
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
	))
}

// BeginReauthentication starts an assertion bound to one user's credentials,
// for step-up, at origin, which must pass [RelyingParty.CheckOrigin] and is
// bound into the ceremony exactly as in [BeginRegistration]. A user with no
// passkey cannot begin one.
func BeginReauthentication(rp *RelyingParty, user *User, origin Origin) (*CredentialAssertion, Ceremony, error) {
	wa, err := rp.loginHandle(origin)
	if err != nil {
		return nil, Ceremony{}, err
	}
	return beganCeremony(wa.BeginLogin(&userAdapter{User: user},
		gowebauthn.WithLoginOrigin(origin.String()),
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
	))
}

// LoginResult is a verified assertion whose custody update is stored.
type LoginResult struct {
	User         *access.User
	CredentialID []byte
	// CloneWarning reports that the sign counter regressed on this assertion,
	// the signal of a cloned authenticator; the stored flag stays set after it.
	CloneWarning bool
}

// CompleteLogin verifies a discoverable assertion read from response (at most
// [MaxResponseBytes], else [ErrResponseTooLarge]) against the ceremony's bound
// origin ([ErrCeremonyUnbound] without one) and stores the custody update. The
// caller MUST check User.Enabled before creating a session. A handle with no
// account, or an account without the credential, is [ErrUnknownCredential]; a
// store failure, in the lookup or the custody write, matches [access.ErrAuthBackend].
func CompleteLogin(ctx context.Context, rp *RelyingParty, store Store, ceremony Ceremony, response io.Reader) (LoginResult, error) {
	wa, err := rp.boundHandle(ceremony)
	if err != nil {
		return LoginResult{}, err
	}
	parsed, err := parseAssertion(response)
	if err != nil {
		return LoginResult{}, err
	}
	var finder loginFinder
	_, cred, err := wa.ValidatePasskeyLogin(finder.handler(ctx, store), *ceremony.data, parsed)
	if err != nil {
		return LoginResult{}, finder.failure(err)
	}
	return completeAssertion(ctx, store, finder.user, parsed, cred)
}

// CompleteReauthentication verifies a step-up assertion, read from response as
// in [CompleteLogin], for user, the ceremony's user from
// [BeginReauthentication] with the passkeys stored now, and stores the custody
// update. A ceremony begun for another user, or a discoverable one, is
// refused; a credential user does not hold is [ErrUnknownCredential]; a failed
// custody write matches [access.ErrAuthBackend].
func CompleteReauthentication(ctx context.Context, rp *RelyingParty, store Store, user *User, ceremony Ceremony, response io.Reader) (LoginResult, error) {
	wa, err := rp.boundHandle(ceremony)
	if err != nil {
		return LoginResult{}, err
	}
	parsed, err := parseAssertion(response)
	if err != nil {
		return LoginResult{}, err
	}
	cred, err := wa.ValidateLogin(&userAdapter{User: user}, *ceremony.data, parsed)
	if err != nil {
		if _, held := user.credential(parsed.RawID); !held && bytes.Equal(user.WebAuthnID(), ceremony.data.UserID) {
			return LoginResult{}, ErrUnknownCredential
		}
		return LoginResult{}, assertionFailed(err)
	}
	return completeAssertion(ctx, store, user, parsed, cred)
}

// readResponse reads one authenticator response under the MaxResponseBytes cap.
func readResponse(response io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(response, MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("access/webauthn: read the authenticator response: %w", err)
	}
	if len(body) > MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}

func parseAssertion(response io.Reader) (*protocol.ParsedCredentialAssertionData, error) {
	body, err := readResponse(response)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, assertionFailed(err)
	}
	return parsed, nil
}

func assertionFailed(err error) error {
	return fmt.Errorf("access/webauthn: assertion ceremony failed: %w", err)
}

// errLookupFailed is the one error the finder hands upstream, which folds it
// into a generic protocol error; failure reads the finder's own record.
var errLookupFailed = errors.New("credential lookup failed")

// loginFinder resolves the asserting account of a discoverable assertion and
// records why a lookup failed. The record, not the upstream error, decides the
// result: go-webauthn@v0.18.2 builds ErrorUnknownCredential only for a
// ceremony with allowCredentials (webauthn/login.go:319-326), which a
// discoverable one never has.
type loginFinder struct {
	user    *User
	backend error
	unknown bool
}

func (f *loginFinder) handler(ctx context.Context, store Store) gowebauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (gowebauthn.User, error) {
		account, found, err := store.UserByWebAuthnHandle(ctx, userHandle)
		if err != nil {
			f.backend = err
			return nil, errLookupFailed
		}
		if !found || account == nil {
			f.unknown = true
			return nil, errLookupFailed
		}
		creds, err := store.PasskeysByUserID(ctx, account.ID)
		if err != nil {
			f.backend = err
			return nil, errLookupFailed
		}
		user := &User{AuthUser: account, Credentials: creds}
		if _, held := user.credential(rawID); !held {
			f.unknown = true
			return nil, errLookupFailed
		}
		f.user = user
		return &userAdapter{User: user}, nil
	}
}

// failure translates a failed ceremony. ErrUnknownCredential is returned on
// its own, so no go-webauthn type is reachable through it.
func (f *loginFinder) failure(err error) error {
	switch {
	case f.backend != nil:
		return fmt.Errorf("%w: access/webauthn: passkey lookup: %w", access.ErrAuthBackend, f.backend)
	case f.unknown:
		return ErrUnknownCredential
	default:
		return assertionFailed(err)
	}
}

// credential returns the stored passkey with the given credential ID.
func (u *User) credential(id []byte) (*access.PasskeyCredential, bool) {
	for i := range u.Credentials {
		if bytes.Equal(u.Credentials[i].CredentialID, id) {
			return &u.Credentials[i], true
		}
	}
	return nil, false
}

// completeAssertion stores the custody of a verified assertion, scoped to the
// user it verified for: the sign count, the full flags octet and the sticky
// clone warning upstream keeps from the stored record.
func completeAssertion(ctx context.Context, store Store, user *User, parsed *protocol.ParsedCredentialAssertionData, cred *gowebauthn.Credential) (LoginResult, error) {
	err := store.UpdatePasskeyAfterLogin(ctx, user.AuthUser.ID, cred.ID, access.PasskeyLoginUpdate{
		At:           time.Now(),
		SignCount:    cred.Authenticator.SignCount,
		RawFlags:     uint8(cred.Flags.ProtocolValue()),
		CloneWarning: cred.Authenticator.CloneWarning,
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: access/webauthn: post-login passkey update: %w", access.ErrAuthBackend, err)
	}
	// upstream verifies only a credential of user.Credentials, so it is found.
	stored, _ := user.credential(cred.ID)
	return LoginResult{
		User:         user.AuthUser,
		CredentialID: slices.Clone(cred.ID),
		CloneWarning: signCountRegressed(stored.SignCount, parsed.Response.AuthenticatorData.Counter),
	}, nil
}

// signCountRegressed is the clone signal of W3C WebAuthn L3 §7.2's signCount
// step: either counter nonzero and the asserted one not above the stored one.
func signCountRegressed(stored, asserted uint32) bool {
	return (stored != 0 || asserted != 0) && asserted <= stored
}
