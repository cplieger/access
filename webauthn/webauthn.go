// Package webauthn is a WebAuthn Level 3 relying party on Go's standard
// library: passkey registration, discoverable sign-in and step-up
// ceremonies. It imports the core access package for types but never the
// reverse.
package webauthn

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn/internal/cose"
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
// custody write. The account package's passkey sign-in implements it over an
// [github.com/cplieger/access/account.Store].
type Store interface {
	PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error)
	// RecordAssertion stores a verified assertion's custody in one atomic
	// step: the larger of the stored and upd's SignCount, the OR of both
	// CloneWarnings, and upd's RawFlags and At (BS may clear,
	// WebAuthn L3 §6.1.3). It compares nothing: the ceremony decided the
	// regression. A credential userID does not hold is an error.
	RecordAssertion(ctx context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error
	UserByWebAuthnHandle(ctx context.Context, handle []byte) (user *access.User, found bool, err error)
}

// User is the account a ceremony runs for, with the passkeys it holds now.
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

// RelyingParty is a configured relying party, and the value every ceremony
// function takes. Construct one with [New]. The zero value is not usable.
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
	case o.scheme == schemeHTTP && o.host != localhost:
		return refuse(RejectInsecureScheme)
	case o.host != rp.id && !strings.HasSuffix(o.host, "."+rp.id):
		return refuse(RejectHostNotCovered)
	}
	return nil
}

// Ceremony is the server-side state of one in-flight WebAuthn ceremony: the
// challenge and the parameters its Finish step verifies the response against.
// Keep it server-side, unmodified, from Begin to Finish, then discard it; a
// ceremony store needs only [Ceremony.Expires]. Copies share one immutable
// ceremony. The zero value is unusable and reports a zero deadline, so a lookup
// reports absence with a separate boolean.
type Ceremony struct {
	st *ceremonyState
}

// Expires reports when the ceremony stops being verifiable. A ceremony store
// evicts on this rather than tracking its own creation time, so the deadline
// the authenticator was given and the deadline the store enforces cannot drift
// apart.
func (c Ceremony) Expires() time.Time {
	if c.st == nil {
		return time.Time{}
	}
	return c.st.expires
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

// ErrCeremonyUnbound reports a Ceremony that no Begin function returned, such
// as the zero value. It is a fail-closed guard, never a condition a caller
// that keeps the Begin function's Ceremony can reach.
var ErrCeremonyUnbound = errors.New("access/webauthn: the ceremony did not come from a Begin function")

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
// passkey rather than telling the user their sign-in failed. It wraps nothing.
var ErrUnknownCredential = errors.New("access/webauthn: the asserted credential is not registered")

// The Begin functions' refusals.
var (
	errUserHandleSize = errors.New("access/webauthn: the user handle is not 1 to 64 bytes")
	errNoPasskeys     = errors.New("access/webauthn: the user holds no passkey to reauthenticate with")
)

// challengeBytes is each ceremony's challenge size, above WebAuthn §13.4.3's
// floor of 16 random bytes.
const challengeBytes = 32

// newCeremony starts a ceremony of kind at origin. It copies userHandle and
// each allowed ID, so the state never changes after Begin.
func newCeremony(kind ceremonyKind, origin Origin, userHandle []byte, allowed [][]byte) *ceremonyState {
	challenge := make([]byte, challengeBytes)
	rand.Read(challenge) // never returns an error (Go 1.24+); it crashes instead
	st := &ceremonyState{
		kind:       kind,
		origin:     origin,
		challenge:  challenge,
		userHandle: slices.Clone(userHandle),
		expires:    time.Now().Add(CeremonyTimeout),
	}
	for _, id := range allowed {
		st.allowed = append(st.allowed, slices.Clone(id))
	}
	return st
}

// checkUserHandle applies WebAuthn §5.4.3's bound on a user handle.
func checkUserHandle(handle []byte) error {
	if len(handle) == 0 || len(handle) > maxUserHandleBytes {
		return errUserHandleSize
	}
	return nil
}

// timeoutMillis is the options' timeout member, the ceremony's own deadline.
func timeoutMillis() int {
	return int(CeremonyTimeout.Milliseconds())
}

// credentialDescriptors lists creds for excludeCredentials or
// allowCredentials (WebAuthn §5.8.3), each with the transports its record
// holds.
func credentialDescriptors(creds []access.PasskeyCredential) []CredentialDescriptor {
	if len(creds) == 0 {
		return nil
	}
	out := make([]CredentialDescriptor, len(creds))
	for i := range creds {
		var transports []AuthenticatorTransport
		if creds[i].Transport != "" {
			for t := range strings.SplitSeq(creds[i].Transport, ",") {
				transports = append(transports, AuthenticatorTransport(t))
			}
		}
		out[i] = CredentialDescriptor{Type: PublicKeyCredentialType, ID: slices.Clone(creds[i].CredentialID), Transports: transports}
	}
	return out
}

// BeginRegistration starts a WebAuthn registration ceremony at origin, the
// browser origin the request arrived from (see [ParseOrigin]). An origin that
// fails [RelyingParty.CheckOrigin] returns its *[OriginError] unchanged; the
// ceremony verifies the response against exactly that origin. A user handle
// outside 1 to 64 bytes is refused (WebAuthn §5.4.3). The three ML-DSA
// parameter sets are offered ahead of EdDSA, ES256 and RS256, so a
// post-quantum authenticator registers a post-quantum credential and every
// other one still registers.
func BeginRegistration(rp *RelyingParty, user *User, origin Origin) (*CredentialCreation, Ceremony, error) {
	if err := rp.CheckOrigin(origin); err != nil {
		return nil, Ceremony{}, err
	}
	if err := checkUserHandle(user.WebAuthnID()); err != nil {
		return nil, Ceremony{}, err
	}
	st := newCeremony(ceremonyRegistration, origin, user.WebAuthnID(), nil)
	offered := cose.Offered()
	params := make([]CredentialParameter, len(offered))
	for i, alg := range offered {
		params[i] = CredentialParameter{Type: PublicKeyCredentialType, Algorithm: COSEAlgorithm(alg)}
	}
	return &CredentialCreation{Response: CredentialCreationOptions{
		RelyingParty: RelyingPartyEntity{Name: rp.displayName, ID: rp.id},
		User: UserEntity{
			Name:        user.WebAuthnName(),
			DisplayName: user.WebAuthnDisplayName(),
			ID:          slices.Clone(st.userHandle),
		},
		Challenge:  slices.Clone(st.challenge),
		Parameters: params,
		AuthenticatorSelection: AuthenticatorSelection{
			ResidentKey:        ResidentKeyRequired,
			RequireResidentKey: true,
			UserVerification:   VerificationRequired,
		},
		ExcludeCredentials: credentialDescriptors(user.Credentials),
		Timeout:            timeoutMillis(),
		Extensions:         RegistrationExtensions{CredProps: true},
	}}, Ceremony{st: st}, nil
}

// FinishRegistration completes a registration from the PublicKeyCredential
// JSON in response, reading at most [MaxResponseBytes] ([ErrResponseTooLarge]
// past it), for the ceremony [BeginRegistration] began for user
// ([ErrCeremonyUnbound] for a Ceremony no Begin function returned). Only
// "none" and self attestation are accepted. A credential the client's
// credProps output reports as not discoverable is [ErrNotDiscoverable],
// since no discoverable login can use it; a missing report is accepted, so
// forward clientExtensionResults for the check to fire.
func FinishRegistration(rp *RelyingParty, user *User, ceremony Ceremony, response io.Reader) (*access.PasskeyCredential, error) {
	body, err := readResponse(response)
	if err != nil {
		return nil, err
	}
	return finishRegistration(rp, ceremony.st, user, body)
}

// beginAssertion is the Begin half the three assertion ceremonies share.
// allow is the user's passkeys for a reauthentication and nil for a login.
func beginAssertion(rp *RelyingParty, origin Origin, kind ceremonyKind, user *User, allow []access.PasskeyCredential) (*CredentialRequestOptions, Ceremony, error) {
	if err := rp.CheckOrigin(origin); err != nil {
		return nil, Ceremony{}, err
	}
	var handle []byte
	var allowed [][]byte
	if user != nil {
		handle = user.WebAuthnID()
		if err := checkUserHandle(handle); err != nil {
			return nil, Ceremony{}, err
		}
		if len(allow) == 0 {
			return nil, Ceremony{}, errNoPasskeys
		}
		for i := range allow {
			allowed = append(allowed, allow[i].CredentialID)
		}
	}
	st := newCeremony(kind, origin, handle, allowed)
	return &CredentialRequestOptions{
		RelyingPartyID:   rp.id,
		UserVerification: VerificationRequired,
		Challenge:        slices.Clone(st.challenge),
		AllowCredentials: credentialDescriptors(allow),
		Timeout:          timeoutMillis(),
	}, Ceremony{st: st}, nil
}

// BeginLogin starts a WebAuthn assertion ceremony (discoverable login) at
// origin, which must pass [RelyingParty.CheckOrigin] and is bound into the
// ceremony exactly as in [BeginRegistration].
func BeginLogin(rp *RelyingParty, origin Origin) (*CredentialAssertion, Ceremony, error) {
	options, ceremony, err := beginAssertion(rp, origin, ceremonyLogin, nil, nil)
	if err != nil {
		return nil, Ceremony{}, err
	}
	return &CredentialAssertion{Response: *options}, ceremony, nil
}

// BeginConditionalLogin starts a WebAuthn assertion ceremony with conditional
// mediation, enabling browser autofill UI for passkeys, at origin, which must
// pass [RelyingParty.CheckOrigin] and is bound into the ceremony exactly as in
// [BeginRegistration]. [CompleteLogin] finishes it.
func BeginConditionalLogin(rp *RelyingParty, origin Origin) (*CredentialAssertion, Ceremony, error) {
	options, ceremony, err := beginAssertion(rp, origin, ceremonyLogin, nil, nil)
	if err != nil {
		return nil, Ceremony{}, err
	}
	return &CredentialAssertion{Mediation: MediationConditional, Response: *options}, ceremony, nil
}

// BeginReauthentication starts an assertion bound to one user's credentials,
// for step-up, at origin, which must pass [RelyingParty.CheckOrigin] and is
// bound into the ceremony exactly as in [BeginRegistration]. A user with no
// passkey cannot begin one, and a user handle outside 1 to 64 bytes is
// refused (WebAuthn §5.4.3).
func BeginReauthentication(rp *RelyingParty, user *User, origin Origin) (*CredentialAssertion, Ceremony, error) {
	options, ceremony, err := beginAssertion(rp, origin, ceremonyReauthentication, user, user.Credentials)
	if err != nil {
		return nil, Ceremony{}, err
	}
	return &CredentialAssertion{Response: *options}, ceremony, nil
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
// [MaxResponseBytes], else [ErrResponseTooLarge]) for a ceremony from
// [BeginLogin] or [BeginConditionalLogin] ([ErrCeremonyUnbound] for one no
// Begin function returned) and stores the custody update. The caller MUST
// check User.Enabled before creating a session. A handle with no account, or
// an account without the credential, is [ErrUnknownCredential]; a store
// failure, in the lookup or the custody write, matches [access.ErrAuthBackend].
func CompleteLogin(ctx context.Context, rp *RelyingParty, store Store, ceremony Ceremony, response io.Reader) (LoginResult, error) {
	body, err := readResponse(response)
	if err != nil {
		return LoginResult{}, err
	}
	return verifyLogin(ctx, rp, store, ceremony.st, body)
}

// CompleteReauthentication verifies a step-up assertion, read from response as
// in [CompleteLogin], for user, the ceremony's user from
// [BeginReauthentication] with the passkeys stored now, and stores the custody
// update. A ceremony begun for another user, or a discoverable one, is
// refused; a credential user does not hold is [ErrUnknownCredential]; a failed
// custody write matches [access.ErrAuthBackend].
func CompleteReauthentication(ctx context.Context, rp *RelyingParty, store Store, user *User, ceremony Ceremony, response io.Reader) (LoginResult, error) {
	body, err := readResponse(response)
	if err != nil {
		return LoginResult{}, err
	}
	return verifyReauthentication(ctx, rp, store, user, ceremony.st, body)
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

// credential returns the stored passkey with the given credential ID.
func (u *User) credential(id []byte) (*access.PasskeyCredential, bool) {
	for i := range u.Credentials {
		if bytes.Equal(u.Credentials[i].CredentialID, id) {
			return &u.Credentials[i], true
		}
	}
	return nil, false
}
