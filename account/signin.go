package account

import (
	"context"
	"slices"

	"github.com/cplieger/access"
)

// Next is the step a pending sign-in needs before it completes, by its wire
// name.
type Next string

const (
	// NextSecondFactor is a second factor the user holds.
	NextSecondFactor Next = "second_factor"
	// NextSetCredential is a password or passkey of the user's own choosing.
	NextSetCredential Next = "set_credential" //nolint:gosec // G101: a step's wire name, not a credential
	// NextEnrol is a first second factor to bind, which
	// Rules.RequireSecondFactor demands.
	NextEnrol Next = "enrol"
)

// Pending is a sign-in whose first factor verified and that needs Next. Its
// Ticket lasts ten minutes, held by the client in memory and sent in a body
// only. A restart, the user's next password sign-in, SetPassword,
// RemovePassword, ResetSecondFactor, SetTemporaryPassword, disabling,
// deleting, AdminUnlinkOIDC and AdminRelinkOIDC drop it, as do an OIDC link,
// ApplySSO, MigrateSSO and SetOwner when they leave the user's local methods
// dormant. Methods are what Next accepts on this request's transport, the only
// one it finishes on. Recovered marks a NextEnrol that completes a recovery.
type Pending struct {
	Ticket    access.Secret
	Next      Next
	Methods   []access.Method
	Recovered bool
}

// LoginResult is a password sign-in's answer: Pending when the sign-in
// needs another step, else SignedIn.
type LoginResult struct {
	Pending  *Pending
	SignedIn SignedIn
}

// ticket is what a pending sign-in carries to its next step.
type ticket struct {
	// draft is the creation a draft's enrolment finish runs; nil for an
	// existing user's ticket.
	draft *draftOf
	// temporary is the hash of the temporary password that minted the
	// ticket or its predecessor, which SetCredentialPassword refuses as the
	// new password; zero for a ticket a password minted.
	temporary access.Hash
	// staged is the password SetCredentialPassword hashed under
	// Rules.RequireSecondFactor, which the enrolment finish writes.
	staged  access.Hash
	next    Next
	methods []access.Method
	// digest is the PasswordHash step 1 left stored; the next step goes on
	// only while the stored hash still matches it.
	digest access.HashKey
	// recovered is the key of the recovery code hash that matched; the
	// enrolment finish spends that code. Zero when none matched.
	recovered access.HashKey
	secure    bool // the minting request's transport
	failed    bool // a second step on it was refused and journalled
}

// secondFactorHeld is the one predicate of whether u, read through tx under
// r, holds a second factor: a usable TOTP record, or under
// Rules.RequireSecondFactor a password and a usable passkey. Held means
// usable, so a record totpOn turns off reads as absent.
func (s *Service) secondFactorHeld(ctx context.Context, tx Tx, r Rules, u *access.User) (bool, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	return s.heldWithout(ctx, tx, r, u, credential{})
}

// usableTOTP reports whether u holds a TOTP record that reads as present.
func (s *Service) usableTOTP(ctx context.Context, tx Tx, r Rules, u *access.User) (bool, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	if !s.totpOn(r) {
		return false, nil
	}
	_, found, err := tx.TOTPByUserID(ctx, u.ID)
	return found, err
}

// passkeysAllowed reports whether passkeys sign u in under r with rpID
// published: rpID is set and Rules.MethodUsable allows passkeys.
func passkeysAllowed(ctx context.Context, tx Tx, r Rules, rpID string, u *access.User) bool { //nolint:gocritic // hugeParam: the operation's one Rules value
	return rpID != "" && methodUsable(ctx, tx, r, u, access.MethodPasskey)
}

// usablePasskeys counts u's passkeys that sign in now, leaving out gone:
// registered under rpID while passkeysAllowed. It is the one passkey count
// of every reader, so a passkey under an old relying-party ID never counts.
func usablePasskeys(ctx context.Context, tx Tx, r Rules, rpID string, u *access.User, gone credential) (int, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	if !passkeysAllowed(ctx, tx, r, rpID, u) {
		return 0, nil
	}
	return passkeysLeft(ctx, tx, u.ID, rpID, gone)
}

// methodUsable is Rules.MethodUsable, nil allowing every method.
func methodUsable(ctx context.Context, tx Tx, r Rules, u *access.User, m access.Method) bool { //nolint:gocritic // hugeParam: the operation's one Rules value
	return r.MethodUsable == nil || r.MethodUsable(ctx, tx, u, m)
}

// rpID is the published relying party's ID; empty while passkeys are off.
func (s *Service) rpID() string {
	if rp := s.relyingParty(); rp != nil {
		return rp.ID()
	}
	return ""
}

// ticketMint is what a mint knows besides the user: the request's
// transport, and whether a NextEnrol of an existing account comes from a
// device that is not known.
type ticketMint struct {
	secure, unknownDevice bool
}

// ticketMethods decides a ticket's Methods at every mint, reading through
// tx: the app's set for next, then ErrNoUsableMethod for an empty set, then
// ErrEnrolNeedsKnownDevice, then the transport filter, whose empty result is
// access.ErrHTTPSRequired. refused is the mint's answer; err a store error.
func (s *Service) ticketMethods(ctx context.Context, tx Tx, r Rules, u *access.User, next Next, m ticketMint) (methods []access.Method, refused, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	set, err := s.appMethods(ctx, tx, r, u, next)
	switch {
	case err != nil:
		return nil, nil, err
	case len(set) == 0:
		return nil, ErrNoUsableMethod, nil
	case next == NextEnrol && m.unknownDevice:
		return nil, ErrEnrolNeedsKnownDevice, nil
	case m.secure:
		return set, nil, nil
	}
	set = slices.DeleteFunc(set, func(x access.Method) bool { return !plainStep(next, x) })
	if len(set) == 0 {
		if r.RequireSecondFactor {
			s.logger().Warn("account: a plain sign-in was refused because Rules.RequireSecondFactor needs HTTPS for its next step", "user_id", u.ID)
		}
		return nil, access.ErrHTTPSRequired, nil
	}
	return set, nil, nil
}

// plainStep reports whether a ticket's step next may take method m over
// plain HTTP: the code as a second factor, and a password to set. The others
// need HTTPS (docs/plain-http.md).
func plainStep(next Next, m access.Method) bool {
	return next == NextSecondFactor && m == access.MethodTOTP || next == NextSetCredential && m == access.MethodPassword
}

// appMethods is next's methods under the app's switches, one per method:
// totp by totpOn, password by Rules.DisablePasswordLogin, passkey by
// passkeysAllowed (and, as a second factor, a usable passkey held), and
// recovery_code when held and the enrolment it leads to is not empty. Under
// the rule a set password must still enrol, so it needs that enrolment too.
func (s *Service) appMethods(ctx context.Context, tx Tx, r Rules, u *access.User, next Next) ([]access.Method, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	rpID := s.rpID()
	passkeys := passkeysAllowed(ctx, tx, r, rpID, u)
	var enrol []access.Method
	if s.totpOn(r) {
		enrol = append(enrol, access.MethodTOTP)
	}
	if passkeys {
		enrol = append(enrol, access.MethodPasskey)
	}
	switch next {
	case NextEnrol:
		return enrol, nil
	case NextSetCredential:
		var set []access.Method
		if !r.DisablePasswordLogin && (!r.RequireSecondFactor || len(enrol) > 0) {
			set = append(set, access.MethodPassword)
		}
		if passkeys {
			set = append(set, access.MethodPasskey)
		}
		return set, nil
	}
	return s.secondFactors(ctx, tx, r, u, rpID, passkeys, len(enrol) > 0)
}

// secondFactors is appMethods' NextSecondFactor set: a usable TOTP, a usable
// passkey while passkeys are allowed, and a recovery code held while the
// enrolment it leads to is not empty.
func (s *Service) secondFactors(ctx context.Context, tx Tx, r Rules, u *access.User, rpID string, passkeys, canEnrol bool) ([]access.Method, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	var set []access.Method
	held, err := s.usableTOTP(ctx, tx, r, u)
	if err != nil {
		return nil, err
	}
	if held {
		set = append(set, access.MethodTOTP)
	}
	if passkeys {
		n, err := passkeysLeft(ctx, tx, u.ID, rpID, credential{})
		if err != nil {
			return nil, err
		}
		if n > 0 {
			set = append(set, access.MethodPasskey)
		}
	}
	if canEnrol {
		_, found, err := tx.RecoveryCodeByUserID(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		if found {
			set = append(set, access.MethodRecoveryCode)
		}
	}
	return set, nil
}

// pendAt is step 1's decision, in its change, for u whose password
// verified: nil and nil sign in; else the pending sign-in to
// mint, or the refusal that answers instead. known is whether step 1
// presented a known device.
func (s *Service) pendAt(ctx context.Context, tx Tx, r Rules, c Client, u *access.User, known bool) (entry *pending, refused, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	held, err := s.secondFactorHeld(ctx, tx, r, u)
	if err != nil {
		return nil, nil, err
	}
	next := NextSecondFactor
	switch {
	case held:
	case r.RequireSecondFactor:
		next = NextEnrol
	default:
		return nil, nil, nil
	}
	methods, refused, err := s.ticketMethods(ctx, tx, r, u, next, ticketMint{secure: c.Secure, unknownDevice: !known})
	if err != nil || refused != nil {
		return nil, refused, err
	}
	return &pending{user: *u, ticket: ticket{next: next, methods: methods, digest: u.PasswordHash.Key(), secure: c.Secure}}, nil, nil
}

// mintTicket puts entry, a pending sign-in, in the cache and answers it, or
// the cache's refusal (pendingCache.put).
func (s *Service) mintTicket(entry *pending) (*Pending, error) {
	purpose := purposeSignIn
	switch d := entry.ticket.draft; {
	case d == nil:
	case d.via == ViaRegistration:
		purpose = purposeRegistrationDraft
	default:
		purpose = purposeDraft
	}
	id, err := s.pending.put(purpose, *entry, s.now())
	if err != nil {
		return nil, err
	}
	return &Pending{Ticket: access.NewSecret(id), Next: entry.ticket.next, Methods: slices.Clone(entry.ticket.methods), Recovered: entry.ticket.recovered != access.HashKey{}}, nil
}
