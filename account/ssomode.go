package account

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cplieger/access"
	"github.com/cplieger/access/oidc"
)

// SSOMode is how single sign-on sits beside local sign-in for a non-owner.
// The store holds it ([SSOModeStore]); owners are exempt under every mode.
// A user whose password and passkeys the stored mode forbids is a dormant
// user in this package's docs. A store persists the number, so a value
// never changes meaning.
type SSOMode int

const (
	// SSOAlongside lets every user sign in by SSO or locally.
	SSOAlongside SSOMode = 0
	// SSOForLinked keeps a linked non-owner's local methods dormant.
	SSOForLinked SSOMode = 1
	// SSOOnly keeps every non-owner's local methods dormant.
	SSOOnly SSOMode = 2
)

// SSOModeName is an SSOMode's wire name.
type SSOModeName string

// The wire names, in SSOMode order.
const (
	SSONameAlongside SSOModeName = "alongside"
	SSONameForLinked SSOModeName = "for_linked"
	SSONameOnly      SSOModeName = "only"
)

var ssoModeNames = [...]SSOModeName{SSOAlongside: SSONameAlongside, SSOForLinked: SSONameForLinked, SSOOnly: SSONameOnly}

// Name is the mode's wire name; empty for a value outside the modes.
func (m SSOMode) Name() SSOModeName {
	if m.valid() {
		return ssoModeNames[m]
	}
	return ""
}

// String is the mode's wire name, and "SSOMode(n)" for a value outside the
// modes.
func (m SSOMode) String() string {
	if m.valid() {
		return string(ssoModeNames[m])
	}
	return fmt.Sprintf("SSOMode(%d)", int(m))
}

// ParseSSOMode is the mode a wire name names; false for any other name.
func ParseSSOMode(name SSOModeName) (SSOMode, bool) {
	for m, n := range ssoModeNames {
		if n == name {
			return SSOMode(m), true
		}
	}
	return 0, false
}

func (m SSOMode) valid() bool { return m >= SSOAlongside && m <= SSOOnly }

// dormant reports whether m keeps a user's local methods dormant: never an
// owner's, every other user's under SSOOnly, and a linked one's under
// SSOForLinked.
func (m SSOMode) dormant(owner, linked bool) bool {
	switch {
	case owner:
		return false
	case m == SSOOnly:
		return true
	default:
		return m == SSOForLinked && linked
	}
}

// dormantFor is dormant for u as stored.
func (m SSOMode) dormantFor(u *access.User) bool { return m.dormant(isOwner(u), !u.OIDC.IsZero()) }

// storedMode is the mode tx reads; a store that never set one reads
// SSOAlongside.
func storedMode(ctx context.Context, tx Tx) (SSOMode, error) {
	mode, _, err := tx.SSOMode(ctx)
	return mode, err
}

// requireLocal is the mode check, inside tx, of every operation that signs
// u in, steps it up or adds to it by a local method: refusal when the
// stored mode keeps u's local methods dormant. Each such Update calls it,
// so a sign-in racing ApplySSO commits before the change, and is swept, or
// after it, and is refused.
func requireLocal(ctx context.Context, tx Tx, u *access.User, refusal error) error {
	mode, err := storedMode(ctx, tx)
	switch {
	case err != nil:
		return err
	case mode.dormantFor(u):
		return refuse(refusal)
	}
	return nil
}

// localAllowed is requireLocal read from the store before an operation
// spends a limiter slot or a ceremony on a refusal its Update would give.
func (s *Service) localAllowed(ctx context.Context, u *access.User) error {
	return answer(requireLocal(ctx, s.store, u, ErrSSOOnly))
}

// SSO returns the stored mode and whether any ApplySSO or MigrateSSO has
// set it; a store never set answers SSOAlongside and false.
func (s *Service) SSO(ctx context.Context) (mode SSOMode, set bool, err error) {
	if s.closed.Load() {
		return 0, false, ErrServiceClosed
	}
	mode, set, err = s.store.SSOMode(ctx)
	if err != nil {
		return 0, false, storeErr(err)
	}
	return mode, set, nil
}

// Readiness is what a change of the stored mode to a new one would do, read
// by SSOReadiness from the stored state.
type Readiness struct {
	// Refusal is the state refusal the change would answer, nil when it
	// would be made: ErrOIDCUnavailable for a provider that is off now, or a
	// *PolicyError with ReasonSingleOwner, ReasonRegistrationEnabled or
	// ReasonOwnerNeedsLocalMethod.
	Refusal error
	// LockedOut counts the enabled non-owners the mode would leave with no
	// sign-in: under SSOOnly, those not linked.
	LockedOut int
	// MethodsMadeDormant and MethodsRestored count the enabled accounts
	// holding a password or passkey that the change makes dormant or brings
	// back; each is zero in the direction that does not apply.
	MethodsMadeDormant, MethodsRestored int
	// TemporaryPasswordsWithdrawn counts the dormant temporary passwords of
	// the accounts the change brings back, which it deletes.
	TemporaryPasswordsWithdrawn int
}

// SSOReadiness reports what changing the stored mode to mode would do now,
// for an admin's preview, writing nothing. a is an out-of-band actor, a
// session, or a built-in key carrying Config.AdminScope, its authority
// re-read inside the read; a principal then meets Policy OpListUsers, and
// the request must be secure. Readiness.Refusal is the one ApplySSO would
// give the reader: an owner session's own change, any other reader's
// out-of-band one. Its errors: the admission's, ErrOIDCUnavailable while
// Config.OIDC is unset, ErrUnknownSSOMode, and a store error.
func (s *Service) SSOReadiness(ctx context.Context, a Actor, mode SSOMode) (Readiness, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.admitReadiness(a, mode)
	if err != nil {
		return Readiness{}, err
	}
	provider := s.provider()
	var rd Readiness
	err = s.update(ctx, func(tx Tx) error {
		reader, readErr := s.readerIn(ctx, tx, a)
		if readErr != nil {
			return readErr
		}
		users, readErr := tx.ListUsers(ctx)
		if readErr != nil {
			return readErr
		}
		cur, readErr := storedMode(ctx, tx)
		if readErr != nil {
			return readErr
		}
		rd, readErr = s.readinessIn(ctx, tx, r, users, previewOwner(reader, users), provider, ssoChange{from: cur, to: mode})
		return readErr
	})
	if err != nil {
		return Readiness{}, err
	}
	return rd, nil
}

// admitReadiness is SSOReadiness's checks before any store read: the
// Service and its Rules, a secure request, single sign-on wired, a known
// mode, and the reader as RequireKeyScope admits it under AdminScope.
func (s *Service) admitReadiness(a Actor, mode SSOMode) (Rules, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.beginOver(plainRefused, a.secure())
	switch {
	case err != nil:
		return Rules{}, err
	case s.oidc == nil:
		return Rules{}, ErrOIDCUnavailable
	case !mode.valid():
		return Rules{}, ErrUnknownSSOMode
	case a.isOutOfBand():
		return r, nil
	}
	p, ok := a.Principal()
	if !ok {
		return Rules{}, ErrSessionRequired
	}
	if err := s.admitKey(p, s.adminScope, func() error { return requireSession(p) }); err != nil {
		return Rules{}, err
	}
	if p.User == nil {
		return Rules{}, ErrSessionRequired
	}
	return r, nil
}

// readerIn is a's authority for an admin read inside tx: a key's re-read
// under AdminScope, then Policy OpListUsers for any principal. An
// out-of-band actor asks no Policy.
func (s *Service) readerIn(ctx context.Context, tx Tx, a Actor) (Actor, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	p, ok := a.Principal()
	if !ok {
		return a, nil
	}
	reader := a
	if p.IsAPIKey() {
		var err error
		if reader, _, err = s.keyAuthority(ctx, tx, OpListUsers, access.KeyRef{ID: p.KeyID, UserID: p.User.ID}, s.adminScope); err != nil {
			return Actor{}, err
		}
	}
	if err := s.authorize(ctx, Decision{Op: OpListUsers, Actor: reader}); err != nil {
		return Actor{}, refuse(err)
	}
	return reader, nil
}

// previewOwner is the owner whose own ApplySSO a's preview shows: an owner
// session's user as users holds it. Every other reader gets nil, the
// out-of-band change's rule.
func previewOwner(a Actor, users []access.User) *access.User { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	if p, ok := a.Principal(); !ok || !p.IsSession() {
		return nil
	}
	if u, ok := storedActor(a, users).user(); ok && isOwner(u) {
		return u
	}
	return nil
}

// CheckSSOReady is ApplySSO's every refusal, read now and writing nothing:
// ApplySSO's admission, its owner rule, then the state refusal for the
// acting owner.
func (s *Service) CheckSSOReady(ctx context.Context, a Actor, mode SSOMode) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.beginSSO(a, mode)
	if err != nil {
		return err
	}
	provider := s.provider()
	return s.update(ctx, func(tx Tx) error {
		cur, err := storedMode(ctx, tx)
		if err != nil {
			return err
		}
		rd, err := s.changeReadinessIn(ctx, tx, r, a, provider, ssoChange{from: cur, to: mode})
		switch {
		case err != nil:
			return err
		case rd.Refusal != nil:
			return refuse(rd.Refusal)
		}
		return nil
	})
}

// ApplySSO stores mode as the SSO mode for a, in one Update after reading
// Config.OIDC outside it: CheckSSOReady's refusals on what the Update read,
// then the mode, the end of every non-owner session the mode forbids, the
// withdrawal of each dormant temporary password the mode brings back to
// use, and an EventSSOModeChanged; once it commits, the dormant users'
// pending sign-ins are dropped. A refusal writes nothing, so the old mode
// stays in force across restarts; the mode it already holds, set, writes
// nothing.
func (s *Service) ApplySSO(ctx context.Context, a Actor, mode SSOMode) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	return s.writeSSO(ctx, a, mode, false)
}

// MigrateSSO is ApplySSO by an out-of-band actor that writes nothing, and
// returns nil, once any write has set the mode, read inside its Update, so
// an app's old constant never overrides an owner's choice. A refusal leaves
// the mode unset, so the next call retries.
func (s *Service) MigrateSSO(ctx context.Context, mode SSOMode) error {
	return s.writeSSO(ctx, OutOfBand(actorMigration), mode, true)
}

// beginSSO is the checks of every mode operation before any store read:
// the Service and its Rules, single sign-on wired, a known mode, and the
// actor.
func (s *Service) beginSSO(a Actor, mode SSOMode) (Rules, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.begin()
	switch {
	case err != nil:
		return Rules{}, err
	case s.oidc == nil:
		return Rules{}, ErrOIDCUnavailable
	case !mode.valid():
		return Rules{}, ErrUnknownSSOMode
	case a.isOutOfBand():
		return r, nil
	}
	p, _ := a.Principal()
	if !p.Secure {
		return Rules{}, access.ErrHTTPSRequired
	}
	if err := requireSession(p); err != nil {
		return Rules{}, err
	}
	if err := s.recentAuth(r, p); err != nil {
		return Rules{}, err
	}
	return r, nil
}

func (s *Service) writeSSO(ctx context.Context, a Actor, mode SSOMode, migrate bool) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.beginSSO(a, mode)
	if err != nil {
		return err
	}
	provider := s.provider()
	var dormant []int64
	err = s.change(ctx, by(a), func(tx Tx, j *journal) error {
		dormant = nil
		cur, set, txErr := tx.SSOMode(ctx)
		if txErr != nil || (migrate && set) {
			return txErr
		}
		ch := ssoChange{from: cur, to: mode}
		rd, txErr := s.changeReadinessIn(ctx, tx, r, a, provider, ch)
		switch {
		case txErr != nil:
			return txErr
		case rd.Refusal != nil:
			return refuse(rd.Refusal)
		case set && cur == mode:
			return nil
		}
		if setErr := tx.SetSSOMode(ctx, mode); setErr != nil {
			return setErr
		}
		if dormant, txErr = s.applyModeIn(ctx, tx, j, a, ch); txErr != nil {
			return txErr
		}
		j.add(Event{Kind: EventSSOModeChanged, At: s.now(), SSOMode: mode, PreviousSSOMode: cur, Actor: eventActor(a)})
		return nil
	})
	if err != nil {
		return err
	}
	for _, id := range dormant {
		s.pending.dropUser(id)
	}
	return nil
}

// ssoChange is a change of the stored mode.
type ssoChange struct{ from, to SSOMode }

// applyModeIn is the change's effect on every user tx reads: the sessions
// of each user the new mode makes dormant that it forbids, and the dormant
// temporary password of each user it brings back. It returns the IDs of
// the users the new mode keeps dormant.
func (s *Service) applyModeIn(ctx context.Context, tx Tx, j *journal, a Actor, ch ssoChange) ([]int64, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	users, err := tx.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	var dormant []int64
	for i := range users {
		u := &users[i]
		switch was, is := ch.from.dormantFor(u), ch.to.dormantFor(u); {
		case is:
			ended, endErr := endForbiddenSessions(ctx, tx, u)
			if endErr != nil {
				return nil, endErr
			}
			s.addRevoked(j, u.ID, ended, eventActor(a))
			dormant = append(dormant, u.ID)
		case was:
			if err := s.withdrawDormant(ctx, tx, j, u.ID, eventActor(a)); err != nil {
				return nil, err
			}
		}
	}
	return dormant, nil
}

// endForbiddenSessions ends, inside tx, each session of u whose AuthMethod
// is a local method, for a u whose local methods the stored mode now keeps
// dormant, and returns their IDs for the caller's entry. AuthMethod is the
// session's latest proof, which a step-up replaces. Each caller drops the
// user's pending sign-ins once its Update commits, the cache being outside
// the store; each completion's own requireLocal stays the guard.
func endForbiddenSessions(ctx context.Context, tx Tx, u *access.User) ([]string, error) {
	sessions, err := tx.SessionsByUserID(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	var ended []string
	for i := range sessions {
		if sessions[i].AuthMethod == access.MethodOIDC {
			continue
		}
		if err := tx.DeleteSession(ctx, access.SessionRef{ID: sessions[i].ID, UserID: u.ID}); err != nil {
			return nil, err
		}
		ended = append(ended, sessions[i].ID)
	}
	return ended, nil
}

// withdrawDormant deletes, inside tx, userID's temporary password when it
// is Dormant, for a change that makes the user's methods usable, and
// journals EventTemporaryPasswordWithdrawn with its issuer.
func (s *Service) withdrawDormant(ctx context.Context, tx Tx, j *journal, userID int64, actor EventActor) error {
	rec, found, err := tx.TemporaryPasswordByUserID(ctx, userID)
	if err != nil || !found || !rec.Dormant {
		return err
	}
	if err := tx.DeleteTemporaryPassword(ctx, userID); err != nil {
		return err
	}
	j.add(Event{
		Kind: EventTemporaryPasswordWithdrawn, At: s.now(), UserID: userID,
		IssuerUserID: rec.IssuedByUser, KeyID: rec.IssuedByKey, Actor: actor,
	})
	return nil
}

// changeReadinessIn is ApplySSO's read of ch by a on the rows tx reads and
// the provider read before tx opened: a principal actor must be an owner
// as stored (else a *PolicyError with ReasonNotOwner, which is no state
// refusal), and the state refusal is that owner's.
func (s *Service) changeReadinessIn(ctx context.Context, tx Tx, r Rules, a Actor, provider *oidc.Provider, ch ssoChange) (Readiness, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and its Actor
	users, err := tx.ListUsers(ctx)
	if err != nil {
		return Readiness{}, err
	}
	actor, isPrincipal := storedActor(a, users).user()
	if isPrincipal && !isOwner(actor) {
		return Readiness{}, refuse(&PolicyError{Op: OpApplySSO, Reason: ReasonNotOwner})
	}
	return s.readinessIn(ctx, tx, r, users, actor, provider, ch)
}

// readinessIn is ch's state refusal and counts over users, the rows tx
// reads; owner is the acting owner, nil for the out-of-band rule.
func (s *Service) readinessIn(ctx context.Context, tx Tx, r Rules, users []access.User, owner *access.User, provider *oidc.Provider, ch ssoChange) (Readiness, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	var rd Readiness
	var err error
	if rd.Refusal, err = s.stateRefusal(ctx, tx, r, owner, users, provider, ch.to); err != nil {
		return Readiness{}, err
	}
	for i := range users {
		if err := countChange(ctx, tx, &rd, &users[i], ch); err != nil {
			return Readiness{}, err
		}
	}
	return rd, nil
}

// stateRefusal is the change's refusal for a state its owner fixes
// elsewhere, or nil. actor is the acting owner, nil for out of band, when
// the one owner whose local method SSOOnly needs may be any owner.
func (s *Service) stateRefusal(ctx context.Context, tx Tx, r Rules, actor *access.User, users []access.User, provider *oidc.Provider, to SSOMode) (refused, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	switch {
	case provider == nil:
		return ErrOIDCUnavailable, nil
	case s.singleUser && to != SSOAlongside:
		return &PolicyError{Op: OpApplySSO, Reason: ReasonSingleOwner}, nil
	case to != SSOOnly:
		return nil, nil
	case r.Registration != RegistrationOff:
		return &PolicyError{Op: OpApplySSO, Reason: ReasonRegistrationEnabled}, nil
	}
	for i := range users {
		u := &users[i]
		if !isOwner(u) || (actor != nil && u.ID != actor.ID) {
			continue
		}
		local, err := s.holdsLocalMethod(ctx, tx, r, u)
		if err != nil || local {
			return nil, err
		}
	}
	return &PolicyError{Op: OpApplySSO, Reason: ReasonOwnerNeedsLocalMethod}, nil
}

// countChange adds u to rd's counts for ch.
func countChange(ctx context.Context, tx Tx, rd *Readiness, u *access.User, ch ssoChange) error {
	was, is := ch.from.dormantFor(u), ch.to.dormantFor(u)
	if was && !is {
		rec, found, err := tx.TemporaryPasswordByUserID(ctx, u.ID)
		if err != nil {
			return err
		}
		if found && rec.Dormant {
			rd.TemporaryPasswordsWithdrawn++
		}
	}
	if !u.Enabled || was == is {
		return nil
	}
	if is && u.OIDC.IsZero() {
		rd.LockedOut++
	}
	local, err := holdsLocal(ctx, tx, u)
	switch {
	case err != nil || !local:
		return err
	case is:
		rd.MethodsMadeDormant++
	default:
		rd.MethodsRestored++
	}
	return nil
}

// holdsLocal reports whether u holds a password or any passkey.
func holdsLocal(ctx context.Context, tx Tx, u *access.User) (bool, error) {
	if !u.PasswordHash.IsZero() {
		return true, nil
	}
	passkeys, err := tx.PasskeysByUserID(ctx, u.ID)
	return len(passkeys) > 0, err
}

// CheckRules reports whether r would pass every operation's Rules check,
// and refuses a registration mode while the stored SSO mode is SSOOnly,
// where registration is refused at use. An app calls it before it
// publishes a settings write or a reload.
func (s *Service) CheckRules(ctx context.Context, r Rules) error { //nolint:gocritic // hugeParam: as Rules.Validate
	if s.closed.Load() {
		return ErrServiceClosed
	}
	if err := s.checkRules(r); err != nil || r.Registration == RegistrationOff {
		return err
	}
	mode, err := storedMode(ctx, s.store)
	switch {
	case err != nil:
		return storeErr(err)
	case mode == SSOOnly:
		return &RulesError{Field: fieldRegistration, Reason: "the stored SSO mode only admits no local registration; people join through the identity provider"}
	}
	return nil
}

// checkStoredMode is New's check of the stored mode: one other than
// SSOAlongside is refused under a single-user Policy, which no ApplySSO
// could have written, and while Config.OIDC is unset, which an app that
// dropped its provider without applying SSOAlongside first leaves. One
// error names each refusal that holds, with its repair.
func (s *Service) checkStoredMode(ctx context.Context) error {
	mode, err := storedMode(ctx, s.store)
	switch {
	case err != nil:
		return storeErr(err)
	case mode == SSOAlongside:
		return nil
	}
	var why []string
	if s.singleUser {
		why = append(why, "a single-user Policy admits only alongside")
	}
	if s.oidc == nil {
		why = append(why, "single sign-on is not wired (Config.OIDC is unset); wire the provider and apply alongside")
	}
	if len(why) == 0 {
		return nil
	}
	return errors.New("account: the stored SSO mode is " + mode.String() + ": " + strings.Join(why, "; ") +
		"; or set the stored mode to alongside with the app stopped")
}
