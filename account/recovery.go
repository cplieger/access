package account

import (
	"context"
	"io"
	"slices"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn"
)

// RecoverOptions keeps what a recovery completion revokes by default.
type RecoverOptions struct {
	KeepSessions bool // false: every other session of the user is revoked
	KeepKeys     bool // false: every API key of the user is deleted, with every token it issued
}

// StartRecovery consumes a recovery token and opens a SessionRecovery
// session for its subject in one Update, under Rules.SessionCaps and
// MaxSessionsPerUser; nobody is signed in. A zero, absent, expired or
// non-recovery token, or a gone or disabled subject, is access.ErrTokenInvalid
// before c's IP attempt limit. A key-issued token's issuer is re-checked as
// at its issue: a refusal commits only the token's deletion
// (access.ErrTokenInvalid), a pass records the key as Session.IssuedByKey with
// a recovery_started attribution. EventRecoveryConsumed names the key.
func (s *Service) StartRecovery(ctx context.Context, c Client, token access.Secret) (Recovery, error) { //nolint:gocritic // hugeParam: the request's Client, read once
	r, err := s.begin()
	if err != nil {
		return Recovery{}, err
	}
	var st started
	out, err := s.createSession(ctx, r, c, &sessionOp{
		method: access.MethodRecovery,
		kind:   access.SessionRecovery,
		gate: admission{
			refusals: func() error { return s.peekRecovery(ctx, token) },
			limit:    s.ipAttempt(c),
		},
		in: func(tx Tx) (*access.User, error) {
			st = started{}
			return s.startIn(ctx, tx, r, token, &st)
		},
		fill: func(sess *access.Session) { sess.IssuedByKey = st.issuedBy },
		announce: func(u *access.User, sess *access.Session) {
			s.emit(Event{Kind: EventRecoveryConsumed, At: sess.CreatedAt, UserID: u.ID, KeyID: sess.IssuedByKey})
		},
	})
	switch {
	case err != nil:
		return Recovery{}, err
	case st.spent:
		return Recovery{}, access.ErrTokenInvalid
	}
	return Recovery{Issued: Issued{Token: out.Token, Session: out.Session}, Username: out.User.Username, Methods: st.methods}, nil
}

// started is what a recovery start's Update did: the ID of the issuer it
// re-checked (0 for a session-issued token), the subject's methods, or
// spent when the token was consumed without a session.
type started struct {
	methods  Methods
	issuedBy int64
	spent    bool
}

// peekRecovery is StartRecovery's refusals before the limiter: the token
// read without consuming it, then its subject.
func (s *Service) peekRecovery(ctx context.Context, token access.Secret) error {
	tok, err := s.peekToken(ctx, token, access.PurposeRecovery)
	if err != nil {
		return err
	}
	u, found, err := s.store.UserByID(ctx, tok.Subject)
	switch {
	case err != nil:
		return storeErr(err)
	case !found || !u.Enabled:
		return access.ErrTokenInvalid
	}
	return nil
}

// startIn is StartRecovery's part of the Update before its session:
// consume the token, read its subject, re-check a key-issued token's issuer
// and append its attribution, then read the subject's methods. A token the
// store found expired or absent, or a refused issuer, sets st.spent and
// commits the consumption alone.
func (s *Service) startIn(ctx context.Context, tx Tx, r Rules, token access.Secret, st *started) (*access.User, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	tok, found, err := tx.ConsumeOneTimeToken(ctx, tokenHash(token), s.now())
	switch {
	case err != nil:
		return nil, err
	case !found:
		st.spent = true
		return nil, nil
	case tok.Purpose != access.PurposeRecovery:
		return nil, refuse(access.ErrTokenInvalid)
	}
	u, found, err := tx.UserByID(ctx, tok.Subject)
	switch {
	case err != nil:
		return nil, err
	case !found || !u.Enabled:
		return nil, refuse(access.ErrTokenInvalid)
	}
	if tok.IssuedByKey != 0 {
		key, current, issuerErr := s.recoveryIssuer(ctx, tx, tok.IssuedByKey, u)
		if issuerErr != nil || !current {
			st.spent = issuerErr == nil
			return nil, issuerErr
		}
		st.issuedBy = key.ID
		if attrErr := s.attribute(ctx, tx, u.ID, access.AttributionRecoveryStarted, key); attrErr != nil {
			return nil, attrErr
		}
	}
	if st.methods, err = s.methods(ctx, tx, r, u); err != nil {
		return nil, err
	}
	return u, nil
}

// recoveryIssuer is tokenIssuer for a recovery: OpIssueRecovery on subject
// as tx read it, and the subject's current role.
func (s *Service) recoveryIssuer(ctx context.Context, tx Tx, keyID int64, subject *access.User) (*access.Key, bool, error) {
	return s.tokenIssuer(ctx, tx, keyID, Decision{Op: OpIssueRecovery, Target: subject}, subject.Role)
}

// RecoverWithPassword sets p's password for a recovery session
// (ErrSessionRequired otherwise; ErrSessionGone once it ended). After the
// password rules, one Update re-checks a key-issued session's issuer as
// StartRecovery does (a refusal deletes the session alone:
// access.ErrTokenInvalid), writes the password and a key's recovered record,
// ends the session and the recovery tokens, revokes the other sessions and
// keys unless opts keeps them, and clears the failure records. Nobody signs
// in; the events follow in emitRecovered's order.
func (s *Service) RecoverWithPassword(ctx context.Context, p access.Principal, password access.Secret, opts RecoverOptions) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.begin()
	if err != nil {
		return err
	}
	if sessErr := requireRecovery(p); sessErr != nil {
		return sessErr
	}
	if pwErr := s.checkPassword(ctx, r, p.User.Username, password); pwErr != nil {
		return pwErr
	}
	hash, err := s.hasher.Hash(ctx, password.Reveal())
	if err != nil {
		return err
	}
	return s.completeRecovery(ctx, p, opts, func(tx Tx, u *access.User) error {
		u.PasswordHash, u.UpdatedAt = hash, s.now()
		return tx.UpdateUser(ctx, u)
	})
}

// RecoverPasskeyBegin starts enrolling a passkey for p's user, for a
// recovery session (ErrSessionRequired otherwise). A nil RP() is
// ErrPasskeysUnavailable.
func (s *Service) RecoverPasskeyBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (PendingCeremony, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return PendingCeremony{}, err
	}
	if err := requireRecovery(p); err != nil {
		return PendingCeremony{}, err
	}
	rp := s.relyingParty()
	if rp == nil {
		return PendingCeremony{}, ErrPasskeysUnavailable
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return PendingCeremony{}, err
	}
	wu, err := s.webauthnUser(ctx, u)
	if err != nil {
		return PendingCeremony{}, err
	}
	cc, ceremony, err := webauthn.BeginRegistration(rp, wu, origin)
	if err != nil {
		return PendingCeremony{}, err
	}
	id := s.pending.put(purposeRecovery, pending{user: u, ceremony: ceremony}, s.now())
	return PendingCeremony{ID: id, Creation: cc}, nil
}

// RecoverPasskeyFinish verifies the registration ceremonyID began and
// completes the recovery with that passkey, as RecoverWithPassword does with
// a password. A ceremony another user began is ErrCeremonyInvalid, and a
// credential registered to any user ErrDuplicateCredential.
func (s *Service) RecoverPasskeyFinish(ctx context.Context, p access.Principal, ceremonyID string, body io.Reader, opts RecoverOptions) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return err
	}
	if err := requireRecovery(p); err != nil {
		return err
	}
	rp := s.relyingParty()
	if rp == nil {
		return ErrPasskeysUnavailable
	}
	entry, err := s.takeOwn(ceremonyID, purposeRecovery, p)
	if err != nil {
		return err
	}
	cred, err := webauthn.FinishRegistration(rp, &webauthn.User{AuthUser: entry.user}, entry.ceremony, body)
	if err != nil {
		return err
	}
	return s.completeRecovery(ctx, p, opts, func(tx Tx, u *access.User) error {
		_, addErr := s.addPasskey(ctx, tx, u.ID, cred)
		return addErr
	})
}

// RecoverOutOfBand sets userID's password for an out-of-band actor (a
// principal is *PolicyError{Reason: ReasonOutOfBandOnly} before any read),
// with no recovery session, Client or limiter: the shared password rules,
// then one Update that asks the Policy (OpIssueRecovery), writes the
// password and runs RecoverWithPassword's completion under opts. A missing
// user is ErrNotFound; Enabled and the user's attributions stay as they
// are. The events are RecoverWithPassword's, with the channel as actor.
func (s *Service) RecoverOutOfBand(ctx context.Context, a Actor, userID int64, password access.Secret, opts RecoverOptions) error { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.begin()
	if err != nil {
		return err
	}
	if !a.isOutOfBand() {
		return &PolicyError{Op: OpIssueRecovery, Reason: ReasonOutOfBandOnly}
	}
	u, found, err := s.store.UserByID(ctx, userID)
	switch {
	case err != nil:
		return storeErr(err)
	case !found:
		return ErrNotFound
	}
	if pwErr := s.checkPassword(ctx, r, u.Username, password); pwErr != nil {
		return pwErr
	}
	hash, err := s.hasher.Hash(ctx, password.Reveal())
	if err != nil {
		return err
	}
	var rep repaired
	err = s.update(ctx, func(tx Tx) error {
		rep = repaired{}
		stored, ok, readErr := tx.UserByID(ctx, userID)
		switch {
		case readErr != nil:
			return readErr
		case !ok:
			return refuse(ErrNotFound)
		}
		if polErr := s.policy.Authorize(ctx, Decision{Op: OpIssueRecovery, Actor: a, Target: stored}); polErr != nil {
			return refuse(polErr)
		}
		stored.PasswordHash, stored.UpdatedAt = hash, s.now()
		if writeErr := tx.UpdateUser(ctx, stored); writeErr != nil {
			return writeErr
		}
		return s.repairIn(ctx, tx, stored, "", opts, &rep)
	})
	if err != nil {
		return err
	}
	s.emitRecovered(userID, &rep, eventActor(a))
	return nil
}

// requireRecovery is the actor precondition of a recovery completion: only
// a recovery session the built-in session verifier produced passes.
func requireRecovery(p access.Principal) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if !p.IsRecoverySession() || p.User == nil {
		return ErrSessionRequired
	}
	return nil
}

// repaired is what a completion's Update did: the issuer of a key-issued
// session as it re-read it, the sessions it ended, the keys it deleted and
// the locks it cleared, or refused when the issuer failed its re-check.
type repaired struct {
	issuer   *access.Key
	sessions []string
	keys     []int64
	locks    []FailureCount
	refused  bool
}

// completeRecovery runs a session-based completion in one Update and,
// after the commit, its events.
func (s *Service) completeRecovery(ctx context.Context, p access.Principal, opts RecoverOptions, write func(tx Tx, u *access.User) error) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	var rep repaired
	err := s.update(ctx, func(tx Tx) error {
		rep = repaired{}
		return s.completeIn(ctx, tx, p, opts, write, &rep)
	})
	switch {
	case err != nil:
		return err
	case rep.refused:
		return access.ErrTokenInvalid
	}
	s.emitRecovered(p.User.ID, &rep, eventActor(As(p)))
	return nil
}

// completeIn is completeRecovery's Update: p's recovery session and user
// re-read, a key-issued session's issuer re-checked (a refusal deletes the
// session alone and sets rep.refused), write's credential, its recovered
// attribution, then repairIn.
func (s *Service) completeIn(ctx context.Context, tx Tx, p access.Principal, opts RecoverOptions, write func(tx Tx, u *access.User) error, rep *repaired) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	sess, err := principalSession(ctx, tx, p, p.User.ID)
	if err != nil {
		return err
	}
	u, err := ownUserIn(ctx, tx, p)
	if err != nil {
		return err
	}
	if sess.IssuedByKey != 0 {
		key, current, issuerErr := s.recoveryIssuer(ctx, tx, sess.IssuedByKey, u)
		if issuerErr != nil {
			return issuerErr
		}
		if !current {
			rep.refused = true
			return tx.DeleteSession(ctx, access.SessionRef{ID: sess.ID, UserID: u.ID})
		}
		rep.issuer = key
	}
	if err := write(tx, u); err != nil {
		return err
	}
	if rep.issuer != nil {
		if err := s.attribute(ctx, tx, u.ID, access.AttributionRecovered, rep.issuer); err != nil {
			return err
		}
	}
	return s.repairIn(ctx, tx, u, sess.ID, opts, rep)
}

// repairIn is the completion after the credential, inside tx: u's recovery
// tokens voided, the recovery session recoveryID deleted (empty for
// RecoverOutOfBand, which has none), every other session revoked unless
// opts.KeepSessions, every key and its tokens deleted unless opts.KeepKeys,
// and every failure record of u's name deleted, recording the locks.
func (s *Service) repairIn(ctx context.Context, tx Tx, u *access.User, recoveryID string, opts RecoverOptions, rep *repaired) error {
	if _, err := tx.DeleteOneTimeTokens(ctx, access.PurposeRecovery, u.ID); err != nil {
		return err
	}
	if !opts.KeepSessions {
		ids, err := tx.DeleteUserSessions(ctx, u.ID, recoveryID)
		if err != nil {
			return err
		}
		rep.sessions = ids
	}
	if recoveryID != "" {
		if err := tx.DeleteSession(ctx, access.SessionRef{ID: recoveryID, UserID: u.ID}); err != nil {
			return err
		}
		rep.sessions = append(rep.sessions, recoveryID)
	}
	slices.Sort(rep.sessions)
	if !opts.KeepKeys {
		keys, err := deleteUserKeys(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		rep.keys = keys
	}
	name := failureName(s.failureMAC(), u.Username)
	locks, err := lockedRecords(ctx, tx, name, countedMethods)
	if err != nil {
		return err
	}
	rep.locks = locks
	return tx.DeleteAuthFailures(ctx, name, countedMethods)
}

// emitRecovered reports a committed completion: EventRecoveryCompleted
// with the sessions it ended and the issuing key, one EventKeyRevoked per
// deleted key, then emitCleared's EventMethodLocked and
// EventMethodReenabled for the cleared locks.
func (s *Service) emitRecovered(userID int64, rep *repaired, actor EventActor) {
	completed := Event{Kind: EventRecoveryCompleted, At: s.now(), UserID: userID, SessionIDs: rep.sessions, Actor: actor}
	if rep.issuer != nil {
		completed.KeyID = rep.issuer.ID
	}
	s.emit(completed)
	s.emitKeysRevoked(userID, rep.keys, actor)
	s.emitCleared(userID, rep.locks, actor)
}
