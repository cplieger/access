package account

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/crockford"
)

// recoveryCodeBytes is a recovery code's entropy: 80 bits, above the 64
// NIST SP 800-63B-4 §4.2.1.1 asks of a saved recovery code, which is 16
// Crockford symbols.
const recoveryCodeBytes = 10

// newRecoveryCode draws a recovery code from crypto/rand: shown is its
// displayed form, XXXX-XXXX-XXXX-XXXX, and canonical the 16 symbols its
// hash covers.
func newRecoveryCode() (shown access.Secret, canonical string) {
	b := make([]byte, recoveryCodeBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+); it crashes the program instead
	canonical = crockford.Encode(b)
	return access.NewSecret(groupFours(canonical)), canonical
}

// groupFours is s in groups of four joined by dashes.
func groupFours(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(s[i:min(i+4, len(s))])
	}
	return b.String()
}

// issuable is a recovery code drawn and hashed before the Update that may
// issue it: a hash is too slow to run inside a transaction.
type issuable struct {
	shown access.Secret
	hash  access.Hash
}

// prepareRecoveryCode draws and hashes a recovery code with the password
// hasher, so it is stored only as its salted hash; the hasher's
// access.ErrHashBusy is returned as it is.
func (s *Service) prepareRecoveryCode(ctx context.Context) (issuable, error) {
	shown, canonical := newRecoveryCode()
	hash, err := s.hasher.Hash(ctx, canonical)
	if err != nil {
		return issuable{}, err
	}
	return issuable{shown: shown, hash: hash}, nil
}

// errRecoveryCodeUndrawn ends a run of issuingChange's change whose issue
// rule found a code due before one was drawn; it never leaves issuingChange.
var errRecoveryCodeUndrawn = errors.New("account: a recovery code is due and none was drawn")

// issuingChange runs fn as one change. With drawFirst, the caller's read
// that the issue rule will find a code due, it draws and hashes one before
// the change; otherwise it runs fn with none, and a run that finds one due
// rolls back and runs once more with one drawn. No hash runs inside a
// transaction, and a change that issues nothing spends none. fn resets
// what it sets outside; a busy hasher answers access.ErrHashBusy.
func (s *Service) issuingChange(ctx context.Context, o origin, drawFirst bool, fn func(tx Tx, j *journal, code *issuable) error) error { //nolint:gocritic // hugeParam: the change's one origin
	if !drawFirst {
		err := s.change(ctx, o, func(tx Tx, j *journal) error { return fn(tx, j, nil) })
		if !errors.Is(err, errRecoveryCodeUndrawn) {
			return err
		}
	}
	code, err := s.prepareRecoveryCode(ctx)
	if err != nil {
		return err
	}
	return s.change(ctx, o, func(tx Tx, j *journal) error { return fn(tx, j, &code) })
}

// issueRecoveryIn is the issue rule of every Update that adds a password or
// a second factor to u, run after the addition inside tx: when u then holds
// a password, a second factor (secondFactorHeld) and no recovery code, it
// stores code's hash, journals EventRecoveryCodeIssued by actor and returns
// the code to show once; otherwise the zero Secret. A code due with code nil
// is errRecoveryCodeUndrawn, for issuingChange.
func (s *Service) issueRecoveryIn(ctx context.Context, tx Tx, j *journal, r Rules, u *access.User, code *issuable, actor EventActor) (access.Secret, error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	if u.PasswordHash.IsZero() {
		return access.Secret{}, nil
	}
	held, err := s.secondFactorHeld(ctx, tx, r, u)
	if err != nil || !held {
		return access.Secret{}, err
	}
	_, found, err := tx.RecoveryCodeByUserID(ctx, u.ID)
	if err != nil || found {
		return access.Secret{}, err
	}
	if code == nil {
		return access.Secret{}, refuse(errRecoveryCodeUndrawn)
	}
	if err := s.storeRecoveryCode(ctx, tx, u, code); err != nil {
		return access.Secret{}, err
	}
	j.add(Event{Kind: EventRecoveryCodeIssued, At: s.now(), UserID: u.ID, Actor: actor})
	return code.shown, nil
}

// storeRecoveryCode writes code as u's recovery code inside tx, with the
// failure records of the code it replaces, whose lock goes with it.
func (s *Service) storeRecoveryCode(ctx context.Context, tx Tx, u *access.User, code *issuable) error {
	if err := tx.SetRecoveryCode(ctx, access.RecoveryCode{UserID: u.ID, Hash: code.hash, CreatedAt: s.stamp()}); err != nil {
		return err
	}
	return tx.DeleteAuthFailures(ctx, failureName(s.failureMAC(), u.Username), []access.Method{access.MethodRecoveryCode})
}

// RegenerateRecoveryCode replaces p's own user's recovery code with a new
// one, returned to show once, for a full session within RecentAuth on a
// secure request, with a current second factor as proof (verifyProof's
// answers). A dormant user is ErrSSOOnly and a user holding no recovery
// code ErrNotFound, both before any count.
func (s *Service) RegenerateRecoveryCode(ctx context.Context, c Client, p access.Principal, proof SecondFactorProof) (access.Secret, error) { //nolint:gocritic // hugeParam: the request's Client and Principal, read once
	r, err := s.beginRecentSession(plainRefused, c.Secure && p.Secure, p)
	if err != nil {
		return access.Secret{}, err
	}
	u, err := s.ownUser(ctx, p)
	if err != nil {
		return access.Secret{}, err
	}
	if modeErr := s.localAllowed(ctx, u); modeErr != nil {
		return access.Secret{}, modeErr
	}
	if _, found, readErr := s.store.RecoveryCodeByUserID(ctx, u.ID); readErr != nil || !found {
		return access.Secret{}, answer(foundOr(readErr, found))
	}
	code, err := s.prepareRecoveryCode(ctx)
	if err != nil {
		return access.Secret{}, err
	}
	pr, err := s.verifyProof(ctx, r, c, p, u, proof)
	if err != nil {
		return access.Secret{}, err
	}
	err = s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		return s.regenerateIn(ctx, tx, j, p, &pr, &code)
	})
	pr.settle(err)
	if err != nil {
		return access.Secret{}, err
	}
	return code.shown, nil
}

// regenerateIn is RegenerateRecoveryCode's change: the user, the mode and
// the code it replaces re-read, the proof committed, then code stored.
func (s *Service) regenerateIn(ctx context.Context, tx Tx, j *journal, p access.Principal, pr *proven, code *issuable) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	cur, err := ownUserIn(ctx, tx, p)
	if err != nil {
		return err
	}
	if modeErr := requireLocal(ctx, tx, cur, ErrSSOOnly); modeErr != nil {
		return modeErr
	}
	if _, found, readErr := tx.RecoveryCodeByUserID(ctx, cur.ID); readErr != nil || !found {
		return foundOr(readErr, found)
	}
	if commitErr := pr.commit(ctx, s, tx, j, p); commitErr != nil {
		return commitErr
	}
	if writeErr := s.storeRecoveryCode(ctx, tx, cur, code); writeErr != nil {
		return writeErr
	}
	j.add(Event{Kind: EventRecoveryCodeReplaced, At: s.now(), UserID: cur.ID, Actor: eventActor(As(p))})
	return nil
}

// foundOr is a lookup's error: err when set, else a refused ErrNotFound
// when nothing was found.
func foundOr(err error, found bool) error {
	switch {
	case err != nil:
		return err
	case !found:
		return refuse(ErrNotFound)
	}
	return nil
}
