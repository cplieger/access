package account

import (
	"context"
	"slices"
	"time"

	"github.com/cplieger/access"
)

// RotateAPIKey gives key id a new secret and keeps the rest of it; the
// superseded secret verifies for Rules.KeyRotationOverlap or until the new
// one's first use, and a rotation during an overlap replaces it. a is
// OutOfBand, reaching every key, or a full session within RecentAuth,
// reaching its own user's keys and rotating into Issued; any other actor is
// ErrSessionRequired before any read. An unreachable key is ErrNotFound;
// then Policy (OpRotateKey) decides on the owner as stored, and an expired
// key is a refused key_expired. One EventKeyRotated follows the commit.
func (s *Service) RotateAPIKey(ctx context.Context, a Actor, id int64) (RotatedKey, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, session, err := s.admitRotation(a)
	if err != nil {
		return RotatedKey{}, err
	}
	gen, err := access.GenerateAPIKey(r.KeyPrefix)
	if err != nil {
		return RotatedKey{}, err
	}
	now := s.now()
	var (
		key access.Key
		rot rotated
	)
	err = s.change(ctx, by(a), func(tx Tx, j *journal) error {
		rot = rotated{}
		var findErr error
		if key, findErr = s.keyToRotate(ctx, tx, a, session, id, now); findErr != nil {
			return findErr
		}
		sec := access.KeySecret{
			KeyHash: gen.Hash, KeyPrefix: gen.DisplayPrefix, KeySuffix: gen.DisplaySuffix,
			PreviousHash: key.KeyHash, PreviousUntil: now.Add(r.KeyRotationOverlap),
		}
		if writeErr := tx.UpdateAPIKeySecret(ctx, access.KeyRef{ID: key.ID, UserID: key.UserID}, sec); writeErr != nil {
			return writeErr
		}
		key.KeyHash, key.KeyPrefix, key.KeySuffix = sec.KeyHash, sec.KeyPrefix, sec.KeySuffix
		key.PreviousHash, key.PreviousUntil, key.LastUsedAt = sec.PreviousHash, sec.PreviousUntil, time.Time{}
		j.add(Event{Kind: EventKeyRotated, At: now, UserID: key.UserID, KeyID: key.ID, Actor: eventActor(a)})
		if !session.IsSession() {
			return nil
		}
		var rotErr error
		rot, rotErr = s.rotate(ctx, tx, session, session.User.ID, "")
		return rotErr
	})
	if err != nil {
		return RotatedKey{}, err
	}
	rotatedKey := RotatedKey{Plaintext: gen.Plaintext, Key: key}
	if session.IsSession() {
		rotatedKey.Issued = Issued{Token: rot.token, Session: rot.session}
	}
	return rotatedKey, nil
}

// admitRotation is RotateAPIKey's actor check, before any store call: the
// operation's Rules, and for a principal a full session within
// Rules().RecentAuth, which it returns; an out-of-band actor gets the zero
// Principal.
func (s *Service) admitRotation(a Actor) (Rules, access.Principal, error) { //nolint:gocritic // hugeParam: Actor is passed by value like the Principal it holds
	r, err := s.begin()
	if err != nil {
		return Rules{}, access.Principal{}, err
	}
	if a.isOutOfBand() {
		return r, access.Principal{}, nil
	}
	p, _ := a.Principal()
	if sessErr := requireSession(p); sessErr != nil {
		return Rules{}, access.Principal{}, sessErr
	}
	if recentErr := s.recentAuth(r, p); recentErr != nil {
		return Rules{}, access.Principal{}, recentErr
	}
	return r, p, nil
}

// keyToRotate reads key id inside tx among the keys a reaches: session's
// own user's for a session, every user's otherwise. A key a cannot reach,
// or whose owner tx lacks, is a refused ErrNotFound; then the Policy
// decides on the owner, and an expired key is a refused key_expired.
func (s *Service) keyToRotate(ctx context.Context, tx Tx, a Actor, session access.Principal, id int64, now time.Time) (access.Key, error) { //nolint:gocritic // hugeParam: the operation's Actor and Principal
	var (
		keys []access.Key
		err  error
	)
	if session.IsSession() {
		keys, err = tx.ListAPIKeysByUserID(ctx, session.User.ID)
	} else {
		keys, err = tx.ListAPIKeys(ctx)
	}
	if err != nil {
		return access.Key{}, err
	}
	i := slices.IndexFunc(keys, func(k access.Key) bool { return k.ID == id })
	if i < 0 {
		return access.Key{}, refuse(ErrNotFound)
	}
	key := keys[i]
	owner, found, err := tx.UserByID(ctx, key.UserID)
	switch {
	case err != nil:
		return access.Key{}, err
	case !found:
		return access.Key{}, refuse(ErrNotFound)
	}
	if polErr := s.policy.Authorize(ctx, Decision{Op: OpRotateKey, Actor: a, Target: owner}); polErr != nil {
		return access.Key{}, refuse(polErr)
	}
	if keyExpired(&key, now) {
		return access.Key{}, refuse(&PolicyError{Op: OpRotateKey, Reason: ReasonKeyExpired})
	}
	return key, nil
}
