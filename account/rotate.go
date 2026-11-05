package account

import (
	"context"

	"github.com/cplieger/access"
)

// rotated is a session as one rotation wrote it, with its new token.
type rotated struct {
	token   access.Secret
	session access.Session
}

// rotate gives p's session a new token inside tx, with p's token hash as
// the compare-and-swap, so a session rotated or ended since p was verified,
// or one of another user than userID, is ErrSessionGone.
func (s *Service) rotate(ctx context.Context, tx Tx, p access.Principal, userID int64, stepUp access.Method) (rotated, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	sess, err := principalSession(ctx, tx, p, userID)
	if err != nil {
		return rotated{}, err
	}
	return s.rotateSession(ctx, tx, sess, p.SessionTokenHash(), stepUp)
}

// principalSession reads p's session inside tx; one rotated or ended since
// p was verified, or of another user than userID, is a refused
// ErrSessionGone.
func principalSession(ctx context.Context, tx Tx, p access.Principal, userID int64) (*access.Session, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	sess, found, err := tx.SessionByHash(ctx, p.SessionTokenHash())
	switch {
	case err != nil:
		return nil, err
	case !found || sess.ID != p.SessionID || sess.UserID != userID:
		return nil, refuse(ErrSessionGone)
	}
	return sess, nil
}

// rotateSession gives sess, as tx read it, a new token. Rotation.Next is
// sess with only TokenHash changed, plus AuthTime (now) and AuthMethod when
// stepUp is non-empty, so the session's ID, times, caps and labels carry
// over and its absolute deadline never moves. expect is the
// RotateSession compare-and-swap; zero rotates by (UserID, ID) alone.
func (s *Service) rotateSession(ctx context.Context, tx Tx, sess *access.Session, expect access.Hash, stepUp access.Method) (rotated, error) {
	token, hash := access.GenerateSessionToken()
	next := *sess
	next.TokenHash = hash
	if stepUp != "" {
		next.AuthTime, next.AuthMethod = s.now(), stepUp
	}
	if err := tx.RotateSession(ctx, Rotation{ID: next.ID, UserID: next.UserID, ExpectHash: expect, Next: next}); err != nil {
		return rotated{}, err
	}
	return rotated{token: token, session: next}, nil
}
