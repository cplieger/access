package account

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"github.com/cplieger/access"
)

// maxSessionLabelRunes bounds a session label.
const maxSessionLabelRunes = 64

// SessionLabel is the input of RenameSession.
type SessionLabel struct{ ID, Label string }

// Sessions returns p's own sessions that the session verifier still
// accepts under Authenticator.Timeouts, oldest first. p must be a full
// session (ErrSessionRequired).
func (s *Service) Sessions(ctx context.Context, p access.Principal) ([]access.Session, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return nil, err
	}
	if err := requireSession(p); err != nil {
		return nil, err
	}
	all, err := s.store.SessionsByUserID(ctx, p.User.ID)
	if err != nil {
		return nil, storeErr(err)
	}
	timeouts, now := s.authn.Timeouts(), s.now()
	live := slices.DeleteFunc(all, func(sess access.Session) bool {
		return access.ValidateSession(&sess, timeouts, now) != nil
	})
	slices.SortFunc(live, func(a, b access.Session) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ID, b.ID))
	})
	return live, nil
}

// RenameSession labels one of p's own sessions: at most 64 runes on one line
// (*TextError), the empty label clearing it. A session of another user, or
// none, is ErrNotFound.
func (s *Service) RenameSession(ctx context.Context, p access.Principal, in SessionLabel) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return err
	}
	if err := requireSession(p); err != nil {
		return err
	}
	if err := checkLine(TextFieldLabel, in.Label, maxSessionLabelRunes); err != nil {
		return err
	}
	if err := s.store.UpdateSessionLabel(ctx, access.SessionRef{ID: in.ID, UserID: p.User.ID}, in.Label); err != nil {
		return answer(refusedBy(err, ErrNotFound))
	}
	return nil
}

// RevokeSession ends one of p's own sessions, the current one included,
// with its EventSessionRevoked. A session of another
// user, or none, is ErrNotFound.
func (s *Service) RevokeSession(ctx context.Context, p access.Principal, id string) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if _, err := s.begin(); err != nil {
		return err
	}
	if err := requireSession(p); err != nil {
		return err
	}
	userID := p.User.ID
	return s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		if err := tx.DeleteSession(ctx, access.SessionRef{ID: id, UserID: userID}); err != nil {
			return refusedBy(err, ErrNotFound)
		}
		j.add(Event{Kind: EventSessionRevoked, At: s.now(), UserID: userID, SessionIDs: []string{id}, Actor: eventActor(As(p))})
		return nil
	})
}

// RevokeOtherSessions ends every session of p's user but p's own. p must be
// a full session within Rules().RecentAuth. Its EventUserSessionsRevoked
// names the ended IDs, when there were any.
func (s *Service) RevokeOtherSessions(ctx context.Context, p access.Principal) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.begin()
	if err != nil {
		return err
	}
	if sessErr := requireSession(p); sessErr != nil {
		return sessErr
	}
	if authErr := s.recentAuth(r, p); authErr != nil {
		return authErr
	}
	userID := p.User.ID
	return s.change(ctx, by(As(p)), func(tx Tx, j *journal) error {
		revoked, err := tx.DeleteUserSessions(ctx, userID, p.SessionID)
		if err != nil {
			return err
		}
		s.addRevoked(j, userID, revoked, eventActor(As(p)))
		return nil
	})
}

// Logout ends the session whose token hashes to tokenHash. It is
// idempotent: no such session is nil, and only a session it ended has an
// EventSessionRevoked, carrying that session's display data.
func (s *Service) Logout(ctx context.Context, tokenHash access.Hash) error {
	if _, err := s.begin(); err != nil {
		return err
	}
	if tokenHash.IsZero() {
		return nil
	}
	return s.change(ctx, origin{}, func(tx Tx, j *journal) error {
		sess, found, err := tx.SessionByHash(ctx, tokenHash)
		if err != nil || !found {
			return err
		}
		j.actorSession(sess)
		if err := tx.DeleteSession(ctx, access.SessionRef{ID: sess.ID, UserID: sess.UserID}); err != nil {
			return err
		}
		j.add(Event{
			Kind: EventSessionRevoked, At: s.now(), UserID: sess.UserID, SessionIDs: []string{sess.ID},
			Actor: EventActor{SessionID: sess.ID, UserID: sess.UserID},
		})
		return nil
	})
}

// addRevoked adds a credential change's or a revocation's ended sessions,
// when there were any.
func (s *Service) addRevoked(j *journal, userID int64, ids []string, actor EventActor) {
	if len(ids) > 0 {
		j.add(Event{Kind: EventUserSessionsRevoked, At: s.now(), UserID: userID, SessionIDs: ids, Actor: actor})
	}
}
