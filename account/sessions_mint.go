package account

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
)

// maxUserAgentBytes caps a stored Session.UserAgent.
const maxUserAgentBytes = 256

// draft is a session built before its Update, so Rules.SessionCaps runs
// once and outside any transaction; store fills its user and writes it.
type draft struct {
	token   access.Secret
	session access.Session
}

// newDraft builds the session of op's method and kind that createSession
// writes for c: a 128-bit hex ID, a fresh token, the sanitised user agent,
// c's IP, and the per-session caps from one Rules.SessionCaps call, keeping
// only positive values.
func (s *Service) newDraft(ctx context.Context, r Rules, c Client, op *sessionOp) draft { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	token, hash := access.GenerateSessionToken()
	id := make([]byte, 16)
	_, _ = rand.Read(id) // crypto/rand.Read never fails (Go 1.24+); it crashes the program instead
	now := s.now()
	d := draft{token: token, session: access.Session{
		ID:           hex.EncodeToString(id),
		TokenHash:    hash,
		AuthMethod:   op.method,
		Kind:         op.kind,
		UserAgent:    sanitizeUserAgent(c.UserAgent),
		CreatedAt:    now,
		LastActivity: now,
		AuthTime:     now,
	}}
	if c.IP.IsValid() {
		d.session.LastIP = c.IP.String()
	}
	if r.SessionCaps != nil {
		idle, absolute := r.SessionCaps(ctx, c)
		d.session.IdleCap = max(idle, 0)
		d.session.AbsoluteCap = max(absolute, 0)
	}
	return d
}

// store writes d's session for userID inside tx. Under
// Rules.MaxSessionsPerUser it first deletes the user's least recently
// active sessions until one more fits, and returns their IDs for the
// caller's EventSessionRevoked.
func (d *draft) store(ctx context.Context, tx Tx, r Rules, userID int64) (evicted []string, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	d.session.UserID = userID
	if r.MaxSessionsPerUser > 0 {
		sessions, err := tx.SessionsByUserID(ctx, userID)
		if err != nil {
			return nil, err
		}
		slices.SortFunc(sessions, func(a, b access.Session) int {
			return cmp.Or(a.LastActivity.Compare(b.LastActivity), strings.Compare(a.ID, b.ID))
		})
		for i := 0; len(sessions)-i >= r.MaxSessionsPerUser; i++ {
			if err := tx.DeleteSession(ctx, access.SessionRef{ID: sessions[i].ID, UserID: userID}); err != nil {
				return nil, err
			}
			evicted = append(evicted, sessions[i].ID)
		}
	}
	sess := d.session
	if err := tx.CreateSession(ctx, &sess); err != nil {
		return nil, err
	}
	return evicted, nil
}

// admission is an anonymous operation's gate: its own refusals, then its
// limiter charge, so a refused input spends no limiter slot. A nil field
// skips its step.
type admission struct {
	// refusals are the answers that need no slot: input rules, store state.
	refusals func() error
	// limit charges the limiter; nil where the operation's begin or its
	// caller charges. The Reservation it returns, if any, is the caller's.
	limit func() (*ratelimit.Reservation, error)
}

func (a *admission) admit() (*ratelimit.Reservation, error) {
	if a.refusals != nil {
		if err := a.refusals(); err != nil {
			return nil, err
		}
	}
	if a.limit == nil {
		return nil, nil
	}
	return a.limit()
}

// requestLimit charges c's IP request limit.
func (s *Service) requestLimit(c Client) func() (*ratelimit.Reservation, error) { //nolint:gocritic // hugeParam: the request's Client
	return func() (*ratelimit.Reservation, error) { return nil, s.limiter.Request(ratelimit.IPKey(c.IP)) }
}

// ipAttempt reserves an IP-only attempt for c.
func (s *Service) ipAttempt(c Client) func() (*ratelimit.Reservation, error) { //nolint:gocritic // hugeParam: the request's Client
	return func() (*ratelimit.Reservation, error) {
		return s.limiter.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(c.IP)})
	}
}

// sessionOp is one operation that creates a session; createSession runs it.
// Every session the module creates goes through createSession, so no path
// skips a step of its order.
type sessionOp struct {
	gate admission
	// prepare is the work after the admission and outside the Update: a
	// hash, a counted verification, a ceremony's verification. Its error
	// cancels the reservation unless prepare settled it.
	prepare func(res *ratelimit.Reservation) error
	// in runs first in the Update and returns the user to sign in, or nil
	// to commit with no session. A store may re-run it, so it resets
	// whatever it sets outside.
	in func(tx Tx) (*access.User, error)
	// fill sets the session fields op.in decided, after each run of it.
	fill func(sess *access.Session)
	// announce adds the operation's own entries for the written session,
	// between EventSessionRevoked and EventSignedIn, in the same run.
	announce func(j *journal, u *access.User, sess *access.Session)
	method   access.Method
	kind     access.SessionKind
}

// createSession runs op in order: the admission, prepare, Rules.SessionCaps
// once with c, then one change holding op.in, op.fill, the session write,
// the MaxSessionsPerUser eviction and its entries: EventSessionRevoked,
// op.announce's and, for a full session, EventSignedIn. A full session's device
// cookie is Succeed's, else (no or an IP-only reservation) Limiter.DeviceCookie
// for c.Device; a recovery session gets none. A prepare error cancels the
// reservation and an Update error fails it; a commit whose op.in gave no user
// fails it too and returns the zero SignedIn and a nil error.
func (s *Service) createSession(ctx context.Context, r Rules, c Client, op *sessionOp) (SignedIn, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	res, err := op.admitAndPrepare()
	if err != nil {
		return SignedIn{}, err
	}
	d := s.newDraft(ctx, r, c, op)
	user, err := s.writeSession(ctx, r, c, op, &d)
	if err != nil || user == nil {
		if res != nil {
			res.Fail()
		}
		return SignedIn{}, err
	}
	var device access.Secret
	if res != nil {
		device = res.Succeed()
	}
	if device.IsZero() && op.kind == access.SessionFull {
		device = s.limiter.DeviceCookie(ratelimit.AccountKey(user.Username), c.Device)
	}
	return SignedIn{User: user.Clone(), Session: d.session, Token: d.token, DeviceCookie: device}, nil
}

// admitAndPrepare runs op's admission, then its prepare, cancelling the
// reservation on a prepare error.
func (op *sessionOp) admitAndPrepare() (*ratelimit.Reservation, error) {
	res, err := op.gate.admit()
	if err != nil || op.prepare == nil {
		return res, err
	}
	if err := op.prepare(res); err != nil {
		if res != nil {
			res.Cancel()
		}
		return nil, err
	}
	return res, nil
}

// writeSession is createSession's change, from c's address: op.in and
// op.fill, then d's session for the user op.in returned, with the
// evictions and the entries.
func (s *Service) writeSession(ctx context.Context, r Rules, c Client, op *sessionOp, d *draft) (user *access.User, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	err = s.change(ctx, byClient(Actor{}, c), func(tx Tx, j *journal) error {
		user = nil
		u, inErr := op.in(tx)
		if inErr != nil || u == nil {
			return inErr
		}
		if op.fill != nil {
			op.fill(&d.session)
		}
		evicted, writeErr := d.store(ctx, tx, r, u.ID)
		if writeErr != nil {
			return writeErr
		}
		j.created(&d.session)
		if len(evicted) > 0 {
			j.add(Event{Kind: EventSessionRevoked, At: s.now(), UserID: u.ID, SessionIDs: evicted})
		}
		if op.announce != nil {
			op.announce(j, u, &d.session)
		}
		if op.kind == access.SessionFull {
			j.add(Event{Kind: EventSignedIn, At: d.session.CreatedAt, UserID: u.ID, Method: op.method, SessionIDs: []string{d.session.ID}})
		}
		user = u
		return nil
	})
	return user, err
}

// createUser creates user through create, which assigns its ID, and deletes
// the new name's failure records in the same Update, so failures typed
// against the name before it was a user lock nothing. refusals are the
// store refusals create answers (refusedBy).
func (s *Service) createUser(ctx context.Context, tx Tx, user *access.User, create func(context.Context, *access.User) error, refusals ...error) error {
	if err := create(ctx, user); err != nil {
		return refusedBy(err, refusals...)
	}
	return tx.DeleteAuthFailures(ctx, failureName(s.failureMAC(), user.Username), countedMethods)
}

// sanitizeUserAgent drops invalid UTF-8, controls, format characters (Cf,
// bidi controls among them) and line or paragraph separators, stopping
// before maxUserAgentBytes on a rune boundary. It drops more than
// lineBreaking: a user agent is not text a person typed, so no invisible
// character in it is legitimate, and one would disguise it where the
// Security page and the security log show it.
func sanitizeUserAgent(ua string) string {
	var b strings.Builder
	for _, r := range ua {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxUserAgentBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
