package account

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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
	token     access.Secret
	presented access.Hash // Client.Presented, the session a full sign-in replaces
	session   access.Session
}

// newDraft builds the session of op's method that createSession
// writes for c: a 128-bit hex ID, a fresh token, c's transport, the sanitised
// user agent, c's IP, and the per-session caps from one Rules.SessionCaps
// call, keeping only positive values.
func (s *Service) newDraft(ctx context.Context, r Rules, c Client, op *sessionOp) draft { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	token, hash := access.GenerateSessionToken()
	id := make([]byte, 16)
	_, _ = rand.Read(id) // crypto/rand.Read never fails (Go 1.24+); it crashes the program instead
	now := s.now()
	d := draft{token: token, presented: c.Presented, session: access.Session{
		ID:           hex.EncodeToString(id),
		TokenHash:    hash,
		AuthMethod:   op.method,
		UserAgent:    sanitizeUserAgent(c.UserAgent),
		CreatedAt:    now,
		LastActivity: now,
		AuthTime:     now,
		Secure:       c.Secure,
	}}
	if ip := c.IP(); ip.IsValid() {
		d.session.LastIP = ip.String()
	}
	if r.SessionCaps != nil {
		idle, absolute := r.SessionCaps(ctx, c, op.method)
		d.session.IdleCap = max(idle, 0)
		d.session.AbsoluteCap = max(absolute, 0)
	}
	return d
}

// store writes d's session for userID inside tx. It first deletes the
// session replace names, then, under Rules.MaxSessionsPerUser, the user's
// least recently active sessions until one more fits, and returns both for
// the caller's EventSessionRevoked entries ("" for no replacement).
func (d *draft) store(ctx context.Context, tx Tx, r Rules, userID int64) (replaced string, evicted []string, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value
	d.session.UserID = userID
	if replaced, err = d.replace(ctx, tx); err != nil {
		return "", nil, err
	}
	if r.MaxSessionsPerUser > 0 {
		sessions, err := tx.SessionsByUserID(ctx, userID)
		if err != nil {
			return "", nil, err
		}
		slices.SortFunc(sessions, func(a, b access.Session) int {
			return cmp.Or(a.LastActivity.Compare(b.LastActivity), strings.Compare(a.ID, b.ID))
		})
		for i := 0; len(sessions)-i >= r.MaxSessionsPerUser; i++ {
			if err := tx.DeleteSession(ctx, access.SessionRef{ID: sessions[i].ID, UserID: userID}); err != nil {
				return "", nil, err
			}
			evicted = append(evicted, sessions[i].ID)
		}
	}
	sess := d.session
	if err := tx.CreateSession(ctx, &sess); err != nil {
		return "", nil, err
	}
	return replaced, evicted, nil
}

// replace deletes the session d.presented names when it is a session of d's
// user on its transport, and returns its ID: a fresh sign-in ends the
// session it was made from, so a sniffed token dies with it.
func (d *draft) replace(ctx context.Context, tx Tx) (string, error) {
	if d.presented.IsZero() {
		return "", nil
	}
	old, found, err := tx.SessionByHash(ctx, d.presented)
	if err != nil || !found || old.UserID != d.session.UserID || old.Secure != d.session.Secure {
		return "", err
	}
	if err := tx.DeleteSession(ctx, access.SessionRef{ID: old.ID, UserID: old.UserID}); err != nil {
		return "", err
	}
	return old.ID, nil
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
	return func() (*ratelimit.Reservation, error) { return nil, s.limiter.Request(ratelimit.IPKey(c.IP())) }
}

// ipAttempt reserves an IP-only attempt for c.
func (s *Service) ipAttempt(c Client) func() (*ratelimit.Reservation, error) { //nolint:gocritic // hugeParam: the request's Client
	return func() (*ratelimit.Reservation, error) {
		return s.limiter.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(c.IP())})
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
	// pend, when set, runs after in for its user and decides whether the
	// sign-in completes now: nil and nil do; a pending entry to mint, or a
	// refusal to answer, commits the Update with no session and pend's
	// entries, so a correct first factor's failure reset stands. full is
	// reserve's refusal: pend answers it as its refusal before it spends
	// anything, and complete answers that refusal before any mint.
	pend func(tx Tx, j *journal, u *access.User, full error) (entry *pending, refused, err error)
	// reserve, when set, runs after prepare and holds the place of the
	// pending sign-in a pend that spends a single-use credential mints:
	// complete fills it with pend's entry and releases it on every other
	// answer. nil, nil holds none; a refusal reaches pend as full.
	reserve func() (*pendingSlot, error)
	// replaces is the live pending sign-in pend's entry replaces, taking
	// its place (replaceTicket); zero mints a new one.
	replaces access.Secret
	// bind, when set, runs after pend lets the sign-in complete and writes
	// what the sign-in binds to its user, sess being the session the Update
	// then writes, nil for a user who waits for approval.
	bind func(tx Tx, j *journal, u *access.User, sess *access.Session) error
	// fill sets the session fields op.in decided, after each run of it.
	fill func(sess *access.Session)
	// announce adds the operation's own entries for the written session,
	// between EventSessionRevoked and EventSignedIn, in the same run; sess
	// is nil when pend held the sign-in back.
	announce func(j *journal, u *access.User, sess *access.Session)
	method   access.Method
}

// createSession is signIn for an operation with no pend.
func (s *Service) createSession(ctx context.Context, r Rules, c Client, op *sessionOp) (SignedIn, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	out, err := s.signIn(ctx, r, c, op)
	return out.SignedIn, err
}

// completion is complete's answer: a LoginResult, or the account op.in
// created that waits for approval, which holds no session.
type completion struct {
	waiting *access.User
	LoginResult
}

// signIn is complete for an op whose in creates no account that waits for
// approval.
func (s *Service) signIn(ctx context.Context, r Rules, c Client, op *sessionOp) (LoginResult, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	out, err := s.complete(ctx, r, c, op)
	return out.LoginResult, err
}

// complete runs op: the admission, prepare, Rules.SessionCaps once with c,
// then one change holding op.in, op.pend, op.bind, op.fill and the session
// write (draft.store). A completed sign-in succeeds the reservation and gets
// deviceCookie's cookie. A sign-in pend holds back, and one whose user waits
// for approval and so gets no session, cancel it; a pend refusal answering as
// a wrong secret fails it. A prepare error cancels it; an Update error, or a
// commit whose op.in gave no user (the zero completion), fails it.
func (s *Service) complete(ctx context.Context, r Rules, c Client, op *sessionOp) (completion, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	res, err := op.admitAndPrepare()
	if err != nil {
		return completion{}, err
	}
	var (
		slot *pendingSlot
		full error
	)
	if op.reserve != nil {
		slot, full = op.reserve()
	}
	defer slot.release()
	d := s.newDraft(ctx, r, c, op)
	user, entry, refused, err := s.writeSession(ctx, r, c, op, &d, full)
	switch {
	case err != nil || user == nil && entry == nil && refused == nil:
		if res != nil {
			res.Fail()
		}
		return completion{}, err
	case refused != nil:
		switch {
		case res == nil:
		case errors.Is(refused, ErrInvalidCredentials):
			res.Fail()
		default:
			res.Cancel()
		}
		return completion{}, refused
	case entry != nil || user.WaitingApproval:
		if res != nil {
			res.Cancel()
		}
		return s.heldBack(op, slot, user, entry)
	}
	if res != nil {
		res.Succeed()
	}
	return completion{SignedIn: SignedIn{User: user.Clone(), Session: d.session, Token: d.token, DeviceCookie: s.deviceCookie(user.Username, c)}}, nil
}

// heldBack is complete's answer for a sign-in op.pend held back with entry,
// its ticket stored in slot, in op.replaces' place, or minted; or, with
// entry nil, for user waiting for approval.
func (s *Service) heldBack(op *sessionOp, slot *pendingSlot, user *access.User, entry *pending) (completion, error) {
	var (
		minted *Pending
		err    error
	)
	switch {
	case entry == nil:
		return completion{waiting: user.Clone()}, nil
	case slot != nil:
		minted = entry.answer(slot.fill(*entry, s.now()))
	case !op.replaces.IsZero():
		minted, err = s.replaceTicket(op.replaces, entry)
	default:
		minted, err = s.mintTicket(entry)
	}
	if err != nil {
		return completion{}, err
	}
	return completion{Pending: minted}, nil
}

// deviceCookie is the device cookie a completed sign-in or step-up of
// username from c answers, sealed with c's transport.
func (s *Service) deviceCookie(username string, c Client) access.Secret { //nolint:gocritic // hugeParam: the request's Client
	return s.limiter.DeviceCookie(ratelimit.AccountKey(username), c.Device, c.Secure)
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

// writeSession is complete's change, from c's address: op.in, op.pend,
// op.bind and op.fill, then d's session for the user op.in returned, with the
// replacement, the evictions and the entries; or, when op.pend holds the
// sign-in back or the user waits for approval, op.announce's entries with no
// session.
func (s *Service) writeSession(ctx context.Context, r Rules, c Client, op *sessionOp, d *draft, full error) (user *access.User, entry *pending, refused, err error) { //nolint:gocritic // hugeParam: the operation's one Rules value and Client
	err = s.change(ctx, byClient(Actor{}, c), func(tx Tx, j *journal) error {
		user, entry, refused = nil, nil, nil
		u, inErr := op.in(tx)
		if inErr != nil || u == nil {
			return inErr
		}
		var holdErr error
		if entry, refused, holdErr = op.hold(tx, j, u, full); holdErr != nil || entry != nil || refused != nil {
			return holdErr
		}
		if completeErr := s.completeIn(ctx, tx, j, r, op, d, u); completeErr != nil {
			return completeErr
		}
		user = u
		return nil
	})
	return user, entry, refused, err
}

// completeIn is writeSession's part after op.pend let u's sign-in complete:
// op.bind, then d's session (storeSession), or for a user who waits for
// approval op.announce's entries alone.
func (s *Service) completeIn(ctx context.Context, tx Tx, j *journal, r Rules, op *sessionOp, d *draft, u *access.User) error { //nolint:gocritic // hugeParam: the operation's one Rules value
	sess := &d.session
	if u.WaitingApproval {
		sess = nil
	}
	if op.bind != nil {
		if err := op.bind(tx, j, u, sess); err != nil {
			return err
		}
	}
	if sess != nil {
		return s.storeSession(ctx, tx, j, r, op, d, u)
	}
	if op.announce != nil {
		op.announce(j, u, nil)
	}
	return nil
}

// hold runs op.pend for u with full, when set, and journals op.announce's
// entries for a sign-in it holds back.
func (op *sessionOp) hold(tx Tx, j *journal, u *access.User, full error) (entry *pending, refused, err error) {
	if op.pend == nil {
		return nil, nil, nil
	}
	if entry, refused, err = op.pend(tx, j, u, full); err != nil || entry == nil && refused == nil {
		return nil, nil, err
	}
	if op.announce != nil {
		op.announce(j, u, nil)
	}
	return entry, refused, nil
}

// storeSession is writeSession's session write for u: op.fill, d's session
// with the replacement and the evictions, and the entries.
func (s *Service) storeSession(ctx context.Context, tx Tx, j *journal, r Rules, op *sessionOp, d *draft, u *access.User) error { //nolint:gocritic // hugeParam: the operation's one Rules value
	if op.fill != nil {
		op.fill(&d.session)
	}
	replaced, evicted, err := d.store(ctx, tx, r, u.ID)
	if err != nil {
		return err
	}
	j.created(&d.session)
	if replaced != "" {
		j.addDetail(Event{Kind: EventSessionRevoked, At: s.now(), UserID: u.ID, SessionIDs: []string{replaced}}, LogDetailSignedInAgain)
	}
	if len(evicted) > 0 {
		j.add(Event{Kind: EventSessionRevoked, At: s.now(), UserID: u.ID, SessionIDs: evicted})
	}
	if op.announce != nil {
		op.announce(j, u, &d.session)
	}
	j.add(Event{Kind: EventSignedIn, At: d.session.CreatedAt, UserID: u.ID, Method: op.method, SessionIDs: []string{d.session.ID}})
	return nil
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
