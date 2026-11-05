package accesstest

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// cleanupTimeouts are rule 14's policy timeouts, except in the caps case.
var cleanupTimeouts = access.SessionTimeouts{Idle: time.Hour, Absolute: 24 * time.Hour}

// rounds is how often each concurrent case of rule 14 repeats.
const rounds = 50

// cleanup: rule 14.
func (c *contract) cleanup(t *testing.T) {
	t.Run("expired_removed", c.cleanupExpired)
	t.Run("caps", c.cleanupCaps)
	t.Run("deleted_set", func(t *testing.T) { c.deletedSet(t, false) })
	t.Run("deleted_set_reopen", func(t *testing.T) { c.deletedSet(t, true) })
	t.Run("bound", c.cleanupBound)
	t.Run("concurrent_delete", func(t *testing.T) { c.cleanupRace(t, raceDelete) })
	t.Run("concurrent_rotate", func(t *testing.T) { c.cleanupRace(t, raceRotate) })
	t.Run("rerun", c.cleanupRerun)
}

// expiredSession is a session of userID idle since an hour before now
// minus one minute, so cleanupTimeouts expire it at now.
func expiredSession(userID int64, now time.Time) *access.Session {
	return newSession(userID, now.Add(-cleanupTimeouts.Idle-time.Minute))
}

// sweep runs one CleanupExpiredSessions and fails on its error.
func sweep(t *testing.T, s account.Store, now time.Time, timeouts access.SessionTimeouts, limit int) []access.SessionRef {
	t.Helper()
	refs, err := s.CleanupExpiredSessions(t.Context(), now, timeouts, limit)
	if err != nil {
		t.Fatalf("CleanupExpiredSessions: %v", err)
	}
	return refs
}

// sameRefs reports whether got holds exactly want, in any order, none twice.
func sameRefs(got []access.SessionRef, want ...*access.Session) bool {
	if len(got) != len(want) {
		return false
	}
	for _, s := range want {
		if !slices.Contains(got, refOf(s)) {
			return false
		}
	}
	return true
}

// present reports which of sessions SessionByHash still finds.
func present(t *testing.T, s account.Store, sessions ...*access.Session) []bool {
	t.Helper()
	out := make([]bool, len(sessions))
	for i, sess := range sessions {
		_, out[i] = sessionFound(t, s, sess.TokenHash)
	}
	return out
}

func (c *contract) cleanupExpired(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	now := epoch.Add(48 * time.Hour)
	idle := expiredSession(1, now)
	absolute := newSession(1, now.Add(-time.Minute))
	absolute.CreatedAt = now.Add(-cleanupTimeouts.Absolute - time.Minute)
	live := newSession(2, now.Add(-time.Minute))
	for _, sess := range []*access.Session{idle, absolute, live} {
		mustSession(t, s, sess)
	}
	if refs := sweep(t, s, now, cleanupTimeouts, 10); !sameRefs(refs, idle, absolute) {
		t.Errorf("CleanupExpiredSessions = %v, want exactly the idle- and absolute-expired sessions", refs)
	}
	if got := present(t, s, idle, absolute, live); !slices.Equal(got, []bool{false, false, true}) {
		t.Errorf("after the sweep idle, absolute, live found = %v, want [false false true]", got)
	}
	tokens := make([]access.OneTimeToken, 0, 3)
	for _, exp := range []time.Time{now.Add(-time.Hour), now, now.Add(time.Hour)} {
		tok := newToken(access.PurposeInvite, 0, exp)
		mustToken(t, s, tok)
		tokens = append(tokens, tok)
	}
	if n, err := s.CleanupExpiredOneTimeTokens(ctx, now); err != nil || n != 2 {
		t.Errorf("CleanupExpiredOneTimeTokens = (%d, %v), want (2, nil)", n, err)
	}
	for i, tok := range tokens {
		if _, found, err := s.OneTimeTokenByHash(ctx, tok.Hash); err != nil || found != (i == 2) {
			t.Errorf("token %d after the sweep found = (%t, %v), want %t", i, found, err, i == 2)
		}
	}
}

func (c *contract) cleanupCaps(t *testing.T) {
	s := c.store(t)
	now := epoch.Add(30 * 24 * time.Hour)
	week := access.SessionTimeouts{Idle: 7 * 24 * time.Hour, Absolute: 7 * 24 * time.Hour}
	idleCap := func(idle time.Duration) *access.Session {
		sess := newSession(1, now.Add(-idle))
		sess.CreatedAt, sess.IdleCap = now.Add(-time.Hour), 30*time.Minute
		return sess
	}
	absoluteCap := func(age time.Duration) *access.Session {
		sess := newSession(1, now.Add(-time.Minute))
		sess.CreatedAt, sess.AbsoluteCap = now.Add(-age), 12*time.Hour
		return sess
	}
	recovery := newSession(1, now.Add(-time.Minute))
	recovery.CreatedAt, recovery.Kind = now.Add(-16*time.Minute), access.SessionRecovery
	gone := []*access.Session{idleCap(31 * time.Minute), absoluteCap(13 * time.Hour), recovery}
	kept := []*access.Session{idleCap(29 * time.Minute), absoluteCap(11 * time.Hour)}
	for _, sess := range slices.Concat(gone, kept) {
		mustSession(t, s, sess)
	}
	if refs := sweep(t, s, now, week, 10); !sameRefs(refs, gone...) {
		t.Errorf("CleanupExpiredSessions under 7-day timeouts = %v, want the over-cap and old recovery sessions", refs)
	}
	if got := present(t, s, kept...); !slices.Equal(got, []bool{true, true}) {
		t.Errorf("sessions inside their caps found = %v, want both", got)
	}
}

// deletedSet: A expires by t1, B between t1 and t2, C is live at both; with
// reopen the store is reopened between the t1 and t2 calls.
func (c *contract) deletedSet(t *testing.T, reopen bool) {
	if reopen {
		c.needReopen(t, "rule 14 (deleted set across a reopen)")
	}
	s := c.store(t)
	t1 := epoch.Add(48 * time.Hour)
	t2 := t1.Add(time.Hour)
	a := expiredSession(1, t1)
	b := newSession(2, t1.Add(-30*time.Minute))
	cs := newSession(2, t1.Add(50*time.Minute))
	for _, sess := range []*access.Session{a, b, cs} {
		sess.CreatedAt = t1.Add(-3 * time.Hour)
		mustSession(t, s, sess)
	}
	remaining := func(when string, want ...*access.Session) {
		if got, w := sessionIDs(t, s, 1, 2), idsOf(want); !slices.Equal(got, w) {
			t.Errorf("%s: sessions left %v, want %v", when, got, w)
		}
	}
	if refs := sweep(t, s, t1, cleanupTimeouts, 10); !sameRefs(refs, a) {
		t.Errorf("CleanupExpiredSessions(t1) = %v, want exactly A", refs)
	}
	remaining("after t1", b, cs)
	if reopen {
		s = c.reopen(t, "rule 14", s)
	}
	if refs := sweep(t, s, t2, cleanupTimeouts, 10); !sameRefs(refs, b) {
		t.Errorf("CleanupExpiredSessions(t2) = %v, want exactly B", refs)
	}
	remaining("after t2", cs)
	if refs := sweep(t, s, t2, cleanupTimeouts, 10); len(refs) != 0 {
		t.Errorf("a third CleanupExpiredSessions(t2) = %v, want none", refs)
	}
}

// sessionIDs returns, sorted, the IDs of every session of users.
func sessionIDs(t *testing.T, s account.Store, users ...int64) []string {
	t.Helper()
	var ids []string
	for _, id := range users {
		rows, err := s.SessionsByUserID(t.Context(), id)
		check(t, "SessionsByUserID", err)
		for i := range rows {
			ids = append(ids, rows[i].ID)
		}
	}
	slices.Sort(ids)
	return ids
}

func idsOf(sessions []*access.Session) []string {
	ids := make([]string, len(sessions))
	for i, s := range sessions {
		ids[i] = s.ID
	}
	slices.Sort(ids)
	return ids
}

func (c *contract) cleanupBound(t *testing.T) {
	s := c.store(t)
	now := epoch.Add(48 * time.Hour)
	expired := make([]*access.Session, 0, 5)
	for i := range 5 {
		sess := expiredSession(int64(1+i%2), now)
		mustSession(t, s, sess)
		expired = append(expired, sess)
	}
	live := newSession(1, now)
	mustSession(t, s, live)
	refs, err := s.CleanupExpiredSessions(t.Context(), now, cleanupTimeouts, 0)
	if got := present(t, s, slices.Concat(expired, []*access.Session{live})...); len(refs) != 0 || slices.Contains(got, false) {
		t.Errorf("limit 0 = (%v, %v) and left %v, want no ref and no delete", refs, err, got)
	}
	union := make([]access.SessionRef, 0, len(expired))
	for i, want := range []int{2, 2, 1, 0} {
		refs := sweep(t, s, now, cleanupTimeouts, 2)
		if len(refs) != want {
			t.Errorf("call %d with limit 2 returned %d refs, want %d", i+1, len(refs), want)
		}
		union = append(union, refs...)
	}
	if !sameRefs(union, expired...) {
		t.Errorf("the calls' refs %v are not exactly the five expired sessions", union)
	}
}

// raceArm is the call rule 14's concurrent case races the cleanup against:
// it reports whether the call found S gone and what S must look like after
// the round.
type raceArm func(t *testing.T, s account.Store, sess *access.Session, now time.Time) (gone bool, check func() error)

var errArm = errors.New("unexpected session state")

func raceDelete(t *testing.T, s account.Store, sess *access.Session, _ time.Time) (gone bool, check func() error) {
	err := s.DeleteSession(t.Context(), refOf(sess))
	if err != nil && !errors.Is(err, account.ErrNotFound) {
		t.Errorf("DeleteSession: %v", err)
	}
	return errors.Is(err, account.ErrNotFound), func() error {
		if _, found := sessionFound(t, s, sess.TokenHash); found {
			return fmt.Errorf("%w: S is still present", errArm)
		}
		return nil
	}
}

func raceRotate(t *testing.T, s account.Store, sess *access.Session, now time.Time) (gone bool, check func() error) {
	next := *sess
	next.TokenHash, next.LastActivity = access.NewHash(fresh("rotated")), now
	err := s.RotateSession(t.Context(), account.Rotation{ID: sess.ID, UserID: sess.UserID, Next: next})
	if err != nil && !errors.Is(err, account.ErrNotFound) {
		t.Errorf("RotateSession: %v", err)
	}
	gone = errors.Is(err, account.ErrNotFound)
	return gone, func() error {
		_, rotated := sessionFound(t, s, next.TokenHash)
		_, old := sessionFound(t, s, sess.TokenHash)
		if old || rotated == gone {
			return fmt.Errorf("%w: old hash found %t, rotated found %t, rotation found S gone %t", errArm, old, rotated, gone)
		}
		return nil
	}
}

func (c *contract) cleanupRace(t *testing.T, arm raceArm) {
	s := c.store(t)
	now := epoch.Add(48 * time.Hour)
	window, stepped := s.(cleanupWindow)
	for round := range rounds {
		sess := expiredSession(1, now)
		mustSession(t, s, sess)
		var refs []access.SessionRef
		var cleanErr, checkErr error
		var gone bool
		var check func() error
		sweepS := func() { refs, cleanErr = s.CleanupExpiredSessions(t.Context(), now, cleanupTimeouts, 10) }
		armS := func() { gone, check = arm(t, s, sess, now) }
		if stepped {
			if !inWindow(t, window, sweepS, armS) {
				return
			}
		} else {
			race(sweepS, armS)
		}
		if cleanErr != nil {
			t.Fatalf("round %d: CleanupExpiredSessions: %v", round, cleanErr)
		}
		if named := slices.Contains(refs, refOf(sess)); named != gone {
			t.Errorf("round %d: the cleanup named S %t, but the racing call found S gone %t", round, named, gone)
		}
		if checkErr = check(); checkErr != nil {
			t.Errorf("round %d: %v", round, checkErr)
		}
	}
}

// inWindow runs sweep, waits for its cleanup window, runs arm to
// completion, then releases the sweep; each wait is bounded at 5 s.
func inWindow(t *testing.T, w cleanupWindow, sweep, arm func()) bool {
	t.Helper()
	listed, release := w.armCleanupWindow()
	done := make(chan struct{})
	go func() {
		defer close(done)
		sweep()
	}()
	if !within(5*time.Second, func() { <-listed }) {
		release()
		t.Error("rule 14: the cleanup never signalled its window within 5 s")
		return false
	}
	arm()
	release()
	if !within(5*time.Second, func() { <-done }) {
		t.Error("rule 14: the cleanup did not return within 5 s of its release")
		return false
	}
	return true
}

func (c *contract) cleanupRerun(t *testing.T) {
	s, f := c.faulty(t, "rule 14 (re-run)")
	for round := range rounds {
		rerunRound(t, s, f, round)
	}
}

// rerunRound shares one grouped commit between a cleanup of three expired
// sessions and eight Updates whose callbacks fail.
func rerunRound(t *testing.T, s account.Store, f DurabilityFaults, round int) {
	t.Helper()
	const failing = 8
	ctx := t.Context()
	now := epoch.Add(48 * time.Hour)
	three := []*access.Session{expiredSession(1, now), expiredSession(1, now), expiredSession(2, now)}
	for _, sess := range three {
		mustSession(t, s, sess)
	}
	var refs []access.SessionRef
	var cleanErr error
	names := make([]string, failing)
	calls := make([]func(), 0, 1+failing)
	calls = append(calls, func() { refs, cleanErr = s.CleanupExpiredSessions(ctx, now, cleanupTimeouts, 10) })
	for i := range failing {
		names[i] = fmt.Sprintf("rerun-%d-%d", round, i)
		calls = append(calls, func() {
			_ = s.Update(ctx, func(tx account.Tx) error {
				return errors.Join(tx.CreateUser(ctx, newUser(names[i])), errContract)
			})
		})
	}
	h := holdPublish(f)
	done := make(chan struct{})
	go func() {
		defer close(done)
		race(calls...)
	}()
	if !h.await(f, f.Publishes(), failing+1) {
		t.Fatalf("round %d: the held publish never had %d pending calls within 5 s", round, failing+1)
	}
	<-done
	if cleanErr != nil || !sameRefs(refs, three...) {
		t.Fatalf("round %d: CleanupExpiredSessions = (%v, %v), want each of the three sessions exactly once", round, refs, cleanErr)
	}
	for _, name := range names {
		if userFound(t, s, name) {
			t.Fatalf("round %d: the failed Update's user %s exists", round, name)
		}
	}
}

// activity: rule 21.
func (c *contract) activity(t *testing.T) {
	t.Run("session", c.activitySession)
	t.Run("key", c.activityKey)
	t.Run("rotation", c.activityRotation)
	t.Run("concurrent", c.activityConcurrent)
}

func readSession(t *testing.T, s account.Store, h access.Hash) *access.Session {
	t.Helper()
	sess, found := sessionFound(t, s, h)
	if !found {
		t.Fatal("the session is not found")
	}
	return sess
}

func (c *contract) activitySession(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	sess := newSession(1, epoch)
	mustSession(t, s, sess)
	steps := []struct {
		act    access.SessionActivity
		wantAt time.Time
		wantIP string
	}{
		{access.SessionActivity{At: epoch.Add(30 * time.Minute), IP: ipB}, epoch.Add(30 * time.Minute), ipB},
		{access.SessionActivity{At: epoch, IP: ipA}, epoch.Add(30 * time.Minute), ipB},
		{access.SessionActivity{At: epoch.Add(30 * time.Minute), IP: "192.0.2.3"}, epoch.Add(30 * time.Minute), ipB},
		{access.SessionActivity{At: epoch.Add(40 * time.Minute), IP: "192.0.2.4"}, epoch.Add(40 * time.Minute), "192.0.2.4"},
	}
	for i, st := range steps {
		if err := s.UpdateSessionActivity(ctx, sess.TokenHash, st.act); err != nil {
			t.Fatalf("UpdateSessionActivity: %v", err)
		}
		if got := readSession(t, s, sess.TokenHash); !got.LastActivity.Equal(st.wantAt) || got.LastIP != st.wantIP {
			t.Errorf("after write %d (%v, %s): LastActivity %v LastIP %s, want %v %s", i+1, st.act.At, st.act.IP, got.LastActivity, got.LastIP, st.wantAt, st.wantIP)
		}
	}
}

func (c *contract) activityKey(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	k := newKey(1)
	mustKey(t, s, k)
	for _, at := range []time.Time{epoch.Add(30 * time.Minute), epoch} {
		if err := s.TouchAPIKey(ctx, k.ID, at); err != nil {
			t.Fatalf("TouchAPIKey: %v", err)
		}
	}
	if got, found, err := s.APIKeyByHash(ctx, k.KeyHash); err != nil || !found || !got.LastUsedAt.Equal(epoch.Add(30*time.Minute)) {
		t.Errorf("after touches at t+30m then t, LastUsedAt = %v, want t+30m", got)
	}
}

func (c *contract) activityRotation(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	sess := newSession(1, epoch)
	mustSession(t, s, sess)
	if err := s.UpdateSessionActivity(ctx, sess.TokenHash, access.SessionActivity{At: epoch.Add(30 * time.Minute), IP: ipB}); err != nil {
		t.Fatalf("UpdateSessionActivity: %v", err)
	}
	next := *sess
	next.TokenHash, next.LastActivity, next.LastIP = access.NewHash(fresh("rotated")), epoch, ipA
	if err := s.RotateSession(ctx, account.Rotation{ID: sess.ID, UserID: sess.UserID, Next: next}); err != nil {
		t.Fatalf("RotateSession: %v", err)
	}
	if got := readSession(t, s, next.TokenHash); !got.LastActivity.Equal(epoch.Add(30*time.Minute)) || got.LastIP != ipB {
		t.Errorf("rotated with an older LastActivity: %v %s, want t+30m 192.0.2.2", got.LastActivity, got.LastIP)
	}
}

func (c *contract) activityConcurrent(t *testing.T) {
	const writers = 32
	s, ctx := c.store(t), t.Context()
	sess, k := newSession(1, epoch), newKey(1)
	mustSession(t, s, sess)
	mustKey(t, s, k)
	order := rand.New(rand.NewPCG(21, 21)).Perm(writers) //nolint:gosec // G404: a reproducible shuffle, not a secret
	at := func(i int) time.Time { return epoch.Add(time.Duration(1+order[i]) * time.Minute) }
	raceN(writers, func(i int) {
		if err := s.UpdateSessionActivity(ctx, sess.TokenHash, access.SessionActivity{At: at(i), IP: fmt.Sprintf("192.0.2.%d", order[i])}); err != nil {
			t.Errorf("UpdateSessionActivity: %v", err)
		}
		if err := s.TouchAPIKey(ctx, k.ID, at(i)); err != nil {
			t.Errorf("TouchAPIKey: %v", err)
		}
	})
	newest := epoch.Add(writers * time.Minute)
	if got := readSession(t, s, sess.TokenHash); !got.LastActivity.Equal(newest) || got.LastIP != fmt.Sprintf("192.0.2.%d", writers-1) {
		t.Errorf("after %d concurrent writes S holds %v %s, want the newest %v with its IP", writers, got.LastActivity, got.LastIP, newest)
	}
	if got, _, err := s.APIKeyByHash(ctx, k.KeyHash); err != nil || got == nil || !got.LastUsedAt.Equal(newest) {
		t.Errorf("after %d concurrent touches K holds %v, want %v", writers, got, newest)
	}
}
