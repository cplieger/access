package accesstest

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// idsAndLineage: rule 17.
func (c *contract) idsAndLineage(t *testing.T) {
	t.Run("distinct", c.idsDistinct)
	t.Run("never_reused_users", func(t *testing.T) {
		s := c.store(t)
		neverReused(t, func() int64 { return mustUser(t, s, fresh("user")).ID },
			func(id int64) error { return s.DeleteUser(t.Context(), id) })
	})
	t.Run("never_reused_keys", func(t *testing.T) {
		s := c.store(t)
		u := mustUser(t, s, "holder")
		neverReused(t, func() int64 { k := newKey(u.ID); mustKey(t, s, k); return k.ID },
			func(id int64) error { return s.DeleteAPIKey(t.Context(), access.KeyRef{ID: id, UserID: u.ID}) })
	})
	t.Run("reopen_users", func(t *testing.T) {
		c.needReopen(t, "rule 17")
		c.neverReusedAcrossReopen(t, func(s account.Store) int64 { return mustUser(t, s, fresh("user")).ID },
			func(s account.Store, id int64) error { return s.DeleteUser(t.Context(), id) })
	})
	t.Run("reopen_keys", func(t *testing.T) {
		c.needReopen(t, "rule 17")
		var owner int64
		c.neverReusedAcrossReopen(t, func(s account.Store) int64 {
			if owner == 0 {
				owner = mustUser(t, s, "holder").ID
			}
			k := newKey(owner)
			mustKey(t, s, k)
			return k.ID
		}, func(s account.Store, id int64) error {
			return s.DeleteAPIKey(t.Context(), access.KeyRef{ID: id, UserID: owner})
		})
	})
	t.Run("lineage", c.lineage)
	t.Run("attributions", c.attributions)
}

func (c *contract) idsDistinct(t *testing.T) {
	const n = 1000
	s, ctx := c.store(t), t.Context()
	owner := mustUser(t, s, "owner")
	ids := map[string][]int64{}
	err := s.Update(ctx, func(tx account.Tx) error {
		clear(ids)
		for i := range n {
			u, k, p := newUser(fmt.Sprintf("bulk-%d", i)), newKey(owner.ID), newPasskey(owner.ID)
			a := &access.KeyAttribution{At: epoch, Action: access.AttributionCreated, KeyLineage: []int64{1}, UserID: owner.ID}
			if err := errors.Join(tx.CreateUser(ctx, u), tx.CreateAPIKey(ctx, k), tx.CreatePasskey(ctx, p), tx.CreateKeyAttribution(ctx, a)); err != nil {
				return err
			}
			ids["user"], ids["key"] = append(ids["user"], u.ID), append(ids["key"], k.ID)
			ids["passkey"], ids["attribution"] = append(ids["passkey"], p.ID), append(ids["attribution"], a.ID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	for kind, got := range ids {
		sorted := slices.Sorted(slices.Values(got))
		if len(slices.Compact(sorted)) != n || sorted[0] < 1 || sorted[len(sorted)-1] > maxID {
			t.Errorf("%d %s IDs are not %d distinct values in [1, 2^53-1]", len(got), kind, n)
		}
	}
}

// neverReused creates three rows, deletes the highest, creates one, deletes
// the lowest, creates one, deletes every row and creates one; no ID may come
// back.
func neverReused(t *testing.T, create func() int64, remove func(id int64) error) {
	t.Helper()
	seen := map[int64]bool{}
	var live []int64
	add := func() {
		id := create()
		if seen[id] {
			t.Fatalf("ID %d assigned twice", id)
		}
		seen[id] = true
		live = append(live, id)
		slices.Sort(live)
	}
	drop := func(i int) {
		if err := remove(live[i]); err != nil {
			t.Fatalf("delete %d: %v", live[i], err)
		}
		live = slices.Delete(live, i, i+1)
	}
	add()
	add()
	add()
	drop(len(live) - 1)
	add()
	drop(0)
	add()
	for len(live) > 0 {
		drop(0)
	}
	add()
}

// neverReusedAcrossReopen creates two rows, deletes the higher, reopens the
// store and creates one more, whose ID must differ from every ID assigned
// before the reopen.
func (c *contract) neverReusedAcrossReopen(t *testing.T, create func(s account.Store) int64, remove func(s account.Store, id int64) error) {
	t.Helper()
	s := c.store(t)
	low, high := create(s), create(s)
	if err := remove(s, high); err != nil {
		t.Fatalf("delete %d: %v", high, err)
	}
	s = c.reopen(t, "rule 17", s)
	if next := create(s); next == low || next == high {
		t.Errorf("after deleting ID %d and reopening, the next ID is %d, which the store assigned before the reopen", high, next)
	}
}

func (c *contract) lineage(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "holder")
	root := newKey(u.ID)
	mustKey(t, s, root)
	child := newKey(u.ID)
	child.LineageIDs = []int64{41, 42}
	mustKey(t, s, child)
	want := map[int64][]int64{root.ID: {root.ID}, child.ID: {41, 42, child.ID}}
	for _, k := range []*access.Key{root, child} {
		got, found, err := s.APIKeyByHash(ctx, k.KeyHash)
		if err != nil || !found || !slices.Equal(got.LineageIDs, want[k.ID]) {
			t.Errorf("APIKeyByHash(key %d).LineageIDs = %v, want %v", k.ID, got, want[k.ID])
		}
	}
	byUser, err1 := s.ListAPIKeysByUserID(ctx, u.ID)
	all, err2 := s.ListAPIKeys(ctx)
	for name, list := range map[string][]access.Key{opListUserKeys: byUser, opListAllKeys: all} {
		if len(list) != 2 || errors.Join(err1, err2) != nil {
			t.Fatalf("%s = (%d keys, %v), want 2", name, len(list), errors.Join(err1, err2))
		}
		for i := range list {
			if k := &list[i]; !slices.Equal(k.LineageIDs, want[k.ID]) {
				t.Errorf("%s key %d LineageIDs = %v, want %v", name, k.ID, k.LineageIDs, want[k.ID])
			}
		}
	}
}

func (c *contract) attributions(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u1, u2 := mustUser(t, s, "first"), mustUser(t, s, "second")
	k1, k2, k3 := newKey(u1.ID), newKey(u1.ID), newKey(u2.ID)
	for _, k := range []*access.Key{k1, k2, k3} {
		mustKey(t, s, k)
	}
	appendOne := func(u *access.User, k *access.Key, action access.AttributionAction, i int) access.KeyAttribution {
		a := &access.KeyAttribution{At: epoch.Add(time.Duration(i) * time.Minute), Action: action, KeyLineage: k.LineageIDs, UserID: u.ID}
		if err := s.CreateKeyAttribution(ctx, a); err != nil {
			t.Fatalf("CreateKeyAttribution: %v", err)
		}
		return *a.Clone()
	}
	written := []access.KeyAttribution{
		appendOne(u1, k1, access.AttributionCreated, 1),
		appendOne(u1, k2, access.AttributionDisabled, 2),
		appendOne(u2, k3, access.AttributionRecovered, 3),
	}
	expectList(t, s, "after three appends", written)
	if err := s.DeleteAPIKey(ctx, access.KeyRef{ID: k1.ID, UserID: u1.ID}); err != nil {
		t.Fatalf("DeleteAPIKey: %v", err)
	}
	for _, u := range []*access.User{u1, u2} {
		if _, err := s.DeleteUserAPIKeys(ctx, u.ID); err != nil {
			t.Fatalf("DeleteUserAPIKeys: %v", err)
		}
		u.Enabled = false
		if err := s.UpdateUser(ctx, u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
	}
	expectList(t, s, "after deleting every named key and disabling both users", written)
	if err := s.DeleteUser(ctx, u2.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	expectList(t, s, "after deleting the user holding the highest ID", written[:2])
	next := appendOne(u1, k1, access.AttributionEnabled, 4)
	if next.ID <= written[2].ID {
		t.Errorf("the append after a delete got ID %d, want above %d", next.ID, written[2].ID)
	}
	written = append(written[:2:2], next)
	if err := s.Update(ctx, func(tx account.Tx) error {
		if err := tx.CreateKeyAttribution(ctx, &access.KeyAttribution{At: epoch, Action: access.AttributionCreated, KeyLineage: []int64{1}, UserID: u1.ID}); err != nil {
			return err
		}
		return errContract
	}); !errors.Is(err, errContract) {
		t.Fatalf("Update = %v, want the callback's error", err)
	}
	expectList(t, s, "after a rolled-back append", written)
}

// expectList fails unless ListKeyAttributions returns exactly want, in
// order, with ascending IDs.
func expectList(t *testing.T, s account.Store, when string, want []access.KeyAttribution) {
	t.Helper()
	got, err := s.ListKeyAttributions(t.Context())
	if err != nil || len(got) != len(want) {
		t.Fatalf("%s: ListKeyAttributions = (%d records, %v), want %d", when, len(got), err, len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.ID != w.ID || g.UserID != w.UserID || g.Action != w.Action || !g.At.Equal(w.At) || !slices.Equal(g.KeyLineage, w.KeyLineage) {
			t.Errorf("%s: record %d = %+v, want %+v", when, i, g, w)
		}
		if i > 0 && g.ID <= got[i-1].ID {
			t.Errorf("%s: IDs %d then %d are not ascending", when, got[i-1].ID, g.ID)
		}
	}
}

// concurrency: rule 13. Each worker owns one user's rows, so its own
// bookkeeping says exactly what the store must hold.
func (c *contract) concurrency(t *testing.T) {
	const workers, steps = 16, 500
	s := c.store(t)
	users := make([]*access.User, workers)
	for i := range users {
		users[i] = mustUser(t, s, fmt.Sprintf("worker-%d", i))
	}
	raceN(workers, func(i int) {
		w := &worker{s: s, ctx: t.Context(), u: users[i], rng: rand.New(rand.NewPCG(uint64(i), 13))} //nolint:gosec // G404: a reproducible workload, not a secret
		for step := range steps {
			if err := w.step(); err != nil {
				t.Errorf("worker %d step %d: %v", i, step, err)
				return
			}
		}
	})
}

type worker struct {
	ctx      context.Context
	s        account.Store
	u        *access.User
	rng      *rand.Rand
	sessions []*access.Session
	keys     []*access.Key
	clock    time.Duration
}

var errWorker = errors.New("store state differs from the worker's own writes")

func (w *worker) now() time.Time {
	w.clock += time.Second
	return epoch.Add(w.clock)
}

func (w *worker) step() error {
	if len(w.sessions) == 0 {
		return w.createSession()
	}
	sess := w.sessions[w.rng.IntN(len(w.sessions))]
	switch w.rng.IntN(7) {
	case 0:
		return w.createSession()
	case 1:
		if got, found, err := w.s.SessionByHash(w.ctx, sess.TokenHash); err != nil || !found || got.ID != sess.ID {
			return errors.Join(errWorker, err)
		}
		return nil
	case 2:
		return w.s.UpdateSessionActivity(w.ctx, sess.TokenHash, access.SessionActivity{At: w.now(), IP: "192.0.2.7"})
	case 3:
		next := *sess
		next.TokenHash, next.LastActivity = access.NewHash(fresh("rotated")), w.now()
		if err := w.s.RotateSession(w.ctx, account.Rotation{ID: sess.ID, UserID: w.u.ID, ExpectHash: sess.TokenHash, Next: next}); err != nil {
			return err
		}
		sess.TokenHash = next.TokenHash
		return nil
	case 4:
		return w.deleteSession(sess)
	case 5:
		return w.touchKey()
	default:
		return w.checkCounts()
	}
}

func (w *worker) createSession() error {
	sess := newSession(w.u.ID, w.now())
	if err := w.s.CreateSession(w.ctx, sess); err != nil {
		return err
	}
	w.sessions = append(w.sessions, sess)
	return nil
}

func (w *worker) deleteSession(sess *access.Session) error {
	if err := w.s.DeleteSession(w.ctx, refOf(sess)); err != nil {
		return err
	}
	w.sessions = slices.DeleteFunc(w.sessions, func(x *access.Session) bool { return x == sess })
	return nil
}

func (w *worker) touchKey() error {
	if len(w.keys) < 3 {
		k := newKey(w.u.ID)
		err := w.s.Update(w.ctx, func(tx account.Tx) error { return tx.CreateAPIKey(w.ctx, k) })
		if err == nil {
			w.keys = append(w.keys, k)
		}
		return err
	}
	return w.s.TouchAPIKey(w.ctx, w.keys[w.rng.IntN(len(w.keys))].ID, w.now())
}

func (w *worker) checkCounts() error {
	sessions, err1 := w.s.SessionsByUserID(w.ctx, w.u.ID)
	keys, err2 := w.s.ListAPIKeysByUserID(w.ctx, w.u.ID)
	if err := errors.Join(err1, err2); err != nil {
		return err
	}
	if len(sessions) != len(w.sessions) || len(keys) != len(w.keys) {
		return fmt.Errorf("%w: %d sessions and %d keys, want %d and %d", errWorker, len(sessions), len(keys), len(w.sessions), len(w.keys))
	}
	return nil
}

// contexts: rule 18.
func (c *contract) contexts(t *testing.T) {
	s := c.store(t)
	expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	forStore, forTx := seedRows(t, s), seedRows(t, s)
	runExpired(expired, t, "store", append(txCalls(s, forStore), sweeperCalls(s)...))
	runExpired(expired, t, "Update", []namedCall{{func(ctx context.Context) error {
		return s.Update(ctx, func(tx account.Tx) error { return tx.CreateUser(ctx, newUser("expired-update")) })
	}, "Update"}})
	runExpired(expired, t, "tx", []namedCall{{func(ctx context.Context) error {
		return s.Update(t.Context(), func(tx account.Tx) error {
			for _, call := range txCalls(tx, forTx) {
				checkContextErr(t, "tx."+call.name, call.call(ctx))
			}
			return nil
		})
	}, "Update with tx calls"}})
}

type namedCall struct {
	call func(ctx context.Context) error
	name string
}

// seeded is one user's rows that rule 18's calls aim at.
type seeded struct {
	user    *access.User
	session *access.Session
	passkey *access.PasskeyCredential
	key     *access.Key
	token   access.OneTimeToken
}

func seedRows(t *testing.T, s account.Store) *seeded {
	t.Helper()
	sd := &seeded{user: mustUser(t, s, fresh("context"))}
	sd.session, sd.passkey, sd.key = newSession(sd.user.ID, epoch), newPasskey(sd.user.ID), newKey(sd.user.ID)
	sd.token = newToken(access.PurposeRecovery, sd.user.ID, epoch.Add(time.Hour))
	mustSession(t, s, sd.session)
	mustPasskey(t, s, sd.passkey)
	mustKey(t, s, sd.key)
	mustToken(t, s, sd.token)
	return sd
}

// runExpired runs every call with ctx and fails when one blocks for 10 s
// or reports a cancellation that is not ctx's deadline.
func runExpired(ctx context.Context, t *testing.T, label string, calls []namedCall) {
	t.Helper()
	var current atomic.Value
	current.Store("")
	if !within(10*time.Second, func() {
		for _, call := range calls {
			current.Store(call.name)
			checkContextErr(t, label+": "+call.name, call.call(ctx))
		}
	}) {
		t.Fatalf("%s: %v blocked on a context whose deadline has passed", label, current.Load())
	}
}

func checkContextErr(t *testing.T, name string, err error) {
	t.Helper()
	if errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("%s = %v, want ctx's DeadlineExceeded or completion", name, err)
	}
}

func sweeperCalls(s account.Store) []namedCall {
	timeouts := access.SessionTimeouts{Idle: time.Hour, Absolute: 24 * time.Hour}
	return []namedCall{
		{func(ctx context.Context) error {
			_, err := s.CleanupExpiredSessions(ctx, epoch, timeouts, 10)
			return err
		}, "CleanupExpiredSessions"},
		{func(ctx context.Context) error { _, err := s.CleanupExpiredOneTimeTokens(ctx, epoch); return err }, "CleanupExpiredOneTimeTokens"},
	}
}

// txCalls is every Tx method, aimed at sd's rows, deletes last.
func txCalls(tx account.Tx, sd *seeded) []namedCall {
	return slices.Concat(userCalls(tx, sd), sessionCalls(tx, sd), credentialCalls(tx, sd), recordCalls(tx, sd), deleteCalls(tx, sd))
}

func userCalls(tx account.Tx, sd *seeded) []namedCall {
	return []namedCall{
		{func(ctx context.Context) error { return tx.CreateUser(ctx, newUser(fresh("ctx"))) }, "CreateUser"},
		{func(ctx context.Context) error { return tx.CreateInitialUser(ctx, newUser(fresh("ctx"))) }, "CreateInitialUser"},
		{func(ctx context.Context) error { _, _, err := tx.UserByID(ctx, sd.user.ID); return err }, "UserByID"},
		{func(ctx context.Context) error { _, _, err := tx.UserByUsername(ctx, sd.user.Username); return err }, opUserByUsername},
		{func(ctx context.Context) error {
			_, _, err := tx.UserByOIDC(ctx, access.OIDCIdentity{Issuer: "i", Subject: "s"})
			return err
		}, "UserByOIDC"},
		{func(ctx context.Context) error {
			_, _, err := tx.UserByWebAuthnHandle(ctx, sd.user.WebAuthnHandle)
			return err
		}, "UserByWebAuthnHandle"},
		{func(ctx context.Context) error { _, err := tx.ListUsers(ctx); return err }, "ListUsers"},
		{func(ctx context.Context) error { return tx.UpdateUser(ctx, sd.user.Clone()) }, "UpdateUser"},
		{func(ctx context.Context) error { _, err := tx.UserCount(ctx); return err }, "UserCount"},
	}
}

func sessionCalls(tx account.Tx, sd *seeded) []namedCall {
	ref := refOf(sd.session)
	return []namedCall{
		{func(ctx context.Context) error { return tx.CreateSession(ctx, newSession(sd.user.ID, epoch)) }, "CreateSession"},
		{func(ctx context.Context) error { _, _, err := tx.SessionByHash(ctx, sd.session.TokenHash); return err }, opSessionByHash},
		{func(ctx context.Context) error { _, err := tx.SessionsByUserID(ctx, sd.user.ID); return err }, "SessionsByUserID"},
		{func(ctx context.Context) error {
			return tx.UpdateSessionActivity(ctx, sd.session.TokenHash, access.SessionActivity{At: epoch.Add(time.Minute), IP: "192.0.2.9"})
		}, "UpdateSessionActivity"},
		{func(ctx context.Context) error { return tx.UpdateSessionLabel(ctx, ref, "ctx") }, "UpdateSessionLabel"},
		{func(ctx context.Context) error {
			next := *sd.session
			next.TokenHash = access.NewHash(fresh("ctx-rotated"))
			return tx.RotateSession(ctx, account.Rotation{ID: ref.ID, UserID: ref.UserID, Next: next})
		}, "RotateSession"},
	}
}

func credentialCalls(tx account.Tx, sd *seeded) []namedCall {
	pref := access.PasskeyRef{ID: sd.passkey.ID, UserID: sd.user.ID}
	return []namedCall{
		{func(ctx context.Context) error { return tx.CreatePasskey(ctx, newPasskey(sd.user.ID)) }, "CreatePasskey"},
		{func(ctx context.Context) error { _, err := tx.PasskeysByUserID(ctx, sd.user.ID); return err }, "PasskeysByUserID"},
		{func(ctx context.Context) error {
			return tx.UpdatePasskeyAfterLogin(ctx, sd.user.ID, sd.passkey.CredentialID, access.PasskeyLoginUpdate{At: epoch, RawFlags: 0x05})
		}, "UpdatePasskeyAfterLogin"},
		{func(ctx context.Context) error { return tx.RenamePasskey(ctx, pref, "ctx") }, "RenamePasskey"},
		{func(ctx context.Context) error { return tx.CreateAPIKey(ctx, newKey(sd.user.ID)) }, "CreateAPIKey"},
		{func(ctx context.Context) error { _, _, err := tx.APIKeyByHash(ctx, sd.key.KeyHash); return err }, "APIKeyByHash"},
		{func(ctx context.Context) error { _, err := tx.ListAPIKeysByUserID(ctx, sd.user.ID); return err }, opListUserKeys},
		{func(ctx context.Context) error { _, err := tx.ListAPIKeys(ctx); return err }, opListAllKeys},
		{func(ctx context.Context) error { return tx.TouchAPIKey(ctx, sd.key.ID, epoch.Add(time.Minute)) }, "TouchAPIKey"},
	}
}

func recordCalls(tx account.Tx, sd *seeded) []namedCall {
	ref := account.FailureRef{Name: "ctx", Method: access.MethodPassword}
	purposes := []access.TokenPurpose{access.PurposeRecovery}
	return []namedCall{
		{func(ctx context.Context) error {
			return tx.CreateOneTimeToken(ctx, newToken(access.PurposeInvite, 0, epoch.Add(time.Hour)))
		}, "CreateOneTimeToken"},
		{func(ctx context.Context) error { _, _, err := tx.OneTimeTokenByHash(ctx, sd.token.Hash); return err }, "OneTimeTokenByHash"},
		{func(ctx context.Context) error { _, err := tx.LiveOneTimeTokens(ctx, purposes, epoch); return err }, "LiveOneTimeTokens"},
		{func(ctx context.Context) error {
			return tx.CreateKeyAttribution(ctx, &access.KeyAttribution{At: epoch, Action: access.AttributionCreated, KeyLineage: []int64{1}, UserID: sd.user.ID})
		}, "CreateKeyAttribution"},
		{func(ctx context.Context) error { _, err := tx.ListKeyAttributions(ctx); return err }, "ListKeyAttributions"},
		{func(ctx context.Context) error {
			return tx.PutAuthFailure(ctx, account.FailureCount{FailureRef: ref, Count: 1})
		}, "PutAuthFailure"},
		{func(ctx context.Context) error { _, _, err := tx.AuthFailure(ctx, ref); return err }, "AuthFailure"},
		{func(ctx context.Context) error { _, err := tx.UnreportedLocks(ctx); return err }, "UnreportedLocks"},
	}
}

func deleteCalls(tx account.Tx, sd *seeded) []namedCall {
	return []namedCall{
		{func(ctx context.Context) error {
			_, _, err := tx.ConsumeOneTimeToken(ctx, sd.token.Hash, epoch)
			return err
		}, "ConsumeOneTimeToken"},
		{func(ctx context.Context) error {
			_, err := tx.DeleteOneTimeTokens(ctx, access.PurposeRecovery, sd.user.ID)
			return err
		}, "DeleteOneTimeTokens"},
		{func(ctx context.Context) error { _, err := tx.DeleteOneTimeTokensIssuedBy(ctx, []int64{7}); return err }, "DeleteOneTimeTokensIssuedBy"},
		{func(ctx context.Context) error {
			return tx.DeleteAuthFailures(ctx, "ctx", []access.Method{access.MethodPassword})
		}, "DeleteAuthFailures"},
		{func(ctx context.Context) error { _, err := tx.PruneAuthFailures(ctx, nil); return err }, "PruneAuthFailures"},
		{func(ctx context.Context) error { return tx.DeleteSession(ctx, refOf(sd.session)) }, "DeleteSession"},
		{func(ctx context.Context) error { return tx.DeleteSessionByHash(ctx, sd.session.TokenHash) }, "DeleteSessionByHash"},
		{func(ctx context.Context) error { _, err := tx.DeleteUserSessions(ctx, sd.user.ID, ""); return err }, "DeleteUserSessions"},
		{func(ctx context.Context) error {
			return tx.DeletePasskey(ctx, access.PasskeyRef{ID: sd.passkey.ID, UserID: sd.user.ID})
		}, "DeletePasskey"},
		{func(ctx context.Context) error { _, err := tx.DeleteUserPasskeys(ctx, sd.user.ID); return err }, "DeleteUserPasskeys"},
		{func(ctx context.Context) error {
			return tx.DeleteAPIKey(ctx, access.KeyRef{ID: sd.key.ID, UserID: sd.user.ID})
		}, "DeleteAPIKey"},
		{func(ctx context.Context) error { _, err := tx.DeleteUserAPIKeys(ctx, sd.user.ID); return err }, "DeleteUserAPIKeys"},
		{func(ctx context.Context) error { return tx.DeleteUser(ctx, sd.user.ID) }, "DeleteUser"},
	}
}
