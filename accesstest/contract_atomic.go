package accesstest

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// racers is rule 5's goroutine count.
const racers = 64

// atomicity: rule 5's single-call cases.
func (c *contract) atomicity(t *testing.T) {
	t.Run("consume_token", c.raceConsume)
	t.Run("initial_user", c.raceInitialUser)
	t.Run("passkey_credential_id", c.racePasskey)
	t.Run("rotate_session", c.raceRotate)
	t.Run("rotate_vs_delete", c.raceRotateDelete)
	t.Run("delete_user_cascade", c.deleteUserCascade)
}

// exactlyOne runs fn on racers goroutines and fails unless exactly one
// reports success.
func exactlyOne(t *testing.T, what string, fn func(i int) bool) {
	t.Helper()
	var wins atomic.Int64
	raceN(racers, func(i int) {
		if fn(i) {
			wins.Add(1)
		}
	})
	if n := wins.Load(); n != 1 {
		t.Errorf("%d concurrent %s: %d succeeded, want exactly 1", racers, what, n)
	}
}

func (c *contract) raceConsume(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	tok := newToken(access.PurposeInvite, 0, epoch.Add(time.Hour))
	mustToken(t, s, tok)
	exactlyOne(t, "consumes", func(int) bool {
		_, found, err := s.ConsumeOneTimeToken(ctx, tok.Hash, epoch)
		if err != nil {
			t.Errorf("ConsumeOneTimeToken: %v", err)
		}
		return found
	})
}

func (c *contract) raceInitialUser(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	exactlyOne(t, "initial users", func(i int) bool {
		err := s.CreateInitialUser(ctx, newUser(fmt.Sprintf("initial-%d", i)))
		if err != nil && !errors.Is(err, account.ErrSetupComplete) {
			t.Errorf("CreateInitialUser: %v, want nil or ErrSetupComplete", err)
		}
		return err == nil
	})
}

func (c *contract) racePasskey(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	users := []*access.User{mustUser(t, s, "a"), mustUser(t, s, "b")}
	credID := []byte(fresh("shared-credential"))
	exactlyOne(t, "passkey inserts", func(i int) bool {
		p := newPasskey(users[i%2].ID)
		p.CredentialID = append([]byte(nil), credID...)
		err := s.CreatePasskey(ctx, p)
		if err != nil && !errors.Is(err, account.ErrDuplicateCredential) {
			t.Errorf("CreatePasskey: %v, want nil or ErrDuplicateCredential", err)
		}
		return err == nil
	})
}

func (c *contract) raceRotate(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	sess := newSession(mustUser(t, s, "rotate").ID, epoch)
	mustSession(t, s, sess)
	exactlyOne(t, "rotations of one ExpectHash", func(int) bool {
		next := *sess
		next.TokenHash = access.NewHash(fresh("rotated"))
		err := s.RotateSession(ctx, account.Rotation{ID: sess.ID, UserID: sess.UserID, ExpectHash: sess.TokenHash, Next: next})
		if err != nil && !errors.Is(err, account.ErrNotFound) {
			t.Errorf("RotateSession: %v, want nil or ErrNotFound", err)
		}
		return err == nil
	})
	if _, found := sessionFound(t, s, sess.TokenHash); found {
		t.Error("the rotated-away hash is still found")
	}
}

func (c *contract) raceRotateDelete(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := mustUser(t, s, "rotate")
	for range 20 {
		sess := newSession(u.ID, epoch)
		mustSession(t, s, sess)
		next := *sess
		next.TokenHash = access.NewHash(fresh("rotated"))
		race(
			func() {
				_ = s.RotateSession(ctx, account.Rotation{ID: sess.ID, UserID: u.ID, ExpectHash: sess.TokenHash, Next: next})
			},
			func() { _ = s.DeleteSession(ctx, refOf(sess)) },
		)
		for _, h := range []access.Hash{sess.TokenHash, next.TokenHash} {
			if _, found := sessionFound(t, s, h); found {
				t.Fatal("a rotation racing DeleteSession left a live hash")
			}
		}
	}
}

func (c *contract) deleteUserCascade(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u, other := mustUser(t, s, "doomed"), mustUser(t, s, "other")
	for _, owner := range []*access.User{u, other} {
		mustSession(t, s, newSession(owner.ID, epoch))
		mustPasskey(t, s, newPasskey(owner.ID))
		mustKey(t, s, newKey(owner.ID))
		mustToken(t, s, newToken(access.PurposeRecovery, owner.ID, epoch.Add(time.Hour)))
		if err := s.CreateKeyAttribution(ctx, &access.KeyAttribution{At: epoch, Action: access.AttributionCreated, KeyLineage: []int64{1}, UserID: owner.ID}); err != nil {
			t.Fatalf("CreateKeyAttribution: %v", err)
		}
	}
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if got := userRows(t, s, u.ID); got != [5]int{} {
		t.Errorf("after DeleteUser, sessions, passkeys, keys, subject tokens, attributions = %v, want none", got)
	}
	if got := userRows(t, s, other.ID); got != [5]int{1, 1, 1, 1, 1} {
		t.Errorf("another user's rows = %v, want one of each untouched", got)
	}
}

// userRows counts id's sessions, passkeys, keys, live recovery tokens with
// id as Subject, and key attributions.
func userRows(t *testing.T, s account.Store, id int64) [5]int {
	t.Helper()
	ctx := t.Context()
	sessions, err1 := s.SessionsByUserID(ctx, id)
	passkeys, err2 := s.PasskeysByUserID(ctx, id)
	keys, err3 := s.ListAPIKeysByUserID(ctx, id)
	tokens, err4 := s.LiveOneTimeTokens(ctx, []access.TokenPurpose{access.PurposeRecovery}, epoch)
	attributions, err5 := s.ListKeyAttributions(ctx)
	check(t, "reading the user's rows", errors.Join(err1, err2, err3, err4, err5))
	n := [5]int{len(sessions), len(passkeys), len(keys)}
	n[3] = countIf(tokens, func(tok *access.OneTimeToken) bool { return tok.Subject == id })
	n[4] = countIf(attributions, func(a *access.KeyAttribution) bool { return a.UserID == id })
	return n
}

func countIf[T any](xs []T, match func(*T) bool) int {
	n := 0
	for i := range xs {
		if match(&xs[i]) {
			n++
		}
	}
	return n
}

// update: rule 5's Update cases.
func (c *contract) update(t *testing.T) {
	t.Run("error_rolls_back", c.updateError)
	t.Run("panic_rolls_back", c.updatePanic)
	t.Run("nil_commits", c.updateCommit)
	t.Run("reads_own_writes", c.updateReadsOwn)
	t.Run("serialisable", c.updateSerialisable)
	t.Run("rerun_keeps_last", c.updateRerun)
	t.Run("grouped_commit", c.groupedCommit)
}

// writeThree writes a user, a session and a key through tx.
func writeThree(t *testing.T, tx account.Tx, name string) (*access.Session, *access.Key) {
	ctx := t.Context()
	u := newUser(name)
	if err := tx.CreateUser(ctx, u); err != nil {
		t.Errorf("tx.CreateUser: %v", err)
	}
	sess := newSession(u.ID, epoch)
	if err := tx.CreateSession(ctx, sess); err != nil {
		t.Errorf("tx.CreateSession: %v", err)
	}
	k := newKey(u.ID)
	if err := tx.CreateAPIKey(ctx, k); err != nil {
		t.Errorf("tx.CreateAPIKey: %v", err)
	}
	return sess, k
}

// visible reports which of the three rows writeThree made are found.
func visible(t *testing.T, s account.Store, name string, sess *access.Session, k *access.Key) [3]bool {
	t.Helper()
	if sess == nil || k == nil {
		t.Fatal("the Update never ran its callback")
	}
	_, keyFound, err := s.APIKeyByHash(t.Context(), k.KeyHash)
	if err != nil {
		t.Fatalf("APIKeyByHash: %v", err)
	}
	_, sessFound := sessionFound(t, s, sess.TokenHash)
	return [3]bool{userFound(t, s, name), sessFound, keyFound}
}

func (c *contract) updateError(t *testing.T) {
	s := c.store(t)
	var sess *access.Session
	var k *access.Key
	err := s.Update(t.Context(), func(tx account.Tx) error {
		sess, k = writeThree(t, tx, "rolled-back")
		return errContract
	})
	if !errors.Is(err, errContract) {
		t.Errorf("Update = %v, want the callback's error", err)
	}
	if got := visible(t, s, "rolled-back", sess, k); got != [3]bool{} {
		t.Errorf("after a failed Update, user, session, key visible = %v, want none", got)
	}
}

func (c *contract) updatePanic(t *testing.T) {
	s := c.store(t)
	var sess *access.Session
	var k *access.Key
	recovered := func() (r any) {
		defer func() { r = recover() }()
		_ = s.Update(t.Context(), func(tx account.Tx) error {
			sess, k = writeThree(t, tx, "panicked")
			panic(errContract)
		})
		return nil
	}()
	if recovered != errContract {
		t.Errorf("Update re-panicked with %v, want the callback's panic value", recovered)
	}
	if got := visible(t, s, "panicked", sess, k); got != [3]bool{} {
		t.Errorf("after a panicking Update, user, session, key visible = %v, want none", got)
	}
}

func (c *contract) updateCommit(t *testing.T) {
	s := c.store(t)
	var sess *access.Session
	var k *access.Key
	if err := s.Update(t.Context(), func(tx account.Tx) error {
		sess, k = writeThree(t, tx, "committed")
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := visible(t, s, "committed", sess, k); got != [3]bool{true, true, true} {
		t.Errorf("after a committed Update, user, session, key visible = %v, want all", got)
	}
}

func (c *contract) updateReadsOwn(t *testing.T) {
	s := c.store(t)
	err := s.Update(t.Context(), func(tx account.Tx) error {
		ctx := t.Context()
		sess, k := writeThree(t, tx, "own")
		if _, found, err := tx.UserByUsername(ctx, "own"); err != nil || !found {
			t.Errorf("tx.UserByUsername of the callback's own user = (%t, %v)", found, err)
		}
		if _, found, err := tx.SessionByHash(ctx, sess.TokenHash); err != nil || !found {
			t.Errorf("tx.SessionByHash of the callback's own session = (%t, %v)", found, err)
		}
		if _, found, err := tx.APIKeyByHash(ctx, k.KeyHash); err != nil || !found {
			t.Errorf("tx.APIKeyByHash of the callback's own key = (%t, %v)", found, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func (c *contract) updateSerialisable(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	raceN(32, func(i int) {
		err := s.Update(ctx, func(tx account.Tx) error {
			n, err := tx.UserCount(ctx)
			if err != nil || n >= 1 {
				return err
			}
			return tx.CreateUser(ctx, newUser(fmt.Sprintf("only-%d", i)))
		})
		if err != nil {
			t.Errorf("Update: %v", err)
		}
	})
	if n, err := s.UserCount(ctx); err != nil || n != 1 {
		t.Errorf("32 read-count-then-create Updates left (%d users, %v), want exactly 1", n, err)
	}
}

func (c *contract) updateRerun(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	runs := 0
	if err := s.Update(ctx, func(tx account.Tx) error {
		runs++
		return tx.CreateUser(ctx, newUser(fmt.Sprintf("run-%d", runs)))
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if n := countIf(users, func(u *access.User) bool { return strings.HasPrefix(u.Username, "run-") }); n != 1 {
		t.Errorf("a callback run %d times left %d run rows, want exactly 1", runs, n)
	}
}

// held is a HoldPublish in force; its zero value holds nothing.
type held struct {
	pending func() int
	release func()
}

// holdPublish arms f's HoldPublish, or holds nothing when the medium has
// none (bbolt groups by delay).
func holdPublish(f DurabilityFaults) held {
	if f.HoldPublish == nil {
		return held{}
	}
	pending, release := f.HoldPublish()
	return held{pending: pending, release: release}
}

// await releases the hold once n callbacks are pending and no publish has
// happened since base; it reports false when that never happens in 5 s.
func (h held) await(f DurabilityFaults, base, n int) bool {
	if h.release == nil {
		return true
	}
	defer h.release()
	return waitFor(5*time.Second, func() bool { return f.Publishes() == base && h.pending() >= n })
}

func (c *contract) groupedCommit(t *testing.T) {
	const writers = 32
	s, f := c.faulty(t, "rule 5 (grouped commit)")
	ctx := t.Context()
	base := f.Publishes()
	h := holdPublish(f)
	done := make(chan struct{})
	go func() {
		defer close(done)
		raceN(writers, func(i int) {
			if err := s.Update(ctx, func(tx account.Tx) error {
				return tx.PutAuthFailure(ctx, account.FailureCount{FailureRef: failureRef(fmt.Sprintf("grouped-%d", i), access.MethodPassword, false), Count: 1})
			}); err != nil {
				t.Errorf("Update: %v", err)
			}
		})
	}()
	if !h.await(f, base, writers-1) {
		t.Errorf("the held publish never had %d pending callbacks and no publish within 5 s", writers-1)
	}
	<-done
	for i := range writers {
		if _, found, err := s.AuthFailure(ctx, failureRef(fmt.Sprintf("grouped-%d", i), access.MethodPassword, false)); err != nil || !found {
			t.Errorf("record %d after its Update = (%t, %v), want found", i, found, err)
		}
	}
	limit := 16
	if f.HoldPublish != nil {
		limit = 2
	}
	if n := f.Publishes() - base; n > limit {
		t.Errorf("%d concurrent Updates made %d publishes, want at most %d (grouped commits)", writers, n, limit)
	}
}

// durability: rule 10.
func (c *contract) durability(t *testing.T) {
	if c.cfg.NewFaulty == nil {
		t.Skip("rule 10: needs ContractConfig.NewFaulty")
	}
	for _, w := range []struct {
		write func(t *testing.T, s account.Store) (visible func() bool, err error)
		name  string
	}{
		{writeUpdateThree, "update"},
		{writeSingleSession, "create_session"},
		{writeFailureUpdate, "failure_update"},
	} {
		t.Run(w.name+"_before_publish", func(t *testing.T) {
			s, f := c.faulty(t, "rule 10")
			f.BeforePublish()
			isVisible, err := w.write(t, s)
			if err == nil {
				t.Error("a write failing before publish returned nil")
			}
			if isVisible() {
				t.Error("a write failing before publish is visible to reads")
			}
		})
		t.Run(w.name+"_after_publish", func(t *testing.T) {
			s, f := c.faulty(t, "rule 10")
			if f.AfterPublish == nil {
				t.Skip("rule 10: the medium reports durability with its commit (AfterPublish nil)")
			}
			f.AfterPublish()
			if _, err := w.write(t, s); err == nil {
				t.Error("a write whose durability failed after publish returned nil")
			}
		})
	}
}

// writeUpdateThree writes a user, a session and a token in one Update and
// returns a probe reporting whether any of them is visible.
func writeUpdateThree(t *testing.T, s account.Store) (func() bool, error) {
	ctx := t.Context()
	sess := newSession(0, epoch)
	tok := newToken(access.PurposeInvite, 0, epoch.Add(time.Hour))
	err := s.Update(ctx, func(tx account.Tx) error {
		u := newUser("durable")
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		sess.UserID = u.ID
		if err := tx.CreateSession(ctx, sess); err != nil {
			return err
		}
		return tx.CreateOneTimeToken(ctx, tok)
	})
	return func() bool {
		_, tokFound, _ := s.OneTimeTokenByHash(ctx, tok.Hash)
		_, sessFound := sessionFound(t, s, sess.TokenHash)
		return userFound(t, s, "durable") || sessFound || tokFound
	}, err
}

func writeSingleSession(t *testing.T, s account.Store) (func() bool, error) {
	sess := newSession(1, epoch)
	err := s.CreateSession(t.Context(), sess)
	return func() bool { _, found := sessionFound(t, s, sess.TokenHash); return found }, err
}

func writeFailureUpdate(t *testing.T, s account.Store) (func() bool, error) {
	ctx := t.Context()
	ref := account.FailureRef{Name: "durable", Method: access.MethodPassword}
	err := s.Update(ctx, func(tx account.Tx) error {
		return tx.PutAuthFailure(ctx, account.FailureCount{FailureRef: ref, Count: 1})
	})
	return func() bool { _, found, _ := s.AuthFailure(ctx, ref); return found }, err
}

// readsNeverWait: rule 16.
func (c *contract) readsNeverWait(t *testing.T) {
	t.Run("update", c.readsDuringUpdate)
	t.Run("direct_write", c.readsDuringDirectWrite)
}

func seedReader(t *testing.T, s account.Store) *access.User {
	t.Helper()
	u := mustUser(t, s, "reader")
	sized := newSession(u.ID, epoch)
	mustSession(t, s, sized)
	if err := s.DeleteSession(t.Context(), refOf(sized)); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	return u
}

func (c *contract) readsDuringUpdate(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	u := seedReader(t, s)
	pendingSess := newSession(u.ID, epoch)
	written, release, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		result <- s.Update(ctx, func(tx account.Tx) error {
			if err := tx.CreateSession(ctx, pendingSess); err != nil {
				return err
			}
			close(written)
			<-release
			return nil
		})
	}()
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	if !waitFor(5*time.Second, func() bool {
		select {
		case <-written:
			return true
		default:
			return false
		}
	}) {
		t.Fatal("the Update callback never wrote its session")
	}
	readsBeforeWrite(t, s, u.Username, pendingSess, "an in-progress Update")
	close(release)
	released = true
	if err := <-result; err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, found := sessionFound(t, s, pendingSess.TokenHash); !found {
		t.Error("after the Update committed, its session is not found")
	}
}

func (c *contract) readsDuringDirectWrite(t *testing.T) {
	s, f := c.faulty(t, "rule 16")
	if f.HoldPublish == nil {
		t.Skip("rule 16: needs DurabilityFaults.HoldPublish")
	}
	u := seedReader(t, s)
	pendingSess := newSession(u.ID, epoch)
	pending, release := f.HoldPublish()
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	result := make(chan error, 1)
	go func() { result <- s.CreateSession(t.Context(), pendingSess) }()
	if !waitFor(5*time.Second, func() bool { return pending() > 0 }) {
		t.Fatal("the direct CreateSession never reached the held publish")
	}
	readsBeforeWrite(t, s, u.Username, pendingSess, "a held CreateSession publish")
	release()
	released = true
	if err := <-result; err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, found := sessionFound(t, s, pendingSess.TokenHash); !found {
		t.Error("after the CreateSession published, its session is not found")
	}
}

// readsBeforeWrite requires each read to return, within 1 s, the state
// before the pending session's write, which during names.
func readsBeforeWrite(t *testing.T, s account.Store, username string, pending *access.Session, during string) {
	t.Helper()
	ctx := t.Context()
	reads := map[string]func() error{
		opSessionByHash: func() error {
			if _, found, err := s.SessionByHash(ctx, pending.TokenHash); err != nil || found {
				return fmt.Errorf("= (%t, %v), want the state before the write (false, nil)", found, err)
			}
			return nil
		},
		opUserByUsername: func() error {
			if _, found, err := s.UserByUsername(ctx, username); err != nil || !found {
				return fmt.Errorf("= (%t, %v), want (true, nil)", found, err)
			}
			return nil
		},
		"UserCount": func() error {
			if n, err := s.UserCount(ctx); err != nil || n != 1 {
				return fmt.Errorf("= (%d, %v), want (1, nil)", n, err)
			}
			return nil
		},
	}
	for name, read := range reads {
		var err error
		if !within(time.Second, func() { err = read() }) {
			t.Errorf("%s waited over 1 s on %s", name, during)
			continue
		}
		if err != nil {
			t.Errorf("%s during %s %v", name, during, err)
		}
	}
}
