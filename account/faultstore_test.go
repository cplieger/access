package account_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// errFault is the error a faultStore injects.
var errFault = errors.New("faultstore: injected fault")

// faultStore wraps a MemStore for the tests that need a store to fail,
// hold, record or group its writes, or keep times at the millisecond. Every
// option is off until set, and the setters may be called while operations
// run.
type faultStore struct {
	mem *accesstest.MemStore
	// faultTx serves the single calls outside Update, with update 0.
	faultTx
	beforeUpdate func(ctx context.Context, n int) // runs as an Update starts
	open         *batch                           // the grouped commit still collecting
	calls        []storeCall
	commits      []commitRecord
	descoped     map[int64][]string // scopes removed per key, from their Update's commit on
	mu           sync.Mutex
	omu          sync.RWMutex // guards descoped
	gmu          sync.Mutex   // guards open
	readDelay    atomic.Int64 // nanoseconds every single-call read sleeps
	publishDelay atomic.Int64 // nanoseconds every publish, or a grouping window, takes
	groupSize    atomic.Int64 // a grouped commit runs once this many Updates joined; 0: after the window
	updates      atomic.Int64
	writes       atomic.Int64           // writes inside Updates since the last arm
	seq          atomic.Int64           // orders commits and a test's own marks
	failAt       atomic.Int64           // the write, counted from the arm, that fails; 0 off
	panicAt      atomic.Int64           // likewise, panicking instead
	published    atomic.Int64           // durable commits; a grouped one counts once
	updateNanos  atomic.Int64           // wall time spent inside Update calls
	failNamed    atomic.Pointer[string] // the next write of this name inside an Update fails
	refuseNamed  atomic.Pointer[namedRefusal]
	failApplied  atomic.Bool // the next Update publishes, then returns errFault
	honourCtx    atomic.Bool // an Update whose ctx has ended returns its error
	grouping     atomic.Bool
	msTimes      atomic.Bool // PutAuthFailure keeps LockedAt to the millisecond, as rule 11 allows
}

var _ account.Store = (*faultStore)(nil)

// storeCall is one recorded store call. update is the ordinal of the
// Update it ran in, 0 for a single call; arg is the name a failure-record
// or username call carries.
type storeCall struct {
	ctx    context.Context
	name   string
	arg    string
	update int
}

// commitRecord is one Update's published commit, at seq.
type commitRecord struct {
	ctx context.Context
	seq int64
}

func newFaultStore() *faultStore {
	s := &faultStore{mem: accesstest.NewMemStore()}
	s.faultTx = faultTx{inner: s.mem, s: s}
	return s
}

// failWrite makes the nth write inside an Update, counted from now, return
// errFault; 0 disarms it.
func (s *faultStore) failWrite(n int) {
	s.writes.Store(0)
	s.failAt.Store(int64(n))
}

// failCall makes the next write named name inside an Update return
// errFault.
func (s *faultStore) failCall(name string) { s.failNamed.Store(&name) }

// namedRefusal is the error the next write of name returns.
type namedRefusal struct {
	err  error
	name string
}

// refuseCall makes the next write named name, inside an Update or a single
// call, return err.
func (s *faultStore) refuseCall(name string, err error) {
	s.refuseNamed.Store(&namedRefusal{name: name, err: err})
}

// panicWrite makes the nth write inside an Update, counted from now, panic.
func (s *faultStore) panicWrite(n int) {
	s.writes.Store(0)
	s.panicAt.Store(int64(n))
}

// failAfterApply makes the next Update publish its writes and then return
// errFault (rule 10).
func (s *faultStore) failAfterApply() { s.failApplied.Store(true) }

// group makes concurrent Updates share one commit, collected for delay.
func (s *faultStore) group(delay time.Duration) {
	s.publishDelay.Store(int64(delay))
	s.grouping.Store(true)
}

// groupOf makes concurrent Updates share one commit, run once n of them
// have joined it, whatever the scheduler does meanwhile.
func (s *faultStore) groupOf(n int) {
	s.groupSize.Store(int64(n))
	s.grouping.Store(true)
}

func (s *faultStore) delayReads(d time.Duration) { s.readDelay.Store(int64(d)) }

// millisecondTimes makes the store keep FailureCount.LockedAt truncated to
// the millisecond, the least precision StoreContract allows.
func (s *faultStore) millisecondTimes() { s.msTimes.Store(true) }

// onUpdate sets the hook every Update runs as it starts, with its ordinal.
func (s *faultStore) onUpdate(f func(ctx context.Context, n int)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beforeUpdate = f
}

// holdUpdate holds the next Update to start until release; entered is
// closed once it is held.
func (s *faultStore) holdUpdate() (entered <-chan struct{}, release func()) {
	in, out := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.onUpdate(func(context.Context, int) {
		held := false
		once.Do(func() { held = true })
		if held {
			s.onUpdate(nil)
			close(in)
			<-out
		}
	})
	var rel sync.Once
	return in, func() { rel.Do(func() { close(out) }) }
}

// mark is the next sequence number, shared with the commit records.
func (s *faultStore) mark() int64 { return s.seq.Add(1) }

func (s *faultStore) recorded() []storeCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

func (s *faultStore) committed() []commitRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.commits)
}

// resetRecord drops the recorded calls and commits.
func (s *faultStore) resetRecord() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls, s.commits = nil, nil
}

func (s *faultStore) record(ctx context.Context, update int, name, arg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, storeCall{ctx: ctx, name: name, arg: arg, update: update})
}

func (s *faultStore) read(ctx context.Context, update int, name, arg string) {
	s.record(ctx, update, name, arg)
	if d := time.Duration(s.readDelay.Load()); update == 0 && d > 0 {
		time.Sleep(d) // the sleeping-single-call store: a check outside Update loses its race
	}
}

func (s *faultStore) write(ctx context.Context, update int, name, arg string) error {
	s.record(ctx, update, name, arg)
	if r := s.refuseNamed.Load(); r != nil && r.name == name && s.refuseNamed.CompareAndSwap(r, nil) {
		return r.err
	}
	if update == 0 {
		return nil
	}
	if named := s.failNamed.Load(); named != nil && *named == name && s.failNamed.CompareAndSwap(named, nil) {
		return errFault
	}
	n := s.writes.Add(1)
	if s.panicAt.Load() == n {
		panic(errFault)
	}
	if s.failAt.Load() == n {
		return errFault
	}
	return nil
}

// commit records that ctx's Update is in a published commit.
func (s *faultStore) commit(ctx context.Context) {
	seq := s.mark()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commits = append(s.commits, commitRecord{ctx: ctx, seq: seq})
}

// Update records itself, runs the start hook, and then runs fn on the
// MemStore, alone or in a grouped commit.
func (s *faultStore) Update(ctx context.Context, fn func(account.Tx) error) error {
	start := time.Now()
	defer func() { s.updateNanos.Add(int64(time.Since(start))) }()
	n := int(s.updates.Add(1))
	s.record(ctx, n, "Update", "")
	s.mu.Lock()
	hook := s.beforeUpdate
	s.mu.Unlock()
	if hook != nil {
		hook(ctx, n)
	}
	if s.honourCtx.Load() && ctx.Err() != nil {
		return ctx.Err()
	}
	if s.grouping.Load() {
		return s.grouped(ctx, n, fn)
	}
	err := s.mem.Update(ctx, func(tx account.Tx) error { return s.run(fn, tx, n) })
	if err != nil {
		return err
	}
	s.published.Add(1)
	s.commit(ctx)
	if d := time.Duration(s.publishDelay.Load()); d > 0 {
		time.Sleep(d) // a durable medium's publish
	}
	if s.failApplied.Swap(false) {
		return errFault
	}
	return nil
}

// batch is one grouped commit: the calls that joined it before it ran.
type batch struct {
	done  chan struct{}
	full  chan struct{} // closed once groupSize calls joined
	calls []*groupedCall
}

type groupedCall struct {
	ctx context.Context
	fn  func(account.Tx) error
	err error
	n   int
}

// grouped joins the open batch, or opens one and, once groupSize calls
// joined or else after the publish delay, runs it as bbolt's db.Batch does:
// every fn in one Update, and a fn that fails is taken out, run alone with
// its own answer, and the rest retried.
func (s *faultStore) grouped(ctx context.Context, n int, fn func(account.Tx) error) error {
	c := &groupedCall{ctx: ctx, fn: fn, n: n}
	size := int(s.groupSize.Load())
	s.gmu.Lock()
	b := s.open
	leader := b == nil
	if leader {
		b = &batch{done: make(chan struct{}), full: make(chan struct{})}
		s.open = b
	}
	b.calls = append(b.calls, c)
	if size > 0 && len(b.calls) == size {
		s.open = nil
		close(b.full)
	}
	s.gmu.Unlock()
	if !leader {
		<-b.done
		return c.err
	}
	if size > 0 {
		<-b.full
	} else {
		time.Sleep(time.Duration(s.publishDelay.Load())) // the batch window
		s.gmu.Lock()
		s.open = nil
		s.gmu.Unlock()
	}
	s.runBatch(b.calls)
	close(b.done)
	return c.err
}

func (s *faultStore) runBatch(calls []*groupedCall) {
	for len(calls) > 0 {
		failed := -1
		err := s.mem.Update(calls[0].ctx, func(tx account.Tx) error {
			var pending []descoping
			for i, c := range calls {
				ft := &faultTx{inner: tx, s: s, update: c.n}
				if err := c.fn(ft); err != nil {
					failed = i
					return err
				}
				pending = append(pending, ft.descopes...)
			}
			s.applyDescopes(pending)
			return nil
		})
		if err == nil {
			s.published.Add(1)
			for _, c := range calls {
				s.commit(c.ctx)
			}
			return
		}
		c := calls[failed]
		c.err = s.mem.Update(c.ctx, func(tx account.Tx) error { return s.run(c.fn, tx, c.n) })
		if c.err == nil {
			s.published.Add(1)
			s.commit(c.ctx)
		}
		calls = slices.Delete(slices.Clone(calls), failed, failed+1)
	}
}

// run is one Update callback on the MemStore's tx: fn, then the de-scopes
// fn made, applied while the MemStore still holds its writer lock, so the
// next Update reads them and a failed fn applies none.
func (s *faultStore) run(fn func(account.Tx) error, tx account.Tx, n int) error {
	ft := &faultTx{inner: tx, s: s, update: n}
	if err := fn(ft); err != nil {
		return err
	}
	s.applyDescopes(ft.descopes)
	return nil
}

// descoping is one scope removal a descope Update makes.
type descoping struct {
	scope string
	keyID int64
}

// descope removes scope from key keyID in its own Update, the stand-in for
// a scope removal the SPI has no write for: from that Update's commit on,
// every key the wrapper returns, inside or outside an Update, lacks it. The
// MemStore row keeps the scope. A failing write fault fails the Update and
// removes nothing.
func (s *faultStore) descope(ctx context.Context, keyID int64, scope string) error {
	return s.Update(ctx, func(tx account.Tx) error {
		ft, ok := tx.(*faultTx)
		if !ok {
			return errors.New("faultstore: descope outside the wrapper")
		}
		if err := s.write(ctx, ft.update, "Descope", ""); err != nil {
			return err
		}
		ft.descopes = append(ft.descopes, descoping{keyID: keyID, scope: scope})
		return nil
	})
}

func (s *faultStore) applyDescopes(ds []descoping) {
	if len(ds) == 0 {
		return
	}
	s.omu.Lock()
	defer s.omu.Unlock()
	if s.descoped == nil {
		s.descoped = map[int64][]string{}
	}
	for _, d := range ds {
		s.descoped[d.keyID] = append(s.descoped[d.keyID], d.scope)
	}
}

// scrub removes the de-scoped scopes from keys in place.
func (s *faultStore) scrub(keys ...*access.Key) {
	s.omu.RLock()
	defer s.omu.RUnlock()
	for _, k := range keys {
		if gone := s.descoped[k.ID]; len(gone) > 0 {
			k.Scopes = slices.DeleteFunc(slices.Clone(k.Scopes), func(sc string) bool { return slices.Contains(gone, sc) })
		}
	}
}

func (s *faultStore) CleanupExpiredSessions(ctx context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	s.record(ctx, 0, "CleanupExpiredSessions", "")
	return s.mem.CleanupExpiredSessions(ctx, now, timeouts, limit)
}

func (s *faultStore) CleanupExpiredOneTimeTokens(ctx context.Context, now time.Time) (int64, error) {
	s.record(ctx, 0, "CleanupExpiredOneTimeTokens", "")
	return s.mem.CleanupExpiredOneTimeTokens(ctx, now)
}

// faultTx records every call and applies the store's write faults inside
// an Update; inner is the Update's Tx, or the MemStore for a single call.
type faultTx struct {
	inner    account.Tx
	descopes []descoping // made by this Update's run, applied at its commit
	s        *faultStore
	update   int
}

func (t *faultTx) UserByID(ctx context.Context, id int64) (*access.User, bool, error) {
	t.s.read(ctx, t.update, "UserByID", "")
	return t.inner.UserByID(ctx, id)
}

func (t *faultTx) CreateUser(ctx context.Context, user *access.User) error {
	if err := t.s.write(ctx, t.update, "CreateUser", ""); err != nil {
		return err
	}
	return t.inner.CreateUser(ctx, user)
}

func (t *faultTx) CreateInitialUser(ctx context.Context, user *access.User) error {
	if err := t.s.write(ctx, t.update, "CreateInitialUser", ""); err != nil {
		return err
	}
	return t.inner.CreateInitialUser(ctx, user)
}

func (t *faultTx) UserByUsername(ctx context.Context, canonical string) (*access.User, bool, error) {
	t.s.read(ctx, t.update, "UserByUsername", canonical)
	return t.inner.UserByUsername(ctx, canonical)
}

func (t *faultTx) UserByOIDC(ctx context.Context, id access.OIDCIdentity) (*access.User, bool, error) {
	t.s.read(ctx, t.update, "UserByOIDC", "")
	return t.inner.UserByOIDC(ctx, id)
}

func (t *faultTx) UserByWebAuthnHandle(ctx context.Context, handle []byte) (*access.User, bool, error) {
	t.s.read(ctx, t.update, "UserByWebAuthnHandle", "")
	return t.inner.UserByWebAuthnHandle(ctx, handle)
}

func (t *faultTx) ListUsers(ctx context.Context) ([]access.User, error) {
	t.s.read(ctx, t.update, "ListUsers", "")
	return t.inner.ListUsers(ctx)
}

func (t *faultTx) UpdateUser(ctx context.Context, user *access.User) error {
	if err := t.s.write(ctx, t.update, "UpdateUser", ""); err != nil {
		return err
	}
	return t.inner.UpdateUser(ctx, user)
}

func (t *faultTx) DeleteUser(ctx context.Context, id int64) error {
	if err := t.s.write(ctx, t.update, "DeleteUser", ""); err != nil {
		return err
	}
	return t.inner.DeleteUser(ctx, id)
}

func (t *faultTx) UserCount(ctx context.Context) (int, error) {
	t.s.read(ctx, t.update, "UserCount", "")
	return t.inner.UserCount(ctx)
}

func (t *faultTx) CreateSession(ctx context.Context, sess *access.Session) error {
	if err := t.s.write(ctx, t.update, "CreateSession", ""); err != nil {
		return err
	}
	return t.inner.CreateSession(ctx, sess)
}

func (t *faultTx) SessionByHash(ctx context.Context, tokenHash access.Hash) (*access.Session, bool, error) {
	t.s.read(ctx, t.update, "SessionByHash", "")
	return t.inner.SessionByHash(ctx, tokenHash)
}

func (t *faultTx) SessionsByUserID(ctx context.Context, userID int64) ([]access.Session, error) {
	t.s.read(ctx, t.update, "SessionsByUserID", "")
	return t.inner.SessionsByUserID(ctx, userID)
}

func (t *faultTx) UpdateSessionActivity(ctx context.Context, tokenHash access.Hash, act access.SessionActivity) error {
	if err := t.s.write(ctx, t.update, "UpdateSessionActivity", ""); err != nil {
		return err
	}
	return t.inner.UpdateSessionActivity(ctx, tokenHash, act)
}

func (t *faultTx) RotateSession(ctx context.Context, rot account.Rotation) error {
	if err := t.s.write(ctx, t.update, "RotateSession", ""); err != nil {
		return err
	}
	return t.inner.RotateSession(ctx, rot)
}

func (t *faultTx) UpdateSessionLabel(ctx context.Context, ref access.SessionRef, label string) error {
	if err := t.s.write(ctx, t.update, "UpdateSessionLabel", ""); err != nil {
		return err
	}
	return t.inner.UpdateSessionLabel(ctx, ref, label)
}

func (t *faultTx) DeleteSession(ctx context.Context, ref access.SessionRef) error {
	if err := t.s.write(ctx, t.update, "DeleteSession", ""); err != nil {
		return err
	}
	return t.inner.DeleteSession(ctx, ref)
}

func (t *faultTx) DeleteSessionByHash(ctx context.Context, tokenHash access.Hash) error {
	if err := t.s.write(ctx, t.update, "DeleteSessionByHash", ""); err != nil {
		return err
	}
	return t.inner.DeleteSessionByHash(ctx, tokenHash)
}

func (t *faultTx) DeleteUserSessions(ctx context.Context, userID int64, exceptID string) ([]string, error) {
	if err := t.s.write(ctx, t.update, "DeleteUserSessions", ""); err != nil {
		return nil, err
	}
	return t.inner.DeleteUserSessions(ctx, userID, exceptID)
}

func (t *faultTx) CreatePasskey(ctx context.Context, cred *access.PasskeyCredential) error {
	if err := t.s.write(ctx, t.update, "CreatePasskey", ""); err != nil {
		return err
	}
	return t.inner.CreatePasskey(ctx, cred)
}

func (t *faultTx) PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error) {
	t.s.read(ctx, t.update, "PasskeysByUserID", "")
	return t.inner.PasskeysByUserID(ctx, userID)
}

func (t *faultTx) UpdatePasskeyAfterLogin(ctx context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error {
	if err := t.s.write(ctx, t.update, "UpdatePasskeyAfterLogin", ""); err != nil {
		return err
	}
	return t.inner.UpdatePasskeyAfterLogin(ctx, userID, credID, upd)
}

func (t *faultTx) RenamePasskey(ctx context.Context, ref access.PasskeyRef, name string) error {
	if err := t.s.write(ctx, t.update, "RenamePasskey", ""); err != nil {
		return err
	}
	return t.inner.RenamePasskey(ctx, ref, name)
}

func (t *faultTx) DeletePasskey(ctx context.Context, ref access.PasskeyRef) error {
	if err := t.s.write(ctx, t.update, "DeletePasskey", ""); err != nil {
		return err
	}
	return t.inner.DeletePasskey(ctx, ref)
}

func (t *faultTx) DeleteUserPasskeys(ctx context.Context, userID int64) ([]int64, error) {
	if err := t.s.write(ctx, t.update, "DeleteUserPasskeys", ""); err != nil {
		return nil, err
	}
	return t.inner.DeleteUserPasskeys(ctx, userID)
}

func (t *faultTx) CreateAPIKey(ctx context.Context, key *access.Key) error {
	if err := t.s.write(ctx, t.update, "CreateAPIKey", ""); err != nil {
		return err
	}
	return t.inner.CreateAPIKey(ctx, key)
}

func (t *faultTx) APIKeyByHash(ctx context.Context, hash access.Hash) (*access.Key, bool, error) {
	t.s.read(ctx, t.update, "APIKeyByHash", "")
	k, found, err := t.inner.APIKeyByHash(ctx, hash)
	if found {
		t.s.scrub(k)
	}
	return k, found, err
}

func (t *faultTx) ListAPIKeysByUserID(ctx context.Context, userID int64) ([]access.Key, error) {
	t.s.read(ctx, t.update, "ListAPIKeysByUserID", "")
	return t.scrubbed(t.inner.ListAPIKeysByUserID(ctx, userID))
}

func (t *faultTx) ListAPIKeys(ctx context.Context) ([]access.Key, error) {
	t.s.read(ctx, t.update, "ListAPIKeys", "")
	return t.scrubbed(t.inner.ListAPIKeys(ctx))
}

func (t *faultTx) scrubbed(keys []access.Key, err error) ([]access.Key, error) {
	for i := range keys {
		t.s.scrub(&keys[i])
	}
	return keys, err
}

func (t *faultTx) DeleteAPIKey(ctx context.Context, ref access.KeyRef) error {
	if err := t.s.write(ctx, t.update, "DeleteAPIKey", ""); err != nil {
		return err
	}
	return t.inner.DeleteAPIKey(ctx, ref)
}

func (t *faultTx) DeleteUserAPIKeys(ctx context.Context, userID int64) ([]int64, error) {
	if err := t.s.write(ctx, t.update, "DeleteUserAPIKeys", ""); err != nil {
		return nil, err
	}
	return t.inner.DeleteUserAPIKeys(ctx, userID)
}

func (t *faultTx) TouchAPIKey(ctx context.Context, keyID int64, at time.Time) error {
	if err := t.s.write(ctx, t.update, "TouchAPIKey", ""); err != nil {
		return err
	}
	return t.inner.TouchAPIKey(ctx, keyID, at)
}

func (t *faultTx) CreateOneTimeToken(ctx context.Context, tok access.OneTimeToken) error {
	if err := t.s.write(ctx, t.update, "CreateOneTimeToken", ""); err != nil {
		return err
	}
	return t.inner.CreateOneTimeToken(ctx, tok)
}

func (t *faultTx) OneTimeTokenByHash(ctx context.Context, hash access.Hash) (access.OneTimeToken, bool, error) {
	t.s.read(ctx, t.update, "OneTimeTokenByHash", "")
	return t.inner.OneTimeTokenByHash(ctx, hash)
}

func (t *faultTx) ConsumeOneTimeToken(ctx context.Context, hash access.Hash, now time.Time) (access.OneTimeToken, bool, error) {
	if err := t.s.write(ctx, t.update, "ConsumeOneTimeToken", ""); err != nil {
		return access.OneTimeToken{}, false, err
	}
	return t.inner.ConsumeOneTimeToken(ctx, hash, now)
}

func (t *faultTx) DeleteOneTimeTokens(ctx context.Context, purpose access.TokenPurpose, subject int64) (int, error) {
	if err := t.s.write(ctx, t.update, "DeleteOneTimeTokens", ""); err != nil {
		return 0, err
	}
	return t.inner.DeleteOneTimeTokens(ctx, purpose, subject)
}

func (t *faultTx) LiveOneTimeTokens(ctx context.Context, purposes []access.TokenPurpose, now time.Time) ([]access.OneTimeToken, error) {
	t.s.read(ctx, t.update, "LiveOneTimeTokens", "")
	return t.inner.LiveOneTimeTokens(ctx, purposes, now)
}

func (t *faultTx) DeleteOneTimeTokensIssuedBy(ctx context.Context, keyIDs []int64) (int, error) {
	if err := t.s.write(ctx, t.update, "DeleteOneTimeTokensIssuedBy", ""); err != nil {
		return 0, err
	}
	return t.inner.DeleteOneTimeTokensIssuedBy(ctx, keyIDs)
}

func (t *faultTx) CreateKeyAttribution(ctx context.Context, a *access.KeyAttribution) error {
	if err := t.s.write(ctx, t.update, "CreateKeyAttribution", ""); err != nil {
		return err
	}
	return t.inner.CreateKeyAttribution(ctx, a)
}

func (t *faultTx) ListKeyAttributions(ctx context.Context) ([]access.KeyAttribution, error) {
	t.s.read(ctx, t.update, "ListKeyAttributions", "")
	return t.inner.ListKeyAttributions(ctx)
}

func (t *faultTx) AuthFailure(ctx context.Context, ref account.FailureRef) (account.FailureCount, bool, error) {
	t.s.read(ctx, t.update, "AuthFailure", ref.Name)
	return t.inner.AuthFailure(ctx, ref)
}

func (t *faultTx) PutAuthFailure(ctx context.Context, f account.FailureCount) error {
	if err := t.s.write(ctx, t.update, "PutAuthFailure", f.Name); err != nil {
		return err
	}
	if t.s.msTimes.Load() {
		f.LockedAt = f.LockedAt.Truncate(time.Millisecond)
	}
	return t.inner.PutAuthFailure(ctx, f)
}

func (t *faultTx) UnreportedLocks(ctx context.Context) ([]account.FailureCount, error) {
	t.s.read(ctx, t.update, "UnreportedLocks", "")
	return t.inner.UnreportedLocks(ctx)
}

func (t *faultTx) DeleteAuthFailures(ctx context.Context, name string, methods []access.Method) error {
	if err := t.s.write(ctx, t.update, "DeleteAuthFailures", name); err != nil {
		return err
	}
	return t.inner.DeleteAuthFailures(ctx, name, methods)
}

func (t *faultTx) PruneAuthFailures(ctx context.Context, keep []string) (int64, error) {
	if err := t.s.write(ctx, t.update, "PruneAuthFailures", ""); err != nil {
		return 0, err
	}
	return t.inner.PruneAuthFailures(ctx, keep)
}

func TestFaultStore(t *testing.T) {
	t.Parallel()
	put := func(name string) func(account.Tx) error {
		return func(tx account.Tx) error {
			return tx.PutAuthFailure(t.Context(), account.FailureCount{Name: name, Method: access.MethodPassword, Count: 1})
		}
	}
	stored := func(s *faultStore, name string) bool {
		_, found, err := s.mem.AuthFailure(t.Context(), account.FailureRef{Name: name, Method: access.MethodPassword})
		if err != nil {
			t.Fatalf("AuthFailure: %v", err)
		}
		return found
	}
	t.Run("fail_write", func(t *testing.T) {
		t.Parallel()
		s := newFaultStore()
		s.failWrite(2)
		err := s.Update(t.Context(), func(tx account.Tx) error {
			if err := put("a")(tx); err != nil {
				return err
			}
			return put("b")(tx)
		})
		if !errors.Is(err, errFault) || stored(s, "a") {
			t.Errorf("Update failing its second write = %v, a stored %t; want errFault and nothing stored", err, stored(s, "a"))
		}
	})
	t.Run("fail_after_apply", func(t *testing.T) {
		t.Parallel()
		s := newFaultStore()
		s.failAfterApply()
		if err := s.Update(t.Context(), put("a")); !errors.Is(err, errFault) || !stored(s, "a") {
			t.Errorf("Update = %v, a stored %t; want errFault with the write published", err, stored(s, "a"))
		}
		if err := s.Update(t.Context(), put("b")); err != nil {
			t.Errorf("the next Update = %v, want nil", err)
		}
	})
	t.Run("panic_write", func(t *testing.T) {
		t.Parallel()
		s := newFaultStore()
		s.panicWrite(1)
		func() {
			defer func() {
				if r := recover(); r != errFault {
					t.Errorf("recovered %v, want errFault re-raised", r)
				}
			}()
			_ = s.Update(t.Context(), put("a"))
		}()
		if stored(s, "a") {
			t.Error("a panicking Update published its write")
		}
	})
	t.Run("hold", func(t *testing.T) {
		t.Parallel()
		s := newFaultStore()
		entered, release := s.holdUpdate()
		done := make(chan error)
		go func() { done <- s.Update(t.Context(), put("a")) }()
		<-entered
		if stored(s, "a") {
			t.Error("a held Update ran before its release")
		}
		release()
		if err := <-done; err != nil || !stored(s, "a") {
			t.Errorf("released Update = %v, a stored %t", err, stored(s, "a"))
		}
		if err := s.Update(t.Context(), put("b")); err != nil || !stored(s, "b") {
			t.Errorf("the next Update was held too: %v", err)
		}
	})
	t.Run("grouped", func(t *testing.T) {
		t.Parallel()
		s := newFaultStore()
		s.groupOf(3)
		errs := make([]error, 3)
		var wg sync.WaitGroup
		for i, fn := range []func(account.Tx) error{put("a"), func(account.Tx) error { return errFault }, put("c")} {
			wg.Go(func() { errs[i] = s.Update(t.Context(), fn) })
		}
		wg.Wait()
		if errs[0] != nil || !errors.Is(errs[1], errFault) || errs[2] != nil || !stored(s, "a") || !stored(s, "c") {
			t.Errorf("grouped answers = %v, a %t, c %t; want the failing call alone refused", errs, stored(s, "a"), stored(s, "c"))
		}
		if n := s.published.Load(); n != 1 {
			t.Errorf("published %d commits for 3 concurrent Updates, one failing; want 1", n)
		}
	})
	t.Run("grouped_window", func(t *testing.T) {
		t.Parallel()
		s := newFaultStore()
		s.group(time.Millisecond)
		if err := s.Update(t.Context(), put("a")); err != nil || !stored(s, "a") || s.published.Load() != 1 {
			t.Errorf("a lone grouped Update = %v, a stored %t, %d commits; want one commit after the window", err, stored(s, "a"), s.published.Load())
		}
	})
	t.Run("read_delay", func(t *testing.T) {
		t.Parallel()
		s := newFaultStore()
		const delay = 20 * time.Millisecond
		s.delayReads(delay)
		start := time.Now()
		if _, err := s.UserCount(t.Context()); err != nil {
			t.Fatalf("UserCount: %v", err)
		}
		if d := time.Since(start); d < delay {
			t.Errorf("a single-call read took %s, want at least %s", d, delay)
		}
	})
	t.Run("millisecond_times", func(t *testing.T) {
		t.Parallel()
		s := newFaultStore()
		s.millisecondTimes()
		at := time.Date(2026, 1, 2, 3, 4, 5, 6_789_012, time.UTC)
		if err := s.Update(t.Context(), func(tx account.Tx) error {
			return tx.PutAuthFailure(t.Context(), account.FailureCount{Name: "a", Method: access.MethodPassword, Locked: true, LockedAt: at})
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		rec, _, err := s.mem.AuthFailure(t.Context(), account.FailureRef{Name: "a", Method: access.MethodPassword})
		if want := at.Truncate(time.Millisecond); err != nil || !rec.LockedAt.Equal(want) {
			t.Errorf("stored LockedAt = %v, %v; want %v", rec.LockedAt, err, want)
		}
	})
}

func TestFaultStoreDescope(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) (*faultStore, access.Key) {
		s := newFaultStore()
		u := mustUser(t, s.mem, "alice", access.RoleAdmin)
		key := access.Key{UserID: u.ID, KeyHash: access.APIKeyHash("descope-key"), Scopes: []string{"read", "create_keys"}}
		if err := s.mem.CreateAPIKey(t.Context(), &key); err != nil {
			t.Fatalf("CreateAPIKey: %v", err)
		}
		return s, key
	}
	scopesIn := func(t *testing.T, tx account.Tx, key access.Key) [][]string {
		t.Helper()
		byUser, err := tx.ListAPIKeysByUserID(t.Context(), key.UserID)
		if err != nil {
			t.Fatalf("ListAPIKeysByUserID: %v", err)
		}
		all, err := tx.ListAPIKeys(t.Context())
		if err != nil {
			t.Fatalf("ListAPIKeys: %v", err)
		}
		byHash, found, err := tx.APIKeyByHash(t.Context(), key.KeyHash)
		if err != nil || !found {
			t.Fatalf("APIKeyByHash = %v, %v", found, err)
		}
		return [][]string{byUser[0].Scopes, all[0].Scopes, byHash.Scopes}
	}
	has := func(views [][]string, scope string) []bool {
		out := make([]bool, len(views))
		for i, v := range views {
			out[i] = slices.Contains(v, scope)
		}
		return out
	}
	t.Run("serialized_orders", func(t *testing.T) {
		t.Parallel()
		s, key := setup(t)
		read, release := make(chan []bool, 1), make(chan struct{})
		before := make(chan error, 1)
		go func() {
			before <- s.Update(t.Context(), func(tx account.Tx) error {
				read <- has(scopesIn(t, tx, key), "create_keys")
				<-release
				return nil
			})
		}()
		got := <-read
		done := make(chan error, 1)
		go func() { done <- s.descope(t.Context(), key.ID, "create_keys") }()
		close(release)
		if err := <-before; err != nil {
			t.Fatalf("the earlier Update = %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("descope = %v", err)
		}
		if !slices.Equal(got, []bool{true, true, true}) {
			t.Errorf("the Update serialized before the de-scope read the scope as %v, want it in every view", got)
		}
		var after []bool
		if err := s.Update(t.Context(), func(tx account.Tx) error {
			after = has(scopesIn(t, tx, key), "create_keys")
			return nil
		}); err != nil {
			t.Fatalf("Update = %v", err)
		}
		if !slices.Equal(after, []bool{false, false, false}) {
			t.Errorf("the Update serialized after the de-scope read the scope as %v, want it in no view", after)
		}
		if got := has(scopesIn(t, s, key), "read"); !slices.Equal(got, []bool{true, true, true}) {
			t.Errorf("the scope left in place reads as %v, want it in every view", got)
		}
	})
	t.Run("failed_descope_keeps_scope", func(t *testing.T) {
		t.Parallel()
		s, key := setup(t)
		s.failWrite(1)
		if err := s.descope(t.Context(), key.ID, "create_keys"); !errors.Is(err, errFault) {
			t.Fatalf("failing descope = %v, want errFault", err)
		}
		if got := has(scopesIn(t, s, key), "create_keys"); !slices.Equal(got, []bool{true, true, true}) {
			t.Errorf("after a failed de-scope the scope reads as %v, want it in every view", got)
		}
	})
	t.Run("single_calls_follow_commit", func(t *testing.T) {
		t.Parallel()
		s, key := setup(t)
		if got := has(scopesIn(t, s, key), "create_keys"); !slices.Equal(got, []bool{true, true, true}) {
			t.Fatalf("before the de-scope the single calls read %v, want the scope in every view", got)
		}
		if err := s.descope(t.Context(), key.ID, "create_keys"); err != nil {
			t.Fatalf("descope = %v", err)
		}
		if got := has(scopesIn(t, s, key), "create_keys"); !slices.Equal(got, []bool{false, false, false}) {
			t.Errorf("after the de-scope the single calls read %v, want the scope in no view", got)
		}
		if got := has(scopesIn(t, s.mem, key), "create_keys"); !slices.Equal(got, []bool{true, true, true}) {
			t.Errorf("the MemStore row reads %v, want the overlay to leave it unchanged", got)
		}
	})
}
