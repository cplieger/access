package accesstest

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

var (
	errBeforePublish = errors.New("accesstest: simulated medium failed before publish")
	errAfterPublish  = errors.New("accesstest: simulated medium published but could not confirm durability")
)

// medium is the simulated durable medium under faultStore. Its committed
// state survives a reopen, and every write reaches it through a grouped
// commit that, like bbolt's db.Batch, re-runs the group without a member
// whose callback failed (go.etcd.io/bbolt@v1.5.0/db.go:1054).
type medium struct {
	committed *state
	hold      chan struct{} // non-nil: the next commit waits for its close
	// take, confirm and reload are the red-check variants' seams; nil is
	// the correct medium: a commit takes every queued call, an
	// after-publish failure is reported, and a reopen reads what was
	// committed.
	take                  func(queued int) int
	confirm               func(err error) error
	reload                func(s *state) *state
	queue                 []*call
	publishes             int
	mu                    sync.Mutex
	failBefore, failAfter bool
}

// call is one write waiting for its commit.
type call struct {
	fn        func(tx *memTx) error
	err       error
	recovered any
	done      chan struct{}
	panicked  bool
}

// run runs c's callback on tx and reports whether it failed or panicked.
func (c *call) run(tx *memTx) (failed bool) {
	defer func() {
		if r := recover(); r != nil {
			c.recovered, c.panicked, failed = r, true, true
		}
	}()
	c.err = c.fn(tx)
	return c.err != nil
}

func newMedium() *medium {
	return &medium{committed: NewMemStore().snap.Load()}
}

func (m *medium) enqueue(c *call) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queue = append(m.queue, c)
}

func (m *medium) pending() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.queue)
}

// next waits out an armed hold, then dequeues the calls one commit serves.
func (m *medium) next() []*call {
	m.mu.Lock()
	hold := m.hold
	m.hold = nil
	m.mu.Unlock()
	if hold != nil {
		<-hold
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.queue)
	if m.take != nil {
		n = min(n, m.take(n))
	}
	batch := slices.Clone(m.queue[:n])
	m.queue = slices.Delete(m.queue, 0, n)
	return batch
}

// publish makes s durable unless a fault is armed; published reports
// whether s reached the medium.
func (m *medium) publish(s *state) (published bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failBefore {
		m.failBefore = false
		return false, errBeforePublish
	}
	m.committed = s
	m.publishes++
	if !m.failAfter {
		return true, nil
	}
	m.failAfter = false
	if m.confirm != nil {
		return true, m.confirm(errAfterPublish)
	}
	return true, errAfterPublish
}

func (m *medium) load() *state {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reload != nil {
		return m.reload(m.committed)
	}
	return m.committed
}

func (m *medium) faults() DurabilityFaults {
	set := func(flag *bool) func() {
		return func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			*flag = true
		}
	}
	return DurabilityFaults{
		BeforePublish: set(&m.failBefore),
		AfterPublish:  set(&m.failAfter),
		Publishes: func() int {
			m.mu.Lock()
			defer m.mu.Unlock()
			return m.publishes
		},
		HoldPublish: func() (func() int, func()) {
			ch := make(chan struct{})
			m.mu.Lock()
			m.hold = ch
			m.mu.Unlock()
			return m.pending, sync.OnceFunc(func() { close(ch) })
		},
	}
}

// faultStore is a MemStore whose every write goes through its medium. Reads
// load the in-memory snapshot without a lock; the MemStore's writer mutex
// serialises commits.
type faultStore struct {
	med *medium
	mem *MemStore
}

var _ account.Store = (*faultStore)(nil)

func openFaultStore(med *medium) *faultStore {
	f := &faultStore{med: med, mem: &MemStore{}}
	f.mem.snap.Store(med.load())
	return f
}

// commit queues fn and returns once a commit has served it, leading the
// commit itself when no other writer has.
func (f *faultStore) commit(fn func(tx *memTx) error) error {
	c := &call{fn: fn, done: make(chan struct{})}
	f.med.enqueue(c)
	f.mem.mu.Lock()
	for !isDone(c) {
		f.runGroup()
	}
	f.mem.mu.Unlock()
	if c.panicked {
		panic(c.recovered)
	}
	return c.err
}

func isDone(c *call) bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// runGroup serves one commit's calls on one private copy, dropping each
// call whose callback fails and re-running the rest, then publishes.
func (f *faultStore) runGroup() {
	batch := f.med.next()
	var tx *memTx
	for len(batch) > 0 {
		tx = &memTx{s: f.mem.snap.Load().clone()}
		failed := slices.IndexFunc(batch, func(c *call) bool { return c.run(tx) })
		if failed < 0 {
			break
		}
		close(batch[failed].done)
		batch = slices.Delete(batch, failed, failed+1)
	}
	if len(batch) == 0 {
		return
	}
	published, err := f.med.publish(tx.s)
	if published {
		f.mem.snap.Store(tx.s)
	}
	for _, c := range batch {
		c.err = err
		close(c.done)
	}
}

// reopen returns a store over f's medium, as a restart would.
func (f *faultStore) reopen() *faultStore { return openFaultStore(f.med) }

func (f *faultStore) view() *memTx { return f.mem.view() }

// Update implements [account.Store].
func (f *faultStore) Update(_ context.Context, fn func(tx account.Tx) error) error {
	return f.commit(func(tx *memTx) error { return fn(tx) })
}

func (f *faultStore) CleanupExpiredSessions(_ context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	switch {
	case limit < 1:
		return nil, errLimit
	case timeouts.Idle <= 0 || timeouts.Absolute <= 0:
		return nil, errTimeouts
	}
	var refs []access.SessionRef
	err := f.commit(func(tx *memTx) error {
		refs = tx.cleanup(now, timeouts, limit)
		return nil
	})
	return refs, err
}

func (f *faultStore) CleanupExpiredOneTimeTokens(_ context.Context, now time.Time) (int64, error) {
	var n int
	err := f.commit(func(tx *memTx) error {
		n = tx.deleteTokens(func(tok access.OneTimeToken) bool { return !tok.ExpiresAt.After(now) })
		return nil
	})
	return int64(n), err
}

func (f *faultStore) CreateUser(ctx context.Context, u *access.User) error {
	return f.commit(func(tx *memTx) error { return tx.CreateUser(ctx, u) })
}

func (f *faultStore) CreateInitialUser(ctx context.Context, u *access.User) error {
	return f.commit(func(tx *memTx) error { return tx.CreateInitialUser(ctx, u) })
}

func (f *faultStore) UserByID(ctx context.Context, id int64) (*access.User, bool, error) {
	return f.view().UserByID(ctx, id)
}

func (f *faultStore) UserByUsername(ctx context.Context, name string) (*access.User, bool, error) {
	return f.view().UserByUsername(ctx, name)
}

func (f *faultStore) UserByOIDC(ctx context.Context, id access.OIDCIdentity) (*access.User, bool, error) {
	return f.view().UserByOIDC(ctx, id)
}

func (f *faultStore) UserByWebAuthnHandle(ctx context.Context, h []byte) (*access.User, bool, error) {
	return f.view().UserByWebAuthnHandle(ctx, h)
}

func (f *faultStore) ListUsers(ctx context.Context) ([]access.User, error) {
	return f.view().ListUsers(ctx)
}

func (f *faultStore) UpdateUser(ctx context.Context, u *access.User) error {
	return f.commit(func(tx *memTx) error { return tx.UpdateUser(ctx, u) })
}

func (f *faultStore) DeleteUser(ctx context.Context, id int64) error {
	return f.commit(func(tx *memTx) error { return tx.DeleteUser(ctx, id) })
}

func (f *faultStore) UserCount(ctx context.Context) (int, error) { return f.view().UserCount(ctx) }

func (f *faultStore) CreateSession(ctx context.Context, sess *access.Session) error {
	return f.commit(func(tx *memTx) error { return tx.CreateSession(ctx, sess) })
}

func (f *faultStore) SessionByHash(ctx context.Context, h access.Hash) (*access.Session, bool, error) {
	return f.view().SessionByHash(ctx, h)
}

func (f *faultStore) SessionsByUserID(ctx context.Context, id int64) ([]access.Session, error) {
	return f.view().SessionsByUserID(ctx, id)
}

func (f *faultStore) UpdateSessionActivity(ctx context.Context, h access.Hash, act access.SessionActivity) error {
	return f.commit(func(tx *memTx) error { return tx.UpdateSessionActivity(ctx, h, act) })
}

func (f *faultStore) RotateSession(ctx context.Context, rot account.Rotation) error {
	return f.commit(func(tx *memTx) error { return tx.RotateSession(ctx, rot) })
}

func (f *faultStore) UpdateSessionLabel(ctx context.Context, ref access.SessionRef, label string) error {
	return f.commit(func(tx *memTx) error { return tx.UpdateSessionLabel(ctx, ref, label) })
}

func (f *faultStore) DeleteSession(ctx context.Context, ref access.SessionRef) error {
	return f.commit(func(tx *memTx) error { return tx.DeleteSession(ctx, ref) })
}

func (f *faultStore) DeleteSessionByHash(ctx context.Context, h access.Hash) error {
	return f.commit(func(tx *memTx) error { return tx.DeleteSessionByHash(ctx, h) })
}

func (f *faultStore) DeleteUserSessions(ctx context.Context, id int64, except string) ([]string, error) {
	var ids []string
	err := f.commit(func(tx *memTx) (err error) { ids, err = tx.DeleteUserSessions(ctx, id, except); return err })
	return ids, err
}

func (f *faultStore) CreatePasskey(ctx context.Context, p *access.PasskeyCredential) error {
	return f.commit(func(tx *memTx) error { return tx.CreatePasskey(ctx, p) })
}

func (f *faultStore) PasskeysByUserID(ctx context.Context, id int64) ([]access.PasskeyCredential, error) {
	return f.view().PasskeysByUserID(ctx, id)
}

func (f *faultStore) UpdatePasskeyAfterLogin(ctx context.Context, id int64, cred []byte, upd access.PasskeyLoginUpdate) error {
	return f.commit(func(tx *memTx) error { return tx.UpdatePasskeyAfterLogin(ctx, id, cred, upd) })
}

func (f *faultStore) RenamePasskey(ctx context.Context, ref access.PasskeyRef, name string) error {
	return f.commit(func(tx *memTx) error { return tx.RenamePasskey(ctx, ref, name) })
}

func (f *faultStore) DeletePasskey(ctx context.Context, ref access.PasskeyRef) error {
	return f.commit(func(tx *memTx) error { return tx.DeletePasskey(ctx, ref) })
}

func (f *faultStore) DeleteUserPasskeys(ctx context.Context, id int64) ([]int64, error) {
	var ids []int64
	err := f.commit(func(tx *memTx) (err error) { ids, err = tx.DeleteUserPasskeys(ctx, id); return err })
	return ids, err
}

func (f *faultStore) CreateAPIKey(ctx context.Context, k *access.Key) error {
	return f.commit(func(tx *memTx) error { return tx.CreateAPIKey(ctx, k) })
}

func (f *faultStore) APIKeyByHash(ctx context.Context, h access.Hash) (*access.Key, bool, error) {
	return f.view().APIKeyByHash(ctx, h)
}

func (f *faultStore) ListAPIKeysByUserID(ctx context.Context, id int64) ([]access.Key, error) {
	return f.view().ListAPIKeysByUserID(ctx, id)
}

func (f *faultStore) ListAPIKeys(ctx context.Context) ([]access.Key, error) {
	return f.view().ListAPIKeys(ctx)
}

func (f *faultStore) DeleteAPIKey(ctx context.Context, ref access.KeyRef) error {
	return f.commit(func(tx *memTx) error { return tx.DeleteAPIKey(ctx, ref) })
}

func (f *faultStore) DeleteUserAPIKeys(ctx context.Context, id int64) ([]int64, error) {
	var ids []int64
	err := f.commit(func(tx *memTx) (err error) { ids, err = tx.DeleteUserAPIKeys(ctx, id); return err })
	return ids, err
}

func (f *faultStore) TouchAPIKey(ctx context.Context, id int64, at time.Time) error {
	return f.commit(func(tx *memTx) error { return tx.TouchAPIKey(ctx, id, at) })
}

func (f *faultStore) CreateOneTimeToken(ctx context.Context, tok access.OneTimeToken) error {
	return f.commit(func(tx *memTx) error { return tx.CreateOneTimeToken(ctx, tok) })
}

func (f *faultStore) OneTimeTokenByHash(ctx context.Context, h access.Hash) (access.OneTimeToken, bool, error) {
	return f.view().OneTimeTokenByHash(ctx, h)
}

func (f *faultStore) ConsumeOneTimeToken(ctx context.Context, h access.Hash, now time.Time) (access.OneTimeToken, bool, error) {
	var (
		tok   access.OneTimeToken
		found bool
	)
	err := f.commit(func(tx *memTx) (err error) { tok, found, err = tx.ConsumeOneTimeToken(ctx, h, now); return err })
	return tok, found, err
}

func (f *faultStore) DeleteOneTimeTokens(ctx context.Context, p access.TokenPurpose, subject int64) (int, error) {
	var n int
	err := f.commit(func(tx *memTx) (err error) { n, err = tx.DeleteOneTimeTokens(ctx, p, subject); return err })
	return n, err
}

func (f *faultStore) LiveOneTimeTokens(ctx context.Context, ps []access.TokenPurpose, now time.Time) ([]access.OneTimeToken, error) {
	return f.view().LiveOneTimeTokens(ctx, ps, now)
}

func (f *faultStore) DeleteOneTimeTokensIssuedBy(ctx context.Context, ids []int64) (int, error) {
	var n int
	err := f.commit(func(tx *memTx) (err error) { n, err = tx.DeleteOneTimeTokensIssuedBy(ctx, ids); return err })
	return n, err
}

func (f *faultStore) CreateKeyAttribution(ctx context.Context, a *access.KeyAttribution) error {
	return f.commit(func(tx *memTx) error { return tx.CreateKeyAttribution(ctx, a) })
}

func (f *faultStore) ListKeyAttributions(ctx context.Context) ([]access.KeyAttribution, error) {
	return f.view().ListKeyAttributions(ctx)
}

func (f *faultStore) AuthFailure(ctx context.Context, ref account.FailureRef) (account.FailureCount, bool, error) {
	return f.view().AuthFailure(ctx, ref)
}

func (f *faultStore) PutAuthFailure(ctx context.Context, fc account.FailureCount) error {
	return f.commit(func(tx *memTx) error { return tx.PutAuthFailure(ctx, fc) })
}

func (f *faultStore) UnreportedLocks(ctx context.Context) ([]account.FailureCount, error) {
	return f.view().UnreportedLocks(ctx)
}

func (f *faultStore) DeleteAuthFailures(ctx context.Context, name string, ms []access.Method) error {
	return f.commit(func(tx *memTx) error { return tx.DeleteAuthFailures(ctx, name, ms) })
}

func (f *faultStore) PruneAuthFailures(ctx context.Context, keep []string) (int64, error) {
	var n int64
	err := f.commit(func(tx *memTx) (err error) { n, err = tx.PruneAuthFailures(ctx, keep); return err })
	return n, err
}

func (f *faultStore) AppendLog(ctx context.Context, e *account.LogEntry) error {
	return f.commit(func(tx *memTx) error { return tx.AppendLog(ctx, e) })
}

func (f *faultStore) ListLog(ctx context.Context, r account.LogRange) ([]account.LogEntry, error) {
	return f.view().ListLog(ctx, r)
}

func (f *faultStore) PruneLog(ctx context.Context, p account.LogPrune) (int, error) {
	var n int
	err := f.commit(func(tx *memTx) (err error) { n, err = tx.PruneLog(ctx, p); return err })
	return n, err
}

func (f *faultStore) LogStats(ctx context.Context) ([]account.LogClassStats, error) {
	return f.view().LogStats(ctx)
}

// faultConfig is the ContractConfig over media that mk wraps: NewFaulty
// returns every hook, and Reopen reopens the medium.
func faultConfig(mk func(med *medium) account.Store, reopen func(old account.Store) account.Store) (func(*testing.T) account.Store, ContractConfig) {
	newStore := func(*testing.T) account.Store { return mk(newMedium()) }
	return newStore, ContractConfig{
		NewFaulty: func(*testing.T) (account.Store, DurabilityFaults) {
			med := newMedium()
			return mk(med), med.faults()
		},
		Reopen: func(t *testing.T, old account.Store) account.Store {
			t.Helper()
			return reopen(old)
		},
	}
}

func plainFaultConfig() (func(*testing.T) account.Store, ContractConfig) {
	return faultConfig(
		func(med *medium) account.Store { return openFaultStore(med) },
		func(old account.Store) account.Store { return old.(*faultStore).reopen() },
	)
}

func TestStoreContractFaultMedium(t *testing.T) {
	newStore, cfg := plainFaultConfig()
	StoreContract(t, newStore, cfg)
}

func TestStoreContractFaultMediumSkips(t *testing.T) {
	t.Parallel()
	out, err := rerun(t, "TestStoreContractFaultMedium")
	if err != nil {
		t.Fatalf("TestStoreContractFaultMedium failed: %v\n%s", err, out)
	}
	if got := reported(out, "SKIP"); len(got) != 0 {
		t.Errorf("TestStoreContractFaultMedium skipped %v, want nothing skipped", got)
	}
}
