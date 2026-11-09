package accesstest

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// variantEnv names the broken store TestRedCheckVariant runs the contract on.
const variantEnv = "AUTHTEST_STORE_CONTRACT_VARIANT"

// variant is one broken store and the contract subtests it must fail.
type variant struct {
	make func() (func(*testing.T) account.Store, ContractConfig)
	// fails lists the subtest paths, under TestRedCheckVariant, that must
	// fail; with only, no other subtest may.
	fails []string
	// mention is text the failure output must hold, such as a field path.
	mention []string
	only    bool
}

// memVariant runs the contract with the zero config on stores wrap makes.
func memVariant(wrap func(m *MemStore) account.Store) func() (func(*testing.T) account.Store, ContractConfig) {
	return func() (func(*testing.T) account.Store, ContractConfig) {
		return func(*testing.T) account.Store { return wrap(NewMemStore()) }, ContractConfig{}
	}
}

// mediumVariant runs the contract on fault stores over media tune breaks.
func mediumVariant(tune func(m *medium)) func() (func(*testing.T) account.Store, ContractConfig) {
	return func() (func(*testing.T) account.Store, ContractConfig) {
		return faultConfig(
			func(med *medium) account.Store { tune(med); return openFaultStore(med) },
			func(old account.Store) account.Store { return old.(*faultStore).reopen() },
		)
	}
}

func faultStoreVariant(wrap func(f *faultStore) account.Store) func() (func(*testing.T) account.Store, ContractConfig) {
	return func() (func(*testing.T) account.Store, ContractConfig) {
		return faultConfig(
			func(med *medium) account.Store { return wrap(openFaultStore(med)) },
			func(old account.Store) account.Store { return wrap(old.(interface{ reopen() *faultStore }).reopen()) },
		)
	}
}

var variants = map[string]variant{
	"publish-per-update": {
		make:  mediumVariant(func(m *medium) { m.take = func(int) int { return 1 } }),
		fails: []string{"rule_05_update/grouped_commit"},
	},
	"after-publish-returns-nil": {
		make:  mediumVariant(func(m *medium) { m.confirm = func(error) error { return nil } }),
		fails: []string{"rule_10_durability/update_after_publish", "rule_10_durability/create_session_after_publish", "rule_10_durability/failure_update_after_publish"},
	},
	"aliases-handle": {
		make:  memVariant(func(m *MemStore) account.Store { return &aliasHandleStore{MemStore: m, handles: map[int64][]byte{}} }),
		fails: []string{"rule_02_ownership/user"},
	},
	"normalises-usernames": {
		make:  memVariant(func(m *MemStore) account.Store { return &foldingStore{m} }),
		fails: []string{"rule_03_canonical_usernames"},
	},
	"reads-take-writer-lock": {
		make:  memVariant(func(m *MemStore) account.Store { return &lockedReadsStore{m} }),
		fails: []string{"rule_16_reads_never_wait/update"},
	},
	"reads-wait-on-direct-writes": {
		make:  faultStoreVariant(func(f *faultStore) account.Store { return &directLockStore{faultStore: f} }),
		fails: []string{"rule_16_reads_never_wait/direct_write"}, only: true,
	},
	"consume-keeps-expired": {
		make:  memVariant(func(m *MemStore) account.Store { return &keepsExpiredStore{m} }),
		fails: []string{"rule_07_expiry/consume"},
	},
	"ids-recomputed-on-reopen": {
		make:  mediumVariant(func(m *medium) { m.reload = recomputeIDs }),
		fails: []string{"rule_17_ids_and_lineage/reopen_users", "rule_17_ids_and_lineage/reopen_keys"}, only: true,
	},
	"issued-by-ignores-list": {
		make:  memVariant(func(m *MemStore) account.Store { return &issuedByAllStore{m} }),
		fails: []string{"rule_06_scoping/issued_by"},
	},
	"id-highest-live-plus-one": {
		make:  memVariant(func(m *MemStore) account.Store { return &highestPlusOneStore{m} }),
		fails: []string{"rule_17_ids_and_lineage/never_reused_users", "rule_17_ids_and_lineage/never_reused_keys"},
	},
	"id-lowest-free": {
		make:  memVariant(func(m *MemStore) account.Store { return &lowestFreeStore{m} }),
		fails: []string{"rule_17_ids_and_lineage/never_reused_users", "rule_17_ids_and_lineage/never_reused_keys"},
	},
	"lineage-not-appended": {
		make:  memVariant(func(m *MemStore) account.Store { return &unappendedLineageStore{m} }),
		fails: []string{"rule_17_ids_and_lineage/lineage"},
	},
	"key-delete-drops-attributions": {
		make:  memVariant(func(m *MemStore) account.Store { return &keyDropsAttributionsStore{m} }),
		fails: []string{"rule_17_ids_and_lineage/attributions"},
	},
	"user-delete-keeps-attributions": {
		make:  memVariant(func(m *MemStore) account.Store { return &userKeepsAttributionsStore{m} }),
		fails: []string{"rule_05_atomicity/delete_user_cascade", "rule_17_ids_and_lineage/attributions"},
	},
	"json-codec": {
		make:  memVariant(func(m *MemStore) account.Store { return &jsonCodecStore{m} }),
		fails: []string{"rule_04_uniqueness/hash_round_trip"},
	},
	"drops-session-label": {
		make:  memVariant(func(m *MemStore) account.Store { return &dropLabelStore{m} }),
		fails: []string{"rule_20_fidelity/write_read"}, mention: []string{"Session.Label"},
	},
	"drops-passkey-rpid": {
		make:  memVariant(func(m *MemStore) account.Store { return &dropRPIDStore{m} }),
		fails: []string{"rule_20_fidelity/write_read"}, mention: []string{"PasskeyCredential.RPID"},
	},
	"idlecap-lost-on-reopen": {
		make:  mediumVariant(func(m *medium) { m.reload = dropIdleCaps }),
		fails: []string{"rule_20_fidelity/reopen"}, mention: []string{"Session.IdleCap"}, only: true,
	},
	"live-lists-expired": {
		make:  memVariant(func(m *MemStore) account.Store { return &liveListsExpiredStore{m} }),
		fails: []string{"rule_07_expiry/live_tokens"},
	},
	"cleanup-ignores-caps": {
		make:  memVariant(func(m *MemStore) account.Store { return &capsIgnoredStore{m} }),
		fails: []string{"rule_14_cleanup/caps"},
	},
	"cleanup-returns-no-refs": {
		make:  memVariant(func(m *MemStore) account.Store { return &noRefsStore{m} }),
		fails: []string{"rule_14_cleanup/deleted_set"},
	},
	"cleanup-ignores-limit": {
		make:  memVariant(func(m *MemStore) account.Store { return &unlimitedStore{m} }),
		fails: []string{"rule_14_cleanup/bound"},
	},
	"cleanup-skips-medium": {
		make:  faultStoreVariant(func(f *faultStore) account.Store { return &memoryOnlyCleanupStore{f} }),
		fails: []string{"rule_14_cleanup/deleted_set_reopen"}, only: true,
	},
	"cleanup-deletes-in-second-step": {
		make:  memVariant(func(m *MemStore) account.Store { return &twoStepCleanupStore{MemStore: m} }),
		fails: []string{"rule_14_cleanup/concurrent_delete"},
	},
	"cleanup-deletes-listed-ids": {
		make:  memVariant(func(m *MemStore) account.Store { return &twoStepCleanupStore{MemStore: m, byID: true} }),
		fails: []string{"rule_14_cleanup/concurrent_rotate"},
	},
	"cleanup-rerun-appends": {
		make:  faultStoreVariant(func(f *faultStore) account.Store { return &appendingCleanupStore{f} }),
		fails: []string{"rule_14_cleanup/rerun"}, mention: []string{"exactly once"},
	},
	"activity-unconditional": {
		make:  memVariant(func(m *MemStore) account.Store { return &unconditionalActivityStore{m} }),
		fails: []string{"rule_21_activity/session"},
	},
	"touch-unconditional": {
		make:  memVariant(func(m *MemStore) account.Store { return &unconditionalTouchStore{m} }),
		fails: []string{"rule_21_activity/key"},
	},
	"rotate-overwrites-activity": {
		make:  memVariant(func(m *MemStore) account.Store { return &rotationOverwritesStore{m} }),
		fails: []string{"rule_21_activity/rotation"},
	},
}

// TestRedCheckVariant runs the contract on the variant variantEnv names;
// without it, it returns at once. TestStoreContractRedCheck runs it.
func TestRedCheckVariant(t *testing.T) {
	name := os.Getenv(variantEnv)
	if name == "" {
		return
	}
	v, ok := redCheckVariants()[name]
	if !ok {
		t.Fatalf("unknown variant %q", name)
	}
	newStore, cfg := v.make()
	StoreContract(t, newStore, cfg)
}

// TestStoreContractRedCheck proves each contract case can fail: a child run
// of every broken store must exit non-zero with its named subtests failing.
func TestStoreContractRedCheck(t *testing.T) {
	t.Parallel()
	all := redCheckVariants()
	for _, name := range slices.Sorted(maps.Keys(all)) {
		v := all[name]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, err := rerun(t, "TestRedCheckVariant", variantEnv+"="+name)
			if _, ok := errors.AsType[*exec.ExitError](err); !ok {
				t.Fatalf("the child run = %v, want a non-zero exit\n%s", err, out)
			}
			for _, bad := range []string{"panic: ", "DATA RACE", "build failed"} {
				if strings.Contains(out, bad) {
					t.Fatalf("the child run reports %q, not a contract failure\n%s", bad, out)
				}
			}
			failed := reported(out, "FAIL")
			want := []string{"TestRedCheckVariant"}
			for _, p := range v.fails {
				path := "TestRedCheckVariant/" + p
				if !slices.Contains(failed, path) {
					t.Errorf("%s did not fail", path)
				}
				for i := range strings.Count(p, "/") + 1 {
					want = append(want, "TestRedCheckVariant/"+strings.Join(strings.Split(p, "/")[:i+1], "/"))
				}
			}
			slices.Sort(want)
			if want = slices.Compact(want); v.only && !slices.Equal(failed, want) {
				t.Errorf("failed %v, want only %v", failed, want)
			}
			for _, m := range v.mention {
				if !strings.Contains(out, m) {
					t.Errorf("the failure output does not mention %s", m)
				}
			}
			if t.Failed() {
				t.Logf("child output:\n%s", out)
			}
		})
	}
}

// aliasHandleStore keeps the caller's handle slice and returns it.
type aliasHandleStore struct {
	*MemStore
	handles map[int64][]byte
	mu      sync.Mutex
}

func (s *aliasHandleStore) CreateUser(ctx context.Context, u *access.User) error {
	if err := s.MemStore.CreateUser(ctx, u); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handles[u.ID] = u.WebAuthnHandle
	return nil
}

func (s *aliasHandleStore) UserByID(ctx context.Context, id int64) (*access.User, bool, error) {
	u, found, err := s.MemStore.UserByID(ctx, id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.handles[id]; ok && found {
		u.WebAuthnHandle = h
	}
	return u, found, err
}

// foldingStore lower-cases every username it is given.
type foldingStore struct{ *MemStore }

func (s *foldingStore) CreateUser(ctx context.Context, u *access.User) error {
	u.Username = strings.ToLower(u.Username)
	return s.MemStore.CreateUser(ctx, u)
}

func (s *foldingStore) UserByUsername(ctx context.Context, name string) (*access.User, bool, error) {
	return s.MemStore.UserByUsername(ctx, strings.ToLower(name))
}

// lockedReadsStore takes the writer mutex for its reads.
type lockedReadsStore struct{ *MemStore }

func (s *lockedReadsStore) SessionByHash(ctx context.Context, h access.Hash) (*access.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.view().SessionByHash(ctx, h)
}

func (s *lockedReadsStore) UserByUsername(ctx context.Context, name string) (*access.User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.view().UserByUsername(ctx, name)
}

func (s *lockedReadsStore) UserCount(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.view().UserCount(ctx)
}

// directLockStore's single-call session writes hold a lock that its reads
// also take, so a read waits out a direct write's publish.
type directLockStore struct {
	*faultStore
	rw sync.RWMutex
}

func (s *directLockStore) CreateSession(ctx context.Context, sess *access.Session) error {
	s.rw.Lock()
	defer s.rw.Unlock()
	return s.faultStore.CreateSession(ctx, sess)
}

func (s *directLockStore) SessionByHash(ctx context.Context, h access.Hash) (*access.Session, bool, error) {
	s.rw.RLock()
	defer s.rw.RUnlock()
	return s.faultStore.SessionByHash(ctx, h)
}

func (s *directLockStore) UserByUsername(ctx context.Context, name string) (*access.User, bool, error) {
	s.rw.RLock()
	defer s.rw.RUnlock()
	return s.faultStore.UserByUsername(ctx, name)
}

func (s *directLockStore) UserCount(ctx context.Context) (int, error) {
	s.rw.RLock()
	defer s.rw.RUnlock()
	return s.faultStore.UserCount(ctx)
}

type keepsExpiredStore struct{ *MemStore }

func (s *keepsExpiredStore) ConsumeOneTimeToken(ctx context.Context, h access.Hash, now time.Time) (access.OneTimeToken, bool, error) {
	if tok, found, err := s.OneTimeTokenByHash(ctx, h); err != nil || (found && !tok.ExpiresAt.After(now)) {
		return access.OneTimeToken{}, false, err
	}
	return s.MemStore.ConsumeOneTimeToken(ctx, h, now)
}

func recomputeIDs(committed *state) *state {
	s := committed.clone()
	s.lastUser, s.lastKey = highestLive(s.users), highestLive(s.keys)
	return s
}

func highestLive[V any](m map[int64]V) int64 {
	return slices.Max(append(slices.Collect(maps.Keys(m)), 0))
}

// issuedByAllStore deletes every key-issued token, whatever the list.
type issuedByAllStore struct{ *MemStore }

func (s *issuedByAllStore) DeleteOneTimeTokensIssuedBy(context.Context, []int64) (int, error) {
	var n int
	err := s.write(func(tx *memTx) (bool, error) {
		n = tx.deleteTokens(func(tok access.OneTimeToken) bool { return tok.IssuedByKey != 0 })
		return true, nil
	})
	return n, err
}

// highestPlusOneStore lowers its counters to the highest live ID on delete.
type highestPlusOneStore struct{ *MemStore }

func (s *highestPlusOneStore) lower() error {
	return s.write(func(tx *memTx) (bool, error) {
		tx.s.lastUser, tx.s.lastKey = highestLive(tx.s.users), highestLive(tx.s.keys)
		return true, nil
	})
}

func (s *highestPlusOneStore) DeleteUser(ctx context.Context, id int64) error {
	return errors.Join(s.MemStore.DeleteUser(ctx, id), s.lower())
}

func (s *highestPlusOneStore) DeleteAPIKey(ctx context.Context, ref access.KeyRef) error {
	return errors.Join(s.MemStore.DeleteAPIKey(ctx, ref), s.lower())
}

// lowestFreeStore assigns the lowest free user and key ID.
type lowestFreeStore struct{ *MemStore }

func lowestFree[V any](m map[int64]V) int64 {
	id := int64(1)
	for ; ; id++ {
		if _, taken := m[id]; !taken {
			return id
		}
	}
}

func (s *lowestFreeStore) CreateUser(ctx context.Context, u *access.User) error {
	return s.write(func(tx *memTx) (bool, error) {
		last := tx.s.lastUser
		tx.s.lastUser = lowestFree(tx.s.users) - 1
		err := tx.CreateUser(ctx, u)
		tx.s.lastUser = max(last, tx.s.lastUser)
		return true, err
	})
}

func (s *lowestFreeStore) CreateAPIKey(ctx context.Context, k *access.Key) error {
	return s.write(func(tx *memTx) (bool, error) {
		last := tx.s.lastKey
		tx.s.lastKey = lowestFree(tx.s.keys) - 1
		err := tx.CreateAPIKey(ctx, k)
		tx.s.lastKey = max(last, tx.s.lastKey)
		return true, err
	})
}

// unappendedLineageStore stores LineageIDs as given, without the new ID.
type unappendedLineageStore struct{ *MemStore }

func (s *unappendedLineageStore) CreateAPIKey(ctx context.Context, k *access.Key) error {
	given := slices.Clone(k.LineageIDs)
	return s.write(func(tx *memTx) (bool, error) {
		err := tx.CreateAPIKey(ctx, k)
		if err == nil {
			stored := tx.s.keys[k.ID]
			stored.LineageIDs = given
			tx.s.keys[k.ID] = stored
		}
		return true, err
	})
}

// keyDropsAttributionsStore deletes the attributions naming a deleted key.
type keyDropsAttributionsStore struct{ *MemStore }

func (s *keyDropsAttributionsStore) dropNaming(ids []int64) error {
	return s.write(func(tx *memTx) (bool, error) {
		tx.s.attributions = slices.DeleteFunc(tx.s.attributions, func(a access.KeyAttribution) bool {
			return slices.ContainsFunc(ids, a.Contains)
		})
		return true, nil
	})
}

func (s *keyDropsAttributionsStore) DeleteAPIKey(ctx context.Context, ref access.KeyRef) error {
	return errors.Join(s.MemStore.DeleteAPIKey(ctx, ref), s.dropNaming([]int64{ref.ID}))
}

func (s *keyDropsAttributionsStore) DeleteUserAPIKeys(ctx context.Context, userID int64) ([]int64, error) {
	ids, err := s.MemStore.DeleteUserAPIKeys(ctx, userID)
	return ids, errors.Join(err, s.dropNaming(ids))
}

// userKeepsAttributionsStore leaves a deleted user's attributions.
type userKeepsAttributionsStore struct{ *MemStore }

func (s *userKeepsAttributionsStore) DeleteUser(ctx context.Context, id int64) error {
	return s.write(func(tx *memTx) (bool, error) {
		kept := slices.Clone(tx.s.attributions)
		err := tx.DeleteUser(ctx, id)
		tx.s.attributions = kept
		return true, err
	})
}

// jsonCodecStore returns every record through encoding/json, as a store
// persisting it that way would, losing each json:"-" field.
type jsonCodecStore struct{ *MemStore }

func viaJSON[T any](v *T) *T {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	out := new(T)
	if err == nil {
		err = json.Unmarshal(b, out)
	}
	if err != nil {
		panic(err)
	}
	return out
}

func (s *jsonCodecStore) UserByID(ctx context.Context, id int64) (*access.User, bool, error) {
	u, found, err := s.MemStore.UserByID(ctx, id)
	return viaJSON(u), found, err
}

func (s *jsonCodecStore) SessionByHash(ctx context.Context, h access.Hash) (*access.Session, bool, error) {
	sess, found, err := s.MemStore.SessionByHash(ctx, h)
	return viaJSON(sess), found, err
}

func (s *jsonCodecStore) APIKeyByHash(ctx context.Context, h access.Hash) (*access.Key, bool, error) {
	k, found, err := s.MemStore.APIKeyByHash(ctx, h)
	return viaJSON(k), found, err
}

func (s *jsonCodecStore) OneTimeTokenByHash(ctx context.Context, h access.Hash) (access.OneTimeToken, bool, error) {
	tok, found, err := s.MemStore.OneTimeTokenByHash(ctx, h)
	return *viaJSON(&tok), found, err
}

// dropLabelStore writes every session without its Label.
type dropLabelStore struct{ *MemStore }

func (s *dropLabelStore) CreateSession(ctx context.Context, sess *access.Session) error {
	cp := *sess
	cp.Label = ""
	return s.MemStore.CreateSession(ctx, &cp)
}

// dropRPIDStore writes every passkey without its RPID.
type dropRPIDStore struct{ *MemStore }

func (s *dropRPIDStore) CreatePasskey(ctx context.Context, p *access.PasskeyCredential) error {
	cp := p.Clone()
	cp.RPID = ""
	err := s.MemStore.CreatePasskey(ctx, cp)
	p.ID = cp.ID
	return err
}

// dropIdleCaps is a medium that never wrote Session.IdleCap to disk.
func dropIdleCaps(committed *state) *state {
	s := committed.clone()
	for k, sess := range s.sessions {
		sess.IdleCap = 0
		s.sessions[k] = sess
	}
	return s
}

// liveListsExpiredStore lists tokens without the expiry check.
type liveListsExpiredStore struct{ *MemStore }

func (s *liveListsExpiredStore) LiveOneTimeTokens(ctx context.Context, ps []access.TokenPurpose, _ time.Time) ([]access.OneTimeToken, error) {
	return s.MemStore.LiveOneTimeTokens(ctx, ps, time.Time{})
}

// capsIgnoredStore sweeps as if no session had a cap.
type capsIgnoredStore struct{ *MemStore }

func (s *capsIgnoredStore) CleanupExpiredSessions(_ context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	var refs []access.SessionRef
	err := s.write(func(tx *memTx) (bool, error) {
		for key, sess := range tx.s.sessions {
			uncapped := sess
			uncapped.IdleCap, uncapped.AbsoluteCap = 0, 0
			if len(refs) < limit && access.ValidateSession(&uncapped, timeouts, now) != nil {
				refs = append(refs, refOf(&sess))
				tx.deleteSession(key)
			}
		}
		return true, nil
	})
	return refs, err
}

// noRefsStore deletes but reports nothing.
type noRefsStore struct{ *MemStore }

func (s *noRefsStore) CleanupExpiredSessions(ctx context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	_, err := s.MemStore.CleanupExpiredSessions(ctx, now, timeouts, limit)
	return nil, err
}

// unlimitedStore deletes every expired session in one call.
type unlimitedStore struct{ *MemStore }

func (s *unlimitedStore) CleanupExpiredSessions(ctx context.Context, now time.Time, timeouts access.SessionTimeouts, _ int) ([]access.SessionRef, error) {
	return s.MemStore.CleanupExpiredSessions(ctx, now, timeouts, math.MaxInt)
}

// memoryOnlyCleanupStore deletes from the in-memory snapshot, but its
// medium never receives the deletes, so a reopen brings the rows back.
type memoryOnlyCleanupStore struct{ *faultStore }

func (s *memoryOnlyCleanupStore) CleanupExpiredSessions(ctx context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	before := s.mem.snap.Load()
	refs, err := s.faultStore.CleanupExpiredSessions(ctx, now, timeouts, limit)
	lost := map[access.HashKey]access.Session{}
	for _, ref := range refs {
		key := before.sessionIDs[ref.ID]
		lost[key] = before.sessions[key]
	}
	s.med.mu.Lock()
	defer s.med.mu.Unlock()
	prev := s.med.reload
	s.med.reload = func(st *state) *state {
		if prev != nil {
			st = prev(st)
		}
		c := st.clone()
		for key, sess := range lost {
			c.sessions[key], c.sessionIDs[sess.ID] = sess, key
		}
		return c
	}
	return refs, err
}

// appendingCleanupStore appends each run's refs of a grouped commit to one
// slice instead of building them afresh.
type appendingCleanupStore struct{ *faultStore }

func (s *appendingCleanupStore) CleanupExpiredSessions(_ context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	var refs []access.SessionRef
	err := s.commit(func(tx *memTx) error {
		refs = append(refs, tx.cleanup(now, timeouts, limit)...)
		return nil
	})
	return refs, err
}

// twoStepCleanupStore lists under the writer mutex, releases it, signals
// its window, and only then deletes: what is still there, or with byID
// whatever row now holds each listed ID. It returns every listed ref.
type twoStepCleanupStore struct {
	*MemStore
	listed  chan struct{}
	release chan struct{}
	byID    bool
	hookMu  sync.Mutex
}

func (s *twoStepCleanupStore) armCleanupWindow() (<-chan struct{}, func()) {
	s.hookMu.Lock()
	defer s.hookMu.Unlock()
	listed, release := make(chan struct{}), make(chan struct{})
	s.listed, s.release = listed, release
	return listed, sync.OnceFunc(func() { close(release) })
}

// window signals an armed hook and waits for its release.
func (s *twoStepCleanupStore) window() {
	s.hookMu.Lock()
	listed, release := s.listed, s.release
	s.listed, s.release = nil, nil
	s.hookMu.Unlock()
	if listed != nil {
		close(listed)
		<-release
	}
}

func (s *twoStepCleanupStore) CleanupExpiredSessions(ctx context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	if limit < 1 {
		return nil, errLimit
	}
	s.mu.Lock()
	snap := s.snap.Load()
	var listed []access.Session
	for key := range snap.sessions {
		if sess := snap.sessions[key]; len(listed) < limit && access.ValidateSession(&sess, timeouts, now) != nil {
			listed = append(listed, sess)
		}
	}
	s.mu.Unlock()
	s.window()
	refs := make([]access.SessionRef, 0, len(listed))
	for i := range listed {
		sess := &listed[i]
		refs = append(refs, refOf(sess))
		if !s.byID {
			if err := s.DeleteSessionByHash(ctx, sess.TokenHash); err != nil {
				return nil, err
			}
			continue
		}
		if err := s.write(func(tx *memTx) (bool, error) {
			key, ok := tx.s.sessionIDs[sess.ID]
			if ok {
				tx.deleteSession(key)
			}
			return ok, nil
		}); err != nil {
			return nil, err
		}
	}
	return refs, nil
}

// unconditionalActivityStore writes every activity, older ones included.
type unconditionalActivityStore struct{ *MemStore }

func (s *unconditionalActivityStore) UpdateSessionActivity(_ context.Context, h access.Hash, act access.SessionActivity) error {
	return s.write(func(tx *memTx) (bool, error) {
		sess, ok := tx.s.sessions[h.Key()]
		if ok {
			sess.LastActivity, sess.LastIP = act.At, act.IP
			tx.s.sessions[h.Key()] = sess
		}
		return ok, nil
	})
}

// unconditionalTouchStore writes every touch, older ones included.
type unconditionalTouchStore struct{ *MemStore }

func (s *unconditionalTouchStore) TouchAPIKey(_ context.Context, id int64, at time.Time) error {
	return s.write(func(tx *memTx) (bool, error) {
		k, ok := tx.s.keys[id]
		if ok {
			k.LastUsedAt = at
			tx.s.keys[id] = k
		}
		return ok, nil
	})
}

// rotationOverwritesStore writes Next's activity as given.
type rotationOverwritesStore struct{ *MemStore }

func (s *rotationOverwritesStore) RotateSession(ctx context.Context, rot account.Rotation) error {
	if err := s.MemStore.RotateSession(ctx, rot); err != nil {
		return err
	}
	return s.write(func(tx *memTx) (bool, error) {
		key := rot.Next.TokenHash.Key()
		sess := tx.s.sessions[key]
		sess.LastActivity, sess.LastIP = rot.Next.LastActivity, rot.Next.LastIP
		tx.s.sessions[key] = sess
		return true, nil
	})
}
