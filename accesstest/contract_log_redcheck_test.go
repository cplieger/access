package accesstest

import (
	"context"
	"errors"
	"maps"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access/account"
)

// logVariants are rule 22's broken stores and the log cases of rules 11, 18
// and 20.
var logVariants = map[string]variant{
	"log-seq-highest-live-plus-one": {
		make:  memVariant(func(m *MemStore) account.Store { return &logHighestPlusOneStore{m} }),
		fails: []string{"rule_22_log/seq_never_reused"},
	},
	"log-seq-recomputed-on-reopen": {
		make:  mediumVariant(func(m *medium) { m.reload = recomputeLogSeq }),
		fails: []string{"rule_22_log/seq_never_reused_reopen"}, only: true,
	},
	"log-append-survives-rollback": {
		make:  memVariant(func(m *MemStore) account.Store { return &rollbackKeepsLogStore{m} }),
		fails: []string{"rule_22_log/seq_rolled_back"},
	},
	"log-seq-before-lock": {
		make:  memVariant(func(m *MemStore) account.Store { return &seqBeforeLockStore{MemStore: m, seen: make(chan struct{})} }),
		fails: []string{"rule_22_log/seq_visible_in_order"},
	},
	"log-seq-past-json-bound": {
		make:  memVariant(func(m *MemStore) account.Store { return &seqPastBoundStore{m} }),
		fails: []string{"rule_22_log/seq_bound"},
	},
	"log-list-always-descending": {
		make:  memVariant(func(m *MemStore) account.Store { return &descendingListStore{m} }),
		fails: []string{"rule_22_log/seq_increasing", "rule_22_log/list_range"},
	},
	"log-list-includes-after": {
		make:  memVariant(func(m *MemStore) account.Store { return &inclusiveAfterStore{m} }),
		fails: []string{"rule_22_log/list_range"},
	},
	"log-aliases-session-ids": {
		make: memVariant(func(m *MemStore) account.Store {
			return &aliasSessionIDsStore{MemStore: m, kept: map[uint64][]string{}}
		}),
		fails: []string{"rule_22_log/list_copies"},
	},
	"log-drops-method": {
		make:  memVariant(func(m *MemStore) account.Store { return &dropMethodStore{m} }),
		fails: []string{"rule_22_log/list_copies"},
	},
	"log-prune-ignores-class": {
		make:  memVariant(func(m *MemStore) account.Store { return &pruneEveryClassStore{m} }),
		fails: []string{"rule_22_log/prune_class"},
	},
	"log-keep-removes-newest": {
		make:  memVariant(func(m *MemStore) account.Store { return &keepNewestStore{m} }),
		fails: []string{"rule_22_log/prune_keep"},
	},
	"log-before-inclusive": {
		make:  memVariant(func(m *MemStore) account.Store { return &inclusiveBeforeStore{m} }),
		fails: []string{"rule_22_log/prune_before"},
	},
	"log-prune-ignores-limit": {
		make:  memVariant(func(m *MemStore) account.Store { return &unlimitedPruneStore{m} }),
		fails: []string{"rule_22_log/prune_limit"},
	},
	"log-prune-keep-wins": {
		make:  memVariant(func(m *MemStore) account.Store { return &keepWinsStore{m} }),
		fails: []string{"rule_22_log/prune_one_criterion"},
	},
	"log-stats-count-includes-evicted": {
		make:  memVariant(func(m *MemStore) account.Store { return &countEvictedStore{m} }),
		fails: []string{"rule_22_log/stats_count"},
	},
	"log-keep-not-evicted": {
		make:  memVariant(func(m *MemStore) account.Store { return &keepUncountedStore{m} }),
		fails: []string{"rule_22_log/stats_evicted"},
	},
	"log-before-evicts": {
		make:  memVariant(func(m *MemStore) account.Store { return &beforeCountedStore{m} }),
		fails: []string{"rule_22_log/stats_evicted"},
	},
	"log-evicted-lost-on-reopen": {
		make:  mediumVariant(func(m *medium) { m.reload = dropEvicted }),
		fails: []string{"rule_22_log/stats_reopen"}, only: true,
	},
	"log-delete-user-deletes-entries": {
		make:  memVariant(func(m *MemStore) account.Store { return &userDropsLogStore{m} }),
		fails: []string{"rule_22_log/delete_user_keeps"},
	},
	"log-reads-take-writer-lock": {
		make:  memVariant(func(m *MemStore) account.Store { return &lockedLogReadsStore{m} }),
		fails: []string{"rule_22_log/list_never_waits"},
	},
	"log-re-run-keeps-earlier-appends": {
		make:  faultStoreVariant(func(f *faultStore) account.Store { return &keptAppendsStore{f} }),
		fails: []string{"rule_22_log/seq_re_run"},
	},
	"log-user-agent-lost-on-reopen": {
		make:  mediumVariant(func(m *medium) { m.reload = dropActorUserAgents }),
		fails: []string{"rule_20_fidelity/reopen"}, mention: []string{"LogEntry.ActorUserAgent"}, only: true,
	},
	"log-append-replaces-context": {
		make:  memVariant(func(m *MemStore) account.Store { return &ownContextLogStore{m} }),
		fails: []string{"rule_18_context"},
	},
	"log-at-whole-seconds": {
		make:  memVariant(func(m *MemStore) account.Store { return &secondsLogStore{m} }),
		fails: []string{"rule_11_time"},
	},
}

// logClauseVariants names, per rule 22 clause, the variants that must fail
// its subtest.
var logClauseVariants = map[string][]string{
	"seq_increasing":          {"log-list-always-descending"},
	"seq_visible_in_order":    {"log-seq-before-lock"},
	"seq_never_reused":        {"log-seq-highest-live-plus-one"},
	"seq_never_reused_reopen": {"log-seq-recomputed-on-reopen"},
	"seq_bound":               {"log-seq-past-json-bound"},
	"seq_rolled_back":         {"log-append-survives-rollback"},
	"seq_re_run":              {"log-re-run-keeps-earlier-appends"},
	"list_range":              {"log-list-includes-after", "log-list-always-descending"},
	"list_copies":             {"log-aliases-session-ids", "log-drops-method"},
	"prune_class":             {"log-prune-ignores-class"},
	"prune_keep":              {"log-keep-removes-newest"},
	"prune_before":            {"log-before-inclusive"},
	"prune_limit":             {"log-prune-ignores-limit"},
	"prune_one_criterion":     {"log-prune-keep-wins"},
	"stats_count":             {"log-stats-count-includes-evicted"},
	"stats_evicted":           {"log-keep-not-evicted", "log-before-evicts"},
	"stats_reopen":            {"log-evicted-lost-on-reopen"},
	"delete_user_keeps":       {"log-delete-user-deletes-entries"},
	"list_never_waits":        {"log-reads-take-writer-lock"},
}

// TestLogClausesRedChecked pins rule 22's clause table to the red-check
// variants: every clause names at least one variant, and each named variant
// must fail that clause's subtest.
func TestLogClausesRedChecked(t *testing.T) {
	t.Parallel()
	clauses := (&contract{}).logClauses()
	if len(logClauseVariants) != len(clauses) {
		t.Errorf("logClauseVariants has %d rows for %d clauses", len(logClauseVariants), len(clauses))
	}
	for _, cl := range clauses {
		if len(logClauseVariants[cl.name]) == 0 {
			t.Errorf("clause %s names no red-check variant", cl.name)
		}
		for _, name := range logClauseVariants[cl.name] {
			if v, ok := redCheckVariants()[name]; !ok || !slices.Contains(v.fails, "rule_22_log/"+cl.name) {
				t.Errorf("clause %s names variant %s, which does not fail rule_22_log/%s", cl.name, name, cl.name)
			}
		}
	}
}

// redCheckVariants is every variant TestStoreContractRedCheck runs.
func redCheckVariants() map[string]variant {
	all := maps.Clone(variants)
	maps.Copy(all, logVariants)
	if len(all) != len(variants)+len(logVariants) {
		panic("accesstest: a log variant reuses another variant's name")
	}
	return all
}

// edit changes m's published state in place of a correct write.
func edit(m *MemStore, fn func(s *state)) error {
	return m.write(func(tx *memTx) (bool, error) {
		fn(tx.s)
		return true, nil
	})
}

// logHighestPlusOneStore lowers its Seq counter to the highest live Seq on
// every prune.
type logHighestPlusOneStore struct{ *MemStore }

func (s *logHighestPlusOneStore) PruneLog(ctx context.Context, p account.LogPrune) (int, error) {
	n, err := s.MemStore.PruneLog(ctx, p)
	return n, errors.Join(err, edit(s.MemStore, func(st *state) { *st = *recomputeLogSeq(st) }))
}

// recomputeLogSeq is a medium that recomputes its Seq counter from the
// highest live Seq on reopen.
func recomputeLogSeq(committed *state) *state {
	s := committed.clone()
	s.lastLog = 0
	for _, l := range s.log {
		for _, e := range l.entries {
			s.lastLog = max(s.lastLog, e.Event.Seq)
		}
	}
	return s
}

// rollbackKeepsLogStore appends an Update's entries even when its callback
// fails.
type rollbackKeepsLogStore struct{ *MemStore }

func (s *rollbackKeepsLogStore) Update(ctx context.Context, fn func(account.Tx) error) error {
	var kept []account.LogEntry
	err := s.MemStore.Update(ctx, func(tx account.Tx) error {
		kept = nil
		return fn(&keepingTx{memTx: tx.(*memTx), kept: &kept})
	})
	if err != nil {
		for i := range kept {
			_ = s.AppendLog(ctx, &kept[i])
		}
	}
	return err
}

// seqBeforeLockStore reserves each Update's Seq before it takes the writer
// lock. Its first Update with a competitor holds between the reservation
// and the lock until a ListLog has returned a larger Seq, so that larger
// Seq is visible before the smaller one commits.
type seqBeforeLockStore struct {
	*MemStore
	seen     chan struct{}
	seenOnce sync.Once
	next     atomic.Uint64
	held     atomic.Uint64
	pending  atomic.Int64
	holdOnce atomic.Bool
}

func (s *seqBeforeLockStore) Update(ctx context.Context, fn func(account.Tx) error) error {
	s.pending.Add(1)
	defer s.pending.Add(-1)
	seq := s.next.Add(1)
	if s.holdOnce.CompareAndSwap(false, true) && waitFor(100*time.Millisecond, func() bool { return s.pending.Load() > 1 }) {
		s.held.Store(seq)
		select {
		case <-s.seen:
		case <-time.After(5 * time.Second):
		}
	}
	return s.MemStore.Update(ctx, func(tx account.Tx) error {
		return fn(&reservedSeqTx{memTx: tx.(*memTx), seq: seq, next: &s.next})
	})
}

func (s *seqBeforeLockStore) AppendLog(ctx context.Context, e *account.LogEntry) error {
	return s.Update(ctx, func(tx account.Tx) error { return tx.AppendLog(ctx, e) })
}

func (s *seqBeforeLockStore) ListLog(ctx context.Context, r account.LogRange) ([]account.LogEntry, error) {
	out, err := s.MemStore.ListLog(ctx, r)
	if held := s.held.Load(); held != 0 && slices.ContainsFunc(out, func(e account.LogEntry) bool { return e.Event.Seq > held }) {
		s.seenOnce.Do(func() { close(s.seen) })
	}
	return out, err
}

// reservedSeqTx appends its first entry at the reserved Seq.
type reservedSeqTx struct {
	*memTx
	next *atomic.Uint64
	seq  uint64
}

func (t *reservedSeqTx) AppendLog(_ context.Context, e *account.LogEntry) error {
	seq := t.seq
	if seq == 0 {
		seq = t.next.Add(1)
	}
	t.seq = 0
	cp := cloneEntry(e)
	cp.Event.Seq = seq
	l := t.s.log[e.Class]
	l.entries = append(l.entries, cp)
	t.s.log[e.Class] = l
	e.Event.Seq = seq
	return nil
}

// seqPastBoundStore hands back Seqs above 2^53 − 1.
type seqPastBoundStore struct{ *MemStore }

func (s *seqPastBoundStore) AppendLog(ctx context.Context, e *account.LogEntry) error {
	err := s.MemStore.AppendLog(ctx, e)
	e.Event.Seq += maxID
	return err
}

// descendingListStore ignores Descending and always lists newest first.
type descendingListStore struct{ *MemStore }

func (s *descendingListStore) ListLog(ctx context.Context, r account.LogRange) ([]account.LogEntry, error) {
	r.Descending = true
	return s.MemStore.ListLog(ctx, r)
}

// inclusiveAfterStore includes the entry at AfterSeq.
type inclusiveAfterStore struct{ *MemStore }

func (s *inclusiveAfterStore) ListLog(ctx context.Context, r account.LogRange) ([]account.LogEntry, error) {
	r.AfterSeq = max(r.AfterSeq, 1) - 1
	return s.MemStore.ListLog(ctx, r)
}

// aliasSessionIDsStore keeps the caller's SessionIDs and returns them.
type aliasSessionIDsStore struct {
	*MemStore
	kept map[uint64][]string
	mu   sync.Mutex
}

func (s *aliasSessionIDsStore) AppendLog(ctx context.Context, e *account.LogEntry) error {
	err := s.MemStore.AppendLog(ctx, e)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kept[e.Event.Seq] = e.Event.SessionIDs
	return err
}

func (s *aliasSessionIDsStore) ListLog(ctx context.Context, r account.LogRange) ([]account.LogEntry, error) {
	out, err := s.MemStore.ListLog(ctx, r)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range out {
		if ids, ok := s.kept[out[i].Event.Seq]; ok {
			out[i].Event.SessionIDs = ids
		}
	}
	return out, err
}

// dropMethodStore stores each single-call entry without its Event.Method.
type dropMethodStore struct{ *MemStore }

func (s *dropMethodStore) AppendLog(ctx context.Context, e *account.LogEntry) error {
	cp := cloneEntry(e)
	cp.Event.Method = ""
	err := s.MemStore.AppendLog(ctx, &cp)
	e.Event.Seq = cp.Event.Seq
	return err
}

// pruneEveryClassStore applies a prune to every class.
type pruneEveryClassStore struct{ *MemStore }

func (s *pruneEveryClassStore) PruneLog(ctx context.Context, p account.LogPrune) (int, error) {
	var total int
	for _, class := range account.LogClasses() {
		p.Class = class
		n, err := s.MemStore.PruneLog(ctx, p)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// keepNewestStore's Keep prune removes the newest entries instead.
type keepNewestStore struct{ *MemStore }

func (s *keepNewestStore) PruneLog(ctx context.Context, p account.LogPrune) (int, error) {
	if p.Keep <= 0 || !p.Before.IsZero() {
		return s.MemStore.PruneLog(ctx, p)
	}
	var n int
	err := edit(s.MemStore, func(st *state) {
		l := st.log[p.Class]
		n = min(p.Limit, max(len(l.entries)-p.Keep, 0))
		l.entries = l.entries[:len(l.entries)-n]
		l.evicted += uint64(n)
		st.log[p.Class] = l
	})
	return n, err
}

// inclusiveBeforeStore's Before prune also removes an entry at Before.
type inclusiveBeforeStore struct{ *MemStore }

func (s *inclusiveBeforeStore) PruneLog(ctx context.Context, p account.LogPrune) (int, error) {
	if !p.Before.IsZero() {
		p.Before = p.Before.Add(time.Nanosecond)
	}
	return s.MemStore.PruneLog(ctx, p)
}

// unlimitedPruneStore ignores Limit.
type unlimitedPruneStore struct{ *MemStore }

func (s *unlimitedPruneStore) PruneLog(ctx context.Context, p account.LogPrune) (int, error) {
	p.Limit = math.MaxInt
	return s.MemStore.PruneLog(ctx, p)
}

// keepWinsStore applies Keep and ignores Before when both are set.
type keepWinsStore struct{ *MemStore }

func (s *keepWinsStore) PruneLog(ctx context.Context, p account.LogPrune) (int, error) {
	if p.Keep > 0 {
		p.Before = time.Time{}
	}
	return s.MemStore.PruneLog(ctx, p)
}

// countEvictedStore counts evicted entries as held.
type countEvictedStore struct{ *MemStore }

func (s *countEvictedStore) LogStats(ctx context.Context) ([]account.LogClassStats, error) {
	out, err := s.MemStore.LogStats(ctx)
	for i := range out {
		out[i].Count += int(out[i].Evicted)
	}
	return out, err
}

// keepUncountedStore's Keep prune does not raise Evicted.
type keepUncountedStore struct{ *MemStore }

func (s *keepUncountedStore) PruneLog(ctx context.Context, p account.LogPrune) (int, error) {
	n, err := s.MemStore.PruneLog(ctx, p)
	if err != nil || p.Keep <= 0 {
		return n, err
	}
	return n, edit(s.MemStore, func(st *state) {
		l := st.log[p.Class]
		l.evicted -= uint64(n)
		st.log[p.Class] = l
	})
}

// beforeCountedStore's Before prune raises Evicted too.
type beforeCountedStore struct{ *MemStore }

func (s *beforeCountedStore) PruneLog(ctx context.Context, p account.LogPrune) (int, error) {
	n, err := s.MemStore.PruneLog(ctx, p)
	if err != nil || p.Before.IsZero() {
		return n, err
	}
	return n, edit(s.MemStore, func(st *state) {
		l := st.log[p.Class]
		l.evicted += uint64(n)
		st.log[p.Class] = l
	})
}

// dropEvicted is a medium that never wrote the Evicted counters to disk.
func dropEvicted(committed *state) *state {
	s := committed.clone()
	for class, l := range s.log {
		l.evicted = 0
		s.log[class] = l
	}
	return s
}

// dropActorUserAgents is a medium that never wrote ActorUserAgent to disk.
func dropActorUserAgents(committed *state) *state {
	s := committed.clone()
	for class, l := range s.log {
		for i := range l.entries {
			l.entries[i].ActorUserAgent = ""
		}
		s.log[class] = l
	}
	return s
}

// userDropsLogStore's DeleteUser also deletes the entries naming the user.
type userDropsLogStore struct{ *MemStore }

func (s *userDropsLogStore) DeleteUser(ctx context.Context, id int64) error {
	return errors.Join(s.MemStore.DeleteUser(ctx, id), edit(s.MemStore, func(st *state) {
		for class, l := range st.log {
			l.entries = slices.DeleteFunc(l.entries, func(e account.LogEntry) bool {
				return e.Event.UserID == id || e.Event.Actor.UserID == id
			})
			st.log[class] = l
		}
	}))
}

// lockedLogReadsStore's log reads take the writer lock.
type lockedLogReadsStore struct{ *MemStore }

func (s *lockedLogReadsStore) ListLog(ctx context.Context, r account.LogRange) ([]account.LogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.view().ListLog(ctx, r)
}

func (s *lockedLogReadsStore) LogStats(ctx context.Context) ([]account.LogClassStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.view().LogStats(ctx)
}

// keptAppendsStore re-appends, on each run of an Update's callback, every
// entry an earlier run of it appended.
type keptAppendsStore struct{ *faultStore }

func (s *keptAppendsStore) Update(ctx context.Context, fn func(account.Tx) error) error {
	var kept []account.LogEntry
	return s.commit(func(tx *memTx) error {
		for i := range kept {
			if err := tx.AppendLog(ctx, new(cloneEntry(&kept[i]))); err != nil {
				return err
			}
		}
		return fn(&keepingTx{memTx: tx, kept: &kept})
	})
}

type keepingTx struct {
	*memTx
	kept *[]account.LogEntry
}

func (t *keepingTx) AppendLog(ctx context.Context, e *account.LogEntry) error {
	*t.kept = append(*t.kept, cloneEntry(e))
	return t.memTx.AppendLog(ctx, e)
}

// ownContextLogStore runs AppendLog on a context of its own, which it
// cancels when the caller's has ended, so it reports a cancellation that
// is not the caller's.
type ownContextLogStore struct{ *MemStore }

func (s *ownContextLogStore) AppendLog(ctx context.Context, e *account.LogEntry) error {
	own, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	if ctx.Err() != nil {
		cancel()
	}
	if err := own.Err(); err != nil {
		return err
	}
	return s.MemStore.AppendLog(own, e)
}

// secondsLogStore keeps LogEntry.At to whole seconds.
type secondsLogStore struct{ *MemStore }

func (s *secondsLogStore) AppendLog(ctx context.Context, e *account.LogEntry) error {
	cp := cloneEntry(e)
	cp.At = cp.At.Truncate(time.Second)
	err := s.MemStore.AppendLog(ctx, &cp)
	e.Event.Seq = cp.Event.Seq
	return err
}
