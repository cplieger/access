package accesstest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access/account"
)

// logPage is the Limit the suite's whole-log reads pass; no case holds more.
const logPage = 10_000

// logClause is one clause of rule 22 and the subtest that pins it.
type logClause struct {
	run    func(t *testing.T)
	name   string
	clause string
}

// logClauses is rule 22's clause table, one row per clause of account's
// package doc, in its order; logClauseVariants holds each row's red-checks.
func (c *contract) logClauses() []logClause {
	return []logClause{
		{c.seqIncreasing, "seq_increasing", "AppendLog assigns Event.Seq in commit order; ascending ListLog is append order"},
		{c.seqVisibleInOrder, "seq_visible_in_order", "a reader that sees an entry already sees every committed entry with a smaller Seq"},
		{c.seqNeverReused, "seq_never_reused", "a Seq is never assigned to two committed entries, after any prune"},
		{c.seqNeverReusedReopen, "seq_never_reused_reopen", "a Seq is never assigned to two committed entries, across a close and a reopen"},
		{c.seqBound, "seq_bound", "every Seq is a positive integer no larger than 2^53 − 1"},
		{c.seqRolledBack, "seq_rolled_back", "an appended entry rolls back with its Update; gaps are allowed"},
		{c.seqReRun, "seq_re_run", "a re-run callback leaves only its last run's entries"},
		{c.listRange, "list_range", "ListLog returns exactly the committed entries in its open range, in the asked order, at most Limit"},
		{c.listCopies, "list_copies", "an entry reads back as written, and reads return deep copies (rules 2 and 20)"},
		{c.pruneClass, "prune_class", "PruneLog never removes an entry of another class"},
		{c.pruneKeep, "prune_keep", "a Keep prune removes each entry beyond the newest Keep of the class, lowest Seq first"},
		{c.pruneBefore, "prune_before", "a Before prune removes each entry with At before Before, lowest Seq first"},
		{c.pruneLimit, "prune_limit", "PruneLog removes never more than Limit and returns the count"},
		{c.pruneOneCriterion, "prune_one_criterion", "PruneLog refuses a LogPrune with both Keep and Before set, or neither"},
		{c.statsCount, "stats_count", "LogStats returns, per class that has ever held an entry, the committed Count, in LogClasses order"},
		{c.statsEvicted, "stats_evicted", "a Keep prune adds its count to Evicted in the same Update; nothing else changes Evicted"},
		{c.statsReopen, "stats_reopen", "Evicted and Count survive a close and a reopen"},
		{c.deleteUserKeeps, "delete_user_keeps", "no other SPI method removes or changes an entry: DeleteUser's cascade deletes none"},
		{c.listNeverWaits, "list_never_waits", "ListLog and LogStats never wait on a write (rule 16)"},
	}
}

// securityLog: rule 22.
func (c *contract) securityLog(t *testing.T) {
	for _, cl := range c.logClauses() {
		t.Run(cl.name, func(t *testing.T) {
			cl.run(t)
			if t.Failed() {
				t.Logf("rule 22 clause: %s", cl.clause)
			}
		})
	}
}

// logEntry is an entry of class with a kind of that class, two session IDs
// and an IP.
func logEntry(class account.LogClass, at time.Time) *account.LogEntry {
	kind := account.EventKeyMinted
	if class == account.LogClassSession {
		kind = account.EventSignedIn
	}
	return &account.LogEntry{
		At:    at,
		Class: class,
		Event: account.Event{At: at, Kind: kind, UserID: 1, SessionIDs: []string{fresh("sid"), fresh("sid")}},
		IP:    netip.MustParseAddr(ipA),
	}
}

func mustAppend(t *testing.T, s account.Store, e *account.LogEntry) uint64 {
	t.Helper()
	if err := s.AppendLog(t.Context(), e); err != nil {
		t.Fatalf("AppendLog: %v", err)
	}
	return e.Event.Seq
}

// appendN appends n entries of class at at and returns their Seqs.
func appendN(t *testing.T, s account.Store, class account.LogClass, at time.Time, n int) []uint64 {
	t.Helper()
	seqs := make([]uint64, n)
	for i := range seqs {
		seqs[i] = mustAppend(t, s, logEntry(class, at))
	}
	return seqs
}

func listLog(t *testing.T, s account.Store, r account.LogRange) []account.LogEntry {
	t.Helper()
	got, err := s.ListLog(t.Context(), r)
	if err != nil {
		t.Fatalf("ListLog(%+v): %v", r, err)
	}
	return got
}

// wholeLog returns every committed entry in ascending Seq.
func wholeLog(t *testing.T, s account.Store) []account.LogEntry {
	t.Helper()
	return listLog(t, s, account.LogRange{Limit: logPage})
}

func seqsOf(entries []account.LogEntry) []uint64 {
	out := make([]uint64, len(entries))
	for i := range entries {
		out[i] = entries[i].Event.Seq
	}
	return out
}

// classSeqs returns the Seqs the log holds for class, ascending.
func classSeqs(t *testing.T, s account.Store, class account.LogClass) []uint64 {
	t.Helper()
	var out []uint64
	entries := wholeLog(t, s)
	for i := range entries {
		if entries[i].Class == class {
			out = append(out, entries[i].Event.Seq)
		}
	}
	return out
}

func mustPrune(t *testing.T, s account.Store, p account.LogPrune) int {
	t.Helper()
	n, err := s.PruneLog(t.Context(), p)
	if err != nil {
		t.Fatalf("PruneLog(%+v): %v", p, err)
	}
	return n
}

// pruneAll removes every entry of class by age.
func pruneAll(t *testing.T, s account.Store, class account.LogClass) int {
	t.Helper()
	return mustPrune(t, s, account.LogPrune{Class: class, Before: epoch.Add(1000 * time.Hour), Limit: logPage})
}

// stats returns LogStats keyed by class, failing on a class listed twice or
// out of LogClasses order.
func stats(t *testing.T, s account.Store) map[account.LogClass]account.LogClassStats {
	t.Helper()
	got, err := s.LogStats(t.Context())
	if err != nil {
		t.Fatalf("LogStats: %v", err)
	}
	out := map[account.LogClass]account.LogClassStats{}
	last := -1
	for _, st := range got {
		i := slices.Index(account.LogClasses(), st.Class)
		if i <= last {
			t.Fatalf("LogStats = %+v, want each class once, in LogClasses order", got)
		}
		last, out[st.Class] = i, st
	}
	return out
}

func (c *contract) seqIncreasing(t *testing.T) {
	s := c.store(t)
	seqs := append(appendN(t, s, account.LogClassChange, epoch, 2), appendN(t, s, account.LogClassSession, epoch, 1)...)
	for i, seq := range seqs {
		if seq == 0 || (i > 0 && seq <= seqs[i-1]) {
			t.Fatalf("three sequential appends got Seqs %v, want positive and increasing", seqs)
		}
	}
	if got := seqsOf(wholeLog(t, s)); !slices.Equal(got, seqs) {
		t.Errorf("ascending ListLog = %v, want append order %v", got, seqs)
	}
}

// seqVisibleInOrder polls ListLog from the largest Seq it saw while eight
// writers append, so an entry committed after a larger Seq was visible
// would never be polled.
func (c *contract) seqVisibleInOrder(t *testing.T) {
	const writers, perWriter = 8, 50
	s, ctx := c.store(t), t.Context()
	var running atomic.Int64
	running.Store(writers)
	done := make(chan struct{})
	go func() {
		defer close(done)
		raceN(writers, func(int) {
			defer running.Add(-1)
			for range perWriter {
				if err := s.Update(ctx, func(tx account.Tx) error { return tx.AppendLog(ctx, logEntry(account.LogClassChange, epoch)) }); err != nil {
					t.Errorf("Update: %v", err)
					return
				}
			}
		})
	}()
	p := &logPoller{t: t, s: s, seen: map[uint64]bool{}}
	var pollErr error
	for pollErr == nil && running.Load() > 0 {
		pollErr = p.poll()
		runtime.Gosched()
	}
	<-done
	if err := errors.Join(pollErr, p.poll()); err != nil {
		t.Fatalf("ListLog: %v", err)
	}
	var missed []uint64
	for _, seq := range seqsOf(wholeLog(t, s)) {
		if !p.seen[seq] {
			missed = append(missed, seq)
		}
	}
	if len(missed) > 0 {
		t.Errorf("a reader catching up from its largest Seq never saw %v: they committed after a larger Seq was visible", missed)
	}
}

// logPoller reads the log from the largest Seq it has seen.
type logPoller struct {
	t    *testing.T
	s    account.Store
	seen map[uint64]bool
	last uint64
}

func (p *logPoller) poll() error {
	got, err := p.s.ListLog(p.t.Context(), account.LogRange{AfterSeq: p.last, Limit: logPage})
	for _, seq := range seqsOf(got) {
		if seq <= p.last {
			p.t.Errorf("ListLog{AfterSeq: %d} returned Seq %d", p.last, seq)
		}
		p.seen[seq] = true
	}
	for seq := range p.seen {
		p.last = max(p.last, seq)
	}
	return err
}

func (c *contract) seqNeverReused(t *testing.T) {
	s := c.store(t)
	seqs := appendN(t, s, account.LogClassChange, epoch, 3)
	if n := pruneAll(t, s, account.LogClassChange); n != 3 {
		t.Fatalf("pruning every entry removed %d, want 3", n)
	}
	if seq := mustAppend(t, s, logEntry(account.LogClassChange, epoch)); seq <= slices.Max(seqs) {
		t.Errorf("after a prune of every entry, the next append got Seq %d, want larger than %d", seq, slices.Max(seqs))
	}
}

func (c *contract) seqNeverReusedReopen(t *testing.T) {
	c.needReopen(t, "rule 22 (Seq never reused across a reopen)")
	s := c.store(t)
	seqs := appendN(t, s, account.LogClassChange, epoch, 3)
	pruneAll(t, s, account.LogClassChange)
	s = c.reopen(t, "rule 22", s)
	if seq := mustAppend(t, s, logEntry(account.LogClassChange, epoch)); seq <= slices.Max(seqs) {
		t.Errorf("after a prune and a reopen, the next append got Seq %d, want larger than %d", seq, slices.Max(seqs))
	}
}

func (c *contract) seqBound(t *testing.T) {
	s := c.store(t)
	seqs := append(appendN(t, s, account.LogClassChange, epoch, 3), appendN(t, s, account.LogClassSession, epoch, 3)...)
	for _, seq := range append(seqs, seqsOf(wholeLog(t, s))...) {
		if seq == 0 || seq > maxID {
			t.Errorf("Seq %d, want in [1, 2^53 − 1]", seq)
		}
	}
}

func (c *contract) seqRolledBack(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	first := mustAppend(t, s, logEntry(account.LogClassChange, epoch))
	err := s.Update(ctx, func(tx account.Tx) error {
		return errors.Join(tx.AppendLog(ctx, logEntry(account.LogClassChange, epoch)), errContract)
	})
	if !errors.Is(err, errContract) {
		t.Fatalf("a failing Update = %v, want its callback's error", err)
	}
	if got := seqsOf(wholeLog(t, s)); !slices.Equal(got, []uint64{first}) {
		t.Errorf("after a rolled-back append the log holds %v, want only %d", got, first)
	}
	if next := mustAppend(t, s, logEntry(account.LogClassSession, epoch)); next <= first {
		t.Errorf("the append after a rolled-back one got Seq %d, want larger than %d", next, first)
	}
}

// seqReRun shares one grouped commit between one appending Update and
// eight whose callbacks append and fail, for rounds rounds.
func (c *contract) seqReRun(t *testing.T) {
	const failing = 8
	s, f := c.faulty(t, "rule 22 (re-run)")
	ctx := t.Context()
	for round := range rounds {
		kind := account.EventKind(fmt.Sprintf("rerun.%d", round))
		calls := make([]func(), 0, 1+failing)
		calls = append(calls, func() {
			if err := s.Update(ctx, func(tx account.Tx) error {
				e := logEntry(account.LogClassChange, epoch)
				e.Event.Kind = kind
				return tx.AppendLog(ctx, e)
			}); err != nil {
				t.Errorf("round %d: the appending Update = %v", round, err)
			}
		})
		for range failing {
			calls = append(calls, func() {
				_ = s.Update(ctx, func(tx account.Tx) error {
					return errors.Join(tx.AppendLog(ctx, logEntry(account.LogClassChange, epoch)), errContract)
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
	}
	entries := wholeLog(t, s)
	if seqs := seqsOf(entries); len(slices.Compact(slices.Clone(seqs))) != len(seqs) {
		t.Errorf("Seqs %v repeat", seqs)
	}
	perRound := map[account.EventKind]int{}
	for i := range entries {
		perRound[entries[i].Event.Kind]++
	}
	if len(entries) != rounds || len(perRound) != rounds {
		t.Errorf("%d rounds of one appending Update grouped with %d failing ones left %d entries over %d rounds, want exactly one per round", rounds, failing, len(entries), len(perRound))
	}
}

func (c *contract) listRange(t *testing.T) {
	s := c.store(t)
	seq := append(appendN(t, s, account.LogClassChange, epoch, 3), appendN(t, s, account.LogClassSession, epoch, 2)...)
	for _, tc := range []struct {
		name string
		want []uint64
		r    account.LogRange
	}{
		{"exclusive_bounds", seq[1:3], account.LogRange{AfterSeq: seq[0], BeforeSeq: seq[3], Limit: logPage}},
		{"exclusive_bounds_descending", []uint64{seq[2], seq[1]}, account.LogRange{AfterSeq: seq[0], BeforeSeq: seq[3], Limit: logPage, Descending: true}},
		{"before_zero_unbounded", seq[2:], account.LogRange{AfterSeq: seq[1], Limit: logPage}},
		{"limit_ascending", seq[:2], account.LogRange{Limit: 2}},
		{"limit_descending", []uint64{seq[4], seq[3]}, account.LogRange{Limit: 2, Descending: true}},
		{"before_only_descending", []uint64{seq[1], seq[0]}, account.LogRange{BeforeSeq: seq[2], Limit: logPage, Descending: true}},
		{"after_last", nil, account.LogRange{AfterSeq: seq[4], Limit: logPage}},
	} {
		if got := seqsOf(listLog(t, s, tc.r)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: ListLog(%+v) = %v, want %v", tc.name, tc.r, got, tc.want)
		}
	}
}

func (c *contract) listCopies(t *testing.T) {
	s := c.store(t)
	e := logEntry(account.LogClassChange, epoch)
	want := slices.Clone(e.Event.SessionIDs)
	mustAppend(t, s, e)
	e.Event.SessionIDs[0] = mutated
	got := wholeLog(t, s)
	if len(got) != 1 || !slices.Equal(got[0].Event.SessionIDs, want) {
		t.Fatalf("after the caller changed its SessionIDs the stored entry reads %v, want %v", got, want)
	}
	got[0].Event.SessionIDs[1] = mutated
	if again := wholeLog(t, s); !slices.Equal(again[0].Event.SessionIDs, want) {
		t.Errorf("after the reader changed a returned SessionIDs the stored entry reads %v, want %v", again[0].Event.SessionIDs, want)
	}
}

func (c *contract) pruneClass(t *testing.T) {
	s := c.store(t)
	appendN(t, s, account.LogClassChange, epoch, 3)
	sessions := appendN(t, s, account.LogClassSession, epoch, 3)
	mustPrune(t, s, account.LogPrune{Class: account.LogClassChange, Keep: 1, Limit: logPage})
	if got := classSeqs(t, s, account.LogClassSession); !slices.Equal(got, sessions) {
		t.Errorf("a Keep prune of the change class left the session class %v, want %v", got, sessions)
	}
	kept := classSeqs(t, s, account.LogClassChange)
	pruneAll(t, s, account.LogClassSession)
	if got := classSeqs(t, s, account.LogClassChange); !slices.Equal(got, kept) {
		t.Errorf("a Before prune of the session class left the change class %v, want %v", got, kept)
	}
}

func (c *contract) pruneKeep(t *testing.T) {
	s := c.store(t)
	seqs := appendN(t, s, account.LogClassChange, epoch, 5)
	p := account.LogPrune{Class: account.LogClassChange, Keep: 2, Limit: logPage}
	if n := mustPrune(t, s, p); n != 3 {
		t.Errorf("Keep 2 of 5 removed %d, want 3", n)
	}
	if got := classSeqs(t, s, account.LogClassChange); !slices.Equal(got, seqs[3:]) {
		t.Errorf("Keep 2 left %v, want the newest two %v", got, seqs[3:])
	}
	if n := mustPrune(t, s, p); n != 0 {
		t.Errorf("Keep 2 of 2 removed %d, want 0", n)
	}
}

func (c *contract) pruneBefore(t *testing.T) {
	s := c.store(t)
	seqs := make([]uint64, 0, 4)
	for _, minutes := range []int{3, 0, 2, 1} {
		seqs = append(seqs, mustAppend(t, s, logEntry(account.LogClassChange, epoch.Add(time.Duration(minutes)*time.Minute))))
	}
	n := mustPrune(t, s, account.LogPrune{Class: account.LogClassChange, Before: epoch.Add(2 * time.Minute), Limit: logPage})
	if n != 2 {
		t.Errorf("a Before prune at minute 2 removed %d, want the 2 entries before it", n)
	}
	if got, want := classSeqs(t, s, account.LogClassChange), []uint64{seqs[0], seqs[2]}; !slices.Equal(got, want) {
		t.Errorf("a Before prune at minute 2 left %v, want %v (minutes 3 and 2)", got, want)
	}
}

func (c *contract) pruneLimit(t *testing.T) {
	s := c.store(t)
	seqs := appendN(t, s, account.LogClassChange, epoch, 5)
	if n := mustPrune(t, s, account.LogPrune{Class: account.LogClassChange, Keep: 1, Limit: 2}); n != 2 {
		t.Errorf("Keep 1 of 5 with Limit 2 removed %d, want 2", n)
	}
	if got := classSeqs(t, s, account.LogClassChange); !slices.Equal(got, seqs[2:]) {
		t.Errorf("Keep 1 with Limit 2 left %v, want %v", got, seqs[2:])
	}
	if n := mustPrune(t, s, account.LogPrune{Class: account.LogClassChange, Before: epoch.Add(time.Hour), Limit: 2}); n != 2 {
		t.Errorf("a Before prune of 3 with Limit 2 removed %d, want 2", n)
	}
	if got := classSeqs(t, s, account.LogClassChange); !slices.Equal(got, seqs[4:]) {
		t.Errorf("a Before prune with Limit 2 left %v, want %v", got, seqs[4:])
	}
}

func (c *contract) pruneOneCriterion(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	seqs := appendN(t, s, account.LogClassChange, epoch, 3)
	for name, p := range map[string]account.LogPrune{
		"both":    {Class: account.LogClassChange, Keep: 1, Before: epoch.Add(time.Hour), Limit: logPage},
		"neither": {Class: account.LogClassChange, Limit: logPage},
	} {
		if n, err := s.PruneLog(ctx, p); err == nil {
			t.Errorf("%s: PruneLog(%+v) = (%d, nil), want an error", name, p, n)
		}
		if got := classSeqs(t, s, account.LogClassChange); !slices.Equal(got, seqs) {
			t.Errorf("%s: a refused PruneLog left %v, want %v", name, got, seqs)
		}
	}
}

func (c *contract) statsCount(t *testing.T) {
	s := c.store(t)
	if got := stats(t, s); len(got) != 0 {
		t.Errorf("an empty store's LogStats = %v, want none", got)
	}
	appendN(t, s, account.LogClassSession, epoch, 2)
	appendN(t, s, account.LogClassChange, epoch, 3)
	mustPrune(t, s, account.LogPrune{Class: account.LogClassChange, Keep: 2, Limit: logPage})
	got := stats(t, s)
	for _, class := range account.LogClasses() {
		if want := len(classSeqs(t, s, class)); got[class].Count != want || got[class].Class != class {
			t.Errorf("LogStats for %s = %+v, want Count %d, what ListLog holds", class, got[class], want)
		}
	}
	pruneAll(t, s, account.LogClassSession)
	if st, ok := stats(t, s)[account.LogClassSession]; !ok || st.Count != 0 {
		t.Errorf("after its last entry was pruned, the session class's LogStats = (%+v, %t), want Count 0, still listed", st, ok)
	}
}

func (c *contract) statsEvicted(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	appendN(t, s, account.LogClassChange, epoch, 4)
	appendN(t, s, account.LogClassSession, epoch, 2)
	n := mustPrune(t, s, account.LogPrune{Class: account.LogClassChange, Keep: 1, Limit: logPage})
	got := stats(t, s)
	if n != 3 || got[account.LogClassChange].Evicted != 3 {
		t.Errorf("a Keep prune removing %d left change Evicted %d, want 3 and 3", n, got[account.LogClassChange].Evicted)
	}
	if got[account.LogClassSession].Evicted != 0 {
		t.Errorf("a Keep prune of the change class raised the session class's Evicted to %d", got[account.LogClassSession].Evicted)
	}
	appendN(t, s, account.LogClassChange, epoch, 2)
	pruneAll(t, s, account.LogClassChange)
	if e := stats(t, s)[account.LogClassChange].Evicted; e != 3 {
		t.Errorf("a Before prune changed Evicted to %d, want 3", e)
	}
	appendN(t, s, account.LogClassChange, epoch, 3)
	err := s.Update(ctx, func(tx account.Tx) error {
		_, err := tx.PruneLog(ctx, account.LogPrune{Class: account.LogClassChange, Keep: 1, Limit: logPage})
		return errors.Join(err, errContract)
	})
	if !errors.Is(err, errContract) {
		t.Fatalf("a failing Update = %v, want its callback's error", err)
	}
	if e := stats(t, s)[account.LogClassChange].Evicted; e != 3 {
		t.Errorf("a rolled-back Keep prune changed Evicted to %d, want 3", e)
	}
}

func (c *contract) statsReopen(t *testing.T) {
	c.needReopen(t, "rule 22 (Evicted and Count across a reopen)")
	s := c.store(t)
	appendN(t, s, account.LogClassChange, epoch, 4)
	appendN(t, s, account.LogClassSession, epoch, 1)
	mustPrune(t, s, account.LogPrune{Class: account.LogClassChange, Keep: 1, Limit: logPage})
	want := stats(t, s)
	got := stats(t, c.reopen(t, "rule 22", s))
	for _, class := range account.LogClasses() {
		if got[class] != want[class] {
			t.Errorf("after a reopen, %s's LogStats = %+v, want %+v", class, got[class], want[class])
		}
	}
}

func (c *contract) deleteUserKeeps(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	subject, actor := mustUser(t, s, "log-subject"), mustUser(t, s, "log-actor")
	for _, class := range account.LogClasses() {
		e := logEntry(class, epoch)
		e.Event.UserID, e.Event.Actor = subject.ID, account.EventActor{UserID: actor.ID, SessionID: fresh("sid")}
		mustAppend(t, s, e)
	}
	mustPrune(t, s, account.LogPrune{Class: account.LogClassChange, Keep: 1, Limit: logPage})
	wantLog, wantStats := wholeLog(t, s), stats(t, s)
	check(t, "DeleteUser(subject)", s.DeleteUser(ctx, subject.ID))
	check(t, "DeleteUser(actor)", s.DeleteUser(ctx, actor.ID))
	if got := wholeLog(t, s); !slices.Equal(seqsOf(got), seqsOf(wantLog)) {
		t.Errorf("deleting the subject and the actor left the log %v, want %v", seqsOf(got), seqsOf(wantLog))
	}
	got := stats(t, s)
	for _, class := range account.LogClasses() {
		if got[class] != wantStats[class] {
			t.Errorf("deleting the users changed %s's LogStats to %+v, want %+v", class, got[class], wantStats[class])
		}
	}
}

// listNeverWaits: rule 16's case with ListLog and LogStats as the reads.
func (c *contract) listNeverWaits(t *testing.T) {
	s, ctx := c.store(t), t.Context()
	committed := mustAppend(t, s, logEntry(account.LogClassChange, epoch))
	written, release, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		result <- s.Update(ctx, func(tx account.Tx) error {
			if err := tx.AppendLog(ctx, logEntry(account.LogClassChange, epoch)); err != nil {
				return err
			}
			close(written)
			<-release
			return nil
		})
	}()
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	select {
	case <-written:
	case <-time.After(5 * time.Second):
		t.Fatal("the Update callback never appended its entry")
	}
	logReadsBeforeCommit(t, s, committed)
	releaseOnce()
	if err := <-result; err != nil {
		t.Fatalf("Update: %v", err)
	}
}

// logReadsBeforeCommit requires ListLog and LogStats to return, within
// 1 s, the log holding only committed while an Update is in progress.
func logReadsBeforeCommit(t *testing.T, s account.Store, committed uint64) {
	t.Helper()
	ctx := t.Context()
	reads := map[string]func() error{
		"ListLog": func() error {
			if got, err := s.ListLog(ctx, account.LogRange{Limit: logPage}); err != nil || !slices.Equal(seqsOf(got), []uint64{committed}) {
				return fmt.Errorf("= (%v, %v), want only the committed %d", seqsOf(got), err, committed)
			}
			return nil
		},
		"LogStats": func() error {
			if got, err := s.LogStats(ctx); err != nil || len(got) != 1 || got[0].Count != 1 {
				return fmt.Errorf("= (%+v, %v), want the committed change class with Count 1", got, err)
			}
			return nil
		},
	}
	for name, read := range reads {
		var err error
		if !within(time.Second, func() { err = read() }) {
			t.Errorf("%s waited over 1 s on an in-progress Update", name)
			continue
		}
		if err != nil {
			t.Errorf("%s during an in-progress Update %v", name, err)
		}
	}
}

// logCalls is rule 18's LogStore calls.
func logCalls(tx account.Tx) []namedCall {
	return []namedCall{
		{func(ctx context.Context) error { return tx.AppendLog(ctx, logEntry(account.LogClassChange, epoch)) }, "AppendLog"},
		{func(ctx context.Context) error { _, err := tx.ListLog(ctx, account.LogRange{Limit: 10}); return err }, "ListLog"},
		{func(ctx context.Context) error { _, err := tx.LogStats(ctx); return err }, "LogStats"},
		{func(ctx context.Context) error {
			_, err := tx.PruneLog(ctx, account.LogPrune{Class: account.LogClassChange, Keep: 1, Limit: 10})
			return err
		}, "PruneLog"},
	}
}

// logTimeRoundTrip appends one entry whose At and Event.At are at and
// reads both back through same (rule 11).
func logTimeRoundTrip(t *testing.T, s account.Store, at time.Time, same func(string, time.Time)) {
	t.Helper()
	e := logEntry(account.LogClassChange, at)
	mustAppend(t, s, e)
	got := wholeLog(t, s)
	if len(got) != 1 {
		t.Fatalf("ListLog after one append = %d entries, want 1", len(got))
	}
	same("LogEntry.At", got[0].At)
	same("LogEntry.Event.At", got[0].Event.At)
}
