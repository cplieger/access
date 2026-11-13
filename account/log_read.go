package account

import (
	"cmp"
	"context"
	"slices"

	"github.com/cplieger/access"
)

// The SecurityLog page sizes.
const (
	DefaultLogPage = 50  // a LogFilter's zero Limit
	MaxLogPage     = 500 // the largest Limit, and the size of each store read
)

// maxSeq is the largest Seq a store assigns (rule 22: JSON's exact
// integer range).
const maxSeq = 1<<53 - 1

// LogFilter narrows SecurityLog; the zero value is the newest DefaultLogPage
// entries of every kind, app entries included.
type LogFilter struct {
	Kinds               []EventKind // library or app kinds; nil is every kind
	AfterSeq, BeforeSeq uint64      // exclusive bounds; 0 is unbounded; neither sets the order
	UserID              int64       // the subject (Event.UserID); 0 is every entry
	ActorUserID         int64       // Event.Actor.UserID; 0 is any
	ActorKeyID          int64       // Event.Actor.KeyID; 0 is any
	Limit               int         // 0 is DefaultLogPage; at most MaxLogPage
	OldestFirst         bool        // ascending Seq; false is newest first
}

// LogPage is one SecurityLog answer: the matching entries, and every
// class's count and cap evictions, read from the same store as the page.
type LogPage struct {
	Entries []LogEntry
	Classes []LogClassStats // one per LogClasses() value; a class never written has zero counts
}

// SecurityLog returns the entries matching f, newest first, or oldest
// first when f.OldestFirst is set, at most f.Limit of them, and every
// class's stats. It admits what Users admits: a full session or an
// admin-scope key whose Policy allows OpListUsers. A refused principal
// never learns whether f is valid; an invalid f is a *LogFilterError,
// refused before any store read. It reads outside Update, so it never
// waits on a commit.
func (s *Service) SecurityLog(ctx context.Context, p access.Principal, f LogFilter) (LogPage, error) { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	if err := s.admitAdminScope(p); err != nil {
		return LogPage{}, err
	}
	if err := s.policy.Authorize(ctx, Decision{Op: OpListUsers, Actor: As(p)}); err != nil {
		return LogPage{}, err
	}
	if err := f.check(); err != nil {
		return LogPage{}, err
	}
	entries, err := s.readLog(ctx, &f)
	if err != nil {
		return LogPage{}, storeErr(err)
	}
	stats, err := s.store.LogStats(ctx)
	if err != nil {
		return LogPage{}, storeErr(err)
	}
	return LogPage{Entries: entries, Classes: everyClass(stats)}, nil
}

func (f *LogFilter) check() error {
	switch {
	case f.Limit < 0 || f.Limit > MaxLogPage:
		return &LogFilterError{Reason: ReasonLogLimit}
	case f.AfterSeq > maxSeq || f.BeforeSeq > maxSeq ||
		(f.AfterSeq != 0 && f.BeforeSeq != 0 && f.AfterSeq+1 >= f.BeforeSeq):
		return &LogFilterError{Reason: ReasonLogRange}
	case slices.ContainsFunc(f.Kinds, func(k EventKind) bool { return !slices.Contains(EventKinds(), k) && !isAppKind(string(k)) }):
		return &LogFilterError{Reason: ReasonLogKind}
	case f.UserID < 0 || f.ActorUserID < 0 || f.ActorKeyID < 0:
		return &LogFilterError{Reason: ReasonLogID}
	}
	return nil
}

func (f *LogFilter) matches(e *LogEntry) bool {
	return (len(f.Kinds) == 0 || slices.Contains(f.Kinds, e.Event.Kind)) &&
		(f.UserID == 0 || e.Event.UserID == f.UserID) &&
		(f.ActorUserID == 0 || e.Event.Actor.UserID == f.ActorUserID) &&
		(f.ActorKeyID == 0 || e.Event.Actor.KeyID == f.ActorKeyID)
}

// readLog pages through the store in f's order from its bound, MaxLogPage
// entries a read, until f.Limit entries match or the range ends. Entries
// are immutable, so a prune between reads only ends the range sooner.
func (s *Service) readLog(ctx context.Context, f *LogFilter) ([]LogEntry, error) {
	limit := cmp.Or(f.Limit, DefaultLogPage)
	r := LogRange{AfterSeq: f.AfterSeq, BeforeSeq: f.BeforeSeq, Limit: MaxLogPage, Descending: !f.OldestFirst}
	out := []LogEntry{}
	for {
		page, err := s.store.ListLog(ctx, r)
		if err != nil {
			return nil, err
		}
		if out = f.take(out, page, limit); len(out) == limit || len(page) < MaxLogPage {
			return out, nil
		}
		if last := page[len(page)-1].Event.Seq; r.Descending {
			r.BeforeSeq = last
		} else {
			r.AfterSeq = last
		}
	}
}

// take appends to out page's entries that match f, until out holds limit.
func (f *LogFilter) take(out, page []LogEntry, limit int) []LogEntry {
	for i := range page {
		if len(out) == limit {
			break
		}
		if f.matches(&page[i]) {
			out = append(out, page[i])
		}
	}
	return out
}

// everyClass is stats filled to one row per LogClasses value, in order.
func everyClass(stats []LogClassStats) []LogClassStats {
	out := make([]LogClassStats, 0, len(LogClasses()))
	for _, c := range LogClasses() {
		row := LogClassStats{Class: c}
		if i := slices.IndexFunc(stats, func(st LogClassStats) bool { return st.Class == c }); i >= 0 {
			row = stats[i]
		}
		out = append(out, row)
	}
	return out
}
