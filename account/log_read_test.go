package account_test

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// appendEvents appends one entry per event straight through s, in order,
// signed_in in the session class and every other kind in the change class,
// and returns their Seqs.
func appendEvents(t testing.TB, s account.Store, evs ...account.Event) []uint64 {
	t.Helper()
	var seqs []uint64
	err := s.Update(t.Context(), func(tx account.Tx) error {
		seqs = make([]uint64, 0, len(evs))
		for _, ev := range evs {
			e := account.LogEntry{At: time.Now().Truncate(time.Millisecond), Class: account.LogClassChange, Event: ev}
			if ev.Kind == account.EventSignedIn {
				e.Class = account.LogClassSession
			}
			if err := tx.AppendLog(t.Context(), &e); err != nil {
				return err
			}
			seqs = append(seqs, e.Event.Seq)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	return seqs
}

// pageSeqs is the Seqs of a page's entries, in page order.
func pageSeqs(page account.LogPage) []uint64 {
	seqs := make([]uint64, 0, len(page.Entries))
	for i := range page.Entries {
		seqs = append(seqs, page.Entries[i].Event.Seq)
	}
	return seqs
}

// pick is the Seqs at the given positions of seqs.
func pick(seqs []uint64, at ...int) []uint64 {
	out := make([]uint64, 0, len(at))
	for _, i := range at {
		out = append(out, seqs[i])
	}
	return out
}

// logReads is the names of the log reads among calls.
func logReads(calls []storeCall) []string {
	var names []string
	for _, c := range calls {
		if c.name == "ListLog" || c.name == "LogStats" {
			names = append(names, c.name)
		}
	}
	return names
}

func filterReason(err error) string {
	if fe, ok := errors.AsType[*account.LogFilterError](err); ok && errors.Is(err, account.ErrLogFilterInvalid) {
		return fe.Reason
	}
	return ""
}

func TestSecurityLog(t *testing.T) {
	t.Parallel()
	t.Run("gate", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, keyOptions(options{}, nil))
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		user := mustUser(t, f.mem, "alice", access.RoleUser)
		for _, tc := range []struct {
			p    func(t *testing.T) access.Principal
			want error
			name string
		}{
			{name: "admin_session", p: func(t *testing.T) access.Principal {
				return f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
			}},
			{name: "admin_scope_key", p: func(t *testing.T) access.Principal { return f.keyPrincipal(t, admin, scopeAdmin) }},
			{name: "user_session", want: account.ErrPolicyRefused, p: func(t *testing.T) access.Principal {
				return f.sessionPrincipal(t, user, access.SessionFull, time.Now())
			}},
			{name: "recovery_session", want: account.ErrSessionRequired, p: func(t *testing.T) access.Principal {
				return f.sessionPrincipal(t, admin, access.SessionRecovery, time.Now())
			}},
			{name: "key_without_scope", want: account.ErrScopeRequired, p: func(t *testing.T) access.Principal { return f.keyPrincipal(t, admin, scopeUsers) }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := f.svc.SecurityLog(t.Context(), tc.p(t), account.LogFilter{})
				if (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
					t.Errorf("SecurityLog = %v, want %v", err, tc.want)
				}
			})
		}
	})
	t.Run("gate_before_validation", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		user := mustUser(t, f.mem, "alice", access.RoleUser)
		p := f.sessionPrincipal(t, user, access.SessionFull, time.Now())
		if _, err := f.svc.SecurityLog(t.Context(), p, account.LogFilter{Limit: -1}); !errors.Is(err, account.ErrPolicyRefused) || errors.Is(err, account.ErrLogFilterInvalid) {
			t.Errorf("a non-admin's invalid filter = %v, want ErrPolicyRefused and not ErrLogFilterInvalid", err)
		}
	})
	t.Run("rules_invalid", func(t *testing.T) {
		t.Parallel()
		var invalid atomic.Bool
		fs := newFaultStore()
		f := newFixture(t, options{store: fs, rules: func() account.Rules {
			if invalid.Load() {
				return account.Rules{Breach: account.BreachFailOpen}
			}
			return account.Rules{}
		}})
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		fs.resetRecord()
		if _, err := f.svc.SecurityLog(t.Context(), p, account.LogFilter{}); err != nil {
			t.Fatalf("SecurityLog under valid Rules = %v", err)
		}
		if got := logReads(fs.recorded()); !slices.Equal(got, []string{"ListLog", "LogStats"}) {
			t.Fatalf("log reads under valid Rules = %v, want [ListLog LogStats]; the counting store does not see them", got)
		}
		invalid.Store(true)
		fs.resetRecord()
		_, err := f.svc.SecurityLog(t.Context(), p, account.LogFilter{})
		if _, ok := errors.AsType[*account.RulesError](err); !ok || !errors.Is(err, account.ErrRulesInvalid) {
			t.Errorf("SecurityLog under invalid Rules = %v, want a *RulesError matching ErrRulesInvalid", err)
		}
		if got := logReads(fs.recorded()); len(got) != 0 {
			t.Errorf("SecurityLog under invalid Rules read %v, want no log read", got)
		}
	})
	t.Run("filters", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		seqs := appendEvents(t, f.mem,
			account.Event{Kind: account.EventUserCreated, UserID: 1, Actor: account.EventActor{UserID: 9}},
			account.Event{Kind: account.EventKeyMinted, UserID: 2, Actor: account.EventActor{UserID: 9, KeyID: 5}},
			account.Event{Kind: account.EventSignedIn, UserID: 1},
			account.Event{Kind: "app.x", Actor: account.EventActor{UserID: 2, SessionID: "s"}},
			account.Event{Kind: account.EventUserCreated, UserID: 2, Actor: account.EventActor{UserID: 1}},
		)
		for _, tc := range []struct {
			name string
			f    account.LogFilter
			want []int // positions in seqs, in page order
		}{
			{"zero", account.LogFilter{}, []int{4, 3, 2, 1, 0}},
			{"kind_library", account.LogFilter{Kinds: []account.EventKind{account.EventUserCreated}}, []int{4, 0}},
			{"kind_library_and_app", account.LogFilter{Kinds: []account.EventKind{account.EventKeyMinted, "app.x"}}, []int{3, 1}},
			{"user", account.LogFilter{UserID: 1}, []int{2, 0}},
			{"actor_user", account.LogFilter{ActorUserID: 9}, []int{1, 0}},
			{"actor_key", account.LogFilter{ActorKeyID: 5}, []int{1}},
			{"after_seq", account.LogFilter{AfterSeq: seqs[1]}, []int{4, 3, 2}},
			{"oldest_first", account.LogFilter{OldestFirst: true}, []int{0, 1, 2, 3, 4}},
			{"after_seq_oldest_first", account.LogFilter{AfterSeq: seqs[1], OldestFirst: true}, []int{2, 3, 4}},
			{"before_seq", account.LogFilter{BeforeSeq: seqs[3]}, []int{2, 1, 0}},
			{"after_and_before", account.LogFilter{AfterSeq: seqs[0], BeforeSeq: seqs[4]}, []int{3, 2, 1}},
			{"limit", account.LogFilter{Limit: 2}, []int{4, 3}},
			{"together", account.LogFilter{Kinds: []account.EventKind{account.EventUserCreated, account.EventKeyMinted}, ActorUserID: 9, UserID: 2}, []int{1}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				page, err := f.svc.SecurityLog(t.Context(), p, tc.f)
				if err != nil {
					t.Fatalf("SecurityLog(%+v) = %v", tc.f, err)
				}
				if got, want := pageSeqs(page), pick(seqs, tc.want...); !slices.Equal(got, want) {
					t.Errorf("SecurityLog(%+v) = %v, want %v", tc.f, got, want)
				}
			})
		}
	})
	t.Run("zero_filter_newest_page", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		seqs := fill(t, f.mem, account.LogClassChange, 60, time.Now())
		page, err := f.svc.SecurityLog(t.Context(), p, account.LogFilter{})
		if err != nil {
			t.Fatalf("SecurityLog = %v", err)
		}
		want := slices.Clone(seqs[10:])
		slices.Reverse(want)
		if got := pageSeqs(page); !slices.Equal(got, want) {
			t.Errorf("zero filter = %v, want the newest 50 newest first %v", got, want)
		}
	})
	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		fs := newFaultStore()
		f := newFixture(t, options{store: fs})
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		const top = 1<<53 - 1
		for _, tc := range []struct {
			name   string
			f      account.LogFilter
			reason string // "" accepted
		}{
			{"limit_max", account.LogFilter{Limit: 500}, ""},
			{"limit_negative", account.LogFilter{Limit: -1}, account.ReasonLogLimit},
			{"limit_above_max", account.LogFilter{Limit: 501}, account.ReasonLogLimit},
			{"after_seq_top", account.LogFilter{AfterSeq: top}, ""},
			{"after_seq_above_top", account.LogFilter{AfterSeq: top + 1}, account.ReasonLogRange},
			{"before_seq_top", account.LogFilter{BeforeSeq: top}, ""},
			{"before_seq_above_top", account.LogFilter{BeforeSeq: top + 1}, account.ReasonLogRange},
			{"one_seq_between", account.LogFilter{AfterSeq: 5, BeforeSeq: 7}, ""},
			{"no_seq_between", account.LogFilter{AfterSeq: 5, BeforeSeq: 6}, account.ReasonLogRange},
			{"after_equals_before", account.LogFilter{AfterSeq: 6, BeforeSeq: 6}, account.ReasonLogRange},
			{"after_above_before", account.LogFilter{AfterSeq: 7, BeforeSeq: 6}, account.ReasonLogRange},
			{"kind_library", account.LogFilter{Kinds: []account.EventKind{account.EventSignedIn}}, ""},
			{"kind_app", account.LogFilter{Kinds: []account.EventKind{"app.x"}}, ""},
			{"kind_unknown", account.LogFilter{Kinds: []account.EventKind{"app.x", "signed_out"}}, account.ReasonLogKind},
			{"kind_uppercase_app", account.LogFilter{Kinds: []account.EventKind{"App.x"}}, account.ReasonLogKind},
			{"user_negative", account.LogFilter{UserID: -1}, account.ReasonLogID},
			{"actor_user_negative", account.LogFilter{ActorUserID: -1}, account.ReasonLogID},
			{"actor_key_negative", account.LogFilter{ActorKeyID: -1}, account.ReasonLogID},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fs.resetRecord()
				_, err := f.svc.SecurityLog(t.Context(), p, tc.f)
				if tc.reason == "" {
					if err != nil {
						t.Errorf("SecurityLog(%+v) = %v, want nil", tc.f, err)
					}
					return
				}
				if filterReason(err) != tc.reason {
					t.Errorf("SecurityLog(%+v) = %v, want a *LogFilterError with Reason %q matching ErrLogFilterInvalid", tc.f, err, tc.reason)
				}
				if got := logReads(fs.recorded()); len(got) != 0 {
					t.Errorf("a refused filter read %v, want no log read", got)
				}
			})
		}
	})
	t.Run("classes", func(t *testing.T) {
		t.Parallel()
		t.Run("never_written_class", func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, options{})
			admin := mustUser(t, f.mem, "root", access.RoleAdmin)
			p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
			fill(t, f.mem, account.LogClassChange, 2, time.Now())
			page, err := f.svc.SecurityLog(t.Context(), p, account.LogFilter{})
			if err != nil {
				t.Fatalf("SecurityLog = %v", err)
			}
			want := []account.LogClassStats{{Class: account.LogClassChange, Count: 2}, {Class: account.LogClassSession}}
			if !slices.Equal(page.Classes, want) {
				t.Errorf("Classes = %+v, want %+v", page.Classes, want)
			}
		})
		t.Run("evicted", func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, options{edit: withLogCaps(3, 2)})
			admin := mustUser(t, f.mem, "root", access.RoleAdmin)
			p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
			createUsers(t, f, 5)
			page, err := f.svc.SecurityLog(t.Context(), p, account.LogFilter{})
			if err != nil {
				t.Fatalf("SecurityLog = %v", err)
			}
			want := []account.LogClassStats{{Class: account.LogClassChange, Count: 3, Evicted: 2}, {Class: account.LogClassSession}}
			if !slices.Equal(page.Classes, want) {
				t.Errorf("Classes = %+v, want %+v", page.Classes, want)
			}
			filtered, err := f.svc.SecurityLog(t.Context(), p, account.LogFilter{Kinds: []account.EventKind{account.EventSignedIn}})
			if err != nil {
				t.Fatalf("SecurityLog(filtered) = %v", err)
			}
			if len(filtered.Entries) != 0 || !slices.Equal(filtered.Classes, page.Classes) {
				t.Errorf("filtered page %v Classes %+v, want no entries and the unfiltered Classes %+v", pageSeqs(filtered), filtered.Classes, page.Classes)
			}
		})
	})
	t.Run("store_errors", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{"ListLog", "LogStats"} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				fs := newFaultStore()
				f := newFixture(t, options{store: fs})
				admin := mustUser(t, f.mem, "root", access.RoleAdmin)
				p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
				fs.refuseCall(name, errFault)
				if _, err := f.svc.SecurityLog(t.Context(), p, account.LogFilter{}); !errors.Is(err, access.ErrAuthBackend) || !errors.Is(err, errFault) {
					t.Errorf("SecurityLog with a failing %s = %v, want access.ErrAuthBackend wrapping the store error", name, err)
				}
			})
		}
	})
	t.Run("closed", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{})
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		if err := f.svc.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown = %v", err)
		}
		if _, err := f.svc.SecurityLog(t.Context(), p, account.LogFilter{}); !errors.Is(err, account.ErrServiceClosed) {
			t.Errorf("SecurityLog after Shutdown = %v, want ErrServiceClosed", err)
		}
	})
}

// readOrderFixture is an admin principal over a log of 120 entries and
// their Seqs, oldest first.
func readOrderFixture(t *testing.T) (*account.Service, access.Principal, []uint64) {
	t.Helper()
	f := newFixture(t, options{})
	admin := mustUser(t, f.mem, "root", access.RoleAdmin)
	p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
	evs := make([]account.Event, 120)
	for i := range evs {
		evs[i] = account.Event{Kind: account.EventUserCreated}
	}
	return f.svc, p, appendEvents(t, f.mem, evs...)
}

// span is seqs[from:to], reversed when newestFirst.
func span(seqs []uint64, from, to int, newestFirst bool) []uint64 {
	out := slices.Clone(seqs[from:to])
	if newestFirst {
		slices.Reverse(out)
	}
	return out
}

func TestSecurityLogOldestFirstFromStart(t *testing.T) {
	t.Parallel()
	svc, p, seqs := readOrderFixture(t)
	for _, tc := range []struct {
		name string
		f    account.LogFilter
		want []uint64
	}{
		{"no_bound", account.LogFilter{OldestFirst: true, Limit: 50}, span(seqs, 0, 50, false)},
		{"after_first_page", account.LogFilter{OldestFirst: true, AfterSeq: seqs[49], Limit: 50}, span(seqs, 50, 100, false)},
		{"before_bound", account.LogFilter{OldestFirst: true, BeforeSeq: seqs[30], Limit: 50}, span(seqs, 0, 30, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := svc.SecurityLog(t.Context(), p, tc.f)
			if err != nil {
				t.Fatalf("SecurityLog(%+v) = %v", tc.f, err)
			}
			if got := pageSeqs(page); !slices.Equal(got, tc.want) {
				t.Errorf("SecurityLog(%+v) = %v, want %v", tc.f, got, tc.want)
			}
		})
	}
}

func TestSecurityLogBoundsDoNotSetOrder(t *testing.T) {
	t.Parallel()
	svc, p, seqs := readOrderFixture(t)
	for _, tc := range []struct {
		name string
		f    account.LogFilter
		want []uint64
	}{
		{"after_seq", account.LogFilter{AfterSeq: seqs[49], Limit: 50}, span(seqs, 70, 120, true)},
		{"before_seq", account.LogFilter{BeforeSeq: seqs[100], Limit: 50}, span(seqs, 50, 100, true)},
		{"after_and_before", account.LogFilter{AfterSeq: seqs[9], BeforeSeq: seqs[20], Limit: 50}, span(seqs, 10, 20, true)},
		{"after_and_before_oldest_first", account.LogFilter{AfterSeq: seqs[9], BeforeSeq: seqs[20], Limit: 50, OldestFirst: true}, span(seqs, 10, 20, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := svc.SecurityLog(t.Context(), p, tc.f)
			if err != nil {
				t.Fatalf("SecurityLog(%+v) = %v", tc.f, err)
			}
			if got := pageSeqs(page); !slices.Equal(got, tc.want) {
				t.Errorf("SecurityLog(%+v) = %v, want %v", tc.f, got, tc.want)
			}
		})
	}
}

func TestSecurityLogPaging(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	admin := mustUser(t, f.mem, "root", access.RoleAdmin)
	p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
	evs := make([]account.Event, 120)
	for i := range evs {
		evs[i] = account.Event{Kind: account.EventUserCreated}
		if i%3 == 2 {
			evs[i].Kind = account.EventKeyMinted
		}
	}
	seqs := appendEvents(t, f.mem, evs...)
	var matches []uint64
	for i, s := range seqs {
		if i%3 == 2 {
			matches = append(matches, s)
		}
	}
	keys := []account.EventKind{account.EventKeyMinted}
	page := func(t *testing.T, lf account.LogFilter) []uint64 {
		t.Helper()
		lf.Kinds, lf.Limit = keys, 10
		got, err := f.svc.SecurityLog(t.Context(), p, lf)
		if err != nil {
			t.Fatalf("SecurityLog(%+v) = %v", lf, err)
		}
		return pageSeqs(got)
	}
	t.Run("before_seq_newest_first", func(t *testing.T) {
		var all []uint64
		var cursor uint64
		for n := 0; ; n++ {
			got := page(t, account.LogFilter{BeforeSeq: cursor})
			if len(got) == 0 {
				break
			}
			if n == 4 || len(got) != 10 || !slices.IsSortedFunc(got, func(a, b uint64) int { return cmp.Compare(b, a) }) {
				t.Fatalf("page %d = %v, want four pages of 10 matches, newest first", n, got)
			}
			all = append(all, got...)
			cursor = got[len(got)-1]
		}
		want := slices.Clone(matches)
		slices.Reverse(want)
		if !slices.Equal(all, want) {
			t.Errorf("pages together = %v, want every match once %v", all, want)
		}
	})
	t.Run("after_seq_oldest_first", func(t *testing.T) {
		var all []uint64
		var cursor uint64
		for n := 0; ; n++ {
			got := page(t, account.LogFilter{AfterSeq: cursor, OldestFirst: true})
			if len(got) == 0 {
				break
			}
			if n == 4 || len(got) != 10 || !slices.IsSorted(got) {
				t.Fatalf("page %d = %v, want four pages of 10 matches, oldest first", n, got)
			}
			all = append(all, got...)
			cursor = got[len(got)-1]
		}
		if !slices.Equal(all, matches) {
			t.Errorf("pages together = %v, want every match once %v", all, matches)
		}
	})
	t.Run("prune_between_pages", func(t *testing.T) {
		g := newFixture(t, options{})
		gadmin := mustUser(t, g.mem, "root", access.RoleAdmin)
		gp := g.sessionPrincipal(t, gadmin, access.SessionFull, time.Now())
		gseqs := appendEvents(t, g.mem, evs...)
		first, err := g.svc.SecurityLog(t.Context(), gp, account.LogFilter{Kinds: keys, Limit: 10})
		if err != nil || len(first.Entries) != 10 {
			t.Fatalf("first page = %v, %v; want 10 entries", pageSeqs(first), err)
		}
		if err := g.mem.Update(t.Context(), func(tx account.Tx) error {
			_, err := tx.PruneLog(t.Context(), account.LogPrune{Class: account.LogClassChange, Keep: 60, Limit: 120})
			return err
		}); err != nil {
			t.Fatalf("PruneLog: %v", err)
		}
		cursor := pageSeqs(first)[9]
		var rest []uint64
		for {
			got, err := g.svc.SecurityLog(t.Context(), gp, account.LogFilter{Kinds: keys, Limit: 10, BeforeSeq: cursor})
			if err != nil {
				t.Fatalf("SecurityLog = %v", err)
			}
			if len(got.Entries) == 0 {
				break
			}
			rest = append(rest, pageSeqs(got)...)
			cursor = rest[len(rest)-1]
		}
		var want []uint64
		for i := 119; i >= 60; i-- {
			if i%3 == 2 && gseqs[i] < pageSeqs(first)[9] {
				want = append(want, gseqs[i])
			}
		}
		if !slices.Equal(rest, want) {
			t.Errorf("pages after the prune = %v, want the kept matches below the first page %v", rest, want)
		}
	})
	t.Run("across_store_reads", func(t *testing.T) {
		// A page of 10 takes three store reads of MaxLogPage. The matches are
		// each full read's last entry and the next read's first, in either
		// order, so a continuation bound off by one either way duplicates or
		// drops one.
		g := newFixture(t, options{})
		gadmin := mustUser(t, g.mem, "root", access.RoleAdmin)
		gp := g.sessionPrincipal(t, gadmin, access.SessionFull, time.Now())
		big := make([]account.Event, 2*account.MaxLogPage+200)
		n := len(big)
		m := account.MaxLogPage
		seams := []int{n - m, n - m - 1, n - 2*m, n - 2*m - 1, m, m + 1, 2 * m, 2*m + 1}
		for i := range big {
			big[i] = account.Event{Kind: account.EventUserCreated}
		}
		for _, i := range seams {
			big[i] = account.Event{Kind: account.EventKeyMinted, UserID: 7}
		}
		bseqs := appendEvents(t, g.mem, big...)
		slices.Sort(seams)
		oldest := pick(bseqs, seams...)
		for _, tc := range []struct {
			name   string
			lf     account.LogFilter
			newest bool
		}{
			{"kind_newest_first", account.LogFilter{Kinds: keys}, true},
			{"kind_oldest_first", account.LogFilter{Kinds: keys, OldestFirst: true}, false},
			{"user_newest_first", account.LogFilter{UserID: 7}, true},
			{"user_oldest_first", account.LogFilter{UserID: 7, OldestFirst: true}, false},
			{"kind_newest_first_above_bound", account.LogFilter{Kinds: keys, AfterSeq: bseqs[0]}, true},
			{"user_oldest_first_below_bound", account.LogFilter{UserID: 7, BeforeSeq: bseqs[n-1], OldestFirst: true}, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tc.lf.Limit = 10
				want := slices.Clone(oldest)
				if tc.newest {
					slices.Reverse(want)
				}
				if got := walkLog(t.Context(), t, g.svc, gp, tc.lf, 3); !slices.Equal(got, want) {
					t.Errorf("pages together = %v, want every seam match once, in order: %v", got, want)
				}
			})
		}
	})
}

// fataler is what walkLog needs of a *testing.T or a *rapid.T.
type fataler interface {
	Helper()
	Fatalf(format string, args ...any)
}

// walkLog calls SecurityLog from lf until a page comes back empty, moving
// lf's bound in its read order to each page's last Seq, and returns every page's Seqs in
// order. It fails past maxPages pages, on a page over lf.Limit, and on a
// page under lf.Limit that more matches follow: a page is short only at
// the range's end.
func walkLog(ctx context.Context, tb fataler, svc *account.Service, p access.Principal, lf account.LogFilter, maxPages int) []uint64 {
	tb.Helper()
	limit := cmp.Or(lf.Limit, account.DefaultLogPage)
	var all []uint64
	short := false
	for n := 0; ; n++ {
		got, err := svc.SecurityLog(ctx, p, lf)
		if err != nil {
			tb.Fatalf("SecurityLog(%+v) = %v", lf, err)
		}
		seqs := pageSeqs(got)
		switch {
		case len(seqs) == 0:
			return all
		case short:
			tb.Fatalf("page %d held fewer than Limit %d entries, yet page %d holds %v", n-1, limit, n, seqs)
		case n == maxPages:
			tb.Fatalf("still paging after %d pages: %v", n, all)
		case len(seqs) > limit:
			tb.Fatalf("page %d holds %d entries, over Limit %d", n, len(seqs), limit)
		}
		short = len(seqs) < limit
		all = append(all, seqs...)
		if lf.OldestFirst {
			lf.AfterSeq = seqs[len(seqs)-1]
		} else {
			lf.BeforeSeq = seqs[len(seqs)-1]
		}
	}
}

func TestSecurityLogNeverWaits(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	admin := mustUser(t, f.mem, "root", access.RoleAdmin)
	p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
	fill(t, f.mem, account.LogClassChange, 3, time.Now())
	entered, release := make(chan struct{}), make(chan struct{})
	held := make(chan error, 1)
	go func() {
		held <- f.mem.Update(t.Context(), func(account.Tx) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	done := make(chan error, 1)
	go func() {
		page, err := f.svc.SecurityLog(t.Context(), p, account.LogFilter{})
		if err == nil && len(page.Entries) != 3 {
			err = errors.New("the page does not hold the three committed entries")
		}
		done <- err
	}()
	returned := false
	select {
	case err := <-done:
		returned = true
		if err != nil {
			t.Errorf("SecurityLog during a held Update = %v", err)
		}
	case <-time.After(time.Second):
		t.Errorf("SecurityLog waited over 1s on a held Update")
	}
	close(release)
	if err := <-held; err != nil {
		t.Errorf("held Update = %v", err)
	}
	if !returned {
		<-done
	}
}
