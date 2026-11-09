package account_test

import (
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"pgregory.net/rapid"
)

// TestSecurityLogPagesEqualFilter appends a random log of up to
// 3*MaxLogPage+2 entries, walks SecurityLog under a random kind and user
// filter, Limit, order and starting bound until a page comes back empty,
// and requires the pages together to be every appended entry past the
// bound the filter matches, once, in the walk's order.
func TestSecurityLogPagesEqualFilter(t *testing.T) {
	kinds := []account.EventKind{account.EventUserCreated, account.EventKeyMinted, account.EventKeyRevoked}
	rapid.Check(t, func(rt *rapid.T) {
		// Whole store reads plus a rest: a walk of one, two or three reads is
		// equally likely, where one draw over the range favours small logs.
		n := rapid.IntRange(0, 2).Draw(rt, "fullReads")*account.MaxLogPage + rapid.IntRange(0, account.MaxLogPage+2).Draw(rt, "rest")
		evs := make([]account.Event, n)
		for i := range evs {
			evs[i] = account.Event{
				Kind:   rapid.SampledFrom(kinds).Draw(rt, "kind"),
				UserID: rapid.Int64Range(0, 2).Draw(rt, "user"),
			}
		}
		lf := account.LogFilter{
			UserID: rapid.Int64Range(0, 2).Draw(rt, "filterUser"),
			Limit:  rapid.IntRange(1, account.MaxLogPage).Draw(rt, "limit"),
		}
		for _, k := range kinds {
			if rapid.Bool().Draw(rt, "filterKind "+string(k)) {
				lf.Kinds = append(lf.Kinds, k)
			}
		}
		lf.OldestFirst = rapid.Bool().Draw(rt, "oldestFirst")
		bound := -1
		if n > 0 && rapid.Bool().Draw(rt, "bounded") {
			bound = rapid.IntRange(0, n-1).Draw(rt, "bound")
		}

		f := newFixture(t, options{})
		admin := mustUser(t, f.mem, "root", access.RoleAdmin)
		p := f.sessionPrincipal(t, admin, access.SessionFull, time.Now())
		seqs := appendEvents(t, f.mem, evs...)
		// The bound is where the walk starts: after it oldest first, before
		// it newest first, so walkLog moves that same bound page by page.
		past := func(i int) bool { return bound < 0 || (lf.OldestFirst && i > bound) || (!lf.OldestFirst && i < bound) }
		var want []uint64
		for i, ev := range evs {
			if past(i) && (len(lf.Kinds) == 0 || slices.Contains(lf.Kinds, ev.Kind)) && (lf.UserID == 0 || ev.UserID == lf.UserID) {
				want = append(want, seqs[i])
			}
		}
		switch {
		case bound >= 0 && lf.OldestFirst:
			lf.AfterSeq = seqs[bound]
		case bound >= 0:
			lf.BeforeSeq = seqs[bound]
		}
		if !lf.OldestFirst {
			slices.Reverse(want)
		}
		got := walkLog(t.Context(), rt, f.svc, p, lf, len(want)/lf.Limit+1)
		if !slices.Equal(got, want) {
			rt.Fatalf("pages together = %v, want every match once, in order: %v", got, want)
		}
	})
}
