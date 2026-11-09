package account_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"pgregory.net/rapid"
)

// classModel is what one class must hold by E35 §5: the entries it was
// given, oldest dropped beyond the cap and counted, and those older than
// LogMaxAge dropped uncounted at a sweep.
type classModel struct {
	entries []modelEntry
	evicted uint64
	given   int
	aged    int
}

type modelEntry struct {
	at  time.Time
	seq uint64
}

// TestLogBoundAtAnyTime runs random logged changes under random caps and
// requires, after every one, each class at or under its cap, holding
// exactly the model's entries, with Count plus Evicted equal to what it was
// given minus its age removals.
func TestLogBoundAtAnyTime(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		caps := map[account.LogClass]int{
			account.LogClassChange:  rapid.IntRange(1, 5).Draw(rt, "changes"),
			account.LogClassSession: rapid.IntRange(1, 5).Draw(rt, "sessions"),
		}
		maxAge := time.Duration(rapid.IntRange(1, 10).Draw(rt, "maxAgeMinutes")) * time.Minute
		clock := newTestClock(time.Now().Truncate(time.Second))
		f := newFixture(t, options{rules: func() account.Rules { return account.Rules{Scopes: []string{"read"}} }, edit: func(c *account.Config) {
			withLogCaps(caps[account.LogClassChange], caps[account.LogClassSession])(c)
			c.LogMaxAge, c.Now, c.CleanupInterval = maxAge, clock.now, 24*time.Hour
		}})
		root := mustUser(t, f.mem, fmt.Sprintf("root%d", userNames.Add(1)), access.RoleAdmin)
		models := map[account.LogClass]*classModel{account.LogClassChange: {}, account.LogClassSession: {}}
		var live []int64
		seen := len(f.events.all())
		step := func(rt *rapid.T) {
			clock.add(time.Duration(rapid.IntRange(0, 120).Draw(rt, "stepSeconds")) * time.Second)
		}
		// logged takes the entries the last call committed into the model,
		// at the clock's now, and trims each class to its cap.
		logged := func() {
			evs := f.events.all()
			for _, ev := range evs[seen:] {
				if ev.Seq == 0 {
					continue
				}
				m := models[classOf(ev.Kind)]
				m.entries = append(m.entries, modelEntry{at: clock.now(), seq: ev.Seq})
				m.given++
			}
			seen = len(evs)
			for class, m := range models {
				if over := len(m.entries) - caps[class]; over > 0 {
					m.entries, m.evicted = m.entries[over:], m.evicted+uint64(over)
				}
			}
		}
		rt.Repeat(map[string]func(*rapid.T){
			"create_user": func(rt *rapid.T) {
				step(rt)
				u, err := f.svc.CreateUser(t.Context(), account.OutOfBand("prop"), account.NewUser{Username: fmt.Sprintf("prop%d", userNames.Add(1))})
				if err != nil {
					rt.Fatalf("CreateUser: %v", err)
				}
				live = append(live, u.ID)
				logged()
			},
			"mint_key": func(rt *rapid.T) {
				if len(live) == 0 {
					rt.Skip("no user")
				}
				step(rt)
				id := rapid.SampledFrom(live).Draw(rt, "keyOwner")
				if _, err := f.svc.CreateAPIKey(t.Context(), account.OutOfBand("prop"), id, account.NewKey{Scopes: []string{"read"}}); err != nil {
					rt.Fatalf("CreateAPIKey: %v", err)
				}
				logged()
			},
			"delete_user": func(rt *rapid.T) {
				if len(live) == 0 {
					rt.Skip("no user")
				}
				step(rt)
				i := rapid.IntRange(0, len(live)-1).Draw(rt, "deleted")
				p := f.sessionPrincipal(t, root, access.SessionFull, clock.now())
				if err := f.svc.DeleteUser(t.Context(), p, live[i]); err != nil {
					rt.Fatalf("DeleteUser: %v", err)
				}
				live = slices.Delete(live, i, i+1)
				logged()
			},
			"revoke_session": func(rt *rapid.T) {
				step(rt)
				p := f.sessionPrincipal(t, root, access.SessionFull, clock.now())
				other := f.sessionPrincipal(t, root, access.SessionFull, clock.now())
				if err := f.svc.RevokeSession(t.Context(), p, other.SessionID); err != nil {
					rt.Fatalf("RevokeSession: %v", err)
				}
				logged()
			},
			"sweep": func(rt *rapid.T) {
				clock.add(time.Duration(rapid.Int64Range(0, int64(2*maxAge/time.Second)).Draw(rt, "sweepAfterSeconds")) * time.Second)
				account.SweepLog(t.Context(), f.svc)
				bound := clock.now().Add(-maxAge)
				for _, m := range models {
					kept := slices.DeleteFunc(m.entries, func(e modelEntry) bool { return e.at.Before(bound) })
					m.aged += len(m.entries) - len(kept)
					m.entries = kept
				}
			},
			"": func(rt *rapid.T) {
				stats := statsOf(t, f.mem)
				for class, m := range models {
					want := make([]uint64, 0, len(m.entries))
					for _, e := range m.entries {
						want = append(want, e.seq)
					}
					got, st := classSeqs(t, f.mem, class), stats[class]
					switch {
					case st.Count > caps[class]:
						rt.Fatalf("%s class holds %d entries, over its cap %d", class, st.Count, caps[class])
					case st.Count+int(st.Evicted) != m.given-m.aged:
						rt.Fatalf("%s class Count %d + Evicted %d, want %d given minus %d aged", class, st.Count, st.Evicted, m.given, m.aged)
					case !slices.Equal(got, want) || st.Count != len(want) || st.Evicted != m.evicted:
						rt.Fatalf("%s class holds %v (stats %+v), want %v with Evicted %d", class, got, st, want, m.evicted)
					}
				}
			},
		})
	})
}
