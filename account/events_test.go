package account_test

import (
	"log/slog"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access/account"
)

// comparableEvents are evs with At cleared, after checking each is set, and
// SessionIDs sorted, nil when empty.
func comparableEvents(t *testing.T, evs []account.Event) []account.Event {
	t.Helper()
	var out []account.Event
	for _, ev := range evs {
		if ev.At.IsZero() {
			t.Errorf("%s has no At", ev.Kind)
		}
		ev.At = time.Time{}
		ev.SessionIDs = slices.Sorted(slices.Values(ev.SessionIDs))
		if len(ev.SessionIDs) == 0 {
			ev.SessionIDs = nil
		}
		out = append(out, ev)
	}
	return out
}

func TestEveryOperationEmits(t *testing.T) {
	t.Parallel()
	for _, op := range operations() {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			w := newOpWorld(t, worldOptions{empty: op.empty})
			call := op.prep(t, w, w.actorFor(t, op.class))
			mark := len(w.events.all())
			if err := call.run(t.Context()); err != nil {
				t.Fatalf("%s = %v", op.name, err)
			}
			got := comparableEvents(t, w.events.all()[mark:])
			want := comparableEvents(t, withAt(call.want()))
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s emitted\n%+v\nwant\n%+v", op.name, got, want)
			}
		})
	}
}

// withAt sets every event's At, so comparableEvents checks only the
// emitted ones'.
func withAt(evs []account.Event) []account.Event {
	for i := range evs {
		evs[i].At = time.Unix(1, 0)
	}
	return evs
}

func TestOnEventPanicRecovered(t *testing.T) {
	t.Parallel()
	const msg = "account: OnEvent panicked"
	for _, tc := range []struct {
		name    string
		hook    func(account.Event)
		wantErr int
	}{
		{"panicking_hook", func(account.Event) { panic("hook") }, 1},
		{"quiet_hook", func(account.Event) {}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newPW(t, pwOptions{edit: func(c *account.Config) { c.OnEvent = tc.hook }})
			passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
			if _, err := p.login(t.Context(), localClient, "alice", goodPassword); err != nil {
				t.Fatalf("PasswordLogin: %v", err)
			}
			n := 0
			for _, r := range p.logs.Records("") {
				if r.Level == slog.LevelError && r.Message == msg {
					n++
				}
			}
			if n != tc.wantErr {
				t.Errorf("%q ERROR lines = %d, want %d", msg, n, tc.wantErr)
			}
		})
	}
}
