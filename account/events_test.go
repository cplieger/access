package account_test

import (
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
