package account

import (
	"context"
	"errors"
	"testing"

	"github.com/cplieger/access"
)

// appendTx is a Tx that serves only AppendLog, numbering the entries, and
// a PruneLog that removes nothing.
type appendTx struct {
	Tx
	entries []LogEntry
}

func (t *appendTx) AppendLog(_ context.Context, e *LogEntry) error {
	e.Event.Seq = uint64(len(t.entries) + 1)
	t.entries = append(t.entries, *e)
	return nil
}

func (*appendTx) PruneLog(context.Context, LogPrune) (int, error) { return 0, nil }

// appendStore runs every Update on one appendTx.
type appendStore struct {
	Store
	tx *appendTx
}

func (s *appendStore) Update(_ context.Context, fn func(Tx) error) error { return fn(s.tx) }

func TestLogActorSnapshotJournal(t *testing.T) {
	t.Parallel()
	for name, addFirst := range map[string]bool{"added_before_created": true, "added_after_created": false} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st := &appendStore{tx: &appendTx{}}
			s := &Service{store: st}
			sess := access.Session{ID: "sess-1", Label: "laptop", UserAgent: "agent"}
			err := s.change(t.Context(), origin{}, func(_ Tx, j *journal) error {
				if addFirst {
					j.add(Event{Kind: EventUserCreated, UserID: 1})
				}
				j.created(&sess)
				if !addFirst {
					j.add(Event{Kind: EventUserCreated, UserID: 1})
				}
				sess.Label, sess.UserAgent = "changed after", "changed after"
				return nil
			})
			if err != nil {
				t.Fatalf("change = %v", err)
			}
			if got := st.tx.entries; len(got) != 1 || got[0].ActorLabel != "laptop" || got[0].ActorUserAgent != "agent" || got[0].Event.Actor != (EventActor{}) {
				t.Errorf("entries = %+v, want one with the created session's Label and UserAgent as j.created saw them, and no actor", got)
			}
		})
	}
}

func TestLogFailsClosed(t *testing.T) {
	t.Parallel()
	refused := map[string]Event{
		"session_never_read": {Kind: EventSessionRevoked, UserID: 1, Actor: EventActor{SessionID: "unread", UserID: 1}},
		"key_never_read":     {Kind: EventKeyMinted, UserID: 1, KeyID: 9, Actor: EventActor{KeyID: 7, UserID: 1}},
		"kind_not_logged":    {Kind: EventSessionsExpired, UserID: 1},
	}
	for name, ev := range refused {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st := &appendStore{tx: &appendTx{}}
			s := &Service{store: st}
			err := s.change(t.Context(), origin{}, func(_ Tx, j *journal) error {
				j.add(Event{Kind: EventUserCreated, UserID: 2})
				j.add(ev)
				return nil
			})
			if !errors.Is(err, errUnlogged) {
				t.Errorf("change = %v, want errUnlogged", err)
			}
			if len(st.tx.entries) != 0 {
				t.Errorf("appended %+v, want no entry of the refused change", st.tx.entries)
			}
		})
	}
	allowed := map[string]EventActor{
		"zero_no_session": {},
		"out_of_band":     {OutOfBand: "socket"},
		"user_only":       {UserID: 1},
		"session_read":    {SessionID: "read", UserID: 1},
	}
	for name, a := range allowed {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st := &appendStore{tx: &appendTx{}}
			s := &Service{store: st}
			err := s.change(t.Context(), origin{}, func(_ Tx, j *journal) error {
				j.actorSession(&access.Session{ID: "read", Label: "laptop"})
				j.add(Event{Kind: EventUserDisabled, UserID: 2, Actor: a})
				return nil
			})
			if err != nil || len(st.tx.entries) != 1 {
				t.Errorf("change = %v with %d entries, want nil and one entry", err, len(st.tx.entries))
			}
		})
	}
}
