package account

import (
	"errors"
	"testing"

	"github.com/cplieger/access"
)

// TestHeldBackAnswersAFullList pins complete's half of a reservation: a
// refused place is answered as it is and no ticket is minted, whatever
// entry pend returned, so a pend that missed full still spends nothing a
// ticket would carry.
func TestHeldBackAnswersAFullList(t *testing.T) {
	t.Parallel()
	s := &Service{pending: newPendingCache(10)}
	full := errors.New("the list is full")
	u := &access.User{ID: 1, Username: "alice"}
	entry := &pending{user: *u, ticket: ticket{next: NextSetCredential}}
	out, err := s.heldBack(&sessionOp{}, nil, full, u, entry)
	if !errors.Is(err, full) {
		t.Errorf("heldBack with a refused place = %v, want the refusal", err)
	}
	if out.Pending != nil {
		t.Errorf("heldBack with a refused place answered ticket %+v, want none", out.Pending)
	}
	if n := len(s.pending.byID); n != 0 {
		t.Errorf("entries after the refused place = %d, want none", n)
	}
}
