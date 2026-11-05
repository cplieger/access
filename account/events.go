package account

import (
	"cmp"
	"slices"
	"time"

	"github.com/cplieger/access"
)

// EventKind names what an Event reports.
type EventKind string

// The event kinds.
const (
	EventSignedIn            EventKind = "signed_in"
	EventSessionRevoked      EventKind = "session_revoked"
	EventUserSessionsRevoked EventKind = "user_sessions_revoked"
	EventSessionRotated      EventKind = "session_rotated"
	EventSessionsExpired     EventKind = "sessions_expired" // the sweep deleted expired sessions; after a call that returns nil
	EventPasswordSet         EventKind = "password_set"
	EventPasswordChanged     EventKind = "password_changed"
	EventPasswordRemoved     EventKind = "password_removed"
	EventPasskeyAdded        EventKind = "passkey_added"
	EventPasskeyRemoved      EventKind = "passkey_removed"
	EventOIDCLinked          EventKind = "oidc_linked"
	EventOIDCUnlinked        EventKind = "oidc_unlinked"
	EventSetupTokenIssued    EventKind = "setup_token_issued" //nolint:gosec // G101: an event name, not a credential
	EventRecoveryIssued      EventKind = "recovery_issued"
	EventRecoveryConsumed    EventKind = "recovery_consumed"
	EventRecoveryCompleted   EventKind = "recovery_completed"
	EventKeyMinted           EventKind = "key_minted"
	EventKeyRevoked          EventKind = "key_revoked"
	EventSteppedUp           EventKind = "stepped_up"
	EventUserDisabled        EventKind = "user_disabled"
	EventUserEnabled         EventKind = "user_enabled"
	EventUserDeleted         EventKind = "user_deleted"
	EventRoleChanged         EventKind = "role_changed"
	EventUserCreated         EventKind = "user_created"
	EventMethodLocked        EventKind = "method_locked"    // a failure counter reached the cap; reported by the sweep
	EventMethodReenabled     EventKind = "method_reenabled" // recovery, ReenableMethod or a sign-in cleared a lock, after its commit
)

// Event is one committed change, delivered to Config.OnEvent after the
// Update that made it returns nil. Delivery is at most once: a crash
// between the commit and the dispatch loses the event.
type Event struct {
	At         time.Time
	Kind       EventKind
	Method     access.Method // sign-in, step-up, lock and re-enable
	SessionIDs []string      // sessions ended or rotated
	Actor      EventActor
	UserID     int64 // the account the event is about (target)
	// KeyID is the key of a key event, and the issuing key of an
	// EventRecoveryConsumed, EventRecoveryCompleted or invite-accepting
	// EventUserCreated whose token a key issued.
	KeyID     int64
	PasskeyID int64 // passkey events
	Trusted   bool  // EventMethodLocked: which context locked
}

// EventActor is who caused an Event; the zero value is no actor (the
// sweep, an anonymous caller).
type EventActor struct {
	SessionID string
	OutOfBand string // the channel; empty for a principal
	UserID    int64
	KeyID     int64
}

// emit delivers ev to Config.OnEvent in the calling goroutine. A panic in
// the hook is recovered and logged at ERROR: the write has committed, and
// the operation must not fail after the fact.
func (s *Service) emit(ev Event) { //nolint:gocritic // hugeParam: each event is built for this one call
	if s.onEvent == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			s.logger().Error("account: OnEvent panicked", "kind", string(ev.Kind), "panic", r)
		}
	}()
	s.onEvent(ev)
}

// sessionsExpired groups one cleanup call's refs into one
// EventSessionsExpired per user, in ascending UserID, each with its IDs
// sorted, from the refs alone.
func sessionsExpired(refs []access.SessionRef, at time.Time) []Event {
	byUser := make(map[int64][]string)
	for _, r := range refs {
		byUser[r.UserID] = append(byUser[r.UserID], r.ID)
	}
	events := make([]Event, 0, len(byUser))
	for userID, ids := range byUser {
		slices.Sort(ids)
		events = append(events, Event{Kind: EventSessionsExpired, At: at, UserID: userID, SessionIDs: ids})
	}
	slices.SortFunc(events, func(a, b Event) int { return cmp.Compare(a.UserID, b.UserID) })
	return events
}
