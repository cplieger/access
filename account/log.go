package account

import (
	"net/netip"
	"time"
)

// LogClass separates the entries retention counts apart, so session churn
// never evicts an account change.
type LogClass string

// The log classes.
const (
	LogClassChange  LogClass = "change"  // account, credential, key, policy and app changes
	LogClassSession LogClass = "session" // signed_in, stepped_up, session_revoked
)

// LogClasses returns every class, in this order.
func LogClasses() []LogClass { return []LogClass{LogClassChange, LogClassSession} }

// LogEntry is one committed change. The store assigns Event.Seq; account
// fills every other field inside the Update that made the change.
type LogEntry struct {
	// At is when the Update appended the entry, from Config.Now at
	// millisecond precision (rule 11); Seq order is append order.
	At    time.Time
	IP    netip.Addr // the acting request's client address; zero for none
	Class LogClass
	// The actor's display data, from the run's snapshot cache, resolved
	// when the operation's callback returns; empty when it does not apply.
	ActorLabel     string // the acting session's Label, or the acting key's Label
	ActorUserAgent string // the acting session's UserAgent
	ActorKeySuffix string // the acting key's Suffix
	Detail         string // app entries only
	Event          Event  // Kind, the subject, the actor's IDs, the kind's fields, and Seq
}
