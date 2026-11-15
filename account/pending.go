package account

import (
	"crypto/rand"
	"encoding/hex"
	"slices"
	"sync"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn"
)

const (
	defaultMaxPending = 10000
	// maxPendingSignIns bounds the pending sign-ins of existing users,
	// which only a correct first factor creates.
	maxPendingSignIns = 10000
	// maxEnrolments bounds the TOTP enrolments begun from a session.
	maxEnrolments = 10000
	// maxDrafts bounds the drafts of setup and invite acceptance, which
	// only a token holder creates (design 4.4's cache table).
	maxDrafts = 1000
	// ticketLifetime is a pending sign-in's and an enrolment's life; it
	// covers installing an authenticator app.
	ticketLifetime = 10 * time.Minute
)

// pendingPurpose is the begin call or step an entry came from; a later
// call takes only an entry of its own purpose.
type pendingPurpose int

const (
	purposeLogin pendingPurpose = iota + 1
	purposeSetup
	purposeRegister
	purposeStepUp
	purposeSignIn       // a pending sign-in of an existing user
	purposeSecondFactor // a passkey assertion as a pending sign-in's second step
	purposeEnrolTOTP    // a TOTP enrolment a session began
	purposeEnrolPasskey // a passkey registration as a pending sign-in's enrolment
	purposeDraft        // a pending sign-in of an account setup or an invite creates at its finish
)

// pendingList is one of the cache's lists. Each has one lifetime, so its
// oldest entry is at its head, and its own cap, so a put evicts only its own
// purposes' entries: anonymous ceremonies never evict a pending sign-in.
type pendingList int

const (
	listCeremony pendingList = iota
	listSignIn
	listEnrolment
	listDraft
	numLists
)

func (p pendingPurpose) list() pendingList {
	switch p {
	case purposeSignIn:
		return listSignIn
	case purposeEnrolTOTP:
		return listEnrolment
	case purposeDraft:
		return listDraft
	default:
		return listCeremony
	}
}

// isTicket reports whether p's entries are pending sign-ins, which a
// ticket names and every step reads.
func (p pendingPurpose) isTicket() bool { return p == purposeSignIn || p == purposeDraft }

// pending is what a begin call or a step leaves for the next.
type pending struct {
	enrol      enrolment
	setupToken access.Hash // the setup token a setup finish spends; zero when setup asked for none
	ceremony   webauthn.Ceremony
	// ticketID is the pending sign-in a second-factor ceremony was begun
	// for.
	ticketID access.Secret
	user     access.User // the ceremony's user, setup's provisional user, the ticket's user (a draft's has ID zero), or zero for a sign-in ceremony
	ticket   ticket
}

// enrolment is a TOTP enrolment's state between its begin and its finish,
// from a session or inside a pending sign-in.
type enrolment struct {
	issued    time.Time
	secret    access.Secret
	sessionID string // the beginning session; no other finishes it
}

type pendingEntry struct {
	expires    time.Time
	prev, next *pendingEntry
	id         string
	value      pending
	purpose    pendingPurpose
}

// entryList is one list, oldest first, threaded through its entries.
type entryList struct {
	head, tail *pendingEntry
	lifetime   time.Duration
	n, max     int
}

// pendingCache holds the begun ceremonies and the pending sign-ins, one
// list per pendingList, with the sign-ins indexed by user so a credential
// change drops them without a scan.
type pendingCache struct {
	byID   map[string]*pendingEntry
	byUser map[int64]*pendingEntry // the user's one live pending sign-in
	lists  [numLists]entryList
	mu     sync.Mutex
}

// newPendingCache bounds the ceremony list at maxCeremonies.
func newPendingCache(maxCeremonies int) *pendingCache {
	c := &pendingCache{byID: make(map[string]*pendingEntry), byUser: make(map[int64]*pendingEntry)}
	c.lists[listCeremony] = entryList{lifetime: webauthn.CeremonyTimeout, max: maxCeremonies}
	c.lists[listSignIn] = entryList{lifetime: ticketLifetime, max: maxPendingSignIns}
	c.lists[listEnrolment] = entryList{lifetime: ticketLifetime, max: maxEnrolments}
	c.lists[listDraft] = entryList{lifetime: ticketLifetime, max: maxDrafts}
	return c
}

// put stores v under a new 256-bit random ID for its list's lifetime from
// now. Expired entries of that list go first; when it is still full, its
// oldest entry is evicted. A pending sign-in replaces its user's earlier
// one, so a step 1 posted again leaves only the ticket it answers.
func (c *pendingCache) put(purpose pendingPurpose, v pending, now time.Time) string { //nolint:gocritic // hugeParam: the entry keeps its own copy
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+); it crashes the program instead
	l := purpose.list()
	e := &pendingEntry{id: hex.EncodeToString(b), purpose: purpose, value: v, expires: now.Add(c.lists[l].lifetime)}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneListLocked(l, now)
	if l == listSignIn {
		if old, ok := c.byUser[v.user.ID]; ok {
			c.unlinkLocked(old)
		}
		c.byUser[v.user.ID] = e
	}
	for c.lists[l].n >= c.lists[l].max {
		c.unlinkLocked(c.lists[l].head)
	}
	c.byID[e.id] = e
	list := &c.lists[l]
	e.prev = list.tail
	if list.tail != nil {
		list.tail.next = e
	} else {
		list.head = e
	}
	list.tail = e
	list.n++
	return e.id
}

// take removes id's entry and returns it when it is of purpose and not
// expired at now. A take of the wrong purpose still removes the entry, so
// every ceremony ID is used once.
func (c *pendingCache) take(id string, purpose pendingPurpose, now time.Time) (pending, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byID[id]
	if !ok {
		return pending{}, false
	}
	c.unlinkLocked(e)
	if e.purpose != purpose || !now.Before(e.expires) {
		return pending{}, false
	}
	return e.value, true
}

// peek returns id's entry when it is of purpose and not expired at now,
// leaving it in place: a second step refused for a wrong code keeps its
// ticket. A pending sign-in comes back with its own copy of the methods.
func (c *pendingCache) peek(id string, purpose pendingPurpose, now time.Time) (pending, bool) {
	return c.peekIf(id, now, func(p pendingPurpose) bool { return p == purpose })
}

// peekTicket is peek of id's pending sign-in, of an existing user or a
// draft.
func (c *pendingCache) peekTicket(id string, now time.Time) (pending, bool) {
	return c.peekIf(id, now, pendingPurpose.isTicket)
}

func (c *pendingCache) peekIf(id string, now time.Time, of func(pendingPurpose) bool) (pending, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byID[id]
	if !ok || !of(e.purpose) || !now.Before(e.expires) {
		return pending{}, false
	}
	v := e.value
	v.ticket.methods = slices.Clone(v.ticket.methods)
	return v, true
}

// setEnrolment sets e on id's live pending sign-in, replacing an enrolment
// begun before, and reports whether one was live.
func (c *pendingCache) setEnrolment(id string, e enrolment, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.byID[id]
	if !ok || !entry.purpose.isTicket() || !now.Before(entry.expires) {
		return false
	}
	entry.value.enrol = e
	return true
}

// drop removes id's entry, if any.
func (c *pendingCache) drop(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byID[id]; ok {
		c.unlinkLocked(e)
	}
}

// markFailed records that id's pending sign-in met its first refused
// second step, reporting whether this call is the first; false for an
// entry that is gone.
func (c *pendingCache) markFailed(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byID[id]
	if !ok || e.purpose != purposeSignIn || e.value.ticket.failed {
		return false
	}
	e.value.ticket.failed = true
	return true
}

// unmarkFailed undoes markFailed when the security log refused its entry,
// so the next refusal journals it.
func (c *pendingCache) unmarkFailed(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byID[id]; ok && e.purpose == purposeSignIn {
		e.value.ticket.failed = false
	}
}

// dropUser removes userID's pending sign-in, if any.
func (c *pendingCache) dropUser(userID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byUser[userID]; ok {
		c.unlinkLocked(e)
	}
}

// prune drops every entry expired at now.
func (c *pendingCache) prune(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for l := range numLists {
		c.pruneListLocked(l, now)
	}
}

// pruneListLocked walks l from its head, where the oldest entry is: every
// entry of l expires one lifetime after its put, so the first live one ends
// the walk while Config.Now does not run backwards.
func (c *pendingCache) pruneListLocked(l pendingList, now time.Time) {
	for h := c.lists[l].head; h != nil && !now.Before(h.expires); h = c.lists[l].head {
		c.unlinkLocked(h)
	}
}

func (c *pendingCache) unlinkLocked(e *pendingEntry) {
	list := &c.lists[e.purpose.list()]
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		list.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		list.tail = e.prev
	}
	e.prev, e.next = nil, nil
	list.n--
	delete(c.byID, e.id)
	if e.purpose == purposeSignIn && c.byUser[e.value.user.ID] == e {
		delete(c.byUser, e.value.user.ID)
	}
}
