package account

import (
	"crypto/rand"
	"encoding/hex"
	"slices"
	"sync"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/ratelimit"
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
	// only a token holder creates.
	maxDrafts = 1000
	// maxRegistrationDrafts bounds the drafts of registration, which anyone
	// creates, in a list of their own so they evict no token holder's.
	maxRegistrationDrafts = 1000
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
	purposeAddPasskey
	purposeStepUp
	purposeSignIn       // a pending sign-in of an existing user
	purposeSecondFactor // a passkey assertion as a pending sign-in's second step
	purposeEnrolTOTP    // a TOTP enrolment a session began
	purposeEnrolPasskey // a passkey registration as a pending sign-in's enrolment
	purposeDraft        // a pending sign-in of an account setup or an invite creates at its finish
	purposeSetPasskey   // a passkey registration as a NextSetCredential step
	// purposeRegistration is the passkey ceremony of a registration.
	purposeRegistration
	// purposeRegistrationDraft is a pending sign-in of an account a
	// registration creates at its finish.
	purposeRegistrationDraft
)

// pendingList is one of the cache's lists. Each has one lifetime, so its
// oldest entry is at its head, and its own cap. An owned list holds one
// entry per owner and purpose and refuses a newcomer while full, so no
// one's entry is lost to another's begins; an anonymous list evicts its
// oldest entry.
type pendingList int

const (
	// listCeremony is anonymous (passkey sign-in and registration begins), so
	// it evicts its oldest; the per-IP Request limit bounds its rate.
	listCeremony pendingList = iota
	listOwnedCeremony
	listSignIn
	listEnrolment
	listDraft
	// listRegistrationDraft is anonymous, as listCeremony is.
	listRegistrationDraft
	numLists
)

func (p pendingPurpose) list() pendingList {
	switch p {
	case purposeSetup, purposeAddPasskey, purposeStepUp:
		return listOwnedCeremony
	case purposeSignIn:
		return listSignIn
	case purposeEnrolTOTP:
		return listEnrolment
	case purposeDraft:
		return listDraft
	case purposeRegistrationDraft:
		return listRegistrationDraft
	default: // purposeLogin, purposeRegistration; a ticket's ceremony is in no list
		return listCeremony
	}
}

// owner is whom an owned list's entry belongs to: its user, or for a draft
// or a setup ceremony the token it spends, zero for a setup that asked for
// none, of which only one is in flight at a time.
type owner struct {
	token   access.HashKey
	user    int64
	purpose pendingPurpose
}

// ownerOf is v's owner when p's list is owned.
func (p pendingPurpose) ownerOf(v *pending) (owner, bool) {
	switch p {
	case purposeSignIn, purposeEnrolTOTP, purposeAddPasskey, purposeStepUp:
		return owner{purpose: p, user: v.user.ID}, true
	case purposeDraft:
		return owner{purpose: p, token: v.ticket.draft.token.Key()}, true
	case purposeSetup:
		return owner{purpose: p, token: v.setupToken.Key()}, true
	default:
		return owner{}, false
	}
}

// isTicket reports whether p's entries are pending sign-ins, which a
// ticket names and every step reads.
func (p pendingPurpose) isTicket() bool {
	return p == purposeSignIn || p == purposeDraft || p == purposeRegistrationDraft
}

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
	// ceremony is a pending sign-in's one passkey ceremony, and parent that
	// ceremony's ticket: it is in no list, and it ends with its ticket.
	ceremony, parent *pendingEntry
	id               string
	value            pending
	owner            owner
	purpose          pendingPurpose
	owned            bool
}

// entryList is one list, oldest first, threaded through its entries.
type entryList struct {
	head, tail *pendingEntry
	lifetime   time.Duration
	n, max     int
}

// pendingCache holds the begun ceremonies and the pending sign-ins, one
// list per pendingList, with an owned list's entries indexed by owner, so a
// begin finds its owner's earlier entry and a credential change drops a
// user's pending sign-in without a scan.
type pendingCache struct {
	byID    map[string]*pendingEntry
	byOwner map[owner]*pendingEntry
	lists   [numLists]entryList
	mu      sync.Mutex
}

// newPendingCache bounds each ceremony list at maxCeremonies.
func newPendingCache(maxCeremonies int) *pendingCache {
	c := &pendingCache{byID: make(map[string]*pendingEntry), byOwner: make(map[owner]*pendingEntry)}
	c.lists[listCeremony] = entryList{lifetime: webauthn.CeremonyTimeout, max: maxCeremonies}
	c.lists[listOwnedCeremony] = entryList{lifetime: webauthn.CeremonyTimeout, max: maxCeremonies}
	c.lists[listSignIn] = entryList{lifetime: ticketLifetime, max: maxPendingSignIns}
	c.lists[listEnrolment] = entryList{lifetime: ticketLifetime, max: maxEnrolments}
	c.lists[listDraft] = entryList{lifetime: ticketLifetime, max: maxDrafts}
	c.lists[listRegistrationDraft] = entryList{lifetime: ticketLifetime, max: maxRegistrationDrafts}
	return c
}

// newPendingID is a fresh 256-bit random entry ID.
func newPendingID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+); it crashes the program instead
	return hex.EncodeToString(b)
}

// put stores v under a new ID for its list's lifetime from now, after
// that list's expired entries go. In an owned list v replaces its owner's
// earlier entry of purpose, and a newcomer to a full list is refused with a
// *ratelimit.RefusedError retrying when the earliest entry expires; an
// anonymous list evicts its oldest entry and never refuses.
func (c *pendingCache) put(purpose pendingPurpose, v pending, now time.Time) (string, error) { //nolint:gocritic // hugeParam: the entry keeps its own copy
	l := purpose.list()
	e := &pendingEntry{id: newPendingID(), purpose: purpose, value: v, expires: now.Add(c.lists[l].lifetime)}
	e.owner, e.owned = purpose.ownerOf(&e.value)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneListLocked(l, now)
	list := &c.lists[l]
	switch earlier, mine := c.byOwner[e.owner]; {
	case !e.owned:
		for list.n >= list.max {
			c.unlinkLocked(list.head)
		}
	case mine:
		c.unlinkLocked(earlier)
	case list.n >= list.max:
		return "", &ratelimit.RefusedError{Dimension: "pending", RetryAfter: list.head.expires.Sub(now)}
	}
	if e.owned {
		c.byOwner[e.owner] = e
	}
	c.byID[e.id] = e
	e.prev = list.tail
	if list.tail != nil {
		list.tail.next = e
	} else {
		list.head = e
	}
	list.tail = e
	list.n++
	return e.id, nil
}

// putOnTicket stores v, a passkey ceremony of purpose begun for ticketID's
// live pending sign-in, as that ticket's one ceremony for CeremonyTimeout
// from now, replacing an earlier one; false when the ticket is gone. The
// ceremony ends with its ticket, so the ticket lists bound it.
func (c *pendingCache) putOnTicket(ticketID string, purpose pendingPurpose, v pending, now time.Time) (string, bool) { //nolint:gocritic // hugeParam: the entry keeps its own copy
	e := &pendingEntry{id: newPendingID(), purpose: purpose, value: v, expires: now.Add(webauthn.CeremonyTimeout)}
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.byID[ticketID]
	if !ok || !t.purpose.isTicket() || !now.Before(t.expires) {
		return "", false
	}
	if t.ceremony != nil {
		c.unlinkLocked(t.ceremony)
	}
	e.parent, t.ceremony = t, e
	c.byID[e.id] = e
	return e.id, true
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
	if e, ok := c.byOwner[owner{purpose: purposeSignIn, user: userID}]; ok {
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

// unlinkLocked removes e, and a ticket's ceremony with it.
func (c *pendingCache) unlinkLocked(e *pendingEntry) {
	delete(c.byID, e.id)
	if e.parent != nil {
		e.parent.ceremony, e.parent = nil, nil
		return
	}
	if e.ceremony != nil {
		c.unlinkLocked(e.ceremony)
	}
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
	if e.owned && c.byOwner[e.owner] == e {
		delete(c.byOwner, e.owner)
	}
}
