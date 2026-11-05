package account

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn"
)

const defaultMaxPending = 10000

// pendingPurpose is the begin call an entry came from; a finish call takes
// only an entry of its own purpose.
type pendingPurpose int

const (
	purposeLogin pendingPurpose = iota + 1
	purposeSetup
	purposeRegister
	purposeStepUp
	purposeRecovery
)

// pending is what a begin call leaves for its finish call.
type pending struct {
	user       *access.User // the user, or setup's provisional user
	setupToken access.Hash  // the setup token a setup finish spends; zero when setup asked for none
	ceremony   webauthn.Ceremony
}

type pendingEntry struct {
	expires    time.Time
	prev, next *pendingEntry
	value      pending
	id         string
	purpose    pendingPurpose
}

// pendingCache holds at most max begun ceremonies, oldest first in a list
// threaded through the entries, so eviction and expiry walk from the head.
type pendingCache struct {
	byID       map[string]*pendingEntry
	head, tail *pendingEntry
	mu         sync.Mutex
	max        int
}

func newPendingCache(maxEntries int) *pendingCache {
	return &pendingCache{max: maxEntries, byID: make(map[string]*pendingEntry)}
}

// put stores v under a new 256-bit random ID for webauthn.CeremonyTimeout
// from now. Expired entries go first; when the cache is still full, the
// oldest entry is evicted.
func (c *pendingCache) put(purpose pendingPurpose, v pending, now time.Time) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+); it crashes the program instead
	e := &pendingEntry{id: hex.EncodeToString(b), purpose: purpose, value: v, expires: now.Add(webauthn.CeremonyTimeout)}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	for len(c.byID) >= c.max {
		c.unlinkLocked(c.head)
	}
	c.byID[e.id] = e
	e.prev = c.tail
	if c.tail != nil {
		c.tail.next = e
	} else {
		c.head = e
	}
	c.tail = e
	return e.id
}

// take removes id's entry and returns it when it is of purpose and not
// expired at now. A take of the wrong purpose still removes the entry, so
// every ID is used once.
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

// prune drops every entry expired at now.
func (c *pendingCache) prune(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
}

// pruneLocked walks from the head, where the oldest entry is: every entry
// expires one CeremonyTimeout after its put, so the first live one ends the
// walk while Config.Now does not run backwards.
func (c *pendingCache) pruneLocked(now time.Time) {
	for c.head != nil && !now.Before(c.head.expires) {
		c.unlinkLocked(c.head)
	}
}

func (c *pendingCache) unlinkLocked(e *pendingEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}
	e.prev, e.next = nil, nil
	delete(c.byID, e.id)
}
