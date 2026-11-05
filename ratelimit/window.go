package ratelimit

import (
	"slices"
	"time"
)

// entry is one counted failure or request; id names the reservation that
// made it, so Succeed and Cancel remove exactly their own.
type entry struct {
	at time.Time
	id uint64
}

// window holds a key's live entries, oldest first, and its place in its
// dimension's recency list. Admission refuses a full window, so it never
// holds more than its dimension's Limit.
type window[K comparable] struct {
	key        K
	prev, next *window[K]
	entries    []entry
}

func (w *window[K]) live(now time.Time, d time.Duration) int {
	i := 0
	for i < len(w.entries) && !now.Before(w.entries[i].at.Add(d)) {
		i++
	}
	w.entries = slices.Delete(w.entries, 0, i)
	return len(w.entries)
}

// dimension is one family of windows, a least-recently-used cache of at
// most max of them: head is the window used last, tail the one a new key
// evicts. Every method needs the lock the Limiter keeps for it.
type dimension[K comparable] struct {
	windows    map[K]*window[K]
	head, tail *window[K]
	name       string
	rate       Rate
	max        int
	// evictedAtLimit counts the evicted windows that were at their limit
	// since the last drain.
	evictedAtLimit int
}

func newDimension[K comparable](name string, rate Rate, maxEntries int) *dimension[K] {
	return &dimension[K]{windows: make(map[K]*window[K]), name: name, rate: rate, max: maxEntries}
}

// check returns how long key waits for one more entry, zero when its window
// has room, and marks key's window as used, admitted or not, so a key that
// keeps trying is the last to be evicted.
func (d *dimension[K]) check(key K, now time.Time) time.Duration {
	w, ok := d.windows[key]
	if !ok {
		return 0
	}
	d.unlink(w)
	d.pushFront(w)
	if w.live(now, d.rate.Window) < d.rate.Limit {
		return 0
	}
	return w.entries[0].at.Add(d.rate.Window).Sub(now)
}

// add appends e under key, after a check of key that returned zero in the
// same hold of the lock. A key new to a full dimension first evicts the
// least recently used window, whatever its count.
func (d *dimension[K]) add(key K, e entry) {
	w, ok := d.windows[key]
	if !ok {
		if len(d.windows) >= d.max {
			lru := d.tail
			if lru.live(e.at, d.rate.Window) >= d.rate.Limit {
				d.evictedAtLimit++
			}
			d.drop(lru)
		}
		w = &window[K]{key: key}
		d.windows[key] = w
		d.pushFront(w)
	}
	w.entries = append(w.entries, e)
}

func (d *dimension[K]) remove(key K, id uint64) {
	w, ok := d.windows[key]
	if !ok {
		return
	}
	w.entries = slices.DeleteFunc(w.entries, func(e entry) bool { return e.id == id })
	if len(w.entries) == 0 {
		d.drop(w)
	}
}

func (d *dimension[K]) clear(key K) {
	if w, ok := d.windows[key]; ok {
		d.drop(w)
	}
}

func (d *dimension[K]) prune(now time.Time) {
	for _, w := range d.windows {
		if w.live(now, d.rate.Window) == 0 {
			d.drop(w)
		}
	}
}

func (d *dimension[K]) drain() int {
	n := d.evictedAtLimit
	d.evictedAtLimit = 0
	return n
}

func (d *dimension[K]) drop(w *window[K]) {
	d.unlink(w)
	delete(d.windows, w.key)
}

func (d *dimension[K]) pushFront(w *window[K]) {
	w.next = d.head
	if d.head != nil {
		d.head.prev = w
	}
	d.head = w
	if d.tail == nil {
		d.tail = w
	}
}

func (d *dimension[K]) unlink(w *window[K]) {
	if w.prev != nil {
		w.prev.next = w.next
	} else {
		d.head = w.next
	}
	if w.next != nil {
		w.next.prev = w.prev
	} else {
		d.tail = w.prev
	}
	w.prev, w.next = nil, nil
}
