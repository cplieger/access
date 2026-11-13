package account

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/cplieger/access"
)

// origin is who makes a logged change and from which address.
type origin struct {
	ip    netip.Addr
	actor Actor
}

// by is a change a makes, from its principal's request address.
func by(a Actor) origin { //nolint:gocritic // hugeParam: as Principal
	o := origin{actor: a}
	if a.kind == actorPrincipal {
		o.ip = a.principal.IP
	}
	return o
}

// byClient is a change a makes from c's address.
func byClient(a Actor, c Client) origin { //nolint:gocritic // hugeParam: as Principal and the request's Client
	return origin{actor: a, ip: c.IP}
}

// shown is an actor's display data, as an entry snapshots it.
type shown struct{ label, userAgent, keySuffix string }

// journal is one run of a change's Update callback: the entries it adds and
// the actor records they resolve from. Every field is reset per run.
type journal struct {
	ip       netip.Addr
	s        *Service
	sessions map[string]shown
	keys     map[int64]shown
	made     *shown // the session the run created; nil for none
	entries  []LogEntry
}

// change runs fn in one Store.Update as a logged change made by o. Each run
// caches o's actor record before fn writes; when fn returns nil it appends
// fn's entries through the same tx in add order, each snapshot resolved only
// then, and trims their classes to their caps, so a delete in fn never
// blanks an actor and the order of add and created inside fn does not
// matter. After the commit it dispatches each entry's Event, Seq set, in Seq
// order. An append or trim error rolls the change back and is answered like
// any store error.
func (s *Service) change(ctx context.Context, o origin, fn func(tx Tx, j *journal) error) error { //nolint:gocritic // hugeParam: the change's one origin
	j := &journal{s: s}
	err := s.update(ctx, func(tx Tx) error {
		j.reset(o.ip)
		if err := j.cacheActor(ctx, tx, o.actor); err != nil {
			return err
		}
		if err := fn(tx, j); err != nil {
			return err
		}
		return j.append(ctx, tx)
	})
	if err != nil {
		return err
	}
	s.dispatch(j.entries)
	return nil
}

func (j *journal) reset(ip netip.Addr) {
	j.sessions, j.keys = map[string]shown{}, map[int64]shown{}
	j.made, j.entries, j.ip = nil, nil, ip
}

// cacheActor caches a session actor's record before fn runs, as empty when
// the session is already gone; a key actor's is cached by currentKeyActor.
func (j *journal) cacheActor(ctx context.Context, tx Tx, a Actor) error { //nolint:gocritic // hugeParam: as Principal
	u, ok := a.user()
	if !ok || a.principal.SessionID == "" {
		return nil
	}
	sessions, err := tx.SessionsByUserID(ctx, u.ID)
	if err != nil {
		return err
	}
	if i := slices.IndexFunc(sessions, func(s access.Session) bool { return s.ID == a.principal.SessionID }); i >= 0 {
		j.actorSession(&sessions[i])
	} else {
		j.sessions[a.principal.SessionID] = shown{}
	}
	return nil
}

// add records ev as an entry of this run, stamped now with its class and
// the change's address.
func (j *journal) add(ev Event) { //nolint:gocritic // hugeParam: each event is built for this one call
	j.record(ev, classOf(ev.Kind), "", j.s.stamp())
}

// record is add with the class, detail and stamp the caller supplies.
func (j *journal) record(ev Event, class LogClass, detail string, at time.Time) { //nolint:gocritic // hugeParam: as add
	j.entries = append(j.entries, LogEntry{At: at, IP: j.ip, Class: class, Detail: detail, Event: ev})
}

// created caches the session fn just wrote as the run's created session,
// whose data every entry with the zero actor takes.
func (j *journal) created(sess *access.Session) {
	j.actorSession(sess)
	c := j.sessions[sess.ID]
	j.made = &c
}

// actorSession caches an actor session fn read itself, before any delete
// of it in the run.
func (j *journal) actorSession(sess *access.Session) {
	j.sessions[sess.ID] = shown{label: sess.Label, userAgent: sess.UserAgent}
}

// errUnlogged is an entry the journal cannot store: a kind with no class,
// or an actor the run never read. Either is a library defect, so the change
// fails and rolls back rather than store an entry without its snapshot.
var errUnlogged = errors.New("account: log entry incomplete")

// append resolves every entry's snapshot, then appends the entries in add
// order, each getting its Seq, and trims their classes.
func (j *journal) append(ctx context.Context, tx Tx) error {
	for i := range j.entries {
		e := &j.entries[i]
		sh, ok := j.snapshot(e.Event.Actor)
		if !ok || e.Class == "" {
			return fmt.Errorf("%w: %s", errUnlogged, e.Event.Kind)
		}
		e.ActorLabel, e.ActorUserAgent, e.ActorKeySuffix = sh.label, sh.userAgent, sh.keySuffix
	}
	for i := range j.entries {
		if err := tx.AppendLog(ctx, &j.entries[i]); err != nil {
			return err
		}
	}
	return j.s.trimLog(ctx, tx, j.entries)
}

// trimLog removes, from each class entries were just appended to, its
// oldest entries beyond the class's cap. Limit is what the class gained:
// New's drain left every class at or under its cap, so that is the most a
// trim can owe, and a request's Update never removes more than it added.
func (s *Service) trimLog(ctx context.Context, tx Tx, entries []LogEntry) error {
	gained := map[LogClass]int{}
	for i := range entries {
		gained[entries[i].Class]++
	}
	for _, class := range LogClasses() {
		if k := gained[class]; k > 0 {
			if _, err := tx.PruneLog(ctx, LogPrune{Class: class, Keep: s.logCap(class), Limit: k}); err != nil {
				return err
			}
		}
	}
	return nil
}

// snapshot is a's cached data: a named session or key by ID, not ok when
// the run never read it, and for the zero actor the run's created session.
// Any other actor has none.
func (j *journal) snapshot(a EventActor) (shown, bool) {
	switch {
	case a.SessionID != "":
		sh, ok := j.sessions[a.SessionID]
		return sh, ok
	case a.KeyID != 0:
		sh, ok := j.keys[a.KeyID]
		return sh, ok
	case a == EventActor{} && j.made != nil:
		return *j.made, true
	default:
		return shown{}, true
	}
}

// dispatch delivers each committed entry's Event in Seq order.
func (s *Service) dispatch(entries []LogEntry) {
	slices.SortFunc(entries, func(a, b LogEntry) int { return cmp.Compare(a.Event.Seq, b.Event.Seq) })
	for i := range entries {
		s.deliver(entries[i].Event)
	}
}
