package account

import (
	"context"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/cplieger/access"
)

// AppEntry is an app's own entry, appended in the app's own Update.
type AppEntry struct {
	Kind   string        // "<app>.<name>": lowercase, at least one dot, at most 64 bytes
	Method access.Method // optional; a lowercase token of at most 64 bytes, auth's or the app's own
	Detail string        // at most 256 bytes, one line, printable
	Actor  Actor         // As(p), OutOfBand(channel), or the zero Actor for none
}

// The AppEntry limits.
const (
	maxAppKindBytes   = 64
	maxAppMethodBytes = 64
	maxAppDetailBytes = 256 // bytes, not runes: it bounds the stored entry
)

// appKind is an app kind. Every library kind has no dot, so an app kind
// never passes as one.
var appKind = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

func isAppKind(k string) bool { return len(k) <= maxAppKindBytes && appKind.MatchString(k) }

// appMethod is a well-formed access.Method. The set is open, as access.Method
// is: a value outside auth's constants is an app's own method.
var appMethod = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// AppendLog appends e through tx, the caller's own Store.Update callback's,
// and returns the entry with its Seq. It sets At, Class (LogClassChange),
// the actor snapshot and IP, and trims the change class in the same tx. It
// fires no OnEvent and reads no Config.Rules value, so an invalid one never
// fails the app's own change. e.Method is open: an app's own method passes.
// A refused entry is an *AppEntryError, after Shutdown ErrServiceClosed, a
// store error matches access.ErrAuthBackend, and none appends anything. Return
// the error from the callback, so the app's change rolls back with the entry.
func (s *Service) AppendLog(ctx context.Context, tx Tx, e AppEntry) (LogEntry, error) { //nolint:gocritic // hugeParam: an AppEntry is built for this one call
	if s.closed.Load() {
		return LogEntry{}, ErrServiceClosed
	}
	if err := checkAppEntry(&e); err != nil {
		return LogEntry{}, err
	}
	o := by(e.Actor)
	j := &journal{s: s}
	j.reset(o.ip)
	if err := j.cacheActor(ctx, tx, e.Actor); err != nil {
		return LogEntry{}, storeErr(err)
	}
	if err := j.cacheKeyActor(ctx, tx, e.Actor); err != nil {
		return LogEntry{}, storeErr(err)
	}
	now := s.now()
	j.record(Event{At: now, Kind: EventKind(e.Kind), Method: e.Method, Actor: eventActor(e.Actor)}, LogClassChange, e.Detail, now.Truncate(time.Millisecond))
	if err := j.append(ctx, tx); err != nil {
		return LogEntry{}, storeErr(err)
	}
	return j.entries[0], nil
}

func checkAppEntry(e *AppEntry) error {
	if !isAppKind(e.Kind) {
		return &AppEntryError{Reason: ReasonAppKind}
	}
	if len(e.Detail) > maxAppDetailBytes || !utf8.ValidString(e.Detail) || slices.ContainsFunc([]rune(e.Detail), lineBreaking) {
		return &AppEntryError{Reason: ReasonAppDetail}
	}
	if e.Method != "" && (len(e.Method) > maxAppMethodBytes || !appMethod.MatchString(string(e.Method))) {
		return &AppEntryError{Reason: ReasonAppMethod}
	}
	return nil
}

// cacheKeyActor caches a key actor's Label and Suffix from the owner's
// stored keys, as empty when the key is already gone. An operation caches
// its key actor through currentKeyActor instead; AppendLog has no key
// authority to check.
func (j *journal) cacheKeyActor(ctx context.Context, tx Tx, a Actor) error { //nolint:gocritic // hugeParam: as Principal
	u, ok := a.user()
	if !ok || a.principal.KeyID == 0 {
		return nil
	}
	keys, err := tx.ListAPIKeysByUserID(ctx, u.ID)
	if err != nil {
		return err
	}
	j.keys[a.principal.KeyID] = shown{}
	if i := slices.IndexFunc(keys, func(k access.Key) bool { return k.ID == a.principal.KeyID }); i >= 0 {
		j.keys[keys[i].ID] = shown{label: keys[i].Label, keySuffix: keys[i].KeySuffix}
	}
	return nil
}
