// Package capture is an access-internal test helper: a slog.Handler that records
// log records so tests can assert on access's logging decisions, plus a helper to
// install it as the default logger.
//
// It is deliberately access-internal rather than a dependency on an external
// logging helper (e.g. slogx/capture): access is a foundational library, and a
// small test handler is not worth a new module edge. Import it only from
// access's _test.go files.
package capture

import (
	"context"
	"log"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Recorder is a slog.Handler that captures every record regardless of level so
// tests can assert on what was logged. A record keeps the attributes and
// groups of the WithAttrs and WithGroup calls that made its handler, and every
// handler derived from one Recorder records into the same log. It is safe for
// concurrent use.
type Recorder struct {
	log *recordLog
	// scopes are the WithGroup and WithAttrs calls that made this handler,
	// oldest first.
	scopes []scope
}

type recordLog struct {
	records []slog.Record
	mu      sync.Mutex
}

// scope is one WithGroup call (group set) or one WithAttrs call.
type scope struct {
	group string
	attrs []slog.Attr
}

// New returns a Recorder and an *slog.Logger writing to it, for code that takes
// an injected logger. It does not touch the global default, so a test using it
// may run in parallel.
func New() (*slog.Logger, *Recorder) {
	rec := &Recorder{log: &recordLog{}}
	return slog.New(rec), rec
}

// Default installs a fresh Recorder as slog's default logger and restores the
// previous default via tb.Cleanup. Use it for code that logs through
// slog.Default(); because it mutates global state the test must not run in
// parallel.
func Default(tb testing.TB) *Recorder {
	tb.Helper()
	rec := &Recorder{log: &recordLog{}}
	SwapDefault(tb, slog.New(rec))
	return rec
}

// SwapDefault installs logger as slog's default for the test and restores all
// three globals slog.SetDefault writes. It also points the log package at the
// installed handler and SKIPS that redirect for slog's own default handler, so
// restoring slog alone leaves log writing into a buffer nothing reads. slog
// goes back first: reinstalling a non-default handler re-runs the redirect and
// would undo an earlier log restore. Use it directly when the test asserts
// through its own handler rather than a Recorder; it mutates global state, so
// the test must not run in parallel.
func SwapDefault(tb testing.TB, logger *slog.Logger) {
	tb.Helper()
	prev, prevWriter, prevFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(logger)
	tb.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})
}

// Enabled reports true for every level so nothing is filtered before capture.
func (*Recorder) Enabled(context.Context, slog.Level) bool { return true }

// Handle records r with the handler's attributes and groups applied. It
// satisfies slog.Handler.
//
//nolint:gocritic // Handle's signature is fixed by the slog.Handler interface; r cannot be a pointer.
func (rec *Recorder) Handle(_ context.Context, r slog.Record) error {
	attrs := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	for _, sc := range slices.Backward(rec.scopes) {
		if sc.group != "" {
			attrs = []slog.Attr{slog.GroupAttrs(sc.group, attrs...)}
		} else {
			attrs = slices.Concat(sc.attrs, attrs)
		}
	}
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	out.AddAttrs(attrs...)
	rec.log.mu.Lock()
	defer rec.log.mu.Unlock()
	rec.log.records = append(rec.log.records, out)
	return nil
}

// WithAttrs returns a handler recording attrs on every record, inside the
// groups opened before it.
func (rec *Recorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return rec
	}
	return rec.with(scope{attrs: slices.Clone(attrs)})
}

// WithGroup returns a handler recording every later attribute inside group;
// an empty name returns rec, as slog.Handler requires.
func (rec *Recorder) WithGroup(group string) slog.Handler {
	if group == "" {
		return rec
	}
	return rec.with(scope{group: group})
}

func (rec *Recorder) with(sc scope) *Recorder {
	return &Recorder{log: rec.log, scopes: append(slices.Clip(rec.scopes), sc)}
}

// Records returns clones of the captured records whose message contains sub,
// in the order they were logged.
func (rec *Recorder) Records(sub string) []slog.Record {
	rec.log.mu.Lock()
	defer rec.log.mu.Unlock()
	var out []slog.Record
	for i := range rec.log.records {
		if strings.Contains(rec.log.records[i].Message, sub) {
			out = append(out, rec.log.records[i].Clone())
		}
	}
	return out
}

// CountMsg returns how many captured records have a message containing sub.
// Reached only by tests, like the rest of this package — see the package doc.
func (rec *Recorder) CountMsg(sub string) int {
	rec.log.mu.Lock()
	defer rec.log.mu.Unlock()
	n := 0
	for i := range rec.log.records {
		if strings.Contains(rec.log.records[i].Message, sub) {
			n++
		}
	}
	return n
}
