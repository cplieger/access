package access

import (
	"log/slog"
	"sync"
	"time"
)

// warnInterval is how long after a WARN further occurrences of its message
// are only counted: a store failing every write, or a misconfigured proxy,
// would otherwise log once per request.
const warnInterval = time.Minute

// warnLimiter rate-limits one WARN message. Each message has its own, so
// each suppressed count is that message's.
type warnLimiter struct {
	last time.Time
	// now is read only under mu, so the times allow compares never run
	// backwards: a time read before the lock lets a later occurrence log
	// first and date the interval from the later instant.
	now        func() time.Time
	mu         sync.Mutex
	suppressed int
}

// allow reports whether an occurrence now logs and, when it does, the
// occurrences counted since the last WARN, resetting the count.
func (l *warnLimiter) allow() (ok bool, suppressed int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.last) < warnInterval {
		l.suppressed++
		return false, 0
	}
	suppressed, l.last, l.suppressed = l.suppressed, now, 0
	return true, suppressed
}

// log writes msg with args at WARN unless allow refuses, adding the
// suppressed count when it is not zero.
func (l *warnLimiter) log(logger *slog.Logger, msg string, args ...any) {
	ok, n := l.allow()
	if !ok {
		return
	}
	if n > 0 {
		args = append(args, "suppressed", n)
	}
	logger.Warn(msg, args...)
}
