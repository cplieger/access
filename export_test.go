package access

import (
	"sync"
	"time"
)

// testClock is a clock a test sets by hand.
type testClock struct {
	at time.Time
	mu sync.Mutex
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) Set(at time.Time) {
	c.mu.Lock()
	c.at = at
	c.mu.Unlock()
}

// setVerifierClock makes a's built-in verifiers and their WARN limiters read
// c instead of time.Now.
func setVerifierClock(a *Authenticator, c *testClock) {
	a.sessions.now = c.Now
	a.keys.now = c.Now
	a.sessions.warn.now = c.Now
	a.keys.warn.now = c.Now
}
