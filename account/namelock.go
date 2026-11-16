package account

import (
	"context"
	"sync"

	"github.com/cplieger/access/ratelimit"
)

// nameLocks orders the verifiers of one account's temporary password: at
// most one holds a name's lock, from admission through its success Update.
// An entry counts its holder and waiters and leaves the map at zero, so
// posts of names no account has leave nothing behind.
type nameLocks struct {
	byKey map[ratelimit.Account]*nameLock
	mu    sync.Mutex
}

type nameLock struct {
	// token is held by the lock's holder; a waiter's send blocks until the
	// holder's receive.
	token chan struct{}
	refs  int
}

func newNameLocks() *nameLocks { return &nameLocks{byKey: make(map[ratelimit.Account]*nameLock)} }

// lock waits for key's lock until ctx ends, which answers ctx.Err(). The
// returned unlock releases it and must be called once.
func (l *nameLocks) lock(ctx context.Context, key ratelimit.Account) (unlock func(), err error) {
	l.mu.Lock()
	e, ok := l.byKey[key]
	if !ok {
		e = &nameLock{token: make(chan struct{}, 1)}
		l.byKey[key] = e
	}
	e.refs++
	l.mu.Unlock()
	select {
	case e.token <- struct{}{}:
		return func() {
			<-e.token
			l.release(key, e)
		}, nil
	case <-ctx.Done():
		l.release(key, e)
		return nil, ctx.Err()
	}
}

func (l *nameLocks) release(key ratelimit.Account, e *nameLock) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.refs--
	if e.refs == 0 {
		delete(l.byKey, key)
	}
}
