package access

import (
	"context"
	"sync"
	"time"
)

// fakeSessionStore is an in-memory AuthenticatorStore plus the setup methods
// access tests need. Its activity and touch writes keep the account store
// contract's rule 21: an older or equal time writes nothing, and a touch
// carrying a hash other than the stored KeyHash writes nothing.
type fakeSessionStore struct {
	users    map[int64]*User
	sessions map[HashKey]*Session // keyed by TokenHash.Key()
	apiKeys  map[HashKey]*Key     // keyed by KeyHash.Key()
	nextID   int64
	mu       sync.Mutex
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{
		users:    make(map[int64]*User),
		sessions: make(map[HashKey]*Session),
		apiKeys:  make(map[HashKey]*Key),
		nextID:   1,
	}
}

// SessionByHash returns a copy: UpdateSessionActivity mutates the stored
// session under f.mu, so a returned alias read outside it is a data race.
func (f *fakeSessionStore) SessionByHash(_ context.Context, tokenHash Hash) (*Session, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[tokenHash.Key()]
	if !ok {
		return nil, false, nil
	}
	return new(*s), true, nil
}

func (f *fakeSessionStore) UserByID(_ context.Context, id int64) (*User, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return nil, false, nil
	}
	return new(*u), true, nil
}

func (f *fakeSessionStore) APIKeyByHash(_ context.Context, hash Hash) (*Key, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if hash.IsZero() {
		return nil, false, nil
	}
	if k, ok := f.apiKeys[hash.Key()]; ok {
		return new(*k), true, nil
	}
	for _, k := range f.apiKeys {
		if !k.PreviousHash.IsZero() && k.PreviousHash.Equal(hash) {
			return new(*k), true, nil
		}
	}
	return nil, false, nil
}

func (f *fakeSessionStore) UpdateSessionActivity(_ context.Context, tokenHash Hash, act SessionActivity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sessions[tokenHash.Key()]; ok && act.At.After(s.LastActivity) {
		s.LastActivity = act.At
		s.LastIP = act.IP
	}
	return nil
}

func (f *fakeSessionStore) TouchAPIKey(_ context.Context, keyID int64, hash Hash, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.apiKeys {
		if k.ID == keyID && k.KeyHash.Equal(hash) && at.After(k.LastUsedAt) {
			k.LastUsedAt = at
		}
	}
	return nil
}

func (f *fakeSessionStore) CreateUser(_ context.Context, u *User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u.ID = f.nextID
	f.nextID++
	cp := *u
	f.users[cp.ID] = &cp
	return nil
}

func (f *fakeSessionStore) CreateSession(_ context.Context, s *Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *s
	f.sessions[cp.TokenHash.Key()] = &cp
	return nil
}

func (f *fakeSessionStore) CreateAPIKey(_ context.Context, k *Key) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *k
	if cp.ID == 0 {
		cp.ID = f.nextID
		f.nextID++
	}
	f.apiKeys[cp.KeyHash.Key()] = &cp
	return nil
}

// deleteUserSessions revokes every session of userID, as an app's own
// store write would.
func (f *fakeSessionStore) deleteUserSessions(userID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for hash, s := range f.sessions {
		if s.UserID == userID {
			delete(f.sessions, hash)
		}
	}
}
