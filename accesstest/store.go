// Package accesstest supports tests of access and its stores: [MemStore] is an
// in-memory [account.Store] for consumer tests, not for production, and
// [StoreContract] runs account's store contract against any store.
package accesstest

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// maxID is the largest ID a JSON number keeps exactly (rule 17).
const maxID = 1<<53 - 1

var (
	errHashTaken        = errors.New("accesstest: hash already stored")
	errSessionIDTaken   = errors.New("accesstest: session ID already stored")
	errHandleTaken      = errors.New("accesstest: WebAuthn handle already stored")
	errNoHash           = errors.New("accesstest: record has no hash")
	errNoSessionID      = errors.New("accesstest: session has no ID")
	errNoCredentialID   = errors.New("accesstest: passkey has no credential ID")
	errRotationIdentity = errors.New("accesstest: rotation changes the session's ID or user")
	errIDsExhausted     = errors.New("accesstest: IDs exhausted")
	errLimit            = errors.New("accesstest: cleanup limit below 1")
	errTimeouts         = errors.New("accesstest: cleanup timeouts not positive")
	errLogClass         = errors.New("accesstest: log entry of no LogClasses class")
	errLogLimit         = errors.New("accesstest: log limit below 1")
	errLogCriterion     = errors.New("accesstest: log prune needs exactly one of a positive Keep and a non-zero Before")
)

// MemStore is an in-memory [account.Store]. Every read returns a deep copy
// and every write stores one. Writers serialise on a mutex and publish a
// copied state through an atomic pointer, so a read takes no lock and never
// waits on a write. Construct it with [NewMemStore].
type MemStore struct {
	snap atomic.Pointer[state]
	mu   sync.Mutex
}

var _ account.Store = (*MemStore)(nil)

// NewMemStore returns a new empty MemStore.
func NewMemStore() *MemStore {
	m := &MemStore{}
	m.snap.Store(&state{
		users:      map[int64]access.User{},
		usernames:  map[string]int64{},
		oidc:       map[access.OIDCIdentity]int64{},
		handles:    map[string]int64{},
		sessions:   map[access.HashKey]access.Session{},
		sessionIDs: map[string]access.HashKey{},
		passkeys:   map[int64]access.PasskeyCredential{},
		credIDs:    map[string]int64{},
		keys:       map[int64]access.Key{},
		keyHashes:  map[access.HashKey]int64{},
		tokens:     map[access.HashKey]access.OneTimeToken{},
		failures:   map[account.FailureRef]account.FailureCount{},
		log:        map[account.LogClass]classLog{},
	})
	return m
}

// state is one published snapshot. A record stored in it is never changed
// in place: a write replaces the whole value in a cloned map, so a reader
// of an older snapshot never sees a write.
type state struct {
	users        map[int64]access.User
	usernames    map[string]int64
	oidc         map[access.OIDCIdentity]int64
	handles      map[string]int64 // string(WebAuthnHandle)
	sessions     map[access.HashKey]access.Session
	sessionIDs   map[string]access.HashKey
	passkeys     map[int64]access.PasskeyCredential
	credIDs      map[string]int64 // string(CredentialID)
	keys         map[int64]access.Key
	keyHashes    map[access.HashKey]int64
	tokens       map[access.HashKey]access.OneTimeToken
	failures     map[account.FailureRef]account.FailureCount
	log          map[account.LogClass]classLog
	attributions []access.KeyAttribution // ascending ID
	// The high-water marks of rules 17 and 22: a delete or a prune never
	// lowers them, and a rolled-back Update discards its copy, so no ID or
	// Seq is ever handed out twice.
	lastUser, lastPasskey, lastKey, lastAttribution int64
	lastLog                                         uint64
}

// classLog is one class's entries in ascending Seq and its Keep evictions.
type classLog struct {
	entries []account.LogEntry
	evicted uint64
}

func (s *state) clone() *state {
	c := *s
	c.users = maps.Clone(s.users)
	c.usernames = maps.Clone(s.usernames)
	c.oidc = maps.Clone(s.oidc)
	c.handles = maps.Clone(s.handles)
	c.sessions = maps.Clone(s.sessions)
	c.sessionIDs = maps.Clone(s.sessionIDs)
	c.passkeys = maps.Clone(s.passkeys)
	c.credIDs = maps.Clone(s.credIDs)
	c.keys = maps.Clone(s.keys)
	c.keyHashes = maps.Clone(s.keyHashes)
	c.tokens = maps.Clone(s.tokens)
	c.failures = maps.Clone(s.failures)
	c.attributions = slices.Clone(s.attributions)
	c.log = make(map[account.LogClass]classLog, len(s.log))
	for class, l := range s.log {
		c.log[class] = classLog{entries: slices.Clone(l.entries), evicted: l.evicted}
	}
	return &c
}

func nextID(last *int64) (int64, error) {
	if *last >= maxID {
		return 0, errIDsExhausted
	}
	*last++
	return *last, nil
}

// view is a read on the published snapshot.
func (m *MemStore) view() *memTx { return &memTx{s: m.snap.Load()} }

// write runs fn on a private copy of the snapshot under the writer mutex and
// publishes the copy when fn changed it without error. A panic in fn
// publishes nothing and propagates.
func (m *MemStore) write(fn func(tx *memTx) (changed bool, err error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx := &memTx{s: m.snap.Load().clone()}
	changed, err := fn(tx)
	if err != nil || !changed {
		return err
	}
	m.snap.Store(tx.s)
	return nil
}

// Update runs fn on a private copy of the store and publishes it when fn
// returns nil; an error or a panic publishes nothing.
func (m *MemStore) Update(_ context.Context, fn func(tx account.Tx) error) error {
	return m.write(func(tx *memTx) (bool, error) { return true, fn(tx) })
}

// memTx implements [account.Tx] over one state: the published snapshot for
// a read, a private copy for a write.
type memTx struct{ s *state }

var _ account.Tx = (*memTx)(nil)

// --- Users ---

// claims reports the first uniqueness rule u breaks against every other user.
func (t *memTx) claims(u *access.User) error {
	if id, ok := t.s.usernames[u.Username]; ok && id != u.ID {
		return account.ErrUsernameTaken
	}
	if !u.OIDC.IsZero() {
		if id, ok := t.s.oidc[u.OIDC]; ok && id != u.ID {
			return account.ErrOIDCIdentityTaken
		}
	}
	if len(u.WebAuthnHandle) > 0 {
		if id, ok := t.s.handles[string(u.WebAuthnHandle)]; ok && id != u.ID {
			return errHandleTaken
		}
	}
	return nil
}

func (t *memTx) unindexUser(id int64) {
	old, ok := t.s.users[id]
	if !ok {
		return
	}
	delete(t.s.usernames, old.Username)
	if !old.OIDC.IsZero() {
		delete(t.s.oidc, old.OIDC)
	}
	if len(old.WebAuthnHandle) > 0 {
		delete(t.s.handles, string(old.WebAuthnHandle))
	}
	delete(t.s.users, id)
}

func (t *memTx) putUser(u *access.User) {
	t.unindexUser(u.ID)
	t.s.users[u.ID] = *u.Clone()
	t.s.usernames[u.Username] = u.ID
	if !u.OIDC.IsZero() {
		t.s.oidc[u.OIDC] = u.ID
	}
	if len(u.WebAuthnHandle) > 0 {
		t.s.handles[string(u.WebAuthnHandle)] = u.ID
	}
}

func (t *memTx) CreateUser(_ context.Context, user *access.User) error {
	cp := user.Clone()
	cp.ID = 0
	if err := t.claims(cp); err != nil {
		return err
	}
	id, err := nextID(&t.s.lastUser)
	if err != nil {
		return err
	}
	cp.ID = id
	t.putUser(cp)
	user.ID = id
	return nil
}

func (t *memTx) CreateInitialUser(ctx context.Context, user *access.User) error {
	if len(t.s.users) > 0 {
		return account.ErrSetupComplete
	}
	return t.CreateUser(ctx, user)
}

func (t *memTx) userBy(id int64, ok bool) (*access.User, bool, error) {
	if !ok {
		return nil, false, nil
	}
	u, ok := t.s.users[id]
	if !ok {
		return nil, false, nil
	}
	return u.Clone(), true, nil
}

func (t *memTx) UserByID(_ context.Context, id int64) (*access.User, bool, error) {
	return t.userBy(id, true)
}

func (t *memTx) UserByUsername(_ context.Context, canonical string) (*access.User, bool, error) {
	id, ok := t.s.usernames[canonical]
	return t.userBy(id, ok)
}

func (t *memTx) UserByOIDC(_ context.Context, ident access.OIDCIdentity) (*access.User, bool, error) {
	id, ok := t.s.oidc[ident]
	return t.userBy(id, ok && !ident.IsZero())
}

func (t *memTx) UserByWebAuthnHandle(_ context.Context, handle []byte) (*access.User, bool, error) {
	id, ok := t.s.handles[string(handle)]
	return t.userBy(id, ok && len(handle) > 0)
}

func (t *memTx) ListUsers(context.Context) ([]access.User, error) {
	out := make([]access.User, 0, len(t.s.users))
	for _, id := range slices.Sorted(maps.Keys(t.s.users)) {
		out = append(out, *new(t.s.users[id]).Clone())
	}
	return out, nil
}

func (t *memTx) UpdateUser(_ context.Context, user *access.User) error {
	if _, ok := t.s.users[user.ID]; !ok {
		return account.ErrNotFound
	}
	if err := t.claims(user); err != nil {
		return err
	}
	t.putUser(user)
	return nil
}

func (t *memTx) DeleteUser(_ context.Context, id int64) error {
	if _, ok := t.s.users[id]; !ok {
		return account.ErrNotFound
	}
	t.unindexUser(id)
	t.deleteUserSessions(id, "")
	t.deleteUserPasskeys(id)
	t.deleteUserKeys(id)
	for k, tok := range t.s.tokens {
		if tok.Subject == id {
			delete(t.s.tokens, k)
		}
	}
	t.s.attributions = slices.DeleteFunc(t.s.attributions, func(a access.KeyAttribution) bool { return a.UserID == id })
	return nil
}

func (t *memTx) UserCount(context.Context) (int, error) { return len(t.s.users), nil }

// --- Sessions ---

func (t *memTx) CreateSession(_ context.Context, sess *access.Session) error {
	switch {
	case sess.TokenHash.IsZero():
		return errNoHash
	case sess.ID == "":
		return errNoSessionID
	}
	key := sess.TokenHash.Key()
	if _, ok := t.s.sessions[key]; ok {
		return errHashTaken
	}
	if _, ok := t.s.sessionIDs[sess.ID]; ok {
		return errSessionIDTaken
	}
	t.s.sessions[key] = *sess
	t.s.sessionIDs[sess.ID] = key
	return nil
}

func (t *memTx) SessionByHash(_ context.Context, tokenHash access.Hash) (*access.Session, bool, error) {
	s, ok := t.s.sessions[tokenHash.Key()]
	if !ok {
		return nil, false, nil
	}
	return &s, true, nil
}

func (t *memTx) SessionsByUserID(_ context.Context, userID int64) ([]access.Session, error) {
	out := []access.Session{}
	for key := range t.s.sessions {
		if s := t.s.sessions[key]; s.UserID == userID {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b access.Session) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

// activity applies rule 21 and reports whether it wrote.
func (t *memTx) activity(tokenHash access.Hash, act access.SessionActivity) bool {
	key := tokenHash.Key()
	s, ok := t.s.sessions[key]
	if !ok || !act.At.After(s.LastActivity) {
		return false
	}
	s.LastActivity, s.LastIP = act.At, act.IP
	t.s.sessions[key] = s
	return true
}

func (t *memTx) UpdateSessionActivity(_ context.Context, tokenHash access.Hash, act access.SessionActivity) error {
	t.activity(tokenHash, act)
	return nil
}

// owned returns the hash key of ref's session when ref names a session of
// ref.UserID.
func (t *memTx) owned(ref access.SessionRef) (access.HashKey, bool) {
	key, ok := t.s.sessionIDs[ref.ID]
	if !ok || ref.UserID == 0 || t.s.sessions[key].UserID != ref.UserID {
		return access.HashKey{}, false
	}
	return key, true
}

func (t *memTx) RotateSession(_ context.Context, rot account.Rotation) error { //nolint:gocritic // hugeParam: account.SessionStore's signature
	key, ok := t.owned(access.SessionRef{ID: rot.ID, UserID: rot.UserID})
	if !ok {
		return account.ErrNotFound
	}
	cur := t.s.sessions[key]
	if !rot.ExpectHash.IsZero() && !rot.ExpectHash.Equal(cur.TokenHash) {
		return account.ErrNotFound
	}
	next := rot.Next
	switch {
	case next.ID != rot.ID || next.UserID != rot.UserID:
		return errRotationIdentity
	case next.TokenHash.IsZero():
		return errNoHash
	}
	nextKey := next.TokenHash.Key()
	if _, taken := t.s.sessions[nextKey]; taken && nextKey != key {
		return errHashTaken
	}
	if cur.LastActivity.After(next.LastActivity) {
		next.LastActivity, next.LastIP = cur.LastActivity, cur.LastIP
	}
	delete(t.s.sessions, key)
	t.s.sessions[nextKey] = next
	t.s.sessionIDs[next.ID] = nextKey
	return nil
}

func (t *memTx) UpdateSessionLabel(_ context.Context, ref access.SessionRef, label string) error {
	key, ok := t.owned(ref)
	if !ok {
		return account.ErrNotFound
	}
	s := t.s.sessions[key]
	s.Label = label
	t.s.sessions[key] = s
	return nil
}

func (t *memTx) has(key access.HashKey) bool {
	_, ok := t.s.sessions[key]
	return ok
}

func (t *memTx) deleteSession(key access.HashKey) {
	delete(t.s.sessionIDs, t.s.sessions[key].ID)
	delete(t.s.sessions, key)
}

func (t *memTx) DeleteSession(_ context.Context, ref access.SessionRef) error {
	key, ok := t.owned(ref)
	if !ok {
		return account.ErrNotFound
	}
	t.deleteSession(key)
	return nil
}

func (t *memTx) DeleteSessionByHash(_ context.Context, tokenHash access.Hash) error {
	if key := tokenHash.Key(); t.has(key) {
		t.deleteSession(key)
	}
	return nil
}

func (t *memTx) deleteUserSessions(userID int64, exceptID string) []string {
	ids := []string{}
	for key := range t.s.sessions {
		if s := t.s.sessions[key]; s.UserID == userID && s.ID != exceptID {
			ids = append(ids, s.ID)
			t.deleteSession(key)
		}
	}
	slices.Sort(ids)
	return ids
}

func (t *memTx) DeleteUserSessions(_ context.Context, userID int64, exceptID string) ([]string, error) {
	return t.deleteUserSessions(userID, exceptID), nil
}

// --- Passkeys ---

func (t *memTx) CreatePasskey(_ context.Context, cred *access.PasskeyCredential) error {
	if len(cred.CredentialID) == 0 {
		return errNoCredentialID
	}
	if _, ok := t.s.credIDs[string(cred.CredentialID)]; ok {
		return account.ErrDuplicateCredential
	}
	id, err := nextID(&t.s.lastPasskey)
	if err != nil {
		return err
	}
	cp := cred.Clone()
	cp.ID = id
	t.s.passkeys[id] = *cp
	t.s.credIDs[string(cp.CredentialID)] = id
	cred.ID = id
	return nil
}

func (t *memTx) PasskeysByUserID(_ context.Context, userID int64) ([]access.PasskeyCredential, error) {
	out := []access.PasskeyCredential{}
	for _, id := range slices.Sorted(maps.Keys(t.s.passkeys)) {
		if p := t.s.passkeys[id]; p.UserID == userID {
			out = append(out, *p.Clone())
		}
	}
	return out, nil
}

func (t *memTx) UpdatePasskeyAfterLogin(_ context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error {
	id, ok := t.s.credIDs[string(credID)]
	p := t.s.passkeys[id]
	if !ok || userID == 0 || p.UserID != userID {
		return account.ErrNotFound
	}
	p.LastUsedAt, p.SignCount, p.RawFlags, p.CloneWarning = upd.At, upd.SignCount, upd.RawFlags, upd.CloneWarning
	p.UserPresent, p.UserVerified, p.BackupEligible, p.BackupState = access.DecodePasskeyFlags(upd.RawFlags)
	t.s.passkeys[id] = p
	return nil
}

func (t *memTx) ownedPasskey(ref access.PasskeyRef) (access.PasskeyCredential, bool) {
	p, ok := t.s.passkeys[ref.ID]
	return p, ok && ref.UserID != 0 && p.UserID == ref.UserID
}

func (t *memTx) RenamePasskey(_ context.Context, ref access.PasskeyRef, name string) error {
	p, ok := t.ownedPasskey(ref)
	if !ok {
		return account.ErrNotFound
	}
	p.Name = name
	t.s.passkeys[p.ID] = p
	return nil
}

func (t *memTx) deletePasskey(id int64) {
	delete(t.s.credIDs, string(t.s.passkeys[id].CredentialID))
	delete(t.s.passkeys, id)
}

func (t *memTx) DeletePasskey(_ context.Context, ref access.PasskeyRef) error {
	p, ok := t.ownedPasskey(ref)
	if !ok {
		return account.ErrNotFound
	}
	t.deletePasskey(p.ID)
	return nil
}

func (t *memTx) deleteUserPasskeys(userID int64) []int64 {
	ids := []int64{}
	for _, id := range slices.Sorted(maps.Keys(t.s.passkeys)) {
		if t.s.passkeys[id].UserID == userID {
			ids = append(ids, id)
			t.deletePasskey(id)
		}
	}
	return ids
}

func (t *memTx) DeleteUserPasskeys(_ context.Context, userID int64) ([]int64, error) {
	return t.deleteUserPasskeys(userID), nil
}

// --- API keys ---

func (t *memTx) CreateAPIKey(_ context.Context, key *access.Key) error {
	if key.KeyHash.IsZero() {
		return errNoHash
	}
	hk := key.KeyHash.Key()
	if _, ok := t.s.keyHashes[hk]; ok {
		return errHashTaken
	}
	id, err := nextID(&t.s.lastKey)
	if err != nil {
		return err
	}
	cp := key.Clone()
	cp.ID = id
	cp.LineageIDs = append(cp.LineageIDs, id)
	t.s.keys[id] = *cp
	t.s.keyHashes[hk] = id
	key.ID, key.LineageIDs = id, slices.Clone(cp.LineageIDs)
	return nil
}

func (t *memTx) APIKeyByHash(_ context.Context, hash access.Hash) (*access.Key, bool, error) {
	id, ok := t.s.keyHashes[hash.Key()]
	if !ok {
		return nil, false, nil
	}
	return new(t.s.keys[id]).Clone(), true, nil
}

func (t *memTx) listKeys(match func(access.Key) bool) []access.Key {
	out := []access.Key{}
	for _, id := range slices.Sorted(maps.Keys(t.s.keys)) {
		if k := t.s.keys[id]; match(k) {
			out = append(out, *k.Clone())
		}
	}
	return out
}

func (t *memTx) ListAPIKeysByUserID(_ context.Context, userID int64) ([]access.Key, error) {
	return t.listKeys(func(k access.Key) bool { return k.UserID == userID }), nil
}

func (t *memTx) ListAPIKeys(context.Context) ([]access.Key, error) {
	return t.listKeys(func(access.Key) bool { return true }), nil
}

func (t *memTx) deleteKey(id int64) {
	delete(t.s.keyHashes, t.s.keys[id].KeyHash.Key())
	delete(t.s.keys, id)
}

func (t *memTx) DeleteAPIKey(_ context.Context, ref access.KeyRef) error {
	k, ok := t.s.keys[ref.ID]
	if !ok || ref.UserID == 0 || k.UserID != ref.UserID {
		return account.ErrNotFound
	}
	t.deleteKey(k.ID)
	return nil
}

func (t *memTx) deleteUserKeys(userID int64) []int64 {
	ids := []int64{}
	for _, id := range slices.Sorted(maps.Keys(t.s.keys)) {
		if t.s.keys[id].UserID == userID {
			ids = append(ids, id)
			t.deleteKey(id)
		}
	}
	return ids
}

func (t *memTx) DeleteUserAPIKeys(_ context.Context, userID int64) ([]int64, error) {
	return t.deleteUserKeys(userID), nil
}

// touch applies rule 21 to a key and reports whether it wrote.
func (t *memTx) touch(keyID int64, at time.Time) bool {
	k, ok := t.s.keys[keyID]
	if !ok || !at.After(k.LastUsedAt) {
		return false
	}
	k.LastUsedAt = at
	t.s.keys[keyID] = k
	return true
}

func (t *memTx) TouchAPIKey(_ context.Context, keyID int64, at time.Time) error {
	t.touch(keyID, at)
	return nil
}

// --- One-time tokens ---

func (t *memTx) CreateOneTimeToken(_ context.Context, tok access.OneTimeToken) error { //nolint:gocritic // hugeParam: account.TokenStore's signature
	if tok.Hash.IsZero() {
		return errNoHash
	}
	key := tok.Hash.Key()
	if _, ok := t.s.tokens[key]; ok {
		return errHashTaken
	}
	t.s.tokens[key] = tok
	return nil
}

func (t *memTx) OneTimeTokenByHash(_ context.Context, hash access.Hash) (access.OneTimeToken, bool, error) {
	tok, ok := t.s.tokens[hash.Key()]
	return tok, ok, nil
}

// consume deletes hash's token and returns it when it is live at now; it
// reports whether it deleted one.
func (t *memTx) consume(hash access.Hash, now time.Time) (tok access.OneTimeToken, found, deleted bool) {
	key := hash.Key()
	tok, ok := t.s.tokens[key]
	if !ok {
		return access.OneTimeToken{}, false, false
	}
	delete(t.s.tokens, key)
	if !tok.ExpiresAt.After(now) {
		return access.OneTimeToken{}, false, true
	}
	return tok, true, true
}

func (t *memTx) ConsumeOneTimeToken(_ context.Context, hash access.Hash, now time.Time) (access.OneTimeToken, bool, error) {
	tok, found, _ := t.consume(hash, now)
	return tok, found, nil
}

func (t *memTx) deleteTokens(match func(access.OneTimeToken) bool) int {
	n := 0
	for key, tok := range t.s.tokens {
		if match(tok) {
			delete(t.s.tokens, key)
			n++
		}
	}
	return n
}

func (t *memTx) DeleteOneTimeTokens(_ context.Context, purpose access.TokenPurpose, subject int64) (int, error) {
	return t.deleteTokens(func(tok access.OneTimeToken) bool { return tok.Purpose == purpose && tok.Subject == subject }), nil
}

func (t *memTx) LiveOneTimeTokens(_ context.Context, purposes []access.TokenPurpose, now time.Time) ([]access.OneTimeToken, error) {
	out := []access.OneTimeToken{}
	for _, tok := range t.s.tokens {
		if slices.Contains(purposes, tok.Purpose) && tok.ExpiresAt.After(now) {
			out = append(out, tok)
		}
	}
	return out, nil
}

func (t *memTx) deleteIssuedBy(keyIDs []int64) int {
	return t.deleteTokens(func(tok access.OneTimeToken) bool {
		return tok.IssuedByKey != 0 && slices.Contains(keyIDs, tok.IssuedByKey)
	})
}

func (t *memTx) DeleteOneTimeTokensIssuedBy(_ context.Context, keyIDs []int64) (int, error) {
	return t.deleteIssuedBy(keyIDs), nil
}

// --- Key attributions ---

func (t *memTx) CreateKeyAttribution(_ context.Context, a *access.KeyAttribution) error {
	id, err := nextID(&t.s.lastAttribution)
	if err != nil {
		return err
	}
	cp := a.Clone()
	cp.ID = id
	t.s.attributions = append(t.s.attributions, *cp)
	a.ID = id
	return nil
}

func (t *memTx) ListKeyAttributions(context.Context) ([]access.KeyAttribution, error) {
	out := make([]access.KeyAttribution, 0, len(t.s.attributions))
	for i := range t.s.attributions {
		out = append(out, *t.s.attributions[i].Clone())
	}
	return out, nil
}

// --- Failure records ---

func (t *memTx) AuthFailure(_ context.Context, ref account.FailureRef) (account.FailureCount, bool, error) {
	f, ok := t.s.failures[ref]
	return f, ok, nil
}

func (t *memTx) PutAuthFailure(_ context.Context, f account.FailureCount) error { //nolint:gocritic // hugeParam: account.FailureStore's signature
	t.s.failures[f.FailureRef] = f
	return nil
}

func (t *memTx) UnreportedLocks(context.Context) ([]account.FailureCount, error) {
	out := []account.FailureCount{}
	for _, f := range t.s.failures {
		if f.Unreported {
			out = append(out, f)
		}
	}
	return out, nil
}

func (t *memTx) DeleteAuthFailures(_ context.Context, name string, methods []access.Method) error {
	for _, m := range methods {
		for _, trusted := range []bool{false, true} {
			delete(t.s.failures, account.FailureRef{Name: name, Method: m, Trusted: trusted})
		}
	}
	return nil
}

func (t *memTx) prune(keep []string) int64 {
	var n int64
	for ref := range t.s.failures {
		if !slices.Contains(keep, ref.Name) {
			delete(t.s.failures, ref)
			n++
		}
	}
	return n
}

func (t *memTx) PruneAuthFailures(_ context.Context, keep []string) (int64, error) {
	return t.prune(keep), nil
}

// --- Security log ---

// cloneEntry returns a deep copy of e.
func cloneEntry(e *account.LogEntry) account.LogEntry {
	cp := *e
	cp.Event.SessionIDs = slices.Clone(e.Event.SessionIDs)
	return cp
}

func (t *memTx) AppendLog(_ context.Context, e *account.LogEntry) error {
	if !slices.Contains(account.LogClasses(), e.Class) {
		return errLogClass
	}
	if t.s.lastLog >= maxID {
		return errIDsExhausted
	}
	t.s.lastLog++
	cp := cloneEntry(e)
	cp.Event.Seq = t.s.lastLog
	l := t.s.log[e.Class]
	l.entries = append(l.entries, cp)
	t.s.log[e.Class] = l
	e.Event.Seq = cp.Event.Seq
	return nil
}

func (t *memTx) ListLog(_ context.Context, r account.LogRange) ([]account.LogEntry, error) {
	if r.Limit < 1 {
		return nil, errLogLimit
	}
	out := []account.LogEntry{}
	for _, class := range account.LogClasses() {
		for i := range t.s.log[class].entries {
			e := &t.s.log[class].entries[i]
			if seq := e.Event.Seq; seq > r.AfterSeq && (r.BeforeSeq == 0 || seq < r.BeforeSeq) {
				out = append(out, cloneEntry(e))
			}
		}
	}
	slices.SortFunc(out, func(a, b account.LogEntry) int {
		if r.Descending {
			a, b = b, a
		}
		return cmp.Compare(a.Event.Seq, b.Event.Seq)
	})
	return out[:min(r.Limit, len(out))], nil
}

// pruneLog applies p to the copy and returns how many entries it removed.
func (t *memTx) pruneLog(p account.LogPrune) (int, error) {
	switch {
	case p.Limit < 1:
		return 0, errLogLimit
	case p.Keep < 0, (p.Keep > 0) == !p.Before.IsZero():
		return 0, errLogCriterion
	}
	l, ok := t.s.log[p.Class]
	if !ok {
		return 0, nil
	}
	var n int
	if p.Keep > 0 {
		n = min(p.Limit, max(len(l.entries)-p.Keep, 0))
		l.entries = l.entries[n:]
		l.evicted += uint64(n)
	} else {
		l.entries = slices.DeleteFunc(l.entries, func(e account.LogEntry) bool {
			if n < p.Limit && e.At.Before(p.Before) {
				n++
				return true
			}
			return false
		})
	}
	t.s.log[p.Class] = l
	return n, nil
}

func (t *memTx) PruneLog(_ context.Context, p account.LogPrune) (int, error) {
	return t.pruneLog(p)
}

func (t *memTx) LogStats(context.Context) ([]account.LogClassStats, error) {
	out := []account.LogClassStats{}
	for _, class := range account.LogClasses() {
		if l, ok := t.s.log[class]; ok {
			out = append(out, account.LogClassStats{Class: class, Count: len(l.entries), Evicted: l.evicted})
		}
	}
	return out, nil
}

// --- Sweeper ---

// cleanup deletes up to limit sessions ValidateSession refuses, in session ID
// order, and returns their refs.
func (t *memTx) cleanup(now time.Time, timeouts access.SessionTimeouts, limit int) []access.SessionRef {
	var expired []access.SessionRef
	for key := range t.s.sessions {
		if s := t.s.sessions[key]; access.ValidateSession(&s, timeouts, now) != nil {
			expired = append(expired, access.SessionRef{ID: s.ID, UserID: s.UserID})
		}
	}
	slices.SortFunc(expired, func(a, b access.SessionRef) int { return cmp.Compare(a.ID, b.ID) })
	expired = expired[:min(limit, len(expired))]
	for _, ref := range expired {
		t.deleteSession(t.s.sessionIDs[ref.ID])
	}
	return expired
}

// CleanupExpiredSessions deletes at most limit of the sessions
// [access.ValidateSession] refuses, in one snapshot swap, and returns their
// refs. It refuses a limit below 1 and a non-positive timeout.
func (m *MemStore) CleanupExpiredSessions(_ context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	switch {
	case limit < 1:
		return nil, errLimit
	case timeouts.Idle <= 0 || timeouts.Absolute <= 0:
		return nil, errTimeouts
	}
	var refs []access.SessionRef
	err := m.write(func(tx *memTx) (bool, error) {
		refs = tx.cleanup(now, timeouts, limit)
		return len(refs) > 0, nil
	})
	return refs, err
}

// CleanupExpiredOneTimeTokens deletes every token whose ExpiresAt is not
// after now.
func (m *MemStore) CleanupExpiredOneTimeTokens(_ context.Context, now time.Time) (int64, error) {
	var n int
	err := m.write(func(tx *memTx) (bool, error) {
		n = tx.deleteTokens(func(tok access.OneTimeToken) bool { return !tok.ExpiresAt.After(now) })
		return n > 0, nil
	})
	return int64(n), err
}

// --- MemStore: reads load the snapshot, writes go through write ---

// CreateUser implements [account.UserStore].
func (m *MemStore) CreateUser(ctx context.Context, user *access.User) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.CreateUser(ctx, user) })
}

// CreateInitialUser implements [account.UserStore].
func (m *MemStore) CreateInitialUser(ctx context.Context, user *access.User) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.CreateInitialUser(ctx, user) })
}

// UserByID implements [account.UserStore].
func (m *MemStore) UserByID(ctx context.Context, id int64) (*access.User, bool, error) {
	return m.view().UserByID(ctx, id)
}

// UserByUsername implements [account.UserStore].
func (m *MemStore) UserByUsername(ctx context.Context, canonical string) (*access.User, bool, error) {
	return m.view().UserByUsername(ctx, canonical)
}

// UserByOIDC implements [account.UserStore].
func (m *MemStore) UserByOIDC(ctx context.Context, id access.OIDCIdentity) (*access.User, bool, error) {
	return m.view().UserByOIDC(ctx, id)
}

// UserByWebAuthnHandle implements [account.UserStore].
func (m *MemStore) UserByWebAuthnHandle(ctx context.Context, handle []byte) (*access.User, bool, error) {
	return m.view().UserByWebAuthnHandle(ctx, handle)
}

// ListUsers implements [account.UserStore].
func (m *MemStore) ListUsers(ctx context.Context) ([]access.User, error) {
	return m.view().ListUsers(ctx)
}

// UpdateUser implements [account.UserStore].
func (m *MemStore) UpdateUser(ctx context.Context, user *access.User) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.UpdateUser(ctx, user) })
}

// DeleteUser implements [account.UserStore].
func (m *MemStore) DeleteUser(ctx context.Context, id int64) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.DeleteUser(ctx, id) })
}

// UserCount implements [account.UserStore].
func (m *MemStore) UserCount(ctx context.Context) (int, error) { return m.view().UserCount(ctx) }

// CreateSession implements [account.SessionStore].
func (m *MemStore) CreateSession(ctx context.Context, sess *access.Session) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.CreateSession(ctx, sess) })
}

// SessionByHash implements [account.SessionStore].
func (m *MemStore) SessionByHash(ctx context.Context, tokenHash access.Hash) (*access.Session, bool, error) {
	return m.view().SessionByHash(ctx, tokenHash)
}

// SessionsByUserID implements [account.SessionStore].
func (m *MemStore) SessionsByUserID(ctx context.Context, userID int64) ([]access.Session, error) {
	return m.view().SessionsByUserID(ctx, userID)
}

// UpdateSessionActivity keeps rule 21: an At not after the stored
// LastActivity, or a hash no session has, publishes nothing.
func (m *MemStore) UpdateSessionActivity(_ context.Context, tokenHash access.Hash, act access.SessionActivity) error {
	return m.write(func(tx *memTx) (bool, error) { return tx.activity(tokenHash, act), nil })
}

// RotateSession implements [account.SessionStore].
func (m *MemStore) RotateSession(ctx context.Context, rot account.Rotation) error { //nolint:gocritic // hugeParam: account.SessionStore's signature
	return m.write(func(tx *memTx) (bool, error) { return true, tx.RotateSession(ctx, rot) })
}

// UpdateSessionLabel implements [account.SessionStore].
func (m *MemStore) UpdateSessionLabel(ctx context.Context, ref access.SessionRef, label string) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.UpdateSessionLabel(ctx, ref, label) })
}

// DeleteSession implements [account.SessionStore].
func (m *MemStore) DeleteSession(ctx context.Context, ref access.SessionRef) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.DeleteSession(ctx, ref) })
}

// DeleteSessionByHash implements [account.SessionStore].
func (m *MemStore) DeleteSessionByHash(ctx context.Context, tokenHash access.Hash) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.DeleteSessionByHash(ctx, tokenHash) })
}

// DeleteUserSessions implements [account.SessionStore].
func (m *MemStore) DeleteUserSessions(_ context.Context, userID int64, exceptID string) ([]string, error) {
	var ids []string
	err := m.write(func(tx *memTx) (bool, error) {
		ids = tx.deleteUserSessions(userID, exceptID)
		return len(ids) > 0, nil
	})
	return ids, err
}

// CreatePasskey implements [account.PasskeyStore].
func (m *MemStore) CreatePasskey(ctx context.Context, cred *access.PasskeyCredential) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.CreatePasskey(ctx, cred) })
}

// PasskeysByUserID implements [account.PasskeyStore].
func (m *MemStore) PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error) {
	return m.view().PasskeysByUserID(ctx, userID)
}

// UpdatePasskeyAfterLogin implements [account.PasskeyStore].
func (m *MemStore) UpdatePasskeyAfterLogin(ctx context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.UpdatePasskeyAfterLogin(ctx, userID, credID, upd) })
}

// RenamePasskey implements [account.PasskeyStore].
func (m *MemStore) RenamePasskey(ctx context.Context, ref access.PasskeyRef, name string) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.RenamePasskey(ctx, ref, name) })
}

// DeletePasskey implements [account.PasskeyStore].
func (m *MemStore) DeletePasskey(ctx context.Context, ref access.PasskeyRef) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.DeletePasskey(ctx, ref) })
}

// DeleteUserPasskeys implements [account.PasskeyStore].
func (m *MemStore) DeleteUserPasskeys(_ context.Context, userID int64) ([]int64, error) {
	var ids []int64
	err := m.write(func(tx *memTx) (bool, error) {
		ids = tx.deleteUserPasskeys(userID)
		return len(ids) > 0, nil
	})
	return ids, err
}

// CreateAPIKey implements [account.KeyStore].
func (m *MemStore) CreateAPIKey(ctx context.Context, key *access.Key) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.CreateAPIKey(ctx, key) })
}

// APIKeyByHash implements [account.KeyStore].
func (m *MemStore) APIKeyByHash(ctx context.Context, hash access.Hash) (*access.Key, bool, error) {
	return m.view().APIKeyByHash(ctx, hash)
}

// ListAPIKeysByUserID implements [account.KeyStore].
func (m *MemStore) ListAPIKeysByUserID(ctx context.Context, userID int64) ([]access.Key, error) {
	return m.view().ListAPIKeysByUserID(ctx, userID)
}

// ListAPIKeys implements [account.KeyStore].
func (m *MemStore) ListAPIKeys(ctx context.Context) ([]access.Key, error) {
	return m.view().ListAPIKeys(ctx)
}

// DeleteAPIKey implements [account.KeyStore].
func (m *MemStore) DeleteAPIKey(ctx context.Context, ref access.KeyRef) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.DeleteAPIKey(ctx, ref) })
}

// DeleteUserAPIKeys implements [account.KeyStore].
func (m *MemStore) DeleteUserAPIKeys(_ context.Context, userID int64) ([]int64, error) {
	var ids []int64
	err := m.write(func(tx *memTx) (bool, error) {
		ids = tx.deleteUserKeys(userID)
		return len(ids) > 0, nil
	})
	return ids, err
}

// TouchAPIKey keeps rule 21: an at not after the stored LastUsedAt, or an
// unknown key, publishes nothing.
func (m *MemStore) TouchAPIKey(_ context.Context, keyID int64, at time.Time) error {
	return m.write(func(tx *memTx) (bool, error) { return tx.touch(keyID, at), nil })
}

// CreateOneTimeToken implements [account.TokenStore].
func (m *MemStore) CreateOneTimeToken(ctx context.Context, tok access.OneTimeToken) error { //nolint:gocritic // hugeParam: account.TokenStore's signature
	return m.write(func(tx *memTx) (bool, error) { return true, tx.CreateOneTimeToken(ctx, tok) })
}

// OneTimeTokenByHash implements [account.TokenStore].
func (m *MemStore) OneTimeTokenByHash(ctx context.Context, hash access.Hash) (access.OneTimeToken, bool, error) {
	return m.view().OneTimeTokenByHash(ctx, hash)
}

// ConsumeOneTimeToken implements [account.TokenStore].
func (m *MemStore) ConsumeOneTimeToken(_ context.Context, hash access.Hash, now time.Time) (access.OneTimeToken, bool, error) {
	var (
		tok   access.OneTimeToken
		found bool
	)
	err := m.write(func(tx *memTx) (bool, error) {
		var deleted bool
		tok, found, deleted = tx.consume(hash, now)
		return deleted, nil
	})
	return tok, found, err
}

// DeleteOneTimeTokens implements [account.TokenStore].
func (m *MemStore) DeleteOneTimeTokens(_ context.Context, purpose access.TokenPurpose, subject int64) (int, error) {
	var n int
	err := m.write(func(tx *memTx) (bool, error) {
		n = tx.deleteTokens(func(tok access.OneTimeToken) bool { return tok.Purpose == purpose && tok.Subject == subject })
		return n > 0, nil
	})
	return n, err
}

// LiveOneTimeTokens implements [account.TokenStore].
func (m *MemStore) LiveOneTimeTokens(ctx context.Context, purposes []access.TokenPurpose, now time.Time) ([]access.OneTimeToken, error) {
	return m.view().LiveOneTimeTokens(ctx, purposes, now)
}

// DeleteOneTimeTokensIssuedBy implements [account.TokenStore].
func (m *MemStore) DeleteOneTimeTokensIssuedBy(_ context.Context, keyIDs []int64) (int, error) {
	var n int
	err := m.write(func(tx *memTx) (bool, error) {
		n = tx.deleteIssuedBy(keyIDs)
		return n > 0, nil
	})
	return n, err
}

// CreateKeyAttribution implements [account.AttributionStore].
func (m *MemStore) CreateKeyAttribution(ctx context.Context, a *access.KeyAttribution) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.CreateKeyAttribution(ctx, a) })
}

// ListKeyAttributions implements [account.AttributionStore].
func (m *MemStore) ListKeyAttributions(ctx context.Context) ([]access.KeyAttribution, error) {
	return m.view().ListKeyAttributions(ctx)
}

// AuthFailure implements [account.FailureStore].
func (m *MemStore) AuthFailure(ctx context.Context, ref account.FailureRef) (account.FailureCount, bool, error) {
	return m.view().AuthFailure(ctx, ref)
}

// PutAuthFailure implements [account.FailureStore].
func (m *MemStore) PutAuthFailure(ctx context.Context, f account.FailureCount) error { //nolint:gocritic // hugeParam: account.FailureStore's signature
	return m.write(func(tx *memTx) (bool, error) { return true, tx.PutAuthFailure(ctx, f) })
}

// UnreportedLocks implements [account.FailureStore].
func (m *MemStore) UnreportedLocks(ctx context.Context) ([]account.FailureCount, error) {
	return m.view().UnreportedLocks(ctx)
}

// DeleteAuthFailures implements [account.FailureStore].
func (m *MemStore) DeleteAuthFailures(ctx context.Context, name string, methods []access.Method) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.DeleteAuthFailures(ctx, name, methods) })
}

// AppendLog implements [account.LogStore].
func (m *MemStore) AppendLog(ctx context.Context, e *account.LogEntry) error {
	return m.write(func(tx *memTx) (bool, error) { return true, tx.AppendLog(ctx, e) })
}

// ListLog implements [account.LogStore] on the published snapshot.
func (m *MemStore) ListLog(ctx context.Context, r account.LogRange) ([]account.LogEntry, error) {
	return m.view().ListLog(ctx, r)
}

// PruneLog implements [account.LogStore].
func (m *MemStore) PruneLog(_ context.Context, p account.LogPrune) (int, error) {
	var n int
	err := m.write(func(tx *memTx) (changed bool, err error) {
		n, err = tx.pruneLog(p)
		return n > 0, err
	})
	return n, err
}

// LogStats implements [account.LogStore] on the published snapshot.
func (m *MemStore) LogStats(ctx context.Context) ([]account.LogClassStats, error) {
	return m.view().LogStats(ctx)
}

// PruneAuthFailures implements [account.FailureStore].
func (m *MemStore) PruneAuthFailures(_ context.Context, keep []string) (int64, error) {
	var n int64
	err := m.write(func(tx *memTx) (bool, error) {
		n = tx.prune(keep)
		return n > 0, nil
	})
	return n, err
}
