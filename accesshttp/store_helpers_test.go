package accesshttp

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// countingStore counts every account.Store call it passes on, so a test
// can show a request made none. With mark set, only calls whose context
// carries that key count, so a background sweep does not. An Update's fn
// gets the transaction behind a countingStore too: its calls reach seen
// but count only as the Update.
type countingStore struct {
	next account.Tx
	// store is the store next is; nil in a transaction's view.
	store account.Store
	mark  any
	// seen, when set, gets every call: its name, its context and whether
	// it ran inside an Update's fn.
	seen  func(ctx context.Context, call string, inTx bool)
	calls atomic.Int64
}

var _ account.Store = (*countingStore)(nil)

// wrap makes st the store s passes calls on to.
func (s *countingStore) wrap(st account.Store) { s.next, s.store = st, st }

func (s *countingStore) count(ctx context.Context, call string) {
	if s.store != nil && (s.mark == nil || ctx.Value(s.mark) != nil) {
		s.calls.Add(1)
	}
	if s.seen != nil {
		s.seen(ctx, call, s.store == nil)
	}
}

func (s *countingStore) Update(ctx context.Context, fn func(account.Tx) error) error {
	s.count(ctx, "Update")
	return s.store.Update(ctx, func(tx account.Tx) error {
		return fn(&countingStore{next: tx, seen: s.seen})
	})
}

func (s *countingStore) CleanupExpiredOneTimeTokens(ctx context.Context, a1 time.Time) (int64, error) {
	s.count(ctx, "CleanupExpiredOneTimeTokens")
	return s.store.CleanupExpiredOneTimeTokens(ctx, a1)
}

func (s *countingStore) CleanupExpiredSessions(ctx context.Context, a1 time.Time, a2 access.SessionTimeouts, a3 int) ([]access.SessionRef, error) {
	s.count(ctx, "CleanupExpiredSessions")
	return s.store.CleanupExpiredSessions(ctx, a1, a2, a3)
}

func (s *countingStore) APIKeyByHash(ctx context.Context, a1 access.Hash) (*access.Key, bool, error) {
	s.count(ctx, "APIKeyByHash")
	return s.next.APIKeyByHash(ctx, a1)
}

func (s *countingStore) AuthFailure(ctx context.Context, a1 account.FailureRef) (account.FailureCount, bool, error) {
	s.count(ctx, "AuthFailure")
	return s.next.AuthFailure(ctx, a1)
}

func (s *countingStore) ConsumeOneTimeToken(ctx context.Context, a1 access.Hash, a2 time.Time) (access.OneTimeToken, bool, error) {
	s.count(ctx, "ConsumeOneTimeToken")
	return s.next.ConsumeOneTimeToken(ctx, a1, a2)
}

func (s *countingStore) CreateAPIKey(ctx context.Context, a1 *access.Key) error {
	s.count(ctx, "CreateAPIKey")
	return s.next.CreateAPIKey(ctx, a1)
}

func (s *countingStore) CreateInitialUser(ctx context.Context, a1 *access.User) error {
	s.count(ctx, "CreateInitialUser")
	return s.next.CreateInitialUser(ctx, a1)
}

func (s *countingStore) CreateKeyAttribution(ctx context.Context, a1 *access.KeyAttribution) error {
	s.count(ctx, "CreateKeyAttribution")
	return s.next.CreateKeyAttribution(ctx, a1)
}

func (s *countingStore) CreateOneTimeToken(ctx context.Context, a1 access.OneTimeToken) error {
	s.count(ctx, "CreateOneTimeToken")
	return s.next.CreateOneTimeToken(ctx, a1)
}

func (s *countingStore) CreatePasskey(ctx context.Context, a1 *access.PasskeyCredential) error {
	s.count(ctx, "CreatePasskey")
	return s.next.CreatePasskey(ctx, a1)
}

func (s *countingStore) CreateSession(ctx context.Context, a1 *access.Session) error {
	s.count(ctx, "CreateSession")
	return s.next.CreateSession(ctx, a1)
}

func (s *countingStore) CreateUser(ctx context.Context, a1 *access.User) error {
	s.count(ctx, "CreateUser")
	return s.next.CreateUser(ctx, a1)
}

func (s *countingStore) DeleteAPIKey(ctx context.Context, a1 access.KeyRef) error {
	s.count(ctx, "DeleteAPIKey")
	return s.next.DeleteAPIKey(ctx, a1)
}

func (s *countingStore) DeleteAuthFailures(ctx context.Context, a1 string, a2 []access.Method) error {
	s.count(ctx, "DeleteAuthFailures")
	return s.next.DeleteAuthFailures(ctx, a1, a2)
}

func (s *countingStore) DeleteOneTimeTokens(ctx context.Context, a1 access.TokenPurpose, a2 int64) (int, error) {
	s.count(ctx, "DeleteOneTimeTokens")
	return s.next.DeleteOneTimeTokens(ctx, a1, a2)
}

func (s *countingStore) DeleteOneTimeTokensIssuedBy(ctx context.Context, a1 []int64) (int, error) {
	s.count(ctx, "DeleteOneTimeTokensIssuedBy")
	return s.next.DeleteOneTimeTokensIssuedBy(ctx, a1)
}

func (s *countingStore) DeletePasskey(ctx context.Context, a1 access.PasskeyRef) error {
	s.count(ctx, "DeletePasskey")
	return s.next.DeletePasskey(ctx, a1)
}

func (s *countingStore) DeleteSession(ctx context.Context, a1 access.SessionRef) error {
	s.count(ctx, "DeleteSession")
	return s.next.DeleteSession(ctx, a1)
}

func (s *countingStore) DeleteSessionByHash(ctx context.Context, a1 access.Hash) error {
	s.count(ctx, "DeleteSessionByHash")
	return s.next.DeleteSessionByHash(ctx, a1)
}

func (s *countingStore) DeleteUser(ctx context.Context, a1 int64) error {
	s.count(ctx, "DeleteUser")
	return s.next.DeleteUser(ctx, a1)
}

func (s *countingStore) DeleteUserAPIKeys(ctx context.Context, a1 int64) ([]int64, error) {
	s.count(ctx, "DeleteUserAPIKeys")
	return s.next.DeleteUserAPIKeys(ctx, a1)
}

func (s *countingStore) DeleteUserPasskeys(ctx context.Context, a1 int64) ([]int64, error) {
	s.count(ctx, "DeleteUserPasskeys")
	return s.next.DeleteUserPasskeys(ctx, a1)
}

func (s *countingStore) DeleteUserSessions(ctx context.Context, a1 int64, a2 string) ([]string, error) {
	s.count(ctx, "DeleteUserSessions")
	return s.next.DeleteUserSessions(ctx, a1, a2)
}

func (s *countingStore) ListAPIKeys(ctx context.Context) ([]access.Key, error) {
	s.count(ctx, "ListAPIKeys")
	return s.next.ListAPIKeys(ctx)
}

func (s *countingStore) ListAPIKeysByUserID(ctx context.Context, a1 int64) ([]access.Key, error) {
	s.count(ctx, "ListAPIKeysByUserID")
	return s.next.ListAPIKeysByUserID(ctx, a1)
}

func (s *countingStore) ListKeyAttributions(ctx context.Context) ([]access.KeyAttribution, error) {
	s.count(ctx, "ListKeyAttributions")
	return s.next.ListKeyAttributions(ctx)
}

func (s *countingStore) ListUsers(ctx context.Context) ([]access.User, error) {
	s.count(ctx, "ListUsers")
	return s.next.ListUsers(ctx)
}

func (s *countingStore) LiveOneTimeTokens(ctx context.Context, a1 []access.TokenPurpose, a2 time.Time) ([]access.OneTimeToken, error) {
	s.count(ctx, "LiveOneTimeTokens")
	return s.next.LiveOneTimeTokens(ctx, a1, a2)
}

func (s *countingStore) OneTimeTokenByHash(ctx context.Context, a1 access.Hash) (access.OneTimeToken, bool, error) {
	s.count(ctx, "OneTimeTokenByHash")
	return s.next.OneTimeTokenByHash(ctx, a1)
}

func (s *countingStore) PasskeysByUserID(ctx context.Context, a1 int64) ([]access.PasskeyCredential, error) {
	s.count(ctx, "PasskeysByUserID")
	return s.next.PasskeysByUserID(ctx, a1)
}

func (s *countingStore) AppendLog(ctx context.Context, a1 *account.LogEntry) error {
	s.count(ctx, "AppendLog")
	return s.next.AppendLog(ctx, a1)
}

func (s *countingStore) ListLog(ctx context.Context, a1 account.LogRange) ([]account.LogEntry, error) {
	s.count(ctx, "ListLog")
	return s.next.ListLog(ctx, a1)
}

func (s *countingStore) PruneLog(ctx context.Context, a1 account.LogPrune) (int, error) {
	s.count(ctx, "PruneLog")
	return s.next.PruneLog(ctx, a1)
}

func (s *countingStore) LogStats(ctx context.Context) ([]account.LogClassStats, error) {
	s.count(ctx, "LogStats")
	return s.next.LogStats(ctx)
}

func (s *countingStore) PruneAuthFailures(ctx context.Context, a1 []string) (int64, error) {
	s.count(ctx, "PruneAuthFailures")
	return s.next.PruneAuthFailures(ctx, a1)
}

func (s *countingStore) PutAuthFailure(ctx context.Context, a1 account.FailureCount) error {
	s.count(ctx, "PutAuthFailure")
	return s.next.PutAuthFailure(ctx, a1)
}

func (s *countingStore) RenamePasskey(ctx context.Context, a1 access.PasskeyRef, a2 string) error {
	s.count(ctx, "RenamePasskey")
	return s.next.RenamePasskey(ctx, a1, a2)
}

func (s *countingStore) RotateSession(ctx context.Context, a1 account.Rotation) error {
	s.count(ctx, "RotateSession")
	return s.next.RotateSession(ctx, a1)
}

func (s *countingStore) SessionByHash(ctx context.Context, a1 access.Hash) (*access.Session, bool, error) {
	s.count(ctx, "SessionByHash")
	return s.next.SessionByHash(ctx, a1)
}

func (s *countingStore) SessionsByUserID(ctx context.Context, a1 int64) ([]access.Session, error) {
	s.count(ctx, "SessionsByUserID")
	return s.next.SessionsByUserID(ctx, a1)
}

func (s *countingStore) TouchAPIKey(ctx context.Context, a1 int64, a2 time.Time) error {
	s.count(ctx, "TouchAPIKey")
	return s.next.TouchAPIKey(ctx, a1, a2)
}

func (s *countingStore) UnreportedLocks(ctx context.Context) ([]account.FailureCount, error) {
	s.count(ctx, "UnreportedLocks")
	return s.next.UnreportedLocks(ctx)
}

func (s *countingStore) UpdatePasskeyAfterLogin(ctx context.Context, a1 int64, a2 []byte, a3 access.PasskeyLoginUpdate) error {
	s.count(ctx, "UpdatePasskeyAfterLogin")
	return s.next.UpdatePasskeyAfterLogin(ctx, a1, a2, a3)
}

func (s *countingStore) UpdateSessionActivity(ctx context.Context, a1 access.Hash, a2 access.SessionActivity) error {
	s.count(ctx, "UpdateSessionActivity")
	return s.next.UpdateSessionActivity(ctx, a1, a2)
}

func (s *countingStore) UpdateSessionLabel(ctx context.Context, a1 access.SessionRef, a2 string) error {
	s.count(ctx, "UpdateSessionLabel")
	return s.next.UpdateSessionLabel(ctx, a1, a2)
}

func (s *countingStore) UpdateUser(ctx context.Context, a1 *access.User) error {
	s.count(ctx, "UpdateUser")
	return s.next.UpdateUser(ctx, a1)
}

func (s *countingStore) UserByID(ctx context.Context, a1 int64) (*access.User, bool, error) {
	s.count(ctx, "UserByID")
	return s.next.UserByID(ctx, a1)
}

func (s *countingStore) UserByOIDC(ctx context.Context, a1 access.OIDCIdentity) (*access.User, bool, error) {
	s.count(ctx, "UserByOIDC")
	return s.next.UserByOIDC(ctx, a1)
}

func (s *countingStore) UserByUsername(ctx context.Context, a1 string) (*access.User, bool, error) {
	s.count(ctx, "UserByUsername")
	return s.next.UserByUsername(ctx, a1)
}

func (s *countingStore) UserByWebAuthnHandle(ctx context.Context, a1 []byte) (*access.User, bool, error) {
	s.count(ctx, "UserByWebAuthnHandle")
	return s.next.UserByWebAuthnHandle(ctx, a1)
}

func (s *countingStore) UserCount(ctx context.Context) (int, error) {
	s.count(ctx, "UserCount")
	return s.next.UserCount(ctx)
}
