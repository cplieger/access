package accesstest

import (
	"context"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// viaTx is a Store whose every Tx method runs as its own Update on s, so
// StoreContract's rules, run on it, check the Tx half account calls. It
// lists each method itself and embeds neither Tx nor Store, so a Tx method
// added to account does not compile here until it runs through an Update.
type viaTx struct{ s account.Store }

// throughUpdate wraps s in a viaTx; Update and the Sweeper methods pass
// through to s.
func throughUpdate(s account.Store) account.Store { return viaTx{s} }

// via1 and via2 run read in one Update on s and return its last run's
// results, since Update may run its callback more than once (rule 5).
func via1[A any](ctx context.Context, s account.Store, read func(account.Tx) (A, error)) (A, error) {
	var a A
	err := s.Update(ctx, func(tx account.Tx) error {
		var err error
		a, err = read(tx)
		return err
	})
	return a, err
}

func via2[A, B any](ctx context.Context, s account.Store, read func(account.Tx) (A, B, error)) (a A, b B, err error) {
	err = s.Update(ctx, func(tx account.Tx) error {
		var rerr error
		a, b, rerr = read(tx)
		return rerr
	})
	return a, b, err
}

func (v viaTx) Update(ctx context.Context, fn func(tx account.Tx) error) error {
	return v.s.Update(ctx, fn)
}

func (v viaTx) CleanupExpiredSessions(ctx context.Context, now time.Time, timeouts access.SessionTimeouts, limit int) ([]access.SessionRef, error) {
	return v.s.CleanupExpiredSessions(ctx, now, timeouts, limit)
}

func (v viaTx) CleanupExpiredOneTimeTokens(ctx context.Context, now time.Time) (int64, error) {
	return v.s.CleanupExpiredOneTimeTokens(ctx, now)
}

func (v viaTx) ClearRetiredAPIKeySecrets(ctx context.Context, now time.Time, limit int) (int, error) {
	return v.s.ClearRetiredAPIKeySecrets(ctx, now, limit)
}

func (v viaTx) CreateUser(ctx context.Context, user *access.User) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.CreateUser(ctx, user) })
}

func (v viaTx) CreateInitialUser(ctx context.Context, user *access.User) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.CreateInitialUser(ctx, user) })
}

func (v viaTx) UserByID(ctx context.Context, id int64) (*access.User, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (*access.User, bool, error) { return tx.UserByID(ctx, id) })
}

func (v viaTx) UserByUsername(ctx context.Context, canonical string) (*access.User, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (*access.User, bool, error) { return tx.UserByUsername(ctx, canonical) })
}

func (v viaTx) UserByOIDC(ctx context.Context, id access.OIDCIdentity) (*access.User, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (*access.User, bool, error) { return tx.UserByOIDC(ctx, id) })
}

func (v viaTx) UserByWebAuthnHandle(ctx context.Context, handle []byte) (*access.User, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (*access.User, bool, error) { return tx.UserByWebAuthnHandle(ctx, handle) })
}

func (v viaTx) ListUsers(ctx context.Context) ([]access.User, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]access.User, error) { return tx.ListUsers(ctx) })
}

func (v viaTx) UpdateUser(ctx context.Context, user *access.User) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.UpdateUser(ctx, user) })
}

func (v viaTx) DeleteUser(ctx context.Context, id int64) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.DeleteUser(ctx, id) })
}

func (v viaTx) UserCount(ctx context.Context) (int, error) {
	return via1(ctx, v.s, func(tx account.Tx) (int, error) { return tx.UserCount(ctx) })
}

func (v viaTx) UsersWaiting(ctx context.Context, limit int) ([]access.User, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]access.User, error) { return tx.UsersWaiting(ctx, limit) })
}

func (v viaTx) CreateSession(ctx context.Context, sess *access.Session) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.CreateSession(ctx, sess) })
}

func (v viaTx) SessionByHash(ctx context.Context, tokenHash access.Hash) (*access.Session, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (*access.Session, bool, error) { return tx.SessionByHash(ctx, tokenHash) })
}

func (v viaTx) SessionsByUserID(ctx context.Context, userID int64) ([]access.Session, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]access.Session, error) { return tx.SessionsByUserID(ctx, userID) })
}

func (v viaTx) UpdateSessionActivity(ctx context.Context, tokenHash access.Hash, act access.SessionActivity) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.UpdateSessionActivity(ctx, tokenHash, act) })
}

func (v viaTx) RotateSession(ctx context.Context, rot account.Rotation) error { //nolint:gocritic // hugeParam: account.SessionStore's signature
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.RotateSession(ctx, rot) })
}

func (v viaTx) UpdateSessionLabel(ctx context.Context, ref access.SessionRef, label string) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.UpdateSessionLabel(ctx, ref, label) })
}

func (v viaTx) DeleteSession(ctx context.Context, ref access.SessionRef) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.DeleteSession(ctx, ref) })
}

func (v viaTx) DeleteSessionByHash(ctx context.Context, tokenHash access.Hash) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.DeleteSessionByHash(ctx, tokenHash) })
}

func (v viaTx) DeleteUserSessions(ctx context.Context, userID int64, exceptID string) ([]string, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]string, error) { return tx.DeleteUserSessions(ctx, userID, exceptID) })
}

func (v viaTx) CreatePasskey(ctx context.Context, cred *access.PasskeyCredential) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.CreatePasskey(ctx, cred) })
}

func (v viaTx) PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]access.PasskeyCredential, error) { return tx.PasskeysByUserID(ctx, userID) })
}

func (v viaTx) UpdatePasskeyAfterLogin(ctx context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.UpdatePasskeyAfterLogin(ctx, userID, credID, upd) })
}

func (v viaTx) RenamePasskey(ctx context.Context, ref access.PasskeyRef, name string) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.RenamePasskey(ctx, ref, name) })
}

func (v viaTx) DeletePasskey(ctx context.Context, ref access.PasskeyRef) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.DeletePasskey(ctx, ref) })
}

func (v viaTx) DeleteUserPasskeys(ctx context.Context, userID int64) ([]int64, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]int64, error) { return tx.DeleteUserPasskeys(ctx, userID) })
}

func (v viaTx) CreateAPIKey(ctx context.Context, key *access.Key) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.CreateAPIKey(ctx, key) })
}

func (v viaTx) APIKeyByHash(ctx context.Context, hash access.Hash) (*access.Key, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (*access.Key, bool, error) { return tx.APIKeyByHash(ctx, hash) })
}

func (v viaTx) ListAPIKeysByUserID(ctx context.Context, userID int64) ([]access.Key, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]access.Key, error) { return tx.ListAPIKeysByUserID(ctx, userID) })
}

func (v viaTx) ListAPIKeys(ctx context.Context) ([]access.Key, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]access.Key, error) { return tx.ListAPIKeys(ctx) })
}

func (v viaTx) DeleteAPIKey(ctx context.Context, ref access.KeyRef) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.DeleteAPIKey(ctx, ref) })
}

func (v viaTx) DeleteUserAPIKeys(ctx context.Context, userID int64) ([]int64, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]int64, error) { return tx.DeleteUserAPIKeys(ctx, userID) })
}

func (v viaTx) TouchAPIKey(ctx context.Context, keyID int64, hash access.Hash, at time.Time) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.TouchAPIKey(ctx, keyID, hash, at) })
}

func (v viaTx) UpdateAPIKeySecret(ctx context.Context, ref access.KeyRef, s access.KeySecret) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.UpdateAPIKeySecret(ctx, ref, s) })
}

func (v viaTx) UpdateAPIKeyLabel(ctx context.Context, ref access.KeyRef, label string) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.UpdateAPIKeyLabel(ctx, ref, label) })
}

func (v viaTx) CreateOneTimeToken(ctx context.Context, tok access.OneTimeToken) error { //nolint:gocritic // hugeParam: account.TokenStore's signature
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.CreateOneTimeToken(ctx, tok) })
}

func (v viaTx) OneTimeTokenByHash(ctx context.Context, hash access.Hash) (access.OneTimeToken, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (access.OneTimeToken, bool, error) { return tx.OneTimeTokenByHash(ctx, hash) })
}

func (v viaTx) ConsumeOneTimeToken(ctx context.Context, hash access.Hash, now time.Time) (access.OneTimeToken, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (access.OneTimeToken, bool, error) { return tx.ConsumeOneTimeToken(ctx, hash, now) })
}

func (v viaTx) DeleteOneTimeTokens(ctx context.Context, purpose access.TokenPurpose) (int, error) {
	return via1(ctx, v.s, func(tx account.Tx) (int, error) { return tx.DeleteOneTimeTokens(ctx, purpose) })
}

func (v viaTx) LiveOneTimeTokens(ctx context.Context, purposes []access.TokenPurpose, now time.Time) ([]access.OneTimeToken, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]access.OneTimeToken, error) { return tx.LiveOneTimeTokens(ctx, purposes, now) })
}

func (v viaTx) DeleteOneTimeTokensIssuedBy(ctx context.Context, keyIDs []int64) (int, error) {
	return via1(ctx, v.s, func(tx account.Tx) (int, error) { return tx.DeleteOneTimeTokensIssuedBy(ctx, keyIDs) })
}

func (v viaTx) TOTPByUserID(ctx context.Context, userID int64) (access.TOTP, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (access.TOTP, bool, error) { return tx.TOTPByUserID(ctx, userID) })
}

func (v viaTx) SetTOTP(ctx context.Context, rec access.TOTP) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.SetTOTP(ctx, rec) })
}

func (v viaTx) DeleteTOTP(ctx context.Context, userID int64) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.DeleteTOTP(ctx, userID) })
}

func (v viaTx) ListTOTP(ctx context.Context, afterUserID int64, limit int) ([]access.TOTP, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]access.TOTP, error) { return tx.ListTOTP(ctx, afterUserID, limit) })
}

func (v viaTx) RecoveryCodeByUserID(ctx context.Context, userID int64) (access.RecoveryCode, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (access.RecoveryCode, bool, error) { return tx.RecoveryCodeByUserID(ctx, userID) })
}

func (v viaTx) SetRecoveryCode(ctx context.Context, rec access.RecoveryCode) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.SetRecoveryCode(ctx, rec) })
}

func (v viaTx) DeleteRecoveryCode(ctx context.Context, userID int64) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.DeleteRecoveryCode(ctx, userID) })
}

func (v viaTx) TemporaryPasswordByUserID(ctx context.Context, userID int64) (access.TemporaryPassword, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (access.TemporaryPassword, bool, error) {
		return tx.TemporaryPasswordByUserID(ctx, userID)
	})
}

func (v viaTx) SetTemporaryPassword(ctx context.Context, rec access.TemporaryPassword) error { //nolint:gocritic // hugeParam: account.TemporaryPasswordStore's signature
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.SetTemporaryPassword(ctx, rec) })
}

func (v viaTx) DeleteTemporaryPassword(ctx context.Context, userID int64) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.DeleteTemporaryPassword(ctx, userID) })
}

func (v viaTx) SSOMode(ctx context.Context) (account.SSOMode, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (account.SSOMode, bool, error) { return tx.SSOMode(ctx) })
}

func (v viaTx) SetSSOMode(ctx context.Context, mode account.SSOMode) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.SetSSOMode(ctx, mode) })
}

func (v viaTx) CreateKeyAttribution(ctx context.Context, a *access.KeyAttribution) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.CreateKeyAttribution(ctx, a) })
}

func (v viaTx) ListKeyAttributions(ctx context.Context) ([]access.KeyAttribution, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]access.KeyAttribution, error) { return tx.ListKeyAttributions(ctx) })
}

func (v viaTx) AuthFailure(ctx context.Context, ref account.FailureRef) (account.FailureCount, bool, error) {
	return via2(ctx, v.s, func(tx account.Tx) (account.FailureCount, bool, error) { return tx.AuthFailure(ctx, ref) })
}

func (v viaTx) PutAuthFailure(ctx context.Context, f account.FailureCount) error { //nolint:gocritic // hugeParam: account.FailureStore's signature
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.PutAuthFailure(ctx, f) })
}

func (v viaTx) UnreportedLocks(ctx context.Context) ([]account.FailureCount, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]account.FailureCount, error) { return tx.UnreportedLocks(ctx) })
}

func (v viaTx) DeleteAuthFailure(ctx context.Context, ref account.FailureRef) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.DeleteAuthFailure(ctx, ref) })
}

func (v viaTx) DeleteAuthFailures(ctx context.Context, name string, methods []access.Method) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.DeleteAuthFailures(ctx, name, methods) })
}

func (v viaTx) PruneAuthFailures(ctx context.Context, keep []string) (int64, error) {
	return via1(ctx, v.s, func(tx account.Tx) (int64, error) { return tx.PruneAuthFailures(ctx, keep) })
}

func (v viaTx) AppendLog(ctx context.Context, e *account.LogEntry) error {
	return v.s.Update(ctx, func(tx account.Tx) error { return tx.AppendLog(ctx, e) })
}

func (v viaTx) ListLog(ctx context.Context, r account.LogRange) ([]account.LogEntry, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]account.LogEntry, error) { return tx.ListLog(ctx, r) })
}

func (v viaTx) PruneLog(ctx context.Context, p account.LogPrune) (int, error) {
	return via1(ctx, v.s, func(tx account.Tx) (int, error) { return tx.PruneLog(ctx, p) })
}

func (v viaTx) LogStats(ctx context.Context) ([]account.LogClassStats, error) {
	return via1(ctx, v.s, func(tx account.Tx) ([]account.LogClassStats, error) { return tx.LogStats(ctx) })
}
