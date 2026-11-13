package accesshttp

import (
	"context"
	"io"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/webauthn"
)

// stubAccount answers every account operation, by its method name, with
// answer's error while answer says so, and passes it to the Service
// otherwise. The guard's calls (Authenticator, the scopes and the Require
// helpers) always reach the Service.
type stubAccount struct {
	accountAPI
	answer func(op string) (stubbed bool, err error)
}

func stubbed[T any](s stubAccount, op string, next func() (T, error)) (T, error) {
	if ok, err := s.answer(op); ok {
		var zero T
		return zero, err
	}
	return next()
}

func stubbedErr(s stubAccount, op string, next func() error) error {
	if ok, err := s.answer(op); ok {
		return err
	}
	return next()
}

// OIDCProvider answers nil, OIDC off, while stubbed.
func (s stubAccount) OIDCProvider() *oidc.Provider {
	if ok, _ := s.answer("OIDCProvider"); ok {
		return nil
	}
	return s.accountAPI.OIDCProvider()
}

func (s stubAccount) State(ctx context.Context) (account.State, error) {
	return stubbed(s, "State", func() (account.State, error) { return s.accountAPI.State(ctx) })
}

func (s stubAccount) SetupWithPassword(ctx context.Context, c account.Client, in account.SetupPassword) (account.SignedIn, error) {
	return stubbed(s, "SetupWithPassword", func() (account.SignedIn, error) { return s.accountAPI.SetupWithPassword(ctx, c, in) })
}

func (s stubAccount) SetupPasskeyBegin(ctx context.Context, c account.Client, in account.SetupPasskey) (account.PendingCeremony, error) {
	return stubbed(s, "SetupPasskeyBegin", func() (account.PendingCeremony, error) { return s.accountAPI.SetupPasskeyBegin(ctx, c, in) })
}

func (s stubAccount) SetupPasskeyFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.SignedIn, error) {
	return stubbed(s, "SetupPasskeyFinish", func() (account.SignedIn, error) {
		return s.accountAPI.SetupPasskeyFinish(ctx, c, ceremonyID, body)
	})
}

func (s stubAccount) PasswordLogin(ctx context.Context, c account.Client, in account.Credentials) (account.SignedIn, error) {
	return stubbed(s, "PasswordLogin", func() (account.SignedIn, error) { return s.accountAPI.PasswordLogin(ctx, c, in) })
}

func (s stubAccount) PasskeyLoginBegin(ctx context.Context, c account.Client, origin webauthn.Origin, mode account.LoginMode) (account.PendingCeremony, error) {
	return stubbed(s, "PasskeyLoginBegin", func() (account.PendingCeremony, error) {
		return s.accountAPI.PasskeyLoginBegin(ctx, c, origin, mode)
	})
}

func (s stubAccount) PasskeyLoginFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.SignedIn, error) {
	return stubbed(s, "PasskeyLoginFinish", func() (account.SignedIn, error) {
		return s.accountAPI.PasskeyLoginFinish(ctx, c, ceremonyID, body)
	})
}

func (s stubAccount) AdmitOIDC(c account.Client) (*oidc.Provider, error) {
	return stubbed(s, "AdmitOIDC", func() (*oidc.Provider, error) { return s.accountAPI.AdmitOIDC(c) })
}

func (s stubAccount) OIDCComplete(ctx context.Context, c account.Client, flow oidc.Flow, claims oidc.Claims) (account.OIDCOutcome, error) {
	return stubbed(s, "OIDCComplete", func() (account.OIDCOutcome, error) { return s.accountAPI.OIDCComplete(ctx, c, flow, claims) })
}

func (s stubAccount) LinkPendingOIDC(ctx context.Context, p access.Principal, pending account.PendingLink) (account.Issued, account.Me, error) {
	if ok, err := s.answer("LinkPendingOIDC"); ok {
		return account.Issued{}, account.Me{}, err
	}
	return s.accountAPI.LinkPendingOIDC(ctx, p, pending)
}

func (s stubAccount) UnlinkOIDC(ctx context.Context, p access.Principal) error {
	return stubbedErr(s, "UnlinkOIDC", func() error { return s.accountAPI.UnlinkOIDC(ctx, p) })
}

func (s stubAccount) Logout(ctx context.Context, tokenHash access.Hash) error {
	return stubbedErr(s, "Logout", func() error { return s.accountAPI.Logout(ctx, tokenHash) })
}

func (s stubAccount) StartRecovery(ctx context.Context, c account.Client, token access.Secret) (account.Recovery, error) {
	return stubbed(s, "StartRecovery", func() (account.Recovery, error) { return s.accountAPI.StartRecovery(ctx, c, token) })
}

func (s stubAccount) RecoverWithPassword(ctx context.Context, p access.Principal, password access.Secret, opts account.RecoverOptions) error {
	return stubbedErr(s, "RecoverWithPassword", func() error { return s.accountAPI.RecoverWithPassword(ctx, p, password, opts) })
}

func (s stubAccount) RecoverPasskeyBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (account.PendingCeremony, error) {
	return stubbed(s, "RecoverPasskeyBegin", func() (account.PendingCeremony, error) {
		return s.accountAPI.RecoverPasskeyBegin(ctx, p, origin)
	})
}

func (s stubAccount) RecoverPasskeyFinish(ctx context.Context, p access.Principal, ceremonyID string, body io.Reader, opts account.RecoverOptions) error {
	return stubbedErr(s, "RecoverPasskeyFinish", func() error {
		return s.accountAPI.RecoverPasskeyFinish(ctx, p, ceremonyID, body, opts)
	})
}

func (s stubAccount) AcceptInvitePassword(ctx context.Context, c account.Client, in account.AcceptInvite) (account.SignedIn, error) {
	return stubbed(s, "AcceptInvitePassword", func() (account.SignedIn, error) { return s.accountAPI.AcceptInvitePassword(ctx, c, in) })
}

func (s stubAccount) StepUpPassword(ctx context.Context, c account.Client, p access.Principal, password access.Secret) (account.Issued, error) {
	return stubbed(s, "StepUpPassword", func() (account.Issued, error) { return s.accountAPI.StepUpPassword(ctx, c, p, password) })
}

func (s stubAccount) SetPassword(ctx context.Context, c account.Client, p access.Principal, current, password access.Secret) (account.Issued, error) {
	return stubbed(s, "SetPassword", func() (account.Issued, error) { return s.accountAPI.SetPassword(ctx, c, p, current, password) })
}

func (s stubAccount) RemovePassword(ctx context.Context, c account.Client, p access.Principal, current access.Secret) (account.Issued, error) {
	return stubbed(s, "RemovePassword", func() (account.Issued, error) { return s.accountAPI.RemovePassword(ctx, c, p, current) })
}

func (s stubAccount) Me(ctx context.Context, p access.Principal) (account.Me, error) {
	return stubbed(s, "Me", func() (account.Me, error) { return s.accountAPI.Me(ctx, p) })
}

func (s stubAccount) UpdateProfile(ctx context.Context, p access.Principal, displayName string) (account.Me, error) {
	return stubbed(s, "UpdateProfile", func() (account.Me, error) { return s.accountAPI.UpdateProfile(ctx, p, displayName) })
}

func (s stubAccount) ReenableMethod(ctx context.Context, p access.Principal, method access.Method) error {
	return stubbedErr(s, "ReenableMethod", func() error { return s.accountAPI.ReenableMethod(ctx, p, method) })
}

func (s stubAccount) StepUpPasskeyBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (account.PendingCeremony, error) {
	return stubbed(s, "StepUpPasskeyBegin", func() (account.PendingCeremony, error) {
		return s.accountAPI.StepUpPasskeyBegin(ctx, p, origin)
	})
}

func (s stubAccount) StepUpPasskeyFinish(ctx context.Context, c account.Client, p access.Principal, ceremonyID string, body io.Reader) (account.Issued, error) {
	return stubbed(s, "StepUpPasskeyFinish", func() (account.Issued, error) {
		return s.accountAPI.StepUpPasskeyFinish(ctx, c, p, ceremonyID, body)
	})
}

func (s stubAccount) Passkeys(ctx context.Context, p access.Principal) ([]access.PasskeyCredential, error) {
	return stubbed(s, "Passkeys", func() ([]access.PasskeyCredential, error) { return s.accountAPI.Passkeys(ctx, p) })
}

func (s stubAccount) PasskeyRegisterBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (account.PendingCeremony, error) {
	return stubbed(s, "PasskeyRegisterBegin", func() (account.PendingCeremony, error) {
		return s.accountAPI.PasskeyRegisterBegin(ctx, p, origin)
	})
}

func (s stubAccount) PasskeyRegisterFinish(ctx context.Context, p access.Principal, ceremonyID string, body io.Reader) (account.Registered, error) {
	return stubbed(s, "PasskeyRegisterFinish", func() (account.Registered, error) {
		return s.accountAPI.PasskeyRegisterFinish(ctx, p, ceremonyID, body)
	})
}

func (s stubAccount) RenamePasskey(ctx context.Context, p access.Principal, id int64, name string) error {
	return stubbedErr(s, "RenamePasskey", func() error { return s.accountAPI.RenamePasskey(ctx, p, id, name) })
}

func (s stubAccount) RemovePasskey(ctx context.Context, p access.Principal, id int64) error {
	return stubbedErr(s, "RemovePasskey", func() error { return s.accountAPI.RemovePasskey(ctx, p, id) })
}

func (s stubAccount) WebAuthnSignals(ctx context.Context, p access.Principal) (webauthn.Signals, error) {
	return stubbed(s, "WebAuthnSignals", func() (webauthn.Signals, error) { return s.accountAPI.WebAuthnSignals(ctx, p) })
}

func (s stubAccount) Sessions(ctx context.Context, p access.Principal) ([]access.Session, error) {
	return stubbed(s, "Sessions", func() ([]access.Session, error) { return s.accountAPI.Sessions(ctx, p) })
}

func (s stubAccount) RenameSession(ctx context.Context, p access.Principal, in account.SessionLabel) error {
	return stubbedErr(s, "RenameSession", func() error { return s.accountAPI.RenameSession(ctx, p, in) })
}

func (s stubAccount) RevokeSession(ctx context.Context, p access.Principal, id string) error {
	return stubbedErr(s, "RevokeSession", func() error { return s.accountAPI.RevokeSession(ctx, p, id) })
}

func (s stubAccount) RevokeOtherSessions(ctx context.Context, p access.Principal) error {
	return stubbedErr(s, "RevokeOtherSessions", func() error { return s.accountAPI.RevokeOtherSessions(ctx, p) })
}

func (s stubAccount) APIKeys(ctx context.Context, p access.Principal) ([]access.Key, error) {
	return stubbed(s, "APIKeys", func() ([]access.Key, error) { return s.accountAPI.APIKeys(ctx, p) })
}

func (s stubAccount) CreateAPIKey(ctx context.Context, a account.Actor, userID int64, in account.NewKey) (account.CreatedKey, error) {
	return stubbed(s, "CreateAPIKey", func() (account.CreatedKey, error) { return s.accountAPI.CreateAPIKey(ctx, a, userID, in) })
}

func (s stubAccount) RevokeAPIKey(ctx context.Context, p access.Principal, id int64) error {
	return stubbedErr(s, "RevokeAPIKey", func() error { return s.accountAPI.RevokeAPIKey(ctx, p, id) })
}

func (s stubAccount) Users(ctx context.Context, p access.Principal, f account.UserFilter) ([]account.ListedUser, error) {
	return stubbed(s, "Users", func() ([]account.ListedUser, error) { return s.accountAPI.Users(ctx, p, f) })
}

func (s stubAccount) CreateUser(ctx context.Context, a account.Actor, in account.NewUser) (*access.User, error) {
	return stubbed(s, "CreateUser", func() (*access.User, error) { return s.accountAPI.CreateUser(ctx, a, in) })
}

func (s stubAccount) UpdateUser(ctx context.Context, p access.Principal, userID int64, ch account.UserChange) (*access.User, error) {
	return stubbed(s, "UpdateUser", func() (*access.User, error) { return s.accountAPI.UpdateUser(ctx, p, userID, ch) })
}

func (s stubAccount) DeleteUser(ctx context.Context, p access.Principal, userID int64) error {
	return stubbedErr(s, "DeleteUser", func() error { return s.accountAPI.DeleteUser(ctx, p, userID) })
}

func (s stubAccount) IssueRecovery(ctx context.Context, a account.Actor, userID int64, ttl time.Duration) (account.IssuedToken, error) {
	return stubbed(s, "IssueRecovery", func() (account.IssuedToken, error) { return s.accountAPI.IssueRecovery(ctx, a, userID, ttl) })
}

func (s stubAccount) CreateInvite(ctx context.Context, p access.Principal, role access.Role, ttl time.Duration) (account.IssuedToken, error) {
	return stubbed(s, "CreateInvite", func() (account.IssuedToken, error) { return s.accountAPI.CreateInvite(ctx, p, role, ttl) })
}

func (s stubAccount) AllAPIKeys(ctx context.Context, p access.Principal) ([]account.ListedKey, error) {
	return stubbed(s, "AllAPIKeys", func() ([]account.ListedKey, error) { return s.accountAPI.AllAPIKeys(ctx, p) })
}

func (s stubAccount) RevokeAnyAPIKey(ctx context.Context, p access.Principal, id int64) error {
	return stubbedErr(s, "RevokeAnyAPIKey", func() error { return s.accountAPI.RevokeAnyAPIKey(ctx, p, id) })
}

func (s stubAccount) Tokens(ctx context.Context, p access.Principal) ([]account.ListedToken, error) {
	return stubbed(s, "Tokens", func() ([]account.ListedToken, error) { return s.accountAPI.Tokens(ctx, p) })
}

func (s stubAccount) SecurityLog(ctx context.Context, p access.Principal, f account.LogFilter) (account.LogPage, error) {
	return stubbed(s, "SecurityLog", func() (account.LogPage, error) { return s.accountAPI.SecurityLog(ctx, p, f) })
}
