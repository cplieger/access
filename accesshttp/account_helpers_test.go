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

func (s stubAccount) State(ctx context.Context, c account.Client) (account.State, error) {
	return stubbed(s, "State", func() (account.State, error) { return s.accountAPI.State(ctx, c) })
}

func (s stubAccount) SetupWithPassword(ctx context.Context, c account.Client, in account.SetupPassword) (account.LoginResult, error) {
	return stubbed(s, "SetupWithPassword", func() (account.LoginResult, error) { return s.accountAPI.SetupWithPassword(ctx, c, in) })
}

func (s stubAccount) SetupPasskeyBegin(ctx context.Context, c account.Client, in account.SetupPasskey) (account.PendingCeremony, error) {
	return stubbed(s, "SetupPasskeyBegin", func() (account.PendingCeremony, error) { return s.accountAPI.SetupPasskeyBegin(ctx, c, in) })
}

func (s stubAccount) SetupPasskeyFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.SignedIn, error) {
	return stubbed(s, "SetupPasskeyFinish", func() (account.SignedIn, error) {
		return s.accountAPI.SetupPasskeyFinish(ctx, c, ceremonyID, body)
	})
}

func (s stubAccount) PasswordLogin(ctx context.Context, c account.Client, in account.Credentials) (account.LoginResult, error) {
	return stubbed(s, "PasswordLogin", func() (account.LoginResult, error) { return s.accountAPI.PasswordLogin(ctx, c, in) })
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

func (s stubAccount) AdmitOIDCSession(c account.Client, p access.Principal) (*oidc.Provider, error) {
	return stubbed(s, "AdmitOIDCSession", func() (*oidc.Provider, error) { return s.accountAPI.AdmitOIDCSession(c, p) })
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

func (s stubAccount) AcceptInviteOIDCBegin(ctx context.Context, c account.Client, token access.Secret) (oidc.BeginRequest, error) {
	return stubbed(s, "AcceptInviteOIDCBegin", func() (oidc.BeginRequest, error) { return s.accountAPI.AcceptInviteOIDCBegin(ctx, c, token) })
}

func (s stubAccount) CreatePendingOIDC(ctx context.Context, c account.Client, pending account.PendingLink, username string) (account.SignedIn, error) {
	return stubbed(s, "CreatePendingOIDC", func() (account.SignedIn, error) { return s.accountAPI.CreatePendingOIDC(ctx, c, pending, username) })
}

func (s stubAccount) LinkPendingOIDCByAdmin(ctx context.Context, c account.Client, pending account.PendingLink, username string, secret access.Secret) (account.SignedIn, error) {
	return stubbed(s, "LinkPendingOIDCByAdmin", func() (account.SignedIn, error) {
		return s.accountAPI.LinkPendingOIDCByAdmin(ctx, c, pending, username, secret)
	})
}

func (s stubAccount) AdminRelinkOIDC(ctx context.Context, a account.Actor, userID int64, in account.TemporaryPasswordOptions) (account.IssuedTemporaryPassword, error) {
	return stubbed(s, "AdminRelinkOIDC", func() (account.IssuedTemporaryPassword, error) {
		return s.accountAPI.AdminRelinkOIDC(ctx, a, userID, in)
	})
}

func (s stubAccount) AdminUnlinkOIDC(ctx context.Context, a account.Actor, userID int64) error {
	return stubbedErr(s, "AdminUnlinkOIDC", func() error { return s.accountAPI.AdminUnlinkOIDC(ctx, a, userID) })
}

func (s stubAccount) SetTemporaryPassword(ctx context.Context, a account.Actor, userID int64, in account.TemporaryPasswordOptions) (account.IssuedTemporaryPassword, error) {
	return stubbed(s, "SetTemporaryPassword", func() (account.IssuedTemporaryPassword, error) {
		return s.accountAPI.SetTemporaryPassword(ctx, a, userID, in)
	})
}

func (s stubAccount) ResetSecondFactor(ctx context.Context, a account.Actor, userID int64) error {
	return stubbedErr(s, "ResetSecondFactor", func() error { return s.accountAPI.ResetSecondFactor(ctx, a, userID) })
}

func (s stubAccount) UnlinkOIDC(ctx context.Context, p access.Principal) error {
	return stubbedErr(s, "UnlinkOIDC", func() error { return s.accountAPI.UnlinkOIDC(ctx, p) })
}

func (s stubAccount) Logout(ctx context.Context, tokenHash access.Hash) error {
	return stubbedErr(s, "Logout", func() error { return s.accountAPI.Logout(ctx, tokenHash) })
}

func (s stubAccount) AcceptInvitePassword(ctx context.Context, c account.Client, in account.AcceptInvite) (account.LoginResult, error) {
	return stubbed(s, "AcceptInvitePassword", func() (account.LoginResult, error) { return s.accountAPI.AcceptInvitePassword(ctx, c, in) })
}

func (s stubAccount) StepUpPassword(ctx context.Context, c account.Client, p access.Principal, password access.Secret) (account.Issued, error) {
	return stubbed(s, "StepUpPassword", func() (account.Issued, error) { return s.accountAPI.StepUpPassword(ctx, c, p, password) })
}

func (s stubAccount) SetPassword(ctx context.Context, c account.Client, p access.Principal, current, password access.Secret) (account.PasswordSet, error) {
	return stubbed(s, "SetPassword", func() (account.PasswordSet, error) { return s.accountAPI.SetPassword(ctx, c, p, current, password) })
}

func (s stubAccount) RegenerateRecoveryCode(ctx context.Context, c account.Client, p access.Principal, proof account.SecondFactorProof) (access.Secret, error) {
	return stubbed(s, "RegenerateRecoveryCode", func() (access.Secret, error) { return s.accountAPI.RegenerateRecoveryCode(ctx, c, p, proof) })
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

func (s stubAccount) Passkeys(ctx context.Context, p access.Principal) ([]account.Passkey, error) {
	return stubbed(s, "Passkeys", func() ([]account.Passkey, error) { return s.accountAPI.Passkeys(ctx, p) })
}

func (s stubAccount) PasskeyRegisterBegin(ctx context.Context, c account.Client, p access.Principal, origin webauthn.Origin, proof account.SecondFactorProof) (account.PendingCeremony, error) {
	return stubbed(s, "PasskeyRegisterBegin", func() (account.PendingCeremony, error) {
		return s.accountAPI.PasskeyRegisterBegin(ctx, c, p, origin, proof)
	})
}

func (s stubAccount) SignInWithCode(ctx context.Context, c account.Client, ticket access.Secret, code string) (account.LoginResult, error) {
	return stubbed(s, "SignInWithCode", func() (account.LoginResult, error) { return s.accountAPI.SignInWithCode(ctx, c, ticket, code) })
}

func (s stubAccount) SecondFactorPasskeyBegin(ctx context.Context, c account.Client, ticket access.Secret, origin webauthn.Origin) (account.PendingCeremony, error) {
	return stubbed(s, "SecondFactorPasskeyBegin", func() (account.PendingCeremony, error) {
		return s.accountAPI.SecondFactorPasskeyBegin(ctx, c, ticket, origin)
	})
}

func (s stubAccount) SignInWithRecoveryCode(ctx context.Context, c account.Client, ticket access.Secret, code string) (account.LoginResult, error) {
	return stubbed(s, "SignInWithRecoveryCode", func() (account.LoginResult, error) {
		return s.accountAPI.SignInWithRecoveryCode(ctx, c, ticket, code)
	})
}

func (s stubAccount) SetCredentialPassword(ctx context.Context, c account.Client, ticket, password access.Secret) (account.LoginResult, error) {
	return stubbed(s, "SetCredentialPassword", func() (account.LoginResult, error) {
		return s.accountAPI.SetCredentialPassword(ctx, c, ticket, password)
	})
}

func (s stubAccount) SetCredentialPasskeyBegin(ctx context.Context, c account.Client, ticket access.Secret, origin webauthn.Origin) (account.PendingCeremony, error) {
	return stubbed(s, "SetCredentialPasskeyBegin", func() (account.PendingCeremony, error) {
		return s.accountAPI.SetCredentialPasskeyBegin(ctx, c, ticket, origin)
	})
}

func (s stubAccount) SetCredentialPasskeyFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.SignedIn, error) {
	return stubbed(s, "SetCredentialPasskeyFinish", func() (account.SignedIn, error) {
		return s.accountAPI.SetCredentialPasskeyFinish(ctx, c, ceremonyID, body)
	})
}

func (s stubAccount) PendingTOTPBegin(ctx context.Context, c account.Client, ticket access.Secret) (account.PendingTOTP, error) {
	return stubbed(s, "PendingTOTPBegin", func() (account.PendingTOTP, error) { return s.accountAPI.PendingTOTPBegin(ctx, c, ticket) })
}

func (s stubAccount) PendingTOTPFinish(ctx context.Context, c account.Client, ticket access.Secret, code string) (account.SignedIn, error) {
	return stubbed(s, "PendingTOTPFinish", func() (account.SignedIn, error) { return s.accountAPI.PendingTOTPFinish(ctx, c, ticket, code) })
}

func (s stubAccount) PendingPasskeyBegin(ctx context.Context, c account.Client, ticket access.Secret, origin webauthn.Origin) (account.PendingCeremony, error) {
	return stubbed(s, "PendingPasskeyBegin", func() (account.PendingCeremony, error) {
		return s.accountAPI.PendingPasskeyBegin(ctx, c, ticket, origin)
	})
}

func (s stubAccount) PendingPasskeyFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.SignedIn, error) {
	return stubbed(s, "PendingPasskeyFinish", func() (account.SignedIn, error) {
		return s.accountAPI.PendingPasskeyFinish(ctx, c, ceremonyID, body)
	})
}

func (s stubAccount) SecondFactorPasskeyFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.LoginResult, error) {
	return stubbed(s, "SecondFactorPasskeyFinish", func() (account.LoginResult, error) {
		return s.accountAPI.SecondFactorPasskeyFinish(ctx, c, ceremonyID, body)
	})
}

func (s stubAccount) StepUpCode(ctx context.Context, c account.Client, p access.Principal, code string) (account.Issued, error) {
	return stubbed(s, "StepUpCode", func() (account.Issued, error) { return s.accountAPI.StepUpCode(ctx, c, p, code) })
}

func (s stubAccount) BeginTOTP(ctx context.Context, p access.Principal) (account.TOTPEnrolment, error) {
	return stubbed(s, "BeginTOTP", func() (account.TOTPEnrolment, error) { return s.accountAPI.BeginTOTP(ctx, p) })
}

func (s stubAccount) FinishTOTP(ctx context.Context, c account.Client, p access.Principal, in account.TOTPFinish) (account.Enrolled, error) {
	return stubbed(s, "FinishTOTP", func() (account.Enrolled, error) { return s.accountAPI.FinishTOTP(ctx, c, p, in) })
}

func (s stubAccount) RemoveTOTP(ctx context.Context, c account.Client, p access.Principal, proof account.SecondFactorProof) error {
	return stubbedErr(s, "RemoveTOTP", func() error { return s.accountAPI.RemoveTOTP(ctx, c, p, proof) })
}

func (s stubAccount) PasskeyRegisterFinish(ctx context.Context, p access.Principal, ceremonyID string, body io.Reader) (account.Registered, error) {
	return stubbed(s, "PasskeyRegisterFinish", func() (account.Registered, error) {
		return s.accountAPI.PasskeyRegisterFinish(ctx, p, ceremonyID, body)
	})
}

func (s stubAccount) RenamePasskey(ctx context.Context, p access.Principal, id int64, name string) error {
	return stubbedErr(s, "RenamePasskey", func() error { return s.accountAPI.RenamePasskey(ctx, p, id, name) })
}

func (s stubAccount) RemovePasskey(ctx context.Context, c account.Client, p access.Principal, id int64, proof account.SecondFactorProof) error {
	return stubbedErr(s, "RemovePasskey", func() error { return s.accountAPI.RemovePasskey(ctx, c, p, id, proof) })
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

func (s stubAccount) RenameAPIKey(ctx context.Context, p access.Principal, id int64, label string) error {
	return stubbedErr(s, "RenameAPIKey", func() error { return s.accountAPI.RenameAPIKey(ctx, p, id, label) })
}

func (s stubAccount) RotateAPIKey(ctx context.Context, a account.Actor, id int64) (account.RotatedKey, error) {
	return stubbed(s, "RotateAPIKey", func() (account.RotatedKey, error) { return s.accountAPI.RotateAPIKey(ctx, a, id) })
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

func (s stubAccount) SetOwner(ctx context.Context, a account.Actor, userID int64, owner bool) (*access.User, error) {
	return stubbed(s, "SetOwner", func() (*access.User, error) { return s.accountAPI.SetOwner(ctx, a, userID, owner) })
}

func (s stubAccount) SSOReadiness(ctx context.Context, a account.Actor, mode account.SSOMode) (account.Readiness, error) {
	return stubbed(s, "SSOReadiness", func() (account.Readiness, error) { return s.accountAPI.SSOReadiness(ctx, a, mode) })
}

func (s stubAccount) ApplySSO(ctx context.Context, a account.Actor, mode account.SSOMode) error {
	return stubbedErr(s, "ApplySSO", func() error { return s.accountAPI.ApplySSO(ctx, a, mode) })
}

func (s stubAccount) CreateInvite(ctx context.Context, p access.Principal, role access.Role, ttl time.Duration) (account.IssuedToken, error) {
	return stubbed(s, "CreateInvite", func() (account.IssuedToken, error) { return s.accountAPI.CreateInvite(ctx, p, role, ttl) })
}

func (s stubAccount) AllAPIKeys(ctx context.Context, a account.Actor) ([]account.ListedKey, error) {
	return stubbed(s, "AllAPIKeys", func() ([]account.ListedKey, error) { return s.accountAPI.AllAPIKeys(ctx, a) })
}

func (s stubAccount) RevokeAnyAPIKey(ctx context.Context, a account.Actor, id int64) error {
	return stubbedErr(s, "RevokeAnyAPIKey", func() error { return s.accountAPI.RevokeAnyAPIKey(ctx, a, id) })
}

func (s stubAccount) Tokens(ctx context.Context, p access.Principal) ([]account.ListedToken, error) {
	return stubbed(s, "Tokens", func() ([]account.ListedToken, error) { return s.accountAPI.Tokens(ctx, p) })
}

func (s stubAccount) SecurityLog(ctx context.Context, p access.Principal, f account.LogFilter) (account.LogPage, error) {
	return stubbed(s, "SecurityLog", func() (account.LogPage, error) { return s.accountAPI.SecurityLog(ctx, p, f) })
}
