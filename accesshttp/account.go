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

// accountAPI is what the handlers call; *account.Service satisfies it, and
// a test stands a fake in its place to drive every sentinel on every route.
type accountAPI interface {
	Authenticator() *access.Authenticator
	AdminScope() string
	ManageUsersScope() string
	CreateKeysScope() string
	RequireRecentAuth(p access.Principal) error
	RequireAdminScope(p access.Principal) error
	RequireKeyPermission(p access.Principal, scope string) error

	State(ctx context.Context, c account.Client) (account.State, error)
	SetupWithPassword(ctx context.Context, c account.Client, in account.SetupPassword) (account.LoginResult, error)
	SetupPasskeyBegin(ctx context.Context, c account.Client, in account.SetupPasskey) (account.PendingCeremony, error)
	SetupPasskeyFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.SignedIn, error)
	PasswordLogin(ctx context.Context, c account.Client, in account.Credentials) (account.LoginResult, error)
	SignInWithCode(ctx context.Context, c account.Client, ticket access.Secret, code string) (account.LoginResult, error)
	SecondFactorPasskeyBegin(ctx context.Context, c account.Client, ticket access.Secret, origin webauthn.Origin) (account.PendingCeremony, error)
	SecondFactorPasskeyFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.LoginResult, error)
	SignInWithRecoveryCode(ctx context.Context, c account.Client, ticket access.Secret, code string) (account.LoginResult, error)
	PendingTOTPBegin(ctx context.Context, c account.Client, ticket access.Secret) (account.PendingTOTP, error)
	PendingTOTPFinish(ctx context.Context, c account.Client, ticket access.Secret, code string) (account.SignedIn, error)
	PendingPasskeyBegin(ctx context.Context, c account.Client, ticket access.Secret, origin webauthn.Origin) (account.PendingCeremony, error)
	PendingPasskeyFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.SignedIn, error)
	SetCredentialPassword(ctx context.Context, c account.Client, ticket, password access.Secret) (account.LoginResult, error)
	SetCredentialPasskeyBegin(ctx context.Context, c account.Client, ticket access.Secret, origin webauthn.Origin) (account.PendingCeremony, error)
	SetCredentialPasskeyFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.SignedIn, error)
	PasskeyLoginBegin(ctx context.Context, c account.Client, origin webauthn.Origin, mode account.LoginMode) (account.PendingCeremony, error)
	PasskeyLoginFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.SignedIn, error)
	AdmitOIDC(c account.Client) (*oidc.Provider, error)
	AdmitOIDCSession(c account.Client, p access.Principal) (*oidc.Provider, error)
	OIDCComplete(ctx context.Context, c account.Client, flow oidc.Flow, claims oidc.Claims) (account.OIDCOutcome, error)
	LinkPendingOIDC(ctx context.Context, p access.Principal, pending account.PendingLink) (account.Issued, account.Me, error)
	UnlinkOIDC(ctx context.Context, p access.Principal) error
	CreatePendingOIDC(ctx context.Context, c account.Client, pending account.PendingLink, username string) (account.SignedIn, error)
	LinkPendingOIDCByAdmin(ctx context.Context, c account.Client, pending account.PendingLink, username string, secret access.Secret) (account.SignedIn, error)
	AcceptInviteOIDCBegin(ctx context.Context, c account.Client, token access.Secret) (oidc.BeginRequest, error)
	Logout(ctx context.Context, tokenHash access.Hash) error
	AcceptInvitePassword(ctx context.Context, c account.Client, in account.AcceptInvite) (account.LoginResult, error)
	StepUpPassword(ctx context.Context, c account.Client, p access.Principal, password access.Secret) (account.Issued, error)
	StepUpCode(ctx context.Context, c account.Client, p access.Principal, code string) (account.Issued, error)
	BeginTOTP(ctx context.Context, p access.Principal) (account.TOTPEnrolment, error)
	FinishTOTP(ctx context.Context, c account.Client, p access.Principal, in account.TOTPFinish) (account.Enrolled, error)
	RemoveTOTP(ctx context.Context, c account.Client, p access.Principal, proof account.SecondFactorProof) error
	SetPassword(ctx context.Context, c account.Client, p access.Principal, current, password access.Secret) (account.PasswordSet, error)
	RegenerateRecoveryCode(ctx context.Context, c account.Client, p access.Principal, proof account.SecondFactorProof) (access.Secret, error)
	RemovePassword(ctx context.Context, c account.Client, p access.Principal, current access.Secret) (account.Issued, error)
	Me(ctx context.Context, p access.Principal) (account.Me, error)
	UpdateProfile(ctx context.Context, p access.Principal, displayName string) (account.Me, error)
	ReenableMethod(ctx context.Context, p access.Principal, method access.Method) error
	StepUpPasskeyBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (account.PendingCeremony, error)
	StepUpPasskeyFinish(ctx context.Context, c account.Client, p access.Principal, ceremonyID string, body io.Reader) (account.Issued, error)
	Passkeys(ctx context.Context, p access.Principal) ([]account.Passkey, error)
	PasskeyRegisterBegin(ctx context.Context, c account.Client, p access.Principal, origin webauthn.Origin, proof account.SecondFactorProof) (account.PendingCeremony, error)
	PasskeyRegisterFinish(ctx context.Context, p access.Principal, ceremonyID string, body io.Reader) (account.Registered, error)
	RenamePasskey(ctx context.Context, p access.Principal, id int64, name string) error
	RemovePasskey(ctx context.Context, c account.Client, p access.Principal, id int64, proof account.SecondFactorProof) error
	WebAuthnSignals(ctx context.Context, p access.Principal) (webauthn.Signals, error)
	Sessions(ctx context.Context, p access.Principal) ([]access.Session, error)
	RenameSession(ctx context.Context, p access.Principal, in account.SessionLabel) error
	RevokeSession(ctx context.Context, p access.Principal, id string) error
	RevokeOtherSessions(ctx context.Context, p access.Principal) error
	APIKeys(ctx context.Context, p access.Principal) ([]access.Key, error)
	CreateAPIKey(ctx context.Context, a account.Actor, userID int64, in account.NewKey) (account.CreatedKey, error)
	RenameAPIKey(ctx context.Context, p access.Principal, id int64, label string) error
	RotateAPIKey(ctx context.Context, a account.Actor, id int64) (account.RotatedKey, error)
	RevokeAPIKey(ctx context.Context, p access.Principal, id int64) error
	Users(ctx context.Context, p access.Principal, f account.UserFilter) ([]account.ListedUser, error)
	CreateUser(ctx context.Context, a account.Actor, in account.NewUser) (*access.User, error)
	UpdateUser(ctx context.Context, p access.Principal, userID int64, ch account.UserChange) (*access.User, error)
	DeleteUser(ctx context.Context, p access.Principal, userID int64) error
	SetOwner(ctx context.Context, a account.Actor, userID int64, owner bool) (*access.User, error)
	AdminUnlinkOIDC(ctx context.Context, a account.Actor, userID int64) error
	AdminRelinkOIDC(ctx context.Context, a account.Actor, userID int64, in account.TemporaryPasswordOptions) (account.IssuedTemporaryPassword, error)
	SetTemporaryPassword(ctx context.Context, a account.Actor, userID int64, in account.TemporaryPasswordOptions) (account.IssuedTemporaryPassword, error)
	TemporaryPasswordHTTPSOnly(issued account.IssuedTemporaryPassword) bool
	ResetSecondFactor(ctx context.Context, a account.Actor, userID int64) error
	SSOReadiness(ctx context.Context, a account.Actor, mode account.SSOMode) (account.Readiness, error)
	ApplySSO(ctx context.Context, a account.Actor, mode account.SSOMode) error
	CreateInvite(ctx context.Context, p access.Principal, role access.Role, ttl time.Duration) (account.IssuedToken, error)
	AllAPIKeys(ctx context.Context, a account.Actor) ([]account.ListedKey, error)
	RevokeAnyAPIKey(ctx context.Context, a account.Actor, id int64) error
	Tokens(ctx context.Context, p access.Principal) ([]account.ListedToken, error)
	SecurityLog(ctx context.Context, p access.Principal, f account.LogFilter) (account.LogPage, error)
}

var _ accountAPI = (*account.Service)(nil)
