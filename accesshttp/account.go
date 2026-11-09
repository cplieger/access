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
	OIDCProvider() *oidc.Provider
	AdminScope() string
	ManageUsersScope() string
	CreateKeysScope() string
	RequireRecentAuth(p access.Principal) error
	RequireAdminScope(p access.Principal) error
	RequireKeyPermission(p access.Principal, scope string) error

	State(ctx context.Context) (account.State, error)
	SetupWithPassword(ctx context.Context, c account.Client, in account.SetupPassword) (account.SignedIn, error)
	SetupPasskeyBegin(ctx context.Context, c account.Client, in account.SetupPasskey) (account.PendingCeremony, error)
	SetupPasskeyFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.SignedIn, error)
	PasswordLogin(ctx context.Context, c account.Client, in account.Credentials) (account.SignedIn, error)
	PasskeyLoginBegin(ctx context.Context, c account.Client, origin webauthn.Origin, mode account.LoginMode) (account.PendingCeremony, error)
	PasskeyLoginFinish(ctx context.Context, c account.Client, ceremonyID string, body io.Reader) (account.SignedIn, error)
	AdmitOIDC(c account.Client) (*oidc.Provider, error)
	OIDCComplete(ctx context.Context, c account.Client, flow oidc.Flow, claims oidc.Claims) (account.OIDCOutcome, error)
	LinkPendingOIDC(ctx context.Context, p access.Principal, pending account.PendingLink) (account.Issued, account.Me, error)
	UnlinkOIDC(ctx context.Context, p access.Principal) error
	Logout(ctx context.Context, tokenHash access.Hash) error
	StartRecovery(ctx context.Context, c account.Client, token access.Secret) (account.Recovery, error)
	RecoverWithPassword(ctx context.Context, p access.Principal, password access.Secret, opts account.RecoverOptions) error
	RecoverPasskeyBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (account.PendingCeremony, error)
	RecoverPasskeyFinish(ctx context.Context, p access.Principal, ceremonyID string, body io.Reader, opts account.RecoverOptions) error
	AcceptInvitePassword(ctx context.Context, c account.Client, in account.AcceptInvite) (account.SignedIn, error)
	StepUpPassword(ctx context.Context, c account.Client, p access.Principal, password access.Secret) (account.Issued, error)
	SetPassword(ctx context.Context, c account.Client, p access.Principal, current, password access.Secret) (account.Issued, error)
	RemovePassword(ctx context.Context, c account.Client, p access.Principal, current access.Secret) (account.Issued, error)
	Me(ctx context.Context, p access.Principal) (account.Me, error)
	UpdateProfile(ctx context.Context, p access.Principal, displayName string) (account.Me, error)
	ReenableMethod(ctx context.Context, p access.Principal, method access.Method) error
	StepUpPasskeyBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (account.PendingCeremony, error)
	StepUpPasskeyFinish(ctx context.Context, c account.Client, p access.Principal, ceremonyID string, body io.Reader) (account.Issued, error)
	Passkeys(ctx context.Context, p access.Principal) ([]access.PasskeyCredential, error)
	PasskeyRegisterBegin(ctx context.Context, p access.Principal, origin webauthn.Origin) (account.PendingCeremony, error)
	PasskeyRegisterFinish(ctx context.Context, p access.Principal, ceremonyID string, body io.Reader) (account.Registered, error)
	RenamePasskey(ctx context.Context, p access.Principal, id int64, name string) error
	RemovePasskey(ctx context.Context, p access.Principal, id int64) error
	WebAuthnSignals(ctx context.Context, p access.Principal) (webauthn.Signals, error)
	Sessions(ctx context.Context, p access.Principal) ([]access.Session, error)
	RenameSession(ctx context.Context, p access.Principal, in account.SessionLabel) error
	RevokeSession(ctx context.Context, p access.Principal, id string) error
	RevokeOtherSessions(ctx context.Context, p access.Principal) error
	APIKeys(ctx context.Context, p access.Principal) ([]access.Key, error)
	CreateAPIKey(ctx context.Context, a account.Actor, userID int64, in account.NewKey) (account.CreatedKey, error)
	RevokeAPIKey(ctx context.Context, p access.Principal, id int64) error
	Users(ctx context.Context, p access.Principal, f account.UserFilter) ([]account.ListedUser, error)
	CreateUser(ctx context.Context, a account.Actor, in account.NewUser) (*access.User, error)
	UpdateUser(ctx context.Context, p access.Principal, userID int64, ch account.UserChange) (*access.User, error)
	DeleteUser(ctx context.Context, p access.Principal, userID int64) error
	IssueRecovery(ctx context.Context, a account.Actor, userID int64, ttl time.Duration) (account.IssuedToken, error)
	CreateInvite(ctx context.Context, p access.Principal, role access.Role, ttl time.Duration) (account.IssuedToken, error)
	AllAPIKeys(ctx context.Context, p access.Principal) ([]account.ListedKey, error)
	RevokeAnyAPIKey(ctx context.Context, p access.Principal, id int64) error
	Tokens(ctx context.Context, p access.Principal) ([]account.ListedToken, error)
	SecurityLog(ctx context.Context, p access.Principal, f account.LogFilter) (account.LogPage, error)
}

var _ accountAPI = (*account.Service)(nil)
