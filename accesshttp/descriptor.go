package accesshttp

import (
	"net/http"
	"reflect"
	"slices"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn"
)

// Class is who a route admits; its guard enforces it.
type Class string

// The classes.
const (
	ClassPublic     Class = "public"
	ClassSession    Class = "session"
	ClassRecentAuth Class = "recent_auth"
	ClassKeyScope   Class = "key_scope" // Scope names the required key scope; a session also passes
	// ClassKeyPermission: a key carrying Scope, or a session under
	// recent auth (account.Service.RequireKeyPermission).
	ClassKeyPermission Class = "key_permission"
)

// Kind is how a route answers: JSON bodies, or a redirect.
type Kind string

// The kinds.
const (
	KindJSON     Kind = "json"
	KindRedirect Kind = "redirect"
)

// Descriptor states one route for an app's mux, gate, census and code
// generator.
type Descriptor struct {
	Request  reflect.Type // nil when there is no JSON body
	Query    reflect.Type // the accepted query arguments; nil when none
	Response reflect.Type // nil when the 2xx body is not decoded
	Name     string       // stable, a valid TS identifier, e.g. "authLoginPassword"
	Method   string
	Path     string // full path including the configured prefix
	Class    Class
	Scope    string // ClassKeyScope and ClassKeyPermission only
	Kind     Kind
	Doc      string // one present-tense sentence saying what the route does
	// Codes is every code this route can answer, in [access.Codes] order: its
	// class guard's, its transport's and its account operation's.
	Codes   []access.Code
	Passive bool // verification does not count as activity
	Array   bool // Response is a JSON array of Response
}

// scopeRule names the Account scope that opens a route to keys; the zero
// value keeps the spec's own class.
type scopeRule int

const (
	scopeAdmin scopeRule = iota + 1 // key_scope with AdminScope when set, else session
	scopeUsers                      // key_permission with ManageUsersScope when set, else recent_auth
	scopeKeys                       // key_permission with CreateKeysScope when set, else recent_auth
)

// pathID is the kind of a route's {id} or {method} path value.
type pathID int

const (
	pathNone pathID = iota
	pathInt
	pathSession
	pathMethod
)

// key is the name of the path wildcard, which the route's path holds as
// {key} and a refusal of its value names.
func (p pathID) key() string {
	if p == pathMethod {
		return "method"
	}
	return "id"
}

// routeSpec is one route's static facts; descriptor derives its Descriptor
// under a DescriptorConfig.
type routeSpec struct {
	request, query, response reflect.Type
	serve                    serveFunc
	name, method, path, doc  string
	op                       string // the account operation, a key of opCodes
	audit                    string // the access.AuditEvent kind prefix; "" audits nothing
	class                    Class
	scope                    scopeRule
	pathID                   pathID
	// cer is set where the body is a credential, a WebAuthn finish, or may
	// carry one, a SecondFactorProof; its fallback code names a refused
	// assertion.
	cer                      ceremony
	oidc                     bool // Path is under OIDCPrefix
	passive, redirect, array bool
	tokenBody                bool // a token is accepted only in the body
	limited                  bool // its admission charges the IP's request window before anything else
}

// Names more than one spec shares, and the sign-in start's, which the query
// decode names too.
const (
	auditSetup           = "setup"
	auditLogin           = "login"
	auditStepUp          = "stepup"
	opOIDCBegin          = "OIDCBegin"
	routeOIDCStartSignIn = "authOIDCStartSignIn"
)

func typeOf[T any]() reflect.Type { return reflect.TypeFor[T]() }

// specs is every route, in Routes order.
var specs = []routeSpec{
	{name: "authState", method: http.MethodGet, path: "/state", doc: "Answers what the sign-in screen offers: setup, the sign-in methods and what needs HTTPS.", class: ClassPublic, passive: true, response: typeOf[StateResponse](), op: "State", serve: serveState},
	{name: "authSetupPassword", method: http.MethodPost, path: "/setup/password", doc: "Creates the first account with a password and answers a session or a pending sign-in.", class: ClassPublic, request: typeOf[SetupPasswordRequest](), response: typeOf[SignInOutcome](), tokenBody: true, op: "SetupWithPassword", audit: auditSetup, serve: serveSetupPassword},
	{name: "authSetupPasskeyBegin", method: http.MethodPost, path: "/setup/passkey/begin", doc: "Starts the passkey registration that creates the first account.", class: ClassPublic, request: typeOf[SetupPasskeyBeginRequest](), response: typeOf[CeremonyResponse](), tokenBody: true, op: "SetupPasskeyBegin", audit: auditSetup, serve: serveSetupPasskeyBegin},
	{name: "authSetupPasskeyFinish", method: http.MethodPost, path: "/setup/passkey/finish", doc: "Finishes the first account's passkey registration and signs it in.", class: ClassPublic, cer: ceremonyRegistration, response: typeOf[SignedInResponse](), op: "SetupPasskeyFinish", audit: auditSetup, serve: serveSetupPasskeyFinish},
	{name: "authLoginPassword", method: http.MethodPost, path: "/login/password", doc: "Signs in with a password and answers a session or a pending sign-in.", class: ClassPublic, request: typeOf[LoginRequest](), response: typeOf[SignInOutcome](), op: "PasswordLogin", audit: auditLogin, serve: serveLoginPassword},
	{name: "authLoginCode", method: http.MethodPost, path: "/login/code", doc: "Completes a pending sign-in with an authenticator app code.", class: ClassPublic, request: typeOf[CodeRequest](), response: typeOf[SignInOutcome](), op: "SignInWithCode", audit: auditLogin, serve: serveLoginCode},
	{name: "authLoginSecondPasskeyBegin", method: http.MethodPost, path: "/login/second-passkey/begin", doc: "Starts the passkey assertion that completes a pending sign-in.", class: ClassPublic, request: typeOf[TicketRequest](), response: typeOf[CeremonyResponse](), op: "SecondFactorPasskeyBegin", serve: serveLoginSecondPasskeyBegin},
	{name: "authLoginSecondPasskeyFinish", method: http.MethodPost, path: "/login/second-passkey/finish", doc: "Finishes the passkey assertion that completes a pending sign-in.", class: ClassPublic, cer: ceremonyAssertion, response: typeOf[SignInOutcome](), op: "SecondFactorPasskeyFinish", audit: auditLogin, serve: serveLoginSecondPasskeyFinish},
	{name: "authLoginRecoveryCode", method: http.MethodPost, path: "/login/recovery-code", doc: "Checks a recovery code on a pending sign-in and answers the step that enrols a new second factor.", class: ClassPublic, request: typeOf[CodeRequest](), response: typeOf[SignInOutcome](), op: "SignInWithRecoveryCode", audit: auditLogin, serve: serveLoginRecoveryCode},
	{name: "authLoginSetPassword", method: http.MethodPost, path: "/login/set-password", doc: "Sets the password chosen after a temporary password and answers a session or a pending sign-in.", class: ClassPublic, request: typeOf[SetPasswordRequest](), response: typeOf[SignInOutcome](), op: "SetCredentialPassword", audit: auditLogin, serve: serveLoginSetPassword},
	{name: "authLoginSetPasskeyBegin", method: http.MethodPost, path: "/login/set-passkey/begin", doc: "Starts the passkey registration that replaces a temporary password.", class: ClassPublic, request: typeOf[TicketRequest](), response: typeOf[CeremonyResponse](), op: "SetCredentialPasskeyBegin", serve: serveLoginSetPasskeyBegin},
	{name: "authLoginSetPasskeyFinish", method: http.MethodPost, path: "/login/set-passkey/finish", doc: "Finishes the passkey registration that replaces a temporary password and signs in.", class: ClassPublic, cer: ceremonyRegistration, response: typeOf[SignInOutcome](), op: "SetCredentialPasskeyFinish", audit: auditLogin, serve: serveLoginSetPasskeyFinish},
	{name: "authPendingTOTPBegin", method: http.MethodPost, path: "/pending/totp/begin", doc: "Draws an authenticator app secret for a pending sign-in to enrol.", class: ClassPublic, request: typeOf[TicketRequest](), response: typeOf[PendingTOTPBeginResponse](), op: "PendingTOTPBegin", serve: servePendingTOTPBegin},
	{name: "authPendingTOTPFinish", method: http.MethodPost, path: "/pending/totp/finish", doc: "Enrols a pending sign-in's authenticator app with its first code and signs in.", class: ClassPublic, request: typeOf[CodeRequest](), response: typeOf[EnrolmentOutcome](), op: "PendingTOTPFinish", audit: auditLogin, serve: servePendingTOTPFinish},
	{name: "authPendingPasskeyBegin", method: http.MethodPost, path: "/pending/passkey/begin", doc: "Starts the passkey registration a pending sign-in enrols.", class: ClassPublic, request: typeOf[TicketRequest](), response: typeOf[CeremonyResponse](), op: "PendingPasskeyBegin", serve: servePendingPasskeyBegin},
	{name: "authPendingPasskeyFinish", method: http.MethodPost, path: "/pending/passkey/finish", doc: "Finishes a pending sign-in's passkey registration and signs in.", class: ClassPublic, cer: ceremonyRegistration, response: typeOf[EnrolmentOutcome](), op: "PendingPasskeyFinish", audit: auditLogin, serve: servePendingPasskeyFinish},
	{name: "authLoginPasskeyBegin", method: http.MethodPost, path: "/login/passkey/begin", doc: "Starts a passkey sign-in.", class: ClassPublic, query: typeOf[PasskeyBeginQuery](), response: typeOf[CeremonyResponse](), op: "PasskeyLoginBegin", serve: serveLoginPasskeyBegin},
	{name: "authLoginPasskeyFinish", method: http.MethodPost, path: "/login/passkey/finish", doc: "Finishes a passkey sign-in and answers the session.", class: ClassPublic, cer: ceremonyAssertion, response: typeOf[SignedInResponse](), op: "PasskeyLoginFinish", audit: auditLogin, serve: serveLoginPasskeyFinish},
	{name: "authLogout", method: http.MethodPost, path: "/logout", doc: "Ends the presented session and clears its cookie.", class: ClassPublic, op: "Logout", serve: serveLogout},
	{name: routeOIDCStartSignIn, method: http.MethodGet, path: "/start/signin", doc: "Redirects to the identity provider to sign in.", oidc: true, class: ClassPublic, redirect: true, query: typeOf[OIDCSignInQuery](), limited: true, op: "AdmitOIDC", audit: "oidc.start", serve: serveOIDCStartSignIn},
	{name: "authOIDCStartLink", method: http.MethodPost, path: "/start/link", doc: "Answers the identity provider URL that links an identity to the signed-in account.", oidc: true, class: ClassRecentAuth, request: typeOf[RedirectRequest](), response: typeOf[OIDCStartResponse](), op: opOIDCBegin, serve: serveOIDCStartLink},
	{name: "authOIDCStartStepUp", method: http.MethodPost, path: "/start/stepup", doc: "Answers the identity provider URL that steps up the current session.", oidc: true, class: ClassSession, request: typeOf[RedirectRequest](), response: typeOf[OIDCStartResponse](), op: opOIDCBegin, serve: serveOIDCStartStepUp},
	{name: "authInviteAcceptOIDC", method: http.MethodPost, path: "/start/invite", doc: "Answers the identity provider URL that accepts an invite by single sign-on.", oidc: true, class: ClassPublic, request: typeOf[TokenRequest](), response: typeOf[OIDCStartResponse](), tokenBody: true, limited: true, op: "AcceptInviteOIDCBegin", audit: "oidc.invite", serve: serveInviteAcceptOIDC},
	{name: "authOIDCCallback", method: http.MethodGet, path: "/callback", doc: "Completes a flow the identity provider sent back and redirects into the app.", oidc: true, class: ClassPublic, redirect: true, query: typeOf[OIDCCallbackQuery](), limited: true, op: "OIDCComplete", audit: "oidc.callback", serve: serveOIDCCallback},
	{name: "authOIDCPending", method: http.MethodGet, path: "/oidc/pending", doc: "Answers the identity waiting to be linked or turned into an account.", class: ClassPublic, passive: true, response: typeOf[PendingLinkResponse](), limited: true, op: "OIDCPending", serve: serveOIDCPending},
	{name: "authOIDCCreatePending", method: http.MethodPost, path: "/oidc/pending/create", doc: "Creates an account for the waiting identity under a chosen username and signs it in.", class: ClassPublic, request: typeOf[PendingCreateRequest](), response: typeOf[SignedInResponse](), limited: true, op: "CreatePendingOIDC", audit: "oidc.create", serve: serveOIDCCreatePending},
	{name: "authOIDCLinkByAdmin", method: http.MethodPost, path: "/oidc/pending/link", doc: "Links the waiting identity to an account named with the temporary password an admin issued it, and signs it in.", class: ClassPublic, request: typeOf[PendingLinkByAdminRequest](), response: typeOf[SignedInResponse](), limited: true, op: "LinkPendingOIDCByAdmin", audit: "oidc.admin_link", serve: serveOIDCLinkByAdmin},
	{name: "authOIDCLinkPending", method: http.MethodPost, path: "/oidc/link", doc: "Links the waiting identity to the signed-in account.", class: ClassRecentAuth, response: typeOf[MeResponse](), op: "LinkPendingOIDC", serve: serveOIDCLinkPending},
	{name: "authOIDCUnlink", method: http.MethodDelete, path: "/oidc/link", doc: "Unlinks the signed-in account's single sign-on identity.", class: ClassRecentAuth, op: "UnlinkOIDC", serve: serveOIDCUnlink},
	{name: "authInviteAcceptPassword", method: http.MethodPost, path: "/invite/password", doc: "Accepts an invite with a password and answers a session or a pending sign-in.", class: ClassPublic, request: typeOf[InviteAcceptRequest](), response: typeOf[SignInOutcome](), tokenBody: true, op: "AcceptInvitePassword", audit: "invite.accept", serve: serveInviteAcceptPassword},
	{name: "authMe", method: http.MethodGet, path: "/me", doc: "Answers the signed-in account, its session and its sign-in methods.", class: ClassSession, passive: true, response: typeOf[MeResponse](), op: "Me", serve: serveMe},
	{name: "authProfile", method: http.MethodPut, path: "/profile", doc: "Updates the signed-in account's profile.", class: ClassSession, request: typeOf[ProfileRequest](), response: typeOf[MeResponse](), op: "UpdateProfile", serve: serveProfile},
	{name: "authMethodReenable", method: http.MethodPost, path: "/methods/{method}/reenable", doc: "Unlocks a sign-in method locked after repeated failures.", class: ClassRecentAuth, pathID: pathMethod, op: "ReenableMethod", serve: serveMethodReenable},
	{name: "authStepUpPassword", method: http.MethodPost, path: "/stepup/password", doc: "Steps up the current session with the account's password.", class: ClassSession, request: typeOf[PasswordRequest](), op: "StepUpPassword", audit: auditStepUp, serve: serveStepUpPassword},
	{name: "authStepUpPasskeyBegin", method: http.MethodPost, path: "/stepup/passkey/begin", doc: "Starts the passkey assertion that steps up the current session.", class: ClassSession, response: typeOf[CeremonyResponse](), op: "StepUpPasskeyBegin", serve: serveStepUpPasskeyBegin},
	{name: "authStepUpPasskeyFinish", method: http.MethodPost, path: "/stepup/passkey/finish", doc: "Finishes the passkey assertion that steps up the current session.", class: ClassSession, cer: ceremonyAssertion, op: "StepUpPasskeyFinish", audit: auditStepUp, serve: serveStepUpPasskeyFinish},
	{name: "authStepUpCode", method: http.MethodPost, path: "/stepup/code", doc: "Steps up the current session with an authenticator app code.", class: ClassSession, request: typeOf[StepUpCodeRequest](), op: "StepUpCode", audit: auditStepUp, serve: serveStepUpCode},
	{name: "authPasswordSet", method: http.MethodPut, path: "/password", doc: "Sets or changes the account's password and answers any new recovery code.", class: ClassRecentAuth, request: typeOf[PasswordChangeRequest](), response: typeOf[RecoveryCodeIssuedResponse](), op: "SetPassword", audit: "password.set", serve: servePasswordSet},
	{name: "authPasswordRemove", method: http.MethodDelete, path: "/password", doc: "Removes the account's password.", class: ClassRecentAuth, request: typeOf[PasswordRemoveRequest](), op: "RemovePassword", audit: "password.remove", serve: servePasswordRemove},
	{name: "authTOTPBegin", method: http.MethodPost, path: "/totp/begin", doc: "Draws a new authenticator app secret for the account to enrol.", class: ClassRecentAuth, response: typeOf[TOTPBeginResponse](), op: "BeginTOTP", serve: serveTOTPBegin},
	{name: "authTOTPFinish", method: http.MethodPost, path: "/totp/finish", doc: "Enrols or replaces the account's authenticator app and answers any new recovery code.", class: ClassRecentAuth, request: typeOf[TOTPFinishRequest](), response: typeOf[RecoveryCodeIssuedResponse](), op: "FinishTOTP", serve: serveTOTPFinish},
	{name: "authRecoveryCodeRegenerate", method: http.MethodPost, path: "/recovery-code", doc: "Replaces the account's recovery code after a second-factor proof.", class: ClassRecentAuth, request: typeOf[SecondFactorProof](), cer: ceremonyAssertion, response: typeOf[RecoveryCodeResponse](), op: "RegenerateRecoveryCode", serve: serveRecoveryCodeRegenerate},
	{name: "authTOTPRemove", method: http.MethodDelete, path: "/totp", doc: "Removes the account's authenticator app.", class: ClassSession, request: typeOf[SecondFactorProof](), cer: ceremonyAssertion, op: "RemoveTOTP", serve: serveTOTPRemove},
	{name: "authPasskeys", method: http.MethodGet, path: "/passkeys", doc: "Lists the account's passkeys.", class: ClassSession, response: typeOf[PasskeyView](), array: true, op: "Passkeys", serve: servePasskeys},
	{name: "authPasskeyRegisterBegin", method: http.MethodPost, path: "/passkeys/begin", doc: "Starts registering a new passkey on the account.", class: ClassRecentAuth, request: typeOf[SecondFactorProof](), cer: ceremonyAssertion, response: typeOf[CeremonyResponse](), op: "PasskeyRegisterBegin", serve: servePasskeyRegisterBegin},
	{name: "authPasskeyRegisterFinish", method: http.MethodPost, path: "/passkeys/finish", doc: "Finishes registering a passkey and answers it with any new recovery code.", class: ClassRecentAuth, cer: ceremonyRegistration, response: typeOf[PasskeyRegisteredResponse](), op: "PasskeyRegisterFinish", serve: servePasskeyRegisterFinish},
	{name: "authPasskeyRename", method: http.MethodPut, path: "/passkeys/{id}", doc: "Renames one of the account's passkeys.", class: ClassSession, pathID: pathInt, request: typeOf[NameRequest](), op: "RenamePasskey", serve: servePasskeyRename},
	{name: "authPasskeyRemove", method: http.MethodDelete, path: "/passkeys/{id}", doc: "Removes one of the account's passkeys.", class: ClassRecentAuth, pathID: pathInt, request: typeOf[SecondFactorProof](), cer: ceremonyAssertion, op: "RemovePasskey", serve: servePasskeyRemove},
	{name: "authWebAuthnSignals", method: http.MethodGet, path: "/webauthn/signals", doc: "Answers the passkeys and user details the browser's WebAuthn signal calls report.", class: ClassSession, response: typeOf[webauthn.Signals](), op: "WebAuthnSignals", serve: serveWebAuthnSignals},
	{name: "authSessions", method: http.MethodGet, path: "/sessions", doc: "Lists the account's sessions.", class: ClassSession, response: typeOf[SessionView](), array: true, op: "Sessions", serve: serveSessions},
	{name: "authSessionRename", method: http.MethodPut, path: "/sessions/{id}", doc: "Renames one of the account's sessions.", class: ClassSession, pathID: pathSession, request: typeOf[NameRequest](), op: "RenameSession", serve: serveSessionRename},
	{name: "authSessionRevoke", method: http.MethodDelete, path: "/sessions/{id}", doc: "Ends one of the account's sessions.", class: ClassSession, pathID: pathSession, op: "RevokeSession", serve: serveSessionRevoke},
	{name: "authSessionsRevokeOthers", method: http.MethodPost, path: "/sessions/revoke-others", doc: "Ends every session of the account but the current one.", class: ClassRecentAuth, op: "RevokeOtherSessions", serve: serveSessionsRevokeOthers},
	{name: "authKeys", method: http.MethodGet, path: "/apikeys", doc: "Lists the account's API keys.", class: ClassSession, response: typeOf[KeyView](), array: true, op: "APIKeys", serve: serveKeys},
	{name: "authKeyCreate", method: http.MethodPost, path: "/apikeys", doc: "Creates an API key and answers its secret once.", scope: scopeKeys, request: typeOf[NewKeyRequest](), response: typeOf[KeyCreatedResponse](), op: "CreateAPIKey", serve: serveKeyCreate},
	{name: "authKeyRename", method: http.MethodPut, path: "/apikeys/{id}", doc: "Renames one of the account's API keys.", class: ClassSession, pathID: pathInt, request: typeOf[NameRequest](), op: "RenameAPIKey", serve: serveKeyRename},
	{name: "authKeyRotate", method: http.MethodPost, path: "/apikeys/{id}/rotate", doc: "Replaces an API key's secret and answers the new one once.", class: ClassRecentAuth, pathID: pathInt, response: typeOf[KeyCreatedResponse](), op: "RotateAPIKey", serve: serveKeyRotate},
	{name: "authKeyRevoke", method: http.MethodDelete, path: "/apikeys/{id}", doc: "Revokes one of the account's API keys.", class: ClassSession, pathID: pathInt, op: "RevokeAPIKey", serve: serveKeyRevoke},
	{name: "authAdminUsers", method: http.MethodGet, path: "/users", doc: "Lists the app's accounts with their sign-in methods.", scope: scopeAdmin, query: typeOf[AdminUsersQuery](), response: typeOf[UserView](), array: true, op: "Users", serve: serveAdminUsers},
	{name: "authAdminUserCreate", method: http.MethodPost, path: "/users", doc: "Creates an account.", scope: scopeUsers, request: typeOf[NewUserRequest](), response: typeOf[UserView](), op: "CreateUser", serve: serveAdminUserCreate},
	{name: "authAdminUserUpdate", method: http.MethodPut, path: "/users/{id}", doc: "Changes an account's role or whether it is enabled.", scope: scopeUsers, pathID: pathInt, request: typeOf[UserUpdateRequest](), response: typeOf[UserView](), op: "UpdateUser", serve: serveAdminUserUpdate},
	{name: "authAdminOwner", method: http.MethodPut, path: "/users/{id}/owner", doc: "Makes an account an owner or removes its owner flag.", class: ClassRecentAuth, pathID: pathInt, request: typeOf[OwnerRequest](), response: typeOf[UserView](), op: "SetOwner", serve: serveAdminOwner},
	{name: "authAdminSSOReadiness", method: http.MethodGet, path: "/sso/readiness", doc: "Answers what applying a single sign-on mode would change, or why it is refused.", class: ClassRecentAuth, query: typeOf[SSOReadinessQuery](), response: typeOf[Readiness](), op: "SSOReadiness", serve: serveAdminSSOReadiness},
	{name: "authAdminSSOApply", method: http.MethodPut, path: "/sso", doc: "Applies a single sign-on mode to the app.", class: ClassRecentAuth, request: typeOf[SSORequest](), op: "ApplySSO", serve: serveAdminSSOApply},
	{name: "authAdminUserDelete", method: http.MethodDelete, path: "/users/{id}", doc: "Deletes an account.", scope: scopeUsers, pathID: pathInt, op: "DeleteUser", serve: serveAdminUserDelete},
	{name: "authAdminOIDCUnlink", method: http.MethodDelete, path: "/users/{id}/oidc", doc: "Unlinks an account's single sign-on identity.", scope: scopeUsers, pathID: pathInt, op: "AdminUnlinkOIDC", serve: serveAdminOIDCUnlink},
	{name: "authAdminOIDCRelink", method: http.MethodPost, path: "/users/{id}/oidc/relink", doc: "Unlinks an account's single sign-on identity, issues it a temporary password and answers it once.", scope: scopeUsers, pathID: pathInt, request: typeOf[TemporaryPasswordOptions](), response: typeOf[TemporaryPasswordResponse](), op: "AdminRelinkOIDC", serve: serveAdminOIDCRelink},
	{name: "authAdminTemporaryPassword", method: http.MethodPost, path: "/users/{id}/temporary-password", doc: "Issues an account a temporary password and answers it once.", scope: scopeUsers, pathID: pathInt, request: typeOf[TemporaryPasswordOptions](), response: typeOf[TemporaryPasswordResponse](), op: "SetTemporaryPassword", serve: serveAdminTemporaryPassword},
	{name: "authAdminSecondFactorReset", method: http.MethodDelete, path: "/users/{id}/second-factor", doc: "Deletes an account's authenticator app and recovery code and ends its sessions.", scope: scopeUsers, pathID: pathInt, op: "ResetSecondFactor", serve: serveAdminSecondFactorReset},
	{name: "authAdminInvite", method: http.MethodPost, path: "/invites", doc: "Creates an invite and answers its token once.", scope: scopeUsers, request: typeOf[InviteRequest](), response: typeOf[TokenResponse](), op: "CreateInvite", serve: serveAdminInvite},
	{name: "authAdminKeys", method: http.MethodGet, path: "/admin/apikeys", doc: "Lists every account's API keys.", scope: scopeAdmin, response: typeOf[KeyView](), array: true, op: "AllAPIKeys", serve: serveAdminKeys},
	{name: "authAdminKeyRevoke", method: http.MethodDelete, path: "/admin/apikeys/{id}", doc: "Revokes any account's API key.", scope: scopeAdmin, pathID: pathInt, op: "RevokeAnyAPIKey", serve: serveAdminKeyRevoke},
	{name: "authAdminTokens", method: http.MethodGet, path: "/tokens", doc: "Lists the unspent one-time tokens, such as invites.", scope: scopeAdmin, response: typeOf[TokenView](), array: true, op: "Tokens", serve: serveAdminTokens},
	{name: "authAdminSecurityLog", method: http.MethodGet, path: "/security-log", doc: "Answers a page of the security log.", scope: scopeAdmin, query: typeOf[AdminSecurityLogQuery](), response: typeOf[SecurityLogView](), op: "SecurityLog", serve: serveAdminSecurityLog},
}

// opCodes is the codes each account operation's errors map to, the third
// part of a route's Codes; the class guard and the transport add theirs.
// An operation that rereads its caller's session or user answers
// ErrSessionGone, which maps to CodeSessionExpired.
var opCodes = map[string][]access.Code{
	"State":                      {access.CodeUnavailable},
	"SetupWithPassword":          {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeUsernameInvalid, access.CodePasswordRejected, access.CodeBreachCheckUnavailable, access.CodeSetupComplete, access.CodeSetupTokenRequired, access.CodeTokenInvalid},
	"SetupPasskeyBegin":          {access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeUsernameInvalid, access.CodeSetupComplete, access.CodeSetupTokenRequired, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeOriginRefused},
	"SetupPasskeyFinish":         {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeUnavailable, access.CodeSetupComplete, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeNotDiscoverable, access.CodeRegistrationFailed},
	"PasswordLogin":              {access.CodeHTTPSRequired, access.CodeInvalidCredentials, access.CodeForbidden, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeUsernameInvalid, access.CodeSecondFactorRequired},
	"SignInWithCode":             {access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeBadRequest, access.CodeTokenInvalid, access.CodeCodeInvalid, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled},
	"SecondFactorPasskeyBegin":   {access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeOriginRefused},
	"SecondFactorPasskeyFinish":  {access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeUnknownCredential, access.CodeAssertionFailed},
	"SignInWithRecoveryCode":     {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeBadRequest, access.CodeTokenInvalid, access.CodeCodeInvalid},
	"SetCredentialPassword":      {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasswordLoginDisabled, access.CodePasswordRejected, access.CodeBreachCheckUnavailable},
	"SetCredentialPasskeyBegin":  {access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeOriginRefused},
	"SetCredentialPasskeyFinish": {access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeNotDiscoverable, access.CodeRegistrationFailed, access.CodeDuplicateCredential},
	"PendingTOTPBegin":           {access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodeTOTPDisabled},
	"PendingTOTPFinish":          {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeBadRequest, access.CodeTokenInvalid, access.CodeCodeInvalid, access.CodeTOTPDisabled, access.CodeSetupComplete, access.CodeUsernameTaken, access.CodeSSOOnly},
	"PendingPasskeyBegin":        {access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeOriginRefused},
	"PendingPasskeyFinish":       {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeNotDiscoverable, access.CodeRegistrationFailed, access.CodeDuplicateCredential, access.CodeSetupComplete, access.CodeUsernameTaken, access.CodeSSOOnly},
	"StepUpCode":                 {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeRateLimited, access.CodeUnavailable, access.CodeBadRequest, access.CodeCodeInvalid, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled, access.CodeSSOOnly},
	"BeginTOTP":                  {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeForbidden, access.CodeUnavailable, access.CodeTOTPDisabled, access.CodeSSOOnly},
	"FinishTOTP":                 {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeForbidden, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeBadRequest, access.CodeTokenInvalid, access.CodeCodeInvalid, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled, access.CodeSSOOnly},
	"RegenerateRecoveryCode":     {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeSSOOnly, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeBadRequest, access.CodeCodeInvalid, access.CodeCeremonyInvalid, access.CodeAssertionFailed, access.CodeUnknownCredential, access.CodePasskeysUnavailable, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled, access.CodeNotFound},
	"RemoveTOTP":                 {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeRecentAuthRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeBadRequest, access.CodeCodeInvalid, access.CodeCeremonyInvalid, access.CodeAssertionFailed, access.CodeUnknownCredential, access.CodePasskeysUnavailable, access.CodeSecondFactorUnavailable, access.CodeLastMethod, access.CodeNotFound},
	"PasskeyLoginBegin":          {access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodePasskeysUnavailable, access.CodeOriginRefused},
	"PasskeyLoginFinish":         {access.CodeHTTPSRequired, access.CodeInvalidCredentials, access.CodeUnavailable, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeUnknownCredential, access.CodeAssertionFailed},
	"Logout":                     {access.CodeUnavailable},
	"AcceptInvitePassword":       {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeUsernameInvalid, access.CodeUsernameTaken, access.CodePasswordRejected, access.CodeBreachCheckUnavailable, access.CodeTokenInvalid, access.CodeSSOOnly},
	"AdmitOIDC":                  {access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeOIDCUnavailable},
	"AcceptInviteOIDCBegin":      {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodeOIDCUnavailable},
	opOIDCBegin:                  {access.CodeHTTPSRequired, access.CodeUnavailable, access.CodeBadRequest, access.CodeCrossOrigin, access.CodeOIDCUnavailable},
	"OIDCComplete":               {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeInvalidCredentials, access.CodeRecentAuthRequired, access.CodeForbidden, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodeIdentityTaken, access.CodeAlreadyLinked, access.CodeOIDCUnavailable, access.CodeOIDCFailed},
	"CreatePendingOIDC":          {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeRateLimited, access.CodeUnavailable, access.CodeUsernameInvalid, access.CodeUsernameTaken, access.CodeTokenInvalid, access.CodeIdentityTaken, access.CodeOIDCUnavailable, access.CodeNotFound},
	"LinkPendingOIDCByAdmin":     {access.CodeHTTPSRequired, access.CodeInvalidCredentials, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeIdentityTaken, access.CodeAlreadyLinked, access.CodeOIDCUnavailable, access.CodeNotFound},
	"OIDCPending":                {access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeOIDCUnavailable, access.CodeNotFound},
	"LinkPendingOIDC":            {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeUnavailable, access.CodeIdentityTaken, access.CodeAlreadyLinked, access.CodeOIDCUnavailable, access.CodeNotFound},
	"UnlinkOIDC":                 {access.CodeSessionExpired, access.CodeUnavailable, access.CodeLastMethod, access.CodeNotFound},
	"StepUpPassword":             {access.CodeHTTPSRequired, access.CodeInvalidCredentials, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodePasswordLoginDisabled, access.CodeSessionExpired, access.CodeSSOOnly, access.CodeSecondFactorRequired},
	"SetPassword":                {access.CodeInvalidCredentials, access.CodeSSOOnly, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeBadRequest, access.CodePasswordRejected, access.CodeBreachCheckUnavailable, access.CodeSessionExpired},
	"RemovePassword":             {access.CodeHTTPSRequired, access.CodeInvalidCredentials, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeBadRequest, access.CodeLastMethod, access.CodeNotFound, access.CodeSessionExpired},
	"Me":                         {access.CodeSessionExpired, access.CodeUnavailable},
	"UpdateProfile":              {access.CodeSessionExpired, access.CodeUnavailable, access.CodeBadRequest},
	"ReenableMethod":             {access.CodeRecentAuthRequired, access.CodeUnavailable, access.CodeMethodNotLocked},
	"StepUpPasskeyBegin":         {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeUnavailable, access.CodePasskeysUnavailable, access.CodeOriginRefused, access.CodeNotFound, access.CodeSSOOnly},
	"StepUpPasskeyFinish":        {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeUnavailable, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeUnknownCredential, access.CodeAssertionFailed, access.CodeSSOOnly},
	"Passkeys":                   {access.CodeSessionExpired, access.CodeUnavailable},
	"PasskeyRegisterBegin":       {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeSSOOnly, access.CodeUnavailable, access.CodePasskeysUnavailable, access.CodeOriginRefused, access.CodeBadRequest, access.CodeCodeInvalid, access.CodeRateLimited, access.CodeCeremonyInvalid, access.CodeAssertionFailed, access.CodeUnknownCredential, access.CodePasskeysUnavailable, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled},
	"PasskeyRegisterFinish":      {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeSSOOnly, access.CodeBusy, access.CodeUnavailable, access.CodeDuplicateCredential, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeNotDiscoverable, access.CodeRegistrationFailed},
	"RenamePasskey":              {access.CodeUnavailable, access.CodeBadRequest, access.CodeNotFound},
	"RemovePasskey":              {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeUnavailable, access.CodeLastMethod, access.CodeNotFound, access.CodeBadRequest, access.CodeCodeInvalid, access.CodeRateLimited, access.CodeCeremonyInvalid, access.CodeAssertionFailed, access.CodeUnknownCredential, access.CodePasskeysUnavailable, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled},
	"WebAuthnSignals":            {access.CodeSessionExpired, access.CodeUnavailable, access.CodePasskeysUnavailable},
	"Sessions":                   {access.CodeUnavailable},
	"RenameSession":              {access.CodeUnavailable, access.CodeBadRequest, access.CodeNotFound},
	"RevokeSession":              {access.CodeUnavailable, access.CodeNotFound},
	"RevokeOtherSessions":        {access.CodeUnavailable},
	"APIKeys":                    {access.CodeUnavailable},
	"CreateAPIKey":               {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeForbidden, access.CodeUnavailable, access.CodeBadRequest, access.CodeUnknownScope, access.CodeKeyLabelTaken},
	"RenameAPIKey":               {access.CodeUnavailable, access.CodeBadRequest, access.CodeNotFound, access.CodeKeyLabelTaken},
	"RotateAPIKey":               {access.CodeHTTPSRequired, access.CodeSessionExpired, access.CodeForbidden, access.CodeUnavailable, access.CodeNotFound},
	"RevokeAPIKey":               {access.CodeUnavailable, access.CodeNotFound},
	"Users":                      {access.CodeForbidden, access.CodeUnavailable},
	"CreateUser":                 {access.CodeForbidden, access.CodeBusy, access.CodeUnavailable, access.CodeUsernameInvalid, access.CodeUsernameTaken, access.CodePasswordRejected, access.CodeBreachCheckUnavailable},
	"UpdateUser":                 {access.CodeForbidden, access.CodeUnavailable, access.CodeBadRequest, access.CodeNotFound},
	"DeleteUser":                 {access.CodeForbidden, access.CodeUnavailable, access.CodeNotFound},
	"SetOwner":                   {access.CodeForbidden, access.CodeUnavailable, access.CodeNotFound},
	"AdminUnlinkOIDC":            {access.CodeForbidden, access.CodeUnavailable, access.CodeNotFound},
	"AdminRelinkOIDC":            {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeBusy, access.CodeUnavailable, access.CodeBadRequest, access.CodeNotFound},
	"SetTemporaryPassword":       {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeBusy, access.CodeUnavailable, access.CodeBadRequest, access.CodeNotFound, access.CodeSSOOnly},
	"ResetSecondFactor":          {access.CodeForbidden, access.CodeUnavailable, access.CodeNotFound},
	"SSOReadiness":               {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeUnavailable, access.CodeOIDCUnavailable},
	"ApplySSO":                   {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeUnavailable, access.CodeOIDCUnavailable},
	"CreateInvite":               {access.CodeHTTPSRequired, access.CodeForbidden, access.CodeUnavailable, access.CodeBadRequest},
	"AllAPIKeys":                 {access.CodeForbidden, access.CodeUnavailable},
	"RevokeAnyAPIKey":            {access.CodeForbidden, access.CodeUnavailable, access.CodeNotFound},
	"Tokens":                     {access.CodeForbidden, access.CodeUnavailable},
	"SecurityLog":                {access.CodeForbidden, access.CodeUnavailable, access.CodeBadRequest},
}

// guardCodes is what a class's guard can answer: the Authenticator's
// refusals on every class that authenticates, auth_https_required among
// them since a descriptor does not know the posture, then the class
// predicate's. A key class has a scope set (classFor), so a non-key
// principal there is refused for the scope, never for want of a session.
func guardCodes(c Class) []access.Code {
	if c == ClassPublic {
		return nil
	}
	codes := []access.Code{access.CodeAuthRequired, access.CodeSessionExpired, access.CodeInvalidCredentials, access.CodeKeyInvalid, access.CodeUnavailable, access.CodeHTTPSRequired}
	switch c {
	case ClassSession:
		codes = append(codes, access.CodeSessionRequired)
	case ClassRecentAuth:
		codes = append(codes, access.CodeSessionRequired, access.CodeRecentAuthRequired)
	case ClassKeyScope:
		codes = append(codes, access.CodeScopeRequired)
	case ClassKeyPermission:
		codes = append(codes, access.CodeRecentAuthRequired, access.CodeScopeRequired)
	default:
	}
	return codes
}

// transportCodes is what the transport can answer before or around the
// operation: method, origin, body, path, query and limiter refusals.
func (s *routeSpec) transportCodes() []access.Code {
	codes := []access.Code{access.CodeMethodNotAllowed}
	if s.method != http.MethodGet {
		codes = append(codes, access.CodeCrossOrigin)
	}
	body := s.request != nil || s.cer != ceremonyNone
	if body {
		codes = append(codes, access.CodeBodyTooLarge)
	}
	if body || s.pathID != pathNone || s.tokenBody || (s.query != nil && !s.redirect) {
		codes = append(codes, access.CodeBadRequest)
	}
	if s.limited {
		codes = append(codes, access.CodeRateLimited)
	}
	return codes
}

// classFor resolves a spec's class and scope against dc's scopes.
func (s *routeSpec) classFor(dc *DescriptorConfig) (class Class, scope string) {
	switch s.scope {
	case scopeAdmin:
		if dc.AdminScope != "" {
			return ClassKeyScope, dc.AdminScope
		}
		return ClassSession, ""
	case scopeUsers:
		return permission(dc.ManageUsersScope)
	case scopeKeys:
		return permission(dc.CreateKeysScope)
	default:
		return s.class, ""
	}
}

func permission(scope string) (class Class, required string) {
	if scope != "" {
		return ClassKeyPermission, scope
	}
	return ClassRecentAuth, ""
}

// DescriptorConfig is what a route's Path and access level read: Config's
// two prefixes and account.Config's three key scopes.
type DescriptorConfig struct {
	Prefix           string
	OIDCPrefix       string
	AdminScope       string
	ManageUsersScope string
	CreateKeysScope  string
}

// Descriptors returns every route's Descriptor, in Routes order, with no
// Account: for the same values it equals the Descriptors of New's Routes.
func Descriptors(cfg DescriptorConfig) []Descriptor { //nolint:gocritic // hugeParam: as New
	out := make([]Descriptor, len(specs))
	for i := range specs {
		out[i] = specs[i].descriptor(&cfg)
	}
	return out
}

func (s *routeSpec) descriptor(dc *DescriptorConfig) Descriptor {
	class, scope := s.classFor(dc)
	path := dc.Prefix + s.path
	if s.oidc {
		path = dc.OIDCPrefix + s.path
	}
	kind := KindJSON
	if s.redirect {
		kind = KindRedirect
	}
	parts := slices.Concat(guardCodes(class), s.transportCodes(), opCodes[s.op])
	return Descriptor{
		Name:     s.name,
		Method:   s.method,
		Path:     path,
		Class:    class,
		Scope:    scope,
		Passive:  s.passive,
		Kind:     kind,
		Request:  s.request,
		Query:    s.query,
		Response: s.response,
		Array:    s.array,
		Codes:    inCodesOrder(parts),
		Doc:      s.doc,
	}
}

// codeRank is each code's position in access.Codes().
var codeRank = func() map[access.Code]int {
	codes := access.Codes()
	m := make(map[access.Code]int, len(codes))
	for i, c := range codes {
		m[c] = i
	}
	return m
}()

// inCodesOrder dedupes codes and orders them as access.Codes() does.
func inCodesOrder(codes []access.Code) []access.Code {
	out := slices.Clone(codes)
	slices.SortFunc(out, func(a, b access.Code) int { return codeRank[a] - codeRank[b] })
	return slices.Compact(out)
}
