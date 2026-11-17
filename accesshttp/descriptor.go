package accesshttp

import (
	"net/http"
	"reflect"
	"slices"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
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
	scopeAdmin   scopeRule = iota + 1 // key_scope with AdminScope when set, else session
	scopeOwnKeys                      // key_scope with CreateKeysScope when set, else session
	scopeUsers                        // key_permission with ManageUsersScope when set, else recent_auth
	scopeKeys                         // key_permission with CreateKeysScope when set, else recent_auth
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

// typ is the type the path value decodes to, the type of the call field
// pathValues sets from it.
func (p pathID) typ() reflect.Type {
	switch p {
	case pathInt:
		return reflect.TypeFor[int64]()
	case pathSession:
		return reflect.TypeFor[string]()
	case pathMethod:
		return reflect.TypeFor[access.Method]()
	default:
		return nil
	}
}

// reasonSet is the Reason values one code can carry on a route: each of
// listed, "" being the answer with none, and, when open, one the route
// does not fix: a refused field's name on auth_bad_request,
// an IdP's error code on auth_oidc_failed, the Policy's on auth_forbidden.
type reasonSet struct {
	listed []string
	open   bool
}

// answer is one code a part of a route can answer, with its reasons there.
type answer struct {
	code access.Code
	reasonSet
}

// answers is what one part of a route can answer, each code once.
type answers []answer

// none is codes, each answered with no Reason.
func none(codes ...access.Code) answers {
	as := make(answers, len(codes))
	for i, c := range codes {
		as[i] = answer{code: c, listed: []string{""}}
	}
	return as
}

// with adds code, answered with one of reasons, "" for none.
func (as answers) with(code access.Code, reasons ...string) answers {
	return append(as, answer{code: code, listed: reasons})
}

// open adds code marked open, beside the reasons it carries fixed.
func (as answers) open(code access.Code, reasons ...string) answers {
	return append(as, answer{code: code, listed: reasons, open: true})
}

// codes is as's codes, deduped, in access.Codes order.
func (as answers) codes() []access.Code {
	codes := make([]access.Code, len(as))
	for i := range as {
		codes[i] = as[i].code
	}
	return inCodesOrder(codes)
}

// routeSpec is one route's static facts; descriptor derives its Descriptor
// under a DescriptorConfig.
type routeSpec struct {
	request, query, response reflect.Type
	serve                    serveFunc
	name, method, path, doc  string
	op                       string // the account operation, a key of opAnswers
	audit                    string // the access.AuditEvent kind prefix; "" audits nothing
	class                    Class
	scope                    scopeRule
	pathID                   pathID
	success                  int // the status the route writes; a JSON route's refusal carries its code's
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
	auditRegister        = "register"
	opOIDCBegin          = "OIDCBegin"
	routeOIDCStartSignIn = "authOIDCStartSignIn"
)

func typeOf[T any]() reflect.Type { return reflect.TypeFor[T]() }

// specs is every route, in Routes order.
var specs = []routeSpec{
	{name: "authState", method: http.MethodGet, path: "/state", doc: "Answers what the sign-in screen offers: setup, the sign-in methods and what needs HTTPS.", success: http.StatusOK, class: ClassPublic, passive: true, response: typeOf[StateResponse](), op: "State", serve: serveState},
	{name: "authSetupPassword", method: http.MethodPost, path: "/setup/password", doc: "Creates the first account with a password and answers a session or a pending sign-in.", success: http.StatusOK, class: ClassPublic, request: typeOf[SetupPasswordRequest](), response: typeOf[SignInOutcome](), tokenBody: true, op: "SetupWithPassword", audit: auditSetup, serve: serveSetupPassword},
	{name: "authSetupPasskeyBegin", method: http.MethodPost, path: "/setup/passkey/begin", doc: "Starts the passkey registration that creates the first account.", success: http.StatusOK, class: ClassPublic, request: typeOf[SetupPasskeyBeginRequest](), response: typeOf[CeremonyResponse](), tokenBody: true, op: "SetupPasskeyBegin", audit: auditSetup, serve: serveSetupPasskeyBegin},
	{name: "authSetupPasskeyFinish", method: http.MethodPost, path: "/setup/passkey/finish", doc: "Finishes the first account's passkey registration and signs it in.", success: http.StatusOK, class: ClassPublic, cer: ceremonyRegistration, response: typeOf[SignedInResponse](), op: "SetupPasskeyFinish", audit: auditSetup, serve: serveSetupPasskeyFinish},
	{name: "authLoginPassword", method: http.MethodPost, path: "/login/password", doc: "Signs in with a password and answers a session or a pending sign-in.", success: http.StatusOK, class: ClassPublic, request: typeOf[LoginRequest](), response: typeOf[SignInOutcome](), op: "PasswordLogin", audit: auditLogin, serve: serveLoginPassword},
	{name: "authLoginCode", method: http.MethodPost, path: "/login/code", doc: "Completes a pending sign-in with an authenticator app code.", success: http.StatusOK, class: ClassPublic, request: typeOf[CodeRequest](), response: typeOf[SignInOutcome](), op: "SignInWithCode", audit: auditLogin, serve: serveLoginCode},
	{name: "authLoginSecondPasskeyBegin", method: http.MethodPost, path: "/login/second-passkey/begin", doc: "Starts the passkey assertion that completes a pending sign-in.", success: http.StatusOK, class: ClassPublic, request: typeOf[TicketRequest](), response: typeOf[CeremonyResponse](), op: "SecondFactorPasskeyBegin", serve: serveLoginSecondPasskeyBegin},
	{name: "authLoginSecondPasskeyFinish", method: http.MethodPost, path: "/login/second-passkey/finish", doc: "Finishes the passkey assertion that completes a pending sign-in.", success: http.StatusOK, class: ClassPublic, cer: ceremonyAssertion, response: typeOf[SignInOutcome](), op: "SecondFactorPasskeyFinish", audit: auditLogin, serve: serveLoginSecondPasskeyFinish},
	{name: "authLoginRecoveryCode", method: http.MethodPost, path: "/login/recovery-code", doc: "Checks a recovery code on a pending sign-in and answers the step that enrols a new second factor.", success: http.StatusOK, class: ClassPublic, request: typeOf[CodeRequest](), response: typeOf[SignInOutcome](), op: "SignInWithRecoveryCode", audit: auditLogin, serve: serveLoginRecoveryCode},
	{name: "authLoginSetPassword", method: http.MethodPost, path: "/login/set-password", doc: "Sets the password chosen after a temporary password and answers a session or a pending sign-in.", success: http.StatusOK, class: ClassPublic, request: typeOf[SetPasswordRequest](), response: typeOf[SignInOutcome](), op: "SetCredentialPassword", audit: auditLogin, serve: serveLoginSetPassword},
	{name: "authLoginSetPasskeyBegin", method: http.MethodPost, path: "/login/set-passkey/begin", doc: "Starts the passkey registration that replaces a temporary password.", success: http.StatusOK, class: ClassPublic, request: typeOf[TicketRequest](), response: typeOf[CeremonyResponse](), op: "SetCredentialPasskeyBegin", serve: serveLoginSetPasskeyBegin},
	{name: "authLoginSetPasskeyFinish", method: http.MethodPost, path: "/login/set-passkey/finish", doc: "Finishes the passkey registration that replaces a temporary password and signs in.", success: http.StatusOK, class: ClassPublic, cer: ceremonyRegistration, response: typeOf[SignInOutcome](), op: "SetCredentialPasskeyFinish", audit: auditLogin, serve: serveLoginSetPasskeyFinish},
	{name: "authPendingTOTPBegin", method: http.MethodPost, path: "/pending/totp/begin", doc: "Draws an authenticator app secret for a pending sign-in to enrol.", success: http.StatusOK, class: ClassPublic, request: typeOf[TicketRequest](), response: typeOf[PendingTOTPBeginResponse](), op: "PendingTOTPBegin", serve: servePendingTOTPBegin},
	{name: "authPendingTOTPFinish", method: http.MethodPost, path: "/pending/totp/finish", doc: "Enrols a pending sign-in's authenticator app with its first code and signs in.", success: http.StatusOK, class: ClassPublic, request: typeOf[CodeRequest](), response: typeOf[EnrolmentOutcome](), op: "PendingTOTPFinish", audit: auditLogin, serve: servePendingTOTPFinish},
	{name: "authPendingPasskeyBegin", method: http.MethodPost, path: "/pending/passkey/begin", doc: "Starts the passkey registration a pending sign-in enrols.", success: http.StatusOK, class: ClassPublic, request: typeOf[TicketRequest](), response: typeOf[CeremonyResponse](), op: "PendingPasskeyBegin", serve: servePendingPasskeyBegin},
	{name: "authPendingPasskeyFinish", method: http.MethodPost, path: "/pending/passkey/finish", doc: "Finishes a pending sign-in's passkey registration and signs in.", success: http.StatusOK, class: ClassPublic, cer: ceremonyRegistration, response: typeOf[EnrolmentOutcome](), op: "PendingPasskeyFinish", audit: auditLogin, serve: servePendingPasskeyFinish},
	{name: "authLoginPasskeyBegin", method: http.MethodPost, path: "/login/passkey/begin", doc: "Starts a passkey sign-in.", success: http.StatusOK, class: ClassPublic, query: typeOf[PasskeyBeginQuery](), response: typeOf[CeremonyResponse](), op: "PasskeyLoginBegin", serve: serveLoginPasskeyBegin},
	{name: "authLoginPasskeyFinish", method: http.MethodPost, path: "/login/passkey/finish", doc: "Finishes a passkey sign-in and answers the session.", success: http.StatusOK, class: ClassPublic, cer: ceremonyAssertion, response: typeOf[SignedInResponse](), op: "PasskeyLoginFinish", audit: auditLogin, serve: serveLoginPasskeyFinish},
	{name: "authLogout", method: http.MethodPost, path: "/logout", doc: "Ends the presented session and clears its cookie.", success: http.StatusNoContent, class: ClassPublic, op: "Logout", serve: serveLogout},
	{name: routeOIDCStartSignIn, method: http.MethodGet, path: "/start/signin", doc: "Redirects to the identity provider to sign in.", success: http.StatusFound, oidc: true, class: ClassPublic, redirect: true, query: typeOf[OIDCSignInQuery](), limited: true, op: "AdmitOIDC", audit: "oidc.start", serve: serveOIDCStartSignIn},
	{name: "authOIDCStartLink", method: http.MethodPost, path: "/start/link", doc: "Answers the identity provider URL that links an identity to the signed-in account.", success: http.StatusOK, oidc: true, class: ClassRecentAuth, request: typeOf[RedirectRequest](), response: typeOf[OIDCStartResponse](), op: opOIDCBegin, serve: serveOIDCStartLink},
	{name: "authOIDCStartStepUp", method: http.MethodPost, path: "/start/stepup", doc: "Answers the identity provider URL that steps up the current session.", success: http.StatusOK, oidc: true, class: ClassSession, request: typeOf[RedirectRequest](), response: typeOf[OIDCStartResponse](), op: opOIDCBegin, serve: serveOIDCStartStepUp},
	{name: "authInviteAcceptOIDC", method: http.MethodPost, path: "/start/invite", doc: "Answers the identity provider URL that accepts an invite by single sign-on.", success: http.StatusOK, oidc: true, class: ClassPublic, request: typeOf[TokenRequest](), response: typeOf[OIDCStartResponse](), tokenBody: true, limited: true, op: "AcceptInviteOIDCBegin", audit: "oidc.invite", serve: serveInviteAcceptOIDC},
	{name: "authOIDCCallback", method: http.MethodGet, path: "/callback", doc: "Completes a flow the identity provider sent back and redirects into the app.", success: http.StatusFound, oidc: true, class: ClassPublic, redirect: true, query: typeOf[OIDCCallbackQuery](), limited: true, op: "OIDCComplete", audit: "oidc.callback", serve: serveOIDCCallback},
	{name: "authOIDCPending", method: http.MethodGet, path: "/oidc/pending", doc: "Answers the identity waiting to be linked or turned into an account.", success: http.StatusOK, class: ClassPublic, passive: true, response: typeOf[PendingLinkResponse](), limited: true, op: "OIDCPending", serve: serveOIDCPending},
	{name: "authOIDCCreatePending", method: http.MethodPost, path: "/oidc/pending/create", doc: "Creates an account for the waiting identity under a chosen username and signs it in.", success: http.StatusOK, class: ClassPublic, request: typeOf[PendingCreateRequest](), response: typeOf[SignedInResponse](), limited: true, op: "CreatePendingOIDC", audit: "oidc.create", serve: serveOIDCCreatePending},
	{name: "authOIDCLinkByAdmin", method: http.MethodPost, path: "/oidc/pending/link", doc: "Links the waiting identity to an account named with the temporary password an admin issued it, and signs it in.", success: http.StatusOK, class: ClassPublic, request: typeOf[PendingLinkByAdminRequest](), response: typeOf[SignedInResponse](), limited: true, op: "LinkPendingOIDCByAdmin", audit: "oidc.admin_link", serve: serveOIDCLinkByAdmin},
	{name: "authOIDCLinkPending", method: http.MethodPost, path: "/oidc/link", doc: "Links the waiting identity to the signed-in account.", success: http.StatusOK, class: ClassRecentAuth, response: typeOf[MeResponse](), op: "LinkPendingOIDC", serve: serveOIDCLinkPending},
	{name: "authOIDCUnlink", method: http.MethodDelete, path: "/oidc/link", doc: "Unlinks the signed-in account's single sign-on identity.", success: http.StatusNoContent, class: ClassRecentAuth, op: "UnlinkOIDC", serve: serveOIDCUnlink},
	{name: "authInviteAcceptPassword", method: http.MethodPost, path: "/invite/password", doc: "Accepts an invite with a password and answers a session or a pending sign-in.", success: http.StatusOK, class: ClassPublic, request: typeOf[InviteAcceptRequest](), response: typeOf[SignInOutcome](), tokenBody: true, op: "AcceptInvitePassword", audit: "invite.accept", serve: serveInviteAcceptPassword},
	{name: "authRegisterPassword", method: http.MethodPost, path: "/register/password", doc: "Creates an account with a password where sign-ups are open and answers a session, a pending sign-in or that the account waits for approval.", success: http.StatusOK, class: ClassPublic, request: typeOf[RegisterPasswordRequest](), response: typeOf[RegistrationOutcome](), op: "RegisterPassword", audit: auditRegister, serve: serveRegisterPassword},
	{name: "authRegisterPasskeyBegin", method: http.MethodPost, path: "/register/passkey/begin", doc: "Starts the passkey registration that creates an account where sign-ups are open.", success: http.StatusOK, class: ClassPublic, request: typeOf[RegisterPasskeyBeginRequest](), response: typeOf[CeremonyResponse](), op: "RegisterPasskeyBegin", audit: auditRegister, serve: serveRegisterPasskeyBegin},
	{name: "authRegisterPasskeyFinish", method: http.MethodPost, path: "/register/passkey/finish", doc: "Finishes the passkey registration that creates an account and answers a session or that the account waits for approval.", success: http.StatusOK, class: ClassPublic, cer: ceremonyRegistration, response: typeOf[EnrolmentOutcome](), op: "RegisterPasskeyFinish", audit: auditRegister, serve: serveRegisterPasskeyFinish},
	{name: "authMe", method: http.MethodGet, path: "/me", doc: "Answers the signed-in account, its session and its sign-in methods.", success: http.StatusOK, class: ClassSession, passive: true, response: typeOf[MeResponse](), op: "Me", serve: serveMe},
	{name: "authProfile", method: http.MethodPut, path: "/profile", doc: "Updates the signed-in account's profile.", success: http.StatusOK, class: ClassSession, request: typeOf[ProfileRequest](), response: typeOf[MeResponse](), op: "UpdateProfile", serve: serveProfile},
	{name: "authMethodReenable", method: http.MethodPost, path: "/methods/{method}/reenable", doc: "Unlocks a sign-in method locked after repeated failures.", success: http.StatusNoContent, class: ClassRecentAuth, pathID: pathMethod, op: "ReenableMethod", serve: serveMethodReenable},
	{name: "authStepUpPassword", method: http.MethodPost, path: "/stepup/password", doc: "Steps up the current session with the account's password.", success: http.StatusNoContent, class: ClassSession, request: typeOf[PasswordRequest](), op: "StepUpPassword", audit: auditStepUp, serve: serveStepUpPassword},
	{name: "authStepUpPasskeyBegin", method: http.MethodPost, path: "/stepup/passkey/begin", doc: "Starts the passkey assertion that steps up the current session.", success: http.StatusOK, class: ClassSession, response: typeOf[CeremonyResponse](), op: "StepUpPasskeyBegin", serve: serveStepUpPasskeyBegin},
	{name: "authStepUpPasskeyFinish", method: http.MethodPost, path: "/stepup/passkey/finish", doc: "Finishes the passkey assertion that steps up the current session.", success: http.StatusNoContent, class: ClassSession, cer: ceremonyAssertion, op: "StepUpPasskeyFinish", audit: auditStepUp, serve: serveStepUpPasskeyFinish},
	{name: "authStepUpCode", method: http.MethodPost, path: "/stepup/code", doc: "Steps up the current session with an authenticator app code.", success: http.StatusNoContent, class: ClassSession, request: typeOf[StepUpCodeRequest](), op: "StepUpCode", audit: auditStepUp, serve: serveStepUpCode},
	{name: "authPasswordSet", method: http.MethodPut, path: "/password", doc: "Sets or changes the account's password and answers any new recovery code.", success: http.StatusOK, class: ClassRecentAuth, request: typeOf[PasswordChangeRequest](), response: typeOf[RecoveryCodeIssuedResponse](), op: "SetPassword", audit: "password.set", serve: servePasswordSet},
	{name: "authPasswordRemove", method: http.MethodDelete, path: "/password", doc: "Removes the account's password.", success: http.StatusNoContent, class: ClassRecentAuth, request: typeOf[PasswordRemoveRequest](), op: "RemovePassword", audit: "password.remove", serve: servePasswordRemove},
	{name: "authTOTPBegin", method: http.MethodPost, path: "/totp/begin", doc: "Draws a new authenticator app secret for the account to enrol.", success: http.StatusOK, class: ClassRecentAuth, response: typeOf[TOTPBeginResponse](), op: "BeginTOTP", serve: serveTOTPBegin},
	{name: "authTOTPFinish", method: http.MethodPost, path: "/totp/finish", doc: "Enrols or replaces the account's authenticator app and answers any new recovery code.", success: http.StatusOK, class: ClassRecentAuth, request: typeOf[TOTPFinishRequest](), response: typeOf[RecoveryCodeIssuedResponse](), op: "FinishTOTP", serve: serveTOTPFinish},
	{name: "authRecoveryCodeRegenerate", method: http.MethodPost, path: "/recovery-code", doc: "Replaces the account's recovery code after a second-factor proof.", success: http.StatusOK, class: ClassRecentAuth, request: typeOf[SecondFactorProof](), cer: ceremonyAssertion, response: typeOf[RecoveryCodeResponse](), op: "RegenerateRecoveryCode", serve: serveRecoveryCodeRegenerate},
	{name: "authTOTPRemove", method: http.MethodDelete, path: "/totp", doc: "Removes the account's authenticator app.", success: http.StatusNoContent, class: ClassSession, request: typeOf[SecondFactorProof](), cer: ceremonyAssertion, op: "RemoveTOTP", serve: serveTOTPRemove},
	{name: "authPasskeys", method: http.MethodGet, path: "/passkeys", doc: "Lists the account's passkeys.", success: http.StatusOK, class: ClassSession, response: typeOf[PasskeyView](), array: true, op: "Passkeys", serve: servePasskeys},
	{name: "authPasskeyRegisterBegin", method: http.MethodPost, path: "/passkeys/begin", doc: "Starts registering a new passkey on the account.", success: http.StatusOK, class: ClassRecentAuth, request: typeOf[SecondFactorProof](), cer: ceremonyAssertion, response: typeOf[CeremonyResponse](), op: "PasskeyRegisterBegin", serve: servePasskeyRegisterBegin},
	{name: "authPasskeyRegisterFinish", method: http.MethodPost, path: "/passkeys/finish", doc: "Finishes registering a passkey and answers it with any new recovery code.", success: http.StatusCreated, class: ClassRecentAuth, cer: ceremonyRegistration, response: typeOf[PasskeyRegisteredResponse](), op: "PasskeyRegisterFinish", serve: servePasskeyRegisterFinish},
	{name: "authPasskeyRename", method: http.MethodPut, path: "/passkeys/{id}", doc: "Renames one of the account's passkeys.", success: http.StatusNoContent, class: ClassSession, pathID: pathInt, request: typeOf[NameRequest](), op: "RenamePasskey", serve: servePasskeyRename},
	{name: "authPasskeyRemove", method: http.MethodDelete, path: "/passkeys/{id}", doc: "Removes one of the account's passkeys.", success: http.StatusNoContent, class: ClassRecentAuth, pathID: pathInt, request: typeOf[SecondFactorProof](), cer: ceremonyAssertion, op: "RemovePasskey", serve: servePasskeyRemove},
	{name: "authWebAuthnSignals", method: http.MethodGet, path: "/webauthn/signals", doc: "Answers the passkeys and user details the browser's WebAuthn signal calls report.", success: http.StatusOK, class: ClassSession, response: typeOf[webauthn.Signals](), op: "WebAuthnSignals", serve: serveWebAuthnSignals},
	{name: "authSessions", method: http.MethodGet, path: "/sessions", doc: "Lists the account's sessions.", success: http.StatusOK, class: ClassSession, response: typeOf[SessionView](), array: true, op: "Sessions", serve: serveSessions},
	{name: "authSessionRename", method: http.MethodPut, path: "/sessions/{id}", doc: "Renames one of the account's sessions.", success: http.StatusNoContent, class: ClassSession, pathID: pathSession, request: typeOf[NameRequest](), op: "RenameSession", serve: serveSessionRename},
	{name: "authSessionRevoke", method: http.MethodDelete, path: "/sessions/{id}", doc: "Ends one of the account's sessions.", success: http.StatusNoContent, class: ClassSession, pathID: pathSession, op: "RevokeSession", serve: serveSessionRevoke},
	{name: "authSessionsRevokeOthers", method: http.MethodPost, path: "/sessions/revoke-others", doc: "Ends every session of the account but the current one.", success: http.StatusNoContent, class: ClassRecentAuth, op: "RevokeOtherSessions", serve: serveSessionsRevokeOthers},
	{name: "authKeys", method: http.MethodGet, path: "/apikeys", doc: "Lists the account's API keys.", success: http.StatusOK, scope: scopeOwnKeys, response: typeOf[KeyView](), array: true, op: "APIKeys", serve: serveKeys},
	{name: "authKeyCreate", method: http.MethodPost, path: "/apikeys", doc: "Creates an API key and answers its secret once.", success: http.StatusCreated, scope: scopeKeys, request: typeOf[NewKeyRequest](), response: typeOf[KeyCreatedResponse](), op: "CreateAPIKey", serve: serveKeyCreate},
	{name: "authKeyRename", method: http.MethodPut, path: "/apikeys/{id}", doc: "Renames one of the account's API keys.", success: http.StatusNoContent, scope: scopeOwnKeys, pathID: pathInt, request: typeOf[NameRequest](), op: "RenameAPIKey", serve: serveKeyRename},
	{name: "authKeyRotate", method: http.MethodPost, path: "/apikeys/{id}/rotate", doc: "Replaces an API key's secret and answers the new one once.", success: http.StatusOK, class: ClassRecentAuth, pathID: pathInt, response: typeOf[KeyCreatedResponse](), op: "RotateAPIKey", serve: serveKeyRotate},
	{name: "authKeyRevoke", method: http.MethodDelete, path: "/apikeys/{id}", doc: "Revokes one of the account's API keys.", success: http.StatusNoContent, scope: scopeOwnKeys, pathID: pathInt, op: "RevokeAPIKey", serve: serveKeyRevoke},
	{name: "authAdminUsers", method: http.MethodGet, path: "/users", doc: "Lists the app's accounts with their sign-in methods.", success: http.StatusOK, scope: scopeAdmin, query: typeOf[AdminUsersQuery](), response: typeOf[UserView](), array: true, op: "Users", serve: serveAdminUsers},
	{name: "authAdminUserCreate", method: http.MethodPost, path: "/users", doc: "Creates an account.", success: http.StatusCreated, scope: scopeUsers, request: typeOf[NewUserRequest](), response: typeOf[UserView](), op: "CreateUser", serve: serveAdminUserCreate},
	{name: "authAdminUserUpdate", method: http.MethodPut, path: "/users/{id}", doc: "Changes an account's role or whether it is enabled.", success: http.StatusOK, scope: scopeUsers, pathID: pathInt, request: typeOf[UserUpdateRequest](), response: typeOf[UserView](), op: "UpdateUser", serve: serveAdminUserUpdate},
	{name: "authAdminOwner", method: http.MethodPut, path: "/users/{id}/owner", doc: "Makes an account an owner or removes its owner flag.", success: http.StatusOK, class: ClassRecentAuth, pathID: pathInt, request: typeOf[OwnerRequest](), response: typeOf[UserView](), op: "SetOwner", serve: serveAdminOwner},
	{name: "authAdminSSOReadiness", method: http.MethodGet, path: "/sso/readiness", doc: "Answers what applying a single sign-on mode would change, or why it is refused.", success: http.StatusOK, scope: scopeAdmin, query: typeOf[SSOReadinessQuery](), response: typeOf[Readiness](), op: "SSOReadiness", serve: serveAdminSSOReadiness},
	{name: "authAdminSSOApply", method: http.MethodPut, path: "/sso", doc: "Applies a single sign-on mode to the app.", success: http.StatusNoContent, class: ClassRecentAuth, request: typeOf[SSORequest](), op: "ApplySSO", serve: serveAdminSSOApply},
	{name: "authAdminUserDelete", method: http.MethodDelete, path: "/users/{id}", doc: "Deletes an account.", success: http.StatusNoContent, scope: scopeUsers, pathID: pathInt, op: "DeleteUser", serve: serveAdminUserDelete},
	{name: "authAdminOIDCUnlink", method: http.MethodDelete, path: "/users/{id}/oidc", doc: "Unlinks an account's single sign-on identity.", success: http.StatusNoContent, scope: scopeUsers, pathID: pathInt, op: "AdminUnlinkOIDC", serve: serveAdminOIDCUnlink},
	{name: "authAdminOIDCRelink", method: http.MethodPost, path: "/users/{id}/oidc/relink", doc: "Unlinks an account's single sign-on identity, issues it a temporary password and answers it once.", success: http.StatusOK, scope: scopeUsers, pathID: pathInt, request: typeOf[TemporaryPasswordOptions](), response: typeOf[TemporaryPasswordResponse](), op: "AdminRelinkOIDC", serve: serveAdminOIDCRelink},
	{name: "authAdminTemporaryPassword", method: http.MethodPost, path: "/users/{id}/temporary-password", doc: "Issues an account a temporary password and answers it once.", success: http.StatusOK, scope: scopeUsers, pathID: pathInt, request: typeOf[TemporaryPasswordOptions](), response: typeOf[TemporaryPasswordResponse](), op: "SetTemporaryPassword", serve: serveAdminTemporaryPassword},
	{name: "authAdminSecondFactorReset", method: http.MethodDelete, path: "/users/{id}/second-factor", doc: "Deletes an account's authenticator app and recovery code and ends its sessions.", success: http.StatusNoContent, scope: scopeUsers, pathID: pathInt, op: "ResetSecondFactor", serve: serveAdminSecondFactorReset},
	{name: "authAdminInvite", method: http.MethodPost, path: "/invites", doc: "Creates an invite and answers its token once.", success: http.StatusCreated, scope: scopeUsers, request: typeOf[InviteRequest](), response: typeOf[TokenResponse](), op: "CreateInvite", serve: serveAdminInvite},
	{name: "authAdminKeys", method: http.MethodGet, path: "/admin/apikeys", doc: "Lists every account's API keys.", success: http.StatusOK, scope: scopeAdmin, response: typeOf[KeyView](), array: true, op: "AllAPIKeys", serve: serveAdminKeys},
	{name: "authAdminKeyRevoke", method: http.MethodDelete, path: "/admin/apikeys/{id}", doc: "Revokes any account's API key.", success: http.StatusNoContent, scope: scopeAdmin, pathID: pathInt, op: "RevokeAnyAPIKey", serve: serveAdminKeyRevoke},
	{name: "authAdminTokens", method: http.MethodGet, path: "/tokens", doc: "Lists the unspent one-time tokens, such as invites.", success: http.StatusOK, scope: scopeAdmin, response: typeOf[TokenView](), array: true, op: "Tokens", serve: serveAdminTokens},
	{name: "authAdminSecurityLog", method: http.MethodGet, path: "/security-log", doc: "Answers a page of the security log.", success: http.StatusOK, scope: scopeAdmin, query: typeOf[AdminSecurityLogQuery](), response: typeOf[SecurityLogView](), op: "SecurityLog", serve: serveAdminSecurityLog},
}

// The reasons each of these codes carries wherever it is answered, read
// from the lists their owners publish.
var (
	originReasons   = reasonStrings(webauthn.OriginRejections())
	usernameReasons = account.UsernameReasons()
	// passwordReasons is a chosen password's refusals; only the password
	// replacing a temporary one is also refused as that temporary password.
	passwordReasons = []string{
		string(access.PasswordTooShort), string(access.PasswordTooLong), string(access.PasswordContainsUsername),
		string(access.PasswordContainsForbiddenWord), string(access.PasswordCommon), string(access.PasswordBreached),
	}
)

func reasonStrings[R ~string](rs []R) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

// opAnswers is the codes each account operation's errors map to, with
// their reasons, the third part of a route's answers; the class guard and
// the transport add theirs. An operation that rereads its caller's session
// or user answers ErrSessionGone, which maps to CodeSessionExpired.
var opAnswers = map[string]answers{
	"State": none(access.CodeUnavailable),
	"SetupWithPassword": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeBreachCheckUnavailable, access.CodeSetupComplete, access.CodeSetupTokenRequired, access.CodeTokenInvalid).
		open(access.CodeForbidden, ReasonNoUsableMethod).
		with(access.CodeUsernameInvalid, usernameReasons...).
		with(access.CodePasswordRejected, passwordReasons...),
	"SetupPasskeyBegin": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeSetupComplete, access.CodeSetupTokenRequired, access.CodeTokenInvalid, access.CodePasskeysUnavailable).
		with(access.CodeUsernameInvalid, usernameReasons...).
		with(access.CodeOriginRefused, originReasons...),
	"SetupPasskeyFinish": none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodeSetupComplete, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeNotDiscoverable, access.CodeRegistrationFailed).
		open(access.CodeForbidden),
	"PasswordLogin": none(access.CodeInvalidCredentials, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable).
		with(access.CodeHTTPSRequired, "", ReasonTemporaryPasswordExposed).
		with(access.CodeForbidden, ReasonNoUsableMethod).
		with(access.CodeUsernameInvalid, usernameReasons...).
		with(access.CodeSecondFactorRequired, ReasonEnrolNeedsKnownDevice),
	"SignInWithCode": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled).
		open(access.CodeBadRequest).
		with(access.CodeCodeInvalid, account.ReasonCodeInvalid, account.ReasonCodeReused, account.ReasonMethodLocked),
	"SecondFactorPasskeyBegin": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable).
		with(access.CodeOriginRefused, originReasons...),
	"SecondFactorPasskeyFinish": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeUnknownCredential, access.CodeAssertionFailed),
	"SignInWithRecoveryCode": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeTokenInvalid).
		with(access.CodeForbidden, ReasonNoUsableMethod).
		open(access.CodeBadRequest).
		with(access.CodeCodeInvalid, account.ReasonCodeInvalid, account.ReasonMethodLocked),
	"SetCredentialPassword": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasswordLoginDisabled, access.CodeBreachCheckUnavailable).
		with(access.CodeForbidden, ReasonNoUsableMethod).
		with(access.CodePasswordRejected, slices.Concat(passwordReasons, []string{string(access.PasswordIsTemporary)})...),
	"SetCredentialPasskeyBegin": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable).
		with(access.CodeOriginRefused, originReasons...),
	"SetCredentialPasskeyFinish": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeNotDiscoverable, access.CodeRegistrationFailed, access.CodeDuplicateCredential),
	"PendingTOTPBegin":           none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodeTOTPDisabled),
	"PendingTOTPFinish": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeTokenInvalid, access.CodeTOTPDisabled, access.CodeSetupComplete, access.CodeUsernameTaken, access.CodeSSOOnly, access.CodeRegistrationClosed, access.CodeRegistrationFull).
		open(access.CodeForbidden, account.ReasonSingleOwner).
		open(access.CodeBadRequest).
		with(access.CodeCodeInvalid, account.ReasonCodeInvalid),
	"PendingPasskeyBegin": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable).
		with(access.CodeOriginRefused, originReasons...),
	"PendingPasskeyFinish": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeTokenInvalid, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeNotDiscoverable, access.CodeRegistrationFailed, access.CodeDuplicateCredential, access.CodeSetupComplete, access.CodeUsernameTaken, access.CodeSSOOnly, access.CodeRegistrationClosed, access.CodeRegistrationFull).
		open(access.CodeForbidden, account.ReasonSingleOwner),
	"RegisterPassword": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeUsernameTaken, access.CodeBreachCheckUnavailable, access.CodeSSOOnly, access.CodeRegistrationClosed, access.CodeRegistrationFull).
		open(access.CodeForbidden, ReasonNoUsableMethod).
		with(access.CodeUsernameInvalid, usernameReasons...).
		with(access.CodePasswordRejected, passwordReasons...),
	"RegisterPasskeyBegin": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodePasskeysUnavailable, access.CodeSSOOnly, access.CodeRegistrationClosed, access.CodeRegistrationFull).
		open(access.CodeForbidden).
		with(access.CodeUsernameInvalid, usernameReasons...).
		with(access.CodeOriginRefused, originReasons...),
	"RegisterPasskeyFinish": none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodeUsernameTaken, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeNotDiscoverable, access.CodeRegistrationFailed, access.CodeSSOOnly, access.CodeRegistrationClosed, access.CodeRegistrationFull).
		open(access.CodeForbidden),
	"StepUpCode": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled, access.CodeSSOOnly).
		with(access.CodeSessionExpired, ReasonSessionGone).
		open(access.CodeBadRequest).
		with(access.CodeCodeInvalid, account.ReasonCodeInvalid, account.ReasonCodeReused, account.ReasonMethodLocked),
	"BeginTOTP": none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodeTOTPDisabled, access.CodeSSOOnly).
		with(access.CodeSessionExpired, ReasonSessionGone).
		with(access.CodeForbidden, ReasonTOTPNeedsPassword),
	"FinishTOTP": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeTokenInvalid, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled, access.CodeSSOOnly).
		with(access.CodeSessionExpired, ReasonSessionGone).
		with(access.CodeForbidden, ReasonTOTPNeedsPassword).
		open(access.CodeBadRequest, ReasonSecondFactorProofRequired).
		with(access.CodeCodeInvalid, account.ReasonCodeInvalid, account.ReasonCodeReused, account.ReasonMethodLocked, account.ReasonCurrentCodeInvalid),
	"RegenerateRecoveryCode": none(access.CodeHTTPSRequired, access.CodeSSOOnly, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeCeremonyInvalid, access.CodeAssertionFailed, access.CodeUnknownCredential, access.CodePasskeysUnavailable, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled, access.CodeNotFound).
		with(access.CodeSessionExpired, ReasonSessionGone).
		open(access.CodeBadRequest, ReasonSecondFactorProofRequired).
		with(access.CodeCodeInvalid, account.ReasonCodeInvalid, account.ReasonCodeReused, account.ReasonMethodLocked),
	"RemoveTOTP": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeCeremonyInvalid, access.CodeAssertionFailed, access.CodeUnknownCredential, access.CodePasskeysUnavailable, access.CodeSecondFactorUnavailable, access.CodeNotFound).
		with(access.CodeSessionExpired, ReasonSessionGone).
		with(access.CodeRecentAuthRequired, "", access.ReasonSignInAgain).
		open(access.CodeBadRequest, ReasonSecondFactorProofRequired).
		with(access.CodeCodeInvalid, account.ReasonCodeInvalid, account.ReasonCodeReused, account.ReasonMethodLocked).
		with(access.CodeLastMethod, ReasonLastSecondFactor),
	"PasskeyLoginBegin": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodePasskeysUnavailable).
		with(access.CodeOriginRefused, originReasons...),
	"PasskeyLoginFinish": none(access.CodeHTTPSRequired, access.CodeInvalidCredentials, access.CodeUnavailable, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeUnknownCredential, access.CodeAssertionFailed),
	"Logout":             none(access.CodeUnavailable),
	"AcceptInvitePassword": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeUsernameTaken, access.CodeBreachCheckUnavailable, access.CodeTokenInvalid, access.CodeSSOOnly).
		open(access.CodeForbidden, ReasonNoUsableMethod, account.ReasonSingleOwner).
		with(access.CodeUsernameInvalid, usernameReasons...).
		with(access.CodePasswordRejected, passwordReasons...),
	"AdmitOIDC": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeOIDCUnavailable),
	"AcceptInviteOIDCBegin": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodeOIDCUnavailable).
		open(access.CodeForbidden, account.ReasonSingleOwner),
	opOIDCBegin: none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodeCrossOrigin, access.CodeOIDCUnavailable).
		with(access.CodeBadRequest, ReasonRedirectTooLong),
	"OIDCComplete": none(access.CodeHTTPSRequired, access.CodeInvalidCredentials, access.CodeRecentAuthRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeTokenInvalid, access.CodeIdentityTaken, access.CodeAlreadyLinked, access.CodeOIDCUnavailable).
		with(access.CodeSessionExpired, ReasonSessionGone).
		open(access.CodeForbidden, ReasonNotAdmitted, account.ReasonSingleOwner).
		open(access.CodeOIDCFailed, ReasonExchangeFailed, ReasonFlowInvalid, ReasonNonceMismatch, ReasonPendingTooLarge, ReasonStaleAuthentication, ReasonTokenInvalid),
	"CreatePendingOIDC": none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeUsernameTaken, access.CodeTokenInvalid, access.CodeIdentityTaken, access.CodeOIDCUnavailable, access.CodeNotFound).
		open(access.CodeForbidden, ReasonProvisioningDisabled, account.ReasonSingleOwner).
		with(access.CodeUsernameInvalid, usernameReasons...),
	"LinkPendingOIDCByAdmin": none(access.CodeHTTPSRequired, access.CodeInvalidCredentials, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeIdentityTaken, access.CodeAlreadyLinked, access.CodeOIDCUnavailable, access.CodeNotFound),
	"OIDCPending":            none(access.CodeHTTPSRequired, access.CodeRateLimited, access.CodeUnavailable, access.CodeOIDCUnavailable, access.CodeNotFound),
	"LinkPendingOIDC": none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodeIdentityTaken, access.CodeAlreadyLinked, access.CodeOIDCUnavailable, access.CodeNotFound).
		with(access.CodeSessionExpired, ReasonSessionGone),
	"UnlinkOIDC": none(access.CodeUnavailable, access.CodeLastMethod, access.CodeNotFound).
		with(access.CodeSessionExpired, ReasonSessionGone),
	"StepUpPassword": none(access.CodeHTTPSRequired, access.CodeInvalidCredentials, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodePasswordLoginDisabled, access.CodeSSOOnly).
		with(access.CodeSessionExpired, ReasonSessionGone).
		with(access.CodeSecondFactorRequired, ReasonSecondFactorHeld),
	"SetPassword": none(access.CodeInvalidCredentials, access.CodeSSOOnly, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeBreachCheckUnavailable).
		with(access.CodeBadRequest, ReasonCurrentPasswordRequired).
		with(access.CodePasswordRejected, passwordReasons...).
		with(access.CodeSessionExpired, ReasonSessionGone),
	"RemovePassword": none(access.CodeHTTPSRequired, access.CodeInvalidCredentials, access.CodeRateLimited, access.CodeBusy, access.CodeUnavailable, access.CodeLastMethod, access.CodeNotFound).
		with(access.CodeBadRequest, ReasonCurrentPasswordRequired).
		with(access.CodeSessionExpired, ReasonSessionGone),
	"Me": none(access.CodeUnavailable).
		with(access.CodeSessionExpired, ReasonSessionGone),
	"UpdateProfile": none(access.CodeUnavailable).
		with(access.CodeSessionExpired, ReasonSessionGone).
		with(access.CodeBadRequest, textReason(account.TextFieldDisplayName, account.ReasonDisallowedCharacter), textReason(account.TextFieldDisplayName, account.ReasonTooLong)),
	"ReenableMethod": none(access.CodeUnavailable, access.CodeMethodNotLocked).
		with(access.CodeRecentAuthRequired, "", ReasonReenableNeedsOtherMethod, access.ReasonSignInAgain),
	"StepUpPasskeyBegin": none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodePasskeysUnavailable, access.CodeNotFound, access.CodeSSOOnly).
		with(access.CodeSessionExpired, ReasonSessionGone).
		with(access.CodeOriginRefused, originReasons...),
	"StepUpPasskeyFinish": none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeUnknownCredential, access.CodeAssertionFailed, access.CodeSSOOnly).
		with(access.CodeSessionExpired, ReasonSessionGone),
	"Passkeys": none(access.CodeUnavailable).
		with(access.CodeSessionExpired, ReasonSessionGone),
	"PasskeyRegisterBegin": none(access.CodeHTTPSRequired, access.CodeSSOOnly, access.CodeUnavailable, access.CodePasskeysUnavailable, access.CodeRateLimited, access.CodeCeremonyInvalid, access.CodeAssertionFailed, access.CodeUnknownCredential, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled).
		with(access.CodeSessionExpired, ReasonSessionGone).
		with(access.CodeOriginRefused, originReasons...).
		open(access.CodeBadRequest, ReasonSecondFactorProofRequired).
		with(access.CodeCodeInvalid, account.ReasonCodeInvalid, account.ReasonCodeReused, account.ReasonMethodLocked),
	"PasskeyRegisterFinish": none(access.CodeHTTPSRequired, access.CodeSSOOnly, access.CodeBusy, access.CodeUnavailable, access.CodeDuplicateCredential, access.CodePasskeysUnavailable, access.CodeCeremonyInvalid, access.CodeNotDiscoverable, access.CodeRegistrationFailed).
		with(access.CodeSessionExpired, ReasonSessionGone),
	"RenamePasskey": none(access.CodeUnavailable, access.CodeNotFound).
		with(access.CodeBadRequest, textReason(account.TextFieldLabel, account.ReasonDisallowedCharacter), textReason(account.TextFieldLabel, account.ReasonTooLong)),
	"RemovePasskey": none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodeNotFound, access.CodeRateLimited, access.CodeCeremonyInvalid, access.CodeAssertionFailed, access.CodeUnknownCredential, access.CodePasskeysUnavailable, access.CodeSecondFactorUnavailable, access.CodeTOTPDisabled).
		with(access.CodeSessionExpired, ReasonSessionGone).
		with(access.CodeLastMethod, "", ReasonLastSecondFactor).
		open(access.CodeBadRequest, ReasonSecondFactorProofRequired).
		with(access.CodeCodeInvalid, account.ReasonCodeInvalid, account.ReasonCodeReused, account.ReasonMethodLocked),
	"WebAuthnSignals": none(access.CodeUnavailable, access.CodePasskeysUnavailable).
		with(access.CodeSessionExpired, ReasonSessionGone),
	"Sessions": none(access.CodeUnavailable),
	"RenameSession": none(access.CodeUnavailable, access.CodeNotFound).
		with(access.CodeBadRequest, textReason(account.TextFieldLabel, account.ReasonDisallowedCharacter), textReason(account.TextFieldLabel, account.ReasonTooLong)),
	"RevokeSession":       none(access.CodeUnavailable, access.CodeNotFound),
	"RevokeOtherSessions": none(access.CodeUnavailable),
	"APIKeys": none(access.CodeUnavailable).
		open(access.CodeForbidden, account.ReasonKeyNotCurrent),
	"CreateAPIKey": none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodeUnknownScope, access.CodeKeyLabelTaken).
		with(access.CodeSessionExpired, ReasonSessionGone).
		open(access.CodeForbidden, account.ReasonExpiryAfterParent, account.ReasonKeyNotCurrent, account.ReasonKeyRetiring, account.ReasonLineageTooDeep, account.ReasonOtherUser, account.ReasonPermissionNotAdmin, account.ReasonScopesNotSubset, account.ReasonTargetNotEligible).
		with(access.CodeBadRequest, ReasonExpiryInvalid, textReason(account.TextFieldLabel, account.ReasonDisallowedCharacter), textReason(account.TextFieldLabel, account.ReasonEmpty), textReason(account.TextFieldLabel, account.ReasonTooLong)),
	"RenameAPIKey": none(access.CodeUnavailable, access.CodeNotFound, access.CodeKeyLabelTaken).
		open(access.CodeForbidden, account.ReasonKeyNotCurrent).
		with(access.CodeBadRequest, textReason(account.TextFieldLabel, account.ReasonDisallowedCharacter), textReason(account.TextFieldLabel, account.ReasonEmpty), textReason(account.TextFieldLabel, account.ReasonTooLong)),
	"RotateAPIKey": none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodeNotFound).
		with(access.CodeSessionExpired, ReasonSessionGone).
		open(access.CodeForbidden, account.ReasonKeyExpired),
	"RevokeAPIKey": none(access.CodeUnavailable, access.CodeNotFound).
		open(access.CodeForbidden, account.ReasonKeyNotCurrent),
	"Users": none(access.CodeUnavailable).
		open(access.CodeForbidden),
	"CreateUser": none(access.CodeBusy, access.CodeUnavailable, access.CodeUsernameTaken, access.CodeBreachCheckUnavailable).
		open(access.CodeForbidden, account.ReasonAdminTarget, account.ReasonKeyNotCurrent, account.ReasonKeyRetiring, account.ReasonSingleOwner).
		with(access.CodeUsernameInvalid, usernameReasons...).
		with(access.CodePasswordRejected, passwordReasons...),
	"UpdateUser": none(access.CodeUnavailable, access.CodeNotFound).
		open(access.CodeForbidden, account.ReasonAdminTarget, account.ReasonKeyNotCurrent, account.ReasonKeyRetiring, account.ReasonLastOwner, account.ReasonOwnerRole, account.ReasonOwnerTarget, account.ReasonSingleOwner).
		with(access.CodeBadRequest, ReasonNoChange),
	"DeleteUser": none(access.CodeUnavailable, access.CodeNotFound).
		open(access.CodeForbidden, account.ReasonAdminTarget, account.ReasonKeyNotCurrent, account.ReasonLastOwner, account.ReasonOwnerTarget),
	"SetOwner": none(access.CodeUnavailable, access.CodeNotFound).
		open(access.CodeForbidden, account.ReasonLastOwner, account.ReasonOwnerNeedsLocalMethod, account.ReasonOwnerTarget),
	"AdminUnlinkOIDC": none(access.CodeUnavailable, access.CodeNotFound).
		open(access.CodeForbidden, account.ReasonAdminTarget, account.ReasonKeyNotCurrent, account.ReasonKeyRetiring, account.ReasonOwnerTarget),
	"AdminRelinkOIDC": none(access.CodeHTTPSRequired, access.CodeBusy, access.CodeUnavailable, access.CodeNotFound).
		open(access.CodeForbidden, account.ReasonAdminTarget, account.ReasonKeyNotCurrent, account.ReasonKeyRetiring, account.ReasonOwnerTarget, account.ReasonSelfRecovery).
		with(access.CodeBadRequest, ReasonTTLNegative, ReasonTTLTooLong),
	"SetTemporaryPassword": none(access.CodeHTTPSRequired, access.CodeBusy, access.CodeUnavailable, access.CodeNotFound).
		open(access.CodeForbidden, account.ReasonAdminTarget, account.ReasonKeyNotCurrent, account.ReasonKeyRetiring, account.ReasonOwnerTarget, account.ReasonSelfRecovery).
		with(access.CodeBadRequest, ReasonTTLNegative, ReasonTTLTooLong).
		with(access.CodeSSOOnly, ReasonLinked),
	"ResetSecondFactor": none(access.CodeUnavailable, access.CodeNotFound).
		open(access.CodeForbidden, account.ReasonAdminTarget, account.ReasonKeyNotCurrent, account.ReasonKeyRetiring, account.ReasonOwnerTarget, account.ReasonSelfRecovery),
	"SSOReadiness": none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodeOIDCUnavailable).
		open(access.CodeForbidden, account.ReasonKeyNotCurrent).
		with(access.CodeBadRequest, ""),
	"ApplySSO": none(access.CodeHTTPSRequired, access.CodeUnavailable, access.CodeOIDCUnavailable).
		with(access.CodeForbidden, account.ReasonNotOwner, account.ReasonOwnerNeedsLocalMethod, account.ReasonRegistrationEnabled, account.ReasonSingleOwner).
		with(access.CodeBadRequest, ""),
	"CreateInvite": none(access.CodeHTTPSRequired, access.CodeUnavailable).
		open(access.CodeForbidden, account.ReasonAdminTarget, account.ReasonKeyNotCurrent, account.ReasonKeyRetiring, account.ReasonSingleOwner).
		with(access.CodeBadRequest, ReasonTTLNegative, ReasonTTLTooLong),
	"AllAPIKeys": none(access.CodeUnavailable).
		open(access.CodeForbidden, account.ReasonKeyNotCurrent),
	"RevokeAnyAPIKey": none(access.CodeUnavailable, access.CodeNotFound).
		open(access.CodeForbidden, account.ReasonKeyNotCurrent),
	"Tokens": none(access.CodeUnavailable).
		open(access.CodeForbidden),
	"SecurityLog": none(access.CodeUnavailable).
		open(access.CodeForbidden).
		with(access.CodeBadRequest, account.ReasonLogID, account.ReasonLogKind, account.ReasonLogLimit, account.ReasonLogRange),
}

// guardAnswers is what a class's guard can answer: the Authenticator's
// refusals on every class that authenticates, auth_https_required among
// them since a descriptor does not know the posture, then the class
// predicate's. A key class has a scope set (classFor), so a non-key
// principal there is refused for the scope, never for want of a session.
func guardAnswers(c Class) answers {
	if c == ClassPublic {
		return nil
	}
	as := none(access.CodeAuthRequired, access.CodeInvalidCredentials, access.CodeKeyInvalid, access.CodeUnavailable, access.CodeHTTPSRequired).
		with(access.CodeSessionExpired, "", access.ReasonTransportChanged)
	switch c {
	case ClassSession:
		as = append(as, none(access.CodeSessionRequired)...)
	case ClassRecentAuth:
		as = append(as, none(access.CodeSessionRequired)...).with(access.CodeRecentAuthRequired, "", access.ReasonSignInAgain)
	case ClassKeyScope:
		as = append(as, none(access.CodeScopeRequired)...)
	case ClassKeyPermission:
		as = append(as, none(access.CodeScopeRequired)...).with(access.CodeRecentAuthRequired, "", access.ReasonSignInAgain)
	default:
	}
	return as
}

// transportAnswers is what the transport can answer before or around the
// operation: method, origin, body, path, query and limiter refusals.
func (s *routeSpec) transportAnswers() answers {
	as := none(access.CodeMethodNotAllowed)
	if s.method != http.MethodGet {
		as = append(as, none(access.CodeCrossOrigin)...)
	}
	var refused []string // the body's own refusals; the decode of s.request also names fields
	if s.request != nil || s.cer != ceremonyNone {
		as = append(as, none(access.CodeBodyTooLarge)...)
		refused = append(refused, ReasonContentType, ReasonBody)
	}
	if s.request != nil {
		refused = append(refused, ReasonMalformedJSON, ReasonTrailingData, ReasonUnknownField)
	}
	if s.tokenBody {
		refused = append(refused, ReasonTokenInQuery)
	}
	switch {
	case s.request != nil || s.pathID != pathNone || (s.query != nil && !s.redirect):
		as = as.open(access.CodeBadRequest, refused...)
	case len(refused) > 0:
		as = as.with(access.CodeBadRequest, refused...)
	}
	if s.limited {
		as = append(as, none(access.CodeRateLimited)...)
	}
	return as
}

// classFor resolves a spec's class and scope against dc's scopes.
func (s *routeSpec) classFor(dc *DescriptorConfig) (class Class, scope string) {
	switch s.scope {
	case scopeAdmin:
		return keyScope(dc.AdminScope)
	case scopeOwnKeys:
		return keyScope(dc.CreateKeysScope)
	case scopeUsers:
		return permission(dc.ManageUsersScope)
	case scopeKeys:
		return permission(dc.CreateKeysScope)
	default:
		return s.class, ""
	}
}

func keyScope(scope string) (class Class, required string) {
	if scope != "" {
		return ClassKeyScope, scope
	}
	return ClassSession, ""
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

// answers is every code the route can answer under class, with its
// reasons: its guard's, its transport's and its operation's.
func (s *routeSpec) answers(class Class) answers {
	return slices.Concat(guardAnswers(class), s.transportAnswers(), opAnswers[s.op])
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
		Codes:    s.answers(class).codes(),
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
