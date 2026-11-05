package accesshttp

import (
	"net/http"
	"reflect"
	"slices"

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
	// ClassKeyPermission: a key carrying Scope, or a full session under
	// recent auth (account.Service.RequireKeyPermission).
	ClassKeyPermission Class = "key_permission"
	ClassRecovery      Class = "recovery" // the restricted recovery session only
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
	Doc      string
	// Codes is every code this route can answer, in Codes() order: its
	// class guard's, its transport's and its account operation's.
	Codes   []Code
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

// routeSpec is one route's static facts; descriptors derives each
// Descriptor from it and the Account's scopes.
type routeSpec struct {
	request, query, response reflect.Type
	serve                    serveFunc
	name, method, path, doc  string
	op                       string // the account operation, a key of opCodes
	audit                    string // the AuditEvent kind prefix; "" audits nothing
	class                    Class
	scope                    scopeRule
	pathID                   pathID
	cer                      ceremony // a WebAuthn finish: the body is a credential
	oidc                     bool     // Path is under OIDCPrefix
	passive, redirect, array bool
	tokenBody                bool // a token is accepted only in the body
	limited                  bool // accesshttp itself calls Limiter.Request
}

// Names more than one spec shares, and the sign-in start's, which the query
// decode names too.
const (
	auditSetup           = "setup"
	opOIDCBegin          = "OIDCBegin"
	routeOIDCStartSignIn = "authOIDCStartSignIn"
)

func typeOf[T any]() reflect.Type { return reflect.TypeFor[T]() }

// specs is every route, in Routes order.
var specs = []routeSpec{
	{name: "authState", method: http.MethodGet, path: "/state", class: ClassPublic, passive: true, response: typeOf[StateResponse](), op: "State", serve: serveState},
	{name: "authSetupPassword", method: http.MethodPost, path: "/setup/password", class: ClassPublic, request: typeOf[SetupPasswordRequest](), response: typeOf[SignedInResponse](), tokenBody: true, op: "SetupWithPassword", audit: auditSetup, serve: serveSetupPassword},
	{name: "authSetupPasskeyBegin", method: http.MethodPost, path: "/setup/passkey/begin", class: ClassPublic, request: typeOf[SetupPasskeyBeginRequest](), response: typeOf[CeremonyResponse](), tokenBody: true, op: "SetupPasskeyBegin", audit: auditSetup, serve: serveSetupPasskeyBegin},
	{name: "authSetupPasskeyFinish", method: http.MethodPost, path: "/setup/passkey/finish", class: ClassPublic, cer: ceremonyRegistration, response: typeOf[SignedInResponse](), op: "SetupPasskeyFinish", audit: auditSetup, serve: serveSetupPasskeyFinish},
	{name: "authLoginPassword", method: http.MethodPost, path: "/login/password", class: ClassPublic, request: typeOf[LoginRequest](), response: typeOf[SignedInResponse](), op: "PasswordLogin", audit: "login", serve: serveLoginPassword},
	{name: "authLoginPasskeyBegin", method: http.MethodPost, path: "/login/passkey/begin", class: ClassPublic, query: typeOf[PasskeyBeginQuery](), response: typeOf[CeremonyResponse](), op: "PasskeyLoginBegin", serve: serveLoginPasskeyBegin},
	{name: "authLoginPasskeyFinish", method: http.MethodPost, path: "/login/passkey/finish", class: ClassPublic, cer: ceremonyAssertion, response: typeOf[SignedInResponse](), op: "PasskeyLoginFinish", audit: "login", serve: serveLoginPasskeyFinish},
	{name: "authLogout", method: http.MethodPost, path: "/logout", class: ClassPublic, op: "Logout", serve: serveLogout},
	{name: routeOIDCStartSignIn, method: http.MethodGet, path: "/start/signin", oidc: true, class: ClassPublic, redirect: true, query: typeOf[OIDCSignInQuery](), limited: true, op: "AdmitOIDC", audit: "oidc.start", serve: serveOIDCStartSignIn},
	{name: "authOIDCStartLink", method: http.MethodPost, path: "/start/link", oidc: true, class: ClassRecentAuth, request: typeOf[RedirectRequest](), response: typeOf[OIDCStartResponse](), op: opOIDCBegin, serve: serveOIDCStartLink},
	{name: "authOIDCStartStepUp", method: http.MethodPost, path: "/start/stepup", oidc: true, class: ClassSession, request: typeOf[RedirectRequest](), response: typeOf[OIDCStartResponse](), op: opOIDCBegin, serve: serveOIDCStartStepUp},
	{name: "authOIDCCallback", method: http.MethodGet, path: "/callback", oidc: true, class: ClassPublic, redirect: true, query: typeOf[OIDCCallbackQuery](), limited: true, op: "OIDCComplete", audit: "oidc.callback", serve: serveOIDCCallback},
	{name: "authOIDCPending", method: http.MethodGet, path: "/oidc/pending", class: ClassPublic, passive: true, response: typeOf[PendingLinkResponse](), op: "OIDCPending", serve: serveOIDCPending},
	{name: "authOIDCLinkPending", method: http.MethodPost, path: "/oidc/link", class: ClassRecentAuth, response: typeOf[MeResponse](), op: "LinkPendingOIDC", serve: serveOIDCLinkPending},
	{name: "authOIDCUnlink", method: http.MethodDelete, path: "/oidc/link", class: ClassRecentAuth, op: "UnlinkOIDC", serve: serveOIDCUnlink},
	{name: "authRecoveryStart", method: http.MethodPost, path: "/recovery", class: ClassPublic, request: typeOf[TokenRequest](), response: typeOf[RecoveryResponse](), tokenBody: true, op: "StartRecovery", audit: "recovery.start", serve: serveRecoveryStart},
	{name: "authRecoveryPassword", method: http.MethodPost, path: "/recovery/password", class: ClassRecovery, request: typeOf[RecoverPasswordRequest](), op: "RecoverWithPassword", audit: "recovery.complete", serve: serveRecoveryPassword},
	{name: "authRecoveryPasskeyBegin", method: http.MethodPost, path: "/recovery/passkey/begin", class: ClassRecovery, response: typeOf[CeremonyResponse](), op: "RecoverPasskeyBegin", serve: serveRecoveryPasskeyBegin},
	{name: "authRecoveryPasskeyFinish", method: http.MethodPost, path: "/recovery/passkey/finish", class: ClassRecovery, cer: ceremonyRegistration, query: typeOf[RecoveryPasskeyFinishQuery](), op: "RecoverPasskeyFinish", audit: "recovery.complete", serve: serveRecoveryPasskeyFinish},
	{name: "authInviteAcceptPassword", method: http.MethodPost, path: "/invite/password", class: ClassPublic, request: typeOf[InviteAcceptRequest](), response: typeOf[SignedInResponse](), tokenBody: true, op: "AcceptInvitePassword", audit: "invite.accept", serve: serveInviteAcceptPassword},
	{name: "authMe", method: http.MethodGet, path: "/me", class: ClassSession, passive: true, response: typeOf[MeResponse](), op: "Me", serve: serveMe},
	{name: "authProfile", method: http.MethodPut, path: "/profile", class: ClassSession, request: typeOf[ProfileRequest](), response: typeOf[MeResponse](), op: "UpdateProfile", serve: serveProfile},
	{name: "authMethodReenable", method: http.MethodPost, path: "/methods/{method}/reenable", class: ClassRecentAuth, pathID: pathMethod, op: "ReenableMethod", serve: serveMethodReenable},
	{name: "authStepUpPassword", method: http.MethodPost, path: "/stepup/password", class: ClassSession, request: typeOf[PasswordRequest](), op: "StepUpPassword", audit: "stepup", serve: serveStepUpPassword},
	{name: "authStepUpPasskeyBegin", method: http.MethodPost, path: "/stepup/passkey/begin", class: ClassSession, response: typeOf[CeremonyResponse](), op: "StepUpPasskeyBegin", serve: serveStepUpPasskeyBegin},
	{name: "authStepUpPasskeyFinish", method: http.MethodPost, path: "/stepup/passkey/finish", class: ClassSession, cer: ceremonyAssertion, op: "StepUpPasskeyFinish", audit: "stepup", serve: serveStepUpPasskeyFinish},
	{name: "authPasswordSet", method: http.MethodPut, path: "/password", class: ClassRecentAuth, request: typeOf[PasswordChangeRequest](), op: "SetPassword", audit: "password.set", serve: servePasswordSet},
	{name: "authPasswordRemove", method: http.MethodDelete, path: "/password", class: ClassRecentAuth, request: typeOf[PasswordRemoveRequest](), op: "RemovePassword", audit: "password.remove", serve: servePasswordRemove},
	{name: "authPasskeys", method: http.MethodGet, path: "/passkeys", class: ClassSession, response: typeOf[PasskeyView](), array: true, op: "Passkeys", serve: servePasskeys},
	{name: "authPasskeyRegisterBegin", method: http.MethodPost, path: "/passkeys/begin", class: ClassRecentAuth, response: typeOf[CeremonyResponse](), op: "PasskeyRegisterBegin", serve: servePasskeyRegisterBegin},
	{name: "authPasskeyRegisterFinish", method: http.MethodPost, path: "/passkeys/finish", class: ClassRecentAuth, cer: ceremonyRegistration, response: typeOf[PasskeyView](), op: "PasskeyRegisterFinish", serve: servePasskeyRegisterFinish},
	{name: "authPasskeyRename", method: http.MethodPut, path: "/passkeys/{id}", class: ClassSession, pathID: pathInt, request: typeOf[NameRequest](), op: "RenamePasskey", serve: servePasskeyRename},
	{name: "authPasskeyRemove", method: http.MethodDelete, path: "/passkeys/{id}", class: ClassRecentAuth, pathID: pathInt, op: "RemovePasskey", serve: servePasskeyRemove},
	{name: "authWebAuthnSignals", method: http.MethodGet, path: "/webauthn/signals", class: ClassSession, response: typeOf[webauthn.Signals](), op: "WebAuthnSignals", serve: serveWebAuthnSignals},
	{name: "authSessions", method: http.MethodGet, path: "/sessions", class: ClassSession, response: typeOf[SessionView](), array: true, op: "Sessions", serve: serveSessions},
	{name: "authSessionRename", method: http.MethodPut, path: "/sessions/{id}", class: ClassSession, pathID: pathSession, request: typeOf[NameRequest](), op: "RenameSession", serve: serveSessionRename},
	{name: "authSessionRevoke", method: http.MethodDelete, path: "/sessions/{id}", class: ClassSession, pathID: pathSession, op: "RevokeSession", serve: serveSessionRevoke},
	{name: "authSessionsRevokeOthers", method: http.MethodPost, path: "/sessions/revoke-others", class: ClassRecentAuth, op: "RevokeOtherSessions", serve: serveSessionsRevokeOthers},
	{name: "authKeys", method: http.MethodGet, path: "/apikeys", class: ClassSession, response: typeOf[KeyView](), array: true, op: "APIKeys", serve: serveKeys},
	{name: "authKeyCreate", method: http.MethodPost, path: "/apikeys", scope: scopeKeys, request: typeOf[NewKeyRequest](), response: typeOf[KeyCreatedResponse](), op: "CreateAPIKey", serve: serveKeyCreate},
	{name: "authKeyRevoke", method: http.MethodDelete, path: "/apikeys/{id}", class: ClassSession, pathID: pathInt, op: "RevokeAPIKey", serve: serveKeyRevoke},
	{name: "authAdminUsers", method: http.MethodGet, path: "/users", scope: scopeAdmin, query: typeOf[AdminUsersQuery](), response: typeOf[UserView](), array: true, op: "Users", serve: serveAdminUsers},
	{name: "authAdminUserCreate", method: http.MethodPost, path: "/users", scope: scopeUsers, request: typeOf[NewUserRequest](), response: typeOf[UserView](), op: "CreateUser", serve: serveAdminUserCreate},
	{name: "authAdminUserUpdate", method: http.MethodPut, path: "/users/{id}", scope: scopeUsers, pathID: pathInt, request: typeOf[UserUpdateRequest](), response: typeOf[UserView](), op: "UpdateUser", serve: serveAdminUserUpdate},
	{name: "authAdminUserDelete", method: http.MethodDelete, path: "/users/{id}", scope: scopeUsers, pathID: pathInt, op: "DeleteUser", serve: serveAdminUserDelete},
	{name: "authAdminRecovery", method: http.MethodPost, path: "/users/{id}/recovery", scope: scopeUsers, pathID: pathInt, request: typeOf[TTLRequest](), response: typeOf[TokenResponse](), op: "IssueRecovery", serve: serveAdminRecovery},
	{name: "authAdminInvite", method: http.MethodPost, path: "/invites", scope: scopeUsers, request: typeOf[InviteRequest](), response: typeOf[TokenResponse](), op: "CreateInvite", serve: serveAdminInvite},
	{name: "authAdminKeys", method: http.MethodGet, path: "/admin/apikeys", scope: scopeAdmin, response: typeOf[KeyView](), array: true, op: "AllAPIKeys", serve: serveAdminKeys},
	{name: "authAdminKeyRevoke", method: http.MethodDelete, path: "/admin/apikeys/{id}", scope: scopeAdmin, pathID: pathInt, op: "RevokeAnyAPIKey", serve: serveAdminKeyRevoke},
	{name: "authAdminTokens", method: http.MethodGet, path: "/tokens", scope: scopeAdmin, response: typeOf[TokenView](), array: true, op: "Tokens", serve: serveAdminTokens},
}

// opCodes is the codes each account operation's errors map to, the third
// part of a route's Codes; the class guard and the transport add theirs.
// An operation that rereads its caller's session or user answers
// ErrSessionGone, which maps to CodeSessionExpired.
var opCodes = map[string][]Code{
	"State":                 {CodeUnavailable},
	"SetupWithPassword":     {CodeForbidden, CodeRateLimited, CodeBusy, CodeUnavailable, CodeUsernameInvalid, CodePasswordRejected, CodeBreachCheckUnavailable, CodeSetupComplete, CodeSetupTokenRequired, CodeTokenInvalid},
	"SetupPasskeyBegin":     {CodeRateLimited, CodeUnavailable, CodeUsernameInvalid, CodeSetupComplete, CodeSetupTokenRequired, CodeTokenInvalid, CodePasskeysUnavailable, CodeOriginRefused},
	"SetupPasskeyFinish":    {CodeForbidden, CodeUnavailable, CodeSetupComplete, CodeTokenInvalid, CodePasskeysUnavailable, CodeCeremonyInvalid, CodeNotDiscoverable, CodeRegistrationFailed},
	"PasswordLogin":         {CodeInvalidCredentials, CodeRateLimited, CodeBusy, CodeUnavailable, CodeUsernameInvalid, CodePasswordLoginDisabled},
	"PasskeyLoginBegin":     {CodeRateLimited, CodeUnavailable, CodePasskeysUnavailable, CodeOriginRefused},
	"PasskeyLoginFinish":    {CodeInvalidCredentials, CodeUnavailable, CodePasskeysUnavailable, CodeCeremonyInvalid, CodeUnknownCredential, CodeAssertionFailed},
	"Logout":                {CodeUnavailable},
	"StartRecovery":         {CodeRateLimited, CodeUnavailable, CodeTokenInvalid},
	"RecoverWithPassword":   {CodeSessionExpired, CodeBusy, CodeUnavailable, CodePasswordRejected, CodeBreachCheckUnavailable, CodeTokenInvalid},
	"RecoverPasskeyBegin":   {CodeSessionExpired, CodeUnavailable, CodePasskeysUnavailable, CodeOriginRefused},
	"RecoverPasskeyFinish":  {CodeSessionExpired, CodeUnavailable, CodeTokenInvalid, CodeDuplicateCredential, CodePasskeysUnavailable, CodeCeremonyInvalid, CodeNotDiscoverable, CodeRegistrationFailed},
	"AcceptInvitePassword":  {CodeForbidden, CodeRateLimited, CodeBusy, CodeUnavailable, CodeUsernameInvalid, CodeUsernameTaken, CodePasswordRejected, CodeBreachCheckUnavailable, CodeTokenInvalid},
	"AdmitOIDC":             {CodeRateLimited, CodeUnavailable, CodeOIDCUnavailable},
	opOIDCBegin:             {CodeBadRequest, CodeCrossOrigin, CodeOIDCUnavailable},
	"OIDCComplete":          {CodeSessionExpired, CodeInvalidCredentials, CodeRecentAuthRequired, CodeForbidden, CodeRateLimited, CodeUnavailable, CodeIdentityTaken, CodeAlreadyLinked, CodeOIDCUnavailable, CodeOIDCFailed},
	"OIDCPending":           {CodeNotFound},
	"LinkPendingOIDC":       {CodeSessionExpired, CodeForbidden, CodeUnavailable, CodeIdentityTaken, CodeAlreadyLinked, CodeOIDCUnavailable, CodeNotFound},
	"UnlinkOIDC":            {CodeSessionExpired, CodeUnavailable, CodeLastMethod, CodeNotFound},
	"StepUpPassword":        {CodeInvalidCredentials, CodeRateLimited, CodeBusy, CodeUnavailable, CodePasswordLoginDisabled, CodeSessionExpired},
	"SetPassword":           {CodeInvalidCredentials, CodeForbidden, CodeRateLimited, CodeBusy, CodeUnavailable, CodeBadRequest, CodePasswordRejected, CodeBreachCheckUnavailable, CodeSessionExpired},
	"RemovePassword":        {CodeInvalidCredentials, CodeRateLimited, CodeBusy, CodeUnavailable, CodeBadRequest, CodeLastMethod, CodeNotFound, CodeSessionExpired},
	"Me":                    {CodeSessionExpired, CodeUnavailable},
	"UpdateProfile":         {CodeSessionExpired, CodeUnavailable, CodeBadRequest},
	"ReenableMethod":        {CodeRecentAuthRequired, CodeUnavailable, CodeMethodNotLocked},
	"StepUpPasskeyBegin":    {CodeSessionExpired, CodeUnavailable, CodePasskeysUnavailable, CodeOriginRefused, CodeNotFound},
	"StepUpPasskeyFinish":   {CodeSessionExpired, CodeUnavailable, CodePasskeysUnavailable, CodeCeremonyInvalid, CodeUnknownCredential, CodeAssertionFailed},
	"Passkeys":              {CodeUnavailable},
	"PasskeyRegisterBegin":  {CodeSessionExpired, CodeForbidden, CodeUnavailable, CodePasskeysUnavailable, CodeOriginRefused},
	"PasskeyRegisterFinish": {CodeSessionExpired, CodeForbidden, CodeUnavailable, CodeDuplicateCredential, CodePasskeysUnavailable, CodeCeremonyInvalid, CodeNotDiscoverable, CodeRegistrationFailed},
	"RenamePasskey":         {CodeUnavailable, CodeBadRequest, CodeNotFound},
	"RemovePasskey":         {CodeSessionExpired, CodeUnavailable, CodeLastMethod, CodeNotFound},
	"WebAuthnSignals":       {CodeSessionExpired, CodeUnavailable, CodePasskeysUnavailable},
	"Sessions":              {CodeUnavailable},
	"RenameSession":         {CodeUnavailable, CodeBadRequest, CodeNotFound},
	"RevokeSession":         {CodeUnavailable, CodeNotFound},
	"RevokeOtherSessions":   {CodeUnavailable},
	"APIKeys":               {CodeUnavailable},
	"CreateAPIKey":          {CodeSessionExpired, CodeForbidden, CodeUnavailable, CodeBadRequest, CodeUnknownScope},
	"RevokeAPIKey":          {CodeUnavailable, CodeNotFound},
	"Users":                 {CodeForbidden, CodeUnavailable},
	"CreateUser":            {CodeForbidden, CodeBusy, CodeUnavailable, CodeUsernameInvalid, CodeUsernameTaken, CodePasswordRejected, CodeBreachCheckUnavailable},
	"UpdateUser":            {CodeForbidden, CodeUnavailable, CodeBadRequest, CodeNotFound},
	"DeleteUser":            {CodeForbidden, CodeUnavailable, CodeNotFound},
	"IssueRecovery":         {CodeForbidden, CodeUnavailable, CodeBadRequest, CodeNotFound},
	"CreateInvite":          {CodeForbidden, CodeUnavailable, CodeBadRequest},
	"AllAPIKeys":            {CodeForbidden, CodeUnavailable},
	"RevokeAnyAPIKey":       {CodeForbidden, CodeUnavailable, CodeNotFound},
	"Tokens":                {CodeForbidden, CodeUnavailable},
}

// guardCodes is what a class's guard can answer: the Authenticator's
// refusals on every class that authenticates, then the class predicate's.
func guardCodes(c Class) []Code {
	if c == ClassPublic {
		return nil
	}
	codes := []Code{CodeAuthRequired, CodeSessionExpired, CodeInvalidCredentials, CodeKeyInvalid, CodeUnavailable, CodeSessionRequired}
	switch c {
	case ClassRecentAuth:
		codes = append(codes, CodeRecentAuthRequired)
	case ClassKeyScope:
		codes = append(codes, CodeScopeRequired)
	case ClassKeyPermission:
		codes = append(codes, CodeRecentAuthRequired, CodeScopeRequired)
	default:
	}
	return codes
}

// transportCodes is what the transport can answer before or around the
// operation: method, origin, body, path, query and limiter refusals.
func (s *routeSpec) transportCodes() []Code {
	codes := []Code{CodeMethodNotAllowed}
	if s.method != http.MethodGet {
		codes = append(codes, CodeCrossOrigin)
	}
	body := s.request != nil || s.cer != ceremonyNone
	if body {
		codes = append(codes, CodeBodyTooLarge)
	}
	if body || s.pathID != pathNone || s.tokenBody || (s.query != nil && !s.redirect) {
		codes = append(codes, CodeBadRequest)
	}
	if s.limited {
		codes = append(codes, CodeRateLimited)
	}
	return codes
}

// classFor resolves a spec's class and scope against the Account's scopes.
func (s *routeSpec) classFor(sc scopes) (class Class, scope string) {
	switch s.scope {
	case scopeAdmin:
		if sc.admin != "" {
			return ClassKeyScope, sc.admin
		}
		return ClassSession, ""
	case scopeUsers:
		return permission(sc.users)
	case scopeKeys:
		return permission(sc.keys)
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

// scopes are the Account's three key scopes, read once at New.
type scopes struct{ admin, users, keys string }

// descriptor builds s's Descriptor under the handler's prefixes and scopes.
func (s *routeSpec) descriptor(prefix, oidcPrefix string, sc scopes) Descriptor {
	class, scope := s.classFor(sc)
	path := prefix + s.path
	if s.oidc {
		path = oidcPrefix + s.path
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

// inCodesOrder dedupes codes and orders them as Codes() does.
func inCodesOrder(codes []Code) []Code {
	out := slices.Clone(codes)
	slices.SortFunc(out, func(a, b Code) int { return codeIndex[a] - codeIndex[b] })
	return slices.Compact(out)
}
