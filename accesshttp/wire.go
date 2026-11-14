package accesshttp

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// Every password or token field of a request is a string: the handler's
// first statement wraps it in access.NewSecret, and an empty one is missing.
// No request struct is printed, logged, stored or passed on.

// SetupPasswordRequest is authSetupPassword's body.
type SetupPasswordRequest struct {
	Token    string `json:"token,omitempty"` // required when the setup rule asks for one
	Username string `json:"username"`
	Password string `json:"password"`
}

// SetupPasskeyBeginRequest is authSetupPasskeyBegin's body.
type SetupPasskeyBeginRequest struct {
	Token    string `json:"token,omitempty"`
	Username string `json:"username"`
}

// LoginRequest is authLoginPassword's body.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RedirectRequest is the OIDC link and step-up starts' body.
type RedirectRequest struct {
	Redirect string `json:"redirect,omitempty"` // the app's return path, at most oidc.MaxRedirectBytes
}

// TokenRequest is authRecoveryStart's body.
type TokenRequest struct {
	Token string `json:"token"`
}

// RecoverPasswordRequest is authRecoveryPassword's body.
type RecoverPasswordRequest struct {
	Password     string `json:"password"`
	KeepSessions bool   `json:"keep_sessions,omitempty"`
	KeepKeys     bool   `json:"keep_keys,omitempty"`
}

// InviteAcceptRequest is authInviteAcceptPassword's body.
type InviteAcceptRequest struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ProfileRequest is authProfile's body.
type ProfileRequest struct {
	DisplayName string `json:"display_name"`
}

// PasswordRequest is authStepUpPassword's body.
type PasswordRequest struct {
	Password string `json:"password"`
}

// PasswordChangeRequest is authPasswordSet's body. CurrentPassword is
// required when the user holds a password.
type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password,omitempty"`
	Password        string `json:"password"`
}

// PasswordRemoveRequest is authPasswordRemove's body: the password being
// removed; empty is current_password_required.
type PasswordRemoveRequest struct {
	CurrentPassword string `json:"current_password"`
}

// NameRequest renames a passkey, a session or an API key.
type NameRequest struct {
	Name string `json:"name"`
}

// NewKeyRequest is authKeyCreate's body.
type NewKeyRequest struct {
	Label         string   `json:"label"`
	Scopes        []string `json:"scopes"`
	ExpiresInDays int      `json:"expires_in_days,omitempty"` // 0 = never
}

// NewUserRequest is authAdminUserCreate's body.
type NewUserRequest struct {
	Username string      `json:"username"`
	Password string      `json:"password,omitempty"` // empty: no sign-in method until a recovery link
	Role     access.Role `json:"role"`
}

// UserUpdateRequest is authAdminUserUpdate's body.
type UserUpdateRequest struct {
	Role    *access.Role `json:"role,omitempty"`
	Enabled *bool        `json:"enabled,omitempty"`
}

// TTLRequest is authAdminRecovery's body.
type TTLRequest struct {
	Hours int `json:"hours,omitempty"` // 0 = the default lifetime
}

// InviteRequest is authAdminInvite's body.
type InviteRequest struct {
	Role  access.Role `json:"role"`
	Hours int         `json:"hours,omitempty"`
}

// StateResponse is authState's answer.
type StateResponse struct {
	SetupRequired bool `json:"setup_required"`
	PasswordLogin bool `json:"password_login"`
	Passkeys      bool `json:"passkeys"`
	OIDC          bool `json:"oidc"`
}

// UserView is one user.
type UserView struct {
	CreatedAt time.Time `json:"created_at"`
	// Methods is the user's sign-in methods; set on the admin list only.
	Methods     *UserMethodsView `json:"methods,omitempty"`
	Username    string           `json:"username"`
	DisplayName string           `json:"display_name,omitempty"`
	Role        access.Role      `json:"role"`
	// KeyLineage is account.ListedUser.KeyLineage; set on the admin list only.
	KeyLineage []int64 `json:"key_lineage,omitempty"`
	ID         int64   `json:"id"`
	Enabled    bool    `json:"enabled"`
	OIDCLinked bool    `json:"oidc_linked"`
}

// UserMethodsView is a listed user's password and passkey count.
type UserMethodsView struct {
	PasskeyCount int  `json:"passkey_count"`
	Password     bool `json:"password"`
}

// SignedInResponse is the answer of every route that signs a user in.
type SignedInResponse struct {
	SessionID    string   `json:"session_id"`
	User         UserView `json:"user"`
	CloneWarning bool     `json:"clone_warning,omitempty"`
}

// CeremonyResponse is a begun WebAuthn ceremony.
type CeremonyResponse struct {
	Ceremony string `json:"ceremony"` // echoed in X-Auth-Ceremony on finish
	// PublicKey is webauthn.CredentialCreation or webauthn.CredentialAssertion
	// in the browser's JSON shape ({"publicKey": …, "mediation"?}).
	PublicKey json.RawMessage `json:"public_key"`
}

// OIDCStartResponse is the link and step-up starts' answer.
type OIDCStartResponse struct {
	URL string `json:"url"`
}

// PendingLinkResponse is the identity a pending link would attach.
type PendingLinkResponse struct {
	Issuer       string `json:"issuer"`
	UsernameHint string `json:"username_hint,omitempty"`
	Email        string `json:"email,omitempty"`
}

// MethodLockView is one locked method, per trust context.
type MethodLockView struct {
	Method    access.Method `json:"method"`
	Untrusted bool          `json:"untrusted"`
	Trusted   bool          `json:"trusted"`
}

// MethodsView is what a user can sign in with.
type MethodsView struct {
	Locks             []MethodLockView `json:"locks"` // [] when none
	PasskeyCount      int              `json:"passkey_count"`
	Password          bool             `json:"password"`
	OIDCLinked        bool             `json:"oidc_linked"`
	OIDCAvailable     bool             `json:"oidc_available"`
	PasskeysAvailable bool             `json:"passkeys_available"`
	PasswordLogin     bool             `json:"password_login"`
}

// CurrentSessionView is the caller's own session.
type CurrentSessionView struct {
	AuthTime         time.Time     `json:"auth_time"`
	IdleDeadline     time.Time     `json:"idle_deadline"`
	AbsoluteDeadline time.Time     `json:"absolute_deadline"`
	ID               string        `json:"id"`
	Method           access.Method `json:"method"`
}

// MeResponse is the signed-in user's own view.
type MeResponse struct {
	Session     CurrentSessionView `json:"session"`
	Methods     MethodsView        `json:"methods"`
	User        UserView           `json:"user"`
	CanLinkOIDC bool               `json:"can_link_oidc"`
	SSOGoverned bool               `json:"sso_governed"`
}

// RecoveryResponse is a started recovery.
type RecoveryResponse struct {
	Username string      `json:"username"`
	Methods  MethodsView `json:"methods"`
}

// PasskeyView is one passkey.
type PasskeyView struct {
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
	Name       string    `json:"name"`
	// RPID is the relying-party ID the passkey was registered against; one
	// that differs from the current RP's ID cannot sign in.
	RPID           string `json:"rp_id"`
	ID             int64  `json:"id"`
	BackupEligible bool   `json:"backup_eligible"`
	BackedUp       bool   `json:"backed_up"`
	CloneWarning   bool   `json:"clone_warning,omitempty"`
}

// SessionView is one session.
type SessionView struct {
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
	AuthTime     time.Time `json:"auth_time"`
	// IdleDeadline and AbsoluteDeadline are access.SessionDeadlines of the
	// session under the Authenticator's timeouts.
	IdleDeadline     time.Time     `json:"idle_deadline"`
	AbsoluteDeadline time.Time     `json:"absolute_deadline"`
	ID               string        `json:"id"`
	Label            string        `json:"label,omitempty"`
	UserAgent        string        `json:"user_agent,omitempty"`
	LastIP           string        `json:"last_ip,omitempty"`
	Method           access.Method `json:"method"`
	Current          bool          `json:"current"`
}

// KeyView is one API key, never its secret or hash.
type KeyView struct {
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
	LastUsedAt  time.Time `json:"last_used_at,omitzero"`
	Owner       string    `json:"owner,omitempty"` // username; set on the admin list only
	Label       string    `json:"label"`
	Prefix      string    `json:"prefix"`
	Suffix      string    `json:"suffix"`
	Scopes      []string  `json:"scopes"`
	ID          int64     `json:"id"`
	UserID      int64     `json:"user_id"`
	ParentKeyID int64     `json:"parent_key_id,omitempty"` // Key.ParentKeyID()
}

// KeyCreatedResponse is a minted key. Only writeShownOnce fills Key.
type KeyCreatedResponse struct {
	Key     string  `json:"key"` // the plaintext, shown once
	Details KeyView `json:"details"`
}

// TokenResponse is a minted invite or recovery token. Only writeShownOnce
// fills Token.
type TokenResponse struct {
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"token"` // the plaintext, shown once
}

// TokenView is one live invite or recovery token on authAdminTokens. It
// carries neither the token nor its hash.
type TokenView struct {
	CreatedAt time.Time           `json:"created_at"`
	ExpiresAt time.Time           `json:"expires_at"`
	Purpose   access.TokenPurpose `json:"purpose"`        // "invite" or "recovery"
	Role      access.Role         `json:"role,omitempty"` // invite only
	// IssuerLineage is the issuing key's LineageIDs, root first; omitted for
	// a token no key issued.
	IssuerLineage []int64 `json:"issuer_lineage,omitempty"`
	Subject       int64   `json:"subject,omitempty"` // recovery only: the user it acts on
	IssuedByKey   int64   `json:"issued_by_key,omitempty"`
}

// SecurityLogView is one authAdminSecurityLog page.
type SecurityLogView struct {
	Entries []LogEntryView `json:"entries"` // never null: an empty page is []
	Classes []LogClassView `json:"classes"` // one per account.LogClasses() value, in order
}

// LogClassView is one log class's entry count and cap evictions.
type LogClassView struct {
	Class   account.LogClass `json:"class"`
	Count   int64            `json:"count"`
	Evicted int64            `json:"evicted"` // removed by the size limit, ever
}

// LogEntryView is one security-log entry.
type LogEntryView struct {
	At         time.Time        `json:"at"`
	OccurredAt time.Time        `json:"occurred_at"` // Event.At
	Class      account.LogClass `json:"class"`
	Kind       string           `json:"kind"`
	IP         string           `json:"ip,omitempty"`
	Method     access.Method    `json:"method,omitempty"`
	Role       access.Role      `json:"role,omitempty"`
	Detail     string           `json:"detail,omitempty"`
	SessionIDs []string         `json:"session_ids,omitempty"`
	Actor      LogActorView     `json:"actor"`
	Seq        int64            `json:"seq"`
	UserID     int64            `json:"user_id,omitempty"`
	KeyID      int64            `json:"key_id,omitempty"`
	PasskeyID  int64            `json:"passkey_id,omitempty"`
	Trusted    bool             `json:"trusted,omitempty"`
}

// LogActorView is who made a logged change, with the display data the
// change's Update snapshotted.
type LogActorView struct {
	SessionID string `json:"session_id,omitempty"`
	OutOfBand string `json:"out_of_band,omitempty"`
	Label     string `json:"label,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	KeySuffix string `json:"key_suffix,omitempty"`
	UserID    int64  `json:"user_id,omitempty"`
	KeyID     int64  `json:"key_id,omitempty"`
}

// A query struct's JSON names are its query keys (query.go).

// PasskeyBeginQuery is authLoginPasskeyBegin's query.
type PasskeyBeginQuery struct {
	Mediation string `json:"mediation,omitempty"` // "conditional" or absent
}

// OIDCSignInQuery is authOIDCStartSignIn's query.
type OIDCSignInQuery struct {
	Redirect string `json:"redirect,omitempty"`
}

// OIDCCallbackQuery is what the IdP sends on its redirect (RFC 6749
// sections 4.1.2 and 4.1.2.1). It converts to oidc.Callback, which compiles
// only while the two types have the same fields.
type OIDCCallbackQuery struct {
	State string `json:"state"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

// RecoveryPasskeyFinishQuery is authRecoveryPasskeyFinish's query.
type RecoveryPasskeyFinishQuery struct {
	KeepSessions bool `json:"keep_sessions,omitempty"` // "true" or absent
	KeepKeys     bool `json:"keep_keys,omitempty"`     // "true" or absent
}

// AdminUsersQuery is authAdminUsers' query.
type AdminUsersQuery struct {
	Key int64 `json:"key,omitempty"` // a positive decimal key ID, or absent
}

// AdminSecurityLogQuery is authAdminSecurityLog's query. Kinds is a
// comma-separated list of kinds, OldestFirst is "true" or absent, and every
// other key is a positive decimal.
type AdminSecurityLogQuery struct {
	Kinds       string `json:"kinds,omitempty"`        // LogFilter.Kinds, split on ","
	User        int64  `json:"user,omitempty"`         // LogFilter.UserID
	Actor       int64  `json:"actor,omitempty"`        // LogFilter.ActorUserID
	ActorKey    int64  `json:"actor_key,omitempty"`    // LogFilter.ActorKeyID
	After       int64  `json:"after,omitempty"`        // LogFilter.AfterSeq
	Before      int64  `json:"before,omitempty"`       // LogFilter.BeforeSeq
	Limit       int64  `json:"limit,omitempty"`        // LogFilter.Limit
	OldestFirst bool   `json:"oldest_first,omitempty"` // LogFilter.OldestFirst
}

// shownOnce is a response that carries one plaintext.
type shownOnce interface {
	KeyCreatedResponse | TokenResponse
}

// writeShownOnce is the only accesshttp code that reveals a response field:
// the plaintext enters resp inside this call, which encodes it to w and
// drops it.
func writeShownOnce[R shownOnce](w http.ResponseWriter, status int, resp R, plaintext access.Secret) {
	switch v := any(&resp).(type) {
	case *KeyCreatedResponse:
		v.Key = plaintext.Reveal()
	case *TokenResponse:
		v.Token = plaintext.Reveal()
	}
	writeJSON(w, status, resp)
}

// writeJSON encodes a success body. The status line is already sent when
// encoding fails, so the error has no one to reach.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func userView(u *access.User) UserView {
	return UserView{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Role:        u.Role,
		Enabled:     u.Enabled,
		OIDCLinked:  !u.OIDC.IsZero(),
		CreatedAt:   u.CreatedAt,
	}
}

// listedUserView is an admin-list row: the user with its key lineage and
// sign-in methods, which no other UserView carries.
func listedUserView(l *account.ListedUser) UserView {
	v := userView(&l.User)
	v.KeyLineage = l.KeyLineage
	v.Methods = &UserMethodsView{Password: !l.User.PasswordHash.IsZero(), PasskeyCount: l.PasskeyCount}
	return v
}

func passkeyView(p *access.PasskeyCredential) PasskeyView {
	return PasskeyView{
		ID: p.ID, Name: p.Name, RPID: p.RPID, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt,
		BackupEligible: p.BackupEligible, BackedUp: p.BackupState, CloneWarning: p.CloneWarning,
	}
}

// sessionView is s under t, Current when s is the caller's session.
func sessionView(s *access.Session, t access.SessionTimeouts, current string) SessionView {
	idle, absolute := access.SessionDeadlines(s, t)
	return SessionView{
		ID: s.ID, Label: s.Label, UserAgent: s.UserAgent, LastIP: s.LastIP, Method: s.AuthMethod,
		CreatedAt: s.CreatedAt, LastActivity: s.LastActivity, AuthTime: s.AuthTime,
		IdleDeadline: idle, AbsoluteDeadline: absolute, Current: s.ID == current,
	}
}

// keyView is k without its hash; owner is set on the admin list only.
func keyView(k *access.Key, owner string) KeyView {
	return KeyView{
		ID: k.ID, UserID: k.UserID, Owner: owner, Label: k.Label, Prefix: k.KeyPrefix, Suffix: k.KeySuffix,
		Scopes: append([]string{}, k.Scopes...), CreatedAt: k.CreatedAt, ExpiresAt: k.ExpiresAt, LastUsedAt: k.LastUsedAt,
		ParentKeyID: k.ParentKeyID(),
	}
}

// tokenView is a listed token without the token or its hash.
func tokenView(l *account.ListedToken) TokenView {
	t := &l.Token
	return TokenView{
		Purpose: t.Purpose, Role: t.Role, Subject: t.Subject, IssuedByKey: t.IssuedByKey,
		IssuerLineage: l.IssuerLineage, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
	}
}

// securityLogView is p on the wire, Entries never nil.
func securityLogView(p *account.LogPage) SecurityLogView {
	entries := make([]LogEntryView, 0, len(p.Entries))
	for i := range p.Entries {
		entries = append(entries, logEntryView(&p.Entries[i]))
	}
	classes := make([]LogClassView, 0, len(p.Classes))
	for _, c := range p.Classes {
		classes = append(classes, LogClassView{Class: c.Class, Count: int64(c.Count), Evicted: int64(c.Evicted)}) //nolint:gosec // G115: rule 22 bounds Evicted by Seq, at most 2^53 - 1
	}
	return SecurityLogView{Entries: entries, Classes: classes}
}

func logEntryView(e *account.LogEntry) LogEntryView {
	ev := &e.Event
	v := LogEntryView{
		Seq: int64(ev.Seq), At: e.At, OccurredAt: ev.At, Class: e.Class, Kind: string(ev.Kind), //nolint:gosec // G115: rule 22 bounds Seq at 2^53 - 1
		UserID: ev.UserID, SessionIDs: ev.SessionIDs, KeyID: ev.KeyID, PasskeyID: ev.PasskeyID,
		Method: ev.Method, Role: ev.Role, Trusted: ev.Trusted, Detail: e.Detail,
		Actor: LogActorView{
			UserID: ev.Actor.UserID, SessionID: ev.Actor.SessionID, KeyID: ev.Actor.KeyID, OutOfBand: ev.Actor.OutOfBand,
			Label: e.ActorLabel, UserAgent: e.ActorUserAgent, KeySuffix: e.ActorKeySuffix,
		},
	}
	if e.IP.IsValid() {
		v.IP = e.IP.String()
	}
	return v
}

func methodsView(m account.Methods) MethodsView {
	locks := make([]MethodLockView, 0, len(m.Locks))
	for _, l := range m.Locks {
		locks = append(locks, MethodLockView{Method: l.Method, Untrusted: l.Untrusted, Trusted: l.Trusted})
	}
	return MethodsView{
		Password:          m.HasPassword,
		PasskeyCount:      m.PasskeyCount,
		OIDCLinked:        m.OIDCLinked,
		OIDCAvailable:     m.OIDCAvailable,
		PasskeysAvailable: m.PasskeysAvailable,
		PasswordLogin:     m.PasswordLogin,
		Locks:             locks,
	}
}

func meResponse(m *account.Me) MeResponse {
	return MeResponse{
		User:    userView(m.User),
		Methods: methodsView(m.Methods),
		Session: CurrentSessionView{
			ID: m.Current.ID, Method: m.Current.Method, AuthTime: m.Current.AuthTime,
			IdleDeadline: m.Current.IdleDeadline, AbsoluteDeadline: m.Current.AbsoluteDeadline,
		},
		CanLinkOIDC: m.CanLinkOIDC,
		SSOGoverned: m.SSOGoverned,
	}
}

func signedInResponse(s account.SignedIn) SignedInResponse { //nolint:gocritic // hugeParam: account's own result, read once
	return SignedInResponse{User: userView(s.User), SessionID: s.Session.ID, CloneWarning: s.CloneWarning}
}

// ceremonyResponse encodes a begun ceremony's options in the browser's shape.
func ceremonyResponse(pc account.PendingCeremony) (CeremonyResponse, error) {
	var v any = pc.Assertion
	if pc.Creation != nil {
		v = pc.Creation
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return CeremonyResponse{}, err
	}
	return CeremonyResponse{Ceremony: pc.ID, PublicKey: raw}, nil
}
