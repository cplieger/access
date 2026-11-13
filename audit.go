package access

// AuditEvent is one request-level outcome that changes no state: a
// failure, a refusal or a rate limit, and the sign-ins beside them. It
// carries no raw request text: no user agent, no provider
// error_description, no typed username that failed normalisation.
type AuditEvent struct {
	Kind     string // "login.success", "login.failure", "login.rate_limited", "setup.failure", ...
	Username string // canonical, or "" when the input was refused; never the raw input
	IP       string
	Method   Method
	// Reason is a code-like class: "invalid_credentials", "method_locked",
	// "provider_error:access_denied", "exchange_failed".
	Reason    string
	SessionID string
	UserID    int64
	KeyID     int64
	Success   bool
}
