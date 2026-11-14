package access

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// CookiePosture decides how the cookie methods use the transport they are
// given, [ClientAddr.Secure].
type CookiePosture int

const (
	// PostureSecure is the default: every cookie is __Host-<base> with
	// Secure, HttpOnly and SameSite, whatever the transport. Works on any
	// HTTPS deployment, self-signed certificates included.
	PostureSecure CookiePosture = iota

	// PosturePerRequest names each cookie from the transport:
	// __Host-<base> with Secure for a secure request, the bare <base>
	// without Secure for a plain one. For one instance served both over
	// plain HTTP on a LAN and over HTTPS.
	PosturePerRequest
)

// String returns the posture's name so structured-log attributes render
// "PostureSecure" rather than the bare iota integer.
func (p CookiePosture) String() string {
	switch p {
	case PostureSecure:
		return "PostureSecure"
	case PosturePerRequest:
		return "PosturePerRequest"
	default:
		return fmt.Sprintf("CookiePosture(%d)", int(p))
	}
}

var _ fmt.Stringer = CookiePosture(0)

// CookieConfig holds the session cookie's attributes. Each cookie method
// takes the request's transport, the [ClientAddr.Secure] the app's
// resolver answers for it. Every cookie is HttpOnly with Path "/" and no
// Domain, as the __Host- prefix requires.
type CookieConfig struct {
	// Name is the base cookie name (without __Host- prefix).
	// Default: "auth_session".
	Name string

	// SameSite is the cookie SameSite attribute: unset (Lax), Lax or Strict.
	// Validate refuses every other value, None included.
	SameSite http.SameSite

	// Posture selects the deploy-time cookie security posture.
	// Default: PostureSecure.
	Posture CookiePosture
}

// defaultCookieName is the base cookie name used when CookieConfig.Name is unset.
const defaultCookieName = "auth_session"

// DefaultCookieConfig returns a CookieConfig with secure defaults.
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Posture:  PostureSecure,
		Name:     defaultCookieName,
		SameSite: http.SameSiteLaxMode,
	}
}

// baseName returns the configured base cookie name, falling back to the
// library default when unset.
func (c *CookieConfig) baseName() string {
	return cmp.Or(c.Name, defaultCookieName)
}

// transport returns the cookie name and its Secure flag for a request
// whose transport is secure. Under PostureSecure both are fixed, so a
// deployment has one name and every cookie it sets is Secure.
func (c *CookieConfig) transport(secure bool) (name string, secureFlag bool) {
	if c.Posture == PosturePerRequest && !secure {
		return c.baseName(), false
	}
	return "__Host-" + c.baseName(), true
}

// effectiveSameSite returns the resolved SameSite mode.
func (c *CookieConfig) effectiveSameSite() http.SameSite {
	return cmp.Or(c.SameSite, http.SameSiteLaxMode)
}

// CookieName returns the cookie name for a request whose transport is
// secure: __Host-<base>, unless Posture is PosturePerRequest and secure is
// false, which gives the bare <base>.
func (c *CookieConfig) CookieName(secure bool) string {
	name, _ := c.transport(secure)
	return name
}

// SetCookie sets the cookie for a request whose transport is secure, and
// sends Cache-Control: no-store. A plain request's cookie ends with the
// browser: a positive maxAge is dropped, so it carries neither Max-Age nor
// Expires. A negative maxAge (a clear) sends Max-Age=0.
func (c *CookieConfig) SetCookie(w http.ResponseWriter, secure bool, value string, maxAge int) {
	if !secure && maxAge > 0 {
		maxAge = 0
	}
	name, secureFlag := c.transport(secure)
	// A browser never sends a Secure cookie over plain HTTP, so Secure is
	// omitted for a plain request under PosturePerRequest; CodeQL
	// go/cookie-secure-not-set flags that as a false positive too.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is conditional for a plain request under PosturePerRequest
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secureFlag,
		SameSite: c.effectiveSameSite(),
	})
	// Cache-Control: no-store on any response with Set-Cookie (OWASP Session Mgmt CS)
	w.Header().Set("Cache-Control", "no-store")
}

// ClearCookie clears the cookie named for a request whose transport is
// secure.
func (c *CookieConfig) ClearCookie(w http.ResponseWriter, secure bool) {
	c.SetCookie(w, secure, "", -1)
}

// ReadCookie reads the cookie named for a request whose transport is
// secure, never the other transport's name. It returns "" unless r carries
// exactly one cookie of that name, so a planted second cookie cannot choose
// the session.
func (c *CookieConfig) ReadCookie(r *http.Request, secure bool) string {
	cookies := r.CookiesNamed(c.CookieName(secure))
	if len(cookies) != 1 {
		return ""
	}
	return cookies[0].Value
}

const maxDeriveSuffix = 16

// Derive returns the config for a companion cookie: the same Posture, the
// name <base>_<suffix> and the given SameSite. The derived name always
// differs from the base name. Derive panics unless suffix matches
// ^[a-z_]{1,16}$ and sameSite is one Validate accepts (unset, Lax or Strict),
// because both are fixed by the calling code.
func (c CookieConfig) Derive(suffix string, sameSite http.SameSite) CookieConfig {
	if !validDeriveSuffix(suffix) {
		panic(fmt.Sprintf("access: CookieConfig.Derive: suffix %q must match ^[a-z_]{1,16}$", suffix))
	}
	if !validSameSite(sameSite) {
		panic(fmt.Sprintf("access: CookieConfig.Derive: SameSite %d must be unset, Lax or Strict", sameSite))
	}
	return CookieConfig{
		Name:     c.baseName() + "_" + suffix,
		SameSite: sameSite,
		Posture:  c.Posture,
	}
}

func validDeriveSuffix(s string) bool {
	if s == "" || len(s) > maxDeriveSuffix {
		return false
	}
	for i := range len(s) {
		if (s[i] < 'a' || s[i] > 'z') && s[i] != '_' {
			return false
		}
	}
	return true
}

// validSameSite reports whether s is unset, Lax or Strict. SameSiteDefaultMode
// is refused because it emits no attribute, which some browsers read as None.
func validSameSite(s http.SameSite) bool {
	switch s {
	case 0, http.SameSiteLaxMode, http.SameSiteStrictMode:
		return true
	default:
		return false
	}
}

// MaxCookieNameBytes is the longest [CookieConfig.Name] Validate accepts:
// far above any real name, it leaves a derived cookie room for a sealed
// value in a browser's 4096 bytes (RFC 6265 §6.1).
const MaxCookieNameBytes = 64

// Validate refuses a configuration browsers would drop: an undeclared
// Posture; a Name [http.Cookie.Valid] refuses, one over
// [MaxCookieNameBytes], or one with a __Secure-, __Host- or __Http- prefix
// in any letter case; and a SameSite other than unset, Lax or Strict. The
// 4096 bytes of name and value stay the caller's, since Validate never sees
// the value.
func (c *CookieConfig) Validate() error {
	if c.Posture < PostureSecure || c.Posture > PosturePerRequest {
		return fmt.Errorf("access: CookieConfig.Posture %v is not a declared posture", c.Posture)
	}
	probe := &http.Cookie{Name: c.CookieName(true), Value: "x", Path: "/"} //nolint:gosec // G124: a validation probe, never sent
	if err := probe.Valid(); err != nil {
		return fmt.Errorf("access: CookieConfig is not a valid cookie: %w", err)
	}
	if len(c.baseName()) > MaxCookieNameBytes {
		return fmt.Errorf("access: CookieConfig.Name must be at most %d bytes", MaxCookieNameBytes)
	}
	// Browsers match the prefixes in any case and drop such a cookie sent without
	// Secure (draft-ietf-httpbis-layered-cookies §5.4.3).
	if l := strings.ToLower(c.baseName()); strings.HasPrefix(l, "__secure-") || strings.HasPrefix(l, "__host-") || strings.HasPrefix(l, "__http-") {
		return errors.New("access: CookieConfig.Name must not carry a __Secure-, __Host- or __Http- prefix")
	}
	if !validSameSite(c.SameSite) {
		return errors.New("access: CookieConfig.SameSite must be unset, Lax or Strict")
	}
	return nil
}
