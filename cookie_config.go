package access

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// CookiePosture determines the cookie security posture. Every posture except
// [PosturePerRequest] is a deploy-time decision with one stable cookie name;
// PosturePerRequest selects the name and Secure flag per request from
// [CookieConfig.HTTPS].
type CookiePosture int

const (
	// PostureSecure is the default: __Host- prefix + Secure + HttpOnly + SameSite=Lax.
	// Works on any HTTPS deployment including self-signed certificates.
	PostureSecure CookiePosture = iota

	// PostureInsecureLAN is for HTTP-only LAN/Docker deployments (ip:port, dockername:port).
	// Uses a non-prefixed name, no Secure flag. Explicitly opt-in only.
	PostureInsecureLAN

	// PosturePerRequest selects the cookie name and Secure flag per request
	// from [CookieConfig.HTTPS]: __Host-<base> with Secure when it reports
	// true, and the bare <base> without Secure otherwise. Intended for a
	// single instance serving both HTTP-LAN (ip:port) and HTTPS-proxied
	// traffic. The base name stays configurable via Name.
	PosturePerRequest
)

// String returns the posture's name so structured-log attributes render
// "PostureSecure" rather than the bare iota integer.
func (p CookiePosture) String() string {
	switch p {
	case PostureSecure:
		return "PostureSecure"
	case PostureInsecureLAN:
		return "PostureInsecureLAN"
	case PosturePerRequest:
		return "PosturePerRequest"
	default:
		return fmt.Sprintf("CookiePosture(%d)", int(p))
	}
}

var _ fmt.Stringer = CookiePosture(0)

// CookieConfig holds the session cookie's attributes. Its cookie methods
// require a config [CookieConfig.Validate] accepts: under [PosturePerRequest]
// a nil HTTPS panics.
type CookieConfig struct {
	// HTTPS decides the name and the Secure flag under PosturePerRequest,
	// and is required there. Pass [RequestIsHTTPS]. A predicate that trusts
	// X-Forwarded-Proto only from listed proxies must not be passed: behind
	// a TLS proxy the app does not list it answers false, and the cookie
	// loses Secure.
	HTTPS func(*http.Request) bool

	// Persistent reports whether a cookie set on r may outlive the browser
	// session. False makes SetCookie drop a positive maxAge, sending neither
	// Max-Age nor Expires. Nil means always persistent.
	Persistent func(*http.Request) bool

	// Name is the base cookie name (without __Host- prefix).
	// Default: "auth_session".
	Name string

	// Path is the cookie Path attribute. Default: "/".
	Path string

	// Domain is the cookie Domain attribute. Default: "" (unset).
	// Note: __Host- prefix requires Domain to be unset.
	Domain string

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
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
}

// RequestIsHTTPS is upgrade-only: it reports true for a TLS request, or when
// the first token of X-Forwarded-Proto is "https" (case-insensitive), from
// any peer. A forged "https" only makes the forger's own browser refuse the
// Secure cookie, so no proxy trust is needed.
func RequestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	first, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(first), "https")
}

// baseName returns the configured base cookie name, falling back to the
// library default when unset.
func (c *CookieConfig) baseName() string {
	return cmp.Or(c.Name, defaultCookieName)
}

// usesHostPrefix reports whether the posture can emit a __Host- name: every
// posture but PostureInsecureLAN. Validate's Domain and Path rules key on it.
func (c *CookieConfig) usesHostPrefix() bool {
	return c.Posture != PostureInsecureLAN
}

// EffectiveName returns the ONE stable cookie name for this deployment.
// Determined entirely by Posture at config time — no per-request logic.
//
// For PosturePerRequest the actual emitted/read name varies per request (see
// CookieName / SetCookie / ReadCookie); EffectiveName returns the secure
// __Host-<base> form as the canonical name for request-less callers and
// validation.
func (c *CookieConfig) EffectiveName() string {
	base := c.baseName()
	if c.usesHostPrefix() {
		return "__Host-" + base
	}
	return base
}

// forRequest returns the cookie name and Secure flag for r. It asks HTTPS at
// most once, so both come from one answer: a predicate that changes its
// answer between two calls would otherwise pair a __Host- name with no
// Secure, which browsers drop.
func (c *CookieConfig) forRequest(r *http.Request) (name string, secure bool) {
	if c.Posture != PosturePerRequest {
		return c.EffectiveName(), c.isSecureCookie()
	}
	if c.isHTTPS(r) {
		return "__Host-" + c.baseName(), true
	}
	return c.baseName(), false
}

// effectivePath returns the resolved path.
func (c *CookieConfig) effectivePath() string {
	return cmp.Or(c.Path, "/")
}

// effectiveSameSite returns the resolved SameSite mode.
func (c *CookieConfig) effectiveSameSite() http.SameSite {
	return cmp.Or(c.SameSite, http.SameSiteLaxMode)
}

// isSecureCookie returns whether the Secure flag should be set based on posture.
func (c *CookieConfig) isSecureCookie() bool {
	return c.Posture != PostureInsecureLAN
}

// isHTTPS asks the HTTPS predicate. A nil predicate panics instead of
// answering false, because false silently drops Secure on an HTTPS request.
func (c *CookieConfig) isHTTPS(r *http.Request) bool {
	if c.HTTPS == nil {
		panic("access: CookieConfig.HTTPS is nil under PosturePerRequest; Validate refuses this config")
	}
	return c.HTTPS(r)
}

// CookieName returns the cookie name for this config. In PosturePerRequest mode
// the name is selected from [CookieConfig.HTTPS] (__Host-<base> when it reports
// true, bare <base> otherwise); in all other postures the request is ignored
// and the stable EffectiveName() is returned.
func (c *CookieConfig) CookieName(r *http.Request) string {
	name, _ := c.forRequest(r)
	return name
}

// SetCookie sets the session cookie on the response and sends
// Cache-Control: no-store. A positive maxAge is dropped when Persistent
// reports false for r; a negative maxAge (a clear) sends Max-Age=0.
//
// Secure is omitted only for plain-HTTP delivery (PostureInsecureLAN, or
// PosturePerRequest over HTTP), because a browser never sends a Secure cookie
// over plain HTTP; gosec G124 and CodeQL go/cookie-secure-not-set flag that
// conditional as a false positive.
func (c *CookieConfig) SetCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	if maxAge > 0 && c.Persistent != nil && !c.Persistent(r) {
		maxAge = 0
	}
	name, secure := c.forRequest(r)
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is conditional for LAN HTTP / per-request support
		Name:     name,
		Value:    token,
		Path:     c.effectivePath(),
		Domain:   c.Domain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: c.effectiveSameSite(),
	})
	// Cache-Control: no-store on any response with Set-Cookie (OWASP Session Mgmt CS)
	w.Header().Set("Cache-Control", "no-store")
}

// ClearCookie clears the session cookie.
func (c *CookieConfig) ClearCookie(w http.ResponseWriter, r *http.Request) {
	c.SetCookie(w, r, "", -1)
}

// ReadCookie reads the session token from the cookie named for r. It returns
// "" unless r carries exactly one cookie of that name, so a planted second
// cookie cannot choose the session.
func (c *CookieConfig) ReadCookie(r *http.Request) string {
	cookies := r.CookiesNamed(c.CookieName(r))
	if len(cookies) != 1 {
		return ""
	}
	return cookies[0].Value
}

const maxDeriveSuffix = 16

// maxCookiePath is the longest Path a browser applies; it skips a longer
// attribute value and scopes the cookie to the default path
// (draft-ietf-httpbis-layered-cookies §5.4.2).
const maxCookiePath = 1024

// Derive returns the config for a companion cookie: the same Posture, Path,
// Domain and HTTPS predicate, the name <base>_<suffix>, the given SameSite,
// and a nil Persistent (each companion keeps its own lifetime). The derived
// name always differs from the base name. Derive panics unless suffix matches
// ^[a-z_]{1,16}$ and sameSite is one Validate accepts (unset, Lax or Strict),
// because both are fixed by the calling code.
func (c CookieConfig) Derive(suffix string, sameSite http.SameSite) CookieConfig { //nolint:gocritic // hugeParam: a value receiver keeps it callable on a non-addressable config
	if !validDeriveSuffix(suffix) {
		panic(fmt.Sprintf("access: CookieConfig.Derive: suffix %q must match ^[a-z_]{1,16}$", suffix))
	}
	if !validSameSite(sameSite) {
		panic(fmt.Sprintf("access: CookieConfig.Derive: SameSite %d must be unset, Lax or Strict", sameSite))
	}
	return CookieConfig{
		HTTPS:    c.HTTPS,
		Name:     c.baseName() + "_" + suffix,
		Path:     c.Path,
		Domain:   c.Domain,
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

// Validate refuses a configuration browsers would drop or mis-scope: an
// undeclared Posture; a name, Path or Domain [http.Cookie.Valid] refuses; a
// Name over [MaxCookieNameBytes], or with a __Secure-, __Host- or __Http-
// prefix in any letter case; a Path not starting with "/" or over 1024
// bytes; a SameSite other than unset, Lax or Strict; a nil HTTPS under
// PosturePerRequest; and, under a __Host- posture (all but
// PostureInsecureLAN), a Domain or a Path other than "/". The 4096 bytes of
// name and value stay the caller's, since Validate never sees the value.
func (c *CookieConfig) Validate() error {
	if c.Posture < PostureSecure || c.Posture > PosturePerRequest {
		return fmt.Errorf("access: CookieConfig.Posture %v is not a declared posture", c.Posture)
	}
	probe := &http.Cookie{Name: c.EffectiveName(), Value: "x", Path: c.Path, Domain: c.Domain} //nolint:gosec // G124: a validation probe, never sent
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
	// A browser ignores a Path that does not start with "/" (RFC 6265 §5.2.4).
	if c.Path != "" && c.Path[0] != '/' {
		return errors.New("access: CookieConfig.Path must start with \"/\"")
	}
	if len(c.Path) > maxCookiePath {
		return fmt.Errorf("access: CookieConfig.Path must be at most %d bytes", maxCookiePath)
	}
	if !validSameSite(c.SameSite) {
		return errors.New("access: CookieConfig.SameSite must be unset, Lax or Strict")
	}
	if c.Posture == PosturePerRequest && c.HTTPS == nil {
		return errors.New("access: CookieConfig.HTTPS is required under PosturePerRequest; pass access.RequestIsHTTPS")
	}
	return c.validateHostPrefix()
}

func (c *CookieConfig) validateHostPrefix() error {
	if !c.usesHostPrefix() {
		return nil
	}
	if c.Domain != "" {
		return errors.New("access: CookieConfig.Domain must be empty when the __Host- prefix is used (all postures except PostureInsecureLAN)")
	}
	if c.Path != "" && c.Path != "/" {
		return errors.New("access: CookieConfig.Path must be \"/\" when the __Host- prefix is used (all postures except PostureInsecureLAN)")
	}
	return nil
}
