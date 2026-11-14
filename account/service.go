package account

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/scopetoken"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// Service runs the account operations over one Store. Build it with New and
// stop it with Shutdown.
type Service struct {
	store   Store
	policy  Policy
	authn   *access.Authenticator
	hasher  hashing
	limiter *ratelimit.Limiter
	rp      func() *webauthn.RelyingParty
	oidc    func() *oidc.Provider
	rulesFn func() Rules
	onEvent func(Event)
	breach  *http.Client
	log     *slog.Logger
	clock   func() time.Time
	pending *pendingCache
	// allowance bounds the untrusted counted password attempts between two
	// failure-record prunes.
	allowance *allowance
	cancel    context.CancelFunc
	done      chan struct{}
	hooks     testHooks
	// failureKey is Config.FailureKey, masked; it is revealed only to build
	// each failure-record HMAC, so no field holds the key or a keyed HMAC.
	failureKey  access.Secret
	adminScope  string
	usersScope  string
	keysScope   string
	interval    time.Duration
	logMaxAge   time.Duration
	logChanges  int
	logSessions int
	closed      atomic.Bool
}

// testHooks are set only from export_test.go; every nil hook is skipped.
type testHooks struct {
	// wrapHasher wraps Config.Hasher, to count its derivations.
	wrapHasher func(hashing) hashing
	// betweenSessionCalls runs on the sweep goroutine after a full
	// CleanupExpiredSessions call's events are dispatched, before the next.
	betweenSessionCalls func(ctx context.Context)
	// failureSweep runs before every failure-record leg, New's included.
	failureSweep func(ctx context.Context)
	// admitted runs once a counted attempt holds its permit and slot, before
	// its context check.
	admitted func(ctx context.Context)
	// beforeVerify runs after the count Update committed, before Verify.
	beforeVerify func(ctx context.Context)
	// afterVerify runs once Verify returned true, before the rehash.
	afterVerify func(ctx context.Context)
}

// New refuses a nil Store, Policy, Authenticator, Hasher, Limiter or Rules,
// a FailureKey that is not 32 bytes (naming the field, never the bytes), a
// non-empty AdminScope, ManageUsersScope or CreateKeysScope that is not one
// RFC 6750 scope-token, two equal non-empty ones, a negative CleanupInterval, MaxPending or Log* field, and
// a Rules() value Rules.Validate refuses or whose breach mode lacks
// Config.Breach. It drains the security log to its caps and LogMaxAge and
// runs the failure-record sweep, returning either's store error, then
// sweeps on ctx's values, not its cancellation, until Shutdown.
func New(ctx context.Context, cfg Config) (*Service, error) { //nolint:gocritic // hugeParam: a construction input, read once
	return newService(ctx, cfg, testHooks{})
}

func newService(ctx context.Context, cfg Config, hooks testHooks) (*Service, error) { //nolint:gocritic // hugeParam: as New
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	s := &Service{
		store:       cfg.Store,
		policy:      cfg.Policy,
		authn:       cfg.Authenticator,
		hasher:      hasherOf{cfg.Hasher},
		limiter:     cfg.Limiter,
		rp:          cfg.RP,
		oidc:        cfg.OIDC,
		rulesFn:     cfg.Rules,
		onEvent:     cfg.OnEvent,
		breach:      cfg.Breach,
		log:         cfg.Logger,
		clock:       cfg.Now,
		hooks:       hooks,
		adminScope:  cfg.AdminScope,
		usersScope:  cfg.ManageUsersScope,
		keysScope:   cfg.CreateKeysScope,
		failureKey:  access.NewSecret(string(cfg.FailureKey)),
		interval:    cfg.CleanupInterval,
		logMaxAge:   cmp.Or(cfg.LogMaxAge, DefaultLogMaxAge),
		logChanges:  cmp.Or(cfg.LogMaxChanges, DefaultLogMaxChanges),
		logSessions: cmp.Or(cfg.LogMaxSessions, DefaultLogMaxSessions),
		done:        make(chan struct{}),
		allowance:   newAllowance(),
	}
	if hooks.wrapHasher != nil {
		s.hasher = hooks.wrapHasher(s.hasher)
	}
	if s.interval == 0 {
		s.interval = defaultCleanupInterval
	}
	maxPending := cfg.MaxPending
	if maxPending == 0 {
		maxPending = defaultMaxPending
	}
	s.pending = newPendingCache(maxPending)
	if err := s.checkRules(cfg.Rules()); err != nil {
		return nil, err
	}
	if err := s.drainLog(ctx); err != nil {
		return nil, err
	}
	if err := s.sweepFailures(ctx); err != nil {
		return nil, err
	}
	sweepCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	s.cancel = cancel
	go s.run(sweepCtx)
	return s, nil
}

// validateScopes refuses a set scope that is not one scope-token, and two
// equal set scopes.
func validateScopes(admin, users, keys string) error {
	scopes := map[string]string{}
	for _, f := range []struct{ name, scope string }{
		{"AdminScope", admin},
		{"ManageUsersScope", users},
		{"CreateKeysScope", keys},
	} {
		if f.scope == "" {
			continue
		}
		if !scopetoken.Valid(f.scope) {
			return fmt.Errorf("account: Config.%s %q is not an RFC 6750 scope-token", f.name, f.scope)
		}
		if other, dup := scopes[f.scope]; dup {
			return fmt.Errorf("account: Config.%s equals Config.%s; no scope may grant another", f.name, other)
		}
		scopes[f.scope] = f.name
	}
	return nil
}

func validateConfig(cfg Config) error { //nolint:gocritic // hugeParam: as New
	for _, f := range []struct {
		v    any
		name string
	}{
		{cfg.Store, "Store"},
		{cfg.Policy, "Policy"},
		{cfg.Authenticator, "Authenticator"},
		{cfg.Hasher, "Hasher"},
		{cfg.Limiter, "Limiter"},
		{cfg.Rules, "Rules"},
	} {
		if isNil(f.v) {
			return fmt.Errorf("account: Config.%s is nil", f.name)
		}
	}
	if len(cfg.FailureKey) != failureKeySize {
		return fmt.Errorf("account: Config.FailureKey is %d bytes, want %d", len(cfg.FailureKey), failureKeySize)
	}
	if err := validateScopes(cfg.AdminScope, cfg.ManageUsersScope, cfg.CreateKeysScope); err != nil {
		return err
	}
	if cfg.CleanupInterval < 0 {
		return fmt.Errorf("account: Config.CleanupInterval must not be negative, got %s", cfg.CleanupInterval)
	}
	if cfg.MaxPending < 0 {
		return fmt.Errorf("account: Config.MaxPending must not be negative, got %d", cfg.MaxPending)
	}
	if cfg.LogMaxAge < 0 {
		return fmt.Errorf("account: Config.LogMaxAge must not be negative, got %s", cfg.LogMaxAge)
	}
	for _, f := range []struct {
		name string
		v    int
	}{{"LogMaxChanges", cfg.LogMaxChanges}, {"LogMaxSessions", cfg.LogMaxSessions}} {
		if f.v < 0 {
			return fmt.Errorf("account: Config.%s must not be negative, got %d", f.name, f.v)
		}
	}
	return nil
}

// isNil reports a nil v, or one holding a nil pointer, map, slice, func or
// chan, so a typed nil fails at New and not at the first operation.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}

// Shutdown stops the sweep and waits for a sweep in progress, or returns
// ctx's error when ctx ends first; the sweep then still dispatches the
// events of a cleanup call that returned and stops before the next. Every
// operation called after Shutdown begins returns ErrServiceClosed. A second
// Shutdown waits the same way.
func (s *Service) Shutdown(ctx context.Context) error {
	s.closed.Store(true)
	s.cancel()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// OIDCProvider resolves Config.OIDC once; nil means OIDC is off. accesshttp
// calls it once per OIDC request, so a provider swapped by the app is used
// from the next request on.
func (s *Service) OIDCProvider() *oidc.Provider {
	if s.oidc == nil {
		return nil
	}
	return s.oidc()
}

// Authenticator returns Config.Authenticator.
func (s *Service) Authenticator() *access.Authenticator { return s.authn }

// AdminScope returns Config.AdminScope.
func (s *Service) AdminScope() string { return s.adminScope }

// ManageUsersScope returns Config.ManageUsersScope.
func (s *Service) ManageUsersScope() string { return s.usersScope }

// CreateKeysScope returns Config.CreateKeysScope.
func (s *Service) CreateKeysScope() string { return s.keysScope }

// RequireRecentAuth is access.RequireRecentAuth with the current
// Rules().RecentAuth and Config.Now; accesshttp's recent_auth guard calls it.
// An invalid Rules() value is ErrRulesInvalid.
func (s *Service) RequireRecentAuth(p access.Principal) error { //nolint:gocritic // hugeParam: callers pass the Principal Authenticate returned
	r, err := s.begin()
	if err != nil {
		return err
	}
	return s.recentAuth(r, p)
}

func (s *Service) recentAuth(r Rules, p access.Principal) error { //nolint:gocritic // hugeParam: the operation's one Rules value and its Principal
	return access.RequireRecentAuth(p, r.RecentAuth, s.now())
}

// RequireAdminScope admits p to the admin-scope operations: nil for a full
// session, or for a principal the built-in API-key verifier produced
// (access.Principal.IsAPIKey) carrying Config.AdminScope when that is set.
// Otherwise ErrSessionRequired for a recovery session or when AdminScope is
// empty, and ErrScopeRequired.
func (s *Service) RequireAdminScope(p access.Principal) error { //nolint:gocritic // hugeParam: as RequireRecentAuth
	if s.closed.Load() {
		return ErrServiceClosed
	}
	return s.admitKey(p, s.adminScope, func() error { return nil })
}

// RequireKeyPermission admits p to an operation that scope opens to keys:
// nil for a full session within Rules().RecentAuth, or for a built-in
// API-key principal (access.Principal.IsAPIKey) carrying scope when scope is
// non-empty. Otherwise the session answers of RequireRecentAuth
// (ErrSessionRequired, ErrRecentAuthRequired), and ErrScopeRequired for a
// key, a custom verifier's principal or a bypass principal when scope is
// set. It reads the request's principal only: the write it guards
// re-checks a key's authority inside its Update.
func (s *Service) RequireKeyPermission(p access.Principal, scope string) error { //nolint:gocritic // hugeParam: as RequireRecentAuth
	r, err := s.begin()
	if err != nil {
		return err
	}
	return s.admitKey(p, scope, func() error { return s.recentAuth(r, p) })
}

// admitKey is the one shape of both guards: a full session gets session's
// answer, a recovery session and an empty scope ErrSessionRequired, a key
// carrying scope nil, and anything else ErrScopeRequired.
func (*Service) admitKey(p access.Principal, scope string, session func() error) error { //nolint:gocritic // hugeParam: as RequireRecentAuth
	switch {
	case p.IsSession():
		return session()
	case p.IsRecoverySession(), scope == "":
		return ErrSessionRequired
	case p.IsAPIKey() && p.HasScope(scope):
		return nil
	default:
		return ErrScopeRequired
	}
}

// admitPermission is RequireKeyPermission under scope for a's principal,
// then the principal's user: the zero Actor and a principal naming no user
// are ErrSessionRequired.
func (s *Service) admitPermission(r Rules, a Actor, scope string) (access.Principal, error) { //nolint:gocritic // hugeParam: the operation's one Rules value and its Actor
	p, ok := a.Principal()
	if !ok {
		return access.Principal{}, ErrSessionRequired
	}
	if err := s.admitKey(p, scope, func() error { return s.recentAuth(r, p) }); err != nil {
		return access.Principal{}, err
	}
	if p.User == nil {
		return access.Principal{}, ErrSessionRequired
	}
	return p, nil
}

// begin is the first call of every operation: ErrServiceClosed after
// Shutdown began, else the one Rules value the operation uses throughout,
// with its defaults applied. An invalid value fails the operation closed,
// logged at ERROR; no earlier value is reused.
func (s *Service) begin() (Rules, error) {
	if s.closed.Load() {
		return Rules{}, ErrServiceClosed
	}
	r := s.rulesFn()
	if err := s.checkRules(r); err != nil {
		s.logger().Error("account: Config.Rules returned invalid rules; the operation is refused", "err", err)
		return Rules{}, err
	}
	return r.withDefaults(), nil
}

// checkRules is Rules.Validate plus the one rule Validate cannot see: a
// breach mode needs Config.Breach.
func (s *Service) checkRules(r Rules) error { //nolint:gocritic // hugeParam: as Rules.Validate
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Breach != BreachOff && s.breach == nil {
		return &RulesError{Field: "Breach", Reason: "a breach mode needs Config.Breach"}
	}
	return nil
}

func (s *Service) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// stamp is now truncated to the millisecond, the precision a conforming
// store round-trips a time at. A time account stores and later compares
// with Equal is created here, or a millisecond store makes it unequal to
// itself.
func (s *Service) stamp() time.Time { return s.now().Truncate(time.Millisecond) }

// logCap is class's entry cap; a class with none gets 0, a LogPrune every
// store refuses, so a new class fails loudly until it has a cap.
func (s *Service) logCap(class LogClass) int {
	switch class {
	case LogClassChange:
		return s.logChanges
	case LogClassSession:
		return s.logSessions
	}
	return 0
}

func (s *Service) logger() *slog.Logger {
	if s.log != nil {
		return s.log
	}
	return slog.Default()
}
