package account_test

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"golang.org/x/text/unicode/norm"
)

const goodPassword = "correct-horse-battery-7"

var localClient = account.Client{
	IP:        netip.MustParseAddr("192.168.1.20"),
	Peer:      netip.MustParseAddr("192.168.1.20"),
	Host:      "nas.lan:8374",
	UserAgent: "test-agent",
}

// busyHasher is a Hasher whose whole budget a held permit takes: every Hash
// it is asked for returns access.ErrHashBusy after a 1 ms wait, so an
// operation that returns any other error hashed nothing.
func busyHasher(t *testing.T) *access.Hasher {
	t.Helper()
	budget, err := access.NewHashBudget(access.HashCost(access.DefaultArgon2Params()))
	if err != nil {
		t.Fatalf("NewHashBudget: %v", err)
	}
	h, err := access.NewHasher(access.HasherConfig{Budget: budget, Wait: time.Millisecond})
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	permit, err := h.Reserve(t.Context())
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	t.Cleanup(permit.Release)
	return h
}

func withBusyHasher(t *testing.T) func(*account.Config) {
	h := busyHasher(t)
	return func(c *account.Config) { c.Hasher = h }
}

func tokenless(context.Context, account.Client) bool { return false }

func rulesWith(edit func(*account.Rules)) func() account.Rules {
	return func() account.Rules {
		var r account.Rules
		edit(&r)
		return r
	}
}

func userCount(t *testing.T, f *fixture) int {
	t.Helper()
	n, err := f.mem.UserCount(t.Context())
	if err != nil {
		t.Fatalf("UserCount: %v", err)
	}
	return n
}

func issueSetupToken(t *testing.T, f *fixture) access.Secret {
	t.Helper()
	tok, err := f.svc.IssueSetupToken(t.Context(), account.OutOfBand("socket"), 0)
	if err != nil {
		t.Fatalf("IssueSetupToken: %v", err)
	}
	return tok
}

func TestSetupOrderNoHashBeforeChecks(t *testing.T) {
	t.Parallel()
	in := account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)}
	t.Run("user_present", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.SetupTokenRequired = tokenless }), edit: withBusyHasher(t)})
		mustUser(t, f.mem, "first", access.RoleAdmin)
		if _, err := f.svc.SetupWithPassword(t.Context(), localClient, in); !errors.Is(err, account.ErrSetupComplete) {
			t.Errorf("setup with a user present = %v, want ErrSetupComplete before any hash", err)
		}
	})
	t.Run("missing_token", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{edit: withBusyHasher(t)})
		if _, err := f.svc.SetupWithPassword(t.Context(), localClient, in); !errors.Is(err, account.ErrSetupTokenRequired) {
			t.Errorf("setup with no token = %v, want ErrSetupTokenRequired before any hash", err)
		}
	})
	t.Run("unknown_token", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{edit: withBusyHasher(t)})
		bad := in
		bad.Token = access.NewSecret("not-a-token")
		if _, err := f.svc.SetupWithPassword(t.Context(), localClient, bad); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("setup with an unknown token = %v, want access.ErrTokenInvalid before any hash", err)
		}
	})
	t.Run("expired_token", func(t *testing.T) {
		t.Parallel()
		clock := newTestClock(time.Now())
		f := newFixture(t, options{edit: func(c *account.Config) { withBusyHasher(t)(c); c.Now = clock.now }})
		tok := issueSetupToken(t, f)
		clock.add(24 * time.Hour)
		bad := in
		bad.Token = tok
		if _, err := f.svc.SetupWithPassword(t.Context(), localClient, bad); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("setup with an expired token = %v, want access.ErrTokenInvalid", err)
		}
	})
	t.Run("refused_admission", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.SetupTokenRequired = tokenless }), edit: func(c *account.Config) {
			withBusyHasher(t)(c)
			lc := ratelimit.DefaultConfig()
			lc.Devices = access.NewEphemeralSealer()
			lc.IP = ratelimit.Rate{Limit: 1, Window: time.Hour}
			l, err := ratelimit.New(t.Context(), lc)
			if err != nil {
				t.Fatalf("ratelimit.New: %v", err)
			}
			res, err := l.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(localClient.IP)})
			if err != nil {
				t.Fatalf("Attempt: %v", err)
			}
			res.Fail()
			c.Limiter = l
		}})
		if _, err := f.svc.SetupWithPassword(t.Context(), localClient, in); !errors.Is(err, ratelimit.ErrRefused) {
			t.Errorf("setup from a refused IP = %v, want a ratelimit refusal before any hash", err)
		}
	})
	t.Run("busy_hash_cancels", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.SetupTokenRequired = tokenless }), edit: withBusyHasher(t)})
		for range 12 {
			if _, err := f.svc.SetupWithPassword(t.Context(), localClient, in); !errors.Is(err, access.ErrHashBusy) {
				t.Fatalf("setup under a held budget = %v, want access.ErrHashBusy", err)
			}
		}
		if n := userCount(t, f); n != 0 {
			t.Errorf("users after busy setups = %d, want 0", n)
		}
	})
	t.Run("signs_in", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.SetupTokenRequired = tokenless })})
		got, err := f.svc.SetupWithPassword(t.Context(), localClient, account.SetupPassword{Username: "Owner", Password: access.NewSecret(goodPassword)})
		if err != nil {
			t.Fatalf("SetupWithPassword: %v", err)
		}
		if got.User.Username != "owner" || got.User.Role != access.RoleAdmin || !got.User.Enabled || got.User.PasswordHash.IsZero() {
			t.Errorf("setup user = %+v, want an enabled admin named owner with a password", got.User)
		}
		if got.Token.IsZero() || got.DeviceCookie.IsZero() || !access.SessionHash(got.Token.Reveal()).Equal(got.Session.TokenHash) {
			t.Errorf("setup returned token %v and device cookie %v, want the session's token and a device cookie", got.Token, got.DeviceCookie)
		}
		if _, found, err := f.mem.SessionByHash(t.Context(), got.Session.TokenHash); err != nil || !found {
			t.Errorf("the setup session is not stored: %v, %t", err, found)
		}
		evs := f.events.all()
		if len(evs) != 1 || evs[0].Kind != account.EventSignedIn || evs[0].UserID != got.User.ID || evs[0].Method != access.MethodPassword {
			t.Errorf("events = %+v, want one EventSignedIn", evs)
		}
		st, err := f.svc.State(t.Context())
		if err != nil || st.SetupRequired || !st.PasswordLogin || st.Passkeys || st.OIDC {
			t.Errorf("State after setup = %+v, %v, want setup done and only password sign-in", st, err)
		}
	})
}

func TestSetupProvenance(t *testing.T) {
	t.Parallel()
	var seen []account.Client
	var mu sync.Mutex
	// The app's predicate: a token whenever the resolver ignored a
	// forwarding header or the client is public.
	predicate := func(_ context.Context, c account.Client) bool {
		mu.Lock()
		seen = append(seen, c)
		mu.Unlock()
		return c.UntrustedForwarding || !c.IP.IsPrivate()
	}
	f := newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.SetupTokenRequired = predicate }), edit: withBusyHasher(t)})
	in := account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)}
	forwarded := localClient
	forwarded.UntrustedForwarding = true
	if _, err := f.svc.SetupWithPassword(t.Context(), forwarded, in); !errors.Is(err, account.ErrSetupTokenRequired) {
		t.Errorf("setup from a private peer with an ignored forwarding header = %v, want ErrSetupTokenRequired with no hash", err)
	}
	public := localClient
	public.IP = netip.MustParseAddr("203.0.113.9")
	if _, err := f.svc.SetupWithPassword(t.Context(), public, in); !errors.Is(err, account.ErrSetupTokenRequired) {
		t.Errorf("setup from a public IP = %v, want ErrSetupTokenRequired", err)
	}
	if _, err := f.svc.SetupWithPassword(t.Context(), localClient, in); !errors.Is(err, access.ErrHashBusy) {
		t.Errorf("setup from a direct private peer = %v, want it past the token rule (to the held hash)", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 || !sameClient(seen[0], forwarded) || !sameClient(seen[1], public) || !sameClient(seen[2], localClient) {
		t.Errorf("the predicate saw %+v, want exactly the three Clients", seen)
	}
}

// sameClient compares every field of two Clients, the device cookie by its
// revealed text.
func sameClient(a, b account.Client) bool {
	return a.ClientAddr == b.ClientAddr && a.Host == b.Host && a.UserAgent == b.UserAgent && a.Device.Reveal() == b.Device.Reveal()
}

// patientHasher waits out a full hash budget, so concurrent setups on a
// loaded host race on the user count and the token, never on ErrHashBusy.
func patientHasher(t *testing.T) func(*account.Config) {
	t.Helper()
	h, err := access.NewHasher(access.HasherConfig{Params: fastParams, Wait: time.Minute})
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	return func(c *account.Config) { c.Hasher = h }
}

func TestConcurrentSetups(t *testing.T) {
	t.Parallel()
	const n = 6
	run := func(t *testing.T, f *fixture, in func(i int) account.SetupPassword) {
		t.Helper()
		var wg sync.WaitGroup
		var won atomic.Int32
		errs := make([]error, n)
		for i := range n {
			wg.Go(func() {
				c := localClient
				c.IP = netip.AddrFrom4([4]byte{192, 168, 2, byte(i + 1)})
				if _, err := f.svc.SetupWithPassword(t.Context(), c, in(i)); err == nil {
					won.Add(1)
				} else {
					errs[i] = err
				}
			})
		}
		wg.Wait()
		if won.Load() != 1 {
			t.Errorf("%d setups succeeded, want exactly 1 (errors %v)", won.Load(), errs)
		}
		for _, err := range errs {
			if err != nil && !errors.Is(err, account.ErrSetupComplete) && !errors.Is(err, access.ErrTokenInvalid) {
				t.Errorf("a losing setup = %v, want ErrSetupComplete or access.ErrTokenInvalid", err)
			}
		}
		if got := userCount(t, f); got != 1 {
			t.Errorf("users = %d, want one owner", got)
		}
	}
	t.Run("tokenless", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.SetupTokenRequired = tokenless }), edit: patientHasher(t)})
		run(t, f, func(i int) account.SetupPassword {
			return account.SetupPassword{Username: fmt.Sprintf("owner%d", i), Password: access.NewSecret(goodPassword)}
		})
	})
	t.Run("tokened", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{edit: patientHasher(t)})
		tok := issueSetupToken(t, f)
		run(t, f, func(i int) account.SetupPassword {
			return account.SetupPassword{Token: tok, Username: fmt.Sprintf("owner%d", i), Password: access.NewSecret(goodPassword)}
		})
	})
}

// recordingPolicy records every decision and answers it with inner, or
// allows it when inner is nil.
type recordingPolicy struct {
	inner     account.Policy
	decisions []account.Decision
	mu        sync.Mutex
}

func (p *recordingPolicy) Authorize(ctx context.Context, d account.Decision) error {
	p.mu.Lock()
	p.decisions = append(p.decisions, d)
	p.mu.Unlock()
	if p.inner == nil {
		return nil
	}
	return p.inner.Authorize(ctx, d)
}

// taken returns the decisions recorded so far.
func (p *recordingPolicy) taken() []account.Decision {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.decisions)
}

func (p *recordingPolicy) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.decisions)
}

func TestIssueSetupToken(t *testing.T) {
	t.Parallel()
	pol := &recordingPolicy{}
	start := time.Now().Truncate(time.Millisecond)
	f := newFixture(t, options{edit: func(c *account.Config) {
		c.Policy = pol
		c.Now = func() time.Time { return start }
	}})
	ctx := t.Context()
	oob := account.OutOfBand("socket")
	first := issueSetupToken(t, f)
	second, err := f.svc.IssueSetupToken(ctx, oob, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueSetupToken(7 × 24h) = %v, want nil", err)
	}
	if pol.calls() != 0 {
		t.Errorf("IssueSetupToken asked the Policy %d times, want 0", pol.calls())
	}
	if _, found, _ := f.mem.OneTimeTokenByHash(ctx, access.NewHash(access.HexSHA256(first.Reveal()))); found {
		t.Error("an earlier setup token survives a new one")
	}
	tok, found, err := f.mem.OneTimeTokenByHash(ctx, access.NewHash(access.HexSHA256(second.Reveal())))
	if err != nil || !found || tok.Purpose != access.PurposeSetup || !tok.ExpiresAt.Equal(start.Add(7*24*time.Hour)) {
		t.Errorf("stored setup token = %+v, %t, %v, want a setup token expiring in 7 × 24h", tok, found, err)
	}
	if evs := f.events.all(); len(evs) != 2 || evs[1].Kind != account.EventSetupTokenIssued || evs[1].Actor.OutOfBand != "socket" {
		t.Errorf("events = %+v, want two EventSetupTokenIssued from socket", evs)
	}
	if _, err := f.svc.IssueSetupToken(ctx, oob, 7*24*time.Hour+time.Nanosecond); !errors.Is(err, account.ErrTTLTooLong) || !strings.HasSuffix(err.Error(), "is above 168h0m0s") {
		t.Errorf("IssueSetupToken(above 7 × 24h) = %v, want ErrTTLTooLong naming the 168h bound", err)
	}
	if _, err := f.svc.IssueSetupToken(ctx, oob, -time.Second); !errors.Is(err, account.ErrTTLNegative) {
		t.Errorf("IssueSetupToken(negative ttl) = %v, want ErrTTLNegative", err)
	}
	t.Run("default_ttl", func(t *testing.T) {
		g := newFixture(t, options{edit: func(c *account.Config) { c.Now = func() time.Time { return start } }})
		plain := issueSetupToken(t, g)
		tok, _, _ := g.mem.OneTimeTokenByHash(ctx, access.NewHash(access.HexSHA256(plain.Reveal())))
		if !tok.ExpiresAt.Equal(start.Add(24 * time.Hour)) {
			t.Errorf("default setup token expires at %v, want 24h after issue", tok.ExpiresAt)
		}
	})
	u := mustUser(t, f.mem, "admin", access.RoleAdmin)
	for name, a := range map[string]account.Actor{
		"principal": account.As(f.sessionPrincipal(t, u, access.SessionFull, time.Now())),
		"zero":      {},
	} {
		_, err := f.svc.IssueSetupToken(ctx, a, 0)
		var pe *account.PolicyError
		if !errors.As(err, &pe) || pe.Reason != "out_of_band_only" || !errors.Is(err, account.ErrPolicyRefused) {
			t.Errorf("IssueSetupToken from %s = %v, want out_of_band_only", name, err)
		}
	}
	if _, err := f.svc.IssueSetupToken(ctx, oob, 0); !errors.Is(err, account.ErrSetupComplete) {
		t.Errorf("IssueSetupToken with a user present = %v, want ErrSetupComplete", err)
	}
	if pol.calls() != 0 {
		t.Errorf("IssueSetupToken asked the Policy %d times, want 0", pol.calls())
	}
}

// failingSessions is a Store whose Update callbacks see a CreateSession
// that fails, so the whole Update rolls back.
type failingSessions struct{ account.Store }

func (s failingSessions) Update(ctx context.Context, fn func(account.Tx) error) error {
	return s.Store.Update(ctx, func(tx account.Tx) error { return fn(failingSessionTx{tx}) })
}

type failingSessionTx struct{ account.Tx }

func (failingSessionTx) CreateSession(context.Context, *access.Session) error {
	return errors.New("disk full")
}

func TestSetupBackendErrorKeepsToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{edit: func(c *account.Config) { c.Store = failingSessions{c.Store} }})
	tok := issueSetupToken(t, f)
	in := account.SetupPassword{Token: tok, Username: "owner", Password: access.NewSecret(goodPassword)}
	if _, err := f.svc.SetupWithPassword(t.Context(), localClient, in); !errors.Is(err, access.ErrAuthBackend) {
		t.Fatalf("setup whose session write fails = %v, want access.ErrAuthBackend", err)
	}
	if n := userCount(t, f); n != 0 {
		t.Errorf("users after a failed setup = %d, want 0", n)
	}
	if _, found, _ := f.mem.OneTimeTokenByHash(t.Context(), access.NewHash(access.HexSHA256(tok.Reveal()))); !found {
		t.Error("the setup token was spent by a setup that rolled back")
	}
	if evs := f.events.all(); len(evs) != 1 {
		t.Errorf("events = %+v, want only the token's issue", evs)
	}
}

func TestUsernameRuleEveryCreationPath(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("é", account.MaxUsernameLength+1)
	limit := strings.Repeat("é", account.MaxUsernameLength)
	// errNotLinked is the JIT path's NotLinked outcome, the one answer
	// OIDCComplete gives a refused name as any other unprovisioned identity.
	errNotLinked := errors.New("not linked")
	usernameRefused := func(err error, reason string) bool {
		var ue *account.UsernameError
		return errors.As(err, &ue) && ue.Reason == reason
	}
	type path struct {
		create  func(t *testing.T, f *fixture, rig *oidcRig, name string) (*access.User, error)
		refused func(err error, reason string) bool // nil: usernameRefused
		name    string
	}
	paths := []path{
		{name: "setup", create: func(t *testing.T, f *fixture, _ *oidcRig, name string) (*access.User, error) {
			got, err := f.svc.SetupWithPassword(t.Context(), localClient, account.SetupPassword{Username: name, Password: access.NewSecret(goodPassword)})
			return got.User, err
		}},
		{name: "admin_create", create: func(t *testing.T, f *fixture, _ *oidcRig, name string) (*access.User, error) {
			return f.svc.CreateUser(t.Context(), account.OutOfBand("socket"), account.NewUser{Username: name, Password: access.NewSecret(goodPassword)})
		}},
		{name: "invite", create: func(t *testing.T, f *fixture, _ *oidcRig, name string) (*access.User, error) {
			admin := mustUser(t, f.mem, "inviter", access.RoleAdmin)
			inv, err := f.svc.CreateInvite(t.Context(), f.sessionPrincipal(t, admin, access.SessionFull, time.Now()), access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite = %v", err)
			}
			got, err := f.accept(t, inv.Plaintext, name)
			return got.User, err
		}},
		{name: "jit", refused: func(err error, _ string) bool { return errors.Is(err, errNotLinked) }, create: func(t *testing.T, f *fixture, rig *oidcRig, name string) (*access.User, error) {
			mustUser(t, f.mem, "owner", access.RoleAdmin)
			flow, claims := rig.signInFlow(t)
			claims.PreferredUsername = name
			if name == "" {
				// With no preferred_username, UsernameCandidate takes the
				// verified email; without it there is no name at all.
				claims.Email = ""
			}
			out, err := f.svc.OIDCComplete(t.Context(), localClient, flow, claims)
			if err == nil && out.Kind == account.OutcomeNotLinked {
				return nil, errNotLinked
			}
			return out.SignedIn.User, err
		}},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			rig := newOIDCRig(t, accesstest.IdPOptions{})
			rules := rulesWith(func(r *account.Rules) {
				r.SetupTokenRequired = tokenless
				r.Provisioning = oidc.Provisioning{Enabled: true}
			})
			refused := p.refused
			if refused == nil {
				refused = usernameRefused
			}
			for name, tc := range map[string]struct {
				username, reason string
			}{
				"empty":    {username: "", reason: "empty"},
				"space":    {username: "two words", reason: "disallowed_character"},
				"too_long": {username: long, reason: "too_long"},
			} {
				// A held hash budget and an exhausted limiter would each
				// answer first if the rule ran after them.
				f := newFixture(t, options{rules: rules, edit: func(c *account.Config) {
					rig.withOIDC(c)
					withBusyHasher(t)(c)
					lc := ratelimit.DefaultConfig()
					lc.Devices = access.NewEphemeralSealer()
					lc.IP = ratelimit.Rate{Limit: 1, Window: time.Hour}
					l, err := ratelimit.New(t.Context(), lc)
					if err != nil {
						t.Fatalf("ratelimit.New: %v", err)
					}
					res, _ := l.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(localClient.IP)})
					res.Fail()
					c.Limiter = l
				}})
				if _, err := p.create(t, f, rig, tc.username); !refused(err, tc.reason) {
					t.Errorf("%s: error = %v, want the %s refusal before the limiter and the hash", name, err, tc.reason)
				}
			}
			f := newFixture(t, options{rules: rules, edit: rig.withOIDC})
			canonical, err := access.NormalizeUsername(limit)
			if err != nil {
				t.Fatalf("NormalizeUsername: %v", err)
			}
			stale := account.FailureCount{Count: 7}
			stale.Name, stale.Method = account.FailureName(f.svc, canonical), access.MethodPassword
			if err := f.mem.PutAuthFailure(t.Context(), stale); err != nil {
				t.Fatalf("PutAuthFailure: %v", err)
			}
			u, err := p.create(t, f, rig, limit)
			if err != nil {
				t.Fatalf("a %d-rune username: %v", account.MaxUsernameLength, err)
			}
			if utf8.RuneCountInString(u.Username) != account.MaxUsernameLength {
				t.Errorf("stored username %q, want %d runes", u.Username, account.MaxUsernameLength)
			}
			if _, found, _ := f.mem.AuthFailure(t.Context(), stale.FailureRef); found {
				t.Error("the new name's failure record survives its creation")
			}
		})
	}
}

func TestPasswordRuleBlocklist(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.SetupTokenRequired = tokenless; r.ForbiddenWords = []string{"examplesite"} })})
	for name, tc := range map[string]struct {
		password, reason string
	}{
		"common":    {password: "qazwsxedcrfvtgb", reason: "common"},
		"too_short": {password: "short", reason: "too_short"},
		"username":  {password: "owner-owner-owner", reason: "contains_username"},
		"forbidden": {password: "examplesite2026!", reason: "contains_forbidden_word"},
	} {
		for path, err := range map[string]error{
			"setup": func() error {
				_, err := f.svc.SetupWithPassword(t.Context(), localClient, account.SetupPassword{Username: "owner", Password: access.NewSecret(tc.password)})
				return err
			}(),
			"admin_create": func() error {
				_, err := f.svc.CreateUser(t.Context(), account.OutOfBand("socket"), account.NewUser{Username: "owner", Password: access.NewSecret(tc.password)})
				return err
			}(),
		} {
			var pe *access.PasswordError
			if !errors.As(err, &pe) || string(pe.Reason) != tc.reason {
				t.Errorf("%s %s: error = %v, want *access.PasswordError{%s}", path, name, err, tc.reason)
			}
		}
	}
	if n := userCount(t, f); n != 0 {
		t.Errorf("users after refused passwords = %d, want 0", n)
	}
}

// hibp answers the breached-password API: a range listing breached's
// suffix, or err for every request when set.
type hibp struct {
	err      error
	breached string
	requests atomic.Int32
}

func (h *hibp) RoundTrip(req *http.Request) (*http.Response, error) {
	h.requests.Add(1)
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	if h.err != nil {
		return nil, h.err
	}
	sum := sha1.Sum([]byte(norm.NFC.String(h.breached)))
	hexSum := fmt.Sprintf("%X", sum)
	body := "0000000000000000000000000000000000A:1\r\n"
	if strings.HasSuffix(req.URL.Path, hexSum[:5]) {
		body += hexSum[5:] + ":42\r\n"
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: req}, nil
}

func TestBreachModes(t *testing.T) {
	t.Parallel()
	const breached = "this-one-leaked-2019"
	create := func(t *testing.T, ctx context.Context, f *fixture, pw string) error {
		t.Helper()
		_, err := f.svc.CreateUser(ctx, account.OutOfBand("socket"), account.NewUser{Username: "user" + fmt.Sprint(userCount(t, f)), Password: access.NewSecret(pw)})
		return err
	}
	fixtureFor := func(t *testing.T, mode account.BreachMode, h *hibp) *fixture {
		t.Helper()
		return newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.Breach = mode }), edit: func(c *account.Config) {
			c.Breach = &http.Client{Transport: h}
		}})
	}
	t.Run("off", func(t *testing.T) {
		t.Parallel()
		h := &hibp{breached: breached}
		f := fixtureFor(t, account.BreachOff, h)
		if err := create(t, t.Context(), f, breached); err != nil {
			t.Errorf("a breached password under BreachOff = %v, want accepted", err)
		}
		if h.requests.Load() != 0 {
			t.Errorf("BreachOff made %d breach requests, want 0", h.requests.Load())
		}
	})
	for _, mode := range []account.BreachMode{account.BreachFailOpen, account.BreachFailClosed} {
		t.Run(fmt.Sprintf("mode_%d", mode), func(t *testing.T) {
			t.Parallel()
			h := &hibp{breached: breached}
			f := fixtureFor(t, mode, h)
			err := create(t, t.Context(), f, breached)
			var pe *access.PasswordError
			if !errors.As(err, &pe) || pe.Reason != "breached" {
				t.Errorf("a breached password = %v, want *access.PasswordError{breached}", err)
			}
			if err := create(t, t.Context(), f, goodPassword); err != nil {
				t.Errorf("an unbreached password = %v, want accepted", err)
			}
			if n := userCount(t, f); n != 1 {
				t.Errorf("users = %d, want 1", n)
			}
		})
	}
	t.Run("fail_open_unavailable", func(t *testing.T) {
		t.Parallel()
		f := fixtureFor(t, account.BreachFailOpen, &hibp{err: errors.New("connection refused")})
		if err := create(t, t.Context(), f, goodPassword); err != nil {
			t.Errorf("an unjudged password under BreachFailOpen = %v, want accepted", err)
		}
		if n := warnings(f.logs); n != 1 {
			t.Errorf("BreachFailOpen logged %d WARN lines, want 1", n)
		}
	})
	t.Run("fail_closed_unavailable", func(t *testing.T) {
		t.Parallel()
		f := fixtureFor(t, account.BreachFailClosed, &hibp{err: errors.New("connection refused")})
		err := create(t, t.Context(), f, goodPassword)
		if !errors.Is(err, account.ErrBreachCheckUnavailable) || !errors.Is(err, access.ErrBreachCheckUnavailable) {
			t.Errorf("an unjudged password under BreachFailClosed = %v, want ErrBreachCheckUnavailable", err)
		}
		if n := userCount(t, f); n != 0 {
			t.Errorf("users = %d, want 0", n)
		}
	})
	// A caller whose request ended is not the breach service failing, so
	// fail-open does not accept it (errata E5).
	for name, tc := range map[string]struct {
		ctx  func(t *testing.T) context.Context
		want error
	}{
		"fail_open_cancelled": {want: context.Canceled, ctx: func(t *testing.T) context.Context {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			return ctx
		}},
		"fail_open_deadline": {want: context.DeadlineExceeded, ctx: func(t *testing.T) context.Context {
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			t.Cleanup(cancel)
			return ctx
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := fixtureFor(t, account.BreachFailOpen, &hibp{breached: breached})
			err := create(t, tc.ctx(t), f, goodPassword)
			if !errors.Is(err, tc.want) {
				t.Errorf("CreateUser on an ended context = %v, want %v", err, tc.want)
			}
			if n := warnings(f.logs); n != 0 {
				t.Errorf("an ended context logged %d WARN lines, want 0", n)
			}
			if n := userCount(t, f); n != 0 {
				t.Errorf("users = %d, want no store write", n)
			}
		})
	}
}

func TestCreateUserOutOfBand(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	f := newFixture(t, options{})
	oob := account.OutOfBand("admin-socket")
	u, err := f.svc.CreateUser(ctx, oob, account.NewUser{Username: "Alice", Password: access.NewSecret(goodPassword), Role: access.RoleAdmin})
	if err != nil {
		t.Fatalf("CreateUser(OutOfBand) = %v", err)
	}
	if u.Username != "alice" || u.Role != access.RoleAdmin || !u.Enabled || u.PasswordHash.IsZero() || len(u.WebAuthnHandle) != access.WebAuthnHandleSize {
		t.Errorf("created user = %+v, want an enabled admin alice with a password and a handle", u)
	}
	if evs := f.events.all(); len(evs) != 1 || evs[0].Kind != account.EventUserCreated || evs[0].UserID != u.ID || evs[0].Actor.OutOfBand != "admin-socket" {
		t.Errorf("events = %+v, want one EventUserCreated from admin-socket", evs)
	}
	nopw, err := f.svc.CreateUser(ctx, oob, account.NewUser{Username: "bob"})
	if err != nil || !nopw.PasswordHash.IsZero() || nopw.Role != access.RoleUser {
		t.Errorf("CreateUser(no password, no role) = %+v, %v, want a RoleUser with no password", nopw, err)
	}
	if _, err := f.svc.CreateUser(ctx, oob, account.NewUser{Username: "ALICE"}); !errors.Is(err, account.ErrUsernameTaken) {
		t.Errorf("CreateUser(a taken name) = %v, want ErrUsernameTaken", err)
	}
	t.Run("principals", func(t *testing.T) {
		admin := f.sessionPrincipal(t, u, access.SessionFull, time.Now())
		if _, err := f.svc.CreateUser(ctx, account.As(admin), account.NewUser{Username: "carol"}); err != nil {
			t.Errorf("CreateUser from a recent admin session = %v, want nil", err)
		}
		stale := f.sessionPrincipal(t, u, access.SessionFull, time.Now().Add(-time.Hour))
		if _, err := f.svc.CreateUser(ctx, account.As(stale), account.NewUser{Username: "dave"}); !errors.Is(err, access.ErrRecentAuthRequired) {
			t.Errorf("CreateUser from a stale session = %v, want access.ErrRecentAuthRequired", err)
		}
		user := f.sessionPrincipal(t, nopw, access.SessionFull, time.Now())
		if _, err := f.svc.CreateUser(ctx, account.As(user), account.NewUser{Username: "erin"}); !errors.Is(err, account.ErrPolicyRefused) {
			t.Errorf("CreateUser from a RoleUser session = %v, want ErrPolicyRefused", err)
		}
		if _, err := f.svc.CreateUser(ctx, account.As(f.bypassPrincipal(t)), account.NewUser{Username: "frank"}); !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("CreateUser from the bypass with ManageUsersScope empty = %v, want ErrSessionRequired", err)
		}
		for name, p := range map[string]access.Principal{
			"key":      f.keyPrincipal(t, u, "admin"),
			"recovery": f.sessionPrincipal(t, u, access.SessionRecovery, time.Now()),
		} {
			if _, err := f.svc.CreateUser(ctx, account.As(p), account.NewUser{Username: "gina"}); !errors.Is(err, account.ErrSessionRequired) {
				t.Errorf("CreateUser from a %s = %v, want ErrSessionRequired", name, err)
			}
		}
	})
	t.Run("anonymous", func(t *testing.T) {
		// A Policy that allows everything and a hasher that answers only
		// ErrHashBusy: ErrSessionRequired is account's own refusal, before
		// any hash, Policy call or write.
		pol := &recordingPolicy{}
		g := newFixture(t, options{edit: func(c *account.Config) { withBusyHasher(t)(c); c.Policy = pol }})
		_, err := g.svc.CreateUser(ctx, account.Actor{}, account.NewUser{Username: "hank", Password: access.NewSecret(goodPassword)})
		if !errors.Is(err, account.ErrSessionRequired) {
			t.Errorf("CreateUser from the zero Actor = %v, want ErrSessionRequired", err)
		}
		if n := pol.calls(); n != 0 {
			t.Errorf("Policy calls = %d, want 0", n)
		}
		if n := userCount(t, g); n != 0 {
			t.Errorf("users = %d, want no store write", n)
		}
	})
	t.Run("single_owner", func(t *testing.T) {
		g := newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.SetupTokenRequired = tokenless }), edit: func(c *account.Config) { c.Policy = account.SingleOwnerPolicy{} }})
		if _, err := g.svc.SetupWithPassword(ctx, localClient, account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)}); err != nil {
			t.Fatalf("setup under SingleOwnerPolicy: %v", err)
		}
		if _, err := g.svc.CreateUser(ctx, oob, account.NewUser{Username: "second", Password: access.NewSecret(goodPassword)}); !errors.Is(err, account.ErrPolicyRefused) {
			t.Errorf("a second user out of band under SingleOwnerPolicy = %v, want ErrPolicyRefused", err)
		}
		if _, err := g.svc.CreateUser(ctx, oob, account.NewUser{Username: "two words"}); !errors.As(err, new(*account.UsernameError)) {
			t.Errorf("an invalid name out of band = %v, want the username rule before the policy", err)
		}
		if n := userCount(t, g); n != 1 {
			t.Errorf("users = %d, want the owner only", n)
		}
	})
}

func TestSessionCapEvictsLeastRecent(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	f := newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.MaxSessionsPerUser = 3 })})
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	other := mustUser(t, f.mem, "bob", access.RoleUser)
	ids := putSessions(t, f,
		sessionSpec{user: u.ID, inactive: 10 * time.Minute},
		sessionSpec{user: u.ID, inactive: 30 * time.Minute},
		sessionSpec{user: u.ID, inactive: 20 * time.Minute},
		sessionSpec{user: other.ID, inactive: time.Hour})
	minted, err := account.MintSession(ctx, f.svc, localClient, u.ID)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	want := []string{ids[0], ids[2], minted.ID}
	got := sessionIDsOf(t, f, u.ID)
	if len(got) != 3 || !containsAll(got, want) {
		t.Errorf("sessions after the cap = %v, want %v: the least recently active goes", got, want)
	}
	if len(sessionIDsOf(t, f, other.ID)) != 1 {
		t.Error("another user's session was evicted")
	}
	evs := eventsOf(f.events, account.EventSessionRevoked)
	if len(evs) != 1 || evs[0].UserID != u.ID || len(evs[0].SessionIDs) != 1 || evs[0].SessionIDs[0] != ids[1] {
		t.Errorf("events = %+v, want one EventSessionRevoked for %s", evs, ids[1])
	}
	unlimited := newFixture(t, options{})
	w := mustUser(t, unlimited.mem, "carol", access.RoleUser)
	for range 5 {
		if _, err := account.MintSession(ctx, unlimited.svc, localClient, w.ID); err != nil {
			t.Fatalf("MintSession: %v", err)
		}
	}
	if n := len(sessionIDsOf(t, unlimited, w.ID)); n != 5 {
		t.Errorf("sessions with MaxSessionsPerUser 0 = %d, want 5", n)
	}
}

func containsAll(got, want []string) bool {
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			return false
		}
	}
	return true
}

func TestSessionMint(t *testing.T) {
	t.Parallel()
	f := newFixture(t, options{})
	u := mustUser(t, f.mem, "alice", access.RoleUser)
	c := localClient
	c.UserAgent = "Mozilla/5.0 \x1b[31m\u202eevil\u202c\na\u2028b\u2029c\xff" + strings.Repeat("é", 200)
	s, err := account.MintSession(t.Context(), f.svc, c, u.ID)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	if len(s.ID) != 32 || strings.Trim(s.ID, "0123456789abcdef") != "" {
		t.Errorf("session ID %q, want 128 bits of lower-case hex", s.ID)
	}
	const safe = "Mozilla/5.0 [31mevilabc"
	if want := safe + strings.Repeat("é", (256-len(safe))/len("é")); s.UserAgent != want {
		t.Errorf("stored user agent %q (%d bytes), want %q (%d bytes): controls, bidi, separators and invalid UTF-8 removed, cut at 256 bytes on a rune boundary", s.UserAgent, len(s.UserAgent), want, len(want))
	}
	for n, want := range map[int]int{256: 256, 257: 256} {
		ascii := c
		ascii.UserAgent = strings.Repeat("a", n)
		if s, err := account.MintSession(t.Context(), f.svc, ascii, u.ID); err != nil || s.UserAgent != strings.Repeat("a", want) {
			t.Errorf("a %d-byte ASCII agent stored as %d bytes (%v), want %d", n, len(s.UserAgent), err, want)
		}
	}
	if s.LastIP != "192.168.1.20" || s.UserID != u.ID || s.Kind != access.SessionFull || s.IdleCap != 0 || s.AbsoluteCap != 0 {
		t.Errorf("session = %+v, want LastIP 192.168.1.20, the user, a full session and no caps", s)
	}
	none := c
	none.IP = netip.Addr{}
	if s, _ := account.MintSession(t.Context(), f.svc, none, u.ID); s.LastIP != "" {
		t.Errorf("LastIP with no resolved IP = %q, want empty", s.LastIP)
	}
}

func TestSessionCapsAtCreation(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		caps              func(context.Context, account.Client) (time.Duration, time.Duration)
		wantIdle, wantAbs time.Duration
	}{
		"capped": {caps: func(context.Context, account.Client) (time.Duration, time.Duration) {
			return 30 * time.Minute, 12 * time.Hour
		}, wantIdle: 30 * time.Minute, wantAbs: 12 * time.Hour},
		"nil":      {},
		"zero":     {caps: func(context.Context, account.Client) (time.Duration, time.Duration) { return 0, 0 }},
		"negative": {caps: func(context.Context, account.Client) (time.Duration, time.Duration) { return -time.Minute, -time.Hour }},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var calls []account.Client
			var mu sync.Mutex
			caps := tc.caps
			if caps != nil {
				caps = func(ctx context.Context, c account.Client) (time.Duration, time.Duration) {
					mu.Lock()
					calls = append(calls, c)
					mu.Unlock()
					return tc.caps(ctx, c)
				}
			}
			f := newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.SetupTokenRequired = tokenless; r.SessionCaps = caps })})
			got, err := f.svc.SetupWithPassword(t.Context(), localClient, account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)})
			if err != nil {
				t.Fatalf("SetupWithPassword: %v", err)
			}
			stored, found, err := f.mem.SessionByHash(t.Context(), got.Session.TokenHash)
			if err != nil || !found {
				t.Fatalf("SessionByHash: %v, %t", err, found)
			}
			if stored.IdleCap != tc.wantIdle || stored.AbsoluteCap != tc.wantAbs {
				t.Errorf("stored caps = %v, %v, want %v, %v", stored.IdleCap, stored.AbsoluteCap, tc.wantIdle, tc.wantAbs)
			}
			mu.Lock()
			defer mu.Unlock()
			if tc.caps != nil && (len(calls) != 1 || !sameClient(calls[0], localClient)) {
				t.Errorf("SessionCaps calls = %+v, want one with the request's Client", calls)
			}
		})
	}
}

func TestSetupLocality(t *testing.T) {
	t.Parallel()
	loopback := access.ClientAddr{IP: netip.MustParseAddr("127.0.0.1"), Peer: netip.MustParseAddr("127.0.0.1")}
	loopback6 := access.ClientAddr{IP: netip.MustParseAddr("::1"), Peer: netip.MustParseAddr("::1")}
	private := access.ClientAddr{IP: netip.MustParseAddr("192.168.1.5"), Peer: netip.MustParseAddr("192.168.1.5")}
	forwarded := loopback
	forwarded.UntrustedForwarding = true
	loopbackOnly := func(c access.ClientAddr) bool { return c.IP.IsLoopback() && !c.UntrustedForwarding }
	privateToo := func(c access.ClientAddr) bool {
		return (c.IP.IsLoopback() || c.IP.IsPrivate()) && !c.UntrustedForwarding
	}
	cases := []struct {
		l    account.SetupLocality
		addr access.ClientAddr
		host string
		want bool // token required
	}{
		{l: account.SetupLocality{}, addr: loopback, host: "localhost", want: true},
		{l: account.SetupLocality{}, addr: loopback, host: "127.0.0.1", want: true},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback, host: "localhost"},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback, host: "localhost:9847"},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback, host: "LOCALHOST."},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback, host: "127.0.0.1:8080"},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback6, host: "[::1]:9847"},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback6, host: "[::1]"},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback, host: "evil.example", want: true},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback, host: "nas.lan", want: true},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback, host: "", want: true},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback, host: ":8080", want: true},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback6, host: "fe80::1%eth0", want: true},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback6, host: "[fe80::1%eth0]:80", want: true},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback6, host: "[::1", want: true},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: loopback6, host: "::1]", want: true},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: private, host: "localhost", want: true},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: private, host: "192.168.1.5:8374", want: true},
		{l: account.SetupLocality{Local: loopbackOnly}, addr: forwarded, host: "localhost", want: true},
		{l: account.SetupLocality{Local: loopbackOnly, Hosts: []string{"nas.lan"}}, addr: loopback, host: "NAS.LAN.:8374"},
		{l: account.SetupLocality{Local: loopbackOnly, Hosts: []string{"NAS.lan."}}, addr: loopback, host: "nas.lan"},
		{l: account.SetupLocality{Local: loopbackOnly, Hosts: []string{"az.lan"}}, addr: loopback, host: "AZ.lan"},
		{l: account.SetupLocality{Local: loopbackOnly, Hosts: []string{"nas.lan"}}, addr: loopback, host: "nas.lan.evil", want: true},
		{l: account.SetupLocality{Local: loopbackOnly, Hosts: []string{""}}, addr: loopback, host: ".", want: true},
		{l: account.SetupLocality{Local: privateToo}, addr: private, host: "192.168.1.5:8374"},
		{l: account.SetupLocality{Local: privateToo}, addr: private, host: "evil.example", want: true},
	}
	for _, tc := range cases {
		c := account.Client{ClientAddr: tc.addr, Host: tc.host}
		if got := tc.l.TokenRequired(t.Context(), c); got != tc.want {
			t.Errorf("TokenRequired(local=%t hosts=%q, ip=%s untrusted=%t, Host %q) = %t, want %t",
				tc.l.Local != nil, tc.l.Hosts, tc.addr.IP, tc.addr.UntrustedForwarding, tc.host, got, tc.want)
		}
	}
	t.Run("as_setup_rule", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, options{rules: rulesWith(func(r *account.Rules) {
			r.SetupTokenRequired = account.SetupLocality{Local: loopbackOnly}.TokenRequired
		}), edit: withBusyHasher(t)})
		in := account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)}
		if _, err := f.svc.SetupWithPassword(t.Context(), account.Client{ClientAddr: loopback, Host: "localhost:8080"}, in); !errors.Is(err, access.ErrHashBusy) {
			t.Errorf("a local setup = %v, want it past the token rule", err)
		}
		if _, err := f.svc.SetupWithPassword(t.Context(), account.Client{ClientAddr: loopback, Host: "rebound.example"}, in); !errors.Is(err, account.ErrSetupTokenRequired) {
			t.Errorf("a rebound Host = %v, want ErrSetupTokenRequired", err)
		}
	})
}

func TestSetupNilAlwaysAsks(t *testing.T) {
	t.Parallel()
	loopback := account.Client{IP: netip.MustParseAddr("127.0.0.1"), Peer: netip.MustParseAddr("127.0.0.1"), Host: "localhost"}
	f := newFixture(t, options{edit: withBusyHasher(t)})
	in := account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)}
	if _, err := f.svc.SetupWithPassword(t.Context(), loopback, in); !errors.Is(err, account.ErrSetupTokenRequired) {
		t.Errorf("setup with a nil SetupTokenRequired from loopback = %v, want ErrSetupTokenRequired with no hash", err)
	}
	g := newFixture(t, options{rules: rulesWith(func(r *account.Rules) { r.SetupTokenRequired = account.SetupLocality{}.TokenRequired })})
	if _, err := g.svc.SetupWithPassword(t.Context(), loopback, in); !errors.Is(err, account.ErrSetupTokenRequired) {
		t.Errorf("setup with the zero SetupLocality from loopback = %v, want ErrSetupTokenRequired", err)
	}
	tok := issueSetupToken(t, g)
	in.Token = tok
	if _, err := g.svc.SetupWithPassword(t.Context(), loopback, in); err != nil {
		t.Errorf("setup with its token = %v, want nil", err)
	}
	if _, err := g.svc.SetupWithPassword(t.Context(), loopback, in); !errors.Is(err, account.ErrSetupComplete) {
		t.Errorf("a second setup = %v, want ErrSetupComplete", err)
	}
}
