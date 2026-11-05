package account_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
)

// rulesAgent marks the request whose Client SessionCaps must receive.
const rulesAgent = "rules-agent"

// creationPath is one operation that creates a session. run arranges the
// path's preconditions from localClient, then makes the creating call
// from c, and returns the IDs of the sessions the signed-in user held
// before it; nil for a user the call creates.
type creationPath struct {
	run  func(t *testing.T, f *oidcFixture, c account.Client) (account.SignedIn, []string, error)
	name string
}

// creationPaths are every operation that creates a session.
func creationPaths() []creationPath {
	return []creationPath{
		{name: "password_login", run: func(t *testing.T, f *oidcFixture, c account.Client) (account.SignedIn, []string, error) {
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			putSession(t, f.mem, liveSession(t, u))
			old := sessionIDsOf(t, f.fixture, u.ID)
			in, err := f.login(t.Context(), c, "alice", goodPassword)
			return in, old, err
		}},
		{name: "passkey_login", run: func(t *testing.T, f *oidcFixture, c account.Client) (account.SignedIn, []string, error) {
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			dev := accesstest.NewPasskeyDevice(t)
			f.enrol(t, u, dev)
			old := sessionIDsOf(t, f.fixture, u.ID)
			in, err := f.signIn(t.Context(), t, c, account.LoginModal, dev)
			return in, old, err
		}},
		{name: "oidc_sign_in", run: func(t *testing.T, f *oidcFixture, c account.Client) (account.SignedIn, []string, error) {
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			linkIdentity(t, f.mem, u, f.rig.identity())
			putSession(t, f.mem, liveSession(t, u))
			old := sessionIDsOf(t, f.fixture, u.ID)
			flow, claims := f.rig.signInFlow(t)
			out, err := f.complete(t, c, flow, claims)
			return out.SignedIn, old, err
		}},
		{name: "oidc_provisioning", run: func(t *testing.T, f *oidcFixture, c account.Client) (account.SignedIn, []string, error) {
			mustUser(t, f.mem, "owner", access.RoleAdmin)
			flow, claims := f.rig.signInFlow(t)
			claims.PreferredUsername = "newcomer"
			out, err := f.complete(t, c, flow, claims)
			return out.SignedIn, nil, err
		}},
		{name: "setup_password", run: func(t *testing.T, f *oidcFixture, c account.Client) (account.SignedIn, []string, error) {
			in, err := f.svc.SetupWithPassword(t.Context(), c, account.SetupPassword{Username: "owner", Password: access.NewSecret(goodPassword)})
			return in, nil, err
		}},
		{name: "setup_passkey", run: func(t *testing.T, f *oidcFixture, c account.Client) (account.SignedIn, []string, error) {
			id, body := f.beginSetup(t, access.Secret{}, accesstest.NewPasskeyDevice(t))
			in, err := f.svc.SetupPasskeyFinish(t.Context(), c, id, bytes.NewReader(body))
			return in, nil, err
		}},
		{name: "invite", run: func(t *testing.T, f *oidcFixture, c account.Client) (account.SignedIn, []string, error) {
			admin := mustUser(t, f.mem, "inviter", access.RoleAdmin)
			inv, err := f.svc.CreateInvite(t.Context(), f.sessionPrincipal(t, admin, access.SessionFull, time.Now()), access.RoleUser, 0)
			if err != nil {
				t.Fatalf("CreateInvite = %v", err)
			}
			in, err := f.svc.AcceptInvitePassword(t.Context(), c, account.AcceptInvite{Token: inv.Plaintext, Username: "invitee", Password: access.NewSecret(goodPassword)})
			return in, nil, err
		}},
		{name: "recovery_start", run: func(t *testing.T, f *oidcFixture, c account.Client) (account.SignedIn, []string, error) {
			u := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
			putSession(t, f.mem, liveSession(t, u))
			old := sessionIDsOf(t, f.fixture, u.ID)
			tok, err := f.svc.IssueRecovery(t.Context(), account.OutOfBand("socket"), u.ID, 0)
			if err != nil {
				t.Fatalf("IssueRecovery = %v", err)
			}
			rec, err := f.svc.StartRecovery(t.Context(), c, tok.Plaintext)
			return account.SignedIn{User: u, Session: rec.Issued.Session}, old, err
		}},
	}
}

func TestSessionRulesEveryCreationPath(t *testing.T) {
	t.Parallel()
	for _, p := range creationPaths() {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int64
			f := newOIDCFixture(t, rigFor(t, "subject-"+p.name), pwOptions{rules: func() account.Rules {
				return account.Rules{
					MaxSessionsPerUser: 1,
					SetupTokenRequired: tokenless,
					Provisioning:       oidc.Provisioning{Enabled: true},
					SessionCaps: func(_ context.Context, c account.Client) (time.Duration, time.Duration) {
						if c.UserAgent == rulesAgent {
							calls.Add(1)
						}
						return 30 * time.Minute, 12 * time.Hour
					},
				}
			}})
			c := localClient
			c.UserAgent = rulesAgent
			in, old, err := p.run(t, f, c)
			if err != nil || in.User == nil {
				t.Fatalf("creating call = %+v, %v; want a session", in, err)
			}
			if n := calls.Load(); n != 1 {
				t.Errorf("SessionCaps called %d times with the request's Client, want 1", n)
			}
			got := storedSession(t, f.mem, in.User.ID, in.Session.ID)
			if got.IdleCap != 30*time.Minute || got.AbsoluteCap != 12*time.Hour {
				t.Errorf("stored caps = %v and %v, want 30m and 12h", got.IdleCap, got.AbsoluteCap)
			}
			if now := sessionIDsOf(t, f.fixture, in.User.ID); !slices.Equal(now, []string{in.Session.ID}) {
				t.Errorf("sessions after the call = %v, want only the new %s", now, in.Session.ID)
			}
			var revoked [][]string
			for _, ev := range eventsOf(f.events, account.EventSessionRevoked) {
				if ev.UserID == in.User.ID {
					revoked = append(revoked, ev.SessionIDs)
				}
			}
			want := [][]string{old}
			if old == nil {
				want = nil
			}
			if !slices.EqualFunc(revoked, want, slices.Equal[[]string]) {
				t.Errorf("EventSessionRevoked for the user = %v, want %v", revoked, want)
			}
		})
	}
}

// toggledPolicy refuses an invite acceptance's OpCreateUser while off is
// set, and is RolePolicy otherwise.
type toggledPolicy struct{ off *atomic.Bool }

func (p toggledPolicy) Authorize(ctx context.Context, d account.Decision) error {
	if p.off.Load() && d.Op == account.OpCreateUser && d.Via == account.ViaInvite {
		return &account.PolicyError{Op: d.Op, Reason: "no_invites"}
	}
	return account.RolePolicy{}.Authorize(ctx, d)
}

// limitEnv is a fixture whose limiter admits one IP attempt and one IP
// request, with switches a refusal row flips and restores.
type limitEnv struct {
	*pkFixture
	inviter                 *access.User // created by the first invite
	subject                 *access.User // created by the first recovery link
	passwordOff, invitesOff atomic.Bool
}

func isUsernameError(err error) bool {
	_, ok := errors.AsType[*account.UsernameError](err)
	return ok
}

func isPasswordError(err error) bool {
	_, ok := errors.AsType[*access.PasswordError](err)
	return ok
}

// is matches err against target.
func is(target error) func(error) bool {
	return func(err error) bool { return errors.Is(err, target) }
}

// refusal is one input an operation refuses before its limiter. call makes
// the refused call and restores whatever state it changed.
type refusal struct {
	call func(t *testing.T, e *limitEnv) error
	want func(error) bool
	name string
}

// limitedPath is one operation that charges the limiter, with valid making
// an admitted call from localClient.
type limitedPath struct {
	valid    func(t *testing.T, e *limitEnv) error
	name     string
	refusals []refusal
}

// The OIDC callback charges nothing here, since its caller charges before
// Provider.Finish, and a ceremony's finish none, since its begin charged.
func limitedPaths() []limitedPath {
	userPresent := func(t *testing.T, e *limitEnv, call func() error) error {
		u := mustUser(t, e.mem, "early", access.RoleUser)
		err := call()
		if delErr := e.mem.DeleteUser(t.Context(), u.ID); delErr != nil {
			t.Fatalf("DeleteUser: %v", delErr)
		}
		return err
	}
	setupPassword := func(e *limitEnv, t *testing.T, tok access.Secret, name, pw string) error {
		_, err := e.svc.SetupWithPassword(t.Context(), localClient, account.SetupPassword{Token: tok, Username: name, Password: access.NewSecret(pw)})
		return err
	}
	setupPasskey := func(e *limitEnv, t *testing.T, tok access.Secret, name string) error {
		_, err := e.svc.SetupPasskeyBegin(t.Context(), localClient, account.SetupPasskey{Token: tok, Username: name, Origin: e.origin})
		return err
	}
	forged := access.NewSecret(strings.Repeat("ab", 32))
	invite := func(t *testing.T, e *limitEnv) access.Secret {
		if e.inviter == nil {
			e.inviter = mustUser(t, e.mem, "inviter", access.RoleAdmin)
		}
		inv, err := e.svc.CreateInvite(t.Context(), e.sessionPrincipal(t, e.inviter, access.SessionFull, time.Now()), access.RoleUser, 0)
		if err != nil {
			t.Fatalf("CreateInvite = %v", err)
		}
		return inv.Plaintext
	}
	accept := func(e *limitEnv, t *testing.T, tok access.Secret, name, pw string) error {
		_, err := e.svc.AcceptInvitePassword(t.Context(), localClient, account.AcceptInvite{Token: tok, Username: name, Password: access.NewSecret(pw)})
		return err
	}
	recovery := func(t *testing.T, e *limitEnv) access.Secret {
		if e.subject == nil {
			e.subject = mustUser(t, e.mem, "subject", access.RoleUser)
		}
		tok, err := e.svc.IssueRecovery(t.Context(), account.OutOfBand("socket"), e.subject.ID, 0)
		if err != nil {
			t.Fatalf("IssueRecovery = %v", err)
		}
		return tok.Plaintext
	}
	startRecovery := func(e *limitEnv, t *testing.T, tok access.Secret) error {
		_, err := e.svc.StartRecovery(t.Context(), localClient, tok)
		return err
	}
	return []limitedPath{
		{
			name: "password_login",
			valid: func(t *testing.T, e *limitEnv) error {
				passwordUser(t, e.mem, e.hasher, "alice", goodPassword)
				_, err := e.login(t.Context(), localClient, "alice", goodPassword)
				return err
			},
			refusals: []refusal{
				{name: "disabled", want: is(account.ErrPasswordLoginDisabled), call: func(t *testing.T, e *limitEnv) error {
					e.passwordOff.Store(true)
					defer e.passwordOff.Store(false)
					_, err := e.login(t.Context(), localClient, "alice", goodPassword)
					return err
				}},
				{name: "refused_name", want: isUsernameError, call: func(t *testing.T, e *limitEnv) error {
					_, err := e.login(t.Context(), localClient, "two words", goodPassword)
					return err
				}},
			},
		},
		{
			name: "setup_password",
			valid: func(t *testing.T, e *limitEnv) error {
				return setupPassword(e, t, setupToken(t, e.svc), "owner", goodPassword)
			},
			refusals: []refusal{
				{name: "user_present", want: is(account.ErrSetupComplete), call: func(t *testing.T, e *limitEnv) error {
					return userPresent(t, e, func() error { return setupPassword(e, t, access.Secret{}, "owner", goodPassword) })
				}},
				{name: "missing_token", want: is(account.ErrSetupTokenRequired), call: func(t *testing.T, e *limitEnv) error {
					return setupPassword(e, t, access.Secret{}, "owner", goodPassword)
				}},
				{name: "invalid_token", want: is(access.ErrTokenInvalid), call: func(t *testing.T, e *limitEnv) error {
					return setupPassword(e, t, forged, "owner", goodPassword)
				}},
				{name: "refused_name", want: isUsernameError, call: func(t *testing.T, e *limitEnv) error {
					return setupPassword(e, t, setupToken(t, e.svc), "two words", goodPassword)
				}},
				{name: "refused_password", want: isPasswordError, call: func(t *testing.T, e *limitEnv) error {
					return setupPassword(e, t, setupToken(t, e.svc), "owner", "short")
				}},
			},
		},
		{
			name: "setup_passkey_begin",
			valid: func(t *testing.T, e *limitEnv) error {
				return setupPasskey(e, t, setupToken(t, e.svc), "owner")
			},
			refusals: []refusal{
				{name: "user_present", want: is(account.ErrSetupComplete), call: func(t *testing.T, e *limitEnv) error {
					return userPresent(t, e, func() error { return setupPasskey(e, t, access.Secret{}, "owner") })
				}},
				{name: "missing_token", want: is(account.ErrSetupTokenRequired), call: func(t *testing.T, e *limitEnv) error {
					return setupPasskey(e, t, access.Secret{}, "owner")
				}},
				{name: "invalid_token", want: is(access.ErrTokenInvalid), call: func(t *testing.T, e *limitEnv) error {
					return setupPasskey(e, t, forged, "owner")
				}},
				{name: "refused_name", want: isUsernameError, call: func(t *testing.T, e *limitEnv) error {
					return setupPasskey(e, t, setupToken(t, e.svc), "")
				}},
			},
		},
		{
			name: "passkey_login_begin",
			valid: func(t *testing.T, e *limitEnv) error {
				_, err := e.svc.PasskeyLoginBegin(t.Context(), localClient, e.origin, account.LoginConditional)
				return err
			},
			refusals: []refusal{
				{name: "unknown_mode", want: func(err error) bool { return err != nil && !errors.Is(err, ratelimit.ErrRefused) }, call: func(t *testing.T, e *limitEnv) error {
					_, err := e.svc.PasskeyLoginBegin(t.Context(), localClient, e.origin, account.LoginMode(9))
					return err
				}},
			},
		},
		{
			name: "invite",
			valid: func(t *testing.T, e *limitEnv) error {
				return accept(e, t, invite(t, e), "invitee", goodPassword)
			},
			refusals: []refusal{
				{name: "invalid_token", want: is(access.ErrTokenInvalid), call: func(t *testing.T, e *limitEnv) error {
					return accept(e, t, forged, "invitee", goodPassword)
				}},
				{name: "refused_name", want: isUsernameError, call: func(t *testing.T, e *limitEnv) error {
					return accept(e, t, invite(t, e), "two words", goodPassword)
				}},
				{name: "refused_password", want: isPasswordError, call: func(t *testing.T, e *limitEnv) error {
					return accept(e, t, invite(t, e), "invitee", "short")
				}},
				{name: "policy", want: is(account.ErrPolicyRefused), call: func(t *testing.T, e *limitEnv) error {
					e.invitesOff.Store(true)
					defer e.invitesOff.Store(false)
					return accept(e, t, invite(t, e), "invitee", goodPassword)
				}},
			},
		},
		{
			name: "recovery_start",
			valid: func(t *testing.T, e *limitEnv) error {
				return startRecovery(e, t, recovery(t, e))
			},
			refusals: []refusal{
				{name: "zero_token", want: is(access.ErrTokenInvalid), call: func(t *testing.T, e *limitEnv) error {
					return startRecovery(e, t, access.Secret{})
				}},
				{name: "invalid_token", want: is(access.ErrTokenInvalid), call: func(t *testing.T, e *limitEnv) error {
					return startRecovery(e, t, forged)
				}},
				{name: "invite_token", want: is(access.ErrTokenInvalid), call: func(t *testing.T, e *limitEnv) error {
					return startRecovery(e, t, invite(t, e))
				}},
				{name: "disabled_subject", want: is(access.ErrTokenInvalid), call: func(t *testing.T, e *limitEnv) error {
					tok := recovery(t, e)
					setEnabled(t, e.mem, e.subject.ID, false)
					defer setEnabled(t, e.mem, e.subject.ID, true)
					return startRecovery(e, t, tok)
				}},
			},
		},
	}
}

// setEnabled stores userID's Enabled as enabled.
func setEnabled(t *testing.T, s account.Store, userID int64, enabled bool) {
	t.Helper()
	u := storedUser(t, s, userID)
	u.Enabled = enabled
	if err := s.UpdateUser(t.Context(), u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

func TestRefusalsBeforeLimitEveryPath(t *testing.T) {
	t.Parallel()
	one := ratelimit.Rate{Limit: 1, Window: time.Hour}
	for _, p := range limitedPaths() {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			for _, r := range p.refusals {
				t.Run(r.name, func(t *testing.T) {
					t.Parallel()
					e := &limitEnv{}
					e.pkFixture = newPK(t, pwOptions{
						limiter: func(c *ratelimit.Config) { c.IP, c.Request = one, one },
						rules: func() account.Rules {
							return account.Rules{DisablePasswordLogin: e.passwordOff.Load()}
						},
						edit: func(c *account.Config) { c.Policy = toggledPolicy{off: &e.invitesOff} },
					})
					if err := r.call(t, e); !r.want(err) {
						t.Fatalf("refused call = %v, want the %s refusal", err, r.name)
					}
					if err := p.valid(t, e); err != nil {
						t.Errorf("a valid call from the same IP after the %s refusal = %v, want admitted: the refusal spent the slot", r.name, err)
					}
				})
			}
		})
	}
}

// issuerPolicy refuses OpInvite and OpIssueRecovery while off is set, and
// is RolePolicy otherwise.
type issuerPolicy struct{ off *atomic.Bool }

func (p issuerPolicy) Authorize(ctx context.Context, d account.Decision) error {
	if p.off.Load() && (d.Op == account.OpInvite || d.Op == account.OpIssueRecovery) {
		return &account.PolicyError{Op: d.Op, Reason: "no_invites"}
	}
	return account.RolePolicy{}.Authorize(ctx, d)
}

// noUserEnv is a pwFixture over a faultStore whose limiter admits one IP
// attempt, with an admin root, a RoleUser subject for recovery links, and
// issuerPolicy's switch.
type noUserEnv struct {
	*pwFixture
	fs        *faultStore
	root      *access.User
	subject   *access.User
	issuerOff atomic.Bool
}

// session is a fresh full session of root's.
func (e *noUserEnv) session(t *testing.T) access.Principal {
	t.Helper()
	return e.sessionPrincipal(t, e.root, access.SessionFull, time.Now())
}

// invite is a RoleUser invite p issues.
func (e *noUserEnv) invite(t *testing.T, p access.Principal) account.IssuedToken {
	t.Helper()
	inv, err := e.svc.CreateInvite(t.Context(), p, access.RoleUser, 0)
	if err != nil {
		t.Fatalf("CreateInvite = %v", err)
	}
	return inv
}

// noUserPath is one way a creating path's Update commits with no user:
// refused arranges it and makes that call from localClient, and made
// reports whether the call created the user or session it was for.
type noUserPath struct {
	refused func(t *testing.T, e *noUserEnv) error
	made    func(t *testing.T, e *noUserEnv) bool
	name    string
}

// consumeAfterPeek makes a concurrent redemption spend tok after the
// operation's peek, before its consuming Update.
func (e *noUserEnv) consumeAfterPeek(t *testing.T, tok account.IssuedToken) {
	t.Helper()
	e.fs.onUpdate(func(ctx context.Context, _ int) {
		e.fs.onUpdate(nil)
		if err := e.mem.Update(ctx, func(tx account.Tx) error {
			_, _, err := tx.ConsumeOneTimeToken(ctx, hashOf(tok), time.Now())
			return err
		}); err != nil {
			t.Errorf("the concurrent consumption = %v", err)
		}
	})
}

func noUserPaths() []noUserPath {
	invitee := func(t *testing.T, e *noUserEnv) bool { return usernameTaken(t, e.fixture, "invitee") }
	recoverySession := func(t *testing.T, e *noUserEnv) bool {
		return len(recoverySessions(t, e.mem, e.subject.ID)) != 0
	}
	start := func(t *testing.T, e *noUserEnv, tok account.IssuedToken) error {
		_, err := e.svc.StartRecovery(t.Context(), localClient, tok.Plaintext)
		return err
	}
	return []noUserPath{
		{name: "invite_consumed", made: invitee, refused: func(t *testing.T, e *noUserEnv) error {
			inv := e.invite(t, e.session(t))
			e.consumeAfterPeek(t, inv)
			_, err := e.accept(t, inv.Plaintext, "invitee")
			return err
		}},
		{name: "invite_refused_issuer", made: invitee, refused: func(t *testing.T, e *noUserEnv) error {
			// Revoking the key would delete its invite, so the Policy refuses
			// the issuer's OpInvite when the Update re-checks it.
			k := e.mint(t, account.As(e.session(t)), e.root.ID, account.NewKey{Scopes: []string{scopeUsers}})
			inv := e.invite(t, k.p)
			e.issuerOff.Store(true)
			defer e.issuerOff.Store(false)
			_, err := e.accept(t, inv.Plaintext, "invitee")
			return err
		}},
		{name: "recovery_consumed", made: recoverySession, refused: func(t *testing.T, e *noUserEnv) error {
			tok, err := e.svc.IssueRecovery(t.Context(), account.OutOfBand("socket"), e.subject.ID, 0)
			if err != nil {
				t.Fatalf("IssueRecovery = %v", err)
			}
			e.consumeAfterPeek(t, tok)
			return start(t, e, tok)
		}},
		{name: "recovery_refused_issuer", made: recoverySession, refused: func(t *testing.T, e *noUserEnv) error {
			k := e.mint(t, account.As(e.session(t)), e.root.ID, account.NewKey{Scopes: []string{scopeUsers}})
			tok, err := e.svc.IssueRecovery(t.Context(), account.As(k.p), e.subject.ID, 0)
			if err != nil {
				t.Fatalf("IssueRecovery from the key = %v", err)
			}
			e.issuerOff.Store(true)
			defer e.issuerOff.Store(false)
			return start(t, e, tok)
		}},
	}
}

func TestNoUserCommitKeepsSlotEveryPath(t *testing.T) {
	t.Parallel()
	for _, p := range noUserPaths() {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			e := &noUserEnv{fs: newFaultStore()}
			e.pwFixture = newPW(t, pwOptions{options: keyOptions(options{store: e.fs}, issuerPolicy{off: &e.issuerOff}), limiter: ipLimit(1)})
			e.root = mustUser(t, e.mem, "root", access.RoleAdmin)
			e.subject = mustUser(t, e.mem, "subject", access.RoleUser)
			if err := p.refused(t, e); !errors.Is(err, access.ErrTokenInvalid) {
				t.Fatalf("the %s call = %v, want access.ErrTokenInvalid", p.name, err)
			}
			if p.made(t, e) {
				t.Fatalf("the %s call created what it was for", p.name)
			}
			_, err := e.accept(t, e.invite(t, e.session(t)).Plaintext, "second")
			if _, ok := errors.AsType[*ratelimit.RefusedError](err); !ok {
				t.Errorf("a valid acceptance from the same IP after the %s commit = %v, want *ratelimit.RefusedError: the commit kept its slot", p.name, err)
			}
		})
	}
}

// TestSessionCapsEveryCreation checks that SessionCaps is read at each
// sign-in, so a change between two sign-ins changes only the second
// session, and that the sweep ends a capped session at its capped deadline
// beside an uncapped one, in one EventSessionsExpired.
func TestSessionCapsEveryCreation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		week := 7 * 24 * time.Hour
		var capped atomic.Bool
		capped.Store(true)
		p := newPW(t, pwOptions{
			timeouts: newTimeoutSource(week, week).get,
			edit:     withInterval,
			rules: rulesWith(func(r *account.Rules) {
				r.SessionCaps = func(context.Context, account.Client) (time.Duration, time.Duration) {
					if capped.Load() {
						return 30 * time.Minute, 12 * time.Hour
					}
					return 0, 0
				}
			}),
		})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		first, err := p.login(t.Context(), localClient, "alice", goodPassword)
		if err != nil {
			t.Fatalf("first sign-in = %v", err)
		}
		capped.Store(false)
		second, err := p.login(t.Context(), localClient, "alice", goodPassword)
		if err != nil {
			t.Fatalf("second sign-in = %v", err)
		}
		if s := storedSession(t, p.mem, u.ID, first.Session.ID); s.IdleCap != 30*time.Minute || s.AbsoluteCap != 12*time.Hour {
			t.Errorf("the first session's caps = %v, %v after SessionCaps changed; want 30m and 12h kept", s.IdleCap, s.AbsoluteCap)
		}
		if s := storedSession(t, p.mem, u.ID, second.Session.ID); s.IdleCap != 0 || s.AbsoluteCap != 0 {
			t.Errorf("the second session's caps = %v, %v; want none", s.IdleCap, s.AbsoluteCap)
		}

		time.Sleep(29 * time.Minute)
		synctest.Wait()
		if ids := sessionIDsOf(t, p.fixture, u.ID); len(ids) != 2 {
			t.Fatalf("sessions 29 minutes in = %v, want both", ids)
		}
		if n := len(expiredEvents(p.fixture)); n != 0 {
			t.Fatalf("%d EventSessionsExpired before the capped deadline", n)
		}
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if ids := sessionIDsOf(t, p.fixture, u.ID); !slices.Equal(ids, []string{second.Session.ID}) {
			t.Errorf("sessions past the capped idle deadline = %v, want only the uncapped %s", ids, second.Session.ID)
		}
		got := expiredEvents(p.fixture)
		if len(got) != 1 || got[0].UserID != u.ID || !slices.Equal(got[0].SessionIDs, []string{first.Session.ID}) {
			t.Errorf("EventSessionsExpired = %+v, want one naming only %s", got, first.Session.ID)
		}
	})
}
