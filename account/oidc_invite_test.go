package account_test

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

// storeInvite stores an invite for role, as CreateInvite would, and returns
// its plaintext; edit adjusts the record first.
func storeInvite(t *testing.T, s account.Store, role access.Role, edit func(*access.OneTimeToken)) access.Secret {
	t.Helper()
	plaintext, rec := access.NewOneTimeToken(access.PurposeInvite, time.Hour, time.Now())
	rec.Role = role
	if edit != nil {
		edit(&rec)
	}
	if err := s.CreateOneTimeToken(t.Context(), rec); err != nil {
		t.Fatalf("CreateOneTimeToken: %v", err)
	}
	return plaintext
}

// inviteHash is the stored hash of an invite's plaintext, as the flow seals it.
func inviteHash(token access.Secret) []byte {
	return []byte(access.HexSHA256(token.Reveal()))
}

// inviteUsable reports whether token is still stored.
func inviteUsable(t *testing.T, s account.Store, token access.Secret) bool {
	t.Helper()
	_, found, err := s.OneTimeTokenByHash(t.Context(), access.NewHash(access.HexSHA256(token.Reveal())))
	if err != nil {
		t.Fatalf("OneTimeTokenByHash: %v", err)
	}
	return found
}

// inviteFlow runs the invite intent for token through g's IdP, as
// AcceptInviteOIDCBegin's request would begin it.
func (g *oidcRig) inviteFlow(t testing.TB, token access.Secret) (oidc.Flow, oidc.Claims) {
	t.Helper()
	return g.run(t, oidc.BeginRequest{Intent: oidc.IntentInvite, InviteHash: inviteHash(token)})
}

// rolesSeen is a multi-user Policy that records the Role of every invite
// acceptance it is asked about and allows what RolePolicy allows.
type rolesSeen struct {
	mu    *sync.Mutex
	roles *[]access.Role
}

func newRolesSeen() rolesSeen { return rolesSeen{mu: &sync.Mutex{}, roles: &[]access.Role{}} }

func (rolesSeen) SingleUser() bool { return false }

func (p rolesSeen) Authorize(ctx context.Context, d account.Decision) error {
	if d.Op == account.OpCreateUser && d.Via == account.ViaInvite {
		p.mu.Lock()
		*p.roles = append(*p.roles, d.Role)
		p.mu.Unlock()
	}
	return account.RolePolicy{}.Authorize(ctx, d)
}

func (p rolesSeen) seen() []access.Role {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]access.Role(nil), *p.roles...)
}

// TestAcceptInviteOIDCBegin: the
// begin route reads the invite first, in both kinds of app, then asks the
// Policy with the invite's Role, and seals only the invite's hash.
func TestAcceptInviteOIDCBegin(t *testing.T) {
	t.Parallel()
	t.Run("begins_the_invite_intent", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		mustOwner(t, f.mem, "owner")
		token := storeInvite(t, f.mem, access.RoleUser, nil)
		req, err := f.svc.AcceptInviteOIDCBegin(t.Context(), localClient, token)
		if err != nil {
			t.Fatalf("AcceptInviteOIDCBegin = %v", err)
		}
		if req.Intent != oidc.IntentInvite || !bytes.Equal(req.InviteHash, inviteHash(token)) || req.SessionID != "" || req.UserID != 0 {
			t.Errorf("request = %+v, want IntentInvite carrying the invite's stored hash alone", req)
		}
		if !inviteUsable(t, f.mem, token) {
			t.Error("the begin consumed the invite")
		}
		if evs := f.events.all(); len(evs) != 0 {
			t.Errorf("events = %+v, want none", evs)
		}
	})
	policies := map[string]account.Policy{"role_policy": account.RolePolicy{}}
	maps.Copy(policies, singleUserPolicies())
	for name, pol := range policies {
		for tokenName, mk := range map[string]func(t *testing.T, s account.Store) access.Secret{
			"made_up": func(*testing.T, account.Store) access.Secret { return access.NewSecret("not-an-invite") },
			"empty":   func(*testing.T, account.Store) access.Secret { return access.Secret{} },
			"expired": func(t *testing.T, s account.Store) access.Secret {
				return storeInvite(t, s, access.RoleUser, func(r *access.OneTimeToken) { r.ExpiresAt = time.Now().Add(-time.Second) })
			},
			"other_purpose": func(t *testing.T, s account.Store) access.Secret {
				return storeInvite(t, s, access.RoleUser, func(r *access.OneTimeToken) { r.Purpose = access.PurposeSetup })
			},
		} {
			t.Run(name+"/token_"+tokenName, func(t *testing.T) {
				t.Parallel()
				f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{edit: func(c *account.Config) { c.Policy = pol }})
				mustOwner(t, f.mem, "owner")
				if _, err := f.svc.AcceptInviteOIDCBegin(t.Context(), localClient, mk(t, f.mem)); !errors.Is(err, access.ErrTokenInvalid) {
					t.Errorf("a %s token = %v, want access.ErrTokenInvalid before any policy question", tokenName, err)
				}
			})
		}
	}
	for name, pol := range singleUserPolicies() {
		t.Run(name+"/stored_invite", func(t *testing.T) {
			t.Parallel()
			f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{edit: func(c *account.Config) { c.Policy = pol }})
			mustOwner(t, f.mem, "owner")
			token := storeInvite(t, f.mem, access.RoleUser, nil)
			if _, err := f.svc.AcceptInviteOIDCBegin(t.Context(), localClient, token); reason(err) != account.ReasonSingleOwner {
				t.Errorf("a stored invite in a single-user app = %v, want single_owner", err)
			}
			if !inviteUsable(t, f.mem, token) {
				t.Error("the refusal consumed the invite")
			}
		})
	}
	t.Run("policy_refuses", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{edit: func(c *account.Config) { c.Policy = refuseInvited{} }})
		mustOwner(t, f.mem, "owner")
		if _, err := f.svc.AcceptInviteOIDCBegin(t.Context(), localClient, storeInvite(t, f.mem, access.RoleUser, nil)); reason(err) != "no_invites" {
			t.Errorf("a refused acceptance = %v, want the Policy's no_invites", err)
		}
	})
	t.Run("policy_sees_the_role", func(t *testing.T) {
		t.Parallel()
		seen := newRolesSeen()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{edit: func(c *account.Config) { c.Policy = seen }})
		mustOwner(t, f.mem, "owner")
		if _, err := f.svc.AcceptInviteOIDCBegin(t.Context(), localClient, storeInvite(t, f.mem, access.RoleAdmin, nil)); err != nil {
			t.Fatalf("AcceptInviteOIDCBegin = %v", err)
		}
		if got := seen.seen(); len(got) != 1 || got[0] != access.RoleAdmin {
			t.Errorf("the Policy saw roles %v, want the invite's admin", got)
		}
	})
	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		plain := localClient
		plain.Secure = false
		if _, err := f.svc.AcceptInviteOIDCBegin(t.Context(), plain, storeInvite(t, f.mem, access.RoleUser, nil)); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Errorf("a plain begin = %v, want access.ErrHTTPSRequired", err)
		}
	})
	t.Run("unwired", func(t *testing.T) {
		t.Parallel()
		f := newPK(t, pwOptions{})
		if _, err := f.svc.AcceptInviteOIDCBegin(t.Context(), localClient, storeInvite(t, f.mem, access.RoleUser, nil)); !errors.Is(err, account.ErrOIDCUnavailable) {
			t.Errorf("a begin with no provider = %v, want ErrOIDCUnavailable", err)
		}
	})
}

// TestOIDCInvite: the callback's
// invite arm.
func TestOIDCInvite(t *testing.T) {
	t.Parallel()
	t.Run("creates_the_linked_account", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		mustOwner(t, f.mem, "owner")
		token := storeInvite(t, f.mem, access.RoleAdmin, nil)
		flow, claims := f.rig.inviteFlow(t, token)
		out, err := f.complete(t, localClient, flow, claims)
		if err != nil || out.Kind != account.OutcomeSignedIn {
			t.Fatalf("OIDCComplete = %+v, %v; want SignedIn", out, err)
		}
		u := storedUser(t, f.mem, out.SignedIn.User.ID)
		if u.Username != accesstest.DefaultIdPUsername || u.Role != access.RoleAdmin || u.OIDC != f.rig.identity() || !u.PasswordHash.IsZero() || u.Owner {
			t.Errorf("user = %+v, want the hint's name, the invite's admin role, the token's identity, no password and no owner flag", u)
		}
		if out.SignedIn.Session.AuthMethod != access.MethodOIDC || out.SignedIn.Session.UserID != u.ID || out.SignedIn.Token.IsZero() {
			t.Errorf("session = %+v, want an OIDC session of the new user", out.SignedIn.Session)
		}
		if inviteUsable(t, f.mem, token) {
			t.Error("the invite is still usable after its acceptance")
		}
		if evs := eventsOf(f.events, account.EventUserCreated); len(evs) != 1 || evs[0].UserID != u.ID || evs[0].Role != access.RoleAdmin {
			t.Errorf("user_created = %+v, want one for the new admin", evs)
		}
		again, claims2 := f.rig.inviteFlow(t, token)
		if _, err := f.complete(t, localClient, again, claims2); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("the spent invite = %v, want access.ErrTokenInvalid", err)
		}
	})
	// Provisioning need not be on, and under SSOOnly this is the
	// only way to accept an invite.
	for _, mode := range []account.SSOMode{account.SSOAlongside, account.SSOForLinked, account.SSOOnly} {
		t.Run("mode_"+string(mode.Name()), func(t *testing.T) {
			t.Parallel()
			f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
			mustOwner(t, f.mem, "owner")
			storeMode(t, f.mem, mode)
			flow, claims := f.rig.inviteFlow(t, storeInvite(t, f.mem, access.RoleUser, nil))
			if out, err := f.complete(t, localClient, flow, claims); err != nil || out.Kind != account.OutcomeSignedIn || out.SignedIn.User.Role != access.RoleUser {
				t.Errorf("an invite by SSO under %s = %+v, %v; want a signed-in RoleUser", mode.Name(), out, err)
			}
		})
	}
	t.Run("linked_identity", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		mustOwner(t, f.mem, "owner")
		bob := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
		linkIdentity(t, f.mem, bob, f.rig.identity())
		token := storeInvite(t, f.mem, access.RoleUser, nil)
		flow, claims := f.rig.inviteFlow(t, token)
		if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, account.ErrOIDCIdentityTaken) {
			t.Fatalf("an invite by a linked identity = %v, want ErrOIDCIdentityTaken", err)
		}
		if !inviteUsable(t, f.mem, token) || userCount(t, f.fixture) != 2 {
			t.Error("the refused invite was consumed or created a user")
		}
	})
	// A taken name gives the free-name pick, with the
	// invite in the pending state, and the failed callback leaves it usable.
	t.Run("taken_name", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		mustOwner(t, f.mem, "owner")
		passwordUser(t, f.mem, f.hasher, accesstest.DefaultIdPUsername, goodPassword)
		passwordUser(t, f.mem, f.hasher, "carol", goodPassword)
		token := storeInvite(t, f.mem, access.RoleAdmin, nil)
		flow, claims := f.rig.inviteFlow(t, token)
		out, err := f.complete(t, localClient, flow, claims)
		if err != nil || out.Kind != account.OutcomeNotLinked {
			t.Fatalf("OIDCComplete = %+v, %v; want NotLinked", out, err)
		}
		p := out.Pending
		if !p.Invite.Equal(access.NewHash(string(inviteHash(token)))) || p.Provision != nil || !p.CanCreate() || p.SuggestedUsername != accesstest.DefaultIdPUsername+"_2" || p.Identity != f.rig.identity() {
			t.Errorf("pending = %+v, want the invite, no provisioning offer, CanCreate and the _2 suggestion", p)
		}
		if !inviteUsable(t, f.mem, token) || userCount(t, f.fixture) != 3 {
			t.Fatal("the pending pick consumed the invite or created a user")
		}
		if _, err := f.svc.CreatePendingOIDC(t.Context(), localClient, p, "carol"); !errors.Is(err, account.ErrUsernameTaken) {
			t.Fatalf("a taken name at create = %v, want ErrUsernameTaken", err)
		}
		if !inviteUsable(t, f.mem, token) {
			t.Fatal("the taken name consumed the invite")
		}
		in, err := f.svc.CreatePendingOIDC(t.Context(), localClient, p, p.SuggestedUsername)
		if err != nil {
			t.Fatalf("CreatePendingOIDC = %v", err)
		}
		if u := storedUser(t, f.mem, in.User.ID); u.Username != p.SuggestedUsername || u.Role != access.RoleAdmin || u.OIDC != f.rig.identity() || in.Session.AuthMethod != access.MethodOIDC {
			t.Errorf("created %+v, session %+v; want the picked name with the invite's admin role, linked, signed in by OIDC", u, in.Session)
		}
		if inviteUsable(t, f.mem, token) {
			t.Error("the invite is still usable after the create")
		}
		if _, err := f.svc.CreatePendingOIDC(t.Context(), localClient, p, "dave"); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("the pending invite once spent = %v, want access.ErrTokenInvalid", err)
		}
	})
	t.Run("pending_invite_needs_no_provisioning", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		mustOwner(t, f.mem, "owner")
		token := storeInvite(t, f.mem, access.RoleUser, nil)
		pending := account.PendingLink{Identity: f.rig.identity(), Invite: access.NewHash(string(inviteHash(token)))}
		if in, err := f.svc.CreatePendingOIDC(t.Context(), localClient, pending, "erin"); err != nil || in.User.Role != access.RoleUser {
			t.Errorf("CreatePendingOIDC of an invite with provisioning off = %+v, %v; want erin created", in, err)
		}
	})
	t.Run("used_between_begin_and_callback", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		mustOwner(t, f.mem, "owner")
		token := storeInvite(t, f.mem, access.RoleUser, nil)
		req, err := f.svc.AcceptInviteOIDCBegin(t.Context(), localClient, token)
		if err != nil {
			t.Fatalf("AcceptInviteOIDCBegin = %v", err)
		}
		flow, claims := f.rig.run(t, req)
		if _, err := f.accept(t, token, "frank"); err != nil {
			t.Fatalf("AcceptInvitePassword = %v", err)
		}
		before := len(f.events.all())
		if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, access.ErrTokenInvalid) {
			t.Fatalf("the callback of a used invite = %v, want access.ErrTokenInvalid", err)
		}
		if n := userCount(t, f.fixture); n != 2 {
			t.Errorf("users = %d, want the owner and frank", n)
		}
		if evs := f.events.all()[before:]; len(evs) != 0 {
			t.Errorf("the refused callback journalled %+v", evs)
		}
	})
	t.Run("issuer_gone", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		mustOwner(t, f.mem, "owner")
		token := storeInvite(t, f.mem, access.RoleUser, func(r *access.OneTimeToken) { r.IssuedByKey = 999 })
		flow, claims := f.rig.inviteFlow(t, token)
		if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, access.ErrTokenInvalid) {
			t.Fatalf("an invite whose issuing key is gone = %v, want access.ErrTokenInvalid", err)
		}
		if inviteUsable(t, f.mem, token) || userCount(t, f.fixture) != 1 {
			t.Error("the refused issuer's invite survived or created a user")
		}
	})
	t.Run("not_admitted", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: rulesWith(staffAdmission)})
		mustOwner(t, f.mem, "owner")
		token := storeInvite(t, f.mem, access.RoleUser, nil)
		flow, claims := f.rig.inviteFlow(t, token)
		if _, err := f.complete(t, localClient, flow, claims); !errors.Is(err, account.ErrNotAdmitted) {
			t.Fatalf("an invite by an identity outside the group = %v, want ErrNotAdmitted", err)
		}
		if !inviteUsable(t, f.mem, token) || userCount(t, f.fixture) != 1 {
			t.Error("the refused invite was consumed or created a user")
		}
		if evs := f.events.all(); len(evs) != 1 || evs[0].Kind != account.EventOIDCNotAdmitted || evs[0].UserID != 0 {
			t.Errorf("events = %+v, want one oidc_not_admitted naming no user", evs)
		}
	})
	// The callback asks the one method again, before
	// admission, whatever the identity, a not-admitted one included.
	for name, pol := range singleUserPolicies() {
		for _, admission := range []bool{false, true} {
			t.Run(name+"/single_user_admission_"+map[bool]string{false: "unset", true: "refusing"}[admission], func(t *testing.T) {
				t.Parallel()
				rules := rulesWith(func(*account.Rules) {})
				if admission {
					rules = rulesWith(staffAdmission)
				}
				f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{rules: rules, edit: func(c *account.Config) { c.Policy = pol }})
				mustOwner(t, f.mem, "owner")
				token := storeInvite(t, f.mem, access.RoleUser, nil)
				flow, claims := f.rig.inviteFlow(t, token)
				if _, err := f.complete(t, localClient, flow, claims); reason(err) != account.ReasonSingleOwner {
					t.Errorf("an invite's callback in a single-user app = %v, want single_owner", err)
				}
				if !inviteUsable(t, f.mem, token) || userCount(t, f.fixture) != 1 {
					t.Error("the refusal consumed the invite or created a user")
				}
				if evs := f.events.all(); len(evs) != 0 {
					t.Errorf("events = %+v, want none", evs)
				}
			})
		}
	}
	t.Run("policy_sees_the_role_at_the_callback", func(t *testing.T) {
		t.Parallel()
		seen := newRolesSeen()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{edit: func(c *account.Config) { c.Policy = seen }})
		mustOwner(t, f.mem, "owner")
		flow, claims := f.rig.inviteFlow(t, storeInvite(t, f.mem, access.RoleAdmin, nil))
		if _, err := f.complete(t, localClient, flow, claims); err != nil {
			t.Fatalf("OIDCComplete = %v", err)
		}
		if got := seen.seen(); len(got) == 0 || got[0] != access.RoleAdmin {
			t.Errorf("the Policy saw roles %v at the callback, want the invite's admin first", got)
		}
	})
	t.Run("identities_racing_one_invite", func(t *testing.T) {
		t.Parallel()
		f := newOIDCFixture(t, newOIDCRig(t, accesstest.IdPOptions{}), pwOptions{})
		mustOwner(t, f.mem, "owner")
		token := storeInvite(t, f.mem, access.RoleUser, nil)
		type run struct {
			flow   oidc.Flow
			claims oidc.Claims
		}
		runs := []run{}
		for _, subject := range []string{"subject-a", "subject-b"} {
			flow, claims := rigFor(t, subject).inviteFlow(t, token)
			claims.PreferredUsername = subject
			runs = append(runs, run{flow, claims})
		}
		var ok, refused atomic.Int32
		var wg sync.WaitGroup
		for _, r := range runs {
			wg.Go(func() {
				switch _, err := f.complete(t, localClient, r.flow, r.claims); {
				case err == nil:
					ok.Add(1)
				case errors.Is(err, access.ErrTokenInvalid):
					refused.Add(1)
				default:
					t.Errorf("OIDCComplete = %v", err)
				}
			})
		}
		wg.Wait()
		if ok.Load() != 1 || refused.Load() != 1 || userCount(t, f.fixture) != 2 {
			t.Errorf("%d accepted, %d refused, %d users; want one account from one invite", ok.Load(), refused.Load(), userCount(t, f.fixture))
		}
	})
}
