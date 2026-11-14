package account_test

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/oidc"
)

// gatePolicy answers as RolePolicy. Once armed it records every decision
// and refuses the ones whose Op is refuse.
type gatePolicy struct {
	decisions []account.Decision
	refuse    account.Operation
	mu        sync.Mutex
	armed     bool
}

// gateReason is the reason of every refusal gatePolicy makes itself.
const gateReason = "gate_refused"

func (p *gatePolicy) Authorize(ctx context.Context, d account.Decision) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.armed {
		p.decisions = append(p.decisions, d)
		if d.Op == p.refuse {
			return &account.PolicyError{Op: d.Op, Reason: gateReason}
		}
	}
	return account.RolePolicy{}.Authorize(ctx, d)
}

// arm starts recording afresh and refuses op from now on; an empty op
// refuses nothing.
func (p *gatePolicy) arm(op account.Operation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.armed, p.refuse, p.decisions = true, op, nil
}

func (p *gatePolicy) taken() []account.Decision {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.decisions)
}

// errNotLinked stands for an OIDCOutcome of kind OutcomeNotLinked.
var errNotLinked = errors.New("oidc callback answered NotLinked")

// policyVariants are catalogued operations called in the configuration
// that asks a Policy operation their catalogue call does not.
func policyVariants() []operation {
	sso := func(r *account.Rules) { r.SSOGoverned = true }
	return []operation{
		{name: "UpdateUser_role_and_enabled", class: classManageUsers, asks: []account.Operation{account.OpSetRole, account.OpSetEnabled}, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			target := w.user(t)
			return opCall{actor: actorOf(p), target: target.ID, run: func(ctx context.Context) error {
				_, err := w.svc.UpdateUser(ctx, p, target.ID, account.UserChange{Role: new(access.RoleAdmin), Enabled: new(false)})
				return err
			}}
		}},
		{name: "CreateAPIKey_out_of_band", class: classOutOfBand, asks: []account.Operation{account.OpCreateKeyFor}, prep: func(_ *testing.T, w *opWorld, p access.Principal) opCall {
			a := w.actor(p)
			return opCall{actor: account.EventActorOf(a), target: w.alice.ID, run: func(ctx context.Context) error {
				_, err := w.svc.CreateAPIKey(ctx, a, w.alice.ID, account.NewKey{Label: uniqueLabel(), Scopes: []string{"read"}})
				return err
			}}
		}},
		{name: "RotateAPIKey_out_of_band", class: classOutOfBand, asks: []account.Operation{account.OpRotateKey}, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			a := w.actor(p)
			k := w.storedKey(t, w.alice, "read")
			return opCall{actor: account.EventActorOf(a), target: w.alice.ID, run: func(ctx context.Context) error {
				_, err := w.svc.RotateAPIKey(ctx, a, k.ID)
				return err
			}}
		}},
		// Design 9.5 "Provisioning": a refusing Policy makes the callback
		// answer NotLinked, not an error.
		{name: "OIDCComplete_provisioning", class: classPublic, refused: errNotLinked, asks: []account.Operation{account.OpCreateUser}, prep: func(t *testing.T, w *opWorld, _ access.Principal) opCall {
			flow, claims := w.rig.signInFlow(t)
			return opCall{run: func(ctx context.Context) error {
				out, err := w.svc.OIDCComplete(ctx, localClient, flow, claims)
				if err == nil && out.Kind == account.OutcomeNotLinked {
					return errNotLinked
				}
				return err
			}}
		}},
		{name: "LinkPendingOIDC_sso_governed", class: classRecentAuth, rules: sso, asks: []account.Operation{account.OpMigrateToSSO}, prep: func(t *testing.T, w *opWorld, p access.Principal) opCall {
			pending := account.PendingLink{Identity: access.OIDCIdentity{Issuer: oidcIssuer, Subject: w.name("pending-")}}
			return opCall{actor: actorOf(p), target: w.owner(t, p).ID, run: func(ctx context.Context) error {
				_, _, err := w.svc.LinkPendingOIDC(ctx, p, pending)
				return err
			}}
		}},
		{name: "OIDCComplete_link_sso_governed", class: classPublic, rules: sso, asks: []account.Operation{account.OpMigrateToSSO}, prep: func(t *testing.T, w *opWorld, _ access.Principal) opCall {
			sess := putSession(t, w.mem, liveSession(t, w.alice))
			flow, claims := w.rig.sessionFlow(t, oidc.IntentLink, w.alice, sess.ID)
			return opCall{
				actor: account.EventActor{UserID: w.alice.ID, SessionID: sess.ID}, target: w.alice.ID,
				run: func(ctx context.Context) error {
					_, err := w.svc.OIDCComplete(ctx, localClient, flow, claims)
					return err
				},
			}
		}},
	}
}

// TestPolicyRefusalEveryOperation runs every catalogued operation, and
// each policy variant, under a recording Policy: the call asks exactly the
// operations its row names, and a Policy refusing any one of them makes
// the call answer the refusal with no store write and no event, after a
// decision naming the call's actor and target.
func TestPolicyRefusalEveryOperation(t *testing.T) {
	t.Parallel()
	world := func(t *testing.T, op *operation) (*opWorld, *gatePolicy) {
		t.Helper()
		pol := &gatePolicy{}
		return newOpWorld(t, worldOptions{empty: op.empty, policy: pol, rules: op.rules}), pol
	}
	for _, op := range slices.Concat(operations(), policyVariants()) {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			t.Run("asks", func(t *testing.T) {
				t.Parallel()
				w, pol := world(t, &op)
				call := op.prep(t, w, w.actorFor(t, op.class))
				pol.arm("")
				if err := call.run(t.Context()); err != nil {
					t.Fatalf("%s under an allowing Policy = %v", op.name, err)
				}
				var asked []account.Operation
				for _, d := range pol.taken() {
					asked = append(asked, d.Op)
				}
				if !slices.Equal(asked, op.asks) {
					t.Errorf("%s asked the Policy %v, want %v", op.name, asked, op.asks)
				}
			})
			for _, refused := range op.asks {
				t.Run("refused_"+string(refused), func(t *testing.T) {
					t.Parallel()
					w, pol := world(t, &op)
					call := op.prep(t, w, w.actorFor(t, op.class))
					mark := len(w.events.all())
					w.fs.resetRecord()
					pol.arm(refused)
					err := call.run(t.Context())
					if want := cmp.Or(op.refused, account.ErrPolicyRefused); !errors.Is(err, want) {
						t.Fatalf("%s with %s refused = %v, want %v", op.name, refused, err, want)
					}
					if op.refused == nil && reason(err) != gateReason {
						t.Errorf("%s answered %v, want the Policy's own refusal %q", op.name, err, gateReason)
					}
					if ws := writesOf(w.fs); len(ws) != 0 {
						t.Errorf("%s wrote %v after the refusal", op.name, ws)
					}
					if n := len(w.events.all()) - mark; n != 0 {
						t.Errorf("%s emitted %d events after the refusal", op.name, n)
					}
					checkDecision(t, op.name, pol.taken(), refused, &call)
				})
			}
		})
	}
}

// checkDecision requires the last decision of decisions to be op's, with
// call's actor and target.
func checkDecision(t *testing.T, name string, decisions []account.Decision, op account.Operation, call *opCall) {
	t.Helper()
	if len(decisions) == 0 || decisions[len(decisions)-1].Op != op {
		t.Fatalf("%s's last decision is not %s: %+v", name, op, decisions)
	}
	d := decisions[len(decisions)-1]
	if got := account.EventActorOf(d.Actor); got != call.actor {
		t.Errorf("%s's %s decision has actor %+v, want %+v", name, op, got, call.actor)
	}
	switch {
	case call.target == 0 && d.Target != nil:
		t.Errorf("%s's %s decision targets user %d, want none", name, op, d.Target.ID)
	case call.target != 0 && (d.Target == nil || d.Target.ID != call.target):
		t.Errorf("%s's %s decision targets %+v, want user %d", name, op, d.Target, call.target)
	}
}
