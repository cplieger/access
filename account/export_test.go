package account

import (
	"context"
	"net/netip"
	"time"

	"github.com/cplieger/access"
)

// Hooks are the test hooks of testHooks; each nil one is skipped.
type Hooks struct {
	WrapHasher          func(Hashing) Hashing
	BetweenSessionCalls func(ctx context.Context)
	FailureSweep        func(ctx context.Context)
	Admitted            func(ctx context.Context)
	BeforeVerify        func(ctx context.Context)
	AfterVerify         func(ctx context.Context)
}

// Hashing is the hasher boundary WrapHasher wraps.
type Hashing = hashing

// HashPermit is the permit a Hashing's Reserve returns.
type HashPermit = hashPermit

// NewWithHooks is New with h set before the first sweep.
func NewWithHooks(ctx context.Context, cfg Config, h Hooks) (*Service, error) {
	return newService(ctx, cfg, testHooks{
		wrapHasher: h.WrapHasher, betweenSessionCalls: h.BetweenSessionCalls, failureSweep: h.FailureSweep,
		admitted: h.Admitted, beforeVerify: h.BeforeVerify, afterVerify: h.AfterVerify,
	})
}

// SweepFailures runs the failure-record leg once, as the sweep does.
func SweepFailures(ctx context.Context, s *Service) error { return s.sweepFailures(ctx) }

// SweepLog runs the log leg once at Config.Now, as the sweep does.
func SweepLog(ctx context.Context, s *Service) { s.sweepLog(ctx, s.now()) }

// AllowanceUsed is how many untrusted slots the current interval has taken.
func AllowanceUsed(s *Service) int {
	return int(s.allowance.state.Load() & (1<<allowanceUsedBits - 1))
}

// LeaveAllowance leaves n untrusted slots in the current interval without
// waking the prune: with n 0 the allowance stays spent until a sweep, and
// otherwise the attempt taking the last slot wakes it.
func LeaveAllowance(s *Service, n int) {
	st := s.allowance.state.Load()
	s.allowance.state.Store(st&^(1<<allowanceUsedBits-1) | uint64(MaxUntrustedCounts-n))
}

// FailureName is the failure-record name s gives a canonical username.
func FailureName(s *Service, canonical string) string {
	return failureName(s.failureMAC(), canonical)
}

// CurrentKeyActor runs the key-authority check inside tx, for a run of its
// own.
func CurrentKeyActor(ctx context.Context, s *Service, tx Tx, op Operation, ref access.KeyRef, scope string) (Actor, *access.Key, error) {
	j := &journal{s: s}
	j.reset(netip.Addr{})
	return s.currentKeyActor(ctx, tx, j, op, ref, scope)
}

// Attribute appends one attribution record inside tx.
func Attribute(ctx context.Context, s *Service, tx Tx, userID int64, action access.AttributionAction, key *access.Key) error {
	return s.attribute(ctx, tx, userID, action, key)
}

// RequireHeld runs the credential precondition for method (and the passkey
// passkeyID names) on userID as the store holds it.
func RequireHeld(ctx context.Context, s *Service, userID int64, method access.Method, passkeyID int64) error {
	u, found, err := s.store.UserByID(ctx, userID)
	switch {
	case err != nil:
		return err
	case !found:
		return ErrNotFound
	}
	return answer(requireHeld(ctx, s.store, u, credential{method: method, passkeyID: passkeyID}))
}

// RequireUserTarget is the admin-target rule.
func RequireUserTarget(op Operation, roles ...access.Role) error {
	return requireUserTarget(op, roles...)
}

// RequireSession is the session-actor precondition.
func RequireSession(p access.Principal) error { return requireSession(p) }

// EventActorOf is a's identity as events carry it.
func EventActorOf(a Actor) EventActor { return eventActor(a) }

// Deliver hands ev to s's OnEvent the way every committed change does.
func Deliver(s *Service, ev Event) { s.deliver(ev) }

// Begin is the first call of every operation.
func Begin(s *Service) (Rules, error) { return s.begin() }

// PendingCache is the pending-ceremony cache, for its own tests.
type PendingCache struct{ c *pendingCache }

// PendingPurpose names a begin call.
type PendingPurpose = pendingPurpose

const (
	PurposeLogin    = purposeLogin
	PurposeSetup    = purposeSetup
	PurposeRegister = purposeRegister
	PurposeStepUp   = purposeStepUp
	PurposeRecovery = purposeRecovery
)

func NewPendingCache(maxEntries int) PendingCache { return PendingCache{newPendingCache(maxEntries)} }

// Put stores an entry for user and returns its ID.
func (p PendingCache) Put(purpose PendingPurpose, user access.User, now time.Time) string {
	return p.c.put(purpose, pending{user: user}, now)
}

// Take returns the user stored under id.
func (p PendingCache) Take(id string, purpose PendingPurpose, now time.Time) (access.User, bool) {
	v, ok := p.c.take(id, purpose, now)
	return v.user, ok
}

func (p PendingCache) Prune(now time.Time) { p.c.prune(now) }

func (p PendingCache) Len() int {
	p.c.mu.Lock()
	defer p.c.mu.Unlock()
	return len(p.c.byID)
}

// Pending is s's own cache.
func Pending(s *Service) PendingCache { return PendingCache{s.pending} }

// MintSession creates the session a sign-in would for c and userID,
// through createSession with no admission.
func MintSession(ctx context.Context, s *Service, c Client, userID int64) (access.Session, error) {
	r, err := s.begin()
	if err != nil {
		return access.Session{}, err
	}
	in, err := s.createSession(ctx, r, c, &sessionOp{method: access.MethodPassword, in: func(tx Tx) (*access.User, error) {
		u, found, err := tx.UserByID(ctx, userID)
		if err == nil && !found {
			err = ErrNotFound
		}
		return u, err
	}})
	return in.Session, err
}
