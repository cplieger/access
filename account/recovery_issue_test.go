package account_test

import (
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
)

// recoveryTokens is every stored recovery token, expired ones included.
func recoveryTokens(t *testing.T, f *fixture) []access.OneTimeToken {
	t.Helper()
	toks, err := f.mem.LiveOneTimeTokens(t.Context(), []access.TokenPurpose{access.PurposeRecovery}, time.Time{})
	if err != nil {
		t.Fatalf("LiveOneTimeTokens: %v", err)
	}
	return toks
}

func TestIssueRecoveryRefusesSelf(t *testing.T) {
	t.Parallel()
	for name, inner := range map[string]account.Policy{"role_policy": account.RolePolicy{}, "single_owner": account.SingleOwnerPolicy{}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pol := &recordingPolicy{inner: inner}
			w := newAdminWorld(t, options{}, pol)
			w.fs.resetRecord()
			_, err := w.f.svc.IssueRecovery(t.Context(), account.As(w.pr), w.root.ID, 0)
			if reason(err) != "self_recovery" {
				t.Errorf("an admin's recovery for itself = %v, want self_recovery", err)
			}
			if n := pol.calls(); n != 0 {
				t.Errorf("Policy calls = %d, want none", n)
			}
			if c := w.fs.recorded(); len(c) != 0 {
				t.Errorf("store calls %+v, want none", c)
			}
			if n := len(recoveryTokens(t, w.f)); n != 0 || len(eventsOf(w.f.events, account.EventRecoveryIssued)) != 0 {
				t.Errorf("the refusal stored %d tokens or emitted", n)
			}
			if _, err := w.f.svc.IssueRecovery(t.Context(), account.OutOfBand("admin-socket"), w.root.ID, 0); err != nil {
				t.Errorf("OutOfBand recovery for the admin = %v, want nil", err)
			}
			_, err = w.f.svc.IssueRecovery(t.Context(), account.As(w.pr), w.alice.ID, 0)
			if name == "role_policy" && err != nil {
				t.Errorf("the admin's recovery for alice = %v, want nil", err)
			}
			if name == "single_owner" && reason(err) != "out_of_band_only" {
				t.Errorf("the owner's recovery for alice = %v, want out_of_band_only", err)
			}
		})
	}
}

// TestTokenTTLNegative: every token issuer refuses a negative lifetime with
// ErrTTLNegative and stores nothing.
func TestTokenTTLNegative(t *testing.T) {
	t.Parallel()
	w := newAdminWorld(t, options{}, nil)
	ctx := t.Context()
	issuers := map[string]func() error{
		"IssueRecovery": func() error {
			_, err := w.f.svc.IssueRecovery(ctx, account.As(w.pr), w.alice.ID, -time.Second)
			return err
		},
		"IssueRecovery_out_of_band": func() error {
			_, err := w.f.svc.IssueRecovery(ctx, account.OutOfBand("admin-socket"), w.alice.ID, -time.Second)
			return err
		},
		"CreateInvite": func() error {
			_, err := w.f.svc.CreateInvite(ctx, w.pr, access.RoleUser, -time.Second)
			return err
		},
		"IssueSetupToken": func() error {
			_, err := w.f.svc.IssueSetupToken(ctx, account.OutOfBand("admin-socket"), -time.Second)
			return err
		},
	}
	for name, issue := range issuers {
		if err := issue(); !errors.Is(err, account.ErrTTLNegative) {
			t.Errorf("%s(-1s) = %v, want ErrTTLNegative", name, err)
		}
	}
	toks, err := w.f.mem.LiveOneTimeTokens(ctx, []access.TokenPurpose{access.PurposeRecovery, access.PurposeInvite, access.PurposeSetup}, time.Time{})
	if err != nil || len(toks) != 0 {
		t.Errorf("stored tokens %+v, %v, want none", toks, err)
	}
}

func TestIssueRecoveryVoidsEarlier(t *testing.T) {
	t.Parallel()
	clock := laterClock()
	w := newAdminWorld(t, options{edit: func(c *account.Config) { c.Now = clock.now }}, nil)
	bob := mustUser(t, w.f.mem, "bob", access.RoleUser)
	oob := account.OutOfBand("admin-socket")
	ctx := t.Context()
	bobs, err := w.f.svc.IssueRecovery(ctx, oob, bob.ID, 0)
	if err != nil {
		t.Fatalf("IssueRecovery(bob) = %v", err)
	}
	first, err := w.f.svc.IssueRecovery(ctx, oob, w.alice.ID, 0)
	if err != nil || !first.ExpiresAt.Equal(clock.now().Add(15*time.Minute)) {
		t.Fatalf("an out-of-band default = %v, %v; want 15 min", first.ExpiresAt, err)
	}
	second, err := w.f.svc.IssueRecovery(ctx, account.As(w.pr), w.alice.ID, 0)
	if err != nil || !second.ExpiresAt.Equal(clock.now().Add(24*time.Hour)) {
		t.Fatalf("an admin's default = %v, %v; want 24 h", second.ExpiresAt, err)
	}
	stored := recoveryTokens(t, w.f)
	if len(stored) != 2 {
		t.Fatalf("recovery tokens = %d, want bob's and alice's second", len(stored))
	}
	for _, tok := range stored {
		switch {
		case tok.Hash.Equal(hashOf(first)):
			t.Error("alice's first token survives the second")
		case tok.Subject == w.alice.ID && !tok.Hash.Equal(hashOf(second)):
			t.Error("alice holds an unknown token")
		case tok.Subject == bob.ID && !tok.Hash.Equal(hashOf(bobs)):
			t.Error("bob's token changed")
		}
	}
	evs := eventsOf(w.f.events, account.EventRecoveryIssued)
	if len(evs) != 3 || evs[1].Actor.OutOfBand != "admin-socket" || evs[2].Actor.SessionID != w.pr.SessionID || evs[2].UserID != w.alice.ID {
		t.Errorf("EventRecoveryIssued = %+v, want three naming their actors", evs)
	}
	if _, err := w.f.svc.IssueRecovery(ctx, oob, w.alice.ID, 7*15*time.Minute+time.Second); !errors.Is(err, account.ErrTTLTooLong) {
		t.Errorf("an out-of-band ttl over 7 × 15 min = %v, want ErrTTLTooLong", err)
	}
	if _, err := w.f.svc.IssueRecovery(ctx, account.As(w.pr), w.alice.ID, 7*24*time.Hour); err != nil {
		t.Errorf("an admin's ttl of 7 × 24 h = %v, want nil", err)
	}
	if _, err := w.f.svc.IssueRecovery(ctx, oob, 9999, 0); !errors.Is(err, account.ErrNotFound) {
		t.Errorf("recovery for a missing user = %v, want ErrNotFound", err)
	}
	if _, err := w.f.svc.IssueRecovery(ctx, account.Actor{}, w.alice.ID, 0); !errors.Is(err, account.ErrSessionRequired) {
		t.Errorf("recovery from the zero Actor = %v, want ErrSessionRequired", err)
	}
}
