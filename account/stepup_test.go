package account_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/failreason"
	"github.com/cplieger/access/ratelimit"
)

// signedInVia stores a full session of u whose AuthMethod is method,
// signed in now, and returns its principal and token.
func (f *fixture) signedInVia(t testing.TB, u *access.User, method access.Method) (access.Principal, access.Secret) {
	t.Helper()
	now := time.Now()
	return f.principalOf(t, &access.Session{
		ID: newSessionID(t), UserID: u.ID, Kind: access.SessionFull,
		AuthMethod: method, CreatedAt: now, LastActivity: now, AuthTime: now,
	})
}

func (p *pwFixture) stepUp(ctx context.Context, c account.Client, pr access.Principal, pw string) (account.Issued, error) {
	return p.svc.StepUpPassword(ctx, c, pr, access.NewSecret(pw))
}

// failStepUps makes n wrong step-ups of pr from c and requires each to be
// ErrInvalidCredentials.
func (p *pwFixture) failStepUps(t *testing.T, c account.Client, pr access.Principal, n int) {
	t.Helper()
	for range n {
		if _, err := p.stepUp(t.Context(), c, pr, wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("wrong step-up = %v, want ErrInvalidCredentials", err)
		}
	}
}

func TestStepUpPassword(t *testing.T) {
	t.Parallel()
	t.Run("rotates_and_resets", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, oldToken := p.signedInVia(t, u, access.MethodPasskey)
		p.failStepUps(t, localClient, pr, 3)
		if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != 3 {
			t.Fatalf("untrusted record after three wrong step-ups = %+v, want count 3", rec)
		}
		before := time.Now()
		is, err := p.stepUp(t.Context(), localClient, pr, goodPassword)
		if err != nil {
			t.Fatalf("StepUpPassword = %v, want a rotation", err)
		}
		if is.Token.IsZero() || is.DeviceCookie.IsZero() {
			t.Errorf("Issued token zero %t, device cookie zero %t; want both set", is.Token.IsZero(), is.DeviceCookie.IsZero())
		}
		if is.Session.ID != pr.SessionID || is.Session.AuthMethod != access.MethodPassword || is.Session.AuthTime.Before(before) {
			t.Errorf("Issued.Session = %+v, want session %s with AuthMethod password and AuthTime from now", is.Session, pr.SessionID)
		}
		if _, err := p.authenticate(t.Context(), oldToken); err == nil {
			t.Error("the pre-rotation token still authenticates")
		}
		next, err := p.authenticate(t.Context(), is.Token)
		if err != nil {
			t.Fatalf("the rotated token = %v, want a principal", err)
		}
		if next.SessionID != pr.SessionID || next.Method != access.MethodPassword || !next.AuthTime.Equal(is.Session.AuthTime) {
			t.Errorf("rotated principal = %+v, want session %s re-proved by password at %v", next, pr.SessionID, is.Session.AuthTime)
		}
		for _, trusted := range []bool{false, true} {
			if rec, found := record(t, p.mem, p.svc, "alice", trusted); found {
				t.Errorf("record (trusted %t) = %+v after the step-up, want none", trusted, rec)
			}
		}
		up := eventsOf(p.events, account.EventSteppedUp)
		want := account.EventActor{SessionID: pr.SessionID, UserID: u.ID}
		if len(up) != 1 || up[0].UserID != u.ID || up[0].Method != access.MethodPassword || up[0].Actor != want ||
			len(up[0].SessionIDs) != 1 || up[0].SessionIDs[0] != pr.SessionID {
			t.Errorf("EventSteppedUp = %+v, want one for alice's session %s by password", up, pr.SessionID)
		}
		cookie := localClient
		cookie.Device = is.DeviceCookie
		if _, err := p.stepUp(t.Context(), cookie, next, wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Fatalf("wrong step-up with the issued device cookie = %v", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", true); rec.Count != 1 {
			t.Errorf("trusted record after a wrong step-up with the issued cookie = %+v, want count 1", rec)
		}
	})
	t.Run("wrong_password_keeps_session", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, token := p.signedInVia(t, u, access.MethodPasskey)
		if _, err := p.stepUp(t.Context(), localClient, pr, wrongPassword); !errors.Is(err, account.ErrInvalidCredentials) || failreason.Of(err) != "" {
			t.Fatalf("wrong step-up = %v, reason %q; want ErrInvalidCredentials with no reason", err, failreason.Of(err))
		}
		again, err := p.authenticate(t.Context(), token)
		if err != nil || again.Method != access.MethodPasskey || !again.AuthTime.Equal(pr.AuthTime) {
			t.Errorf("session after a wrong step-up = %+v, %v; want it unchanged", again, err)
		}
		if got := eventsOf(p.events, account.EventSteppedUp); len(got) != 0 {
			t.Errorf("EventSteppedUp after a wrong step-up = %v, want none", got)
		}
	})
	t.Run("locked_refuses_right_password", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		seedLock(t, p.mem, p.svc, "alice", false, false)
		zero := p.counted.zeroCompared()
		_, err := p.stepUp(t.Context(), localClient, pr, goodPassword)
		if !errors.Is(err, account.ErrInvalidCredentials) || failreason.Of(err) != failreason.MethodLocked {
			t.Errorf("right step-up while the untrusted context is locked = %v, reason %q; want ErrInvalidCredentials, reason %q",
				err, failreason.Of(err), failreason.MethodLocked)
		}
		if err != nil && err.Error() != account.ErrInvalidCredentials.Error() {
			t.Errorf("locked step-up text = %q, want the sentinel's %q", err, account.ErrInvalidCredentials)
		}
		if got := p.counted.zeroCompared(); got != zero+1 {
			t.Errorf("zero-hash comparisons = %d, want %d: a locked record compares against the zero hash", got, zero+1)
		}
	})
	t.Run("not_a_session", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		f := p.fixture
		for name, pr := range map[string]access.Principal{
			"key":      f.keyPrincipal(t, u, "read"),
			"recovery": f.sessionPrincipal(t, u, access.SessionRecovery, time.Now()),
			"bypass":   f.bypassPrincipal(t),
			"zero":     {},
		} {
			if _, err := p.stepUp(t.Context(), localClient, pr, goodPassword); !errors.Is(err, account.ErrSessionRequired) {
				t.Errorf("StepUpPassword(%s) = %v, want ErrSessionRequired", name, err)
			}
		}
		if n := p.counted.reserved.Load(); n != 0 {
			t.Errorf("refused step-ups reserved %d permits, want none", n)
		}
	})
	t.Run("session_gone", func(t *testing.T) {
		t.Parallel()
		var hk armed
		p := newPW(t, pwOptions{hooks: account.Hooks{AfterVerify: hk.hook}})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		hk.arm(func(ctx context.Context) {
			if err := p.mem.DeleteSession(ctx, access.SessionRef{ID: pr.SessionID, UserID: u.ID}); err != nil {
				t.Errorf("DeleteSession: %v", err)
			}
		})
		if _, err := p.stepUp(t.Context(), localClient, pr, goodPassword); !errors.Is(err, account.ErrSessionGone) {
			t.Errorf("step-up of a session ended after its verify = %v, want ErrSessionGone", err)
		}
		if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != 1 {
			t.Errorf("record after the refused success Update = %+v, want the attempt still counted", rec)
		}
		if got := eventsOf(p.events, account.EventSteppedUp); len(got) != 0 {
			t.Errorf("EventSteppedUp = %v, want none", got)
		}
	})
}

// TestStepUpLimitsAccountAndDevice: a step-up is limited on the account and
// device dimensions only, since its caller already holds a full session.
func TestStepUpLimitsAccountAndDevice(t *testing.T) {
	t.Parallel()
	refusedIn := func(t *testing.T, err error, dim string) {
		t.Helper()
		if re, ok := errors.AsType[*ratelimit.RefusedError](err); !ok || re.Dimension != dim {
			t.Errorf("step-up past the %s window = %v, want a *ratelimit.RefusedError in %q", dim, err, dim)
		}
	}
	t.Run("ip_neither_checked_nor_charged", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{limiter: ipLimit(1)})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		p.failStepUps(t, localClient, pr, 3)
		ipOnly := ratelimit.Attempt{IP: ratelimit.IPKey(localClient.IP)}
		res, err := p.limiter.Attempt(ipOnly)
		if err != nil {
			t.Fatalf("IP-only attempt after three wrong step-ups = %v, want admitted: a step-up charged the IP", err)
		}
		res.Fail()
		if _, err := p.limiter.Attempt(ipOnly); err == nil {
			t.Fatal("the IP window of one admitted a second attempt; the fixture is not limiting the IP")
		}
		if _, err := p.stepUp(t.Context(), localClient, pr, goodPassword); err != nil {
			t.Errorf("right step-up from an IP whose window is spent = %v, want a rotation", err)
		}
	})
	t.Run("account_window_refuses", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{limiter: func(c *ratelimit.Config) { c.Account = ratelimit.Rate{Limit: 2, Window: time.Hour} }})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		p.failStepUps(t, localClient, pr, 2)
		_, err := p.stepUp(t.Context(), localClient, pr, goodPassword)
		refusedIn(t, err, "account")
	})
	t.Run("device_window_refuses", func(t *testing.T) {
		t.Parallel()
		p := newPW(t, pwOptions{limiter: func(c *ratelimit.Config) { c.Device = ratelimit.Rate{Limit: 2, Window: time.Hour} }})
		u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
		trusted := localClient
		trusted.Device = p.deviceCookie(t, localClient, "alice", goodPassword)
		pr, _ := p.signedInVia(t, u, access.MethodPasskey)
		p.failStepUps(t, trusted, pr, 2)
		_, err := p.stepUp(t.Context(), trusted, pr, goodPassword)
		refusedIn(t, err, "device")
	})
}

func TestStepUpPasswordLoginDisabled(t *testing.T) {
	t.Parallel()
	p := newPW(t, pwOptions{rules: func() account.Rules { return account.Rules{DisablePasswordLogin: true} }})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	pr, token := p.signedInVia(t, u, access.MethodPasskey)
	if _, err := p.stepUp(t.Context(), localClient, pr, goodPassword); !errors.Is(err, account.ErrPasswordLoginDisabled) {
		t.Errorf("StepUpPassword with password sign-in disabled = %v, want ErrPasswordLoginDisabled", err)
	}
	if n := p.counted.reserved.Load(); n != 0 {
		t.Errorf("the refused step-up reserved %d permits, want none", n)
	}
	if _, found := record(t, p.mem, p.svc, "alice", false); found {
		t.Error("the refused step-up wrote a failure record")
	}
	if again, err := p.authenticate(t.Context(), token); err != nil || again.Method != access.MethodPasskey {
		t.Errorf("session after the refused step-up = %+v, %v; want it unchanged", again, err)
	}
}

func TestStepUpCountsWhileAllowanceSpent(t *testing.T) {
	t.Parallel()
	p := newPW(t, pwOptions{edit: noTick})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	pr, _ := p.signedInVia(t, u, access.MethodPasskey)
	account.LeaveAllowance(p.svc, 0)
	_, err := p.login(t.Context(), clientAt(1), "ghost", wrongPassword)
	if refused, ok := errors.AsType[*ratelimit.RefusedError](err); !ok || refused.Dimension != "untrusted" {
		t.Fatalf("untrusted sign-in with the allowance spent = %v, want the untrusted refusal", err)
	}
	p.failStepUps(t, clientAt(2), pr, 1)
	if rec, _ := record(t, p.mem, p.svc, "alice", false); rec.Count != 1 {
		t.Errorf("untrusted record after a wrong step-up with the allowance spent = %+v, want count 1", rec)
	}
	compared := p.counted.verified()
	if len(compared) != 1 || !compared[0].Equal(u.PasswordHash) {
		t.Errorf("compared %d hashes, want alice's stored hash once", len(compared))
	}
	if _, err := p.stepUp(t.Context(), clientAt(2), pr, goodPassword); err != nil {
		t.Errorf("right step-up with the allowance spent = %v, want a rotation", err)
	}
	if got := account.AllowanceUsed(p.svc); got != account.MaxUntrustedCounts {
		t.Errorf("allowance used = %d, want %d: a step-up takes no slot", got, account.MaxUntrustedCounts)
	}
}

func TestStepUpFailuresShareTrustedLock(t *testing.T) {
	t.Parallel()
	p := newPW(t, pwOptions{})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	laptop, phone := clientAt(1), clientAt(2)
	laptop.Device = p.deviceCookie(t, laptop, "alice", goodPassword)
	phone.Device = p.deviceCookie(t, phone, "alice", goodPassword)
	pr, _ := p.signedInVia(t, u, access.MethodPasskey)
	p.failN(t, laptop, "alice", 60)
	p.failStepUps(t, phone, pr, 40)
	if rec, _ := record(t, p.mem, p.svc, "alice", true); !rec.Locked || rec.Count != account.FailureCap {
		t.Errorf("trusted record = %+v, want locked at count %d", rec, account.FailureCap)
	}
	if rec, found := record(t, p.mem, p.svc, "alice", false); found {
		t.Errorf("untrusted record = %+v, want none", rec)
	}
	if _, err := p.login(t.Context(), laptop, "alice", goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
		t.Errorf("trusted sign-in from the laptop after the shared lock = %v, want ErrInvalidCredentials", err)
	}
	if _, err := p.stepUp(t.Context(), phone, pr, goodPassword); !errors.Is(err, account.ErrInvalidCredentials) {
		t.Errorf("trusted step-up from the phone after the shared lock = %v, want ErrInvalidCredentials", err)
	}
}
