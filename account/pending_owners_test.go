package account_test

import (
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

// mustPutToken is c.PutToken, failing t on a refusal.
func mustPutToken(t testing.TB, c account.PendingCache, purpose account.PendingPurpose, token access.Hash, now time.Time) string {
	t.Helper()
	id, err := c.PutToken(purpose, token, now)
	if err != nil {
		t.Fatalf("PutToken(%d) = %v", purpose, err)
	}
	return id
}

// tokenHash is a distinct token hash for each n.
func tokenHash(n int) access.Hash { return access.NewHash("token " + string(rune('a'+n))) }

// requireFull requires err to be a full list's refusal, retrying when
// the earliest entry, put at first, expires lifetime after it.
func requireFull(t testing.TB, err error, first, now time.Time, lifetime time.Duration) {
	t.Helper()
	refused, ok := errors.AsType[*ratelimit.RefusedError](err)
	if !ok {
		t.Fatalf("a newcomer to a full list = %v, want *ratelimit.RefusedError", err)
	}
	if want := first.Add(lifetime).Sub(now); refused.RetryAfter != want {
		t.Errorf("RetryAfter = %s, want %s: the earliest entry's expiry", refused.RetryAfter, want)
	}
}

// ownedTable is one list whose entries a user or a token owns.
type ownedTable struct {
	name     string
	purpose  account.PendingPurpose
	lifetime time.Duration
	max      int // its cap in a Service with the default MaxPending
	put      func(c account.PendingCache, owner int, now time.Time) (string, error)
}

func ownedTables() []ownedTable {
	byUser := func(purpose account.PendingPurpose) func(account.PendingCache, int, time.Time) (string, error) {
		return func(c account.PendingCache, owner int, now time.Time) (string, error) {
			return c.Put(purpose, access.User{ID: int64(owner + 1)}, now)
		}
	}
	byToken := func(purpose account.PendingPurpose) func(account.PendingCache, int, time.Time) (string, error) {
		return func(c account.PendingCache, owner int, now time.Time) (string, error) {
			return c.PutToken(purpose, tokenHash(owner), now)
		}
	}
	return []ownedTable{
		{name: "pending_sign_in", purpose: account.PurposeSignIn, lifetime: 10 * time.Minute, max: 10000, put: byUser(account.PurposeSignIn)},
		{name: "totp_enrolment", purpose: account.PurposeEnrolTOTP, lifetime: 10 * time.Minute, max: 10000, put: byUser(account.PurposeEnrolTOTP)},
		{name: "passkey_add", purpose: account.PurposeAddPasskey, lifetime: webauthn.CeremonyTimeout, max: 10000, put: byUser(account.PurposeAddPasskey)},
		{name: "passkey_step_up", purpose: account.PurposeStepUp, lifetime: webauthn.CeremonyTimeout, max: 10000, put: byUser(account.PurposeStepUp)},
		{name: "setup_ceremony", purpose: account.PurposeSetup, lifetime: webauthn.CeremonyTimeout, max: 10000, put: byToken(account.PurposeSetup)},
		{name: "setup_or_invite_draft", purpose: account.PurposeDraft, lifetime: 10 * time.Minute, max: 1000, put: byToken(account.PurposeDraft)},
	}
}

// TestPendingOwnedTables checks every list of in-flight entries a user or
// a token owns: one entry per owner, a new begin replacing its owner's
// earlier one, and a full list refusing a newcomer with the earliest
// entry's expiry rather than evicting anyone's entry.
func TestPendingOwnedTables(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range ownedTables() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			t.Run("flood_leaves_the_victim", func(t *testing.T) {
				t.Parallel()
				c := account.NewPendingCache(10000)
				victim, err := tc.put(c, 1, t0)
				if err != nil {
					t.Fatalf("the victim's begin = %v", err)
				}
				for i := range tc.max + 1 {
					if _, err := tc.put(c, 2, t0.Add(time.Duration(i)*time.Microsecond)); err != nil {
						t.Fatalf("begin %d of one owner = %v, want each to replace the last", i+1, err)
					}
				}
				if !c.Peek(victim, tc.purpose, t0.Add(time.Second)) {
					t.Errorf("one owner's %d begins evicted another owner's entry", tc.max+1)
				}
				if n := c.Len(); n != 2 {
					t.Errorf("entries after the flood = %d, want 2: one per owner", n)
				}
			})
			t.Run("second_begin_replaces_the_first", func(t *testing.T) {
				t.Parallel()
				c := account.NewPendingCache(10000)
				first, err := tc.put(c, 1, t0)
				if err != nil {
					t.Fatalf("first begin = %v", err)
				}
				second, err := tc.put(c, 1, t0.Add(time.Second))
				if err != nil {
					t.Fatalf("second begin = %v", err)
				}
				if c.Peek(first, tc.purpose, t0.Add(time.Second)) {
					t.Error("an owner's earlier entry survived its new begin")
				}
				if !c.Peek(second, tc.purpose, t0.Add(time.Second)) {
					t.Error("the new begin's entry is gone")
				}
			})
			t.Run("full_refuses_a_newcomer", func(t *testing.T) {
				t.Parallel()
				c := account.NewPendingCache(10000)
				c.SetMax(tc.purpose, 2)
				a, errA := tc.put(c, 1, t0)
				b, errB := tc.put(c, 2, t0.Add(time.Second))
				if errA != nil || errB != nil {
					t.Fatalf("filling begins = %v, %v", errA, errB)
				}
				now := t0.Add(time.Minute)
				_, err := tc.put(c, 3, now)
				requireFull(t, err, t0, now, tc.lifetime)
				for name, id := range map[string]string{"first": a, "second": b} {
					if !c.Peek(id, tc.purpose, now) {
						t.Errorf("the %s owner's entry is gone after a refused newcomer", name)
					}
				}
				if again, err := tc.put(c, 1, now); err != nil || !c.Peek(again, tc.purpose, now) {
					t.Errorf("an owner's new begin in a full list = %v, want it to replace its own entry", err)
				}
				if _, err := tc.put(c, 3, t0.Add(time.Second+tc.lifetime)); err != nil {
					t.Errorf("a newcomer once the earliest entry expired = %v, want admitted", err)
				}
			})
		})
	}
}

// TestPendingAnonymousTables checks the lists anyone can fill, which keep
// their oldest-first bound and never refuse: passkey sign-in and
// registration ceremonies, and registration drafts.
func TestPendingAnonymousTables(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for name, purpose := range map[string]account.PendingPurpose{
		"passkey_sign_in":    account.PurposeLogin,
		"registration":       account.PurposeRegistration,
		"registration_draft": account.PurposeRegistrationDraft,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := account.NewPendingCache(10000)
			c.SetMax(purpose, 2)
			ids := make([]string, 3)
			for i := range ids {
				ids[i] = mustPut(t, c, purpose, access.User{}, t0.Add(time.Duration(i)*time.Second))
			}
			for i, id := range ids {
				if want := i > 0; c.Peek(id, purpose, t0.Add(time.Minute)) != want {
					t.Errorf("entry %d live = %t, want %t: the oldest goes first", i, !want, want)
				}
			}
		})
	}
	t.Run("never_evict_an_owned_entry", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(3)
		owned := map[account.PendingPurpose]string{}
		for _, purpose := range []account.PendingPurpose{account.PurposeAddPasskey, account.PurposeStepUp} {
			owned[purpose] = mustPut(t, c, purpose, access.User{ID: 1}, t0)
		}
		owned[account.PurposeSetup] = mustPutToken(t, c, account.PurposeSetup, tokenHash(1), t0)
		for i := range 5 {
			mustPut(t, c, account.PurposeLogin, access.User{}, t0.Add(time.Duration(i)*time.Second))
		}
		for purpose, id := range owned {
			if !c.Peek(id, purpose, t0.Add(time.Minute)) {
				t.Errorf("a flood of passkey sign-in begins evicted a purpose %d ceremony", purpose)
			}
		}
	})
}

// TestPendingTicketCeremonies checks the passkey ceremonies a pending
// sign-in begins: one per ticket, a new begin replacing the last, ended
// with its ticket, and outside every list anonymous begins fill.
func TestPendingTicketCeremonies(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	alice := access.User{ID: 1}
	for name, purpose := range map[string]account.PendingPurpose{
		"second_factor": account.PurposeSecondFactor,
		"enrol_passkey": account.PurposeEnrolPasskey,
		"set_passkey":   account.PurposeSetPasskey,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Run("one_per_ticket", func(t *testing.T) {
				t.Parallel()
				c := account.NewPendingCache(10)
				ticket := mustPut(t, c, account.PurposeSignIn, alice, t0)
				first, ok1 := c.PutOnTicket(ticket, purpose, alice, t0)
				second, ok2 := c.PutOnTicket(ticket, purpose, alice, t0)
				if !ok1 || !ok2 {
					t.Fatalf("begins on a live ticket = %t, %t", ok1, ok2)
				}
				if _, ok := c.Take(first, purpose, t0); ok {
					t.Error("a ticket's earlier ceremony survived its new begin")
				}
				if _, ok := c.Take(second, purpose, t0); !ok {
					t.Error("the ticket's new ceremony is gone")
				}
			})
			t.Run("ends_with_its_ticket", func(t *testing.T) {
				t.Parallel()
				c := account.NewPendingCache(10)
				dropped := mustPut(t, c, account.PurposeSignIn, alice, t0)
				ceremony, _ := c.PutOnTicket(dropped, purpose, alice, t0)
				c.Drop(dropped)
				if _, ok := c.Take(ceremony, purpose, t0); ok {
					t.Error("a ceremony outlived its dropped ticket")
				}
				replaced := mustPut(t, c, account.PurposeSignIn, alice, t0)
				ceremony, _ = c.PutOnTicket(replaced, purpose, alice, t0)
				mustPut(t, c, account.PurposeSignIn, alice, t0)
				if _, ok := c.Take(ceremony, purpose, t0); ok {
					t.Error("a ceremony outlived its replaced ticket")
				}
				if n := c.Len(); n != 1 {
					t.Errorf("entries = %d, want only the live ticket", n)
				}
			})
			t.Run("needs_a_live_ticket", func(t *testing.T) {
				t.Parallel()
				c := account.NewPendingCache(10)
				if _, ok := c.PutOnTicket("unknown", purpose, alice, t0); ok {
					t.Error("a ceremony began on no ticket")
				}
				ticket := mustPut(t, c, account.PurposeSignIn, alice, t0)
				if _, ok := c.PutOnTicket(ticket, purpose, alice, t0.Add(10*time.Minute)); ok {
					t.Error("a ceremony began on an expired ticket")
				}
				if n := c.Len(); n != 1 {
					t.Errorf("entries = %d, want only the ticket", n)
				}
			})
			t.Run("anonymous_flood_never_evicts_it", func(t *testing.T) {
				t.Parallel()
				c := account.NewPendingCache(2)
				ticket := mustPut(t, c, account.PurposeSignIn, alice, t0)
				ceremony, _ := c.PutOnTicket(ticket, purpose, alice, t0)
				for i := range 5 {
					mustPut(t, c, account.PurposeLogin, access.User{}, t0.Add(time.Duration(i)*time.Second))
				}
				if _, ok := c.Take(ceremony, purpose, t0.Add(time.Minute)); !ok {
					t.Error("a flood of passkey sign-in begins evicted a ticket's ceremony")
				}
			})
			t.Run("lives_one_ceremony_timeout", func(t *testing.T) {
				t.Parallel()
				c := account.NewPendingCache(10)
				ticket := mustPut(t, c, account.PurposeSignIn, alice, t0)
				ceremony, _ := c.PutOnTicket(ticket, purpose, alice, t0)
				if _, ok := c.Take(ceremony, purpose, t0.Add(webauthn.CeremonyTimeout)); ok {
					t.Error("a ticket's ceremony outlived CeremonyTimeout")
				}
			})
		})
	}
}

// TestBeginTOTPOwnEntry checks a session's TOTP enrolment through the
// Service: one user's begins never void another user's enrolment, a user's
// new begin replaces their own, and a full list refuses a newcomer.
func TestBeginTOTPOwnEntry(t *testing.T) {
	t.Parallel()
	t0 := time.Now().Truncate(time.Second)
	world := func(t *testing.T) (*sfFixture, access.Principal, access.Principal) {
		f := newSF(t, account.Rules{}, pwOptions{})
		f.at.Store(&t0)
		alice := f.sessionPrincipal(t, passwordUser(t, f.mem, f.hasher, "alice", goodPassword), t0)
		mallory := f.sessionPrincipal(t, passwordUser(t, f.mem, f.hasher, "mallory", goodPassword), t0)
		return f, alice, mallory
	}
	begin := func(t *testing.T, f *sfFixture, pr access.Principal) (account.TOTPEnrolment, error) {
		return f.svc.BeginTOTP(t.Context(), pr)
	}
	finish := func(t *testing.T, f *sfFixture, pr access.Principal, e account.TOTPEnrolment) error {
		_, err := f.svc.FinishTOTP(t.Context(), clientAt(1), pr, account.TOTPFinish{Ticket: e.Ticket, Code: codeAt(secretOf(t, e), t0)})
		return err
	}
	t.Run("flood_leaves_the_victim", func(t *testing.T) {
		t.Parallel()
		f, alice, mallory := world(t)
		e, err := begin(t, f, alice)
		if err != nil {
			t.Fatalf("alice's BeginTOTP = %v", err)
		}
		for i := range 10001 {
			if _, err := begin(t, f, mallory); err != nil {
				t.Fatalf("mallory's BeginTOTP %d = %v", i+1, err)
			}
		}
		if err := finish(t, f, alice, e); err != nil {
			t.Errorf("alice's FinishTOTP after another user's 10,001 begins = %v, want enrolled", err)
		}
	})
	t.Run("second_begin_replaces_the_first", func(t *testing.T) {
		t.Parallel()
		f, alice, _ := world(t)
		first, err1 := begin(t, f, alice)
		second, err2 := begin(t, f, alice)
		if err1 != nil || err2 != nil {
			t.Fatalf("BeginTOTP = %v, %v", err1, err2)
		}
		if err := finish(t, f, alice, first); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("FinishTOTP of the replaced ticket = %v, want access.ErrTokenInvalid", err)
		}
		if err := finish(t, f, alice, second); err != nil {
			t.Errorf("FinishTOTP of the new ticket = %v, want enrolled", err)
		}
	})
	t.Run("full_refuses_a_newcomer", func(t *testing.T) {
		t.Parallel()
		f, alice, mallory := world(t)
		account.PendingOf(f.svc).SetMax(account.PurposeEnrolTOTP, 2)
		ea, errA := begin(t, f, alice)
		em, errM := begin(t, f, mallory)
		if errA != nil || errM != nil {
			t.Fatalf("filling begins = %v, %v", errA, errM)
		}
		carol := f.sessionPrincipal(t, passwordUser(t, f.mem, f.hasher, "carol", goodPassword), t0)
		_, err := begin(t, f, carol)
		requireFull(t, err, t0, t0, 10*time.Minute)
		if err := finish(t, f, alice, ea); err != nil {
			t.Errorf("alice's FinishTOTP after the refusal = %v", err)
		}
		if err := finish(t, f, mallory, em); err != nil {
			t.Errorf("mallory's FinishTOTP after the refusal = %v", err)
		}
	})
}

// TestStepOneFullList checks a pending sign-in through the Service: a
// full list refuses a newcomer's step 1 and leaves every ticket live.
func TestStepOneFullList(t *testing.T) {
	t.Parallel()
	t0 := time.Now().Truncate(time.Second)
	f := newSF(t, account.Rules{}, pwOptions{})
	f.at.Store(&t0)
	login := func(name string) (account.LoginResult, error) {
		return f.svc.PasswordLogin(t.Context(), localClient, account.Credentials{Username: name, Password: access.NewSecret(goodPassword)})
	}
	for _, name := range []string{"alice", "bob"} {
		storeTOTP(t, f.mem, passwordUser(t, f.mem, f.hasher, name, goodPassword))
	}
	account.PendingOf(f.svc).SetMax(account.PurposeSignIn, 1)
	out, err := login("alice")
	ticket := pending(t, out, err, account.NextSecondFactor, access.MethodTOTP).Ticket
	_, err = login("bob")
	requireFull(t, err, t0, t0, 10*time.Minute)
	if _, live := account.TicketOf(f.svc, ticket); !live {
		t.Error("alice's ticket is gone after bob's refused step 1")
	}
	out, err = login("alice")
	if again := pending(t, out, err, account.NextSecondFactor, access.MethodTOTP).Ticket; again.Reveal() == ticket.Reveal() {
		t.Error("alice's step 1 again answered her old ticket")
	}
	if _, live := account.TicketOf(f.svc, ticket); live {
		t.Error("alice's earlier ticket survived her new step 1")
	}
}

// TestInviteDraftOwnEntry checks an invite's draft through the Service:
// accepting one invite again replaces its draft, and another invite's
// draft is untouched.
func TestInviteDraftOwnEntry(t *testing.T) {
	t.Parallel()
	f, p := inviteWorld(t, ruleOn)
	first := inviteDraft(t, f, f.invite(t, p, access.RoleUser), "newcomer")
	inv := f.invite(t, p, access.RoleUser)
	old := inviteDraft(t, f, inv, "other")
	fresh := inviteDraft(t, f, inv, "other")
	if _, live := account.TicketOf(f.svc, old); live {
		t.Error("an invite's earlier draft survived its acceptance again")
	}
	for name, ticket := range map[string]access.Secret{"fresh": fresh, "other invite's": first} {
		if _, live := account.TicketOf(f.svc, ticket); !live {
			t.Errorf("the %s draft is gone", name)
		}
	}
}

// TestPendingReservations checks a place held in an owned list before the
// step that fills it spends anything: a held place counts toward the cap,
// a newcomer is refused while the list is full, filling it never fails,
// and releasing it gives it back once.
func TestPendingReservations(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tables := []struct {
		drop     func(c account.PendingCache, id string, userID int64)
		name     string
		purpose  account.PendingPurpose
		lifetime time.Duration
	}{
		{name: "pending_sign_in", purpose: account.PurposeSignIn, lifetime: 10 * time.Minute, drop: func(c account.PendingCache, _ string, userID int64) { c.DropUser(userID) }},
		{name: "passkey_add", purpose: account.PurposeAddPasskey, lifetime: webauthn.CeremonyTimeout, drop: func(c account.PendingCache, id string, _ int64) { c.Drop(id) }},
	}
	user := func(n int) access.User { return access.User{ID: int64(n)} }
	for _, tc := range tables {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			full := func(t *testing.T, max int) account.PendingCache {
				c := account.NewPendingCache(10000)
				c.SetMax(tc.purpose, max)
				for i := range max {
					mustPut(t, c, tc.purpose, user(i+1), t0.Add(time.Duration(i)*time.Second))
				}
				return c
			}
			t.Run("full_refuses_a_newcomer", func(t *testing.T) {
				t.Parallel()
				c := full(t, 2)
				now := t0.Add(time.Minute)
				_, err := c.Reserve(tc.purpose, 3, now)
				requireFull(t, err, t0, now, tc.lifetime)
				if n := c.Len(); n != 2 {
					t.Errorf("entries after a refused reservation = %d, want 2", n)
				}
			})
			t.Run("held_place_counts", func(t *testing.T) {
				t.Parallel()
				c := full(t, 1)
				c.SetMax(tc.purpose, 2)
				slot, err := c.Reserve(tc.purpose, 2, t0)
				if err != nil {
					t.Fatalf("Reserve with one place free = %v", err)
				}
				if _, err := c.Put(tc.purpose, user(3), t0); !isRefused(err) {
					t.Errorf("a newcomer while the last place is held = %v, want refused", err)
				}
				id := slot.Fill(user(2), t0)
				if !c.Peek(id, tc.purpose, t0) {
					t.Error("the filled place holds no live entry")
				}
				if _, err := c.Put(tc.purpose, user(3), t0); !isRefused(err) {
					t.Errorf("a newcomer once the held place is filled = %v, want refused", err)
				}
			})
			t.Run("release_gives_it_back", func(t *testing.T) {
				t.Parallel()
				c := account.NewPendingCache(10000)
				c.SetMax(tc.purpose, 1)
				slot, err := c.Reserve(tc.purpose, 1, t0)
				if err != nil {
					t.Fatalf("Reserve = %v", err)
				}
				if _, err := c.Put(tc.purpose, user(2), t0); !isRefused(err) {
					t.Errorf("a newcomer while the only place is held = %v, want refused", err)
				}
				slot.Release()
				if _, err := c.Put(tc.purpose, user(2), t0); err != nil {
					t.Errorf("a newcomer after the release = %v, want admitted", err)
				}
			})
			t.Run("release_after_fill_frees_nothing", func(t *testing.T) {
				t.Parallel()
				c := account.NewPendingCache(10000)
				c.SetMax(tc.purpose, 1)
				slot, err := c.Reserve(tc.purpose, 1, t0)
				if err != nil {
					t.Fatalf("Reserve = %v", err)
				}
				slot.Fill(user(1), t0)
				slot.Release()
				slot.Release()
				if _, err := c.Put(tc.purpose, user(2), t0); !isRefused(err) {
					t.Errorf("a newcomer to a list its filled place keeps full = %v, want refused", err)
				}
			})
			t.Run("own_entry_admits_when_full", func(t *testing.T) {
				t.Parallel()
				c := full(t, 2)
				earlier := mustPut(t, c, tc.purpose, user(1), t0)
				slot, err := c.Reserve(tc.purpose, 1, t0)
				if err != nil {
					t.Fatalf("an owner's Reserve in a full list = %v, want admitted: the fill replaces its own entry", err)
				}
				id := slot.Fill(user(1), t0)
				if c.Peek(earlier, tc.purpose, t0) || !c.Peek(id, tc.purpose, t0) {
					t.Error("the fill did not replace the owner's earlier entry")
				}
				if n := c.Len(); n != 2 {
					t.Errorf("entries = %d, want 2", n)
				}
			})
			t.Run("own_entry_gone_meanwhile", func(t *testing.T) {
				t.Parallel()
				c := full(t, 2)
				own := mustPut(t, c, tc.purpose, user(1), t0)
				slot, err := c.Reserve(tc.purpose, 1, t0)
				if err != nil {
					t.Fatalf("Reserve = %v", err)
				}
				tc.drop(c, own, 1)
				if _, err := c.Put(tc.purpose, user(3), t0); !isRefused(err) {
					t.Errorf("a newcomer after the owner's entry left = %v, want refused: its place is held", err)
				}
				if id := slot.Fill(user(1), t0); !c.Peek(id, tc.purpose, t0) {
					t.Error("the filled place holds no live entry")
				}
				if n := c.Len(); n != 2 {
					t.Errorf("entries = %d, want the cap, 2", n)
				}
			})
			// RFC 9110 §10.2.3: Retry-After is a delay the client waits.
			t.Run("every_place_held_retries_soon", func(t *testing.T) {
				t.Parallel()
				c := account.NewPendingCache(10000)
				c.SetMax(tc.purpose, 1)
				if _, err := c.Reserve(tc.purpose, 1, t0); err != nil {
					t.Fatalf("Reserve = %v", err)
				}
				_, err := c.Reserve(tc.purpose, 2, t0)
				refused, ok := errors.AsType[*ratelimit.RefusedError](err)
				if !ok {
					t.Fatalf("a newcomer while every place is held = %v, want *ratelimit.RefusedError", err)
				}
				if refused.RetryAfter <= 0 || refused.RetryAfter >= tc.lifetime {
					t.Errorf("RetryAfter = %s, want a positive delay shorter than an entry's life: a held place frees when its step ends", refused.RetryAfter)
				}
			})
		})
	}
}

// isRefused reports whether err is a full list's refusal.
func isRefused(err error) bool {
	_, ok := errors.AsType[*ratelimit.RefusedError](err)
	return ok
}

// TestPendingReplace checks a pending sign-in's replacement: it takes its
// predecessor's place, so a full list never refuses it, and a predecessor
// already gone is never brought back.
func TestPendingReplace(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	alice := access.User{ID: 1}
	t.Run("in_a_full_list", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		c.SetMax(account.PurposeSignIn, 1)
		old := mustPut(t, c, account.PurposeSignIn, alice, t0)
		id, ok := c.Replace(old, alice, t0)
		if !ok || !c.Peek(id, account.PurposeSignIn, t0) {
			t.Fatalf("Replace in a full list = %t, want the replacement live", ok)
		}
		if c.Peek(old, account.PurposeSignIn, t0) {
			t.Error("the predecessor survived its replacement")
		}
		if n := c.Len(); n != 1 {
			t.Errorf("entries = %d, want 1", n)
		}
	})
	t.Run("predecessor_dropped", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		old := mustPut(t, c, account.PurposeSignIn, alice, t0)
		c.DropUser(alice.ID)
		if _, ok := c.Replace(old, alice, t0); ok {
			t.Error("Replace brought back a dropped ticket")
		}
		if n := c.Len(); n != 0 {
			t.Errorf("entries = %d, want none", n)
		}
	})
	t.Run("predecessor_expired", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		old := mustPut(t, c, account.PurposeSignIn, alice, t0)
		if _, ok := c.Replace(old, alice, t0.Add(10*time.Minute)); ok {
			t.Error("Replace brought back an expired ticket")
		}
	})
	t.Run("predecessor_replaced_by_a_new_step_1", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		old := mustPut(t, c, account.PurposeSignIn, alice, t0)
		newer := mustPut(t, c, account.PurposeSignIn, alice, t0)
		if _, ok := c.Replace(old, alice, t0); ok {
			t.Error("Replace of a ticket a new step 1 replaced succeeded")
		}
		if !c.Peek(newer, account.PurposeSignIn, t0) {
			t.Error("the newer step 1's ticket is gone")
		}
	})
	t.Run("ends_its_ceremony", func(t *testing.T) {
		t.Parallel()
		c := account.NewPendingCache(10)
		old := mustPut(t, c, account.PurposeSignIn, alice, t0)
		ceremony, _ := c.PutOnTicket(old, account.PurposeSecondFactor, alice, t0)
		if _, ok := c.Replace(old, alice, t0); !ok {
			t.Fatal("Replace of a live ticket failed")
		}
		if _, ok := c.Take(ceremony, account.PurposeSecondFactor, t0); ok {
			t.Error("the predecessor's ceremony outlived its replacement")
		}
	})
}
