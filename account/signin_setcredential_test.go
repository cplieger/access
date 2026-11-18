package account_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
)

// chosenPassword is a password checkPassword accepts for alice.
const chosenPassword = "a-password-of-alices-own-9"

// setCredentialTicket issues alice a temporary password and answers her
// step 1's NextSetCredential ticket from c, listing methods.
func setCredentialTicket(t *testing.T, f *sfFixture, c account.Client, methods ...access.Method) (*access.User, string, access.Secret) {
	t.Helper()
	mustOwner(t, f.mem, "root")
	alice := passwordUser(t, f.mem, f.hasher, "alice", goodPassword)
	secret := issueTemp(t, f, account.OutOfBand("cli"), alice)
	out, err := f.step1(t.Context(), c, "alice", secret)
	return alice, secret, pending(t, out, err, account.NextSetCredential, methods...).Ticket
}

// requireSignedIn requires out to be a completed sign-in of userID.
func requireSignedIn(t *testing.T, out account.LoginResult, err error, userID int64) account.SignedIn {
	t.Helper()
	switch {
	case err != nil:
		t.Fatalf("the step = %v, want a session", err)
	case out.Pending != nil || out.SignedIn.User == nil:
		t.Fatalf("the step = %+v, want a session", out)
	case out.SignedIn.User.ID != userID || out.SignedIn.Token.IsZero():
		t.Fatalf("the step signed in %+v, want user %d with a token", out.SignedIn.User, userID)
	}
	return out.SignedIn
}

// requireBy requires one event of kind for userID, by userID's own session
// sessionID.
func requireBy(t *testing.T, f *sfFixture, kind account.EventKind, userID int64, sessionID string) {
	t.Helper()
	evs := eventsOf(f.events, kind)
	if len(evs) != 1 || evs[0].UserID != userID || evs[0].Actor.UserID != userID || evs[0].Actor.SessionID != sessionID {
		t.Errorf("%s = %+v, want one for user %d by its session %s (each journal names the ticket's user as the actor)", kind, evs, userID, sessionID)
	}
}

// requirePasswordError requires err to be a *access.PasswordError of reason.
func requirePasswordError(t *testing.T, err error, reason access.PasswordRejection) {
	t.Helper()
	pe, ok := errors.AsType[*access.PasswordError](err)
	if !ok || pe.Reason != reason {
		t.Fatalf("SetCredentialPassword = %v, want PasswordError %s", err, reason)
	}
}

// TestSetCredentialPassword sets the credential by password:
// NIST SP 800-63B-4 §3.1.1.2's checks, the temporary password refused as the
// new one, the rule off writing and signing in, the rule on staging the
// password for the enrolment finish.
func TestSetCredentialPassword(t *testing.T) {
	t.Parallel()
	// With the rule off, one Update writes PasswordHash, journals
	// password_set by the user and creates the session; the ticket ends.
	t.Run("rule_off_signs_in", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		alice, secret, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		out, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword))
		in := requireSignedIn(t, out, err, alice.ID)
		if in.Session.AuthMethod != access.MethodPassword || !in.Session.Secure {
			t.Errorf("the session = %s secure %t, want a secure password session", in.Session.AuthMethod, in.Session.Secure)
		}
		requireBy(t, f, account.EventPasswordSet, alice.ID, in.Session.ID)
		if !in.RecoveryCode.IsZero() {
			t.Error("a password with no second factor was issued a recovery code")
		}
		if _, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword)); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("the spent ticket again = %v, want access.ErrTokenInvalid", err)
		}
		if _, err := f.step1(t.Context(), clientAt(2), "alice", secret); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the temporary password after set-password = %v, want ErrInvalidCredentials", err)
		}
		if _, err := f.login(t.Context(), clientAt(3), "alice", chosenPassword); err != nil {
			t.Errorf("the chosen password afterwards = %v, want a session", err)
		}
	})
	// NIST SP 800-63B-4 §3.1.1.2: the chosen password meets checkPassword
	// with the account's username; a refusal keeps the ticket.
	t.Run("checked_and_kept", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		alice, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		_, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret("fourteen-chars"))
		requirePasswordError(t, err, access.PasswordTooShort)
		_, err = f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret("alice-alice-alice-1"))
		requirePasswordError(t, err, access.PasswordContainsUsername)
		if u := storedUser(t, f.mem, alice.ID); !u.PasswordHash.IsZero() {
			t.Error("a refused password was written")
		}
		out, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword))
		requireSignedIn(t, out, err, alice.ID)
	})
	// NIST SP 800-63B-4 §3.1.1.2: a value known to the issuer is a
	// compromised value, so the temporary password itself, dashed or not,
	// answers is_temporary_password, writes nothing and keeps the ticket.
	t.Run("is_temporary_password", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		alice, secret, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		for _, typed := range []string{secret, strings.ReplaceAll(secret, "-", ""), strings.ToLower(strings.ReplaceAll(secret, "-", " "))} {
			_, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(typed))
			requirePasswordError(t, err, access.PasswordIsTemporary)
		}
		if u := storedUser(t, f.mem, alice.ID); !u.PasswordHash.IsZero() {
			t.Error("the temporary password was written as the password")
		}
		out, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword))
		requireSignedIn(t, out, err, alice.ID)
	})
	// Only the one form the hash can match is verified against it, so
	// no other password costs a second Argon2 run; and checkPassword refuses
	// nothing for its form (NIST SP 800-63B-4 §3.1.1.1: no composition rule).
	t.Run("verified_only_in_its_form", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		alice, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		before := len(f.counted.verified())
		if _, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret("short")); err == nil {
			t.Fatal("a short password was accepted")
		}
		if got := len(f.counted.verified()); got != before {
			t.Errorf("a password not in the temporary form ran %d verifies, want none", got-before)
		}
		other, _ := account.NewTemporaryPassword()
		out, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, other)
		requireSignedIn(t, out, err, alice.ID)
		if got := len(f.counted.verified()); got != before+1 {
			t.Errorf("an issued-shape password ran %d verifies, want one against the ticket's hash", got-before)
		}
	})
	t.Run("passphrase_accepted", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		alice, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		out, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret("tree bird fish wolf"))
		requireSignedIn(t, out, err, alice.ID)
	})
	// A ticket whose Methods lack password
	// answers ErrPasswordLoginDisabled, writes nothing and keeps the ticket.
	t.Run("password_login_off", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{DisablePasswordLogin: true}, pwOptions{})
		alice, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPasskey)
		if _, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword)); !errors.Is(err, account.ErrPasswordLoginDisabled) {
			t.Fatalf("SetCredentialPassword = %v, want ErrPasswordLoginDisabled", err)
		}
		if u := storedUser(t, f.mem, alice.ID); !u.PasswordHash.IsZero() {
			t.Error("a refused set-password wrote a password")
		}
		if _, ok := account.TicketOf(f.svc, ticket); !ok {
			t.Error("the refusal dropped the ticket")
		}
	})
	// A password-minted ticket is not a NextSetCredential one.
	t.Run("other_ticket", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		u := passwordUser(t, f.mem, f.hasher, "bob", goodPassword)
		sealTOTP(t, f.mem, f.sealer, u)
		out, err := f.step1(t.Context(), localClient, "bob", goodPassword)
		p := pending(t, out, err, account.NextSecondFactor, access.MethodTOTP)
		if _, err := f.svc.SetCredentialPassword(t.Context(), localClient, p.Ticket, access.NewSecret(chosenPassword)); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("SetCredentialPassword on a NextSecondFactor ticket = %v, want access.ErrTokenInvalid", err)
		}
	})
	// Transport binding: a ticket minted on plain is refused over
	// HTTPS, and one finishing over plain makes a plain session.
	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{posture: access.PosturePerRequest})
		alice, _, ticket := setCredentialTicket(t, f, plain(localClient), access.MethodPassword)
		out, err := f.svc.SetCredentialPassword(t.Context(), plain(localClient), ticket, access.NewSecret(chosenPassword))
		if in := requireSignedIn(t, out, err, alice.ID); in.Session.Secure {
			t.Error("a plain ticket's set-password made a secure session")
		}
	})
	t.Run("plain_ticket_on_https", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{posture: access.PosturePerRequest})
		_, _, ticket := setCredentialTicket(t, f, plain(localClient), access.MethodPassword)
		if _, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword)); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("a plain ticket over HTTPS = %v, want access.ErrTokenInvalid", err)
		}
	})
	// Re-check of a temporary-password ticket (cal.com
	// GHSA-9r3w-4j8q-pw98: a reset token outliving a changed credential):
	// PasswordHash still zero and no live temporary password.
	t.Run("recheck_password_written", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		alice, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		u := storedUser(t, f.mem, alice.ID)
		u.PasswordHash = passwordUser(t, f.mem, f.hasher, "carol", goodPassword).PasswordHash
		if err := f.mem.UpdateUser(t.Context(), u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		if _, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword)); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("SetCredentialPassword after a password was written = %v, want access.ErrTokenInvalid", err)
		}
		if _, ok := account.TicketOf(f.svc, ticket); ok {
			t.Error("the ended ticket is still live")
		}
	})
	t.Run("recheck_record_live", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		alice, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		now := time.Now()
		if err := f.mem.SetTemporaryPassword(t.Context(), access.TemporaryPassword{UserID: alice.ID, Hash: alice.PasswordHash, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatalf("SetTemporaryPassword: %v", err)
		}
		if _, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword)); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("SetCredentialPassword with a live record = %v, want access.ErrTokenInvalid", err)
		}
	})
	// Issued under old hasher parameters, entered after they are
	// raised, then SetCredentialPassword: PasswordHash verifies the chosen
	// password and the temporary password fails afterwards.
	t.Run("old_hasher_parameters", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		mustOwner(t, f.mem, "root")
		alice := passwordUser(t, f.mem, nil, "alice", "")
		old, err := access.NewHasher(access.HasherConfig{Params: access.Argon2Params{Memory: 12288, Iterations: 3, Parallelism: 1, SaltLength: 16, KeyLength: 32}})
		if err != nil {
			t.Fatalf("NewHasher: %v", err)
		}
		shown, canonical := account.NewTemporaryPassword()
		hash, err := old.Hash(t.Context(), canonical)
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		now := time.Now()
		if err := f.mem.SetTemporaryPassword(t.Context(), access.TemporaryPassword{UserID: alice.ID, Hash: hash, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatalf("SetTemporaryPassword: %v", err)
		}
		out, err := f.step1(t.Context(), localClient, "alice", shown.Reveal())
		p := pending(t, out, err, account.NextSetCredential, access.MethodPassword, access.MethodPasskey)
		out, err = f.svc.SetCredentialPassword(t.Context(), localClient, p.Ticket, access.NewSecret(chosenPassword))
		requireSignedIn(t, out, err, alice.ID)
		if _, err := f.login(t.Context(), clientAt(2), "alice", chosenPassword); err != nil {
			t.Errorf("the chosen password afterwards = %v, want a session", err)
		}
		if _, err := f.step1(t.Context(), clientAt(3), "alice", shown.Reveal()); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the temporary password afterwards = %v, want ErrInvalidCredentials", err)
		}
	})
}

// TestSetCredentialPasswordUnderTheRule checks the staged password:
// under RequireSecondFactor, SetCredentialPassword writes nothing and
// replaces the ticket with a NextEnrol one holding the password's hash,
// which the enrolment finish writes beside the factor and a recovery code.
func TestSetCredentialPasswordUnderTheRule(t *testing.T) {
	t.Parallel()
	rule := account.Rules{RequireSecondFactor: true}
	stage := func(t *testing.T, f *sfFixture) (*access.User, access.Secret) {
		t.Helper()
		alice, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		out, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword))
		next := pending(t, out, err, account.NextEnrol, access.MethodTOTP, access.MethodPasskey)
		// A ticket is replaced whenever its state changes.
		if _, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword)); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("the replaced ticket = %v, want access.ErrTokenInvalid", err)
		}
		if got, ok := account.TicketOf(f.svc, next.Ticket); !ok || !got.Temporary {
			t.Errorf("the replacement = %+v, %t; want it to keep its temporary-password origin", got, ok)
		}
		if u := storedUser(t, f.mem, alice.ID); !u.PasswordHash.IsZero() {
			t.Error("set-password under the rule wrote the password")
		}
		if n := len(eventsOf(f.events, account.EventPasswordSet)); n != 0 {
			t.Errorf("set-password under the rule journalled %d password_set, want none", n)
		}
		return alice, next.Ticket
	}
	t.Run("totp_finish_writes_it", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		alice, ticket := stage(t, f)
		in, _, err := pendingEnrolTOTP(t, f, localClient, ticket)
		if err != nil {
			t.Fatalf("PendingTOTPFinish = %v", err)
		}
		if in.RecoveryCode.IsZero() {
			t.Error("the finish binding a password and a TOTP issued no recovery code")
		}
		for _, kind := range []account.EventKind{account.EventPasswordSet, account.EventTOTPAdded, account.EventRecoveryCodeIssued} {
			requireBy(t, f, kind, alice.ID, in.Session.ID)
		}
		out, err := f.step1(t.Context(), clientAt(2), "alice", chosenPassword)
		pending(t, out, err, account.NextSecondFactor, access.MethodTOTP, access.MethodRecoveryCode)
	})
	t.Run("passkey_finish_writes_it", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		alice, ticket := stage(t, f)
		in, err := pendingEnrolPasskey(t, f, localClient, ticket, accesstest.NewPasskeyDevice(t))
		if err != nil {
			t.Fatalf("PendingPasskeyFinish = %v", err)
		}
		if in.RecoveryCode.IsZero() {
			t.Error("the finish binding a password and a passkey issued no recovery code")
		}
		for _, kind := range []account.EventKind{account.EventPasswordSet, account.EventPasskeyAdded, account.EventRecoveryCodeIssued} {
			requireBy(t, f, kind, alice.ID, in.Session.ID)
		}
		if u := storedUser(t, f.mem, alice.ID); u.PasswordHash.IsZero() {
			t.Error("the passkey finish did not write the staged password")
		}
	})
	// Abandoned after set-password under the rule, the new password
	// does not sign in.
	t.Run("abandoned", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		stage(t, f)
		if _, err := f.step1(t.Context(), clientAt(2), "alice", chosenPassword); !errors.Is(err, account.ErrInvalidCredentials) {
			t.Errorf("the staged password before the finish = %v, want ErrInvalidCredentials", err)
		}
	})
	// The temporary-password re-check runs at every later step, the
	// enrolment finish included (cal.com GHSA-9r3w-4j8q-pw98).
	t.Run("recheck_at_the_finish", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		alice, ticket := stage(t, f)
		e, err := f.svc.PendingTOTPBegin(t.Context(), localClient, ticket)
		if err != nil {
			t.Fatalf("PendingTOTPBegin = %v", err)
		}
		now := time.Now()
		if err := f.mem.SetTemporaryPassword(t.Context(), access.TemporaryPassword{UserID: alice.ID, Hash: alice.PasswordHash, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatalf("SetTemporaryPassword: %v", err)
		}
		code := codeNow(secretOf(t, account.TOTPEnrolment{URI: e.URI, Text: e.Text}))
		if _, err := f.svc.PendingTOTPFinish(t.Context(), localClient, ticket, code); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("the finish with a live record = %v, want access.ErrTokenInvalid", err)
		}
		if u := storedUser(t, f.mem, alice.ID); !u.PasswordHash.IsZero() {
			t.Error("a refused finish wrote the staged password")
		}
	})
	// Ticket-method function at set-password's replacement: a hook
	// refusing passkeys leaves totp.
	t.Run("hook_refusing_passkeys", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{RequireSecondFactor: true, MethodUsable: refusePasskeys}, pwOptions{})
		_, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword)
		out, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword))
		pending(t, out, err, account.NextEnrol, access.MethodTOTP)
	})
	// Enrolment is refused over plain, so a plain ticket meeting the
	// rule switched on since its step 1 answers access.ErrHTTPSRequired at
	// set-password's replacement, writes nothing and ends.
	t.Run("plain_rule_on_since", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{posture: access.PosturePerRequest})
		alice, _, ticket := setCredentialTicket(t, f, plain(localClient), access.MethodPassword)
		f.set(rule)
		if _, err := f.svc.SetCredentialPassword(t.Context(), plain(localClient), ticket, access.NewSecret(chosenPassword)); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Errorf("SetCredentialPassword = %v, want access.ErrHTTPSRequired", err)
		}
		if _, ok := account.TicketOf(f.svc, ticket); ok {
			t.Error("the refused replacement kept the ticket")
		}
		if u := storedUser(t, f.mem, alice.ID); !u.PasswordHash.IsZero() {
			t.Error("the refused replacement wrote the password")
		}
	})
	// An empty NextEnrol set at the replacement is no_usable_method and
	// drops the ticket.
	t.Run("no_way_to_enrol", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, rule, pwOptions{})
		_, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		f.set(account.Rules{RequireSecondFactor: true, DisableTOTP: true, MethodUsable: refusePasskeys})
		if _, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword)); !errors.Is(err, account.ErrNoUsableMethod) {
			t.Errorf("SetCredentialPassword = %v, want ErrNoUsableMethod", err)
		}
		if _, ok := account.TicketOf(f.svc, ticket); ok {
			t.Error("no_usable_method kept the ticket")
		}
	})
}

// setPasskey registers dev on ticket's NextSetCredential from c and answers
// the finish.
func setPasskey(t *testing.T, f *sfFixture, c account.Client, ticket access.Secret, dev *accesstest.PasskeyDevice) (account.SignedIn, error) {
	t.Helper()
	pc, err := f.svc.SetCredentialPasskeyBegin(t.Context(), c, ticket, f.origin)
	if err != nil {
		t.Fatalf("SetCredentialPasskeyBegin = %v", err)
	}
	return f.svc.SetCredentialPasskeyFinish(t.Context(), c, pc.ID, bytes.NewReader(dev.Register(browserJSON(t, pc.Creation))))
}

// TestSetCredentialPasskey sets the credential by passkey: a registered
// passkey meets the rule, so the finish
// signs in under either setting, journalling passkey_added by the user.
func TestSetCredentialPasskey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		r    account.Rules
	}{{"rule_off", account.Rules{}}, {"rule_on", account.Rules{RequireSecondFactor: true}}, {"password_login_off", account.Rules{DisablePasswordLogin: true}}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newSF(t, tc.r, pwOptions{})
			methods := []access.Method{access.MethodPassword, access.MethodPasskey}
			if tc.r.DisablePasswordLogin {
				methods = methods[1:]
			}
			alice, _, ticket := setCredentialTicket(t, f, localClient, methods...)
			dev := accesstest.NewPasskeyDevice(t)
			in, err := setPasskey(t, f, localClient, ticket, dev)
			if err != nil {
				t.Fatalf("SetCredentialPasskeyFinish = %v", err)
			}
			if in.User == nil || in.User.ID != alice.ID || in.Token.IsZero() {
				t.Fatalf("the finish = %+v, want alice's session", in)
			}
			requireBy(t, f, account.EventPasskeyAdded, alice.ID, in.Session.ID)
			if !in.RecoveryCode.IsZero() {
				t.Error("a passkey with no password was issued a recovery code (NIST SP 800-63B-4 §4.2.2)")
			}
			if u := storedUser(t, f.mem, alice.ID); !u.PasswordHash.IsZero() {
				t.Error("the passkey arm wrote a password")
			}
			if _, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword)); !errors.Is(err, access.ErrTokenInvalid) {
				t.Errorf("the spent ticket = %v, want access.ErrTokenInvalid", err)
			}
		})
	}
	// The passkey pair stays refused over plain.
	t.Run("plain_refused", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{posture: access.PosturePerRequest})
		_, _, ticket := setCredentialTicket(t, f, plain(localClient), access.MethodPassword)
		if _, err := f.svc.SetCredentialPasskeyBegin(t.Context(), plain(localClient), ticket, f.origin); !errors.Is(err, access.ErrHTTPSRequired) {
			t.Errorf("SetCredentialPasskeyBegin over plain = %v, want access.ErrHTTPSRequired", err)
		}
	})
	// A ticket that does not list passkey begins nothing.
	t.Run("not_listed", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{MethodUsable: refusePasskeys}, pwOptions{})
		_, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword)
		if _, err := f.svc.SetCredentialPasskeyBegin(t.Context(), localClient, ticket, f.origin); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("SetCredentialPasskeyBegin = %v, want access.ErrTokenInvalid", err)
		}
	})
	t.Run("no_relying_party", func(t *testing.T) {
		t.Parallel()
		var rp atomicRP
		f := newSF(t, account.Rules{}, pwOptions{edit: func(c *account.Config) { c.RP = rp.get }})
		rp.set(f.rp)
		_, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		pc, err := f.svc.SetCredentialPasskeyBegin(t.Context(), localClient, ticket, f.origin)
		if err != nil {
			t.Fatalf("SetCredentialPasskeyBegin = %v", err)
		}
		rp.set(nil)
		body := accesstest.NewPasskeyDevice(t).Register(browserJSON(t, pc.Creation))
		if _, err := f.svc.SetCredentialPasskeyFinish(t.Context(), localClient, pc.ID, bytes.NewReader(body)); !errors.Is(err, account.ErrPasskeysUnavailable) {
			t.Errorf("SetCredentialPasskeyFinish with no relying party = %v, want ErrPasskeysUnavailable", err)
		}
	})
	// Re-check at the finish (cal.com GHSA-9r3w-4j8q-pw98).
	t.Run("recheck_at_the_finish", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		alice, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		pc, err := f.svc.SetCredentialPasskeyBegin(t.Context(), localClient, ticket, f.origin)
		if err != nil {
			t.Fatalf("SetCredentialPasskeyBegin = %v", err)
		}
		now := time.Now()
		if err := f.mem.SetTemporaryPassword(t.Context(), access.TemporaryPassword{UserID: alice.ID, Hash: alice.PasswordHash, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatalf("SetTemporaryPassword: %v", err)
		}
		body := accesstest.NewPasskeyDevice(t).Register(browserJSON(t, pc.Creation))
		if _, err := f.svc.SetCredentialPasskeyFinish(t.Context(), localClient, pc.ID, bytes.NewReader(body)); !errors.Is(err, access.ErrTokenInvalid) {
			t.Errorf("the finish with a live record = %v, want access.ErrTokenInvalid", err)
		}
		if n := len(eventsOf(f.events, account.EventPasskeyAdded)); n != 0 {
			t.Error("a refused finish added a passkey")
		}
	})
	// A ceremony of another purpose does not finish a set-credential one.
	t.Run("ceremony_purpose", func(t *testing.T) {
		t.Parallel()
		f := newSF(t, account.Rules{}, pwOptions{})
		_, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
		pc, err := f.svc.SetCredentialPasskeyBegin(t.Context(), localClient, ticket, f.origin)
		if err != nil {
			t.Fatalf("SetCredentialPasskeyBegin = %v", err)
		}
		body := accesstest.NewPasskeyDevice(t).Register(browserJSON(t, pc.Creation))
		if _, err := f.svc.PendingPasskeyFinish(t.Context(), localClient, pc.ID, bytes.NewReader(body)); !errors.Is(err, account.ErrCeremonyInvalid) {
			t.Errorf("PendingPasskeyFinish on a set-credential ceremony = %v, want ErrCeremonyInvalid", err)
		}
	})
}

// atomicRP is a Config.RP a test turns off mid-ceremony.
type atomicRP struct {
	p atomic.Pointer[webauthn.RelyingParty]
}

func (a *atomicRP) get() *webauthn.RelyingParty   { return a.p.Load() }
func (a *atomicRP) set(rp *webauthn.RelyingParty) { a.p.Store(rp) }

// TestSetCredentialPasswordTicketEnded checks that the staged replacement
// under the rule takes its ticket's place only while that ticket is live: a
// credential change that ended it meanwhile is not undone.
func TestSetCredentialPasswordTicketEnded(t *testing.T) {
	t.Parallel()
	fs := newFaultStore()
	f := newSF(t, account.Rules{RequireSecondFactor: true}, pwOptions{store: fs})
	alice, _, ticket := setCredentialTicket(t, f, localClient, access.MethodPassword, access.MethodPasskey)
	var ended atomic.Bool
	fs.onUpdate(func(context.Context, int) {
		if ended.CompareAndSwap(false, true) {
			account.PendingOf(f.svc).DropUser(alice.ID)
		}
	})
	if _, err := f.svc.SetCredentialPassword(t.Context(), localClient, ticket, access.NewSecret(chosenPassword)); !errors.Is(err, access.ErrTokenInvalid) {
		t.Errorf("set-password whose ticket ended meanwhile = %v, want access.ErrTokenInvalid", err)
	}
	if n := account.PendingOf(f.svc).Len(); n != 0 {
		t.Errorf("entries = %d, want none: an ended ticket was brought back", n)
	}
}
