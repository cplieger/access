package account_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// recoveredPassword is the password a recovery completion sets.
const recoveredPassword = "recovered-horse-battery-5"

// recWorld is a pkFixture over a faultStore with the key scopes, an admin
// root with its recent full session pr, and alice, a RoleUser whose
// password is goodPassword.
type recWorld struct {
	*pkFixture
	fs    *faultStore
	root  *access.User
	alice *access.User
	pr    access.Principal
}

func newRecWorld(t *testing.T, o pwOptions, policy account.Policy) *recWorld {
	t.Helper()
	fs := newFaultStore()
	o.store = fs
	o.options = keyOptions(o.options, policy)
	w := &recWorld{pkFixture: newPK(t, o), fs: fs}
	w.root = mustUser(t, w.mem, "root", access.RoleAdmin)
	w.alice = passwordUser(t, w.mem, w.hasher, "alice", goodPassword)
	w.pr = w.sessionPrincipal(t, w.root, access.SessionFull, time.Now())
	return w
}

// issue mints a recovery link for userID from a, with the default lifetime.
func (w *recWorld) issue(t *testing.T, a account.Actor, userID int64) account.IssuedToken {
	t.Helper()
	tok, err := w.svc.IssueRecovery(t.Context(), a, userID, 0)
	if err != nil {
		t.Fatalf("IssueRecovery = %v", err)
	}
	return tok
}

// start redeems tok on svc from localClient and returns the recovery and
// its session's principal.
func (w *recWorld) start(t *testing.T, svc *account.Service, tok account.IssuedToken) (account.Recovery, access.Principal) {
	t.Helper()
	rec, err := svc.StartRecovery(t.Context(), localClient, tok.Plaintext)
	if err != nil {
		t.Fatalf("StartRecovery = %v", err)
	}
	return rec, w.principal(t, rec.Issued.Token)
}

// key mints a root key of root's from its session, then replaces pr with
// a fresh session, since the mint rotated it.
func (w *recWorld) key(t *testing.T, in account.NewKey) minted {
	t.Helper()
	m := w.mint(t, account.As(w.pr), w.root.ID, in)
	w.pr = w.sessionPrincipal(t, w.root, access.SessionFull, time.Now())
	return m
}

// completeWithPassword completes rp's recovery on svc with recoveredPassword.
func completeWithPassword(t *testing.T, svc *account.Service, rp access.Principal, opts account.RecoverOptions) error {
	t.Helper()
	return svc.RecoverWithPassword(t.Context(), rp, access.NewSecret(recoveredPassword), opts)
}

// recoverPasskey completes rp's recovery on svc by enrolling dev.
func (p *pkFixture) recoverPasskey(t *testing.T, svc *account.Service, rp access.Principal, dev *accesstest.PasskeyDevice, opts account.RecoverOptions) error {
	t.Helper()
	pc, err := svc.RecoverPasskeyBegin(t.Context(), rp, p.origin)
	if err != nil {
		t.Fatalf("RecoverPasskeyBegin = %v", err)
	}
	return svc.RecoverPasskeyFinish(t.Context(), rp, pc.ID, bytes.NewReader(dev.Register(browserJSON(t, pc.Creation))), opts)
}

// signsIn reports whether name signs in with pw on svc now.
func signsIn(t *testing.T, svc *account.Service, name, pw string) bool {
	t.Helper()
	_, err := svc.PasswordLogin(t.Context(), localClient, account.Credentials{Username: name, Password: access.NewSecret(pw)})
	return err == nil
}

// recoverySessions is userID's stored SessionRecovery sessions.
func recoverySessions(t *testing.T, s account.Store, userID int64) []access.Session {
	t.Helper()
	var out []access.Session
	for _, sess := range sessionsOf(t, s, userID) {
		if sess.Kind == access.SessionRecovery {
			out = append(out, sess)
		}
	}
	return out
}

// completion is one way a recovery session completes: run completes rp's
// recovery on svc, holds reports whether the user holds the credential it
// sets, and method is that credential's.
type completion struct {
	run    func(t *testing.T, w *recWorld, svc *account.Service, rp access.Principal, opts account.RecoverOptions) error
	holds  func(t *testing.T, w *recWorld, u *access.User) bool
	name   string
	method access.Method
}

// completions are RecoverWithPassword and RecoverPasskeyFinish, the latter
// enrolling one device per completion.
func completions() []completion {
	return []completion{
		{
			name:   "password",
			method: access.MethodPassword,
			run: func(t *testing.T, _ *recWorld, svc *account.Service, rp access.Principal, opts account.RecoverOptions) error {
				return completeWithPassword(t, svc, rp, opts)
			},
			holds: func(t *testing.T, w *recWorld, u *access.User) bool { return w.verifies(t, u, recoveredPassword) },
		},
		{
			name:   "passkey",
			method: access.MethodPasskey,
			run: func(t *testing.T, w *recWorld, svc *account.Service, rp access.Principal, opts account.RecoverOptions) error {
				return w.recoverPasskey(t, svc, rp, accesstest.NewPasskeyDevice(t), opts)
			},
			holds: func(t *testing.T, w *recWorld, u *access.User) bool { return len(passkeysOf(t, w.mem, u.ID)) > 0 },
		},
	}
}
