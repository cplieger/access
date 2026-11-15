package account_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
)

// ceremonyTag names one passkey finish in its context, for readGate.
type ceremonyTag struct{}

// readGate holds the passkey read of a finish whose context carries a
// ceremonyTag, after the read, until the test releases that tag: two
// finishes then both read the stored count before either writes.
type readGate struct {
	account.Store
	read    chan string
	release map[string]chan struct{}
}

func newReadGate(tags ...string) *readGate {
	g := &readGate{read: make(chan string, len(tags)), release: map[string]chan struct{}{}}
	for _, tag := range tags {
		g.release[tag] = make(chan struct{})
	}
	return g
}

func (g *readGate) PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error) {
	pks, err := g.Store.PasskeysByUserID(ctx, userID)
	if tag, ok := ctx.Value(ceremonyTag{}).(string); ok {
		g.read <- tag
		<-g.release[tag]
	}
	return pks, err
}

// custodyRun is a pkFixture over a readGate with one enrolled credential
// whose stored count is 50.
type custodyRun struct {
	*pkFixture
	gate *readGate
	user *access.User
	dev  *accesstest.PasskeyDevice
	pk   access.PasskeyCredential
}

func newCustodyRun(t *testing.T, tags ...string) *custodyRun {
	t.Helper()
	gate := newReadGate(tags...)
	p := newPK(t, pwOptions{edit: func(c *account.Config) { gate.Store = c.Store; c.Store = gate }})
	u := passwordUser(t, p.mem, p.hasher, "alice", goodPassword)
	dev := accesstest.NewPasskeyDevice(t)
	dev.SignCount = 50
	pk := p.enrol(t, u, dev)
	if pk.SignCount != 50 {
		t.Fatalf("enrolled sign count = %d, want 50", pk.SignCount)
	}
	return &custodyRun{pkFixture: p, gate: gate, user: u, dev: dev, pk: pk}
}

type finished struct {
	in  account.SignedIn
	err error
}

// start begins a sign-in on a copy of the device that asserts count, and
// finishes it on its own goroutine under tag; the finish's result arrives
// on the returned channel once the test releases tag.
func (r *custodyRun) start(t *testing.T, tag string, count uint32) <-chan finished {
	t.Helper()
	dev := *r.dev
	dev.SignCount = count - 1
	pc, err := r.svc.PasskeyLoginBegin(t.Context(), localClient, r.origin, account.LoginModal)
	if err != nil {
		t.Fatalf("PasskeyLoginBegin: %v", err)
	}
	body := dev.Assert(browserJSON(t, pc.Assertion))
	ctx := context.WithValue(t.Context(), ceremonyTag{}, tag)
	out := make(chan finished, 1)
	go func() {
		in, err := r.svc.PasskeyLoginFinish(ctx, localClient, pc.ID, bytes.NewReader(body))
		out <- finished{in, err}
	}()
	return out
}

// awaitReads waits until n finishes have read the stored passkeys.
func (r *custodyRun) awaitReads(t *testing.T, n int) {
	t.Helper()
	for range n {
		select {
		case <-r.gate.read:
		case <-time.After(10 * time.Second):
			t.Fatal("a finish never read the stored passkeys")
		}
	}
}

// finish releases tag and returns its finish's result.
func (r *custodyRun) finish(t *testing.T, tag string, out <-chan finished) finished {
	t.Helper()
	close(r.gate.release[tag])
	select {
	case f := <-out:
		return f
	case <-time.After(10 * time.Second):
		t.Fatalf("finish %s never returned", tag)
		return finished{}
	}
}

func (r *custodyRun) stored(t *testing.T) access.PasskeyCredential {
	t.Helper()
	for _, pk := range passkeysOf(t, r.mem, r.user.ID) {
		if pk.ID == r.pk.ID {
			return pk
		}
	}
	t.Fatalf("passkey %d is gone", r.pk.ID)
	return access.PasskeyCredential{}
}

// TestRecordAssertion_WebAuthn7_2_signCount checks the custody write of
// WebAuthn L3 §7.2's signCount step when two finishes of one credential
// both compared against the count they read at the identification step.
func TestRecordAssertion_WebAuthn7_2_signCount(t *testing.T) {
	t.Parallel()
	for _, order := range [][2]string{{"asserts52", "asserts51"}, {"asserts51", "asserts52"}} {
		t.Run("interleaved_advances_"+order[0]+"_first", func(t *testing.T) {
			t.Parallel()
			r := newCustodyRun(t, "asserts52", "asserts51")
			outs := map[string]<-chan finished{"asserts52": r.start(t, "asserts52", 52), "asserts51": r.start(t, "asserts51", 51)}
			r.awaitReads(t, 2)
			for _, tag := range order {
				if f := r.finish(t, tag, outs[tag]); f.err != nil || f.in.CloneWarning {
					t.Errorf("finish %s = %v, clone warning %t; want a clean sign-in, since both advance past 50", tag, f.err, f.in.CloneWarning)
				}
			}
			if got := r.stored(t); got.SignCount != 52 || got.CloneWarning {
				t.Errorf("stored sign count %d, clone warning %t; want 52 and no warning", got.SignCount, got.CloneWarning)
			}
		})
	}
	for _, order := range [][2]string{{"genuine", "clone"}, {"clone", "genuine"}} {
		t.Run("clone_and_genuine_"+order[0]+"_first", func(t *testing.T) {
			t.Parallel()
			r := newCustodyRun(t, "genuine", "clone")
			outs := map[string]<-chan finished{"genuine": r.start(t, "genuine", 52), "clone": r.start(t, "clone", 40)}
			r.awaitReads(t, 2)
			for _, tag := range order {
				f := r.finish(t, tag, outs[tag])
				if want := tag == "clone"; f.err != nil || f.in.CloneWarning != want {
					t.Errorf("%s finish = %v, clone warning %t; want a sign-in with clone warning %t", tag, f.err, f.in.CloneWarning, want)
				}
			}
			if got := r.stored(t); got.SignCount != 52 || !got.CloneWarning {
				t.Errorf("stored sign count %d, clone warning %t; want 52 kept and the warning set", got.SignCount, got.CloneWarning)
			}
		})
	}
	t.Run("credential_deleted_since_the_read", func(t *testing.T) {
		t.Parallel()
		r := newCustodyRun(t, "late")
		out := r.start(t, "late", 51)
		r.awaitReads(t, 1)
		if err := r.mem.DeletePasskey(t.Context(), access.PasskeyRef{ID: r.pk.ID, UserID: r.user.ID}); err != nil {
			t.Fatalf("DeletePasskey: %v", err)
		}
		before := len(sessionsOf(t, r.mem, r.user.ID))
		f := r.finish(t, "late", out)
		if !errors.Is(f.err, access.ErrAuthBackend) || errors.Is(f.err, account.ErrNotFound) {
			t.Errorf("finish for a deleted credential = %v, want access.ErrAuthBackend with the store's ErrNotFound reduced to its text", f.err)
		}
		if after := len(sessionsOf(t, r.mem, r.user.ID)); after != before {
			t.Errorf("sessions %d after the failed finish, want %d", after, before)
		}
	})
}
