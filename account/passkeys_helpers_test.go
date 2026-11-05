package account_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
)

// pkFixture is a pwFixture whose Service resolves one relying party for
// rpID, with the origin its ceremonies run at.
type pkFixture struct {
	*pwFixture
	rp     *webauthn.RelyingParty
	origin webauthn.Origin
}

func newPK(t testing.TB, o pwOptions) *pkFixture {
	t.Helper()
	rp := newRP(t)
	origin, err := webauthn.ParseOrigin("https://" + rpID)
	if err != nil {
		t.Fatalf("ParseOrigin: %v", err)
	}
	edit := o.edit
	o.edit = func(c *account.Config) {
		c.RP = func() *webauthn.RelyingParty { return rp }
		if edit != nil {
			edit(c)
		}
	}
	return &pkFixture{pwFixture: newPW(t, o), rp: rp, origin: origin}
}

// browserJSON is v as the browser hands it to the authenticator.
func browserJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// register enrols dev for pr's user and returns the result.
func (p *pkFixture) register(t testing.TB, pr access.Principal, dev *accesstest.PasskeyDevice) (account.Registered, error) {
	t.Helper()
	pc, err := p.svc.PasskeyRegisterBegin(t.Context(), pr, p.origin)
	if err != nil {
		t.Fatalf("PasskeyRegisterBegin: %v", err)
	}
	return p.svc.PasskeyRegisterFinish(t.Context(), pr, pc.ID, bytes.NewReader(dev.Register(browserJSON(t, pc.Creation))))
}

// enrol registers dev for u from a fresh session of its own and returns
// the stored passkey.
func (p *pkFixture) enrol(t testing.TB, u *access.User, dev *accesstest.PasskeyDevice) access.PasskeyCredential {
	t.Helper()
	pr, _ := p.signedInVia(t, u, access.MethodPassword)
	reg, err := p.register(t, pr, dev)
	if err != nil {
		t.Fatalf("PasskeyRegisterFinish: %v", err)
	}
	return reg.Passkey
}

// signIn runs a passkey sign-in in mode from c on dev.
func (p *pkFixture) signIn(ctx context.Context, t testing.TB, c account.Client, mode account.LoginMode, dev *accesstest.PasskeyDevice) (account.SignedIn, error) {
	t.Helper()
	pc, err := p.svc.PasskeyLoginBegin(ctx, c, p.origin, mode)
	if err != nil {
		t.Fatalf("PasskeyLoginBegin: %v", err)
	}
	return p.svc.PasskeyLoginFinish(ctx, c, pc.ID, bytes.NewReader(dev.Assert(browserJSON(t, pc.Assertion))))
}

// stepUpPasskey re-proves pr's user on dev from c.
func (p *pkFixture) stepUpPasskey(t testing.TB, c account.Client, pr access.Principal, dev *accesstest.PasskeyDevice) (account.Issued, error) {
	t.Helper()
	pc, err := p.svc.StepUpPasskeyBegin(t.Context(), pr, p.origin)
	if err != nil {
		t.Fatalf("StepUpPasskeyBegin: %v", err)
	}
	return p.svc.StepUpPasskeyFinish(t.Context(), c, pr, pc.ID, bytes.NewReader(dev.Assert(browserJSON(t, pc.Assertion))))
}

// principal is the principal the Authenticator grants for a session token.
func (p *pkFixture) principal(t testing.TB, token access.Secret) access.Principal {
	t.Helper()
	pr, err := p.authenticate(t.Context(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return pr
}
