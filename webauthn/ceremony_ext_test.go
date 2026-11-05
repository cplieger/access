package webauthn_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/webauthn"
	"github.com/go-webauthn/webauthn/protocol"
)

const rpID = "example.com"

// harness is one relying party at https://example.com over a MemStore.
type harness struct {
	t      *testing.T
	rp     *webauthn.RelyingParty
	store  *accesstest.MemStore
	origin webauthn.Origin
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	rp, err := webauthn.New(webauthn.RPConfig{ID: rpID, DisplayName: "Example"})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	origin, err := webauthn.ParseOrigin("https://" + rpID)
	if err != nil {
		t.Fatalf("ParseOrigin: %v", err)
	}
	return &harness{t: t, rp: rp, store: accesstest.NewMemStore(), origin: origin}
}

func (h *harness) user(name string) *access.User {
	h.t.Helper()
	u := &access.User{Username: name, Enabled: true, Role: access.RoleUser, WebAuthnHandle: access.GenerateWebAuthnHandle()}
	if err := h.store.CreateUser(h.t.Context(), u); err != nil {
		h.t.Fatalf("CreateUser(%s): %v", name, err)
	}
	return u
}

func (h *harness) webauthnUser(u *access.User) *webauthn.User {
	h.t.Helper()
	creds, err := h.store.PasskeysByUserID(h.t.Context(), u.ID)
	if err != nil {
		h.t.Fatalf("PasskeysByUserID: %v", err)
	}
	wu, err := webauthn.NewUser(u, creds)
	if err != nil {
		h.t.Fatalf("NewUser: %v", err)
	}
	return wu
}

func (h *harness) json(v any) []byte {
	h.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		h.t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// register runs a registration ceremony for u on dev and returns the record
// FinishRegistration built, not yet stored.
func (h *harness) register(u *access.User, dev *accesstest.PasskeyDevice) *access.PasskeyCredential {
	h.t.Helper()
	wu := h.webauthnUser(u)
	creation, ceremony, err := webauthn.BeginRegistration(h.rp, wu, h.origin)
	if err != nil {
		h.t.Fatalf("BeginRegistration: %v", err)
	}
	cred, err := webauthn.FinishRegistration(h.rp, wu, ceremony, bytes.NewReader(dev.Register(h.json(creation))))
	if err != nil {
		h.t.Fatalf("FinishRegistration: %v", err)
	}
	return cred
}

// enrol registers and stores a passkey for u on dev.
func (h *harness) enrol(u *access.User, dev *accesstest.PasskeyDevice) *access.PasskeyCredential {
	h.t.Helper()
	cred := h.register(u, dev)
	if err := h.store.CreatePasskey(h.t.Context(), cred); err != nil {
		h.t.Fatalf("CreatePasskey: %v", err)
	}
	return cred
}

func (h *harness) login(store webauthn.Store, dev *accesstest.PasskeyDevice) (webauthn.LoginResult, error) {
	h.t.Helper()
	assertion, ceremony, err := webauthn.BeginLogin(h.rp, h.origin)
	if err != nil {
		h.t.Fatalf("BeginLogin: %v", err)
	}
	return webauthn.CompleteLogin(h.t.Context(), h.rp, store, ceremony, bytes.NewReader(dev.Assert(h.json(assertion))))
}

func (h *harness) passkey(u *access.User, credID []byte) access.PasskeyCredential {
	h.t.Helper()
	creds, err := h.store.PasskeysByUserID(h.t.Context(), u.ID)
	if err != nil {
		h.t.Fatalf("PasskeysByUserID: %v", err)
	}
	for _, c := range creds {
		if bytes.Equal(c.CredentialID, credID) {
			return c
		}
	}
	h.t.Fatalf("user %d holds no passkey %x", u.ID, credID)
	return access.PasskeyCredential{}
}

func TestPasskeyLoginStoresCustody(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	alice := h.user("alice")
	dev := accesstest.NewPasskeyDevice(t)
	h.enrol(alice, dev)
	before := time.Now()

	res, err := h.login(h.store, dev)
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if res.User == nil || res.User.ID != alice.ID {
		t.Errorf("LoginResult.User = %+v, want user %d", res.User, alice.ID)
	}
	if !bytes.Equal(res.CredentialID, dev.CredentialID) {
		t.Errorf("LoginResult.CredentialID = %x, want %x", res.CredentialID, dev.CredentialID)
	}
	if res.CloneWarning {
		t.Error("LoginResult.CloneWarning = true on an advancing counter, want false")
	}
	stored := h.passkey(alice, dev.CredentialID)
	if stored.SignCount != dev.SignCount {
		t.Errorf("stored SignCount = %d, want the asserted %d", stored.SignCount, dev.SignCount)
	}
	if stored.LastUsedAt.Before(before) {
		t.Errorf("stored LastUsedAt = %v, want at or after %v", stored.LastUsedAt, before)
	}
}

func TestUnknownCredentialAfterDeletion(t *testing.T) {
	t.Parallel()
	t.Run("passkey_deleted", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		alice := h.user("alice")
		dev := accesstest.NewPasskeyDevice(t)
		cred := h.enrol(alice, dev)
		if err := h.store.DeletePasskey(t.Context(), access.PasskeyRef{UserID: alice.ID, ID: cred.ID}); err != nil {
			t.Fatalf("DeletePasskey: %v", err)
		}
		assertUnknown(t, h, dev)
	})
	t.Run("user_deleted", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		alice := h.user("alice")
		dev := accesstest.NewPasskeyDevice(t)
		h.enrol(alice, dev)
		if err := h.store.DeleteUser(t.Context(), alice.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		assertUnknown(t, h, dev)
	})
	t.Run("another_users_handle", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		alice, bob := h.user("alice"), h.user("bob")
		dev := accesstest.NewPasskeyDevice(t)
		h.enrol(alice, dev)
		h.enrol(bob, accesstest.NewPasskeyDevice(t))
		dev.UserHandle = bob.WebAuthnHandle
		assertUnknown(t, h, dev)
	})
}

func assertUnknown(t *testing.T, h *harness, dev *accesstest.PasskeyDevice) {
	t.Helper()
	res, err := h.login(h.store, dev)
	if !errors.Is(err, webauthn.ErrUnknownCredential) {
		t.Fatalf("CompleteLogin error = %v, want ErrUnknownCredential", err)
	}
	if _, ok := errors.AsType[*protocol.Error](err); ok {
		t.Errorf("CompleteLogin error %v reaches a go-webauthn error, want it untranslated away", err)
	}
	if res.User != nil {
		t.Errorf("CompleteLogin user = %+v on failure, want nil", res.User)
	}
}

func TestCloneWarningSurfaced(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	alice := h.user("alice")
	dev := accesstest.NewPasskeyDevice(t)
	h.enrol(alice, dev)
	if _, err := h.login(h.store, dev); err != nil {
		t.Fatalf("first CompleteLogin: %v", err)
	}
	counted := dev.SignCount

	dev.SignCount = counted - 1
	res, err := h.login(h.store, dev)
	if err != nil {
		t.Fatalf("CompleteLogin on a regressed counter: %v", err)
	}
	if !res.CloneWarning {
		t.Error("LoginResult.CloneWarning = false on a counter equal to the stored one, want true")
	}
	if stored := h.passkey(alice, dev.CredentialID); !stored.CloneWarning || stored.SignCount != counted {
		t.Errorf("stored CloneWarning, SignCount = %v, %d; want true, %d (a regression keeps the stored count)", stored.CloneWarning, stored.SignCount, counted)
	}

	dev.SignCount = counted + 5
	res, err = h.login(h.store, dev)
	if err != nil {
		t.Fatalf("CompleteLogin after the regression: %v", err)
	}
	if res.CloneWarning {
		t.Error("LoginResult.CloneWarning = true on an advancing counter, want false: it reports this assertion only")
	}
	if stored := h.passkey(alice, dev.CredentialID); !stored.CloneWarning {
		t.Error("stored CloneWarning cleared by a later advancing login, want it kept")
	}
}

// faultStore fails the named Store method and delegates every other one.
type faultStore struct {
	*accesstest.MemStore
	fail string
}

var errDisk = errors.New("disk on fire")

func (f *faultStore) UserByWebAuthnHandle(ctx context.Context, handle []byte) (*access.User, bool, error) {
	if f.fail == "UserByWebAuthnHandle" {
		return nil, false, errDisk
	}
	return f.MemStore.UserByWebAuthnHandle(ctx, handle)
}

func (f *faultStore) PasskeysByUserID(ctx context.Context, userID int64) ([]access.PasskeyCredential, error) {
	if f.fail == "PasskeysByUserID" {
		return nil, errDisk
	}
	return f.MemStore.PasskeysByUserID(ctx, userID)
}

func (f *faultStore) UpdatePasskeyAfterLogin(ctx context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error {
	if f.fail == "UpdatePasskeyAfterLogin" {
		return errDisk
	}
	return f.MemStore.UpdatePasskeyAfterLogin(ctx, userID, credID, upd)
}

func TestCustodyFailureFailsLogin(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	alice := h.user("alice")
	dev := accesstest.NewPasskeyDevice(t)
	h.enrol(alice, dev)

	res, err := h.login(&faultStore{MemStore: h.store, fail: "UpdatePasskeyAfterLogin"}, dev)
	if !errors.Is(err, access.ErrAuthBackend) || !errors.Is(err, errDisk) {
		t.Errorf("CompleteLogin error = %v, want access.ErrAuthBackend wrapping the store error", err)
	}
	if res.User != nil {
		t.Errorf("CompleteLogin user = %+v after a failed custody write, want nil", res.User)
	}
}

func TestLookupFailureIsBackend(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"UserByWebAuthnHandle", "PasskeysByUserID"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			alice := h.user("alice")
			dev := accesstest.NewPasskeyDevice(t)
			h.enrol(alice, dev)

			res, err := h.login(&faultStore{MemStore: h.store, fail: method}, dev)
			if !errors.Is(err, access.ErrAuthBackend) || !errors.Is(err, errDisk) {
				t.Errorf("CompleteLogin error = %v, want access.ErrAuthBackend wrapping the store error", err)
			}
			if errors.Is(err, webauthn.ErrUnknownCredential) {
				t.Errorf("CompleteLogin error = %v, a store failure reported as an unknown credential", err)
			}
			if res.User != nil {
				t.Errorf("CompleteLogin user = %+v, want nil", res.User)
			}
		})
	}
}

func TestDuplicateCredentialAcrossUsers(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	alice, bob := h.user("alice"), h.user("bob")
	dev := accesstest.NewPasskeyDevice(t)
	h.enrol(alice, dev)

	again := h.register(bob, dev)
	if err := h.store.CreatePasskey(t.Context(), again); !errors.Is(err, account.ErrDuplicateCredential) {
		t.Errorf("CreatePasskey(alice's credential for bob) error = %v, want account.ErrDuplicateCredential", err)
	}
	if creds, err := h.store.PasskeysByUserID(t.Context(), bob.ID); err != nil || len(creds) != 0 {
		t.Errorf("bob's passkeys = %d, %v; want none", len(creds), err)
	}
}

func TestReauthenticationBoundToUser(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	alice, bob := h.user("alice"), h.user("bob")
	aliceDev, bobDev := accesstest.NewPasskeyDevice(t), accesstest.NewPasskeyDevice(t)
	h.enrol(alice, aliceDev)
	h.enrol(bob, bobDev)

	reauth := func(begin *access.User, dev *accesstest.PasskeyDevice, finish *access.User) (webauthn.LoginResult, error) {
		t.Helper()
		options, ceremony, err := webauthn.BeginReauthentication(h.rp, h.webauthnUser(begin), h.origin)
		if err != nil {
			t.Fatalf("BeginReauthentication: %v", err)
		}
		return webauthn.CompleteReauthentication(t.Context(), h.rp, h.store, h.webauthnUser(finish), ceremony, bytes.NewReader(dev.Assert(h.json(options))))
	}

	t.Run("own_user", func(t *testing.T) {
		res, err := reauth(alice, aliceDev, alice)
		if err != nil {
			t.Fatalf("CompleteReauthentication: %v", err)
		}
		if res.User == nil || res.User.ID != alice.ID || !bytes.Equal(res.CredentialID, aliceDev.CredentialID) {
			t.Errorf("LoginResult = %+v, want alice's credential", res)
		}
		if stored := h.passkey(alice, aliceDev.CredentialID); stored.SignCount != aliceDev.SignCount {
			t.Errorf("stored SignCount = %d, want %d", stored.SignCount, aliceDev.SignCount)
		}
	})
	t.Run("finished_as_another_user", func(t *testing.T) {
		before := h.passkey(bob, bobDev.CredentialID)
		res, err := reauth(alice, bobDev, bob)
		if err == nil || res.User != nil {
			t.Fatalf("CompleteReauthentication(alice's ceremony as bob) = %+v, %v; want a refusal", res, err)
		}
		if errors.Is(err, webauthn.ErrUnknownCredential) {
			t.Errorf("error = %v, want a ceremony mismatch, not an unknown credential", err)
		}
		if after := h.passkey(bob, bobDev.CredentialID); !after.LastUsedAt.Equal(before.LastUsedAt) {
			t.Error("bob's passkey custody written by a refused step-up")
		}
	})
	t.Run("another_users_ceremony_and_credential", func(t *testing.T) {
		res, err := reauth(alice, aliceDev, bob)
		if err == nil || res.User != nil {
			t.Fatalf("CompleteReauthentication(alice's ceremony and passkey as bob) = %+v, %v; want a refusal", res, err)
		}
		if errors.Is(err, webauthn.ErrUnknownCredential) {
			t.Errorf("error = %v, want a ceremony mismatch: the passkey is registered, to another user", err)
		}
	})
	t.Run("another_users_credential", func(t *testing.T) {
		res, err := reauth(alice, bobDev, alice)
		if !errors.Is(err, webauthn.ErrUnknownCredential) || res.User != nil {
			t.Errorf("CompleteReauthentication(bob's passkey for alice) = %+v, %v; want ErrUnknownCredential", res, err)
		}
	})
	t.Run("discoverable_ceremony", func(t *testing.T) {
		options, ceremony, err := webauthn.BeginLogin(h.rp, h.origin)
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		res, err := webauthn.CompleteReauthentication(t.Context(), h.rp, h.store, h.webauthnUser(alice), ceremony, bytes.NewReader(aliceDev.Assert(h.json(options))))
		if err == nil || res.User != nil {
			t.Errorf("CompleteReauthentication(discoverable ceremony) = %+v, %v; want a refusal", res, err)
		}
	})
	t.Run("reauthentication_ceremony_at_login", func(t *testing.T) {
		options, ceremony, err := webauthn.BeginReauthentication(h.rp, h.webauthnUser(alice), h.origin)
		if err != nil {
			t.Fatalf("BeginReauthentication: %v", err)
		}
		res, err := webauthn.CompleteLogin(t.Context(), h.rp, h.store, ceremony, bytes.NewReader(aliceDev.Assert(h.json(options))))
		if err == nil || res.User != nil {
			t.Errorf("CompleteLogin(step-up ceremony) = %+v, %v; want a refusal", res, err)
		}
	})
}
