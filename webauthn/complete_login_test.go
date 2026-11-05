package webauthn

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// custodyRecord captures one UpdatePasskeyAfterLogin call.
type custodyRecord struct {
	credID []byte
	upd    access.PasskeyLoginUpdate
	userID int64
}

// fakeStore is an in-memory Store double for the white-box login path.
type fakeStore struct {
	users     map[int64]*access.User
	creds     map[int64][]access.PasskeyCredential
	userErr   error
	credsErr  error
	updateErr error
	updated   *custodyRecord
}

func (f *fakeStore) UserByWebAuthnHandle(_ context.Context, handle []byte) (*access.User, bool, error) {
	if f.userErr != nil {
		return nil, false, f.userErr
	}
	for _, u := range f.users {
		if bytes.Equal(u.WebAuthnHandle, handle) {
			return u, true, nil
		}
	}
	return nil, false, nil
}

func (f *fakeStore) PasskeysByUserID(_ context.Context, userID int64) ([]access.PasskeyCredential, error) {
	if f.credsErr != nil {
		return nil, f.credsErr
	}
	return f.creds[userID], nil
}

func (f *fakeStore) UpdatePasskeyAfterLogin(_ context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error {
	f.updated = &custodyRecord{userID: userID, credID: credID, upd: upd}
	return f.updateErr
}

var _ Store = (*fakeStore)(nil)

func TestLoginFinder(t *testing.T) {
	t.Parallel()
	handle := access.GenerateWebAuthnHandle()
	alice := &access.User{ID: 7, Username: "alice", Enabled: true, WebAuthnHandle: handle}
	credID := []byte{1, 2, 3}
	held := map[int64][]access.PasskeyCredential{7: {{CredentialID: credID, UserID: 7}}}
	errDisk := errors.New("pg://secret-host timeout")
	upstream := protocol.ErrBadRequest.WithDetails("Failed to lookup Client-side Discoverable Credential")

	tests := []struct {
		store       *fakeStore
		wantErr     error
		name        string
		handle      []byte
		rawID       []byte
		wantBackend bool
	}{
		{name: "unknown_handle", store: &fakeStore{users: map[int64]*access.User{7: alice}, creds: held}, handle: access.GenerateWebAuthnHandle(), rawID: credID, wantErr: ErrUnknownCredential},
		{name: "empty_handle", store: &fakeStore{users: map[int64]*access.User{7: alice}, creds: held}, rawID: credID, wantErr: ErrUnknownCredential},
		{name: "credential_not_held", store: &fakeStore{users: map[int64]*access.User{7: alice}, creds: held}, handle: handle, rawID: []byte{9}, wantErr: ErrUnknownCredential},
		{name: "user_lookup_error", store: &fakeStore{userErr: errDisk}, handle: handle, rawID: credID, wantErr: access.ErrAuthBackend, wantBackend: true},
		{name: "passkey_lookup_error", store: &fakeStore{users: map[int64]*access.User{7: alice}, credsErr: errDisk}, handle: handle, rawID: credID, wantErr: access.ErrAuthBackend, wantBackend: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f loginFinder
			got, err := f.handler(t.Context(), tc.store)(tc.rawID, tc.handle)
			if !errors.Is(err, errLookupFailed) || got != nil {
				t.Fatalf("handler = %v, %v; want nil, errLookupFailed", got, err)
			}
			if f.user != nil {
				t.Errorf("finder recorded user %+v on a failed lookup", f.user)
			}
			ferr := f.failure(upstream)
			if !errors.Is(ferr, tc.wantErr) {
				t.Errorf("failure() = %v, want it to match %v", ferr, tc.wantErr)
			}
			if _, ok := errors.AsType[*protocol.Error](ferr); ok {
				t.Errorf("failure() = %v reaches the upstream error, want it translated", ferr)
			}
			if tc.wantBackend && !errors.Is(ferr, errDisk) {
				t.Errorf("failure() = %v, want the store error in the chain", ferr)
			}
		})
	}

	t.Run("resolved", func(t *testing.T) {
		t.Parallel()
		var f loginFinder
		got, err := f.handler(t.Context(), &fakeStore{users: map[int64]*access.User{7: alice}, creds: held})(credID, handle)
		if err != nil {
			t.Fatalf("handler error = %v, want nil", err)
		}
		u, ok := got.(*userAdapter)
		if !ok || u.User != f.user || f.user.AuthUser != alice || len(f.user.Credentials) != 1 {
			t.Fatalf("handler = %#v, recorded %+v; want alice with her one passkey", got, f.user)
		}
		if ferr := f.failure(upstream); !errors.Is(ferr, upstream) || !strings.Contains(ferr.Error(), "assertion ceremony failed") {
			t.Errorf("failure() after a resolved lookup = %v, want the wrapped verification error", ferr)
		}
	})
}

func TestCompleteAssertionStoresCustody(t *testing.T) {
	t.Parallel()
	fs := &fakeStore{}
	stored := access.PasskeyCredential{CredentialID: []byte{9, 9, 9}, UserID: 7, SignCount: 41}
	user := &User{AuthUser: &access.User{ID: 7, Username: "alice"}, Credentials: []access.PasskeyCredential{stored}}
	// UP, UV, BE and AT set, BS clear: the AT bit has no boolean, so only the
	// octet carries it.
	const octet = 0x4D
	cred := &gowebauthn.Credential{
		ID:            stored.CredentialID,
		Flags:         gowebauthn.NewCredentialFlags(octet),
		Authenticator: gowebauthn.Authenticator{SignCount: 42, CloneWarning: true},
	}
	parsed := &protocol.ParsedCredentialAssertionData{}
	parsed.Response.AuthenticatorData.Counter = 42
	before := time.Now()

	res, err := completeAssertion(t.Context(), fs, user, parsed, cred)
	if err != nil {
		t.Fatalf("completeAssertion: %v", err)
	}
	if res.User != user.AuthUser || !bytes.Equal(res.CredentialID, cred.ID) || res.CloneWarning {
		t.Errorf("LoginResult = %+v, want alice, %x, no clone warning on 41 to 42", res, cred.ID)
	}
	if fs.updated == nil {
		t.Fatal("custody write not issued")
	}
	if fs.updated.userID != 7 || !bytes.Equal(fs.updated.credID, cred.ID) {
		t.Errorf("custody write for user %d, credential %x; want 7, %x", fs.updated.userID, fs.updated.credID, cred.ID)
	}
	upd := fs.updated.upd
	if upd.SignCount != 42 || upd.RawFlags != octet || !upd.CloneWarning || upd.At.Before(before) {
		t.Errorf("custody update = %+v, want SignCount 42, RawFlags %#x, the sticky CloneWarning and At now", upd, octet)
	}
	res.CredentialID[0] = 0
	if cred.ID[0] != 9 {
		t.Error("LoginResult.CredentialID aliases the credential")
	}
}

func TestCompleteAssertionFailedCustody(t *testing.T) {
	t.Parallel()
	errBucket := errors.New("bucket unavailable")
	fs := &fakeStore{updateErr: errBucket}
	user := &User{AuthUser: &access.User{ID: 7}}

	res, err := completeAssertion(t.Context(), fs, user, &protocol.ParsedCredentialAssertionData{}, &gowebauthn.Credential{ID: []byte{1}})
	if !errors.Is(err, access.ErrAuthBackend) || !errors.Is(err, errBucket) {
		t.Errorf("completeAssertion error = %v, want access.ErrAuthBackend wrapping the store error", err)
	}
	if res.User != nil {
		t.Errorf("completeAssertion user = %+v, want nil", res.User)
	}
}

func TestSignCountRegressed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		stored, asserted uint32
		want             bool
	}{
		{stored: 0, asserted: 0, want: false},
		{stored: 0, asserted: 1, want: false},
		{stored: 4, asserted: 5, want: false},
		{stored: 5, asserted: 5, want: true},
		{stored: 5, asserted: 4, want: true},
		{stored: 5, asserted: 0, want: true},
	}
	for _, tc := range tests {
		if got := signCountRegressed(tc.stored, tc.asserted); got != tc.want {
			t.Errorf("signCountRegressed(%d, %d) = %v, want %v", tc.stored, tc.asserted, got, tc.want)
		}
	}
}

// TestCompleteLogin_ceremony_failure_returns_wrapped_error: an undecodable
// assertion body fails the ceremony with context, no user and no custody write.
func TestCompleteLogin_ceremony_failure_returns_wrapped_error(t *testing.T) {
	t.Parallel()
	rp, err := New(RPConfig{ID: "example.com", DisplayName: "Example"})
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeStore{}
	sess := Ceremony{data: &gowebauthn.SessionData{Challenge: "test-challenge", Origin: "https://example.com"}}

	res, cerr := CompleteLogin(t.Context(), rp, fs, sess, strings.NewReader("not json"))
	if cerr == nil || !strings.Contains(cerr.Error(), "assertion ceremony failed") {
		t.Fatalf("CompleteLogin with garbage assertion = %v, want a failure naming the ceremony", cerr)
	}
	if res.User != nil {
		t.Errorf("CompleteLogin returned user %v on failure, want nil", res.User)
	}
	if fs.updated != nil {
		t.Error("custody write issued despite ceremony failure")
	}
}
