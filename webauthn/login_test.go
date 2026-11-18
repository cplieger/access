package webauthn

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/webauthn/internal/cose"
)

// recordedAssertion is one custody write a loginStore was handed.
type recordedAssertion struct {
	upd    access.PasskeyLoginUpdate
	credID []byte
	userID int64
}

// lookupAnswer bends a loginStore's account lookup off the store contract,
// for the finish to refuse.
type lookupAnswer uint8

const (
	lookupHonest    lookupAnswer = iota
	lookupNotFound               // the account beside found false
	lookupNoAccount              // found true with a nil account
)

// loginStore is a Store over fixed accounts and passkeys that records each
// custody write; a set error fails its method.
type loginStore struct {
	lookupErr, passkeysErr, recordErr error
	passkeys                          map[int64][]access.PasskeyCredential
	users                             []*access.User
	recorded                          []recordedAssertion
	lookup                            lookupAnswer
}

func (s *loginStore) UserByWebAuthnHandle(_ context.Context, handle []byte) (*access.User, bool, error) {
	if s.lookupErr != nil {
		return nil, false, s.lookupErr
	}
	for _, u := range s.users {
		if bytes.Equal(u.WebAuthnHandle, handle) {
			switch s.lookup {
			case lookupHonest:
			case lookupNotFound:
				return u, false, nil
			case lookupNoAccount:
				return nil, true, nil
			}
			return u, true, nil
		}
	}
	return nil, false, nil
}

func (s *loginStore) PasskeysByUserID(_ context.Context, userID int64) ([]access.PasskeyCredential, error) {
	if s.passkeysErr != nil {
		return nil, s.passkeysErr
	}
	return s.passkeys[userID], nil
}

func (s *loginStore) RecordAssertion(_ context.Context, userID int64, credID []byte, upd access.PasskeyLoginUpdate) error {
	s.recorded = append(s.recorded, recordedAssertion{userID: userID, credID: bytes.Clone(credID), upd: upd})
	return s.recordErr
}

var _ Store = (*loginStore)(nil)

// bob is a second account, holding no passkey.
func bob() *access.User {
	return &access.User{ID: 43, Username: "bob", WebAuthnHandle: []byte("bob's user handle")}
}

// loginCase is one assertion finish: the relying party, the ceremony, the
// store, the reauthenticating user, and the response's members. A nil
// userHandle sends none; sign re-signs the members with signer.
type loginCase struct {
	rp         *RelyingParty
	st         *ceremonyState
	store      *loginStore
	user       *User
	signer     crypto.Signer
	ext        any
	userHandle []byte
	rawID      []byte
	clientData []byte
	authData   []byte
	sig        []byte
}

// assertCase answers half's authentication ceremony of kind, begun at the
// vectors' origin, for regUser holding cred.
func assertCase(t testing.TB, kind ceremonyKind, half vectorHalf, cred access.PasskeyCredential) *loginCase {
	t.Helper()
	user := regUser()
	user.Credentials = []access.PasskeyCredential{cred}
	st := &ceremonyState{
		kind:      kind,
		challenge: half.bytes(t, "challenge"),
		origin:    mustParseOrigin(t, vectorOrigin),
		expires:   time.Now().Add(CeremonyTimeout),
	}
	if kind == ceremonyReauthentication {
		st.userHandle = user.WebAuthnID()
		st.allowed = [][]byte{cred.CredentialID}
	}
	return &loginCase{
		rp:         mustNew(t, RPConfig{ID: vectorRPID}),
		st:         st,
		store:      &loginStore{users: []*access.User{user.AuthUser, bob()}, passkeys: map[int64][]access.PasskeyCredential{42: {cred}}},
		user:       user,
		ext:        map[string]any{},
		userHandle: user.WebAuthnID(),
		rawID:      cred.CredentialID,
		clientData: half.bytes(t, "clientDataJSON"),
		authData:   half.bytes(t, "authenticatorData"),
		sig:        half.bytes(t, "signature"),
	}
}

// resigned is section's authentication half against the record
// finishRegistration returns for its registration half, its authData with UV
// set, signed anew with the vector's private key.
func resigned(t testing.TB, kind ceremonyKind, section string) *loginCase {
	t.Helper()
	c := assertCase(t, kind, s16Section(t, section).Authentication, registered(t, section))
	c.signer = vectorSigner(t, section)
	c.authData = bytes.Clone(c.authData)
	c.authData[32] |= 0x04
	c.sign(t)
	return c
}

// registered is the record finishRegistration stores for section's
// credential: WebAuthn §16.3's self attestation as published, every other
// with UV set under none.
func registered(t testing.TB, section string) access.PasskeyCredential {
	t.Helper()
	c := noneCase(t, section)
	if section == "16.3" {
		c = regCaseWith(t, section, s16Section(t, section).Registration.bytes(t, "attestationObject"))
	}
	rec, err := c.finish(t)
	if err != nil {
		t.Fatalf("finishRegistration(%s) = %v", section, err)
	}
	return *rec
}

// vectorSigner is section's credential private key: credential_private_key
// for ES256, the RSA key of WebAuthn §16.10 from private_key_p and
// private_key_q with e = 65537, and the Ed25519 seed private_key of
// WebAuthn §16.11.
func vectorSigner(t testing.TB, section string) crypto.Signer {
	t.Helper()
	r := s16Section(t, section).Registration
	switch section {
	case "16.10":
		p := new(big.Int).SetBytes(r.bytes(t, "private_key_p"))
		q := new(big.Int).SetBytes(r.bytes(t, "private_key_q"))
		one := big.NewInt(1)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		k := &rsa.PrivateKey{
			N:      new(big.Int).Mul(p, q),
			E:      65537,
			D:      new(big.Int).ModInverse(big.NewInt(65537), phi),
			Primes: []*big.Int{p, q},
		}
		k.Precompute()
		if err := k.Validate(); err != nil {
			t.Fatal(err)
		}
		return k
	case "16.11":
		return ed25519.NewKeyFromSeed(r.bytes(t, "private_key"))
	default:
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), r.bytes(t, "credential_private_key"))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
}

// signM signs m as k's COSE algorithm does: ES256 and RS256 over SHA-256(m),
// EdDSA and ML-DSA over m itself.
func signM(t testing.TB, k crypto.Signer, m []byte) []byte {
	t.Helper()
	digest, opts := m, crypto.SignerOpts(crypto.Hash(0))
	switch k.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey:
		d := sha256.Sum256(m)
		digest, opts = d[:], crypto.SHA256
	}
	sig, err := k.Sign(rand.Reader, digest, opts)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// signedMessage is WebAuthn §7.2's signed message, authData ‖ SHA-256(cData).
func signedMessage(authData, clientData []byte) []byte {
	hash := sha256.Sum256(clientData)
	return append(bytes.Clone(authData), hash[:]...)
}

func (c *loginCase) sign(t testing.TB) {
	t.Helper()
	c.sig = signM(t, c.signer, signedMessage(c.authData, c.clientData))
}

// members is the case's AuthenticationResponseJSON (WebAuthn §5.1), as a
// browser's toJSON() writes it.
func (c *loginCase) members() map[string]any {
	id := b64(c.rawID)
	resp := map[string]any{
		"clientDataJSON":    b64(c.clientData),
		"authenticatorData": b64(c.authData),
		"signature":         b64(c.sig),
	}
	if c.userHandle != nil {
		resp["userHandle"] = b64(c.userHandle)
	}
	return map[string]any{
		"id": id, "rawId": id, "type": "public-key", "response": resp,
		"clientExtensionResults": c.ext,
	}
}

func (c *loginCase) body(t testing.TB) []byte {
	t.Helper()
	return marshal(t, c.members())
}

func (c *loginCase) login(t testing.TB) (LoginResult, error) {
	t.Helper()
	return verifyLogin(t.Context(), c.rp, c.store, c.st, c.body(t))
}

func (c *loginCase) reauth(t testing.TB) (LoginResult, error) {
	t.Helper()
	return verifyReauthentication(t.Context(), c.rp, c.store, c.user, c.st, c.body(t))
}

// finish runs the finish of the case's ceremony kind.
func (c *loginCase) finish(t testing.TB) (LoginResult, error) {
	t.Helper()
	if c.st != nil && c.st.kind == ceremonyReauthentication {
		return c.reauth(t)
	}
	return c.login(t)
}

func wantNoLogin(t *testing.T, c *loginCase, res LoginResult, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("finish = %v, want %v", err, want)
	}
	if res.User != nil || res.CredentialID != nil {
		t.Errorf("finish returned %+v beside its refusal", res)
	}
	if len(c.store.recorded) != 0 {
		t.Errorf("a refused assertion wrote custody: %+v", c.store.recorded)
	}
}

func wantLoggedIn(t *testing.T, c *loginCase, res LoginResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("finish = %v, want a login", err)
	}
	if res.User == nil || res.User.ID != 42 || !bytes.Equal(res.CredentialID, c.rawID) {
		t.Errorf("LoginResult = %+v, want user 42 and credential %x", res, c.rawID)
	}
	if len(c.store.recorded) != 1 {
		t.Fatalf("%d custody writes, want 1", len(c.store.recorded))
	}
	if w := c.store.recorded[0]; w.userID != 42 || !bytes.Equal(w.credID, c.rawID) {
		t.Errorf("custody written for user %d credential %x, want 42 and %x", w.userID, w.credID, c.rawID)
	}
}

var bothKinds = []struct {
	name string
	kind ceremonyKind
}{{"login", ceremonyLogin}, {"reauthentication", ceremonyReauthentication}}

// TestVerifyLogin_WebAuthn7_2_ceremony checks that the response answers this
// login: a ceremony from a Begin function (ErrCeremonyUnbound otherwise), of
// the login kind, holding a challenge that has not outlived it
// (WebAuthn §13.4.3).
func TestVerifyLogin_WebAuthn7_2_ceremony(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		edit func(*loginCase)
		want error
		name string
	}{
		{name: "no ceremony", edit: func(c *loginCase) { c.st = nil }, want: ErrCeremonyUnbound},
		{name: "a registration ceremony", edit: func(c *loginCase) { c.st.kind = ceremonyRegistration }, want: errCeremonyKind},
		{name: "a reauthentication ceremony", edit: func(c *loginCase) { c.st.kind = ceremonyReauthentication }, want: errCeremonyKind},
		{name: "a ceremony of no kind", edit: func(c *loginCase) { c.st.kind = 0 }, want: errCeremonyKind},
		{name: "expired", edit: func(c *loginCase) { c.st.expires = time.Now().Add(-time.Second) }, want: errCeremonyExpired},
		{name: "no expiry", edit: func(c *loginCase) { c.st.expires = time.Time{} }, want: errCeremonyExpired},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			lc := resigned(t, ceremonyLogin, "16.2")
			c.edit(lc)
			res, err := lc.login(t)
			wantNoLogin(t, lc, res, err, c.want)
		})
	}
}

// TestVerifyReauthentication_WebAuthn7_2_ceremony checks that the response
// answers this step-up: a ceremony of the reauthentication kind, not
// expired, begun for the user it finishes for (WebAuthn §7.2's identified-user
// branch).
func TestVerifyReauthentication_WebAuthn7_2_ceremony(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		edit func(*loginCase)
		want error
		name string
	}{
		{name: "no ceremony", edit: func(c *loginCase) { c.st = nil }, want: ErrCeremonyUnbound},
		{name: "a login ceremony", edit: func(c *loginCase) { c.st.kind = ceremonyLogin }, want: errCeremonyKind},
		{name: "a registration ceremony", edit: func(c *loginCase) { c.st.kind = ceremonyRegistration }, want: errCeremonyKind},
		{name: "expired", edit: func(c *loginCase) { c.st.expires = time.Now().Add(-time.Second) }, want: errCeremonyExpired},
		{name: "begun for another user", edit: func(c *loginCase) { c.st.userHandle = bob().WebAuthnHandle }, want: errCeremonyUser},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			lc := resigned(t, ceremonyReauthentication, "16.2")
			c.edit(lc)
			res, err := lc.reauth(t)
			wantNoLogin(t, lc, res, err, c.want)
		})
	}
}

// TestVerifyLogin_WebAuthn7_2_response checks that both finishes read the
// response as WebAuthn §5.1's AuthenticationResponseJSON before any other
// step, its userHandle 1 to 64 bytes when present (WebAuthn §5.4.3).
func TestVerifyLogin_WebAuthn7_2_response(t *testing.T) {
	t.Parallel()
	for _, k := range bothKinds {
		for _, c := range []struct {
			body func(t *testing.T, m map[string]any) []byte
			want error
			name string
		}{
			{name: "not JSON", body: func(*testing.T, map[string]any) []byte { return []byte("{") }, want: errResponseJSON},
			{name: "a duplicate member", body: func(t *testing.T, m map[string]any) []byte {
				return withMember(marshal(t, m), `"type":"public-key"`)
			}, want: errResponseJSON},
			{name: "type", body: func(t *testing.T, m map[string]any) []byte {
				m["type"] = "password"
				return marshal(t, m)
			}, want: errCredentialType},
			{name: "id not rawId", body: func(t *testing.T, m map[string]any) []byte {
				m["id"] = b64([]byte("another credential"))
				return marshal(t, m)
			}, want: errIDMismatch},
		} {
			t.Run(k.name+" "+c.name, func(t *testing.T) {
				t.Parallel()
				lc := resigned(t, k.kind, "16.2")
				body := c.body(t, lc.members())
				var (
					res LoginResult
					err error
				)
				if k.kind == ceremonyLogin {
					res, err = verifyLogin(t.Context(), lc.rp, lc.store, lc.st, body)
				} else {
					res, err = verifyReauthentication(t.Context(), lc.rp, lc.store, lc.user, lc.st, body)
				}
				wantNoLogin(t, lc, res, err, c.want)
			})
		}
		t.Run(k.name+" a userHandle of 65 bytes", func(t *testing.T) {
			t.Parallel()
			lc := resigned(t, k.kind, "16.2")
			lc.userHandle = bytes.Repeat([]byte{'h'}, 65)
			res, err := lc.finish(t)
			wantNoLogin(t, lc, res, err, errUserHandle)
		})
	}
}

// TestVerifyLogin_WebAuthn7_2_identification checks §7.2's identification
// step for a user not identified before the ceremony: userHandle is
// required, and the account it names must hold a credential record whose id
// is rawId; anything else is ErrUnknownCredential, and a store failure is
// access.ErrAuthBackend.
func TestVerifyLogin_WebAuthn7_2_identification(t *testing.T) {
	t.Parallel()
	errStore := errors.New("store down")
	for _, c := range []struct {
		edit func(*loginCase)
		want error
		name string
	}{
		{name: "no userHandle", edit: func(c *loginCase) { c.userHandle = nil }, want: errNoUserHandle},
		{name: "a handle with no account", edit: func(c *loginCase) { c.userHandle = []byte("nobody") }, want: ErrUnknownCredential},
		{name: "another user's handle", edit: func(c *loginCase) { c.userHandle = bob().WebAuthnHandle }, want: ErrUnknownCredential},
		{name: "the account holds no such credential", edit: func(c *loginCase) { c.store.passkeys[42] = nil }, want: ErrUnknownCredential},
		{name: "another credential of the account", edit: func(c *loginCase) {
			c.store.passkeys[42] = []access.PasskeyCredential{registered(t, "16.3")}
		}, want: ErrUnknownCredential},
		{name: "the account lookup fails", edit: func(c *loginCase) { c.store.lookupErr = errStore }, want: access.ErrAuthBackend},
		{name: "not found beside an account", edit: func(c *loginCase) { c.store.lookup = lookupNotFound }, want: ErrUnknownCredential},
		{name: "found with no account", edit: func(c *loginCase) { c.store.lookup = lookupNoAccount }, want: ErrUnknownCredential},
		{name: "the passkey lookup fails", edit: func(c *loginCase) { c.store.passkeysErr = errStore }, want: access.ErrAuthBackend},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			lc := resigned(t, ceremonyLogin, "16.2")
			c.edit(lc)
			res, err := lc.login(t)
			wantNoLogin(t, lc, res, err, c.want)
			if errors.Is(c.want, access.ErrAuthBackend) && !errors.Is(err, errStore) {
				t.Errorf("finish = %v, want it to wrap the store's error", err)
			}
			if errors.Is(c.want, ErrUnknownCredential) && errors.Is(err, access.ErrAuthBackend) {
				t.Errorf("finish = %v, an unknown credential is not a backend failure", err)
			}
		})
	}
}

// TestVerifyReauthentication_WebAuthn7_2_identification checks §7.2's
// identification step for an identified user: rawId must be on the
// ceremony's allowCredentials and among the user's passkeys now, so one
// deleted since Begin fails, and a userHandle, when present, must be the
// user's.
func TestVerifyReauthentication_WebAuthn7_2_identification(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		edit func(*loginCase)
		want error
		name string
	}{
		{name: "held but not allowed", edit: func(c *loginCase) { c.st.allowed = [][]byte{[]byte("another credential")} }, want: ErrUnknownCredential},
		{name: "no allowed credential", edit: func(c *loginCase) { c.st.allowed = nil }, want: ErrUnknownCredential},
		{name: "deleted since Begin", edit: func(c *loginCase) { c.user.Credentials = nil }, want: ErrUnknownCredential},
		{name: "another user's handle", edit: func(c *loginCase) { c.userHandle = bob().WebAuthnHandle }, want: errAssertionUser},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			lc := resigned(t, ceremonyReauthentication, "16.2")
			c.edit(lc)
			res, err := lc.reauth(t)
			wantNoLogin(t, lc, res, err, c.want)
		})
	}
	t.Run("no userHandle", func(t *testing.T) {
		t.Parallel()
		lc := resigned(t, ceremonyReauthentication, "16.2")
		lc.userHandle = nil
		res, err := lc.reauth(t)
		wantLoggedIn(t, lc, res, err)
	})
}

// TestVerifyLogin_WebAuthn7_2_clientData checks §7.2's client data steps
// against the ceremony, each response re-signed so only the step refuses:
// type webauthn.get, the ceremony's challenge, the origin it began at, so a
// second allowlisted origin is refused (WebAuthn §13.4.9), and no frame.
func TestVerifyLogin_WebAuthn7_2_clientData(t *testing.T) {
	t.Parallel()
	challenge := b64(s16Section(t, "16.2").Authentication.bytes(t, "challenge"))
	for _, k := range bothKinds {
		for _, c := range []struct {
			want       error
			name       string
			clientData []byte
		}{
			{name: "type webauthn.create", clientData: clientDataJSON("webauthn.create", challenge, vectorOrigin, ""), want: errClientDataType},
			{name: "another ceremony's challenge", clientData: s16Section(t, "16.3").Authentication.bytes(t, "clientDataJSON"), want: errChallenge},
			{name: "a second allowed origin", clientData: clientDataJSON("webauthn.get", challenge, "https://login.example.org", ""), want: errOrigin},
			{name: "crossOrigin", clientData: clientDataJSON("webauthn.get", challenge, vectorOrigin, `,"crossOrigin":true`), want: errFramed},
			{name: "topOrigin", clientData: clientDataJSON("webauthn.get", challenge, vectorOrigin, `,"topOrigin":"https://example.com"`), want: errFramed},
		} {
			t.Run(k.name+" "+c.name, func(t *testing.T) {
				t.Parallel()
				lc := resigned(t, k.kind, "16.2")
				lc.rp = mustNew(t, RPConfig{ID: vectorRPID, Origins: []string{vectorOrigin, "https://login.example.org"}})
				lc.clientData = c.clientData
				lc.sign(t)
				res, err := lc.finish(t)
				wantNoLogin(t, lc, res, err, c.want)
			})
		}
	}
}

// TestVerifyLogin_WebAuthn7_2_extensions checks §7.2's extension step: no
// Begin requests an extension, and unsolicited client outputs
// (WebAuthn §16.17's prf, appid) and authenticator outputs (ED set, one CBOR
// map) are ignored.
func TestVerifyLogin_WebAuthn7_2_extensions(t *testing.T) {
	t.Parallel()
	for _, k := range bothKinds {
		t.Run(k.name+" client outputs", func(t *testing.T) {
			t.Parallel()
			lc := resigned(t, k.kind, "16.2")
			lc.ext = map[string]any{"prf": map[string]any{"results": map[string]any{"first": b64([]byte("prf output"))}}, "appid": true}
			res, err := lc.finish(t)
			wantLoggedIn(t, lc, res, err)
		})
		t.Run(k.name+" authenticator outputs", func(t *testing.T) {
			t.Parallel()
			lc := resigned(t, k.kind, "16.2")
			lc.authData = append(lc.authData, cborEnc(cborMap{"credProtect", 2})...)
			lc.authData[32] |= flagExtensions
			lc.sign(t)
			res, err := lc.finish(t)
			wantLoggedIn(t, lc, res, err)
		})
	}
}

// TestVerifyLogin_WebAuthn7_2_authData checks §7.2's authenticator-data
// steps, each response re-signed so only the step refuses: the rpIdHash, UP,
// UV (access always requires it), BS only with BE (WebAuthn §6.1.3), BE equal
// to the stored record's, which never changes (WebAuthn §6.1.3), and no
// attested credential data (WebAuthn §6.1).
func TestVerifyLogin_WebAuthn7_2_authData(t *testing.T) {
	t.Parallel()
	// WebAuthn §16.2's credential is registered BE and BS (0x5d), §16.11's
	// with BE clear (0x45).
	for _, k := range bothKinds {
		for _, c := range []struct {
			edit    func(*loginCase)
			want    error
			name    string
			section string
		}{
			{name: "another RP ID", section: "16.2", edit: func(c *loginCase) { c.rp = mustNew(t, RPConfig{ID: "login.example.org"}) }, want: errRPIDHash},
			{name: "UP clear", section: "16.2", edit: func(c *loginCase) { c.authData[32] &^= 0x01 }, want: errUserPresence},
			{name: "UV clear", section: "16.2", edit: func(c *loginCase) { c.authData[32] &^= 0x04 }, want: errUserVerification},
			{name: "BS without BE", section: "16.11", edit: func(c *loginCase) { c.authData[32] |= 0x10 }, want: errBackupState},
			{name: "BE cleared", section: "16.2", edit: func(c *loginCase) { c.authData[32] &^= 0x18 }, want: errBackupEligibility},
			{name: "BE set", section: "16.11", edit: func(c *loginCase) { c.authData[32] |= 0x08 }, want: errBackupEligibility},
			{name: "a store that dropped RawFlags", section: "16.2", edit: func(c *loginCase) {
				c.user.Credentials[0].RawFlags = 0
				c.store.passkeys[42][0].RawFlags = 0
			}, want: errBackupEligibility},
			{name: "AT set", section: "16.2", edit: func(c *loginCase) {
				id := c.rawID
				c.authData = append(c.authData, make([]byte, 16)...)
				c.authData = binary.BigEndian.AppendUint16(c.authData, uint16(len(id)))
				c.authData = append(append(c.authData, id...), c.store.passkeys[42][0].PublicKey...)
				c.authData[32] |= flagAttested
			}, want: errAttestedData},
		} {
			t.Run(k.name+" "+c.name, func(t *testing.T) {
				t.Parallel()
				lc := resigned(t, k.kind, c.section)
				c.edit(lc)
				lc.sign(t)
				res, err := lc.finish(t)
				wantNoLogin(t, lc, res, err, c.want)
			})
		}
		t.Run(k.name+" BS cleared", func(t *testing.T) {
			t.Parallel()
			lc := resigned(t, k.kind, "16.2")
			lc.authData[32] &^= 0x10
			lc.sign(t)
			res, err := lc.finish(t)
			wantLoggedIn(t, lc, res, err)
			if got := lc.store.recorded[0].upd.RawFlags; got != 0x0d {
				t.Errorf("RawFlags written = %#x, want the assertion's 0x0d", got)
			}
		})
	}
}

// TestVerifyLogin_WebAuthn7_2_signature checks §7.2's signature step: sig
// over authData ‖ SHA-256(cData) as received, under the stored key, which is
// read under the parser's rules each time.
func TestVerifyLogin_WebAuthn7_2_signature(t *testing.T) {
	t.Parallel()
	for _, k := range bothKinds {
		for _, c := range []struct {
			edit func(*loginCase)
			want error
			name string
		}{
			{name: "a flipped signature byte", edit: func(c *loginCase) { c.sig[len(c.sig)-1] ^= 1 }, want: errAssertionSignature},
			{name: "signed over authData alone", edit: func(c *loginCase) { c.sig = signM(t, c.signer, c.authData) }, want: errAssertionSignature},
			{name: "signed over the cData parsed", edit: func(c *loginCase) {
				c.sig = signM(t, c.signer, signedMessage(c.authData, c.clientData))
				c.clientData = append(bytes.Clone(utf8BOM), c.clientData...)
			}, want: errAssertionSignature},
			{name: "signed by another credential", edit: func(c *loginCase) {
				c.sig = signM(t, vectorSigner(t, "16.3"), signedMessage(c.authData, c.clientData))
			}, want: errAssertionSignature},
			{name: "a stored key of an algorithm not offered", edit: func(c *loginCase) {
				v := s16Section(t, "16.8")
				key := vectorAuthData(t, v)[55+len(v.Registration.bytes(t, "credential_id")):]
				c.user.Credentials[0].PublicKey = key
				c.store.passkeys[42][0].PublicKey = key
			}, want: cose.ErrUnsupported},
			{name: "a stored key that does not parse", edit: func(c *loginCase) {
				c.user.Credentials[0].PublicKey = c.user.Credentials[0].PublicKey[:10]
				c.store.passkeys[42][0].PublicKey = c.user.Credentials[0].PublicKey
			}, want: errCredentialKey},
		} {
			t.Run(k.name+" "+c.name, func(t *testing.T) {
				t.Parallel()
				lc := resigned(t, k.kind, "16.2")
				c.edit(lc)
				res, err := lc.finish(t)
				wantNoLogin(t, lc, res, err, c.want)
			})
		}
		t.Run(k.name+" signed over the cData as received", func(t *testing.T) {
			t.Parallel()
			lc := resigned(t, k.kind, "16.2")
			lc.clientData = append(bytes.Clone(utf8BOM), lc.clientData...)
			lc.sign(t)
			res, err := lc.finish(t)
			wantLoggedIn(t, lc, res, err)
		})
	}
}

// TestVerifyLogin_WebAuthn7_2_signCount checks §7.2's signCount step against
// the count the ceremony read: when either is nonzero and the new one is not
// greater, the result signals a clone. The write carries the asserted count,
// flags and this assertion's signal; merging them is the store's.
func TestVerifyLogin_WebAuthn7_2_signCount(t *testing.T) {
	t.Parallel()
	for _, k := range bothKinds {
		for _, c := range []struct {
			name             string
			stored, asserted uint32
			storedWarning    bool
			regressed        bool
		}{
			{name: "both zero", stored: 0, asserted: 0},
			{name: "first count", stored: 0, asserted: 1},
			{name: "greater", stored: 4, asserted: 5},
			{name: "equal", stored: 5, asserted: 5, regressed: true},
			{name: "lower", stored: 5, asserted: 4, regressed: true},
			{name: "zero after nonzero", stored: 5, asserted: 0, regressed: true},
			{name: "greater after a stored warning", stored: 5, asserted: 6, storedWarning: true},
		} {
			t.Run(k.name+" "+c.name, func(t *testing.T) {
				t.Parallel()
				lc := resigned(t, k.kind, "16.2")
				lc.user.Credentials[0].SignCount, lc.store.passkeys[42][0].SignCount = c.stored, c.stored
				lc.user.Credentials[0].CloneWarning, lc.store.passkeys[42][0].CloneWarning = c.storedWarning, c.storedWarning
				binary.BigEndian.PutUint32(lc.authData[33:37], c.asserted)
				lc.sign(t)
				before := time.Now()
				res, err := lc.finish(t)
				wantLoggedIn(t, lc, res, err)
				if res.CloneWarning != c.regressed {
					t.Errorf("LoginResult.CloneWarning = %v, want %v", res.CloneWarning, c.regressed)
				}
				upd := lc.store.recorded[0].upd
				if upd.SignCount != c.asserted || upd.CloneWarning != c.regressed || upd.RawFlags != lc.authData[32] {
					t.Errorf("written %+v, want SignCount %d, CloneWarning %v, RawFlags %#x", upd, c.asserted, c.regressed, lc.authData[32])
				}
				if upd.At.Before(before) || upd.At.After(time.Now()) {
					t.Errorf("At = %v, want the finish's time", upd.At)
				}
			})
		}
	}
}

// TestVerifyLogin_WebAuthn7_2_custody checks §7.2's last step: a failed
// custody write fails the ceremony as access.ErrAuthBackend.
func TestVerifyLogin_WebAuthn7_2_custody(t *testing.T) {
	t.Parallel()
	errDiskFull := errors.New("disk full")
	for _, k := range bothKinds {
		t.Run(k.name, func(t *testing.T) {
			t.Parallel()
			lc := resigned(t, k.kind, "16.2")
			lc.store.recordErr = errDiskFull
			res, err := lc.finish(t)
			if !errors.Is(err, access.ErrAuthBackend) || !errors.Is(err, errDiskFull) {
				t.Errorf("finish = %v, want access.ErrAuthBackend wrapping the store's error", err)
			}
			if res.User != nil {
				t.Errorf("finish returned %+v beside its failure", res)
			}
		})
	}
}

// TestVerifyLogin_resultOwnsItsBytes checks that the result's credential ID
// is not the stored record's slice.
func TestVerifyLogin_resultOwnsItsBytes(t *testing.T) {
	t.Parallel()
	for _, k := range bothKinds {
		t.Run(k.name, func(t *testing.T) {
			t.Parallel()
			lc := resigned(t, k.kind, "16.2")
			want := slices.Clone(lc.rawID)
			res, err := lc.finish(t)
			wantLoggedIn(t, lc, res, err)
			res.CredentialID[0] ^= 0xff
			if !bytes.Equal(lc.user.Credentials[0].CredentialID, want) || !bytes.Equal(lc.store.passkeys[42][0].CredentialID, want) {
				t.Error("changing the result's CredentialID changed a stored record")
			}
		})
	}
}
