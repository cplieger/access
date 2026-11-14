package accesshttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/capture"
	"github.com/cplieger/access/internal/printcheck"
	"github.com/cplieger/access/oidc"
	"github.com/cplieger/access/ratelimit"
	"github.com/cplieger/access/webauthn"
)

const (
	printingSealerKey    = "printing-inventory-sealer-key-32"
	printingClientSecret = "printing-inventory-oidc-client-secret"
	printingFailureKey   = "printing-inventory-failure-key-3"
	printingPassword     = "printing-inventory-known-password"
	printingToken        = "printing-inventory-known-token-text"
)

// inventoryRow is one value of the printing inventory, held through a
// pointer, and the texts no printer of it may show.
type inventoryRow struct {
	ptr     any
	name    string
	secrets []string
}

func row(name string, ptr any, secrets ...string) inventoryRow {
	return inventoryRow{name: name, ptr: ptr, secrets: secrets}
}

// leaked reports whether got holds text in a form printcheck.Leak names or
// as decimal bytes, the form fmt gives a []byte it reaches by reflection
// under a verb a pointer does not take (%s and %q of a masked value's
// pointer print the pointed-to bytes through %v).
func leaked(got, text string) bool {
	decimal := make([]string, len(text))
	for i := range len(text) {
		decimal[i] = strconv.Itoa(int(text[i]))
	}
	return printcheck.Leak(got, text) || strings.Contains(got, strings.Join(decimal, " "))
}

// renderings returns v printed through every in-module printer, keyed by
// route. %p is built at run time, so go vet's printf check sees no
// constant pairing of %p with a non-pointer.
func renderings(v any) map[string]string {
	out := make(map[string]string)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		out[verb] = fmt.Sprintf(verb, v)
	}
	out["%p"] = fmt.Sprintf("%"+"p", v)
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("row", "v", v)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("row", "v", v)
	out["slog.TextHandler"], out["slog.JSONHandler"] = text.String(), js.String()
	b, err := json.Marshal(v)
	out["json.Marshal"] = string(b)
	if err != nil {
		out["json.Marshal"] = err.Error()
	}
	return out
}

// inventoryAllow is the inventory's one reviewed allow-list: every field
// of a row's type graph that can carry text and is not a masked type.
func inventoryAllow(t *testing.T) printcheck.Allow {
	t.Helper()
	m := reflect.TypeFor[access.Hash]().Field(1).Type
	if m.String() != "*access.masked" {
		t.Fatalf("access.Hash's second field is %s, want *access.masked", m)
	}
	return printcheck.Allow{
		Masked: []reflect.Type{reflect.TypeFor[access.Secret](), reflect.TypeFor[access.Hash](), m.Elem()},
		// Each has its own printing test or holds no secret: the caller's
		// transport and logger, times and addresses, the Authenticator and
		// Limiter (whose Sealer is a row of its own), a pending ceremony's
		// public challenge state, and a public origin.
		Types: []string{
			"time.Time", "netip.Addr", "http.Client", "slog.Logger",
			"access.Authenticator", "ratelimit.Limiter", "webauthn.Ceremony", "webauthn.Origin",
		},
		Fields: []string{
			"access.User.Username", "access.User.DisplayName", "access.User.Email", "access.User.Role",
			// The user handle a passkey ceremony sends to every authenticator.
			"access.User.WebAuthnHandle",
			"access.Session.ID", "access.Session.Kind", "access.Session.AuthMethod", "access.Session.Label",
			"access.Session.LastIP", "access.Session.UserAgent",
			"access.Key.KeyPrefix", "access.Key.KeySuffix", "access.Key.Label", "access.Key.LineageIDs", "access.Key.Scopes",
			"access.GeneratedKey.DisplayPrefix", "access.GeneratedKey.DisplaySuffix",
			"access.OneTimeToken.Purpose", "access.OneTimeToken.Role",
			// A session ID names a session; using one still needs its token.
			"access.Principal.SessionID", "access.Principal.SessionKind", "access.Principal.Method", "access.Principal.Scopes",
			"access.Principal.KeyLabel",
			"access.OIDCIdentity.Issuer", "access.OIDCIdentity.Subject",
			"oidc.Config.IssuerURL", "oidc.Config.ClientID", "oidc.Config.RedirectURL", "oidc.Config.Scopes",
			// The discovered public endpoints, and go-oidc's verifier: the
			// issuer, client ID, algorithms and the public keys of jwks_uri.
			"oidc.Provider.endpoint", "oidc.Provider.verifier",
			"account.Rotation.ID", "account.Recovery.Username", "account.OIDCOutcome.Redirect",
			"account.PendingLink.Email", "account.PendingLink.UsernameHint", "account.MethodLock.Method",
			"account.Client.Host", "account.Client.UserAgent",
			"account.Credentials.Username", "account.SetupPassword.Username", "account.SetupPasskey.Username",
			"account.AcceptInvite.Username", "account.NewUser.Username", "account.NewUser.Role",
			"account.ListedToken.IssuerLineage",
			// The app's store, policy and Argon2 hasher behind their interfaces,
			// and the configured scope names.
			"account.Service.store", "account.Service.policy", "account.Service.hasher",
			"account.Service.adminScope", "account.Service.usersScope", "account.Service.keysScope",
			// A ceremony ID names a pending entry; finishing it still needs
			// the authenticator's signature.
			"account.pendingEntry.id", "account.pendingCache.byID",
			// The SHA-256 of the username, the limiter's account key.
			"ratelimit.Account.digest",
			"accesshttp.TokenView.Purpose", "accesshttp.TokenView.Role", "accesshttp.TokenView.IssuerLineage",
		},
	}
}

// inventory builds every row of the printing inventory from its producer
// where one exists, holding known secrets.
func inventory(t *testing.T) []inventoryRow {
	t.Helper()
	sealer, err := access.NewSealer([]byte(printingSealerKey))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := sealer.Seal("printing", []byte("payload"), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	e := newEnv(t, envOptions{edit: func(c *account.Config) { c.FailureKey = []byte(printingFailureKey) }})
	setupToken, err := e.svc.IssueSetupToken(t.Context(), account.OutOfBand("test"), 0)
	if err != nil {
		t.Fatalf("IssueSetupToken: %v", err)
	}
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{URL: testIssuer, ClientSecret: printingClientSecret})
	ocfg := oidc.Config{
		IssuerURL: idp.Issuer(), ClientID: idp.ClientID(), ClientSecret: access.NewSecret(printingClientSecret),
		RedirectURL: testCallback, HTTPClient: idp.Client(),
	}
	provider, err := oidc.NewProvider(t.Context(), ocfg)
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}
	e.provider.Store(provider)
	e.signInFlow(t, newBrowser(t), idp, "")

	e.createUser(t, "root", access.RoleAdmin)
	e.createUser(t, "alice", access.RoleUser)
	alice := e.user(t, "alice")
	if _, err := e.svc.PasswordLogin(t.Context(), account.Client{}, account.Credentials{Username: "alice", Password: access.NewSecret(printingPassword)}); err == nil {
		t.Fatal("PasswordLogin with a wrong password succeeded")
	}
	signed, err := e.svc.PasswordLogin(t.Context(), account.Client{}, account.Credentials{Username: "alice", Password: access.NewSecret(testPassword)})
	if err != nil {
		t.Fatalf("PasswordLogin: %v", err)
	}
	cookie := e.cookie(signed.Token)
	principal := e.principal(t, cookie)
	issued, err := e.svc.StepUpPassword(t.Context(), account.Client{Device: signed.DeviceCookie}, principal, access.NewSecret(testPassword))
	if err != nil {
		t.Fatalf("StepUpPassword: %v", err)
	}
	created := e.mintKey(t, "alice", account.NewKey{Label: "ci"})
	keyPrincipal := e.keyPrincipal(t, created.Plaintext)
	recoveryLink, err := e.svc.IssueRecovery(t.Context(), account.OutOfBand("test"), alice.ID, 0)
	if err != nil {
		t.Fatalf("IssueRecovery: %v", err)
	}
	recovery, err := e.svc.StartRecovery(t.Context(), account.Client{}, recoveryLink.Plaintext)
	if err != nil {
		t.Fatalf("StartRecovery: %v", err)
	}
	invite, err := e.svc.CreateInvite(t.Context(), e.principal(t, e.sessionCookie(t, "root")), access.RoleUser, 0)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	listed, err := e.svc.Tokens(t.Context(), e.principal(t, e.sessionCookie(t, "root")))
	if err != nil || len(listed) == 0 {
		t.Fatalf("Tokens = %d, %v, want the live invite", len(listed), err)
	}
	view := tokenView(&listed[0])

	generated, err := access.GenerateAPIKey("ak_")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	sessionPlain, sessionHash := access.GenerateSessionToken()
	opaquePlain, opaqueHash := access.GenerateOpaqueToken()
	otPlain, ot := access.NewOneTimeToken(access.PurposeInvite, 0, time.Hour, time.Now())
	byToken := access.SessionHash(printingToken)
	byKey := access.APIKeyHash(printingToken)
	principalHash := principal.SessionTokenHash()
	hashed, err := e.hasher.Hash(t.Context(), printingPassword)
	if err != nil {
		t.Fatalf("Hasher.Hash: %v", err)
	}
	nextPlain, nextHash := access.GenerateSessionToken()
	rotation := account.Rotation{ID: signed.Session.ID, ExpectHash: signed.Session.TokenHash, Next: access.Session{ID: "next", TokenHash: nextHash}, UserID: alice.ID}
	outcome := account.OIDCOutcome{Issued: issued, SignedIn: signed, Kind: account.OutcomeSignedIn}
	client := account.Client{Host: "app.example.com", UserAgent: "test", Device: signed.DeviceCookie}
	origin, err := webauthn.ParseOrigin(testOrigin)
	if err != nil {
		t.Fatalf("ParseOrigin: %v", err)
	}
	pw, tok := access.NewSecret(printingPassword), access.NewSecret(printingToken)
	attempt := ratelimit.Attempt{IP: ratelimit.IPKey(netip.MustParseAddr("192.0.2.1")), Device: signed.DeviceCookie, Account: ratelimit.AccountKey("alice")}
	res, err := e.limiter.Attempt(ratelimit.Attempt{IP: ratelimit.IPKey(netip.MustParseAddr("192.0.2.2")), Account: ratelimit.AccountKey("carol")})
	if err != nil {
		t.Fatalf("limiter.Attempt: %v", err)
	}
	succeeded := res.Succeed()
	deviceCookie := e.limiter.DeviceCookie(ratelimit.AccountKey("carol"), access.Secret{})

	return []inventoryRow{
		row("access.User", alice, alice.PasswordHash.Reveal(), testPassword),
		row("access.Session", &signed.Session, signed.Session.TokenHash.Reveal(), signed.Token.Reveal()),
		row("access.Key", &created.Key, created.Key.KeyHash.Reveal(), created.Plaintext.Reveal()),
		row("access.OneTimeToken", &ot, ot.Hash.Reveal(), otPlain.Reveal()),
		row("access.Principal session", &principal, principalHash.Reveal(), cookie.Value),
		row("access.Principal key", &keyPrincipal, created.Key.KeyHash.Reveal(), created.Plaintext.Reveal()),
		row("access.GeneratedKey", &generated, generated.Plaintext.Reveal(), generated.Hash.Reveal()),
		row("SessionHash", &byToken, byToken.Reveal(), printingToken),
		row("GenerateSessionToken hash", &sessionHash, sessionHash.Reveal(), sessionPlain.Reveal()),
		row("GenerateSessionToken plaintext", &sessionPlain, sessionPlain.Reveal()),
		row("APIKeyHash", &byKey, byKey.Reveal(), printingToken),
		row("GenerateOpaqueToken hash", &opaqueHash, opaqueHash.Reveal(), opaquePlain.Reveal()),
		row("GenerateOpaqueToken plaintext", &opaquePlain, opaquePlain.Reveal()),
		row("Principal.SessionTokenHash", &principalHash, principalHash.Reveal(), cookie.Value),
		row("Hasher.Hash", &hashed, hashed.Reveal(), printingPassword),
		row("access.Sealer", sealer, printingSealerKey),
		row("oidc.Provider", provider, printingClientSecret),
		row("oidc.Config", &ocfg, printingClientSecret),
		row("account.Rotation", &rotation, signed.Session.TokenHash.Reveal(), nextHash.Reveal(), nextPlain.Reveal()),
		row("account.SignedIn", &signed, signed.Token.Reveal(), signed.DeviceCookie.Reveal(), signed.Session.TokenHash.Reveal()),
		row("account.Issued", &issued, issued.Token.Reveal(), issued.DeviceCookie.Reveal(), issued.Session.TokenHash.Reveal()),
		row("account.Recovery", &recovery, recovery.Issued.Token.Reveal(), recovery.Issued.Session.TokenHash.Reveal(), recoveryLink.Plaintext.Reveal()),
		row("account.OIDCOutcome", &outcome, issued.Token.Reveal(), signed.Token.Reveal(), signed.DeviceCookie.Reveal()),
		row("account.CreatedKey", &created, created.Plaintext.Reveal(), created.Key.KeyHash.Reveal()),
		row("account.Client", &client, signed.DeviceCookie.Reveal()),
		row("account.Credentials", &account.Credentials{Password: pw, Username: "alice"}, printingPassword),
		row("account.SetupPassword", &account.SetupPassword{Token: tok, Password: pw, Username: "alice"}, printingPassword, printingToken),
		row("account.SetupPasskey", &account.SetupPasskey{Token: tok, Username: "alice", Origin: origin}, printingToken),
		row("account.AcceptInvite", &account.AcceptInvite{Token: tok, Password: pw, Username: "alice"}, printingPassword, printingToken),
		row("account.NewUser", &account.NewUser{Password: pw, Username: "alice"}, printingPassword),
		row("account.Service", e.svc, printingFailureKey),
		row("IssueSetupToken", &setupToken, setupToken.Reveal()),
		row("IssueRecovery", &recoveryLink, recoveryLink.Plaintext.Reveal()),
		row("CreateInvite", &invite, invite.Plaintext.Reveal()),
		row("NewOneTimeToken plaintext", &otPlain, otPlain.Reveal()),
		row("ratelimit.Attempt", &attempt, signed.DeviceCookie.Reveal()),
		row("Reservation.Succeed", &succeeded, succeeded.Reveal()),
		row("Limiter.DeviceCookie", &deviceCookie, deviceCookie.Reveal()),
		row("account.ListedToken", &listed[0], listed[0].Token.Hash.Reveal(), invite.Plaintext.Reveal()),
		row("TokenView", &view, listed[0].Token.Hash.Reveal(), invite.Plaintext.Reveal()),
	}
}

func TestPrintingInventory(t *testing.T) {
	rows := inventory(t)
	t.Run("routes", func(t *testing.T) {
		for _, r := range rows {
			for _, s := range r.secrets {
				if s == "" {
					t.Fatalf("%s: an empty secret; the row's producer gave no value", r.name)
				}
			}
			value := reflect.ValueOf(r.ptr).Elem().Interface()
			for form, v := range map[string]any{"pointer": r.ptr, "value": value} {
				for route, got := range renderings(v) {
					for _, s := range r.secrets {
						if leaked(got, s) {
							t.Errorf("%s by %s through %s printed a secret: %s", r.name, form, route, got)
						}
					}
				}
			}
		}
	})
	t.Run("type_graph", func(t *testing.T) {
		roots := make([]reflect.Type, 0, len(rows))
		for _, r := range rows {
			roots = append(roots, reflect.TypeOf(r.ptr))
		}
		for _, line := range printcheck.Unmasked(inventoryAllow(t), roots...) {
			t.Error(line)
		}
	})
	t.Run("requests", checkRequestLogs)
}

// failingActivity is a store whose activity and key-use writes fail, so
// the verifiers log their failed-write WARN.
type failingActivity struct{ account.Store }

var errActivityWrite = errors.New("activity write failed")

func (failingActivity) UpdateSessionActivity(context.Context, access.Hash, access.SessionActivity) error {
	return errActivityWrite
}

func (failingActivity) TouchAPIKey(context.Context, int64, access.Hash, time.Time) error {
	return errActivityWrite
}

// checkRequestLogs sends requests carrying a known password, session
// token, API key and OIDC client secret, refused and accepted, through
// paths that log at DEBUG, WARN and ERROR with every logger of the stack
// recording, and requires that no record's message or attribute holds any
// of them.
func checkRequestLogs(t *testing.T) {
	t.Helper()
	logger, logs := capture.New()
	breachDown := &atomic.Bool{}
	e := newEnv(t, envOptions{
		authn:  func(_ *env, c *access.Config) { c.Logger = logger },
		limits: func(c *ratelimit.Config) { c.Logger = logger },
		edit:   func(c *account.Config) { c.Logger = logger },
		store:  func(m *accesstest.MemStore) account.Store { return failingActivity{m} },
		rules: func(r *account.Rules) {
			if breachDown.Load() {
				r.Breach = account.BreachFailOpen
			}
		},
	})
	e.createUser(t, "alice", access.RoleUser)
	unknownKey, err := access.GenerateAPIKey("ak_")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	cookie := e.storedSession(t, "alice", 0, 10*time.Minute)
	key := e.mintKey(t, "alice", account.NewKey{Label: "ci"})
	secrets := []string{
		testPassword, newPassword, printingPassword, printingToken, printingClientSecret,
		cookie.Value, access.SessionHash(cookie.Value).Reveal(),
		key.Plaintext.Reveal(), key.Key.KeyHash.Reveal(), unknownKey.Plaintext.Reveal(),
	}

	me := e.route(t, "authMe")
	do(me, request(me, "", cookie))
	do(me, request(me, "", &http.Cookie{Name: cookie.Name, Value: printingToken}))
	for _, k := range []access.Secret{key.Plaintext, unknownKey.Plaintext} {
		do(me, bearer(request(me, ""), k))
	}
	breachDown.Store(true)
	do(e.route(t, "authPasswordSet"), e.post(t, "authPasswordSet", passwordSetBody(t, testPassword, newPassword), cookie))
	breachDown.Store(false)
	// A step-up that succeeds rotates the session, so it runs after every
	// request the cookie authenticates.
	login, stepUp := e.route(t, "authLoginPassword"), e.route(t, "authStepUpPassword")
	for _, password := range []string{printingPassword, testPassword} {
		do(stepUp, request(stepUp, jsonBody(t, PasswordRequest{Password: password}), cookie))
		do(login, request(login, jsonBody(t, LoginRequest{Username: "alice", Password: password})))
	}
	for _, clientSecret := range []string{printingClientSecret, "printing-inventory-other-client-secret"} {
		idp := accesstest.NewIdP(t, accesstest.IdPOptions{URL: testIssuer, ClientSecret: clientSecret})
		p, err := oidc.NewProvider(t.Context(), oidc.Config{
			IssuerURL: idp.Issuer(), ClientID: idp.ClientID(), ClientSecret: access.NewSecret(printingClientSecret),
			RedirectURL: testCallback, HTTPClient: idp.Client(),
		})
		if err != nil {
			t.Fatalf("oidc.NewProvider: %v", err)
		}
		e.provider.Store(p)
		e.signInFlow(t, newBrowser(t), idp, "")
	}

	levels := map[slog.Level]int{}
	for _, rec := range []*capture.Recorder{logs, e.logs} {
		for _, r := range rec.Records("") {
			levels[r.Level]++
			var text, js bytes.Buffer
			for _, h := range []slog.Handler{slog.NewTextHandler(&text, nil), slog.NewJSONHandler(&js, nil)} {
				if err := h.Handle(context.Background(), r); err != nil {
					t.Fatalf("Handle: %v", err)
				}
			}
			for _, s := range secrets {
				if leaked(text.String(), s) || leaked(js.String(), s) {
					t.Errorf("a log record holds a request secret: %s", text.String())
				}
			}
		}
	}
	if levels[slog.LevelWarn] == 0 || levels[slog.LevelError] == 0 {
		t.Errorf("records by level %v, want a WARN and an ERROR among them", levels)
	}
}
