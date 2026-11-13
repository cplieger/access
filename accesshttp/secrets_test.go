package accesshttp_test

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesshttp"
	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/account"
	"github.com/cplieger/access/ratelimit"
)

const secretsPassword = "correct-horse-battery-staple-9" // gitleaks:allow (test fixture password)

// recordingAccount records, per operation, the Reveal of every Secret a
// handler passes, and answers success; the guard still runs on the real
// Service it embeds.
type recordingAccount struct {
	accesshttp.AccountAPI
	got map[string][]string
	mu  sync.Mutex
}

func (a *recordingAccount) record(op string, secrets ...access.Secret) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range secrets {
		a.got[op] = append(a.got[op], s.Reveal())
	}
}

var signedIn = account.SignedIn{User: &access.User{ID: 1, Username: "x"}}

func (a *recordingAccount) SetupWithPassword(_ context.Context, _ account.Client, in account.SetupPassword) (account.SignedIn, error) {
	a.record("authSetupPassword", in.Token, in.Password)
	return signedIn, nil
}

func (a *recordingAccount) SetupPasskeyBegin(_ context.Context, _ account.Client, in account.SetupPasskey) (account.PendingCeremony, error) {
	a.record("authSetupPasskeyBegin", in.Token)
	return account.PendingCeremony{ID: "c"}, nil
}

func (a *recordingAccount) PasswordLogin(_ context.Context, _ account.Client, in account.Credentials) (account.SignedIn, error) {
	a.record("authLoginPassword", in.Password)
	return signedIn, nil
}

func (a *recordingAccount) StartRecovery(_ context.Context, _ account.Client, token access.Secret) (account.Recovery, error) {
	a.record("authRecoveryStart", token)
	return account.Recovery{}, nil
}

func (a *recordingAccount) RecoverWithPassword(_ context.Context, _ access.Principal, password access.Secret, _ account.RecoverOptions) error {
	a.record("authRecoveryPassword", password)
	return nil
}

func (a *recordingAccount) AcceptInvitePassword(_ context.Context, _ account.Client, in account.AcceptInvite) (account.SignedIn, error) {
	a.record("authInviteAcceptPassword", in.Token, in.Password)
	return signedIn, nil
}

func (a *recordingAccount) StepUpPassword(_ context.Context, _ account.Client, _ access.Principal, password access.Secret) (account.Issued, error) {
	a.record("authStepUpPassword", password)
	return account.Issued{}, nil
}

func (a *recordingAccount) SetPassword(_ context.Context, _ account.Client, _ access.Principal, current, password access.Secret) (account.Issued, error) {
	a.record("authPasswordSet", current, password)
	return account.Issued{}, nil
}

func (a *recordingAccount) RemovePassword(_ context.Context, _ account.Client, _ access.Principal, current access.Secret) (account.Issued, error) {
	a.record("authPasswordRemove", current)
	return account.Issued{}, nil
}

func (a *recordingAccount) CreateUser(_ context.Context, _ account.Actor, in account.NewUser) (*access.User, error) {
	a.record("authAdminUserCreate", in.Password)
	return &access.User{ID: 2}, nil
}

func newService(t *testing.T) (*account.Service, *access.Authenticator) {
	t.Helper()
	mem := accesstest.NewMemStore()
	authn, err := access.New(mem, access.Config{})
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := access.NewHasher(access.HasherConfig{})
	if err != nil {
		t.Fatal(err)
	}
	lcfg := ratelimit.DefaultConfig()
	lcfg.Devices = access.NewEphemeralSealer()
	limiter, err := ratelimit.New(t.Context(), lcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = limiter.Shutdown(context.Background()) })
	svc, err := account.New(t.Context(), account.Config{
		Store: mem, Policy: account.RolePolicy{}, Authenticator: authn, Hasher: hasher, Limiter: limiter,
		Rules:      func() account.Rules { return account.Rules{} },
		FailureKey: []byte("accesshttp-test-failure-key-32by"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
	return svc, authn
}

// secretKeys are the request keys that carry a password or a token.
var secretKeys = []string{"password", "token", "current_password"}

// secretCase is one secret-bearing request route's valid body, the secrets
// account must receive from it, and the ones whose absence is a refusal.
type secretCase struct {
	cookie   *http.Cookie
	body     map[string]string
	want     []string
	required []string
}

// secretsFixture is a Handler over a recordingAccount, with a case per
// secret-bearing request route; errs is handed every refusal.
func secretsFixture(t *testing.T, errs func(accesshttp.Error)) (*accesshttp.Handler, *recordingAccount, map[string]secretCase) {
	t.Helper()
	svc, authn := newService(t)
	u, err := svc.CreateUser(t.Context(), account.OutOfBand("test"), account.NewUser{Username: "alice", Password: access.NewSecret(secretsPassword), Role: access.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	cookieReq := httptest.NewRequest(http.MethodPost, "https://app.example.com/", nil)
	cfg := authn.Cookie()
	in, err := svc.PasswordLogin(t.Context(), account.Client{}, account.Credentials{Username: "alice", Password: access.NewSecret(secretsPassword)})
	if err != nil {
		t.Fatal(err)
	}
	session := &http.Cookie{Name: cfg.CookieName(cookieReq), Value: in.Token.Reveal()}
	tok, err := svc.IssueRecovery(t.Context(), account.OutOfBand("test"), u.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := svc.StartRecovery(t.Context(), account.Client{}, tok.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	recovery := &http.Cookie{Name: cfg.CookieName(cookieReq), Value: rec.Issued.Token.Reveal()}

	fake := &recordingAccount{AccountAPI: svc, got: map[string][]string{}}
	h, err := accesshttp.NewWithAccount(accesshttp.Config{
		Errors: func(w http.ResponseWriter, _ *http.Request, e accesshttp.Error) {
			errs(e)
			w.WriteHeader(e.Status)
		},
		Prefix: "/api/auth",
	}, fake)
	if err != nil {
		t.Fatal(err)
	}
	// required is the design's: a setup token is optional (Rules decides
	// whether setup needs one), an absent current password is account's to
	// refuse, and an admin may create a user with no password.
	cases := map[string]secretCase{
		"authSetupPassword":        {body: map[string]string{"token": "tok-setup", "username": "bob", "password": "pw-setup"}, want: []string{"tok-setup", "pw-setup"}, required: []string{"password"}},
		"authSetupPasskeyBegin":    {body: map[string]string{"token": "tok-passkey", "username": "bob"}, want: []string{"tok-passkey"}},
		"authLoginPassword":        {body: map[string]string{"username": "bob", "password": "pw-login"}, want: []string{"pw-login"}, required: []string{"password"}},
		"authRecoveryStart":        {body: map[string]string{"token": "tok-recovery"}, want: []string{"tok-recovery"}, required: []string{"token"}},
		"authRecoveryPassword":     {cookie: recovery, body: map[string]string{"password": "pw-recovered"}, want: []string{"pw-recovered"}, required: []string{"password"}},
		"authInviteAcceptPassword": {body: map[string]string{"token": "tok-invite", "username": "carol", "password": "pw-invite"}, want: []string{"tok-invite", "pw-invite"}, required: []string{"token", "password"}},
		"authStepUpPassword":       {cookie: session, body: map[string]string{"password": "pw-stepup"}, want: []string{"pw-stepup"}, required: []string{"password"}},
		"authPasswordSet":          {cookie: session, body: map[string]string{"current_password": "pw-current", "password": "pw-next"}, want: []string{"pw-current", "pw-next"}, required: []string{"password"}},
		"authPasswordRemove":       {cookie: session, body: map[string]string{"current_password": "pw-removed"}, want: []string{"pw-removed"}},
		"authAdminUserCreate":      {cookie: session, body: map[string]string{"username": "dave", "password": "pw-created", "role": "user"}, want: []string{"pw-created"}},
	}
	for _, rt := range h.Routes() {
		if rt.Request == nil {
			continue
		}
		holds := false
		for f := range rt.Request.Fields() {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			holds = holds || slices.Contains(secretKeys, name)
		}
		if _, ok := cases[rt.Name]; holds != ok {
			t.Errorf("%s: holds a secret field %v, has a case %v", rt.Name, holds, ok)
		}
	}
	return h, fake, cases
}

// serveSecret sends body to rt as tc's caller would.
func serveSecret(t *testing.T, rt accesshttp.Route, tc secretCase, body map[string]string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(rt.Method, "https://app.example.com"+rt.Path, strings.NewReader(string(raw)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://app.example.com")
	if tc.cookie != nil {
		r.AddCookie(tc.cookie)
	}
	rt.Handler.ServeHTTP(httptest.NewRecorder(), r)
}

func (a *recordingAccount) received(op string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.got[op])
}

func TestHandlerWrapsSecrets(t *testing.T) {
	h, fake, cases := secretsFixture(t, func(e accesshttp.Error) { t.Errorf("refused: %+v", e) })
	for _, rt := range h.Routes() {
		tc, ok := cases[rt.Name]
		if !ok {
			continue
		}
		t.Run(rt.Name, func(t *testing.T) {
			serveSecret(t, rt, tc, tc.body)
			if got := fake.received(rt.Name); !slices.Equal(got, tc.want) {
				t.Errorf("account received %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRequiredSecretMissing(t *testing.T) {
	var mu sync.Mutex
	var refused []accesshttp.Error
	h, fake, cases := secretsFixture(t, func(e accesshttp.Error) {
		mu.Lock()
		defer mu.Unlock()
		refused = append(refused, e)
	})
	for _, rt := range h.Routes() {
		for _, field := range cases[rt.Name].required {
			tc := cases[rt.Name]
			for _, variant := range []string{"absent", "empty"} {
				t.Run(rt.Name+"_"+field+"_"+variant, func(t *testing.T) {
					body := maps.Clone(tc.body)
					delete(body, field)
					if variant == "empty" {
						body[field] = ""
					}
					mu.Lock()
					before := len(refused)
					mu.Unlock()
					serveSecret(t, rt, tc, body)
					mu.Lock()
					got := slices.Clone(refused[before:])
					mu.Unlock()
					if len(got) != 1 || got[0].Code != accesshttp.CodeBadRequest || got[0].Status != http.StatusBadRequest || got[0].Reason != field {
						t.Errorf("refusals %+v, want one 400 auth_bad_request naming %s", got, field)
					}
					if calls := fake.received(rt.Name); len(calls) != 0 {
						t.Errorf("account received %q, want no call", calls)
					}
				})
			}
		}
	}
}
