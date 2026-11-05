package access_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cplieger/access"
	"github.com/cplieger/access/accesstest"
)

func ExampleHasher() {
	hasher, err := access.NewHasher(access.HasherConfig{})
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	hash, err := hasher.Hash(ctx, "correct horse battery staple")
	if err != nil {
		panic(err) // access.ErrHashBusy: the budget stayed full for the whole wait
	}
	ok, needsRehash, err := hasher.Verify(ctx, "correct horse battery staple", hash)
	fmt.Println(ok, needsRehash, err)
	// For an unknown username, verify against the zero Hash: it costs the same.
	ok, _, err = hasher.Verify(ctx, "correct horse battery staple", access.Hash{})
	fmt.Println(ok, err)
	// Output:
	// true false <nil>
	// false <nil>
}

func ExampleHashBudget() {
	// One budget per process, shared by every Hasher, bounds their memory together.
	budget, err := access.NewHashBudget(76 << 20)
	if err != nil {
		panic(err)
	}
	passwords, err := access.NewHasher(access.HasherConfig{Budget: budget})
	if err != nil {
		panic(err)
	}
	_ = passwords
	fmt.Println(budget.Capacity() / access.HashCost(access.DefaultArgon2Params()))
	// Output: 4
}

func ExampleValidatePasswordLength() {
	var pe *access.PasswordError
	if err := access.ValidatePasswordLength("short"); errors.As(err, &pe) {
		fmt.Println(pe.Reason, pe.Min)
	}
	fmt.Println(access.ValidatePasswordLength("correct horse battery staple"))
	// Output:
	// too_short 15
	// <nil>
}

func ExampleValidatePasswordContext() {
	pctx := access.PasswordContext{Username: "alice", ForbiddenWords: []string{"subflux"}}
	fmt.Println(access.ValidatePasswordContext("Alice2024!", pctx))
	fmt.Println(access.ValidatePasswordContext("my subflux library passphrase", pctx))
	// Output:
	// access: password refused: contains_username
	// <nil>
}

func ExampleGenerateSessionToken() {
	plaintext, hash := access.GenerateSessionToken()
	cookieValue := plaintext.Reveal() // reveal only into the cookie
	fmt.Println(plaintext, len(cookieValue) == 64, access.SessionHash(cookieValue).Equal(hash))
	// Output: [redacted] true true
}

func ExampleGenerateAPIKey() {
	key, err := access.GenerateAPIKey("ak_")
	if err != nil {
		panic(err)
	}
	shown := key.Plaintext.Reveal() // reveal only into the one-time display
	fmt.Println(key.Plaintext, shown[:3], len(key.Hash.Reveal()) == 64, key.DisplayPrefix == shown[:8], len(key.DisplaySuffix) == 4)
	// Output: [redacted] ak_ true true true
}

func ExampleAuthenticator_RequireAuth() {
	store := accesstest.NewMemStore()
	if err := store.CreateUser(context.Background(), &access.User{
		Username: "alice",
		Role:     access.RoleAdmin,
		Enabled:  true,
	}); err != nil {
		panic(err)
	}

	authn, err := access.New(store, access.Config{
		IdleTimeout: time.Hour,
		AbsTimeout:  24 * time.Hour,
	})
	if err != nil {
		panic(err)
	}
	_ = authn
	fmt.Println("authenticator configured")
	// Output: authenticator configured
}

func ExampleVerifyAPIKey() {
	ctx := context.Background()
	store := accesstest.NewMemStore()
	bot := &access.User{
		Username: "bot",
		Role:     access.RoleUser,
		Enabled:  true,
	}
	if err := store.CreateUser(ctx, bot); err != nil {
		panic(err)
	}

	generated, err := access.GenerateAPIKey("ak_")
	if err != nil {
		panic(err)
	}
	if err := store.CreateAPIKey(ctx, &access.Key{
		UserID:    bot.ID,
		KeyHash:   generated.Hash,
		KeyPrefix: generated.DisplayPrefix,
		KeySuffix: generated.DisplaySuffix,
		Label:     "ci",
	}); err != nil {
		panic(err)
	}

	key, err := access.VerifyAPIKey(ctx, store, generated.Plaintext.Reveal())
	fmt.Println(key != nil, err == nil)
	// Output: true true
}

func ExampleHasRole() {
	admin := &access.User{Role: access.RoleAdmin}
	user := &access.User{Role: access.RoleUser}
	fmt.Println(access.HasRole(admin, access.RoleUser))
	fmt.Println(access.HasRole(user, access.RoleAdmin))
	// Output:
	// true
	// false
}

func ExampleValidateRedirectURI() {
	fmt.Println(access.ValidateRedirectURI("/dashboard"))
	fmt.Println(access.ValidateRedirectURI("https://evil.com"))
	// Output:
	// /dashboard
	// /
}
