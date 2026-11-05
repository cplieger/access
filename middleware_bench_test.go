package access

import (
	"net/http"
	"testing"
	"time"
)

func BenchmarkAuthenticate(b *testing.B) {
	store := newFakeSessionStore()
	ctx := b.Context()

	user := &User{Username: "bench", Role: RoleUser, Enabled: true}
	if err := store.CreateUser(ctx, user); err != nil {
		b.Fatal(err)
	}

	token := "bench-session-token-value"
	hash := SessionHash(token)
	if err := store.CreateSession(ctx, &Session{
		UserID: user.ID, TokenHash: hash, AuthMethod: MethodPassword, CreatedAt: time.Now(), LastActivity: time.Now(),
	}); err != nil {
		b.Fatal(err)
	}

	generated, err := GenerateAPIKey("ak_")
	if err != nil {
		b.Fatal(err)
	}
	apiKeyRaw := generated.Plaintext.Reveal()
	if err := store.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: generated.Hash, Label: "bench-key",
	}); err != nil {
		b.Fatal(err)
	}

	auth := mustAuthenticator(b, store, Config{IdleTimeout: 24 * time.Hour, AbsTimeout: 7 * 24 * time.Hour})

	b.Run("session_cookie", func(b *testing.B) {
		req, _ := http.NewRequest(http.MethodGet, "/api/test", nil)
		req.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: token})
		b.ReportAllocs()
		for b.Loop() {
			_, _ = auth.Authenticate(req)
		}
	})

	b.Run("api_key_header", func(b *testing.B) {
		req, _ := http.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Authorization", "Bearer "+apiKeyRaw)
		b.ReportAllocs()
		for b.Loop() {
			_, _ = auth.Authenticate(req)
		}
	})

	b.Run("no_credentials", func(b *testing.B) {
		req, _ := http.NewRequest(http.MethodGet, "/api/test", nil)
		b.ReportAllocs()
		for b.Loop() {
			_, _ = auth.Authenticate(req)
		}
	})
}
