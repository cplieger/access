package access

import (
	"testing"
	"time"
)

func TestGenerateOpaqueToken(t *testing.T) {
	t.Parallel()
	plain, hash := GenerateOpaqueToken()
	if len(plain.Reveal()) != 64 { // 32 bytes hex-encoded
		t.Errorf("GenerateOpaqueToken() plaintext length = %d, want 64", len(plain.Reveal()))
	}
	if got := HexSHA256(plain.Reveal()); got != hash.Reveal() {
		t.Errorf("HexSHA256(plaintext) = %q, want the returned hash %q", got, hash.Reveal())
	}
}

func TestVerifyOpaqueToken_Valid(t *testing.T) {
	t.Parallel()
	plain, hash := GenerateOpaqueToken()
	expires := time.Now().Add(time.Hour)
	if err := VerifyOpaqueToken(plain.Reveal(), hash, expires); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestVerifyOpaqueToken_Expired(t *testing.T) {
	t.Parallel()
	plain, hash := GenerateOpaqueToken()
	expires := time.Now().Add(-time.Hour)
	if err := VerifyOpaqueToken(plain.Reveal(), hash, expires); err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerifyOpaqueToken_WrongToken(t *testing.T) {
	t.Parallel()
	_, hash := GenerateOpaqueToken()
	expires := time.Now().Add(time.Hour)
	if err := VerifyOpaqueToken("wrong", hash, expires); err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}
