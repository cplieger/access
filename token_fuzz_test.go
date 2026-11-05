package access

import (
	"testing"
	"time"
)

func FuzzVerifyOpaqueToken(f *testing.F) {
	f.Add("random-plaintext")
	f.Add("")
	f.Add("\x00\x01\x02\x03")
	f.Add("正確なトークン")

	f.Fuzz(func(t *testing.T, fuzzInput string) {
		plaintext, hash := GenerateOpaqueToken()

		if err := VerifyOpaqueToken(plaintext.Reveal(), hash, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}

		if fuzzInput == plaintext.Reveal() {
			return
		}
		if err := VerifyOpaqueToken(fuzzInput, hash, time.Now().Add(time.Hour)); err == nil {
			t.Fatal("fuzzed plaintext verified against hash")
		}
	})
}
