package totp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// rfcSecret is the shared secret of RFC 4226 Appendix D and RFC 6238 Appendix B.
var rfcSecret = []byte("12345678901234567890")

// refHOTP is RFC 4226 §5.3's algorithm written from its text, so the tests
// can state preconditions without trusting the package under test.
func refHOTP(secret []byte, counter int64) string {
	m := hmac.New(sha1.New, secret)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(counter))
	m.Write(c[:])
	sum := m.Sum(nil)
	off := sum[19] & 0xf
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:])&0x7fffffff)%1000000)
}

// RFC 4226 Appendix D, Table 1 and Table 2: HMAC-SHA-1(secret, count) and
// its dynamic truncation, for counts 0 to 9.
func TestTruncateAppendixD(t *testing.T) {
	rows := []struct {
		hmac  string
		trunc uint32
	}{
		{"cc93cf18508d94934c64b65d8ba7667fb7cde4b0", 0x4c93cf18},
		{"75a48a19d4cbe100644e8ac1397eea747a2d33ab", 0x41397eea},
		{"0bacb7fa082fef30782211938bc1c5e70416ff44", 0x082fef30},
		{"66c28227d03a2d5529262ff016a1e6ef76557ece", 0x66ef7655},
		{"a904c900a64b35909874b33e61c5938a8e15ed1c", 0x61c5938a},
		{"a37e783d7b7233c083d4f62926c7a25f238d0316", 0x33c083d4},
		{"bc9cd28561042c83f219324d3c607256c03272ae", 0x7256c032},
		{"a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", 0x04e5b397},
		{"1b3c89f65e6c9e883012052823443f048b4332db", 0x2823443f},
		{"1637409809a679dc698207310c8c7fc07290d9e5", 0x2679dc69},
	}
	for i, r := range rows {
		sum, err := hex.DecodeString(r.hmac)
		if err != nil {
			t.Fatal(err)
		}
		if got := truncate(sum); got != r.trunc {
			t.Errorf("count %d: truncate = %#08x, want %#08x", i, got, r.trunc)
		}
	}
}

// RFC 4226 §5.4's worked example: offset 0xa, DBC1 0x50ef7f19, HOTP 872921.
func TestTruncateWorkedExample(t *testing.T) {
	sum, err := hex.DecodeString("1f8698690e02ca16618550ef7f19da8e945b555a")
	if err != nil {
		t.Fatal(err)
	}
	got := truncate(sum)
	if got != 0x50ef7f19 {
		t.Fatalf("truncate = %#08x, want 0x50ef7f19", got)
	}
	if got%1000000 != 872921 {
		t.Errorf("DBC2 mod 10^6 = %d, want 872921", got%1000000)
	}
}

// RFC 4226 Appendix D, Table 2: the six-digit HOTP values for counts 0 to 9.
func TestCodeAppendixD(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got := Code(rfcSecret, int64(i)); got != w {
			t.Errorf("Code(count %d) = %q, want %q", i, got, w)
		}
	}
}

// RFC 6238 Appendix B, the SHA1 rows: T at T0 = 0 and X = 30 (§4.2), and the
// TOTP value, whose low six digits are the six-digit code (RFC 4226 §5.3's
// mod 10^Digit). 20000000000 is beyond 2^31 seconds.
func TestAppendixB(t *testing.T) {
	rows := []struct {
		unix int64
		step int64
		totp string
	}{
		{59, 0x1, "94287082"},
		{1111111109, 0x23523EC, "07081804"},
		{1111111111, 0x23523ED, "14050471"},
		{1234567890, 0x273EF07, "89005924"},
		{2000000000, 0x3F940AA, "69279037"},
		{20000000000, 0x27BC86AA, "65353130"},
	}
	for _, r := range rows {
		t.Run(fmt.Sprint(r.unix), func(t *testing.T) {
			s := Step(time.Unix(r.unix, 0))
			if s != r.step {
				t.Errorf("Step = %#x, want %#x", s, r.step)
			}
			if got := Code(rfcSecret, r.step); got != r.totp[2:] {
				t.Errorf("Code = %q, want %q", got, r.totp[2:])
			}
		})
	}
}

// RFC 6238 §4.2: T = floor((Current Unix time - T0) / X).
func TestStepFloor(t *testing.T) {
	cases := []struct {
		unix int64
		step int64
	}{{0, 0}, {29, 0}, {30, 1}, {59, 1}, {60, 2}, {-1, -1}, {-30, -1}, {-31, -2}}
	for _, c := range cases {
		if got := Step(time.Unix(c.unix, 999_999_999)); got != c.step {
			t.Errorf("Step(%d.999999999) = %d, want %d", c.unix, got, c.step)
		}
	}
}

func TestConstants(t *testing.T) {
	// RFC 4226 §5.3 and the Key Uri Format default.
	if Digits != 6 {
		t.Errorf("Digits = %d", Digits)
	}
	// RFC 6238 §5.2's recommended time-step size.
	if Period != 30*time.Second {
		t.Errorf("Period = %v", Period)
	}
	// RFC 6238 §5.2 and §6: at most one step backward (and forward) of drift.
	if Skew != 1 {
		t.Errorf("Skew = %d", Skew)
	}
}

// RFC 4226 §4 R6 (160 bits recommended) and NIST SP 800-63B-4 §3.1.4 (at
// least 112 bits); R7 asks for a random secret.
func TestNewSecret(t *testing.T) {
	a, b := NewSecret(), NewSecret()
	if len(a) != 20 || SecretBytes != 20 {
		t.Fatalf("len(NewSecret()) = %d, SecretBytes = %d, want 20", len(a), SecretBytes)
	}
	if bytes.Equal(a, b) {
		t.Errorf("two secrets are equal: %x", a)
	}
}

// windowNow is RFC 6238 Appendix B's 1111111111, at step 0x23523ED.
var windowNow = time.Unix(1111111111, 0)

// RFC 6238 §5.2 and §6: the verifier accepts the current step and at most one
// step of drift either side, and each code once.
func TestMatchWindow(t *testing.T) {
	now := Step(windowNow)
	seen := map[string]int64{}
	for d := int64(-2); d <= 2; d++ {
		c := refHOTP(rfcSecret, now+d)
		if prev, ok := seen[c]; ok {
			t.Fatalf("precondition: steps %d and %d share code %s", prev, now+d, c)
		}
		seen[c] = now + d
	}
	for d := int64(-1); d <= 1; d++ {
		t.Run(fmt.Sprintf("accept%+d", d), func(t *testing.T) {
			step, r := Match(rfcSecret, refHOTP(rfcSecret, now+d), windowNow, 0)
			if r != Matched || step != now+d {
				t.Errorf("Match = %d, %v, want %d, Matched", step, r, now+d)
			}
		})
	}
	for _, d := range []int64{-2, 2} {
		t.Run(fmt.Sprintf("refuse%+d", d), func(t *testing.T) {
			if _, r := Match(rfcSecret, refHOTP(rfcSecret, now+d), windowNow, 0); r != NoMatch {
				t.Errorf("Match = %v, want NoMatch", r)
			}
		})
	}
	t.Run("wrong", func(t *testing.T) {
		wrong := "000000"
		for seen[wrong] != 0 {
			wrong = fmt.Sprintf("%06d", len(wrong)+1)
		}
		if _, r := Match(rfcSecret, wrong, windowNow, 0); r != NoMatch {
			t.Errorf("Match = %v, want NoMatch", r)
		}
	})
}

// RFC 6238 §5.2: "the verifier MUST NOT accept the second attempt of the OTP
// after the successful validation has been issued for the first OTP"; logto
// GHSA-6wj7-c66m-6c82 accepted a used code again within its window.
func TestMatchReused(t *testing.T) {
	now := Step(windowNow)
	cases := []struct {
		name  string
		code  int64
		after int64
		want  Result
	}{
		{"current at after", now, now, Reused},
		{"previous below after", now - 1, now, Reused},
		{"next at after", now + 1, now + 1, Reused},
		{"previous above after", now - 1, now - 2, Matched},
		{"current above previous", now, now - 1, Matched},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			step, r := Match(rfcSecret, refHOTP(rfcSecret, c.code), windowNow, c.after)
			if r != c.want {
				t.Fatalf("Match = %v, want %v", r, c.want)
			}
			if r == Matched && step != c.code {
				t.Errorf("step = %d, want %d", step, c.code)
			}
		})
	}
}

// RFC 6238 §5.2's single acceptance when two steps in the window share a
// code: at step 57017783 the RFC secret's codes at -1 and +1 are both 882938
// (found by search). The first submission takes the higher step, so its
// replay finds no fresher step and is refused; ROTP keeps the last match too.
func TestMatchSharedCode(t *testing.T) {
	const s = 57017783
	now := time.Unix(s*30+15, 0)
	code := refHOTP(rfcSecret, s-1)
	if code != refHOTP(rfcSecret, s+1) || code == refHOTP(rfcSecret, s) {
		t.Fatalf("precondition: codes at s-1, s, s+1 = %s, %s, %s", code, refHOTP(rfcSecret, s), refHOTP(rfcSecret, s+1))
	}
	step, r := Match(rfcSecret, code, now, 0)
	if r != Matched || step != s+1 {
		t.Fatalf("first Match = %d, %v, want %d, Matched", step, r, s+1)
	}
	if _, r := Match(rfcSecret, code, now, step); r != Reused {
		t.Errorf("replay Match = %v, want Reused", r)
	}
	t.Run("used lower step does not refuse a fresh one", func(t *testing.T) {
		step, r := Match(rfcSecret, code, now, s-1)
		if r != Matched || step != s+1 {
			t.Errorf("Match after s-1 = %d, %v, want %d, Matched", step, r, s+1)
		}
	})
}

// RFC 4226 §5.3: the value is Digit decimal digits. Anything else is
// malformed and never reaches a count.
func TestMatchMalformed(t *testing.T) {
	for _, raw := range []string{
		"", " ", "12345", "1234567", "12345a", "123-456", "123\t456", "123\n456",
		"123\u00a0456", "١٢٣٤٥٦", "１２３４５６", "+12345", "-12345", "0x1234",
	} {
		t.Run(fmt.Sprintf("%q", raw), func(t *testing.T) {
			if _, r := Match(rfcSecret, raw, windowNow, 0); r != Malformed {
				t.Errorf("Match(%q) = %v, want Malformed", raw, r)
			}
		})
	}
}

// OpenBao GHSA-rxp7-9q75-vj3p: whitespace let one code be counted and
// replayed as a different value. Spaces are removed before both checks.
func TestMatchSpaces(t *testing.T) {
	now := Step(windowNow)
	code := refHOTP(rfcSecret, now)
	spaced := code[:3] + " " + code[3:]
	step, r := Match(rfcSecret, spaced, windowNow, 0)
	if r != Matched || step != now {
		t.Fatalf("Match(%q) = %d, %v, want %d, Matched", spaced, step, r, now)
	}
	for _, replay := range []string{code, spaced, " " + code + " ", "  " + code[:2] + " " + code[2:4] + " " + code[4:]} {
		if _, r := Match(rfcSecret, replay, windowNow, step); r != Reused {
			t.Errorf("replay Match(%q) = %v, want Reused", replay, r)
		}
	}
}

// RFC 4648 §10's base32 vectors, unpadded (the Key Uri Format omits the
// padding), and the Key Uri Format's own example key.
func TestText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"f", "MY"},
		{"fo", "MZXQ"},
		{"foo", "MZXW6"},
		{"foob", "MZXW6YQ"},
		{"fooba", "MZXW6YTB"},
		{"foobar", "MZXW6YTBOI"},
		{"Hello!\xDE\xAD\xBE\xEF", "JBSWY3DPEHPK3PXP"},
	}
	for _, c := range cases {
		if got := Text([]byte(c.in)); got != c.want {
			t.Errorf("Text(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
