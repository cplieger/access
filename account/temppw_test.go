package account_test

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/access/account"
	"github.com/cplieger/access/internal/crockford"
)

// temporaryPasswordVectors is the file the web suite's recogniser tests read:
// issued values with the random bytes each came from.
var temporaryPasswordVectors = filepath.Join("..", "web", "testdata", "temporary-password", "vectors.json")

const regenerateVectors = "UPDATE_VECTORS=1 go test ./account/ -run '^TestTemporaryPasswordVectors$'"

type temporaryPasswordVector struct {
	Random string `json:"random"`
	Shown  string `json:"shown"`
}

type temporaryPasswordVectorFile struct {
	Source string                    `json:"source"`
	Issued []temporaryPasswordVector `json:"issued"`
}

// checkBytes reports whether b is ten bytes whose last two are the low 16
// bits of the CRC-32/ISO-HDLC of the first eight, big-endian.
func checkBytes(b []byte) bool {
	return len(b) == 10 && uint32(binary.BigEndian.Uint16(b[8:])) == crc32.ChecksumIEEE(b[:8])&0xFFFF
}

// TestTemporaryPasswordCRC is the CRC-32/ISO-HDLC catalogue check value
// (reveng.sourceforge.io CRC catalogue: check=0xcbf43926), which the
// temporary password's check is the low half of.
func TestTemporaryPasswordCRC(t *testing.T) {
	if got := crc32.ChecksumIEEE([]byte("123456789")); got != 0xCBF43926 {
		t.Fatalf("ChecksumIEEE(123456789) = %#x, want 0xcbf43926", got)
	}
}

// TestTemporaryPasswordFrom checks values computed outside Go (Python's
// zlib.crc32 and a by-hand Crockford encode, crockford.com/base32.html,
// most significant bit first): eight random bytes, then the CRC's low 16
// bits big-endian, as 16 symbols.
func TestTemporaryPasswordFrom(t *testing.T) {
	for _, c := range []struct{ random, want string }{
		{"0000000000000000", "0000000000001QV9"},
		{"0123456789abcdef", "04HMASW9NF6YZMDE"},
		{"ffffffffffffffff", "ZZZZZZZZZZZZZQRW"},
		{"3132333435363738", "64S36D1N6RVKHPNF"},
	} {
		t.Run(c.random, func(t *testing.T) {
			var r [8]byte
			if _, err := hex.Decode(r[:], []byte(c.random)); err != nil {
				t.Fatal(err)
			}
			if got := account.TemporaryPasswordFrom(r); got != c.want {
				t.Fatalf("TemporaryPasswordFrom(%s) = %q, want %q", c.random, got, c.want)
			}
		})
	}
}

// TestNewTemporaryPassword: NIST SP 800-63B-4 §3.1.1.1 (the CSP assigns
// the password randomly) and §3.1.1.2 (at least 15 characters), with 64
// random bits, §4.2.1.1's floor for a saved recovery code: ten bytes, the
// last two the CRC check, shown as XXXX-XXXX-XXXX-XXXX.
func TestNewTemporaryPassword(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		shown, canonical := account.NewTemporaryPassword()
		if !shownCode.MatchString(shown.Reveal()) {
			t.Fatalf("shown %q is not XXXX-XXXX-XXXX-XXXX", shown.Reveal())
		}
		if strings.ReplaceAll(shown.Reveal(), "-", "") != canonical {
			t.Fatalf("canonical %q is not shown %q undashed", canonical, shown.Reveal())
		}
		b, ok := crockford.Decode(canonical)
		if !ok || !checkBytes(b) {
			t.Fatalf("%q decodes to %x, %t: want ten bytes whose last two are the check", canonical, b, ok)
		}
		if seen[canonical] {
			t.Fatalf("%q drawn twice in 1000", canonical)
		}
		seen[canonical] = true
	}
}

// TestTemporaryPasswordForm checks the normalisation (the recovery code's
// table: ASCII "-" and space removed, ASCII letters folded, O to 0 and I,
// L to 1, every other rune kept) and the check the one hashable form passes.
func TestTemporaryPasswordForm(t *testing.T) {
	const canonical = "04HMASW9NF6YZMDE"
	accepted := map[string]string{
		"dashed":        "04HM-ASW9-NF6Y-ZMDE",
		"undashed":      canonical,
		"lower_case":    "04hm-asw9-nf6y-zmde",
		"spaced":        "04HM ASW9 NF6Y ZMDE",
		"o_for_zero":    "O4HM-ASW9-NF6Y-ZMDE",
		"lower_o":       "o4HMASW9NF6YZMDE",
		"between_runes": "0 4 H M - A S W 9 N F 6 Y Z M D E",
	}
	for name, in := range accepted {
		t.Run(name, func(t *testing.T) {
			got, ok := account.TemporaryPasswordForm(in)
			if !ok || got != canonical {
				t.Fatalf("TemporaryPasswordForm(%q) = %q, %t, want %q, true", in, got, ok, canonical)
			}
		})
	}
	t.Run("look_alikes_for_one", func(t *testing.T) {
		for _, one := range []string{"I", "i", "L", "l"} {
			in := strings.Replace("64S36D1N6RVKHPNF", "1", one, 1)
			if got, ok := account.TemporaryPasswordForm(in); !ok || got != "64S36D1N6RVKHPNF" {
				t.Errorf("TemporaryPasswordForm(%q) = %q, %t, want the canonical value", in, got, ok)
			}
		}
	})
	refused := map[string]string{
		// Go's and JavaScript's case mappings both take ı to I, which
		// Crockford's table does not accept.
		"dotless_i":       strings.Replace("64S36D1N6RVKHPNF", "1", "ı", 1),
		"fullwidth_digit": strings.Replace(canonical, "0", "０", 1),
		"long_s":          strings.Replace("64S36D1N6RVKHPNF", "S", "ſ", 1),
		"letter_u":        strings.Replace(canonical, "Z", "U", 1),
		"check_fails":     "04HMASW9NF6YZMDF",
		"fifteen":         canonical[:15],
		"seventeen":       canonical + "0",
		"tab":             "04HM\tASW9NF6YZMDE",
		"empty":           "",
	}
	for name, in := range refused {
		t.Run(name, func(t *testing.T) {
			if got, ok := account.TemporaryPasswordForm(in); ok {
				t.Fatalf("TemporaryPasswordForm(%q) = %q, true, want false", in, got)
			}
		})
	}
}

// TestTemporaryPasswordVectors writes (UPDATE_VECTORS=1) and checks the
// issued values the web recogniser's tests read, so both suites test one
// generator.
func TestTemporaryPasswordVectors(t *testing.T) {
	if os.Getenv("UPDATE_VECTORS") == "1" {
		f := temporaryPasswordVectorFile{Source: "written by " + regenerateVectors}
		for range 64 {
			shown, canonical := account.NewTemporaryPassword()
			b, _ := crockford.Decode(canonical)
			f.Issued = append(f.Issued, temporaryPasswordVector{Random: hex.EncodeToString(b[:8]), Shown: shown.Reveal()})
		}
		out, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(temporaryPasswordVectors), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(temporaryPasswordVectors, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(temporaryPasswordVectors)
	if err != nil {
		t.Fatalf("%v: run %s", err, regenerateVectors)
	}
	var f temporaryPasswordVectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Issued) < 64 {
		t.Fatalf("%d issued values, want 64: run %s", len(f.Issued), regenerateVectors)
	}
	seen := map[string]bool{}
	for _, v := range f.Issued {
		var r [8]byte
		if n, err := hex.Decode(r[:], []byte(v.Random)); err != nil || n != 8 || len(v.Random) != 16 {
			t.Fatalf("random %q is not eight hex bytes", v.Random)
		}
		want := account.TemporaryPasswordFrom(r)
		if strings.ReplaceAll(v.Shown, "-", "") != want || !shownCode.MatchString(v.Shown) {
			t.Errorf("vector %s: password %q, the generator gives %q shown in fours", v.Random, v.Shown, want)
		}
		if seen[v.Shown] {
			t.Errorf("vector %q twice", v.Shown)
		}
		seen[v.Shown] = true
	}
}
