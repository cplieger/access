package access

import (
	"runtime"
	"strings"
	"testing"
)

const (
	phcSalt16 = "c2FsdHNhbHRzYWx0c2FsdA"                      // "saltsaltsaltsalt"
	phcKey32  = "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g" // "hash" × 8
)

func TestParsePHC(t *testing.T) {
	t.Parallel()
	canonical := "$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16 + "$" + phcKey32
	t.Run("canonical", func(t *testing.T) {
		t.Parallel()
		p, err := parsePHC(canonical)
		if err != nil {
			t.Fatalf("parsePHC(canonical) = %v", err)
		}
		if p.params != DefaultArgon2Params() || string(p.salt) != "saltsaltsaltsalt" || string(p.key) != strings.Repeat("hash", 8) {
			t.Errorf("parsePHC(canonical) = %+v, want the default params, salt and key", p)
		}
	})
	t.Run("ceilings", func(t *testing.T) {
		t.Parallel()
		s := "$argon2id$v=19$m=4194304,t=100,p=16$" + strings.Repeat("A", 86) + "$" + strings.Repeat("A", 86)
		if _, err := parsePHC(s); err != nil {
			t.Errorf("parsePHC(64-byte salt and key at the parameter ceilings) = %v", err)
		}
	})
	for _, tc := range []struct{ name, s string }{
		{"empty", ""},
		{"no leading empty field", "x$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16 + "$" + phcKey32},
		{"wrong algorithm", "$argon2i$v=19$m=19456,t=2,p=1$" + phcSalt16 + "$" + phcKey32},
		{"too few parts", "$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16},
		{"too many parts", canonical + "$"},
		{"wrong version", "$argon2id$v=18$m=19456,t=2,p=1$" + phcSalt16 + "$" + phcKey32},
		{"version with a leading zero", "$argon2id$v=019$m=19456,t=2,p=1$" + phcSalt16 + "$" + phcKey32},
		{"memory with a leading zero", "$argon2id$v=19$m=019456,t=2,p=1$" + phcSalt16 + "$" + phcKey32},
		{"memory with a plus sign", "$argon2id$v=19$m=+19456,t=2,p=1$" + phcSalt16 + "$" + phcKey32},
		{"params with a space", "$argon2id$v=19$m=19456, t=2,p=1$" + phcSalt16 + "$" + phcKey32},
		{"params with trailing text", "$argon2id$v=19$m=19456,t=2,p=1,x=1$" + phcSalt16 + "$" + phcKey32},
		{"params reordered", "$argon2id$v=19$t=2,m=19456,p=1$" + phcSalt16 + "$" + phcKey32},
		{"padded salt", "$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16 + "==$" + phcKey32},
		{"salt with trailing bits set", "$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16[:21] + "B$" + phcKey32},
		{"salt with a newline", "$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16[:10] + "\n" + phcSalt16[10:] + "$" + phcKey32},
		{"memory below the floor", "$argon2id$v=19$m=1024,t=38,p=1$" + phcSalt16 + "$" + phcKey32},
		{"memory above the ceiling", "$argon2id$v=19$m=4194305,t=1,p=1$" + phcSalt16 + "$" + phcKey32},
		{"memory below the t=2 row", "$argon2id$v=19$m=19455,t=2,p=1$" + phcSalt16 + "$" + phcKey32},
		{"zero iterations", "$argon2id$v=19$m=19456,t=0,p=1$" + phcSalt16 + "$" + phcKey32},
		{"iterations above the ceiling", "$argon2id$v=19$m=19456,t=101,p=1$" + phcSalt16 + "$" + phcKey32},
		{"zero parallelism", "$argon2id$v=19$m=19456,t=2,p=0$" + phcSalt16 + "$" + phcKey32},
		{"parallelism above the ceiling", "$argon2id$v=19$m=19456,t=2,p=17$" + phcSalt16 + "$" + phcKey32},
		{"parallelism over a byte", "$argon2id$v=19$m=19456,t=2,p=257$" + phcSalt16 + "$" + phcKey32},
		{"8-byte salt", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$" + phcKey32},
		{"65-byte salt", "$argon2id$v=19$m=19456,t=2,p=1$" + strings.Repeat("A", 87) + "$" + phcKey32},
		{"empty key", "$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16 + "$"},
		{"1-byte key", "$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16 + "$AA"},
		{"65-byte key", "$argon2id$v=19$m=19456,t=2,p=1$" + phcSalt16 + "$" + strings.Repeat("A", 87)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if p, err := parsePHC(tc.s); err == nil {
				t.Errorf("parsePHC(%q) = %+v, want an error", tc.s, p)
			}
		})
	}
}

// Not parallel: TotalAlloc is process-wide.
func TestParsePHCOversized(t *testing.T) {
	encoded := "$argon2id$v=19$m=19456,t=2,p=1$" + strings.Repeat("A", 8<<20) + "$" + phcKey32
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := parsePHC(encoded)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("parsePHC(8 MiB salt) succeeded, want an error")
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 64<<10 {
		t.Errorf("parsePHC(8 MiB salt) allocated %d bytes before refusing, want at most %d", got, 64<<10)
	}
}
