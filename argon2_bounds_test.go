package access

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestArgon2Params_Validate_bounds(t *testing.T) {
	t.Parallel()
	with := func(change func(*Argon2Params)) Argon2Params {
		p := DefaultArgon2Params()
		change(&p)
		return p
	}
	cases := []struct {
		name    string
		p       Argon2Params
		wantErr bool
	}{
		{"default", DefaultArgon2Params(), false},

		{"memory below the floor", with(func(p *Argon2Params) { p.Memory, p.Iterations = 7167, 6 }), true},
		{"memory at the floor", with(func(p *Argon2Params) { p.Memory, p.Iterations = 7168, 6 }), false},
		{"memory at the ceiling", with(func(p *Argon2Params) { p.Memory = 4 << 20 }), false},
		{"memory above the ceiling", with(func(p *Argon2Params) { p.Memory = 4<<20 + 1 }), true},
		{"memory max uint32", with(func(p *Argon2Params) { p.Memory = math.MaxUint32 }), true},

		{"memory below the t=2 row", with(func(p *Argon2Params) { p.Memory, p.Iterations = 19455, 2 }), true},
		{"memory below the t=1 row", with(func(p *Argon2Params) { p.Memory, p.Iterations = 38912, 1 }), true},

		{"iterations zero", with(func(p *Argon2Params) { p.Iterations = 0 }), true},
		{"iterations at the ceiling", with(func(p *Argon2Params) { p.Iterations = 100 }), false},
		{"iterations above the ceiling", with(func(p *Argon2Params) { p.Iterations = 101 }), true},
		{"iterations max uint32", with(func(p *Argon2Params) { p.Iterations = math.MaxUint32 }), true},

		{"parallelism zero", with(func(p *Argon2Params) { p.Parallelism = 0 }), true},
		{"parallelism at the ceiling", with(func(p *Argon2Params) { p.Parallelism = 16 }), false},
		{"parallelism above the ceiling", with(func(p *Argon2Params) { p.Parallelism = 17 }), true},
		{"parallelism max uint8", with(func(p *Argon2Params) { p.Parallelism = math.MaxUint8 }), true},

		{"salt below the floor", with(func(p *Argon2Params) { p.SaltLength = 15 }), true},
		{"salt at the floor", with(func(p *Argon2Params) { p.SaltLength = 16 }), false},
		{"salt at the ceiling", with(func(p *Argon2Params) { p.SaltLength = 64 }), false},
		{"salt above the ceiling", with(func(p *Argon2Params) { p.SaltLength = 65 }), true},

		{"key below the floor", with(func(p *Argon2Params) { p.KeyLength = 15 }), true},
		{"key at the floor", with(func(p *Argon2Params) { p.KeyLength = 16 }), false},
		{"key at the ceiling", with(func(p *Argon2Params) { p.KeyLength = 64 }), false},
		{"key above the ceiling", with(func(p *Argon2Params) { p.KeyLength = 65 }), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.p.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate(%+v) error = %v, wantErr = %v", tc.p, err, tc.wantErr)
			}
		})
	}
}

// owaspArgon2Rows are the Password Storage Cheat Sheet's minimum Argon2id
// configurations, all at p=1, written out here so the test does not read the
// table it checks.
var owaspArgon2Rows = []struct{ m, t uint32 }{{47104, 1}, {19456, 2}, {12288, 3}, {9216, 4}, {7168, 5}}

func floorParams(m, t uint32) Argon2Params {
	return Argon2Params{Memory: m, Iterations: t, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

func TestFloorAcceptsOWASPRows(t *testing.T) {
	t.Parallel()
	for _, row := range owaspArgon2Rows {
		t.Run(fmt.Sprintf("m=%d t=%d", row.m, row.t), func(t *testing.T) {
			t.Parallel()
			if err := floorParams(row.m, row.t).Validate(); err != nil {
				t.Errorf("Validate = %v, want nil", err)
			}
			phc := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=1$%s$%s", row.m, row.t, phcSalt16, phcKey32)
			if _, err := parsePHC(phc); err != nil {
				t.Errorf("parsePHC(%q) = %v, want nil", phc, err)
			}
		})
	}
}

func TestFloorRefusesBelowEachRow(t *testing.T) {
	t.Parallel()
	type refusal struct {
		name      string
		m, t      uint32
		row, rowT uint32
	}
	var cases []refusal
	for i, row := range owaspArgon2Rows {
		cases = append(cases, refusal{name: fmt.Sprintf("m=%d one below at t=%d", row.m-1, row.t), m: row.m - 1, t: row.t, row: row.m, rowT: row.t})
		if i > 0 {
			prev := owaspArgon2Rows[i-1]
			cases = append(cases, refusal{name: fmt.Sprintf("m=%d at t=%d", row.m, prev.t), m: row.m, t: prev.t, row: prev.m, rowT: prev.t})
		}
	}
	cases = append(cases,
		refusal{name: "m=7167 at t=6", m: 7167, t: 6, row: 7168, rowT: 5},
		refusal{name: "m=7167 at t=100", m: 7167, t: 100, row: 7168, rowT: 5},
		refusal{name: "m=38912 at t=1", m: 38912, t: 1, row: 47104, rowT: 1},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := floorParams(tc.m, tc.t).Validate()
			want := fmt.Sprintf("access: argon2 memory %d KiB is below %d KiB, OWASP's minimum at t=%d", tc.m, tc.row, tc.rowT)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("Validate = %v, want an error naming the row: %q", err, want)
			}
		})
	}
}
