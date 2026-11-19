package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/access/internal/aaguidgen"
)

func TestCommitFor(t *testing.T) {
	t.Parallel()
	recorded := strings.Repeat("ab", 20)
	out, err := aaguidgen.Generate([]byte(`{"00000000-1111-2222-3333-444444444444":{"name":"Vault"}}`), recorded)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	dir := t.TempDir()
	gen := filepath.Join(dir, "aaguids_gen.go")
	if err := os.WriteFile(gen, out.Source, 0o600); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	other := strings.Repeat("cd", 20)
	cases := []struct {
		name, commit, out, want string
		wantErr                 bool
	}{
		{name: "the given commit", commit: other, out: gen, want: other},
		{name: "the recorded commit", out: gen, want: recorded},
		{name: "no output to read", out: filepath.Join(dir, "missing.go"), wantErr: true},
	}
	for _, tc := range cases {
		got, err := commitFor(tc.commit, tc.out)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("%s: commitFor(%q, %s) = %q, %v, want %q, error %v", tc.name, tc.commit, filepath.Base(tc.out), got, err, tc.want, tc.wantErr)
		}
	}
}
