package blocklist

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBlocklistSize(t *testing.T) {
	t.Parallel()
	_, entries, err := Decode(common)
	if err != nil {
		t.Fatalf("Decode(common.txt): %v", err)
	}
	if n := len(entries); n < 10_000 || n > 20_000 {
		t.Errorf("common.txt holds %d entries, want 10000 to 20000", n)
	}
}

func TestBlocklistHeaderCommit(t *testing.T) {
	t.Parallel()
	h, _, err := Decode(common)
	if err != nil {
		t.Fatalf("Decode(common.txt): %v", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(h.Commit) {
		t.Errorf("common.txt header commit = %q, want a 40-character lowercase hex commit", h.Commit)
	}
	want := "https://raw.githubusercontent.com/danielmiessler/SecLists/" + h.Commit + "/Passwords/Common-Credentials/"
	if !strings.HasPrefix(h.URL, want) {
		t.Errorf("common.txt header url = %s, want a SecLists password list at the header commit, %s...", h.URL, want)
	}
}

func TestReadCommit(t *testing.T) {
	t.Parallel()
	h, _, err := Decode(common)
	if err != nil {
		t.Fatalf("Decode(common.txt): %v", err)
	}
	for name, tc := range map[string]struct {
		commit  string
		wantErr bool
	}{
		"40 lowercase hex": {commit: h.Commit},
		"a branch name":    {commit: "master", wantErr: true},
		"39 hex":           {commit: h.Commit[:39], wantErr: true},
		"upper case":       {commit: strings.ToUpper(h.Commit), wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "common.txt")
			data := strings.Replace(common, "# commit: "+h.Commit+"\n", "# commit: "+tc.commit+"\n", 1)
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := ReadCommit(path)
			switch {
			case tc.wantErr && err == nil:
				t.Errorf("ReadCommit with commit %q = %q, want an error", tc.commit, got)
			case !tc.wantErr && (err != nil || got != tc.commit):
				t.Errorf("ReadCommit = %q, %v; want %q", got, err, tc.commit)
			}
		})
	}
}

func TestBlocklistInSync(t *testing.T) {
	t.Parallel()
	h, entries, err := Decode(common)
	if err != nil {
		t.Fatalf("Decode(common.txt): %v", err)
	}
	_, body, _ := strings.Cut(common, "\n\n")
	sum := sha256.Sum256([]byte(body))
	if got := hex.EncodeToString(sum[:]); got != h.BodySHA256 {
		t.Errorf("common.txt body SHA-256 = %s, header body-sha256 = %s", got, h.BodySHA256)
	}
	if h.Kept > h.Survivors || h.Survivors > h.SourceEntries {
		t.Errorf("header counts kept %d, survivors %d, source entries %d are not non-increasing", h.Kept, h.Survivors, h.SourceEntries)
	}
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if seen[e] {
			t.Errorf("entry %q is listed twice", e)
		}
		seen[e] = true
		if Fold(e) != e {
			t.Errorf("entry %q is not folded", e)
		}
		if utf8.RuneCountInString(e) < h.MinRunes {
			t.Errorf("entry %q is shorter than min-runes %d", e, h.MinRunes)
		}
	}
}

func TestBlocklistContains(t *testing.T) {
	t.Parallel()
	_, entries, err := Decode(common)
	if err != nil {
		t.Fatalf("Decode(common.txt): %v", err)
	}
	for _, e := range []string{entries[0], entries[len(entries)/2], entries[len(entries)-1]} {
		if !Contains(e) || !Contains(strings.ToUpper(e)) {
			t.Errorf("Contains(%q) or Contains(%q) = false, want true", e, strings.ToUpper(e))
		}
		if Contains(e + "x") {
			t.Errorf("Contains(%q) = true, want false", e+"x")
		}
	}
	if Contains("") {
		t.Error(`Contains("") = true, want false`)
	}
}

func TestBlocklistDecode(t *testing.T) {
	t.Parallel()
	valid := Header{URL: "https://example.test/list.txt", Commit: strings.Repeat("a", 40), MinRunes: 15, SourceEntries: 3, Survivors: 2, SourceSHA256: strings.Repeat("0", 64)}
	good := string(Encode(&valid, []string{"first-entry-long", "second-entry-long"}))
	h, entries, err := Decode(good)
	if err != nil {
		t.Fatalf("Decode(Encode(...)): %v", err)
	}
	if h.Kept != 2 || len(entries) != 2 || entries[0] != "first-entry-long" || h.URL != valid.URL || h.Survivors != 2 {
		t.Errorf("Decode(Encode(...)) = %+v, %q, want the encoded header and both entries", h, entries)
	}

	cases := []struct {
		name string
		data string
	}{
		{"no blank line", strings.ReplaceAll(good, "\n\n", "\n")},
		{"a header line not a comment", "x" + good},
		{"a missing field", strings.Replace(good, "# url: ", "# uri: ", 1)},
		{"a non-numeric count", strings.Replace(good, "# kept: 2", "# kept: two", 1)},
		{"a body edited after hashing", strings.Replace(good, "first-entry-long", "first-entry-lonG", 1)},
		{"a kept count the body does not hold", strings.Replace(good, "# kept: 2", "# kept: 3", 1)},
		{"an empty entry", string(Encode(&valid, []string{"first-entry-long", ""}))},
		{"no entries", string(Encode(&valid, nil))},
		{"an empty body", withBody(good, "", 0)},
		{"no final newline", withBody(good, "first-entry-long", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := Decode(tc.data); err == nil {
				t.Errorf("Decode(%q) = nil error, want a refusal", tc.data)
			}
		})
	}
}

// withBody replaces data's body and sets the header's kept count and body
// hash to match it, so only the body's shape is wrong.
func withBody(data, body string, kept int) string {
	head, _, _ := strings.Cut(data, "\n\n")
	sum := sha256.Sum256([]byte(body))
	var lines []string
	for line := range strings.SplitSeq(head, "\n") {
		switch {
		case strings.HasPrefix(line, "# kept: "):
			line = "# kept: " + strconv.Itoa(kept)
		case strings.HasPrefix(line, "# body-sha256: "):
			line = "# body-sha256: " + hex.EncodeToString(sum[:])
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n") + "\n\n" + body
}
