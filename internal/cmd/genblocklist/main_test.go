package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cplieger/access/internal/blocklist"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

// survivorList returns n distinct 15-rune entries, each followed by a
// 14-rune one the length filter drops.
func survivorList(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "survivor-%06d\nshort-%08d\n", i, i)
	}
	return b.String()
}

// fixture is the test server's answer for a source file at any commit.
type fixture struct {
	bodies map[string]string // by file name; a file missing from it gets a 404
	status int               // 0 answers 200
	cut    bool              // declares one byte more than the body, so its read fails
}

func serve(t *testing.T, fx fixture) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, file, _ := strings.Cut(r.URL.Path, "/"+sourceDir)
		body, ok := fx.bodies[file]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if fx.cut {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)+1))
		}
		if fx.status != 0 {
			w.WriteHeader(fx.status)
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/"
}

// testFetcher reads from base with the production body cap.
func testFetcher(base string) fetcher {
	return fetcher{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: base,
		maxBody: maxSourceBytes,
	}
}

// runIn runs the generator at testCommit in a fresh directory and returns
// the output path and the directory's entries after the run.
func runIn(t *testing.T, f fetcher) (string, []os.DirEntry, error) {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "common.txt")
	err := run(t.Context(), f, testCommit, out, io.Discard)
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("Setup: read %s: %v", dir, readErr)
	}
	return out, entries, err
}

func decodeOutput(t *testing.T, out string) (blocklist.Header, []string) {
	t.Helper()
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	h, entries, err := blocklist.Decode(string(data))
	if err != nil {
		t.Fatalf("blocklist.Decode(output): %v", err)
	}
	return h, entries
}

// TestGenRefusals gives each refusal a fixture that only its own check
// refuses, and asserts that check's error, since a later check would also
// refuse most of them.
func TestGenRefusals(t *testing.T) {
	t.Parallel()
	enough := survivorList(minSurvivors)
	both := map[string]string{sourceFiles[0]: enough, sourceFiles[1]: enough}
	overScanner := enough + strings.Repeat("x", 64<<10+1) + "\n"
	cases := []struct {
		name    string
		base    string // replaces the test server's URL when set
		fx      fixture
		maxBody int64 // 0 keeps the production cap
		want    string
		is      error // when set, the refusal must also match it
	}{
		{name: "a base URL that does not parse", base: "http://exa\x7fmple/", want: "invalid control character"},
		{name: "a fetch that fails", base: "unsupported://example/", want: "fetch: "},
		{name: "a non-200 fetch", fx: fixture{bodies: both, status: http.StatusInternalServerError}, want: "500 Internal Server Error"},
		{name: "a body cut short", fx: fixture{bodies: both, cut: true}, want: io.ErrUnexpectedEOF.Error(), is: io.ErrUnexpectedEOF},
		{name: "an empty list", fx: fixture{bodies: map[string]string{sourceFiles[0]: "", sourceFiles[1]: enough}}, want: "is an empty list"},
		{name: "a list of blank lines", fx: fixture{bodies: map[string]string{sourceFiles[0]: "\n\n\n", sourceFiles[1]: enough}}, want: "is an empty list"},
		{name: "a body one byte over the cap", fx: fixture{bodies: both}, maxBody: int64(len(enough)) - 1, want: "is larger than"},
		{name: "a line over 64 KiB", fx: fixture{bodies: map[string]string{sourceFiles[0]: overScanner, sourceFiles[1]: enough}}, want: bufio.ErrTooLong.Error(), is: bufio.ErrTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := tc.base
			if base == "" {
				base = serve(t, tc.fx)
			}
			f := testFetcher(base)
			if tc.maxBody != 0 {
				f.maxBody = tc.maxBody
			}
			out, entries, err := runIn(t, f)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("run = %v, want a refusal containing %q", err, tc.want)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("run = %v, want it to match %v", err, tc.is)
			}
			if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
				t.Errorf("os.Stat(%s) = %v, want not exist", out, statErr)
			}
			if len(entries) != 0 {
				t.Errorf("the directory holds %d files after the refusal, want none", len(entries))
			}
		})
	}
}

func TestGenFallback(t *testing.T) {
	t.Parallel()
	t.Run("the second file when the first is short", func(t *testing.T) {
		t.Parallel()
		second := survivorList(minSurvivors)
		out, _, err := runIn(t, testFetcher(serve(t, fixture{bodies: map[string]string{
			sourceFiles[0]: survivorList(minSurvivors - 1),
			sourceFiles[1]: second,
		}})))
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		h, entries := decodeOutput(t, out)
		if !strings.HasSuffix(h.URL, "/"+testCommit+"/"+sourceDir+sourceFiles[1]) {
			t.Errorf("header url = %s, want the second file %s", h.URL, sourceFiles[1])
		}
		sum := sha256.Sum256([]byte(second))
		if h.SourceSHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("header source-sha256 = %s, want the second file's", h.SourceSHA256)
		}
		if h.Commit != testCommit || h.Survivors != minSurvivors || len(entries) != minSurvivors || h.SourceEntries != 2*minSurvivors {
			t.Errorf("header = %+v with %d entries, want commit %s, %d survivors and entries, %d source entries", h, len(entries), testCommit, minSurvivors, 2*minSurvivors)
		}
	})
	t.Run("both files short", func(t *testing.T) {
		t.Parallel()
		out, entries, err := runIn(t, testFetcher(serve(t, fixture{bodies: map[string]string{
			sourceFiles[0]: survivorList(minSurvivors - 1),
			sourceFiles[1]: survivorList(minSurvivors - 1),
		}})))
		if want := fmt.Sprintf("fewer than %d survivors", minSurvivors); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("run = %v, want a refusal containing %q", err, want)
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) || len(entries) != 0 {
			t.Errorf("os.Stat(%s) = %v with %d files in the directory, want nothing written", out, statErr, len(entries))
		}
	})
}

func TestGenFilter(t *testing.T) {
	t.Parallel()
	// The Kelvin sign and long s fold to k and s, so the second line repeats
	// the first; the NFD line composes to 15 runes from 16; the sharp s line
	// has 14 runes and folds to 15.
	head := "Kelvin-Sign-Word\n\u212Aelvin-\u017Fign-word\r\nmixed-ok-abc-e\u0301d\nfourteen-runes\nstra\u00dfe-1234567\n"
	list := head + survivorList(maxKept)
	out, _, err := runIn(t, testFetcher(serve(t, fixture{bodies: map[string]string{sourceFiles[0]: list}})))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	h, entries := decodeOutput(t, out)
	if len(entries) != maxKept || h.Kept != maxKept || h.Survivors != maxKept+3 {
		t.Errorf("kept %d (header %d) of %d survivors, want %d of %d", len(entries), h.Kept, h.Survivors, maxKept, maxKept+3)
	}
	want := []string{"kelvin-sign-word", "mixed-ok-abc-\u00e9d", "strasse-1234567", "survivor-000000"}
	for i, w := range want {
		if entries[i] != w {
			t.Errorf("entry %d = %q, want %q (source order, folded, deduplicated)", i, entries[i], w)
		}
	}
	if last := entries[len(entries)-1]; last != fmt.Sprintf("survivor-%06d", maxKept-4) {
		t.Errorf("last entry = %q, want the cap to keep the first %d survivors", last, maxKept)
	}
}

func TestGenCaps(t *testing.T) {
	t.Parallel()
	// A body exactly at its cap is read whole, and a line well past any
	// password's length but inside the scanner's buffer is kept.
	long := strings.Repeat("x", 32<<10)
	atCap := survivorList(minSurvivors) + long + "\n"
	f := testFetcher(serve(t, fixture{bodies: map[string]string{sourceFiles[0]: atCap}}))
	f.maxBody = int64(len(atCap))
	out, _, err := runIn(t, f)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	h, entries := decodeOutput(t, out)
	if h.SourceEntries != 2*minSurvivors+1 {
		t.Errorf("header source-entries = %d, want %d", h.SourceEntries, 2*minSurvivors+1)
	}
	if len(entries) != minSurvivors+1 {
		t.Fatalf("kept %d entries, want %d", len(entries), minSurvivors+1)
	}
	if entries[len(entries)-1] != long {
		t.Errorf("last entry is %d bytes, want the %d-byte line", len(entries[len(entries)-1]), len(long))
	}
	sum := sha256.Sum256([]byte(atCap))
	if h.SourceSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("header source-sha256 = %s, want the whole body's", h.SourceSHA256)
	}
}
