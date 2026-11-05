// Command genblocklist regenerates internal/blocklist/common.txt from the
// SecLists password lists at blocklist.SeclistsCommit. go generate runs it
// from the internal/blocklist directory, which the default -out path is
// relative to.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/cplieger/access"
	"github.com/cplieger/access/internal/blocklist"
)

const (
	rawBaseURL     = "https://raw.githubusercontent.com/danielmiessler/SecLists/"
	sourceDir      = "Passwords/Common-Credentials/"
	minSurvivors   = 10_000
	maxKept        = 20_000
	maxSourceBytes = 128 << 20 // the larger list is about 48 MB
)

// sourceFiles is tried in order; a file with fewer than minSurvivors
// survivors falls back to the next.
var sourceFiles = []string{
	"xato-net-10-million-passwords-1000000.txt",
	"xato-net-10-million-passwords.txt",
}

// fetcher reads the source files under baseURL, refusing a body longer than
// maxBody.
type fetcher struct {
	client  *http.Client
	baseURL string
	maxBody int64
}

func main() {
	out := flag.String("out", "common.txt", "list file to replace")
	flag.Parse()
	if err := generate(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(out string) error {
	f := fetcher{
		client:  &http.Client{Timeout: 5 * time.Minute},
		baseURL: rawBaseURL,
		maxBody: maxSourceBytes,
	}
	return run(context.Background(), f, blocklist.SeclistsCommit, out, os.Stderr)
}

// run generates from the first source file at commit with enough survivors
// and replaces out by rename. Every refusal writes nothing.
func run(ctx context.Context, f fetcher, commit, out string, report io.Writer) error {
	for _, file := range sourceFiles {
		url := f.baseURL + commit + "/" + sourceDir + file
		h, entries, err := f.filter(ctx, url)
		if err != nil {
			return err
		}
		if h.Survivors < minSurvivors {
			fmt.Fprintf(report, "%s: %d survivors, below %d; trying the next file\n", file, h.Survivors, minSurvivors)
			continue
		}
		h.Commit = commit
		if err := replaceFile(out, blocklist.Encode(&h, entries)); err != nil {
			return err
		}
		fmt.Fprintf(report, "%s: %d entries, %d survivors, %d kept\n", file, h.SourceEntries, h.Survivors, len(entries))
		return nil
	}
	return fmt.Errorf("genblocklist: every source file has fewer than %d survivors", minSurvivors)
}

// filter fetches url and returns its provenance and the first maxKept
// distinct folded entries of at least access.PasswordMinLength runes.
func (f fetcher) filter(ctx context.Context, url string) (blocklist.Header, []string, error) {
	h := blocklist.Header{URL: url, MinRunes: access.PasswordMinLength}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return h, nil, fmt.Errorf("genblocklist: %w", err)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return h, nil, fmt.Errorf("genblocklist: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return h, nil, fmt.Errorf("genblocklist: fetch %s: %s", url, resp.Status)
	}
	sum := sha256.New()
	limited := &io.LimitedReader{R: resp.Body, N: f.maxBody + 1}
	entries, err := scan(io.TeeReader(limited, sum), &h)
	if err != nil {
		return h, nil, fmt.Errorf("genblocklist: read %s: %w", url, err)
	}
	if limited.N == 0 {
		return h, nil, fmt.Errorf("genblocklist: %s is larger than %d bytes", url, f.maxBody)
	}
	if h.SourceEntries == 0 {
		return h, nil, fmt.Errorf("genblocklist: %s is an empty list", url)
	}
	h.SourceSHA256 = hex.EncodeToString(sum.Sum(nil))
	return h, entries, nil
}

// scan counts h's source entries and survivors in r and returns the kept
// ones. Invalid UTF-8 lines are skipped: no password a client sends as JSON
// can equal one. A line too long for the scanner's default 64 KiB buffer
// fails with bufio.ErrTooLong.
func scan(r io.Reader, h *blocklist.Header) ([]string, error) {
	scanner := bufio.NewScanner(r)
	seen := map[string]bool{}
	var entries []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		h.SourceEntries++
		if !utf8.ValidString(line) {
			continue
		}
		// The floor counts the folded form Contains compares: case folding
		// never shortens NFC text, so a password ValidatePasswordLength
		// accepts folds to at least MinRunes runes, and an entry that reaches
		// MinRunes only once folded stays on the list.
		folded := blocklist.Fold(line)
		if utf8.RuneCountInString(folded) < h.MinRunes || seen[folded] {
			continue
		}
		seen[folded] = true
		h.Survivors++
		if len(entries) < maxKept {
			entries = append(entries, folded)
		}
	}
	return entries, scanner.Err()
}

func replaceFile(dst string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".genblocklist-*")
	if err != nil {
		return fmt.Errorf("genblocklist: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("genblocklist: write %s: %w", dst, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("genblocklist: write %s: %w", dst, err)
	}
	if err = os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("genblocklist: %w", err)
	}
	if err = os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("genblocklist: %w", err)
	}
	return nil
}
