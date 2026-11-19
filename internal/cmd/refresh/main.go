// Command refresh regenerates access's community data, the common-password
// list from SecLists and the passkey AAGUID list, at the newest commit of
// each upstream branch, and writes the proposal cplieger/ci's community data
// refresh opens a pull request from.
//
//	go run ./internal/cmd/refresh -out <dir>
//
// It reads the commit each committed output records, resolves the upstream
// head through the GitHub API (GITHUB_TOKEN, when set, authenticates it),
// and runs the source's generator at that head into a staging folder, so the
// working tree is never written. A source whose regenerated files differ from
// the committed ones only by the commit they name proposes nothing. <dir>
// receives proposal.json listing the changed paths, their content under
// files/, and the pull request's title and body.md when a path changed. Any
// generator refusal fails the run with nothing written to <dir>. Run from the
// module root.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cplieger/access/internal/aaguidgen"
	"github.com/cplieger/access/internal/blocklist"
)

func main() {
	out := flag.String("out", "", "write the proposal to this directory, which must be empty or absent")
	flag.Parse()
	if *out == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	api := github{base: "https://api.github.com", token: os.Getenv("GITHUB_TOKEN")}
	if err := run(context.Background(), os.Stdout, ".", *out, api, goCommand); err != nil {
		fmt.Fprintln(os.Stderr, "refresh:", err)
		os.Exit(1)
	}
}

type output struct {
	flag, path string // the generator flag naming the file, its slash path in the module
}

// source is one upstream list and the generator that turns it into outputs.
type source struct {
	recorded                      func(path string) (string, error) // the commit outputs[0] records
	name, repo, branch, generator string
	outputs                       []output
}

// sources' outputs are exactly the access row's paths in cplieger/ci's
// scripts/community_data_refresh.py, which refuses a proposal naming any other.
var sources = []*source{
	{
		name: "the common-password list", repo: "danielmiessler/SecLists", branch: "master",
		generator: "./internal/cmd/genblocklist",
		outputs:   []output{{"-out", "internal/blocklist/common.txt"}},
		recorded:  blocklist.ReadCommit,
	},
	{
		name: "the passkey AAGUID list", repo: "passkeydeveloper/passkey-authenticator-aaguids", branch: "main",
		generator: "./internal/cmd/genaaguids",
		outputs:   []output{{"-out", "webauthn/aaguids_gen.go"}, {"-snapshot", "webauthn/testdata/aaguid.json"}},
		recorded:  aaguidgen.ReadCommit,
	},
}

type goFunc func(ctx context.Context, dir string, report io.Writer, args ...string) error

// change is a source whose data moves from one commit to another.
type change struct {
	*source
	content          map[string][]byte // by slash path, only the paths that changed
	from, to, report string
	paths            []string
}

func run(ctx context.Context, w io.Writer, root, out string, api github, goRun goFunc) error {
	if err := checkEmpty(out); err != nil {
		return err
	}
	moves, err := resolve(ctx, root, api)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp("", "access-refresh-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	var log strings.Builder
	changes, err := regenerateAll(ctx, root, stage, moves, goRun, &log)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		log.WriteString("no change\n")
	}
	return publish(w, out, changes, log.String())
}

// publish writes the proposal to out, then prints log to w.
func publish(w io.Writer, out string, changes []*change, log string) error {
	if err := write(out, changes); err != nil {
		return err
	}
	_, err := io.WriteString(w, log)
	return err
}

func checkEmpty(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case err == nil && len(entries) > 0:
		return fmt.Errorf("%s is not empty", dir)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}
	return nil
}

// regenerateAll regenerates every move whose upstream head moved, logging
// each, and returns the moves whose data changed.
func regenerateAll(ctx context.Context, root, stage string, moves []*change, goRun goFunc, log io.Writer) ([]*change, error) {
	var changes []*change
	for i, m := range moves {
		if m.from == m.to {
			fmt.Fprintf(log, "%s: %s is still at %s\n", m.repo, m.branch, m.from)
			continue
		}
		moved, err := regenerate(ctx, root, filepath.Join(stage, strconv.Itoa(i)), m, goRun)
		if err != nil {
			return nil, err
		}
		if !moved {
			fmt.Fprintf(log, "%s: %s leaves %s as it is at %s\n", m.repo, m.to, m.name, m.from)
			continue
		}
		fmt.Fprintf(log, "%s: %s to %s\n", m.repo, m.from, m.to)
		for _, path := range m.paths {
			fmt.Fprintf(log, "changed %s\n", path)
		}
		changes = append(changes, m)
	}
	return changes, nil
}

// resolve returns, for every source, the commit its committed output records
// and the head of its upstream branch, both checked before any is used.
func resolve(ctx context.Context, root string, api github) ([]*change, error) {
	moves := make([]*change, len(sources))
	for i, s := range sources {
		from, err := s.recorded(filepath.Join(root, filepath.FromSlash(s.outputs[0].path)))
		if err != nil {
			return nil, err
		}
		if !commitShape.MatchString(from) {
			return nil, fmt.Errorf("%s records commit %q, not a 40-character lowercase commit", s.outputs[0].path, from)
		}
		to, err := api.head(ctx, s.repo, s.branch)
		if err != nil {
			return nil, err
		}
		moves[i] = &change{source: s, from: from, to: to}
	}
	return moves, nil
}

// regenerate runs c's generator at c.to into stage, records in c the files
// that differ from the committed ones, and reports whether any differs from
// the committed one read with c.from swapped for c.to.
func regenerate(ctx context.Context, root, stage string, c *change, goRun goFunc) (bool, error) {
	args := []string{"run", c.generator, "-commit", c.to}
	for _, o := range c.outputs {
		staged := filepath.Join(stage, filepath.FromSlash(o.path))
		if err := os.MkdirAll(filepath.Dir(staged), 0o750); err != nil {
			return false, err
		}
		args = append(args, o.flag, staged)
	}
	var report bytes.Buffer
	if err := goRun(ctx, root, &report, args...); err != nil {
		return false, fmt.Errorf("regenerate %s: %w", c.name, err)
	}
	c.report, c.content = report.String(), map[string][]byte{}
	moved := false
	for _, o := range c.outputs {
		staged, err := os.ReadFile(filepath.Join(stage, filepath.FromSlash(o.path)))
		if err != nil {
			return false, fmt.Errorf("regenerate %s: %w", c.name, err)
		}
		committed, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(o.path)))
		if err != nil {
			return false, err
		}
		if !bytes.Equal(staged, bytes.ReplaceAll(committed, []byte(c.from), []byte(c.to))) {
			moved = true
		}
		if !bytes.Equal(staged, committed) {
			c.paths = append(c.paths, o.path)
			c.content[o.path] = staged
		}
	}
	return moved, nil
}

// write writes dir in the proposal format of cplieger/ci's
// docs/workflows.md, with the title and body only when something changed.
func write(dir string, changes []*change) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	paths := []string{}
	for _, c := range changes {
		if err := writeFiles(dir, c); err != nil {
			return err
		}
		paths = append(paths, c.paths...)
	}
	if len(changes) > 0 {
		if err := os.WriteFile(filepath.Join(dir, "title"), []byte(title(changes)+"\n"), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "body.md"), []byte(body(changes)), 0o600); err != nil {
			return err
		}
	}
	manifest, err := json.Marshal(struct {
		Changes []string `json:"changes"`
	}{paths})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "proposal.json"), append(manifest, '\n'), 0o600)
}

func writeFiles(dir string, c *change) error {
	for _, path := range c.paths {
		dest := filepath.Join(dir, "files", filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(dest, c.content[path], 0o600); err != nil {
			return err
		}
	}
	return nil
}

// title is a chore(deps) subject so a merged refresh releases as the
// dependency update it is (cliff.toml's Dependencies group).
func title(changes []*change) string {
	names := make([]string, len(changes))
	for i, c := range changes {
		names[i] = c.name
	}
	return "chore(deps): update " + strings.Join(names, " and ")
}

// reportMax keeps each generator report's tail, so two of them stay well
// under GitHub's 65,536-character cap on a pull request body.
const reportMax = 8 << 10

func body(changes []*change) string {
	var b strings.Builder
	b.WriteString("Regenerates access's community data at the newest upstream commits. Each file records the commit it came from, and `go generate ./...` regenerates it from that commit.\n")
	for _, c := range changes {
		fmt.Fprintf(&b, "\n## %s\n\n", strings.ToUpper(c.name[:1])+c.name[1:])
		fmt.Fprintf(&b, "[%s](https://github.com/%s) `%s` moved from `%s` to `%s`: https://github.com/%s/compare/%s...%s\n\n", c.repo, c.repo, c.branch, c.from, c.to, c.repo, c.from, c.to)
		report := c.report
		if len(report) > reportMax {
			report = report[len(report)-reportMax:]
			report = "(earlier lines cut)\n" + report[strings.IndexByte(report, '\n')+1:]
		}
		fmt.Fprintf(&b, "Generator output:\n\n```text\n%s```\n", report)
	}
	return b.String()
}

// goCommand runs go in dir, copying its output to report and to stderr.
func goCommand(ctx context.Context, dir string, report io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Stdout = io.MultiWriter(report, os.Stderr)
	cmd.Stderr = cmd.Stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
