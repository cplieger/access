package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// moduleRoot is the access module, whose committed outputs record the
// commits a refresh starts from.
var moduleRoot = filepath.Join("..", "..", "..")

// subjectMax is the shared cap on a squash-merge subject, which the pull
// request title becomes.
const subjectMax = 69

// ciPaths is the access row of REPOS in cplieger/ci's
// scripts/community_data_refresh.py: a proposal naming any other path is
// refused there.
var ciPaths = []string{
	"internal/blocklist/common.txt",
	"webauthn/aaguids_gen.go",
	"webauthn/testdata/aaguid.json",
}

var (
	newSeclists = strings.Repeat("1a", 20)
	newAAGUIDs  = strings.Repeat("2b", 20)
)

// recordedCommits returns the commit each source's committed output records.
func recordedCommits(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, s := range sources {
		c, err := s.recorded(filepath.Join(moduleRoot, filepath.FromSlash(s.outputs[0].path)))
		if err != nil {
			t.Fatalf("Setup: the recorded commit of %s: %v", s.repo, err)
		}
		out[s.repo] = c
	}
	return out
}

// fakeRoot copies every source's committed outputs into a fresh module root.
func fakeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, path := range ciPaths {
		data, err := os.ReadFile(filepath.Join(moduleRoot, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("Setup: %v", err)
		}
		dst := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			t.Fatalf("Setup: %v", err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			t.Fatalf("Setup: %v", err)
		}
	}
	return root
}

// fakeGitHub answers the git/ref read of each branch with heads[repo]; a
// repo missing from heads gets a 404.
type fakeGitHub struct {
	t      *testing.T
	heads  map[string]string
	status int
	ref    string // replaces the answered ref name when set
	typ    string // replaces the answered object type when set

	mu    sync.Mutex
	reads []string
	auths []string
}

func (f *fakeGitHub) serve() github {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reads = append(f.reads, r.URL.Path)
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		f.mu.Unlock()
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			f.t.Errorf("read %s with Accept %q, want application/vnd.github+json", r.URL, r.Header.Get("Accept"))
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		for _, s := range sources {
			if r.URL.Path != "/repos/"+s.repo+"/git/ref/heads/"+s.branch {
				continue
			}
			sha, ok := f.heads[s.repo]
			if !ok {
				break
			}
			ref, typ := "refs/heads/"+s.branch, "commit"
			if f.ref != "" {
				ref = f.ref
			}
			if f.typ != "" {
				typ = f.typ
			}
			_, _ = fmt.Fprintf(w, `{"ref":%q,"object":{"sha":%q,"type":%q}}`, ref, sha, typ)
			return
		}
		http.NotFound(w, r)
	}))
	f.t.Cleanup(srv.Close)
	return github{base: srv.URL, token: "test-token"}
}

// fakeGo stands in for go run of each generator. A generator in same writes
// the committed outputs with the old commit swapped for the new one; any
// other writes new content naming the commit.
type fakeGo struct {
	root   string
	same   map[string]bool
	fail   string
	report string
	calls  []string
}

func (g *fakeGo) run(_ context.Context, dir string, report io.Writer, args ...string) error {
	g.calls = append(g.calls, strings.Join(args, " "))
	if dir != g.root {
		return fmt.Errorf("go ran in %s, want the module root %s", dir, g.root)
	}
	if len(args) < 4 || args[0] != "run" || args[2] != "-commit" {
		return fmt.Errorf("go %q, want run <generator> -commit <commit> ...", args)
	}
	generator, commit := args[1], args[3]
	if generator == g.fail {
		return fmt.Errorf("go %s: exit status 1", strings.Join(args, " "))
	}
	var s *source
	for _, c := range sources {
		if c.generator == generator {
			s = c
		}
	}
	from, err := s.recorded(filepath.Join(g.root, filepath.FromSlash(s.outputs[0].path)))
	if err != nil {
		return err
	}
	for i, o := range s.outputs {
		if args[4+2*i] != o.flag {
			return fmt.Errorf("go %q, want %s at argument %d", args, o.flag, 4+2*i)
		}
		staged := args[5+2*i]
		committed, err := os.ReadFile(filepath.Join(g.root, filepath.FromSlash(o.path)))
		if err != nil {
			return err
		}
		data := []byte("new " + o.path + " at " + commit + "\n")
		if g.same[generator] {
			data = bytes.ReplaceAll(committed, []byte(from), []byte(commit))
		}
		if err := os.WriteFile(staged, data, 0o600); err != nil {
			return err
		}
	}
	_, err = io.WriteString(report, g.report)
	return err
}

func readManifest(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "proposal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Changes []string `json:"changes"`
	}
	if err := json.Unmarshal(b, &m); err != nil || m.Changes == nil {
		t.Fatalf("proposal.json = %q (%v), want a changes list", b, err)
	}
	return m.Changes
}

// filesUnder returns the slash path of every regular file under dir.
func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		found = append(found, filepath.ToSlash(rel))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(found)
	return found
}

func TestSourcesCoverTheCIRow(t *testing.T) {
	t.Parallel()
	var paths []string
	for _, s := range sources {
		for _, o := range s.outputs {
			paths = append(paths, o.path)
		}
	}
	if !slices.Equal(paths, ciPaths) {
		t.Errorf("the sources' outputs are %q, want the ci row's %q", paths, ciPaths)
	}
	for repo, commit := range recordedCommits(t) {
		if !commitShape.MatchString(commit) {
			t.Errorf("%s: the recorded commit is %q, want 40 lowercase hex", repo, commit)
		}
	}
}

func TestRunProposesEveryChangedSource(t *testing.T) {
	t.Parallel()
	was := recordedCommits(t)
	fake := &fakeGitHub{t: t, heads: map[string]string{"danielmiessler/SecLists": newSeclists, "passkeydeveloper/passkey-authenticator-aaguids": newAAGUIDs}}
	api := fake.serve()
	root, out := fakeRoot(t), t.TempDir()
	g := &fakeGo{root: root, report: "generator report\n"}
	var w bytes.Buffer
	if err := run(t.Context(), &w, root, out, api, g.run); err != nil {
		t.Fatal(err)
	}
	if len(g.calls) != 2 || !strings.HasPrefix(g.calls[0], "run ./internal/cmd/genblocklist -commit "+newSeclists+" -out ") ||
		!strings.HasPrefix(g.calls[1], "run ./internal/cmd/genaaguids -commit "+newAAGUIDs+" -out ") || !strings.Contains(g.calls[1], " -snapshot ") {
		t.Errorf("ran %q, want each generator at its new commit", g.calls)
	}
	if changes := readManifest(t, out); !slices.Equal(changes, ciPaths) {
		t.Errorf("proposal.json lists %q, want %q", changes, ciPaths)
	}
	wantFiles := []string{"body.md", "files/internal/blocklist/common.txt", "files/webauthn/aaguids_gen.go", "files/webauthn/testdata/aaguid.json", "proposal.json", "title"}
	if got := filesUnder(t, out); !slices.Equal(got, wantFiles) {
		t.Errorf("-out holds %q, want %q", got, wantFiles)
	}
	for _, s := range sources {
		commit := map[string]string{"danielmiessler/SecLists": newSeclists, "passkeydeveloper/passkey-authenticator-aaguids": newAAGUIDs}[s.repo]
		for _, o := range s.outputs {
			b, err := os.ReadFile(filepath.Join(out, "files", filepath.FromSlash(o.path)))
			if want := "new " + o.path + " at " + commit + "\n"; err != nil || string(b) != want {
				t.Errorf("files/%s = %q, %v; want %q", o.path, b, err, want)
			}
		}
	}
	title, err := os.ReadFile(filepath.Join(out, "title"))
	if want := "feat: update the common-password list and the passkey list\n"; err != nil || string(title) != want {
		t.Errorf("title = %q, %v; want %q", title, err, want)
	}
	if n := len(title) - 1; n > subjectMax {
		t.Errorf("title is %d characters, over the %d-character squash subject cap", n, subjectMax)
	}
	body, err := os.ReadFile(filepath.Join(out, "body.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https://github.com/danielmiessler/SecLists/compare/" + was["danielmiessler/SecLists"] + "..." + newSeclists,
		"https://github.com/passkeydeveloper/passkey-authenticator-aaguids/compare/" + was["passkeydeveloper/passkey-authenticator-aaguids"] + "..." + newAAGUIDs,
		"generator report\n",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body.md = %q, want it to contain %q", body, want)
		}
	}
	for _, path := range ciPaths {
		committed, _ := os.ReadFile(filepath.Join(moduleRoot, filepath.FromSlash(path)))
		left, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if !bytes.Equal(committed, left) {
			t.Errorf("run changed %s in the module root, want it left alone", path)
		}
	}
	for _, auth := range fake.auths {
		if auth != "Bearer test-token" {
			t.Errorf("a GitHub read sent Authorization %q, want the token", auth)
		}
	}
	if want := "changed internal/blocklist/common.txt\n"; !strings.Contains(w.String(), want) {
		t.Errorf("printed %q, want it to contain %q", w.String(), want)
	}
}

func TestRunAtTheRecordedCommitsChangesNothing(t *testing.T) {
	t.Parallel()
	was := recordedCommits(t)
	api := (&fakeGitHub{t: t, heads: was}).serve()
	root, out := fakeRoot(t), t.TempDir()
	g := &fakeGo{root: root}
	var w bytes.Buffer
	if err := run(t.Context(), &w, root, out, api, g.run); err != nil {
		t.Fatal(err)
	}
	if len(g.calls) != 0 {
		t.Errorf("ran %q, want no generator", g.calls)
	}
	if changes := readManifest(t, out); len(changes) != 0 {
		t.Errorf("proposal.json lists %q, want no change", changes)
	}
	if got := filesUnder(t, out); !slices.Equal(got, []string{"proposal.json"}) {
		t.Errorf("-out holds %q, want proposal.json alone", got)
	}
	if want := "no change\n"; !strings.HasSuffix(w.String(), want) {
		t.Errorf("printed %q, want it to end with %q", w.String(), want)
	}
}

func TestRunSkipsACommitThatLeavesTheDataAlone(t *testing.T) {
	t.Parallel()
	api := (&fakeGitHub{t: t, heads: map[string]string{"danielmiessler/SecLists": newSeclists, "passkeydeveloper/passkey-authenticator-aaguids": newAAGUIDs}}).serve()
	root, out := fakeRoot(t), t.TempDir()
	g := &fakeGo{root: root, same: map[string]bool{"./internal/cmd/genblocklist": true}}
	if err := run(t.Context(), io.Discard, root, out, api, g.run); err != nil {
		t.Fatal(err)
	}
	if changes, want := readManifest(t, out), ciPaths[1:]; !slices.Equal(changes, want) {
		t.Errorf("proposal.json lists %q, want %q", changes, want)
	}
	title, err := os.ReadFile(filepath.Join(out, "title"))
	if want := "feat: update the passkey list\n"; err != nil || string(title) != want {
		t.Errorf("title = %q, %v; want %q", title, err, want)
	}
	body, err := os.ReadFile(filepath.Join(out, "body.md"))
	if err != nil || strings.Contains(string(body), "SecLists") {
		t.Errorf("body.md = %q, %v; want no SecLists section", body, err)
	}
}

func TestRunRefuses(t *testing.T) {
	t.Parallel()
	both := map[string]string{"danielmiessler/SecLists": newSeclists, "passkeydeveloper/passkey-authenticator-aaguids": newAAGUIDs}
	with := func(repo, sha string) map[string]string {
		m := maps.Clone(both)
		m[repo] = sha
		return m
	}
	for name, c := range map[string]struct {
		gh        *fakeGitHub
		fail      string
		wantErr   string
		wantCalls int
	}{
		"the API refuses":          {gh: &fakeGitHub{heads: both, status: http.StatusForbidden}, wantErr: "403 Forbidden"},
		"no such branch":           {gh: &fakeGitHub{heads: map[string]string{}}, wantErr: "404 Not Found"},
		"a branch name for a sha":  {gh: &fakeGitHub{heads: with("danielmiessler/SecLists", "master")}, wantErr: `"master" is not a 40-character lowercase commit`},
		"a short sha":              {gh: &fakeGitHub{heads: with("passkeydeveloper/passkey-authenticator-aaguids", newAAGUIDs[:39])}, wantErr: "is not a 40-character lowercase commit"},
		"an upper-case sha":        {gh: &fakeGitHub{heads: with("danielmiessler/SecLists", strings.ToUpper(newSeclists))}, wantErr: "is not a 40-character lowercase commit"},
		"another ref":              {gh: &fakeGitHub{heads: both, ref: "refs/heads/other"}, wantErr: `answered ref "refs/heads/other"`},
		"a tag object":             {gh: &fakeGitHub{heads: both, typ: "tag"}, wantErr: `a tag, want a commit`},
		"the blocklist generator":  {gh: &fakeGitHub{heads: both}, fail: "./internal/cmd/genblocklist", wantErr: "regenerate the common-password list: go run ./internal/cmd/genblocklist", wantCalls: 1},
		"the AAGUID generator":     {gh: &fakeGitHub{heads: both}, fail: "./internal/cmd/genaaguids", wantErr: "regenerate the passkey list: go run ./internal/cmd/genaaguids", wantCalls: 2},
		"a generator writing none": {gh: &fakeGitHub{heads: both}, fail: "none", wantErr: "no such file", wantCalls: 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c.gh.t = t
			api := c.gh.serve()
			root, out := fakeRoot(t), t.TempDir()
			g := &fakeGo{root: root, fail: c.fail}
			goRun := g.run
			if c.fail == "none" {
				goRun = func(_ context.Context, _ string, _ io.Writer, args ...string) error {
					g.calls = append(g.calls, strings.Join(args, " "))
					return nil
				}
			}
			err := run(t.Context(), io.Discard, root, out, api, goRun)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("run = %v, want an error containing %q", err, c.wantErr)
			}
			if len(g.calls) != c.wantCalls {
				t.Errorf("ran %q, want %d generators", g.calls, c.wantCalls)
			}
			if got := filesUnder(t, out); len(got) != 0 {
				t.Errorf("-out holds %q after the refusal, want nothing", got)
			}
		})
	}
}

func TestRunRefusesAnOutThatIsNotEmpty(t *testing.T) {
	t.Parallel()
	api := (&fakeGitHub{t: t, heads: recordedCommits(t)}).serve()
	root, out := fakeRoot(t), t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "stale"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), io.Discard, root, out, api, (&fakeGo{root: root}).run); err == nil || !strings.Contains(err.Error(), "is not empty") {
		t.Errorf("run into a non-empty -out = %v, want a refusal", err)
	}
}

func TestBodyCapsAReport(t *testing.T) {
	t.Parallel()
	var long strings.Builder
	for i := 0; long.Len() < 4*reportMax; i++ {
		fmt.Fprintf(&long, "go: downloading line %d\n", i)
	}
	long.WriteString("the generator's summary\n")
	changes := []*change{
		{source: sources[0], from: strings.Repeat("0", 40), to: newSeclists, report: long.String()},
		{source: sources[1], from: strings.Repeat("0", 40), to: newAAGUIDs, report: long.String()},
	}
	b := body(changes)
	if len(b) > 60000 {
		t.Errorf("body is %d bytes, want it well under GitHub's 65,536-character cap", len(b))
	}
	if strings.Count(b, "the generator's summary\n") != 2 {
		t.Errorf("body keeps %d summaries, want each report's tail", strings.Count(b, "the generator's summary\n"))
	}
}

func TestGoCommand(t *testing.T) {
	t.Parallel()
	var report bytes.Buffer
	err := goCommand(t.Context(), t.TempDir(), &report, "no-such-command")
	var exit interface{ ExitCode() int }
	if err == nil || !strings.HasPrefix(err.Error(), "go no-such-command: ") || !errors.As(err, &exit) {
		t.Errorf("goCommand of an unknown command = %v, want the exit error naming it", err)
	}
	if !strings.Contains(report.String(), "unknown command") {
		t.Errorf("the report holds %q, want go's own complaint", report.String())
	}
}
