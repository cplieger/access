// Command genaaguids regenerates webauthn/aaguids_gen.go and its name-only
// snapshot from the community list at -commit, or at the commit the current
// aaguids_gen.go names on its Source line; see internal/aaguidgen. go
// generate runs it from the webauthn directory, which the default paths are
// relative to.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cplieger/access/internal/aaguidgen"
)

func main() {
	commit := flag.String("commit", "", "list commit to generate from (default: the one -out names)")
	out := flag.String("out", "aaguids_gen.go", "generated Go file to replace")
	snapshot := flag.String("snapshot", "testdata/aaguid.json", "name-only snapshot to replace")
	flag.Parse()
	if err := run(*commit, aaguidgen.Paths{Out: *out, Snapshot: *snapshot}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// commitFor returns commit, or when it is empty the commit the generated
// file at out names.
func commitFor(commit, out string) (string, error) {
	if commit != "" {
		return commit, nil
	}
	return aaguidgen.ReadCommit(out)
}

func run(commit string, p aaguidgen.Paths) error {
	commit, err := commitFor(commit, p.Out)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 90 * time.Second}
	body, err := aaguidgen.Fetch(ctx, client, aaguidgen.SourceURL(commit))
	if err != nil {
		return err
	}
	defer body.Close()
	return aaguidgen.Run(body, commit, p, os.Stderr)
}
