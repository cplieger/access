package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

var commitShape = regexp.MustCompile(`^[0-9a-f]{40}$`)

type github struct {
	base, token string
}

// maxRefBytes bounds a git/ref answer, about 300 bytes.
const maxRefBytes = 1 << 20

var client = &http.Client{Timeout: 60 * time.Second}

// head returns the commit branch of repo points at. git/ref/ answers one
// exact ref, where git/refs/ also lists the refs it prefixes:
// https://docs.github.com/en/rest/git/refs#get-a-reference
func (g github) head(ctx context.Context, repo, branch string) (string, error) {
	url := g.base + "/repos/" + repo + "/git/ref/heads/" + branch
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("read %s's %s head: %w", repo, branch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("read %s's %s head: %s", repo, branch, resp.Status)
	}
	var ref struct {
		Ref    string `json:"ref"`
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRefBytes)).Decode(&ref); err != nil {
		return "", fmt.Errorf("read %s's %s head: %w", repo, branch, err)
	}
	switch want := "refs/heads/" + branch; {
	case ref.Ref != want:
		return "", fmt.Errorf("GitHub answered ref %q for %s, want %q", ref.Ref, repo, want)
	case ref.Object.Type != "commit":
		return "", fmt.Errorf("%s's %s names a %s, want a commit", repo, branch, ref.Object.Type)
	case !commitShape.MatchString(ref.Object.SHA):
		return "", fmt.Errorf("%s's %s head %q is not a 40-character lowercase commit", repo, branch, ref.Object.SHA)
	}
	return ref.Object.SHA, nil
}
