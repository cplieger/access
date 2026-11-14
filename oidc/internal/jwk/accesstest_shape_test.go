package jwk_test

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"net/http"
	"testing"

	"github.com/cplieger/access/accesstest"
	"github.com/cplieger/access/oidc/internal/jwk"
)

func get(t *testing.T, c *http.Client, url string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d, %v", url, resp.StatusCode, err)
	}
	return body
}

// RFC 7517 §4.2, §4.3 and 6.3: accesstest.IdP publishes use sig and alg
// with no key_ops, as most providers do, and every key it serves is usable
// for exactly its own alg.
func TestParse_AccesstestIdPShape(t *testing.T) {
	t.Parallel()
	idp := accesstest.NewIdP(t, accesstest.IdPOptions{})
	var doc map[string]jsontext.Value
	if err := json.Unmarshal(get(t, idp.Client(), idp.Issuer()+"/.well-known/openid-configuration"), &doc); err != nil {
		t.Fatal(err)
	}
	var jwksURI string
	if err := json.Unmarshal(doc["jwks_uri"], &jwksURI); err != nil {
		t.Fatal(err)
	}
	s := mustParse(t, get(t, idp.Client(), jwksURI))
	want := map[string]jwk.Alg{"accesstest-rs256": jwk.RS256, "accesstest-es256": jwk.ES256}
	if s.Len() != len(want) {
		t.Fatalf("Len = %d; want %d", s.Len(), len(want))
	}
	for k := range s.All() {
		id, _ := k.KeyID()
		a, ok := want[id]
		if !ok {
			t.Errorf("unexpected kid %q", id)
			continue
		}
		if k.Alg() != a || !k.Fits(a) {
			t.Errorf("kid %q: Alg = %v, Fits(%v) = %v; want %v, true", id, k.Alg(), a, k.Fits(a), a)
		}
	}
}
