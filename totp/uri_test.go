package totp

import (
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
)

// parsedURI is what an authenticator reads back from a Key Uri Format URI.
type parsedURI struct {
	labelIssuer, account string
	query                url.Values
}

func parseURI(t testing.TB, raw string) parsedURI {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("scheme and type = %q, %q, want otpauth, totp", u.Scheme, u.Host)
	}
	issuer, account, ok := strings.Cut(strings.TrimPrefix(u.Path, "/"), ":")
	if !ok || strings.Contains(account, ":") {
		t.Fatalf("label %q is not one issuer:account pair", u.Path)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", u.RawQuery, err)
	}
	return parsedURI{issuer, account, q}
}

// checkParams pins the Key Uri Format's parameters: exactly one of each,
// the secret in unpadded base32, issuer equal to the label prefix, and the
// fixed algorithm, digits and period.
func checkParams(t testing.TB, p parsedURI, secret []byte) {
	t.Helper()
	want := map[string]string{
		"secret": Text(secret), "issuer": p.labelIssuer,
		"algorithm": "SHA1", "digits": "6", "period": "30",
	}
	if len(p.query) != len(want) {
		t.Errorf("parameters = %v, want exactly %v", p.query, want)
	}
	for k, v := range want {
		if got := p.query[k]; len(got) != 1 || got[0] != v {
			t.Errorf("parameter %s = %q, want [%q]", k, got, v)
		}
	}
}

var wikiSecret = []byte("Hello!\xDE\xAD\xBE\xEF")

// The Key Uri Format's own examples: the label, the parameters, and the
// issuer parameter equal to the label prefix.
func TestURIKeyUriFormat(t *testing.T) {
	got := URI("Example", "alice@google.com", wikiSecret)
	want := "otpauth://totp/Example:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30"
	if got != want {
		t.Errorf("URI =\n %s\nwant\n %s", got, want)
	}
	// The format's second example spells @ literally; both parse to one label.
	wiki := parseURI(t, "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")
	secret, err := base32.StdEncoding.DecodeString("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
	if err != nil {
		t.Fatal(err)
	}
	ours := parseURI(t, URI("ACME Co", "john.doe@email.com", secret))
	if ours.labelIssuer != wiki.labelIssuer || ours.account != wiki.account {
		t.Errorf("label = %q:%q, want %q:%q", ours.labelIssuer, ours.account, wiki.labelIssuer, wiki.account)
	}
	checkParams(t, ours, secret)
	for k, v := range wiki.query {
		if ours.query.Get(k) != v[0] {
			t.Errorf("parameter %s = %q, the format's example has %q", k, ours.query.Get(k), v[0])
		}
	}
}

// The Key Uri Format: the label and the issuer are URI-encoded (RFC 3986
// §2.1), a space as %20, and neither part may hold a colon, since the format
// reads ":" and "%3A" alike as the separator. Each value parses back with
// net/url to the same issuer and account and one secret.
func TestURIEncoding(t *testing.T) {
	cases := []struct{ name, issuer, account, wantIssuer, wantAccount string }{
		{"space", "Big Corporation", "Alice Smith", "Big Corporation", "Alice Smith"},
		{"at and dot", "Example", "alice@bigco.com", "Example", "alice@bigco.com"},
		{"colon in account", "Example", "a:b", "Example", "a_b"},
		{"colon in issuer", "Ex:ample", "alice", "Ex_ample", "alice"},
		{"encoded colon", "Example", "a%3Ab", "Example", "a%3Ab"},
		{"ampersand and hash", "R&D #1", "a&b#c", "R&D #1", "a&b#c"},
		{"percent and plus", "100% + co", "a+b%20c", "100% + co", "a+b%20c"},
		{"question and slash", "a/b?c", "d/e?f=g", "a/b?c", "d/e?f=g"},
		{"non-ASCII", "Café Münster", "José 日本", "Café Münster", "José 日本"},
		{"control", "a\x00b", "c\nd\te", "a\x00b", "c\nd\te"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := URI(c.issuer, c.account, wikiSecret)
			p := parseURI(t, raw)
			if p.labelIssuer != c.wantIssuer || p.account != c.wantAccount {
				t.Errorf("label = %q:%q, want %q:%q (URI %s)", p.labelIssuer, p.account, c.wantIssuer, c.wantAccount, raw)
			}
			checkParams(t, p, wikiSecret)
			if strings.Contains(raw, "+") || strings.ContainsAny(raw, " \x00\n\t") {
				t.Errorf("URI %s holds a raw space, + or control byte", raw)
			}
		})
	}
}

// spomky-labs/otphp GHSA-2jx3-65f3-xr8r: parameters smuggled through a
// label or issuer reached the parsed object. An account or issuer naming
// parameters still yields one secret and the true issuer.
func TestURIParameterInjection(t *testing.T) {
	cases := []struct{ issuer, account string }{
		{"Example", "x&secret=AAAA&issuer=evil"},
		{"Example", "x?secret=AAAA&issuer=evil"},
		{"Example&secret=AAAA", "alice"},
		{"Example", "x#&secret=AAAA"},
	}
	for _, c := range cases {
		raw := URI(c.issuer, c.account, wikiSecret)
		p := parseURI(t, raw)
		if p.labelIssuer != c.issuer || p.account != c.account {
			t.Errorf("label = %q:%q, want %q:%q (URI %s)", p.labelIssuer, p.account, c.issuer, c.account, raw)
		}
		checkParams(t, p, wikiSecret)
	}
}
