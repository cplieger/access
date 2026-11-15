package jws_test

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/access/oidc/internal/jwk"
	"github.com/cplieger/access/oidc/internal/jws"
)

// Project Wycheproof's vectors run through jwk.Parse and Token.Verify.
// testdata/wycheproof holds the files byte for byte from C2SP/wycheproof
// (Apache License 2.0), and its MANIFEST pins the commit and each file's
// SHA-256.
const wycheproofDir = "testdata/wycheproof"

// wpSuite is one primitive-signature suite and the row its cases verify
// under. saltNotHash marks a PSS suite signed with a salt other than the
// hash's size, which RFC 7518 §3.5 forbids, so a case verifies only when
// its salt is the hash's size, valid ones refused otherwise.
type wpSuite struct {
	file        string
	alg         jwk.Alg
	saltNotHash bool
}

var wpSignatureSuites = []wpSuite{
	{file: "ecdsa_secp256r1_sha256_p1363_test.json", alg: jwk.ES256},
	{file: "ecdsa_secp384r1_sha384_p1363_test.json", alg: jwk.ES384},
	{file: "ecdsa_secp521r1_sha512_p1363_test.json", alg: jwk.ES512},
	{file: "rsa_signature_2048_sha256_test.json", alg: jwk.RS256},
	{file: "rsa_signature_2048_sha384_test.json", alg: jwk.RS384},
	{file: "rsa_signature_2048_sha512_test.json", alg: jwk.RS512},
	{file: "rsa_signature_3072_sha256_test.json", alg: jwk.RS256},
	{file: "rsa_signature_3072_sha384_test.json", alg: jwk.RS384},
	{file: "rsa_signature_3072_sha512_test.json", alg: jwk.RS512},
	{file: "rsa_signature_4096_sha256_test.json", alg: jwk.RS256},
	{file: "rsa_signature_4096_sha384_test.json", alg: jwk.RS384},
	{file: "rsa_signature_4096_sha512_test.json", alg: jwk.RS512},
	{file: "rsa_pss_2048_sha256_mgf1_32_test.json", alg: jwk.PS256},
	{file: "rsa_pss_2048_sha384_mgf1_48_test.json", alg: jwk.PS384},
	{file: "rsa_pss_3072_sha256_mgf1_32_test.json", alg: jwk.PS256},
	{file: "rsa_pss_4096_sha256_mgf1_32_test.json", alg: jwk.PS256},
	{file: "rsa_pss_4096_sha384_mgf1_48_test.json", alg: jwk.PS384},
	{file: "rsa_pss_4096_sha512_mgf1_64_test.json", alg: jwk.PS512},
	{file: "rsa_pss_2048_sha256_mgf1_0_test.json", alg: jwk.PS256, saltNotHash: true},
	{file: "rsa_pss_4096_sha512_mgf1_32_test.json", alg: jwk.PS512, saltNotHash: true},
	{file: "ed25519_test.json", alg: jwk.EdDSA},
}

const (
	wpJWSFile = "json_web_signature_test.json"
	wpJWKFile = "json_web_key_test.json"
)

type wpFile struct {
	TestGroups []wpGroup `json:"testGroups"`
}

type wpGroup struct {
	PublicKeyJWK jsontext.Value `json:"publicKeyJwk"`
	KeyJWK       jsontext.Value `json:"keyJwk"`
	Public       jsontext.Value `json:"public"`
	Private      jsontext.Value `json:"private"`
	PublicKey    struct {
		Modulus        string `json:"modulus"`
		PublicExponent string `json:"publicExponent"`
		Uncompressed   string `json:"uncompressed"`
		PK             string `json:"pk"`
	} `json:"publicKey"`
	SHA    string   `json:"sha"`
	MGFSHA string   `json:"mgfSha"`
	Tests  []wpCase `json:"tests"`
	SLen   int      `json:"sLen"`
}

type wpCase struct {
	Comment string   `json:"comment"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	JWS     string   `json:"jws"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
	TcID    int      `json:"tcId"`
}

func (c wpCase) name() string { return fmt.Sprintf("tc%d %s", c.TcID, c.Comment) }

func wpLoad(t *testing.T, file string) wpFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(wycheproofDir, file))
	if err != nil {
		t.Fatal(err)
	}
	var f wpFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if len(f.TestGroups) == 0 {
		t.Fatalf("%s: no test groups", file)
	}
	return f
}

func present(v jsontext.Value) bool { return len(v) > 0 && v.Kind() != 'n' }

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func keySet(t *testing.T, keys ...jsontext.Value) (jwk.Set, error) {
	t.Helper()
	doc, err := json.Marshal(map[string][]jsontext.Value{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return jwk.Parse(doc)
}

// wpGroupJWK is the group's own JWK, or, where Wycheproof gives none, the
// JWK of its raw public key: RFC 7518 §6.3.1's n and e, §6.2.1's x and y
// from the SEC 1 uncompressed point, or RFC 8037 §2's x.
func wpGroupJWK(t *testing.T, g wpGroup, alg jwk.Alg) jsontext.Value {
	t.Helper()
	for _, v := range []jsontext.Value{g.PublicKeyJWK, g.KeyJWK} {
		if present(v) {
			return v
		}
	}
	var m map[string]string
	switch alg.Scheme() {
	case jwk.PKCS1v15, jwk.PSS:
		m = map[string]string{"kty": "RSA", "n": b64(mustHex(t, g.PublicKey.Modulus)), "e": b64(mustHex(t, g.PublicKey.PublicExponent))}
	case jwk.ECDSA:
		pt := mustHex(t, g.PublicKey.Uncompressed)
		size := (len(pt) - 1) / 2
		crv := map[jwk.Alg]string{jwk.ES256: "P-256", jwk.ES384: "P-384", jwk.ES512: "P-521"}[alg]
		m = map[string]string{"kty": "EC", "crv": crv, "x": b64(pt[1 : 1+size]), "y": b64(pt[1+size:])}
	case jwk.Ed25519:
		m = map[string]string{"kty": "OKP", "crv": "Ed25519", "x": b64(mustHex(t, g.PublicKey.PK))}
	}
	v, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func allFlagged(g wpGroup, flag string) bool {
	return len(g.Tests) > 0 && !slices.ContainsFunc(g.Tests, func(c wpCase) bool { return !slices.Contains(c.Flags, flag) })
}

// wpSignatureVerdict is access's verdict on a primitive case and, where it
// is not Wycheproof's own, the reading that decides it.
func wpSignatureVerdict(s wpSuite, c wpCase) (verifies bool, reading string) {
	switch {
	case s.saltNotHash && c.Comment == fmt.Sprintf("s_len changed to %d", s.alg.Hash().Size()):
		return true, "RFC 7518 §3.5: re-salted to the hash's size, the case is a valid " + s.alg.String() + " signature"
	case s.saltNotHash:
		return false, "RFC 7518 §3.5: the PSS salt must be the hash's size"
	case c.Result == "valid":
		return true, ""
	case c.Result == "invalid":
		return false, ""
	case slices.Contains(c.Flags, "MissingNull"):
		return false, "RFC 8017 §9.2: the DigestInfo carries the NULL parameters, and §8.2.2 compares the encodings octet for octet"
	case slices.Contains(c.Flags, "SmallOrderPublicKey"):
		return false, "RFC 8032 §5.1.7: a key of small order verifies a forgery, so jwk skips it"
	case slices.Contains(c.Flags, "MixedOrderPublicKey"):
		return true, "RFC 8032 §5.1.7: the signature meets the verification equation, and only a small-order key is skipped"
	}
	return false, "no reading"
}

var wpHashNames = map[jwk.Alg]string{
	jwk.RS256: "SHA-256", jwk.RS384: "SHA-384", jwk.RS512: "SHA-512",
	jwk.PS256: "SHA-256", jwk.PS384: "SHA-384", jwk.PS512: "SHA-512",
	jwk.ES256: "SHA-256", jwk.ES384: "SHA-384", jwk.ES512: "SHA-512",
}

// TestWycheproof_Signatures runs the ECDSA P1363 (RFC 7518 §3.4), RSASSA
// PKCS #1 v1.5 (§3.3, RFC 8017 §8.2), RSASSA-PSS (§3.5) and Ed25519 (RFC
// 8037 §3.1, RFC 8032 §5.1.7) suites, each case by its verdict.
func TestWycheproof_Signatures(t *testing.T) {
	readings := map[string]int{}
	for _, s := range wpSignatureSuites {
		t.Run(strings.TrimSuffix(s.file, "_test.json"), func(t *testing.T) {
			f := wpLoad(t, s.file)
			for _, g := range f.TestGroups {
				wpCheckGroupParams(t, s, g)
				smallOrder := allFlagged(g, "SmallOrderPublicKey")
				set, err := keySet(t, wpGroupJWK(t, g, s.alg))
				if err != nil {
					t.Fatalf("group key refused the set: %v", err)
				}
				// Every suite key is usable but Ed25519's small-order ones
				// (RFC 8032 §5.1.7); RSA moduli all lie in [2048, 4096].
				if want := map[bool]int{false: 1, true: 0}[smallOrder]; set.Len() != want {
					t.Fatalf("group key: %d usable keys; want %d", set.Len(), want)
				}
				for _, c := range g.Tests {
					want, reading := wpSignatureVerdict(s, c)
					if reading == "no reading" {
						t.Errorf("%s: %s case with flags %v has no reading", c.name(), c.Result, c.Flags)
						continue
					}
					if reading != "" {
						readings[reading]++
					}
					_, err := jws.RawToken(s.alg, mustHex(t, c.Msg), mustHex(t, c.Sig)).Verify(set)
					switch {
					case want && err != nil:
						t.Errorf("%s (%s): %v; want it to verify", c.name(), c.Result, err)
					case !want && !errors.Is(err, jws.ErrNoKey):
						t.Errorf("%s (%s, %s): err = %v; want ErrNoKey", c.name(), c.Result, reading, err)
					}
				}
			}
		})
	}
	// Each reading's reach, counted from the files, so a widened one fails.
	want := map[string]int{
		"RFC 7518 §3.5: re-salted to the hash's size, the case is a valid PS256 signature":                             1,
		"RFC 7518 §3.5: the PSS salt must be the hash's size":                                                          279,
		"RFC 8017 §9.2: the DigestInfo carries the NULL parameters, and §8.2.2 compares the encodings octet for octet": 9,
		"RFC 8032 §5.1.7: a key of small order verifies a forgery, so jwk skips it":                                    8,
		"RFC 8032 §5.1.7: the signature meets the verification equation, and only a small-order key is skipped":        21,
	}
	if fmt.Sprint(readings) != fmt.Sprint(want) {
		t.Errorf("cases decided by a reading: %v; want %v", readings, want)
	}
}

// wpCheckGroupParams holds a group to the row it runs under: the row's
// hash, and for PSS an MGF1 of the same hash (RFC 7518 §3.5) and a salt the
// hash's size unless the suite is marked saltNotHash.
func wpCheckGroupParams(t *testing.T, s wpSuite, g wpGroup) {
	t.Helper()
	if s.alg == jwk.EdDSA {
		return
	}
	if g.SHA != wpHashNames[s.alg] {
		t.Fatalf("group hash %s; the suite runs under %s", g.SHA, s.alg)
	}
	if s.alg.Scheme() != jwk.PSS {
		return
	}
	if g.MGFSHA != g.SHA {
		t.Fatalf("MGF1 hash %s differs from %s", g.MGFSHA, g.SHA)
	}
	if saltIsHash := g.SLen == s.alg.Hash().Size(); saltIsHash == s.saltNotHash {
		t.Fatalf("salt %d bytes against a %d-byte hash, saltNotHash %v", g.SLen, s.alg.Hash().Size(), s.saltNotHash)
	}
}

// The accepted algorithms by their registered names (RFC 7518 §3.1, RFC
// 8037 §3.1, RFC 9864 §2.2), written out so a reading never asks the code
// under test what it accepts.
var wpAccessAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"}

func wpHeaderAlg(token string) (string, bool) {
	h, _, _ := strings.Cut(token, ".")
	raw, err := base64.RawURLEncoding.Strict().DecodeString(h)
	if err != nil {
		return "", false
	}
	var head struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return "", false
	}
	return head.Alg, true
}

func wpKeyAlg(t *testing.T, key jsontext.Value) (string, bool) {
	t.Helper()
	var m map[string]jsontext.Value
	if err := json.Unmarshal(key, &m); err != nil {
		t.Fatal(err)
	}
	v, ok := m["alg"]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		t.Fatal(err)
	}
	return s, true
}

// wpJOSEVerdict reads a valid JOSE case as a refusal when its header is
// not base64url (RFC 7515 §2), its header names an algorithm outside
// wpAccessAlgs (RFC 8725 §3.1: HS* and none are refused whatever the key),
// or a key's alg is not one of them or names another algorithm than the
// header's (RFC 7517 §4.4).
func wpJOSEVerdict(t *testing.T, c wpCase, keys []jsontext.Value) (verifies bool, reading string) {
	t.Helper()
	if c.Result != "valid" {
		return false, ""
	}
	alg, ok := wpHeaderAlg(c.JWS)
	switch {
	case !ok:
		return false, "the header is not base64url JSON"
	case !slices.Contains(wpAccessAlgs, alg):
		return false, "header alg " + alg + " is not an accepted algorithm"
	}
	for _, k := range keys {
		switch keyAlg, has := wpKeyAlg(t, k); {
		case has && !slices.Contains(wpAccessAlgs, keyAlg):
			return false, "key alg " + keyAlg + " is not a JWS algorithm, so the key is skipped"
		case has && keyAlg != alg:
			return false, "key alg " + keyAlg + " does not name the header's " + alg
		}
	}
	return true, ""
}

func wpVerify(token string, set jwk.Set) error {
	tok, err := jws.Parse(token, allAlgs)
	if err != nil {
		return err
	}
	_, err = tok.Verify(set)
	return err
}

// TestWycheproof_JSONWebSignature runs json_web_signature_test.json under
// every accepted row: each group's public JWK, or its only key when it has
// none, as the set. The embedded attacker jwk, symmetric confusion, none
// with no signature, an extra component and the JSON serialization are
// among its invalid cases.
func TestWycheproof_JSONWebSignature(t *testing.T) {
	f := wpLoad(t, wpJWSFile)
	readings := map[string]int{}
	verified := 0
	for _, g := range f.TestGroups {
		key := g.Public
		if !present(key) {
			key = g.Private
		}
		set, err := keySet(t, key)
		if err != nil {
			t.Fatalf("group key refused the set: %v", err)
		}
		for _, c := range g.Tests {
			want, reading := wpJOSEVerdict(t, c, []jsontext.Value{key})
			err := wpVerify(c.JWS, set)
			switch {
			case want && err != nil:
				t.Errorf("%s: %v; want it to verify", c.name(), err)
			case want:
				verified++
			case err == nil:
				t.Errorf("%s (%s %s): verified; want refused", c.name(), c.Result, reading)
			case reading != "":
				readings[reading]++
			}
		}
	}
	// Of Wycheproof's 46 valid cases, 14 are read as refusals: 9 HS256, one
	// whose header holds a '?', and the RFC 7520 keys, which carry the alg
	// ES521 that RFC 7518 §3.1 does not register, or PS256 under PS384.
	if verified != 32 {
		t.Errorf("%d valid cases verified; want 32", verified)
	}
	wantReadings := map[string]int{
		"header alg HS256 is not an accepted algorithm":               9,
		"the header is not base64url JSON":                            1,
		"key alg ES521 is not a JWS algorithm, so the key is skipped": 2,
		"key alg PS256 does not name the header's PS384":              2,
	}
	if fmt.Sprint(readings) != fmt.Sprint(wantReadings) {
		t.Errorf("valid cases read as refusals: %v; want %v", readings, wantReadings)
	}
}

// RFC 7518 §6.2.2 and §6.3.2's private parameters, and RFC 8037 §2's d.
var wpPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth"}

// wpPublished is the set a provider publishes from a private one: each
// RSA, EC and OKP key with its private parameters removed (RFC 7517 §4).
func wpPublished(t *testing.T, private jsontext.Value) []jsontext.Value {
	t.Helper()
	var doc struct {
		Keys []map[string]jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(private, &doc); err != nil {
		t.Fatal(err)
	}
	out := make([]jsontext.Value, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		if kty := string(k["kty"]); kty == `"RSA"` || kty == `"EC"` || kty == `"OKP"` {
			for _, name := range wpPrivateMembers {
				delete(k, name)
			}
		}
		v, err := json.Marshal(k)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

func wpHasPrivateAsymmetricKey(t *testing.T, private jsontext.Value) bool {
	t.Helper()
	var doc struct {
		Keys []map[string]jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(private, &doc); err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(doc.Keys, func(k map[string]jsontext.Value) bool {
		kty := string(k["kty"])
		_, hasD := k["d"]
		return hasD && (kty == `"RSA"` || kty == `"EC"` || kty == `"OKP"`)
	})
}

// TestWycheproof_JSONWebKey runs json_web_key_test.json, whose groups give
// a private JWK Set, twice: as given, where jwk refuses every set that
// publishes a private RSA, EC or OKP key, and as a provider would publish
// it, by verdict.
func TestWycheproof_JSONWebKey(t *testing.T) {
	f := wpLoad(t, wpJWKFile)
	t.Run("as given", func(t *testing.T) {
		for _, g := range f.TestGroups {
			set, err := jwk.Parse(g.Private)
			if private := wpHasPrivateAsymmetricKey(t, g.Private); private != errors.Is(err, jwk.ErrSet) {
				t.Errorf("tc%d: Parse err = %v; publishes a private key: %v", g.Tests[0].TcID, err, private)
				continue
			}
			for _, c := range g.Tests {
				if err == nil && wpVerify(c.JWS, set) == nil {
					t.Errorf("%s (%s): verified; want refused", c.name(), c.Result)
				}
			}
		}
	})
	t.Run("published", func(t *testing.T) {
		verified := 0
		for _, g := range f.TestGroups {
			keys := wpPublished(t, g.Private)
			set, err := keySet(t, keys...)
			if err != nil {
				t.Fatalf("tc%d: published set refused: %v", g.Tests[0].TcID, err)
			}
			for _, c := range g.Tests {
				want, reading := wpJOSEVerdict(t, c, keys)
				err := wpVerify(c.JWS, set)
				switch {
				case want && err != nil:
					t.Errorf("%s: %v; want it to verify", c.name(), err)
				case want:
					verified++
				case err == nil:
					t.Errorf("%s (%s %s): verified; want refused", c.name(), c.Result, reading)
				}
			}
		}
		// Of the 5 valid cases, 4 are HS256, HS384 and HS512.
		if verified != 1 {
			t.Errorf("%d valid cases verified; want 1", verified)
		}
	})
}

// TestWycheproof_Manifest holds testdata/wycheproof to its MANIFEST: every
// file listed with its SHA-256, and every listed file read by a test above.
func TestWycheproof_Manifest(t *testing.T) {
	mf, err := os.Open(filepath.Join(wycheproofDir, "MANIFEST"))
	if err != nil {
		t.Fatal(err)
	}
	defer mf.Close()
	listed := map[string]string{}
	sc := bufio.NewScanner(mf)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("MANIFEST line %q is not <sha256>  <file>", line)
		}
		listed[name] = sum
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(wycheproofDir)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []string
	for _, e := range entries {
		if e.Name() == "MANIFEST" {
			continue
		}
		onDisk = append(onDisk, e.Name())
		data, err := os.ReadFile(filepath.Join(wycheproofDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != listed[e.Name()] {
			t.Errorf("%s: SHA-256 %x; MANIFEST lists %q", e.Name(), got, listed[e.Name()])
		}
	}
	read := []string{wpJWSFile, wpJWKFile}
	for _, s := range wpSignatureSuites {
		read = append(read, s.file)
	}
	var names []string
	for n := range listed {
		names = append(names, n)
	}
	slices.Sort(onDisk)
	slices.Sort(names)
	slices.Sort(read)
	if !slices.Equal(onDisk, names) {
		t.Errorf("files %v; MANIFEST lists %v", onDisk, names)
	}
	if !slices.Equal(names, read) {
		t.Errorf("MANIFEST lists %v; the tests read %v", names, read)
	}
}
