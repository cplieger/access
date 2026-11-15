package jsonmember_test

import (
	"encoding/json/jsontext"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/cplieger/access/oidc/internal/jsonmember"
)

// FuzzNumericDate_exact: NumericDate accepts exactly the JSON numbers (RFC
// 8259 §6) whose exact value lies in [0, 253402300799] (RFC 7519 §2), and
// yields their floor; the oracle is big.Rat's exact decimal reading, so no
// float rounding can make it agree with a broken parser.
func FuzzNumericDate_exact(f *testing.F) {
	for _, seed := range []string{
		`0`, `-0`, `1760000000`, `1760000000.999`, `1.76e9`, `253402300799`, `253402300799.5`, `253402300800`,
		`-1e-400`, `1e-400`, `1e300`, `-0.1`, `0.000000000000000000001e25`, `2.53402300799e11`, `1E+3`,
		`"1"`, `null`, `01`, `.5`, `1e99999999999999999999`, ` 5 `, `5 5`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, num string) {
		got, ok := jsonmember.NumericDate(jsontext.Value(num))
		v := jsontext.Value(num)
		if v.Kind() != '0' || !v.IsValid() {
			if ok {
				t.Fatalf("NumericDate(%q) = %v, true for a value that is not one JSON number", num, got)
			}
			return
		}
		r, exact := exactValue(strings.TrimSpace(num))
		if !exact {
			return
		}
		inRange := r.Sign() >= 0 && r.Cmp(new(big.Rat).SetInt64(253402300799)) <= 0
		if ok != inRange {
			t.Fatalf("NumericDate(%q) ok = %v, want %v", num, ok, inRange)
		}
		if ok {
			floor := new(big.Int).Quo(r.Num(), r.Denom())
			if got.Unix() != floor.Int64() {
				t.Fatalf("NumericDate(%q) = %d, want %d", num, got.Unix(), floor.Int64())
			}
		}
	})
}

// exactValue reads num exactly; false for an exponent too large for
// big.Rat to expand at a test's cost.
func exactValue(num string) (*big.Rat, bool) {
	if i := strings.IndexAny(num, "eE"); i >= 0 {
		e, err := strconv.ParseInt(strings.TrimPrefix(num[i+1:], "+"), 10, 32)
		if err != nil || e > 400 || e < -400 {
			return nil, false
		}
	}
	r, ok := new(big.Rat).SetString(num)
	return r, ok
}
