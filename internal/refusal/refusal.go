// Package refusal writes one refusal the way [access.ErrorWriter]'s contract
// promises, for every tree that answers through one.
package refusal

import (
	"net/http"
	"strconv"
	"time"

	"github.com/cplieger/access"
)

// Write sets Cache-Control: no-store, a's challenge for e.Code with scope,
// and, when e.RetryAfter is set, Retry-After in whole seconds rounded up;
// then it hands e to write.
func Write(w http.ResponseWriter, r *http.Request, a *access.Authenticator, write access.ErrorWriter, e access.Error, scope string) { //nolint:gocritic // hugeParam: the ErrorWriter takes the Error by value
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	a.Challenge(h, e.Code, scope)
	if e.RetryAfter > 0 {
		h.Set("Retry-After", strconv.FormatInt(int64((e.RetryAfter+time.Second-1)/time.Second), 10))
	}
	write(w, r, e)
}
