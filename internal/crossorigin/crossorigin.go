// Package crossorigin is the one cross-origin check every tree serving a
// session cookie runs before an unsafe-method route.
package crossorigin

import "net/http"

// Guard serves next behind [http.CrossOriginProtection], answering a refused
// request with deny.
func Guard(next, deny http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(deny)
	return cop.Handler(next)
}
