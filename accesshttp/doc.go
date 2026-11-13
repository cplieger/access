// Package accesshttp serves the access HTTP routes over an account.Service. It
// mounts nothing itself: Routes returns each route's Descriptor and handler
// for the app's own mux, and every refusal goes through the app's
// [access.ErrorWriter].
package accesshttp
