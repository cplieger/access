// Package totp computes and checks time-based one-time passwords on the
// standard library: RFC 6238 over RFC 4226's HOTP, fixed at HMAC-SHA-1,
// six digits and a 30-second step, since Google Authenticator ignores any
// other algorithm, length or period. It emits the Key Uri Format and never
// parses one. Replay protection is the caller's: Match returns the step it
// accepted, and the caller stores it and passes it back as after.
package totp
