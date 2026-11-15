package ratelimit

import (
	"net/netip"
)

// Reservation is an admitted Attempt. Only the first of Succeed, Fail and
// Cancel acts; every later call does nothing.
type Reservation struct {
	ip        netip.Addr
	l         *Limiter
	account   Account
	device    deviceKey // set for an attempt with an account; its id is valid only when trusted
	id        uint64
	trusted   bool
	known     bool // trusted, through a cookie a secure sign-in sealed
	settled   bool
	ipOmitted bool // the Attempt's OmitIP: r added no IP entry
}

// Succeed is for the step that completes a sign-in: it removes this
// reservation's own entries and clears the succeeding account's bucket for
// this client (the device bucket for a valid device cookie, else the
// untrusted bucket). It never touches other accounts' failures in the IP
// window. The device cookie is Limiter.DeviceCookie's.
func (r *Reservation) Succeed() {
	r.settle(func() {
		r.removeIP()
		switch {
		case r.trusted:
			r.l.device.clear(r.device)
		case !r.account.isZero():
			r.l.account.clear(r.account)
		}
	})
}

// Fail settles the reservation as the failure it already counts.
func (r *Reservation) Fail() { r.settle(func() {}) }

// Cancel removes this reservation's entries without crediting a success, so
// the attempt neither counts nor forgives and earlier failures stay. It is
// for a server-side refusal before anything was counted or verified (a hash
// permit refused), and for a correct first factor that did not sign in (a
// pending sign-in, or a refusal after it), except a sign-in the SSO mode
// refuses, which Fail settles as a wrong secret.
func (r *Reservation) Cancel() {
	r.settle(func() {
		r.removeIP()
		switch {
		case r.trusted:
			r.l.device.remove(r.device, r.id)
		case !r.account.isZero():
			r.l.account.remove(r.account, r.id)
		}
	})
}

func (r *Reservation) removeIP() {
	if !r.ipOmitted {
		r.l.ip.remove(r.ip, r.id)
	}
}

// Trusted reports whether the attempt carried a valid device cookie for its
// account.
func (r *Reservation) Trusted() bool { return r.trusted }

// KnownDevice reports whether the attempt's valid device cookie was sealed by
// a sign-in on a secure request: a cookie a plain response carried serves
// the limiter, and a reader of that response cannot replay it to pass as
// known.
func (r *Reservation) KnownDevice() bool { return r.known }

// settle runs f under the limiter's lock unless r is already settled.
func (r *Reservation) settle(f func()) {
	r.l.mu.Lock()
	defer r.l.mu.Unlock()
	if r.settled {
		return
	}
	r.settled = true
	f()
}
