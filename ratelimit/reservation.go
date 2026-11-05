package ratelimit

import (
	"net/netip"

	"github.com/cplieger/access"
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
	settled   bool
	ipOmitted bool // the Attempt's OmitIP: r added no IP entry
}

// Succeed removes this reservation's own entries, clears the succeeding
// account's bucket for this client (the device bucket for a valid device
// cookie, else the untrusted bucket), and returns a fresh device cookie,
// which keeps a trusted attempt's device ID. It never touches other
// accounts' failures in the IP window. It returns the zero Secret for an
// IP-only attempt and once the reservation is settled.
func (r *Reservation) Succeed() (deviceCookie access.Secret) {
	acted := r.settle(func() {
		r.removeIP()
		switch {
		case r.trusted:
			r.l.device.clear(r.device)
		case !r.account.isZero():
			r.l.account.clear(r.account)
		}
	})
	if !acted || r.account.isZero() {
		return access.Secret{}
	}
	id := r.device.id
	if !r.trusted {
		id = newDeviceID()
	}
	return r.l.sealDevice(r.account, id, r.l.now())
}

// Fail settles the reservation as the failure it already counts.
func (r *Reservation) Fail() { r.settle(func() {}) }

// Cancel removes this reservation's entries without crediting a success. It
// is for a server-side refusal before anything was counted or verified (a
// hash permit refused).
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

// settle runs f under the limiter's lock unless r is already settled, and
// reports whether it ran.
func (r *Reservation) settle(f func()) bool {
	r.l.mu.Lock()
	defer r.l.mu.Unlock()
	if r.settled {
		return false
	}
	r.settled = true
	f()
	return true
}
