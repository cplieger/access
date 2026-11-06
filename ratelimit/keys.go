package ratelimit

import (
	"crypto/sha256"
	"net/netip"

	"github.com/cplieger/access"
)

// maxRawAccountKey caps the raw bytes of a refused username that its key's
// digest covers, and nothing more: AccountKey still passes the whole input to
// access.NormalizeUsername first.
const maxRawAccountKey = 256

// IP is the IP dimension's key. Build it with IPKey; the zero value is the
// shared "unknown" key, the one IPKey returns for the zero netip.Addr.
type IP struct{ addr netip.Addr }

// IPKey returns addr's key. A 4in6 address keys as its IPv4 form, IPv4
// keeps all 32 bits, an IPv6 zone is dropped, and IPv6 is masked to
// Config.IPv6Prefix when the Limiter admits it. The zero Addr maps to one
// shared "unknown" key.
func IPKey(addr netip.Addr) IP {
	return IP{addr: addr.Unmap().WithZone("")}
}

// bucket returns ip's admission key under an IPv6 prefix of bits.
func (ip IP) bucket(bits int) netip.Addr {
	if !ip.addr.Is6() {
		return ip.addr // IPv4 /32, or the zero "unknown" key
	}
	p, _ := ip.addr.Prefix(bits) // New refuses a bits outside [48, 128], Prefix's only error
	return p.Addr()
}

// Account is the account dimension's key. Build it with AccountKey; the
// zero value means no account, an IP-only Attempt.
type Account struct {
	// digest is the SHA-256 of a raw flag byte and the key bytes, so every
	// key, and the device cookie naming it, has one size whatever the
	// name's length, and a refused name never equals a canonical one.
	digest [sha256.Size]byte
}

// AccountKey returns username's key: its access.NormalizeUsername form, so
// every spelling of one account shares one key. A refused input keys as its
// raw bytes capped at 256, apart from every canonical name, so a refusal
// never escapes the account dimension. Every key has the same fixed size,
// however long the username.
func AccountKey(username string) Account {
	if canonical, err := access.NormalizeUsername(username); err == nil {
		return accountOf(false, canonical)
	}
	return accountOf(true, username[:min(len(username), maxRawAccountKey)])
}

func accountOf(raw bool, key string) Account {
	flag := byte(0)
	if raw {
		flag = 1
	}
	return Account{digest: sha256.Sum256(append([]byte{flag}, key...))}
}

func (a Account) isZero() bool { return a == Account{} }
