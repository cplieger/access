package ratelimit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/cplieger/access"
)

const (
	devicePurpose  = "ratelimit-device"
	deviceLifetime = 180 * 24 * time.Hour
	deviceIDLen    = 16
	// devicePayloadLen is the sealed payload: the account's digest, the
	// device ID, then 1 when a secure sign-in sealed it, else 0.
	devicePayloadLen = sha256.Size + deviceIDLen + 1
)

type deviceID [deviceIDLen]byte

// deviceKey is the device dimension's key: one device of one account.
type deviceKey struct {
	acct Account
	id   deviceID
}

func newDeviceID() deviceID {
	var id deviceID
	rand.Read(id[:]) // never returns an error (Go 1.24+); it crashes instead
	return id
}

// DeviceCookie returns a fresh device cookie for acct after a completed
// sign-in, and is the only place one is sealed. It keeps the device ID of a
// presented cookie that is valid for acct, so a device stays one device, and
// seals secure, the minting request's transport, never the presented
// cookie's: only a cookie a secure sign-in sealed makes a known device
// (Reservation.KnownDevice). It returns the zero Secret for the zero Account.
func (l *Limiter) DeviceCookie(acct Account, presented access.Secret, secure bool) access.Secret {
	if acct.isZero() {
		return access.Secret{}
	}
	now := l.now()
	id, _, ok := l.openDevice(acct, presented, now)
	if !ok {
		id = newDeviceID()
	}
	return l.sealDevice(acct, id, secure, now)
}

// openDevice returns the device ID of presented and its secure bit when it
// is a device cookie sealed for acct and unexpired at now.
func (l *Limiter) openDevice(acct Account, presented access.Secret, now time.Time) (id deviceID, secure, ok bool) {
	if presented.IsZero() {
		return deviceID{}, false, false
	}
	payload, err := l.devices.Open(devicePurpose, presented.Reveal(), now)
	if err != nil || len(payload) != devicePayloadLen {
		return deviceID{}, false, false
	}
	flag := payload[devicePayloadLen-1]
	if flag > 1 || !bytes.Equal(payload[:sha256.Size], acct.digest[:]) {
		return deviceID{}, false, false
	}
	return deviceID(payload[sha256.Size : sha256.Size+deviceIDLen]), flag == 1, true
}

func (l *Limiter) sealDevice(acct Account, id deviceID, secure bool, now time.Time) access.Secret {
	var flag byte
	if secure {
		flag = 1
	}
	payload := append(append(acct.digest[:], id[:]...), flag)
	sealed, err := l.devices.Seal(devicePurpose, payload, now.Add(deviceLifetime))
	if err != nil {
		// Seal refuses only a payload over access.MaxSealPayload, and this
		// one is always devicePayloadLen bytes.
		panic(fmt.Sprintf("ratelimit: sealing the fixed %d-byte device payload: %v", devicePayloadLen, err))
	}
	return access.NewSecret(sealed)
}
