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
	// devicePayloadLen is the sealed payload: the account's digest, then
	// the device ID.
	devicePayloadLen = sha256.Size + deviceIDLen
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

// DeviceCookie returns a fresh device cookie for acct after a successful
// sign-in that ran no Attempt (passkey, OIDC). It keeps the device ID of a
// presented cookie that is valid for acct, so a device stays one device,
// and returns the zero Secret for the zero Account.
func (l *Limiter) DeviceCookie(acct Account, presented access.Secret) access.Secret {
	if acct.isZero() {
		return access.Secret{}
	}
	now := l.now()
	id, ok := l.openDevice(acct, presented, now)
	if !ok {
		id = newDeviceID()
	}
	return l.sealDevice(acct, id, now)
}

// openDevice returns the device ID of presented when it is a device cookie
// sealed for acct and unexpired at now.
func (l *Limiter) openDevice(acct Account, presented access.Secret, now time.Time) (deviceID, bool) {
	if presented.IsZero() {
		return deviceID{}, false
	}
	payload, err := l.devices.Open(devicePurpose, presented.Reveal(), now)
	if err != nil || len(payload) != devicePayloadLen {
		return deviceID{}, false
	}
	if !bytes.Equal(payload[:sha256.Size], acct.digest[:]) {
		return deviceID{}, false
	}
	return deviceID(payload[sha256.Size:]), true
}

func (l *Limiter) sealDevice(acct Account, id deviceID, now time.Time) access.Secret {
	payload := append(acct.digest[:], id[:]...)
	sealed, err := l.devices.Seal(devicePurpose, payload, now.Add(deviceLifetime))
	if err != nil {
		// Seal refuses only a payload over access.MaxSealPayload, and this
		// one is always devicePayloadLen bytes.
		panic(fmt.Sprintf("ratelimit: sealing the fixed %d-byte device payload: %v", devicePayloadLen, err))
	}
	return access.NewSecret(sealed)
}
