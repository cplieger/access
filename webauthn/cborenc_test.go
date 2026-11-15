package webauthn

import (
	"encoding/binary"
	"fmt"
)

// cborMap is a CBOR map's keys and values, interleaved in encoding order.
type cborMap []any

// cborRaw is an already encoded item, written as is.
type cborRaw []byte

// cborEnc encodes v in RFC 8949's preferred serialization, for building test
// inputs; it covers the types WebAuthn's structures use.
func cborEnc(v any) []byte {
	switch v := v.(type) {
	case int:
		if v < 0 {
			return cborHead(nil, 1, uint64(-1-v))
		}
		return cborHead(nil, 0, uint64(v))
	case []byte:
		return append(cborHead(nil, 2, uint64(len(v))), v...)
	case string:
		return append(cborHead(nil, 3, uint64(len(v))), v...)
	case bool:
		if v {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case []any:
		out := cborHead(nil, 4, uint64(len(v)))
		for _, e := range v {
			out = append(out, cborEnc(e)...)
		}
		return out
	case cborMap:
		out := cborHead(nil, 5, uint64(len(v)/2))
		for _, e := range v {
			out = append(out, cborEnc(e)...)
		}
		return out
	case cborRaw:
		return v
	default:
		panic(fmt.Sprintf("cborEnc: %T", v))
	}
}

func cborHead(out []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(out, m|byte(n))
	case n <= 0xff:
		return append(out, m|24, byte(n))
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16(append(out, m|25), uint16(n))
	case n <= 0xffffffff:
		return binary.BigEndian.AppendUint32(append(out, m|26), uint32(n))
	default:
		return binary.BigEndian.AppendUint64(append(out, m|27), n)
	}
}
