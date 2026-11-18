// Package crockford is Douglas Crockford's base32
// (https://www.crockford.com/base32.html): the symbols 0-9 and A-Z
// without I, L, O and U, five bits each, most significant bit first. It
// has no check symbol; a caller that wants one carries its own.
package crockford

// alphabet is the encode symbol set, indexed by symbol value.
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// decodeTable maps an encode symbol to its value, and every other byte to
// 0xFF.
var decodeTable = func() [256]byte {
	var t [256]byte
	for i := range t {
		t[i] = 0xFF
	}
	for i := range len(alphabet) {
		t[alphabet[i]] = byte(i)
	}
	return t
}()

// Encode returns b in encode symbols, most significant bit first, the last
// symbol padded with zero bits.
func Encode(b []byte) string {
	out := make([]byte, 0, (len(b)*8+4)/5)
	var acc uint
	bits := 0
	for _, c := range b {
		acc = acc<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, alphabet[(acc>>bits)&0x1F])
		}
	}
	if bits > 0 {
		out = append(out, alphabet[(acc<<(5-bits))&0x1F])
	}
	return string(out)
}

// Decode returns the bytes s encodes, accepting only what Encode returns:
// encode symbols alone, no symbol beyond the bytes' last bit, and zero
// padding bits, so Encode(Decode(s)) == s whenever ok. Run Normalize first
// for typed input.
func Decode(s string) (b []byte, ok bool) {
	n := len(s) * 5 / 8
	if (n*8+4)/5 != len(s) {
		return nil, false
	}
	out := make([]byte, 0, n)
	var acc uint
	bits := 0
	for i := range len(s) {
		v := decodeTable[s[i]]
		if v == 0xFF {
			return nil, false
		}
		acc = acc<<5 | uint(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits)) //nolint:gosec // G115: the conversion keeps the low eight bits, the byte just completed
		}
	}
	if acc&(1<<bits-1) != 0 {
		return nil, false
	}
	return out, true
}

// Normalize applies Crockford's decode reading to typed input: it removes
// ASCII '-' and space, folds ASCII a-z to upper case, and maps O and o to
// 0 and I, i, L and l to 1. Every other rune is kept as it is, so a value
// holding one never decodes. It folds byte by byte, never with Unicode
// case mapping, which would turn 'ı' and 'ſ' into ASCII letters and so
// disagree with a client that folds ASCII alone.
func Normalize(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '-' || c == ' ':
			continue
		case c == 'O' || c == 'o':
			c = '0'
		case c == 'I' || c == 'i' || c == 'L' || c == 'l':
			c = '1'
		case 'a' <= c && c <= 'z':
			c -= 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}
