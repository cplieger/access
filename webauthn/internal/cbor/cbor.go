// Package cbor decodes the RFC 8949 data items WebAuthn carries: one item per
// call, bounded in size, depth and item count, with no indefinite lengths or
// tags. Integer width and map key order are not checked (WebAuthn §2.4's
// canonical form): values are compared, never encodings.
package cbor

import (
	"bytes"
	"errors"
	"iter"
	"math"
	"unicode/utf8"
)

// The decoder's refusals, matched with errors.Is.
var (
	errTruncated     = errors.New("cbor: a declared length runs past the input")
	errNotWellFormed = errors.New("cbor: not well-formed (RFC 8949 Appendix F)")
	errIndefinite    = errors.New("cbor: indefinite length")
	errTag           = errors.New("cbor: tag")
	errIntRange      = errors.New("cbor: integer outside int64")
	errMapKey        = errors.New("cbor: map key is not an integer or a text string")
	errDuplicateKey  = errors.New("cbor: duplicate map key")
	errUTF8          = errors.New("cbor: text string is not valid UTF-8")
	errLimit         = errors.New("cbor: input exceeds the size, depth or item bound")
)

// The bounds on one Decode call; WebAuthn §16's largest attestation object
// holds 20 items and nests 3 levels.
const (
	maxInput = 64 << 10
	maxDepth = 4
	maxItems = 256
)

type kind uint8

const (
	kindInvalid kind = iota
	kindInt
	kindBytes
	kindText
	kindArray
	kindMap
	kindBool
	kindNull
	kindUndefined
	kindSimple
	kindFloat
)

// RFC 8949 §3.1 major types.
const (
	majorUint = iota
	majorNegInt
	majorBytes
	majorText
	majorArray
	majorMap
	majorTag
	majorSimple
)

// Value is one decoded data item.
type Value struct {
	b []byte
	// kids holds an array's elements, or a map's keys and values
	// interleaved in input order.
	kids []Value
	i    int64
	kind kind
}

// Decode reads one data item from data and returns the bytes after it. Byte
// and text strings in the value alias data. Every refusal is one of the package's
// errors, and nothing sized by the input is allocated before the item is
// known to be well-formed and within bounds.
func Decode(data []byte) (Value, []byte, error) {
	if len(data) > maxInput {
		return Value{}, nil, errLimit
	}
	// RFC 8949 §5.3 defines validity only for a well-formed item, so the
	// allocation-free scan runs first and the decode never meets a
	// truncated or unbounded item.
	s := decoder{data: data}
	if err := s.scan(1); err != nil {
		return Value{}, nil, err
	}
	d := decoder{data: data[:s.off]}
	v, err := d.item()
	if err != nil {
		return Value{}, nil, err
	}
	return v, data[s.off:], nil
}

type decoder struct {
	data  []byte
	off   int
	items int
}

// head reads an initial byte and its argument (RFC 8949 §3).
func (d *decoder) head() (major, info byte, arg uint64, err error) {
	if d.off >= len(d.data) {
		return 0, 0, 0, errTruncated
	}
	b := d.data[d.off]
	d.off++
	major, info = b>>5, b&0x1f
	switch {
	case info < 24:
		return major, info, uint64(info), nil
	case info <= 27:
		n := 1 << (info - 24)
		if len(d.data)-d.off < n {
			return 0, 0, 0, errTruncated
		}
		for _, c := range d.data[d.off : d.off+n] {
			arg = arg<<8 | uint64(c)
		}
		d.off += n
		return major, info, arg, nil
	case info == 31 && major >= majorBytes && major <= majorMap:
		return 0, 0, 0, errIndefinite
	default:
		// 28 to 30 on any major type; 31 on 0, 1 and 6; a break (7, 31).
		return 0, 0, 0, errNotWellFormed
	}
}

// length reads a string's byte count or a container's entry count, which
// cannot exceed the bytes left since every entry takes at least one.
func (d *decoder) length(arg uint64) (int, error) {
	left := len(d.data) - d.off
	if arg > uint64(left) { //nolint:gosec // G115: off never passes len(data), so left is not negative
		return 0, errTruncated
	}
	return int(arg), nil //nolint:gosec // G115: arg is at most left, an int
}

// scan checks one item's well-formedness and the depth and item bounds.
func (d *decoder) scan(depth int) error {
	d.items++
	if d.items > maxItems {
		return errLimit
	}
	major, info, arg, err := d.head()
	if err != nil {
		return err
	}
	switch major {
	case majorBytes, majorText:
		n, err := d.length(arg)
		d.off += n
		return err
	case majorArray, majorMap:
		return d.scanContainer(depth, major, arg)
	case majorTag:
		return errTag
	case majorSimple:
		if info == 24 && arg < 32 {
			return errNotWellFormed
		}
	}
	return nil
}

func (d *decoder) scanContainer(depth int, major byte, arg uint64) error {
	n, err := d.length(arg)
	if err != nil {
		return err
	}
	if depth > maxDepth {
		return errLimit
	}
	if major == majorMap {
		n *= 2
	}
	for range n {
		if err := d.scan(depth + 1); err != nil {
			return err
		}
	}
	return nil
}

// item decodes an item scan has accepted, so its lengths fit the input.
func (d *decoder) item() (Value, error) {
	major, info, arg, err := d.head()
	if err != nil {
		return Value{}, err
	}
	switch major {
	case majorUint:
		if arg > math.MaxInt64 {
			return Value{}, errIntRange
		}
		return Value{kind: kindInt, i: int64(arg)}, nil
	case majorNegInt:
		if arg > math.MaxInt64 {
			return Value{}, errIntRange
		}
		return Value{kind: kindInt, i: -1 - int64(arg)}, nil
	case majorBytes, majorText, majorArray, majorMap:
		n := int(arg) //nolint:gosec // G115: scan bounded every length by the input's
		switch major {
		case majorMap:
			return d.mapItem(n)
		case majorArray:
			return d.array(n)
		default:
			return d.str(major, n)
		}
	default:
		return simple(info, arg), nil
	}
}

func (d *decoder) str(major byte, n int) (Value, error) {
	b := d.data[d.off : d.off+n : d.off+n]
	d.off += n
	if major == majorBytes {
		return Value{kind: kindBytes, b: b}, nil
	}
	if !utf8.Valid(b) {
		return Value{}, errUTF8
	}
	return Value{kind: kindText, b: b}, nil
}

func (d *decoder) array(n int) (Value, error) {
	kids := make([]Value, n)
	for i := range kids {
		v, err := d.item()
		if err != nil {
			return Value{}, err
		}
		kids[i] = v
	}
	return Value{kind: kindArray, kids: kids}, nil
}

func (d *decoder) mapItem(n int) (Value, error) {
	kids := make([]Value, 0, 2*n)
	for range n {
		k, err := d.item()
		if err != nil {
			return Value{}, err
		}
		if k.kind != kindInt && k.kind != kindText {
			return Value{}, errMapKey
		}
		for j := 0; j < len(kids); j += 2 {
			if sameKey(&kids[j], &k) {
				return Value{}, errDuplicateKey
			}
		}
		v, err := d.item()
		if err != nil {
			return Value{}, err
		}
		kids = append(kids, k, v)
	}
	return Value{kind: kindMap, kids: kids}, nil
}

func sameKey(a, b *Value) bool {
	return a.kind == b.kind && a.i == b.i && bytes.Equal(a.b, b.b)
}

// simple reads major type 7 (RFC 8949 §3.3) after scan has refused a
// two-byte simple value below 32. Only the booleans, null and undefined carry
// meaning for WebAuthn; the rest keep their kind alone.
func simple(info byte, arg uint64) Value {
	switch {
	case info > 24:
		return Value{kind: kindFloat}
	case arg == 20, arg == 21:
		return Value{kind: kindBool, i: int64(arg - 20)}
	case arg == 22:
		return Value{kind: kindNull}
	case arg == 23:
		return Value{kind: kindUndefined}
	default:
		return Value{kind: kindSimple}
	}
}

// Int returns an unsigned or negative integer.
func (v Value) Int() (int64, bool) {
	if v.kind != kindInt {
		return 0, false
	}
	return v.i, true
}

// Bytes returns a byte string, aliasing the decoded input.
func (v Value) Bytes() ([]byte, bool) {
	if v.kind != kindBytes {
		return nil, false
	}
	return v.b, true
}

// Text returns a text string.
func (v Value) Text() (string, bool) {
	if v.kind != kindText {
		return "", false
	}
	return string(v.b), true
}

// Map returns a map's entries in input order.
func (v Value) Map() (iter.Seq2[Value, Value], bool) {
	if v.kind != kindMap {
		return nil, false
	}
	return func(yield func(Value, Value) bool) {
		for i := 0; i < len(v.kids); i += 2 {
			if !yield(v.kids[i], v.kids[i+1]) {
				return
			}
		}
	}, true
}
