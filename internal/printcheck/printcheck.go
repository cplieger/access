// Package printcheck finds a secret a printer could show. Unmasked checks
// types: it reports every field of a type graph that can carry text and is
// neither a masked type nor a reviewed non-secret field. Leak checks a
// printer's output for a secret's text, its HMAC pad forms, and their hex
// or base64. Import it only from access's _test.go files.
package printcheck

import (
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
)

// Allow is what Unmasked accepts without looking inside it.
type Allow struct {
	// Masked are the types whose own tests pin that they hold no text in
	// clear (access.Secret, access.Hash and their shared masked value).
	Masked []reflect.Type
	// Fields are reviewed non-secret fields, each written as its declaring
	// type's reflect.Type.String, a dot and the field name: "access.User.Email".
	Fields []string
	// Types are reviewed non-secret types, by reflect.Type.String: "time.Time".
	Types []string
}

// Unmasked walks each root's type graph through struct fields (unexported
// included), pointers, slices, arrays and maps, and returns, sorted, one line
// per field that can carry text: a string, an integer slice or array (a
// []byte, an expanded key schedule), or an interface, whose dynamic value the
// type does not fix. Masked types, allowed types and allowed fields are not
// entered; an allow entry no root reached is reported, so none goes stale.
// Funcs, chans and unsafe pointers pass: every printer shows an address.
func Unmasked(a Allow, roots ...reflect.Type) []string {
	w := walker{
		allow: a,
		used:  make(map[string]bool),
		seen:  make(map[item]bool),
		found: make(map[string]bool),
	}
	for _, r := range roots {
		w.queue = append(w.queue, item{t: r, owner: r.String()})
	}
	w.run()
	for _, name := range slices.Concat(a.Fields, a.Types) {
		if !w.used[name] {
			w.found["allow entry "+name+": reached by no root"] = true
		}
	}
	out := make([]string, 0, len(w.found))
	for line := range w.found {
		out = append(out, line)
	}
	slices.Sort(out)
	return out
}

// item is one type to check on behalf of owner, the struct field (or root)
// whose type it is or lies inside. A violation is reported against owner,
// so the verdict on a field does not depend on the route that reached it.
type item struct {
	t     reflect.Type
	owner string
}

type walker struct {
	used  map[string]bool
	seen  map[item]bool
	found map[string]bool
	queue []item
	allow Allow
}

// run drains the queue, checking each item once, which ends every type
// cycle. A struct is one item whatever its owner, because its fields'
// verdicts are its own; any other type is one item per owner, so two fields
// of one named slice type are both reported.
func (w *walker) run() {
	for len(w.queue) > 0 {
		it := w.queue[0]
		w.queue = w.queue[1:]
		if it.t.Kind() == reflect.Struct {
			it.owner = ""
		}
		if w.seen[it] {
			continue
		}
		w.seen[it] = true
		if slices.Contains(w.allow.Masked, it.t) {
			continue
		}
		if name := it.t.String(); slices.Contains(w.allow.Types, name) {
			w.used[name] = true
			continue
		}
		w.check(it)
	}
}

func (w *walker) fields(t reflect.Type) {
	for f := range t.Fields() {
		name := t.String() + "." + f.Name
		if slices.Contains(w.allow.Fields, name) {
			w.used[name] = true
			continue
		}
		w.queue = append(w.queue, item{t: f.Type, owner: name})
	}
}

func (w *walker) check(it item) {
	t := it.t
	switch t.Kind() {
	case reflect.Struct:
		w.fields(t)
	case reflect.String:
		w.report(it, "a string")
	case reflect.Interface:
		w.report(it, "an interface")
	case reflect.Slice, reflect.Array:
		if isInteger(t.Elem().Kind()) {
			w.report(it, "an integer sequence")
			return
		}
		w.queue = append(w.queue, item{t: t.Elem(), owner: it.owner})
	case reflect.Pointer:
		w.queue = append(w.queue, item{t: t.Elem(), owner: it.owner})
	case reflect.Map:
		w.queue = append(w.queue, item{t: t.Key(), owner: it.owner}, item{t: t.Elem(), owner: it.owner})
	default:
	}
}

func (w *walker) report(it item, what string) {
	w.found[it.owner+": holds "+what+" ("+it.t.String()+")"] = true
}

func isInteger(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return true
	default:
		return false
	}
}

// forms returns text, its hex in both cases, and every run of base64
// characters, standard and URL alphabets, that text alone determines at each
// of the three byte offsets it can start at inside a longer encoded value.
// A padded or longer encoding of text contains one of them.
func forms(text string) []string {
	h := hex.EncodeToString([]byte(text))
	out := []string{text, h, strings.ToUpper(h)}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for offset := range 3 {
			encoded := enc.EncodeToString(append(make([]byte, offset), text...))
			// A character covers 6 bits: skip those that hold a prefix bit and
			// stop before the one that would hold a bit of what follows text.
			start, end := (8*offset+5)/6, 8*(offset+len(text))/6
			if start < end {
				out = append(out, encoded[start:end])
			}
		}
	}
	return out
}

// KeyForms returns the forms of key a printer can show: key itself, and
// key XOR 0x36 and XOR 0x5c, the inner and outer pads a crypto/hmac value
// caches (RFC 2104 §2), each in clear, hex and base64.
func KeyForms(key string) []string {
	out := forms(key)
	for _, pad := range []byte{0x36, 0x5c} {
		b := []byte(key)
		for i := range b {
			b[i] ^= pad
		}
		out = append(out, forms(string(b))...)
	}
	return out
}

// Leak reports whether got contains text in any form KeyForms returns. text
// must not be empty (every string contains it), and a text of a few bytes
// has base64 runs short enough to match by chance.
func Leak(got, text string) bool {
	for _, f := range KeyForms(text) {
		if strings.Contains(got, f) {
			return true
		}
	}
	return false
}
