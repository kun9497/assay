package report

import (
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Text is s with every character that can drive a terminal, or start a new
// line in a log, spelled out as an escape instead of written through.
//
// A package name, a version, a path inside an image and a waiver's reason are
// all text the scanned target or its author chose. Printed raw, an SBOM could
// put ESC sequences into every finding row -- retitle the window, hide the
// row that follows, rewrite what scrolled past -- and a tar entry whose name
// holds a newline could begin a line of the scan's stderr with "error: ",
// which is the line the provenance sidecar records as the cause of an exit 2
// (QA 2026-11-20). JSON and SARIF are not affected: their encoder escapes
// these already.
//
// Escaped: the C0 and C1 controls, DEL, the Unicode line and paragraph
// separators, the bidirectional overrides and isolates (a name that renders
// right-to-left reads as another name), and bytes that are not UTF-8. Tab is
// escaped too: the table is tab-aligned, and one inside a cell would move
// every column after it. Printable text of any script passes unchanged.
func Text(s string) string {
	clean := true
	for _, r := range s {
		if unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean && utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case !unsafeRune(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
		i += size
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	switch {
	case unicode.IsControl(r): // C0, DEL, C1
		return true
	case r == ' ', r == ' ': // line and paragraph separators
		return true
	case r >= '‪' && r <= '‮', r >= '⁦' && r <= '⁩': // bidi overrides and isolates
		return true
	}
	return false
}

// terminalSafe returns a copy of v in which every string has been through
// Text. The human renderers call it once on what they are about to print,
// rather than at each of the dozens of places a name or a reason is
// formatted: a cell added later is covered without anyone remembering to,
// and the SGR colour codes the renderer adds itself are never in v, so they
// are not escaped.
//
// A copy: slices, maps and pointers are rebuilt, so the caller's value -- the
// one the JSON renderer and the verdict read -- is untouched. Unexported
// fields are carried over as they are; nothing prints them.
func terminalSafe[T any](v T) T {
	out := reflect.New(reflect.TypeOf(&v).Elem()).Elem()
	out.Set(reflect.ValueOf(&v).Elem())
	cleanStrings(out)
	return out.Interface().(T)
}

var timeType = reflect.TypeOf(time.Time{})

func cleanStrings(v reflect.Value) {
	if !v.CanSet() || v.Type() == timeType {
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(Text(v.String()))
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			cleanStrings(v.Field(i))
		}
	case reflect.Slice:
		if v.IsNil() {
			return
		}
		fresh := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(fresh, v)
		for i := 0; i < fresh.Len(); i++ {
			cleanStrings(fresh.Index(i))
		}
		v.Set(fresh)
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		fresh := reflect.New(v.Type().Elem())
		fresh.Elem().Set(v.Elem())
		cleanStrings(fresh.Elem())
		v.Set(fresh)
	case reflect.Map:
		if v.IsNil() {
			return
		}
		fresh := reflect.MakeMapWithSize(v.Type(), v.Len())
		for it := v.MapRange(); it.Next(); {
			key := reflect.New(v.Type().Key()).Elem()
			key.Set(it.Key())
			cleanStrings(key)
			val := reflect.New(v.Type().Elem()).Elem()
			val.Set(it.Value())
			cleanStrings(val)
			fresh.SetMapIndex(key, val)
		}
		v.Set(fresh)
	case reflect.Interface:
		// Left alone: nothing the renderers print is carried behind one,
		// and an interface value cannot be rebuilt in place.
	}
}
