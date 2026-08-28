package report

import (
	"strings"

	"github.com/kun9497/assay/internal/severity"
)

// ANSI SGR codes for D107's table colors. Assembled as named constants
// rather than typed inline at each call site — CLAUDE.md's escape-sequence
// rule, which is as much about a reviewer being able to find every color
// decision in one place as it is about avoiding a literal escape byte lost
// in transit through a shell.
//
// The palette matches docs/assets/demo.svg loosely, per D107: critical bold
// red, high red, medium yellow, low/unknown dim. This package never decides
// WHETHER these are allowed to reach a real terminal — that policy (a TTY,
// and NO_COLOR unset) lives in cmd/assay, the layer that owns the real
// stdout; this package only ever asks "should this text be colored, given
// that colorize is already true".
const (
	ansiReset   = "\x1b[0m"
	ansiBoldRed = "\x1b[1;31m" // critical
	ansiRed     = "\x1b[31m"   // high
	ansiYellow  = "\x1b[33m"   // medium
	ansiDim     = "\x1b[2m"    // low, unknown, none, and informational lines
	ansiBold    = "\x1b[1m"    // the summary's own finding count
)

// wrapSGR brackets s in code and ansiReset, or returns s unchanged when
// colorize is false. The single place a reset is appended, so "no color
// bleeds across a line" is a property of this function rather than
// something every call site has to remember to do for itself.
//
// A no-op on an empty s: wrapping "" in a code and a reset would still emit
// four invisible bytes into the stream, which is pointless when there is no
// text for them to color and, worse, is a color span with nothing visible
// inside it for a byte-count assertion (like the ones in scancmd's
// colorize-off tests) to reason about.
func wrapSGR(code, s string, colorize bool) string {
	if !colorize || s == "" {
		return s
	}
	return code + s + ansiReset
}

// severityColor maps a band to the SGR code the table colors it with.
//
// None falls into the same default as Low and Unknown rather than getting
// its own case: a finding actually reaching this renderer with band None is
// already the least severe point on the ordering (severity.Band's own doc
// comment), the same place Low and Unknown sit for coloring purposes, and
// None is not one of the four bands D107's brief named explicitly.
func severityColor(b severity.Band) string {
	switch b {
	case severity.Critical:
		return ansiBoldRed
	case severity.High:
		return ansiRed
	case severity.Medium:
		return ansiYellow
	default: // severity.Low, severity.Unknown, severity.None
		return ansiDim
	}
}

// colorizeSeverityColumn takes tbl — the tabwriter-rendered findings table,
// already flushed and therefore already fully padded — and brackets each
// row's SEVERITY cell in its band's color, leaving every other byte
// (including the padding spaces around that cell) untouched.
//
// This runs AFTER Flush deliberately (Table's own call site comment
// explains why): tabwriter decides column widths from the byte length of
// each cell's content, so injecting an escape sequence before Flush would
// make that cell look wider than it renders, and by a different amount per
// row depending on which band's code is in it — exactly the misalignment
// enrichmentMarker's own comment describes for a double-width Korean title,
// caused here by invisible-width bytes instead of double-width ones.
// Coloring only after every column's width is fixed sidesteps that: the
// extra bytes land inside one row's own line, after that line's tab stops
// have already been decided, so they cannot move where any column starts —
// on this row or, since each line is independent, on any other.
//
// bands is one entry per data row (line 0 is the header), in the same order
// Table's own loop appended to it — so pairing line i+1 with bands[i] never
// has to re-parse the rendered SEVERITY text back into a band, which would
// have to duplicate formatSeverity's own "unknown has no score" special
// case to even locate the cell's boundary reliably.
//
// The header's own literal cell text ("SEVERITY", "ALIASES") is used to
// find the column's byte offsets rather than a generic column-splitting
// helper: both words are fixed constants a few lines above this file, they
// cannot collide with any other header word, and this table's shape is not
// something a caller can reconfigure at runtime — so locating them directly
// is exact, not an approximation the way splitting on whitespace runs would
// be (columnStarts, in table_test.go, exists because A TEST has no access to
// the strings that built each row and has to recover column boundaries from
// nothing but the rendered text; this function has that access already,
// through the header's own two constant words).
func colorizeSeverityColumn(tbl string, bands []severity.Band) string {
	lines := strings.Split(tbl, "\n")
	if len(lines) == 0 {
		return tbl
	}
	sevStart := strings.Index(lines[0], "SEVERITY")
	aliasesStart := strings.Index(lines[0], "ALIASES")
	if sevStart < 0 || aliasesStart < 0 || aliasesStart <= sevStart {
		// Defensive only: PACKAGE...FIXED IN is a literal a few lines above
		// this file, not runtime input, so this never fires in practice.
		// Left uncolored rather than panicking — a header this function
		// cannot parse is a reason to fall back to plain output, not to
		// crash a scan over a cosmetic feature.
		return tbl
	}
	for i, band := range bands {
		li := i + 1 // line 0 is the header
		if li >= len(lines) {
			break
		}
		line := lines[li]
		if aliasesStart > len(line) {
			continue
		}
		cell := line[sevStart:aliasesStart]
		trimmed := strings.TrimRight(cell, " ")
		pad := cell[len(trimmed):]
		lines[li] = line[:sevStart] + severityColor(band) + trimmed + ansiReset + pad + line[aliasesStart:]
	}
	return strings.Join(lines, "\n")
}
