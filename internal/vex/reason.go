package vex

import (
	"fmt"
	"time"
)

// impactStatementTruncateAt bounds how much of a free-text impact_statement
// lands in Suppressed.Reason — the table and JSON both show this inline, and
// an author can write a paragraph where a sentence would do; ~120 characters
// (D104's rules doc) keeps a reader's line scannable without losing which
// statement is being quoted.
const impactStatementTruncateAt = 120

// reasonFor synthesizes Suppressed.Reason for the statement resolve chose,
// in the exact shapes D104's rules doc specifies. Every branch's literal
// prefix ("VEX: not_affected" / "VEX: fixed") is what keeps the floor rule —
// never an empty reason — true regardless of how bare the statement's own
// author/@id/timestamp fields are.
func reasonFor(ls liveStatement, versionless bool) string {
	ts := formatTimestamp(ls.timestamp)

	var reason string
	switch {
	case ls.stmt.Status == "fixed":
		reason = fmt.Sprintf("VEX: fixed — %s (statement %s)", authorOrUnknown(ls.author), ts)
	case ls.stmt.Justification != "":
		reason = fmt.Sprintf("VEX: not_affected (%s) — %s, %s, %s",
			ls.stmt.Justification, authorOrUnknown(ls.author), docIDOrUnknown(ls.docID), ts)
	default:
		// not_affected reached liveStatements with no justification only
		// when impact_statement carried the reason instead (the only other
		// way a not_affected statement survives validation).
		reason = fmt.Sprintf("VEX: not_affected — %q — %s, %s",
			truncate(ls.stmt.ImpactStatement, impactStatementTruncateAt), authorOrUnknown(ls.author), ts)
	}
	if versionless {
		reason += " (product purl has no version: applies to all versions)"
	}
	return reason
}

func authorOrUnknown(s string) string {
	if s == "" {
		return "unknown author"
	}
	return s
}

func docIDOrUnknown(s string) string {
	if s == "" {
		return "no document @id"
	}
	return s
}

// formatTimestamp renders the statement's effective ordering timestamp for
// display. The zero value (row 29: neither the statement nor the document
// carried a parseable timestamp) prints as a word, not as
// "0001-01-01T00:00:00Z" — a date that looks like real data but is not one.
func formatTimestamp(t time.Time) string {
	if t.IsZero() {
		return "unknown time"
	}
	return t.Format(time.RFC3339)
}

// truncate shortens s to at most n runes, marking the cut with an ellipsis
// so a reader can tell the reason was clipped rather than that the statement
// itself ended abruptly.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
