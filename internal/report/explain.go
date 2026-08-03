package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/kun9497/assay/internal/matcher"
)

// Explain writes a human-readable account of every finding in res whose
// advisory is identified by id — its own ID, or one of the aliases/upstream
// identifiers it carries (D3) — to w. This is D10 made visible: which range
// matched, which comparer decided it, what the comparison actually
// returned, and which name reached the advisory (D8), the fields Evidence
// and MatchedName exist on Finding to carry rather than leaving to a log
// line.
//
// Matching against BOTH aliases and upstream, exactly like otherIDs (the
// table's own ALIASES column), because which field carries a CVE depends on
// the ecosystem (D3): the Go dump files it under aliases, the Alpine dump
// under upstream. A reader who greps the table for an identifier must be
// able to hand that same identifier to --explain and get the finding back,
// regardless of which field it happened to live in.
//
// It returns the number of findings written, not just an error, so the
// caller can tell "id matched nothing" apart from "matched and had nothing
// to say" — the two would otherwise be indistinguishable from an empty w.
// Zero writes nothing at all to w: a partial or empty-but-successful report
// for a typo'd identifier would be a quiet wrong answer, the opposite of
// what explain mode exists for.
func Explain(w io.Writer, res matcher.Result, id string) (int, error) {
	n := 0
	for _, f := range res.Findings {
		if !identifiesFinding(f, id) {
			continue
		}
		if err := explainOne(w, f); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// identifiesFinding reports whether id names f: the displayed advisory's own
// ID, or any identifier any record that joined this finding answered to. It reuses otherIDs — the exact set the
// table's ALIASES column shows — rather than re-deriving which fields count
// as identifiers a second time, and compares with ==, never Contains: real
// identifiers nest (ALPINE-CVE-2025-46394 contains CVE-2025-46394), so a
// substring match here would explain the wrong advisory on a false-positive
// hit.
func identifiesFinding(f matcher.Finding, id string) bool {
	if f.Advisory.ID == id {
		return true
	}
	for _, other := range otherIDs(f) {
		if other == id {
			return true
		}
	}
	return false
}

// explainOne writes one finding's account: the package and how it was
// named, the advisory and its other identifiers, the severity, and the full
// version.Evidence — which comparer, which range, and the comparison's own
// Reason string.
func explainOne(w io.Writer, f matcher.Finding) error {
	lines := []string{
		fmt.Sprintf("package:  %s %s [%s]", f.Package.Name, f.Package.Version, f.Package.Ecosystem),
	}
	if f.MatchedName == "" || f.MatchedName == f.Package.Name {
		lines = append(lines, fmt.Sprintf("matched:  %s (direct match)", f.Package.Name))
	} else {
		// D8: the advisory names the source package, not the installed one.
		// Spelled out in words as well as names, because a reader who only
		// sees two names side by side has no way to tell which one is the
		// indirection this line exists to explain.
		lines = append(lines, fmt.Sprintf(
			"matched:  %s (source package, D8 — installed package is %s)",
			f.MatchedName, f.Package.Name))
	}
	lines = append(lines, fmt.Sprintf("advisory: %s", f.Advisory.ID))
	if ids := otherIDs(f); len(ids) > 0 {
		lines = append(lines, fmt.Sprintf("also known as: %s", strings.Join(ids, ", ")))
	}
	if f.Advisory.Summary != "" {
		lines = append(lines, fmt.Sprintf("summary:  %s", f.Advisory.Summary))
	}
	// Explain is the "why" view (D10), so unlike the table's single SEVERITY
	// cell it shows every source in full, not just the one that set the
	// band — agreeing or not.
	//
	// The base line is unconditional; the source count and the per-source
	// breakdown are purely additive on top of it. Deliberately NOT an
	// if/else between "has Ratings" and "does not": Match always populates
	// at least one Rating (D25), so a Finding with none reaches this
	// function only by direct construction — several older fixtures in this
	// package still do that, for reasons unrelated to D25 (D8 indirection,
	// alias matching, and so on). An if/else here would give those fixtures
	// their own dedicated rendering branch that nothing built by Match could
	// ever reach, which is not a real code path worth maintaining as one.
	// Structuring it as one line plus a loop means the zero-Ratings case is
	// just that same loop running zero times, not a different branch.
	sevLine := fmt.Sprintf("severity: %s", formatSeverity(f.Severity, f.Score))
	if n := len(f.Ratings); n > 0 {
		source := "source"
		if n != 1 {
			source = "sources"
		}
		sevLine += fmt.Sprintf("   [highest of %d %s]", n, source)
	}
	lines = append(lines, sevLine)
	for _, r := range f.Ratings {
		lines = append(lines, ratingLine(r))
	}
	lines = append(lines, fmt.Sprintf("comparer: %s", comparerName(f.Package.Ecosystem)))

	ev := f.Evidence
	lines = append(lines, fmt.Sprintf(
		"range:    type=%s introduced=%q fixed=%q lastAffected=%q",
		ev.RangeType, ev.Introduced, ev.Fixed, ev.LastAffected))
	reason := ev.Reason
	if reason == "" {
		reason = "matched an enumerated affected version, not a range"
	}
	lines = append(lines, fmt.Sprintf("result:   %s", reason))

	_, err := fmt.Fprintln(w, strings.Join(lines, "\n")+"\n")
	return err
}

// ratingLine formats one source's assessment of a finding for the full
// breakdown printed under "severity:" — the detail the table's marker only
// points at.
//
// Column widths are fixed rather than computed from the ratings actually
// present: this is a handful of lines under one finding, not a table whose
// rows must line up with a header printed once for the whole document
// (table.go's own tabwriter), so a fixed width keeps each finding's
// breakdown independently predictable rather than shifting with whichever
// other findings happen to be explained alongside it. 6 fits every database
// name measured so far ("ALPINE" is the longest); 24 clears real advisory
// IDs including Alpine's own "ALPINE-CVE-2025-46394"; 16 clears the longest
// formatSeverity output, "critical (10.0)".
func ratingLine(r matcher.Rating) string {
	fixed := r.Fixed
	if fixed == "" {
		fixed = "-"
	}
	return fmt.Sprintf("  %-6s %-24s %-16s fixed %s",
		r.Database, r.AdvisoryID, formatSeverity(r.Severity, r.Score), fixed)
}

// comparerName names the version.Comparer that version.For would select
// for ecosystem, without exporting version's own unexported registry just
// for this display purpose. It mirrors version.For's dispatch exactly —
// Alpine:vX.Y -> apk, Go/npm -> semver, PyPI -> pep440 — and
// TestComparerName_AgreesWithVersionFor cross-checks the two directly, so a
// future ecosystem added to one and not the other fails loudly here rather
// than explain mode quietly naming the wrong comparer (D9: comparison rules
// are genuinely per-ecosystem, and getting the name wrong is exactly the
// kind of quiet error D9 exists to prevent).
func comparerName(ecosystem string) string {
	if rel, ok := strings.CutPrefix(ecosystem, "Alpine:"); ok && rel != "" {
		return "apk"
	}
	switch ecosystem {
	case "Go", "npm":
		return "semver"
	case "PyPI":
		return "pep440"
	default:
		return "unknown"
	}
}
