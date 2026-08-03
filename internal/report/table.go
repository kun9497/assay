// Package report renders findings. Output is deterministic and diffable, which
// is design goal #3 — a scanner whose output churns cannot be used in CI.
package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/severity"
)

// Summary is what the report concluded. It is returned rather than kept private
// because the renderer is the only place that knows how much of the scan
// actually ran, and the exit code is the part CI reads — a verdict printed in
// prose that the process contradicts with a 0 is not a verdict.
type Summary struct {
	Components       int `json:"components"`
	Evaluated        int `json:"evaluated"`
	NotEvaluated     int `json:"notEvaluated"`
	IncompleteChecks int `json:"incompleteChecks"`
	Findings         int `json:"findings"`
	// UnknownSeverity is the number of findings whose severity could not be
	// rated — no vector scored (D17). It is populated whether or not it is
	// zero, because a --fail-on-unknown gate reads it directly and a count
	// that only appears when non-zero is not one a caller can rely on.
	UnknownSeverity int `json:"unknownSeverity"`
}

// Trustworthy reports whether the run produced a result worth acting on. A scan
// that evaluated nothing carries no information about the target, and D11
// reserves exit 2 for exactly that — a result that cannot be trusted, as
// distinct from a clean one. An empty document is vacuously fine.
func (s Summary) Trustworthy() bool {
	return s.Components == 0 || s.Evaluated > 0
}

func Table(w io.Writer, res matcher.Result, cat cyclonedx.Stats) (Summary, error) {
	sum := Summarize(res, cat)
	evaluated := sum.Evaluated
	notEvaluated := sum.NotEvaluated
	incompleteChecks := sum.IncompleteChecks
	unknownSeverity := sum.UnknownSeverity

	switch {
	case len(res.Findings) > 0:
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PACKAGE\tVERSION\tECOSYSTEM\tADVISORY\tSEVERITY\tALIASES\tFIXED IN")
		// disagreement tracks whether any row got the marker, so the footnote
		// that explains it is printed at most once and only when it applies —
		// a footnote nobody's row earned is worse than no footnote.
		disagreement := false
		for _, f := range res.Findings {
			fixed := f.Evidence.Fixed
			if fixed == "" {
				fixed = "-"
			}
			// Other identifiers are printed because dedup keeps only one record
			// per vulnerability, and the one that wins is whichever the index
			// returned first. Without this, a CVE that assay matched correctly
			// is absent from the output whenever the GHSA record won, and
			// `assay scan … | grep CVE-…` finds nothing.
			aliases := strings.Join(otherIDs(f), ",")
			if aliases == "" {
				aliases = "-"
			}
			// When the advisory was written against a different package than
			// the one installed — the source package (D8) — the report has to
			// say so. "libssl3 is vulnerable to CVE-x" is unverifiable when the
			// advisory that says so names openssl; the reader looks it up, sees
			// no mention of libssl3, and cannot tell a real finding from a bug.
			name := f.Package.Name
			if f.MatchedName != "" && f.MatchedName != f.Package.Name {
				name = f.Package.Name + " (" + f.MatchedName + ")"
			}
			sev := formatSeverity(f.Severity, f.Score)
			// One row, one SEVERITY cell (D25): the table is the scannable
			// view and a row that grows with source count stops being
			// scannable. When the sources behind it do not all agree, the
			// cell earns a marker rather than silently presenting the
			// highest band as if it were the only opinion; --explain carries
			// the full breakdown (D10).
			if sourcesDisagree(f.Ratings) {
				sev += " " + disagreementMarker
				disagreement = true
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				name, f.Package.Version, f.Package.Ecosystem,
				f.Advisory.ID, sev, aliases, fixed)
		}
		if err := tw.Flush(); err != nil {
			return Summary{}, err
		}
		if disagreement {
			fmt.Fprintf(w, "%s sources disagree on severity; see --explain <id> for the detail\n", disagreementMarker)
		}

	case cat.Components == 0:
		// Distinct from "nothing could be evaluated": there was nothing to
		// evaluate. Trustworthy() treats this as vacuously fine, and the
		// wording has to agree with the exit code.
		fmt.Fprintln(w, "The document contained no components.")

	case evaluated == 0:
		// Nothing was actually judged. "No known vulnerabilities found" would be
		// true and useless here — the same sentence a genuinely clean scan
		// prints, from a run that checked nothing. A reader who greps the first
		// line, or whose output is truncated, must not read this as safety.
		fmt.Fprintln(w, "No packages could be evaluated - this is NOT a clean result.")

	case incompleteChecks > 0 || notEvaluated > 0:
		// Nothing found, but not every check ran. Saying "no known
		// vulnerabilities" would claim a completeness the run did not have.
		//
		// Both counts gate this, not incompleteChecks alone. Keyed on that
		// one, a scan where a single advisory could not be judged warned
		// loudly, while a scan where 15 of 17 packages were never checked
		// at all printed the clean sentence — the louder warning for the
		// smaller gap.
		//
		// notEvaluated, not the matcher's skip count: a component the
		// CATALOGER dropped never reaches the matcher, so keying on matcher
		// skips alone left the same hole open through the other door.
		switch {
		case incompleteChecks > 0 && notEvaluated > 0:
			fmt.Fprintf(w,
				"No vulnerabilities found in %d package(s), but %d package(s) were not checked and %d check(s) could not be completed - this is NOT a clean result.\n",
				evaluated, notEvaluated, incompleteChecks)
		case notEvaluated > 0:
			fmt.Fprintf(w,
				"No vulnerabilities found in %d package(s), but %d package(s) were not checked at all - this is NOT a clean result.\n",
				evaluated, notEvaluated)
		default:
			fmt.Fprintf(w,
				"No vulnerabilities found in %d package(s), but %d check(s) could not be completed - this is NOT a clean result.\n",
				evaluated, incompleteChecks)
		}

	default:
		fmt.Fprintf(w, "No known vulnerabilities found in %d package(s).\n", evaluated)
	}

	// The summary keeps a partial scan from reading as a clean one, so its
	// parts must add up: every component the document contained is either
	// evaluated or not, and no package is counted in both.
	//
	// The unknown-severity count is appended unconditionally (D17): printed
	// even at zero, because a count that only shows up when non-zero is one
	// readers learn to stop checking for.
	fmt.Fprintf(w, "\n%d component(s) seen, %d evaluated, %d finding(s), %d not evaluated, %d unknown severity\n",
		cat.Components, evaluated, len(res.Findings), notEvaluated, unknownSeverity)

	// Gated on both counts. Keying only on notEvaluated hid every
	// advisory-scoped skip whenever the rest of the document was fully
	// evaluated — reintroducing, one advisory at a time, the silence this
	// block exists to break.
	if notEvaluated > 0 || incompleteChecks > 0 {
		fmt.Fprintln(w, "\nNot evaluated:")
		if cat.SkippedUnsupportedEcosystem > 0 {
			fmt.Fprintf(w, "  %d package(s) in an unsupported ecosystem\n",
				cat.SkippedUnsupportedEcosystem)
		}
		if cat.SkippedNoPURL > 0 {
			fmt.Fprintf(w, "  %d component(s) without a usable purl\n", cat.SkippedNoPURL)
		}
		if cat.SkippedNoVersion > 0 {
			fmt.Fprintf(w, "  %d package(s) with no version to compare\n", cat.SkippedNoVersion)
		}
		for _, s := range res.Skipped {
			if s.AdvisoryID != "" {
				fmt.Fprintf(w, "  %s %s (%s): %s\n",
					s.Package.Name, s.Package.Version, s.AdvisoryID, s.Reason)
				continue
			}
			fmt.Fprintf(w, "  %s %s: %s\n", s.Package.Name, s.Package.Version, s.Reason)
		}
	}
	return sum, nil
}

// Summarize computes exactly the counts Table's own summary line prints,
// pulled out so a second renderer (JSON) — and scancmd's exit-code verdict
// under --explain, which runs neither Table nor JSON — derive them the same
// way Table does rather than re-deriving them and risking the two silently
// disagreeing. That is the identical two-computations-of-one-fact hazard
// verdict() already avoids by reading Summary.UnknownSeverity directly
// instead of re-deriving it from res.Findings; this is the same fix one
// level up, so Table, JSON, and --explain's own exit code cannot drift apart
// on what "evaluated" or "unknown severity" means.
//
// Table's own printed wording, counts, and headline selection are UNCHANGED
// by this: this function is the exact code that used to sit inline at the
// top of Table, moved verbatim, and the existing table_test.go suite (which
// asserts on Table's output, never on this function directly) passes
// unmodified after the move — the proof that nothing observable shifted.
func Summarize(res matcher.Result, cat cyclonedx.Stats) Summary {
	// A package counts as evaluated only if it was cataloged AND the matcher
	// could judge it. A whole-package matcher skip (empty AdvisoryID) was
	// cataloged but never checked, so counting it as scanned would inflate the
	// number a reader trusts most.
	// Two different kinds of "could not tell" live in res.Skipped. A
	// whole-package skip means the package was never checked at all; an
	// advisory-scoped one means the package was checked but one advisory could
	// not be judged. They must be counted apart, because only the first one
	// changes how many packages were evaluated — and only the second one used
	// to disappear from the report entirely.
	var unevaluated, incompleteChecks int
	for _, s := range res.Skipped {
		if s.AdvisoryID == "" {
			unevaluated++
			continue
		}
		incompleteChecks++
	}
	evaluated := cat.Cataloged - unevaluated
	// Every component the document held that was not evaluated, whether the
	// matcher skipped it or the cataloger never produced a package for it.
	notEvaluated := cat.Components - evaluated

	// Counted unconditionally (D17): a threshold that hides how much it could
	// not judge is not a threshold.
	var unknownSeverity int
	for _, f := range res.Findings {
		if f.Severity == severity.Unknown {
			unknownSeverity++
		}
	}

	return Summary{
		Components:       cat.Components,
		Evaluated:        evaluated,
		NotEvaluated:     notEvaluated,
		IncompleteChecks: incompleteChecks,
		Findings:         len(res.Findings),
		UnknownSeverity:  unknownSeverity,
	}
}

// disagreementMarker flags a SEVERITY cell whose sources did not all agree.
//
// `*` over `⚠`: this table is read in CI logs and terminals with unreliable
// Unicode width handling, and the rest of the table (tabwriter's own output)
// is plain ASCII already — a two-column-wide glyph that some terminals
// render as one throws off every column after it, which is exactly the
// misalignment cellAt's own doc comment warns a reader cannot see happen.
const disagreementMarker = "*"

// sourcesDisagree reports whether a finding's sources gave different
// severity bands for the same vulnerability — the disagreement the table's
// marker exists to surface.
//
// A difference in score or fixed version alone is NOT disagreement here:
// two sources that both say "high" have not disagreed even if their CVSS
// scores differ by a point or they name different fixed releases. Only the
// band is what the table's aggregate SEVERITY cell — and any --fail-on gate
// reading it — actually acts on, so that is the one field this checks.
//
// A finding with fewer than two ratings can never disagree with itself:
// len(ratings) < 2 covers both the zero-rating case (a hand-built Finding in
// a test that predates D25) and the single-source case the brief calls out
// explicitly.
func sourcesDisagree(ratings []matcher.Rating) bool {
	if len(ratings) < 2 {
		return false
	}
	first := ratings[0].Severity
	for _, r := range ratings[1:] {
		if r.Severity != first {
			return true
		}
	}
	return false
}

// formatSeverity renders a finding's band together with the score behind it.
// Unknown gets no parenthetical score: a finding that could not be rated has
// no number to show, and printing "unknown (0.0)" would read as a real score
// of zero — the exact coercion D17 forbids, back in through formatting.
func formatSeverity(b severity.Band, score float64) string {
	if b == severity.Unknown {
		return b.String()
	}
	return fmt.Sprintf("%s (%.1f)", b.String(), score)
}

// otherIDs returns the identifiers a reader might grep for besides the one the
// finding is filed under, drawn from BOTH aliases and upstream (D3).
//
// Which field carries the CVE depends entirely on the ecosystem, and the two
// measured cases are exact mirror images: on the live Go dump all 8,510 records
// have an empty upstream and carry the CVE in aliases, while on the live Alpine
// dump all 4,405 records have an empty aliases and carry it in upstream. Reading
// either field alone makes `assay scan … | grep CVE-…` silently find nothing for
// half the ecosystems — which is the failure this column exists to prevent.
//
// This is display, not identity. The matcher deliberately does NOT treat
// upstream as an identifier when deduplicating, because OSV defines it as
// "derived from" rather than "the same as", and collapsing on it would suppress
// a genuinely distinct advisory. Showing a reader one extra identifier is noise;
// hiding a finding is a false negative.
// Read off the FINDING, not off its displayed advisory. Once two records
// become one finding (D25), the names the losing record answered to are no
// longer reachable through Advisory — and a reader handed a PYSEC ID by our
// own JSON must still find the row it belongs to.
func otherIDs(f matcher.Finding) []string {
	out := make([]string, 0, len(f.Identifiers))
	seen := map[string]bool{f.Advisory.ID: true}
	for _, id := range f.Identifiers {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
