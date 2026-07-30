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
)

// Summary is what the report concluded. It is returned rather than kept private
// because the renderer is the only place that knows how much of the scan
// actually ran, and the exit code is the part CI reads — a verdict printed in
// prose that the process contradicts with a 0 is not a verdict.
type Summary struct {
	Components       int
	Evaluated        int
	NotEvaluated     int
	IncompleteChecks int
	Findings         int
}

// Trustworthy reports whether the run produced a result worth acting on. A scan
// that evaluated nothing carries no information about the target, and D11
// reserves exit 2 for exactly that — a result that cannot be trusted, as
// distinct from a clean one. An empty document is vacuously fine.
func (s Summary) Trustworthy() bool {
	return s.Components == 0 || s.Evaluated > 0
}

func Table(w io.Writer, res matcher.Result, cat cyclonedx.Stats) (Summary, error) {
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

	switch {
	case len(res.Findings) > 0:
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PACKAGE\tVERSION\tECOSYSTEM\tADVISORY\tALIASES\tFIXED IN")
		for _, f := range res.Findings {
			fixed := f.Evidence.Fixed
			if fixed == "" {
				fixed = "-"
			}
			// Aliases are printed because dedup keeps only one record per
			// vulnerability, and the one that wins is whichever the index
			// returned first. Without this, a CVE that assay matched correctly
			// is absent from the output whenever the GHSA record won, and
			// `assay scan … | grep CVE-…` finds nothing.
			aliases := strings.Join(f.Advisory.Aliases, ",")
			if aliases == "" {
				aliases = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				f.Package.Name, f.Package.Version, f.Package.Ecosystem,
				f.Advisory.ID, aliases, fixed)
		}
		if err := tw.Flush(); err != nil {
			return Summary{}, err
		}

	case evaluated == 0:
		// Nothing was actually judged. "No known vulnerabilities found" would be
		// true and useless here — the same sentence a genuinely clean scan
		// prints, from a run that checked nothing. A reader who greps the first
		// line, or whose output is truncated, must not read this as safety.
		fmt.Fprintln(w, "No packages could be evaluated - this is NOT a clean result.")

	case incompleteChecks > 0:
		// Nothing found, but not every check ran. Saying "no known
		// vulnerabilities" would claim a completeness the run did not have.
		fmt.Fprintf(w,
			"No vulnerabilities found in %d package(s), but %d check(s) could not be completed - this is NOT a clean result.\n",
			evaluated, incompleteChecks)

	default:
		fmt.Fprintf(w, "No known vulnerabilities found in %d package(s).\n", evaluated)
	}

	// The summary keeps a partial scan from reading as a clean one, so its
	// parts must add up: every component the document contained is either
	// evaluated or not, and no package is counted in both.
	notEvaluated := cat.Components - evaluated
	fmt.Fprintf(w, "\n%d component(s) seen, %d evaluated, %d finding(s), %d not evaluated\n",
		cat.Components, evaluated, len(res.Findings), notEvaluated)

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
	return Summary{
		Components:       cat.Components,
		Evaluated:        evaluated,
		NotEvaluated:     notEvaluated,
		IncompleteChecks: incompleteChecks,
		Findings:         len(res.Findings),
	}, nil
}
