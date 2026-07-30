// Package report renders findings. Output is deterministic and diffable, which
// is design goal #3 — a scanner whose output churns cannot be used in CI.
package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
)

func Table(w io.Writer, res matcher.Result, cat cyclonedx.Stats) error {
	// A package counts as evaluated only if it was cataloged AND the matcher
	// could judge it. A whole-package matcher skip (empty AdvisoryID) was
	// cataloged but never checked, so counting it as scanned would inflate the
	// number a reader trusts most.
	var unevaluated int
	for _, s := range res.Skipped {
		if s.AdvisoryID == "" {
			unevaluated++
		}
	}
	evaluated := cat.Cataloged - unevaluated

	switch {
	case len(res.Findings) > 0:
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PACKAGE\tVERSION\tECOSYSTEM\tADVISORY\tFIXED IN")
		for _, f := range res.Findings {
			fixed := f.Evidence.Fixed
			if fixed == "" {
				fixed = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
				f.Package.Name, f.Package.Version, f.Package.Ecosystem, f.Advisory.ID, fixed)
		}
		if err := tw.Flush(); err != nil {
			return err
		}

	case evaluated == 0:
		// Nothing was actually judged. "No known vulnerabilities found" would be
		// true and useless here — the same sentence a genuinely clean scan
		// prints, from a run that checked nothing. A reader who greps the first
		// line, or whose output is truncated, must not read this as safety.
		fmt.Fprintln(w, "No packages could be evaluated - this is NOT a clean result.")

	default:
		fmt.Fprintf(w, "No known vulnerabilities found in %d package(s).\n", evaluated)
	}

	// The summary keeps a partial scan from reading as a clean one, so its
	// parts must add up: every component the document contained is either
	// evaluated or not, and no package is counted in both.
	notEvaluated := cat.Components - evaluated
	fmt.Fprintf(w, "\n%d component(s) seen, %d evaluated, %d finding(s), %d not evaluated\n",
		cat.Components, evaluated, len(res.Findings), notEvaluated)

	if notEvaluated > 0 {
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
	return nil
}
