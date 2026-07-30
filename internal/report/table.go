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
	if len(res.Findings) == 0 {
		fmt.Fprintln(w, "No known vulnerabilities found.")
	} else {
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
	}

	// The summary is what keeps a partial scan from reading as a clean one.
	skipped := cat.SkippedNoPURL + cat.SkippedNoVersion +
		cat.SkippedUnsupportedEcosystem + len(res.Skipped)
	fmt.Fprintf(w, "\n%d package(s) scanned, %d finding(s), %d skipped\n",
		cat.Cataloged, len(res.Findings), skipped)

	if skipped > 0 {
		fmt.Fprintln(w, "\nSkipped:")
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
