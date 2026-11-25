package matcher

import (
	"slices"
	"strings"

	"github.com/kun9497/assay/internal/advisory"
)

// readAtInstalledEpoch gives a Hummingbird fix that states no epoch the
// installed build's (D176).
//
// Red Hat's feed writes part of its Hummingbird fixes without the epoch the
// builds have. The provider restores what another document states
// (hummingbirdHold); libpng, nodejs20 and xz are stated with one nowhere, and
// nodejs24-npm with two. rpm reads a missing epoch as 0, so every build of
// those was above every fix: clean, with nothing skipped. A fix the feed gave
// no epoch is ordered on its version and release instead.
//
// Never the other way round, and never where the fix states one: a build
// without an epoch (an SBOM that dropped it) stays below a fix that has one.
// Hummingbird only -- everywhere else a missing epoch is the 0 rpm says it is.
func readAtInstalledEpoch(aff advisory.Affected, installed string) advisory.Affected {
	epoch, _, ok := strings.Cut(installed, ":")
	if aff.Ecosystem != "Hummingbird" || !ok || epoch == "0" {
		return aff
	}
	// Copied: the record is the store's.
	aff.Ranges = slices.Clone(aff.Ranges)
	for i, r := range aff.Ranges {
		aff.Ranges[i].Events = slices.Clone(r.Events)
		for j, e := range r.Events {
			if e.Fixed != "" && !strings.Contains(e.Fixed, ":") {
				aff.Ranges[i].Events[j].Fixed = epoch + ":" + e.Fixed
			}
		}
	}
	return aff
}
