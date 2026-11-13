package scancmd

import (
	"testing"
	"time"

	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
)

// PR #321 review: with Debian 4-6 keyed as Debian:4.0 / 5.0 / 6.0, the EOL
// lookup had asked endoflife.date's rows for a "6.0" cycle that is named
// "6" there, so --fail-on-eol stopped firing for exactly the releases that
// are end-of-life. Driven through lookupEOL, the caller of eolCycle.
func TestLookupEOL_DebianTwoPartKeysReachTheirCycle(t *testing.T) {
	rows := []store.EOLRelease{
		{DistroID: "debian", Release: "6", EOLFrom: "2014-05-31"},
		{DistroID: "debian", Release: "4", EOLFrom: "2010-02-15"},
		{DistroID: "debian", Release: "3.1", EOLFrom: "2008-03-31"},
		{DistroID: "debian", Release: "12", EOLFrom: "2028-06-30"},
	}
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		versionID  string
		known, eol bool
	}{
		{"6.0", true, true}, {"6", true, true}, {"6.0.10", true, true},
		{"4.0", true, true}, {"3.1", true, true},
		{"12", true, false}, {"12.15", true, false},
		{"5.0", false, false}, // no row for lenny in this fixture: unknown, never a false trip
	} {
		t.Run(tc.versionID, func(t *testing.T) {
			got := lookupEOL(&pkgmeta.Distro{ID: "debian", VersionID: tc.versionID}, rows, now)
			if got.Known != tc.known || got.EOL != tc.eol {
				t.Fatalf("Debian %s: known %v, EOL %v (%s); want known %v, EOL %v", tc.versionID, got.Known, got.EOL, got.Reason, tc.known, tc.eol)
			}
		})
	}
}
