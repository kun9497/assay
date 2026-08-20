package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
)

// TestMatch_AmazonRPMComparerIsWired is the caller-first proof for D73's
// version.go clause: version.For("Amazon Linux:2") must actually be reached
// through Match, not merely resolve in isolation. Driven exactly the way
// alma_test.go's own module-build test explains its reasoning -- the helper
// being right proves nothing if nothing calls it for THIS ecosystem
// (CLAUDE.md's own recurring-defect warning). Deleting the "Amazon Linux:"
// clause from version.go turns this into a coverage skip (SkipCoverage, "no
// version comparer") instead of a finding, and this is the only test that
// would notice.
func TestMatch_AmazonRPMComparerIsWired(t *testing.T) {
	const eco = "Amazon Linux:2"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00openssh": {{
				ID:       "ALAS2-2026-0001",
				Database: "ALAS2",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "openssh",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "8.7p1-38.amzn2"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "amzn", VersionID: "2"},
		Packages: []pkgmeta.Package{
			// Below the fixed release -- rpmvercmp must actually run for
			// this to come out vulnerable rather than skipped.
			{Name: "openssh", Version: "8.7p1-1.amzn2", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "openssh"}},
			// At the fixed release already -- proves the comparer is doing
			// real ordering rather than always reporting a hit.
			{Name: "vim", Version: "9.0-1.amzn2", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "vim"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	for _, s := range res.Skipped {
		if s.Cause == SkipCoverage && s.Package.Name == "openssh" {
			t.Fatalf("openssh was skipped for coverage (%q) -- version.For(%q) is not wired", s.Reason, eco)
		}
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1: %+v", len(res.Findings), res.Findings)
	}
	if got := res.Findings[0].Package.Name; got != "openssh" {
		t.Errorf("finding is for %q, want openssh", got)
	}
	if got := res.Findings[0].Advisory.ID; got != "ALAS2-2026-0001" {
		t.Errorf("Advisory.ID = %q, want ALAS2-2026-0001", got)
	}
}

// TestMatch_AmazonVendorWordSeverityIsDerivedAndGates mirrors
// alma_test.go's TestMatch_AlmaVendorWordSeverityIsDerivedAndGates exactly:
// an ALAS record whose only severity signal is a VENDOR_WORD entry (D73's
// shape, same as D72's -- Amazon's updateinfo carries no CVSS vector at all)
// must still produce a finding with a real, gate-able Severity band.
//
// The word here is "Medium" -- Amazon's own spelling (D73), not RHSA's
// "Moderate" -- which is what proves the severity.vendorSeverityWords
// extension is actually reachable through a real match, not just through
// severity.Of called directly (that half is
// severity.TestOf_VendorWord/"Medium").
func TestMatch_AmazonVendorWordSeverityIsDerivedAndGates(t *testing.T) {
	const eco = "Amazon Linux:2023"
	a := advisory.Advisory{
		ID:       "ALAS2023-2026-0002",
		Database: "ALAS2023",
		Kind:     advisory.KindVulnerability,
		Related:  []string{"CVE-2026-4"},
		Severity: []advisory.Severity{{Type: "VENDOR_WORD", Score: "Medium"}},
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      "curl",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "8.5.0-1.amzn2023"}},
			}},
		}},
	}
	s := fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00curl": {a},
		},
	}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("curl", "8.4.0-1.amzn2023", eco)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != severity.Medium {
		t.Errorf("Severity = %v, want medium -- \"Medium\" is Amazon's own word for that band", f.Severity)
	}
	if len(f.Ratings) != 1 || f.Ratings[0].Severity != severity.Medium {
		t.Errorf("Ratings = %+v, want one rating banded medium", f.Ratings)
	}
	// Gated: the exact call --fail-on makes.
	if !f.Severity.AtOrAbove(severity.Medium) {
		t.Error("Severity.AtOrAbove(medium) = false, want true -- --fail-on medium must catch this finding")
	}
	if f.Severity.AtOrAbove(severity.High) {
		t.Error("Severity.AtOrAbove(high) = true, want false -- \"Medium\" is Medium, not High")
	}
	// Identifiers carries the CVE from Related -- ALAS records carry no
	// aliases or upstream field at all, only references (D73, same shape
	// D71 decision 1 established for AlmaLinux).
	var gotCVE bool
	for _, id := range f.Identifiers {
		if id == "CVE-2026-4" {
			gotCVE = true
		}
	}
	if !gotCVE {
		t.Errorf("Identifiers = %v, want CVE-2026-4", f.Identifiers)
	}
}
