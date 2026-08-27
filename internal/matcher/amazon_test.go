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

// TestMatch_AmazonNvidiaAdvisoryReachableUnderAL2023Key is the caller-first
// proof for D100: an ALAS2023NVIDIA advisory (real ID and CVE, measured live
// 2026-08-27 against cdn.amazonlinux.com/al2023/nvidia) must produce a
// finding under the SAME "Amazon Linux:2023" ecosystem key core uses -- an
// NVIDIA advisory is a source of advisories for AL2023, not a separate
// ecosystem (amazon.DefaultRepos' own doc comment). Measured zero CVE and
// package-name overlap between NVIDIA and AL2023 core (58 distinct CVEs,
// entirely disjoint), so this CVE would be invisible to a core-only database
// -- deleting the NVIDIA entry from amazon.DefaultRepos removes exactly this
// coverage from a real `assay db build`, and nothing else in this package
// would notice.
func TestMatch_AmazonNvidiaAdvisoryReachableUnderAL2023Key(t *testing.T) {
	const eco = "Amazon Linux:2023"
	a := advisory.Advisory{
		ID:       "ALAS2023NVIDIA-2025-001",
		Database: "ALAS2023NVIDIA",
		Kind:     advisory.KindVulnerability,
		Related:  []string{"CVE-2025-23359"},
		Severity: []advisory.Severity{{Type: "VENDOR_WORD", Score: "Important"}},
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      "libnvidia-container1",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.17.4-1"}},
			}},
		}},
	}
	s := fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00libnvidia-container1": {a},
		},
	}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("libnvidia-container1", "1.17.3-1", eco)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1 -- an NVIDIA advisory must be reachable through the SAME "+
			"Amazon Linux:2023 key core uses, not a separate ecosystem", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Advisory.ID != "ALAS2023NVIDIA-2025-001" {
		t.Errorf("Advisory.ID = %q, want ALAS2023NVIDIA-2025-001", f.Advisory.ID)
	}
	var gotCVE bool
	for _, id := range f.Identifiers {
		if id == "CVE-2025-23359" {
			gotCVE = true
		}
	}
	if !gotCVE {
		t.Errorf("Identifiers = %v, want CVE-2025-23359 -- invisible to a core-only database "+
			"(measured zero CVE overlap between NVIDIA's 58 CVEs and AL2023 core's own)", f.Identifiers)
	}
}

// TestMatch_AmazonLivepatchQualifiedPackageMatchesItsOwnName pins the other
// half of D100's livepatch guard from the matcher side: an installed
// kernel-livepatch package below its advisory's fixed version must produce a
// finding keyed on its own fully-qualified name, and a DIFFERENT installed
// kernel-livepatch build (a different kernel/patch version, still not the
// bare "kernel" collision the amazon package doc comment measures away) must
// not be flagged by an advisory that never names it.
func TestMatch_AmazonLivepatchQualifiedPackageMatchesItsOwnName(t *testing.T) {
	const eco = "Amazon Linux:2023"
	a := advisory.Advisory{
		ID:       "ALAS2023LIVEPATCH-2023-001",
		Database: "ALAS2023LIVEPATCH",
		Kind:     advisory.KindVulnerability,
		Related:  []string{"CVE-2023-26545"},
		Severity: []advisory.Severity{{Type: "VENDOR_WORD", Score: "Important"}},
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      "kernel-livepatch-6.1.12-19.43",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0-1.amzn2023"}},
			}},
		}},
	}
	s := fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00kernel-livepatch-6.1.12-19.43": {a},
		},
	}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{
			// Below the fixed release for the package the advisory actually names.
			pkg("kernel-livepatch-6.1.12-19.43", "1.0-0.amzn2023", eco),
			// A DIFFERENTLY-qualified livepatch build for another kernel version --
			// no advisory names it, so it must not be flagged.
			pkg("kernel-livepatch-6.1.19-30.43", "1.0-0.amzn2023", eco),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1: %+v", len(res.Findings), res.Findings)
	}
	if got := res.Findings[0].Package.Name; got != "kernel-livepatch-6.1.12-19.43" {
		t.Errorf("finding is for %q, want kernel-livepatch-6.1.12-19.43", got)
	}
}
