package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
)

// No Fedora-specific module-build test lives here, unlike
// TestMatch_OracleModuleBuildFixIsSkippedNotMatched for Oracle Linux and the
// equivalent D46/D71 tests for Red Hat/Rocky/AlmaLinux: Fedora's own release
// strings carry no module platform tag at all (measured against the
// research this slice shipped from -- Bodhi builds are plain NVRs like
// "openssh-8.7p1-1.fc43", never "...module+fc43..."), so
// matcher.rpmModuleBuild's pattern simply never matches one. The guard
// stays gated on the RPM comparer rather than any ecosystem list, so it
// would still catch a modular Fedora build if one ever existed; there is
// just no real data to prove the negative against, the same reasoning
// amazon's own package doc comment gives for omitting an equivalent test.

// TestMatch_FedoraRPMComparerIsWired is the caller-first proof for D75's
// version.go clause: version.For("Fedora:44") must actually be reached
// through Match, not merely resolve in isolation. Mirrors
// TestMatch_OracleRPMComparerIsWired and TestMatch_AmazonRPMComparerIsWired
// exactly, for the identical reason their own doc comments give: deleting
// the "Fedora:" clause from version.go turns this into a coverage skip
// (SkipCoverage, "no version comparer") instead of a finding, and this is
// the only test that would notice.
//
// The target package's Name is deliberately "openssh-server" -- a real
// Fedora subpackage -- while the advisory (as Bodhi's builds[] actually
// name it) is keyed on the SOURCE name "openssh". Package.Source is what
// bridges the two (D8), and this is the divergence proof: without it, this
// package would only be reachable by fluke when the installed name happens
// to equal the source name.
func TestMatch_FedoraRPMComparerIsWired(t *testing.T) {
	const eco = "Fedora:44"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00openssh": {{
				ID:       "FEDORA-2026-0001",
				Database: "FEDORA",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "openssh",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "8.7p1-38.fc44"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "fedora", VersionID: "44"},
		Packages: []pkgmeta.Package{
			// Below the fixed release -- rpmvercmp must actually run for
			// this to come out vulnerable rather than skipped. Installed
			// under the BINARY subpackage name, reachable only via
			// Package.Source (D8): Bodhi's builds[] never name
			// "openssh-server" at all.
			{Name: "openssh-server", Version: "8.7p1-1.fc44", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "openssh"}},
			// At the fixed release already -- proves the comparer is doing
			// real ordering rather than always reporting a hit.
			{Name: "vim", Version: "9.0-1.fc44", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "vim"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	for _, s := range res.Skipped {
		if s.Cause == SkipCoverage && s.Package.Name == "openssh-server" {
			t.Fatalf("openssh-server was skipped for coverage (%q) -- version.For(%q) is not wired", s.Reason, eco)
		}
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1: %+v", len(res.Findings), res.Findings)
	}
	if got := res.Findings[0].Package.Name; got != "openssh-server" {
		t.Errorf("finding is for %q, want openssh-server", got)
	}
	if got := res.Findings[0].Advisory.ID; got != "FEDORA-2026-0001" {
		t.Errorf("Advisory.ID = %q, want FEDORA-2026-0001", got)
	}
}

// TestMatch_FedoraVendorWordSeverityIsDerivedAndGates mirrors
// TestMatch_OracleVendorWordSeverityIsDerivedAndGates and
// TestMatch_AmazonVendorWordSeverityIsDerivedAndGates: a FEDORA record whose
// only severity signal is a VENDOR_WORD entry (D75's shape -- Bodhi carries
// no CVSS vector at all) must still produce a finding with a real,
// gate-able Severity band.
//
// The word here is "Urgent" -- Bodhi's OWN top label, not RHSA's
// "Critical" -- which is what proves the severity.vendorSeverityWords
// extension D75 added is actually reachable through a real match, not just
// through severity.Of called directly (that half is
// severity.TestOf_VendorWord/"Urgent").
func TestMatch_FedoraVendorWordSeverityIsDerivedAndGates(t *testing.T) {
	const eco = "Fedora:43"
	a := advisory.Advisory{
		ID:       "FEDORA-2026-0002",
		Database: "FEDORA",
		Kind:     advisory.KindVulnerability,
		Related:  []string{"CVE-2026-4321"},
		Severity: []advisory.Severity{{Type: "VENDOR_WORD", Score: "Urgent"}},
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      "kernel",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "6.10.5-100.fc43"}},
			}},
		}},
	}
	s := fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00kernel": {a},
		},
	}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("kernel", "6.10.4-99.fc43", eco)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != severity.Critical {
		t.Errorf("Severity = %v, want critical -- \"Urgent\" is Bodhi's own top label", f.Severity)
	}
	if len(f.Ratings) != 1 || f.Ratings[0].Severity != severity.Critical {
		t.Errorf("Ratings = %+v, want one rating banded critical", f.Ratings)
	}
	if !f.Severity.AtOrAbove(severity.Critical) {
		t.Error("Severity.AtOrAbove(critical) = false, want true -- --fail-on critical must catch this finding")
	}
	if f.Severity.AtOrAbove(severity.Unknown) {
		t.Error("Severity.AtOrAbove(unknown) = true, want false -- Unknown never gates (D17)")
	}
	// Identifiers carries the CVE from Related -- Bodhi's REST API has no
	// aliases or upstream field at all, only the id it puts in Related
	// (D75, same shape D71 decision 1/D73/D74 established).
	var gotCVE bool
	for _, id := range f.Identifiers {
		if id == "CVE-2026-4321" {
			gotCVE = true
		}
	}
	if !gotCVE {
		t.Errorf("Identifiers = %v, want CVE-2026-4321", f.Identifiers)
	}
}
