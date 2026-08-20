package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
)

// TestMatch_AlmaModuleBuildFixIsSkippedNotMatched is D71/D47's module-build
// guard, inherited by AlmaLinux rather than reimplemented: the guard in
// Match is gated on the RPM comparer (`if _, isRPM := cmp.(version.RPM)`),
// not on any particular ecosystem string, so version.For routing
// "AlmaLinux:9" to RPM{} is what makes this fire. Driven through Match
// rather than by calling moduleBuildBound directly, for the same reason
// rocky_module_test.go's sibling test is: the helper being right proves
// nothing if nothing calls it for THIS ecosystem (CLAUDE.md's own
// recurring-defect warning) -- version.For could resolve "AlmaLinux:9" to a
// comparer that is not version.RPM, and every other test in this package
// would stay green.
//
// The fixture's spelling is Alma's own ("module_el", not Red Hat/Rocky's
// "module+el" -- rpmModuleBuild's own table already covers both spellings in
// isolation; this proves the ALMA spelling specifically reaches the guard
// through a real AlmaLinux match).
func TestMatch_AlmaModuleBuildFixIsSkippedNotMatched(t *testing.T) {
	const eco = "AlmaLinux:9"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00nodejs": {{
				ID:       "ALSA-2026:0001",
				Database: "ALSA",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "nodejs",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "1:20.20.2-2.module_el8.5.0+119+9a9ec082"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "almalinux", VersionID: "9.6"},
		Packages: []pkgmeta.Package{
			// An installed modular build from an OLDER stream context. No
			// comparison should be attempted at all, because the fixed
			// bound's stream is unknown from the release string alone.
			{Name: "nodejs", Version: "1:20.18.1-1.module_el8.5.0+21542+abc12345", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "nodejs"}},
			// An ordinary package on the same target, to prove the skip is
			// per-advisory and does not poison the rest of the scan.
			{Name: "bash", Version: "5.1.8-9.el9", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "bash"}},
		},
	}

	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 -- a module-build fix must not be judged "+
			"as a mainline comparison would judge it", len(res.Findings))
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d entries, want exactly 1 (nodejs, not bash): %+v",
			len(res.Skipped), res.Skipped)
	}
	s := res.Skipped[0]
	if s.Package.Name != "nodejs" {
		t.Errorf("skipped %q, want nodejs -- bash carries no module marker and "+
			"must still be evaluated", s.Package.Name)
	}
	if s.AdvisoryID != "ALSA-2026:0001" {
		t.Errorf("AdvisoryID = %q, want ALSA-2026:0001", s.AdvisoryID)
	}
	if s.Cause != SkipAdvisory {
		t.Errorf("Cause = %q, want %q", s.Cause, SkipAdvisory)
	}
	if !strings.Contains(s.Reason, "module_el8.5.0") {
		t.Errorf("Reason = %q, want it to quote the module-tagged bound", s.Reason)
	}
}

// TestMatch_AlmaMainlineFixIsEvaluated is the other half, and it is the row
// that fails if the guard is too eager. Without it, a check that fired on
// every AlmaLinux advisory would turn every scan into skips and the test
// above would still pass.
func TestMatch_AlmaMainlineFixIsEvaluated(t *testing.T) {
	const eco = "AlmaLinux:9"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00bash": {{
				ID:       "ALSA-2026:0002",
				Database: "ALSA",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "bash",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "5.1.8-9.el9"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "almalinux", VersionID: "9.6"},
		Packages: []pkgmeta.Package{
			{Name: "bash", Version: "5.1.8-6.el9", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "bash"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Skipped) != 0 {
		t.Fatalf("Skipped = %+v, want none -- 5.1.8-9.el9 carries no module marker",
			res.Skipped)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if got := res.Findings[0].Advisory.ID; got != "ALSA-2026:0002" {
		t.Errorf("Advisory.ID = %q, want ALSA-2026:0002", got)
	}
}

// TestMatch_FindingIdentifiersIncludeRelated is D72's lookupIDs extension
// (item B), driven through Match beside TestMatch_FindingIdentifiersInclude-
// Upstream rather than by calling lookupIDs directly -- the helper being
// right proves nothing if nothing calls it. This fixture is AlmaLinux's own
// measured shape: Aliases and Upstream both empty, the CVE reachable only
// through Related. Losing Related here silently disconnects such a finding
// from the CVE that --explain's lookup and a `scan | grep CVE-…` both depend
// on -- exactly the failure D71 decision 1 exists to prevent for the one
// provider whose whole feed is shaped this way.
func TestMatch_FindingIdentifiersIncludeRelated(t *testing.T) {
	a := advisory.Advisory{
		ID:       "ALSA-2026:0003",
		Database: "ALSA",
		Kind:     advisory.KindVulnerability,
		Related:  []string{"CVE-2026-2"}, // no Aliases, no Upstream -- Alma's own shape
		Affected: []advisory.Affected{{
			Ecosystem: "AlmaLinux:9",
			Name:      "openssh",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "8.7p1-38.el9"}},
			}},
		}},
	}
	s := fakeStore{
		covers: []string{"AlmaLinux:9"},
		byKey: map[string][]advisory.Advisory{
			"AlmaLinux:9\x00openssh": {a},
		},
	}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("openssh", "8.0p1-5.el9", "AlmaLinux:9")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	var gotRelated bool
	for _, id := range res.Findings[0].Identifiers {
		if id == "CVE-2026-2" {
			gotRelated = true
		}
	}
	if !gotRelated {
		t.Errorf("Identifiers = %v, want CVE-2026-2 from Related (D72) -- --explain and a "+
			"CVE-keyed grep both read this field", res.Findings[0].Identifiers)
	}
}

// TestMatch_AlmaVendorWordSeverityIsDerivedAndGates is item C's/E's
// matcher-level proof: an ALSA record whose ONLY severity signal is a
// VENDOR_WORD entry (AlmaLinux's measured shape -- 0% CVSS anywhere) must
// still produce a finding with a real, gate-able Severity band, not an
// Unknown one that --fail-on silently ignores (D17).
//
// Checked against severity.Band.AtOrAbove directly rather than through the
// CLI, because AtOrAbove IS the whole of what scancmd's --fail-on gate calls
// (internal/scancmd/scancmd.go: `f.Severity.AtOrAbove(*opts.FailOn)`) --
// there is no Alma-specific gating code for a CLI-level test to exercise
// that this does not already reach directly.
func TestMatch_AlmaVendorWordSeverityIsDerivedAndGates(t *testing.T) {
	a := advisory.Advisory{
		ID:       "ALSA-2026:0004",
		Database: "ALSA",
		Kind:     advisory.KindVulnerability,
		Related:  []string{"CVE-2026-3"},
		Severity: []advisory.Severity{{Type: "VENDOR_WORD", Score: "Important"}},
		Affected: []advisory.Affected{{
			Ecosystem: "AlmaLinux:9",
			Name:      "openssh",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "8.7p1-38.el9"}},
			}},
		}},
	}
	s := fakeStore{
		covers: []string{"AlmaLinux:9"},
		byKey: map[string][]advisory.Advisory{
			"AlmaLinux:9\x00openssh": {a},
		},
	}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("openssh", "8.0p1-5.el9", "AlmaLinux:9")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	// Reported: the band is on the finding, not lost as Unknown.
	if f.Severity != severity.High {
		t.Errorf("Severity = %v, want high -- \"Important\" is the RHSA word for High", f.Severity)
	}
	if len(f.Ratings) != 1 || f.Ratings[0].Severity != severity.High {
		t.Errorf("Ratings = %+v, want one rating banded high", f.Ratings)
	}
	// Gated: the exact call --fail-on makes.
	if !f.Severity.AtOrAbove(severity.High) {
		t.Error("Severity.AtOrAbove(high) = false, want true -- --fail-on high must catch this finding")
	}
	if f.Severity.AtOrAbove(severity.Critical) {
		t.Error("Severity.AtOrAbove(critical) = true, want false -- \"Important\" is High, not Critical")
	}
	// Identifiers still carries the CVE, from Related (the only place this
	// record's CVE lives).
	var gotCVE bool
	for _, id := range f.Identifiers {
		if id == "CVE-2026-3" {
			gotCVE = true
		}
	}
	if !gotCVE {
		t.Errorf("Identifiers = %v, want CVE-2026-3", f.Identifiers)
	}
}
