package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
)

// TestMatch_OracleRPMComparerIsWired is the caller-first proof for D74's
// version.go clause: version.For("Oracle Linux:9") must actually be reached
// through Match, not merely resolve in isolation. Mirrors
// TestMatch_AmazonRPMComparerIsWired exactly, for the identical reason its
// own doc comment gives: deleting the "Oracle Linux:" clause from version.go
// turns this into a coverage skip (SkipCoverage, "no version comparer")
// instead of a finding, and this is the only test that would notice.
func TestMatch_OracleRPMComparerIsWired(t *testing.T) {
	const eco = "Oracle Linux:9"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00openssh": {{
				ID:       "ELSA-2026-0001",
				Database: "ELSA",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "openssh",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "0:8.7p1-38.el9_8"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "ol", VersionID: "9.8"},
		Packages: []pkgmeta.Package{
			// Below the fixed release -- rpmvercmp must actually run for
			// this to come out vulnerable rather than skipped.
			{Name: "openssh", Version: "0:8.7p1-1.el9", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "openssh"}},
			// At the fixed release already -- proves the comparer is doing
			// real ordering rather than always reporting a hit.
			{Name: "vim", Version: "0:9.0-1.el9", Ecosystem: eco,
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
	if got := res.Findings[0].Advisory.ID; got != "ELSA-2026-0001" {
		t.Errorf("Advisory.ID = %q, want ELSA-2026-0001", got)
	}
}

// TestMatch_OracleVendorWordSeverityIsDerivedAndGates mirrors
// alma_test.go's TestMatch_AlmaVendorWordSeverityIsDerivedAndGates: an ELSA
// record whose only severity signal is a VENDOR_WORD entry (D74's shape for
// the 7 N/A definitions and, more commonly, alongside a real CVSS_V3 entry --
// this fixture carries only the word, the v2-only/no-vector shape) must
// still produce a finding with a real, gate-able Severity band.
func TestMatch_OracleVendorWordSeverityIsDerivedAndGates(t *testing.T) {
	const eco = "Oracle Linux:6"
	a := advisory.Advisory{
		ID:       "ELSA-2013-0002",
		Database: "ELSA",
		Kind:     advisory.KindVulnerability,
		Related:  []string{"CVE-2012-3430"},
		Severity: []advisory.Severity{{Type: "VENDOR_WORD", Score: "Important"}},
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      "openssl",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "0:1.0.1e-16.el6"}},
			}},
		}},
	}
	s := fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00openssl": {a},
		},
	}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("openssl", "0:1.0.1e-15.el6", eco)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != severity.High {
		t.Errorf("Severity = %v, want high -- \"Important\" is the RHSA word for High", f.Severity)
	}
	if len(f.Ratings) != 1 || f.Ratings[0].Severity != severity.High {
		t.Errorf("Ratings = %+v, want one rating banded high", f.Ratings)
	}
	if !f.Severity.AtOrAbove(severity.High) {
		t.Error("Severity.AtOrAbove(high) = false, want true -- --fail-on high must catch this finding")
	}
	if f.Severity.AtOrAbove(severity.Critical) {
		t.Error("Severity.AtOrAbove(critical) = true, want false -- \"Important\" is High, not Critical")
	}
	// Identifiers carries the CVE from Related -- Oracle's OVAL reference
	// list is the only place a definition's CVE lives (D74, the same shape
	// D71 decision 1 established for AlmaLinux and D73 for Amazon Linux).
	var gotCVE bool
	for _, id := range f.Identifiers {
		if id == "CVE-2012-3430" {
			gotCVE = true
		}
	}
	if !gotCVE {
		t.Errorf("Identifiers = %v, want CVE-2012-3430", f.Identifiers)
	}
}

// TestMatch_OracleModuleBuildFixIsSkippedNotMatched proves the EXISTING
// module-build guard (D71/D47's moduleBuildBound, gated on the RPM comparer
// and not on any particular ecosystem string) reaches Oracle Linux data for
// free, once version.For routes "Oracle Linux:" to RPM{}. This is not
// hypothetical: Oracle Linux is a RHEL rebuild and its OVAL feed spells a
// modular build's platform tag identically to Red Hat's own
// ("module+el9.8.0+90993+075b4fd6", measured directly against nodejs's real
// fixed-EVR set 2026-08-19), so nothing in oval.go has to detect this shape
// at all -- the guard this slice reuses already does, at match time, for
// every RPM-family ecosystem.
func TestMatch_OracleModuleBuildFixIsSkippedNotMatched(t *testing.T) {
	const eco = "Oracle Linux:9"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00nodejs": {{
				ID:       "ELSA-2026-0003",
				Database: "ELSA",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "nodejs",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "1:24.18.0-6.module+el9.8.0+90993+075b4fd6"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "ol", VersionID: "9.8"},
		Packages: []pkgmeta.Package{
			// ModuleStream as the D80 cataloger reads it; Oracle OVAL entries
			// gain streams in D81, so this one is stream-blind and the
			// per-advisory skip is still the asserted path.
			{Name: "nodejs", Version: "1:20.19.1-1.module+el9.6.0+90603+e4b3d4d2", Ecosystem: eco, ModuleStream: "nodejs:20",
				Source: &pkgmeta.SourcePackage{Name: "nodejs"}},
			{Name: "bash", Version: "0:5.1.8-9.el9", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "bash"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 -- a modular build fix must not be judged "+
			"as a mainline comparison would judge it", len(res.Findings))
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d entries, want exactly 1 (nodejs, not bash): %+v",
			len(res.Skipped), res.Skipped)
	}
	s := res.Skipped[0]
	if s.Package.Name != "nodejs" {
		t.Errorf("skipped %q, want nodejs -- bash carries no module marker and must still be evaluated", s.Package.Name)
	}
	if s.Cause != SkipAdvisory {
		t.Errorf("Cause = %q, want %q", s.Cause, SkipAdvisory)
	}
	if !strings.Contains(s.Reason, "module+el9.8.0") {
		t.Errorf("Reason = %q, want it to quote the module-tagged bound", s.Reason)
	}
}
