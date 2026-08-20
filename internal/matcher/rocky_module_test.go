package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// TestMatch_RockyModuleBuildFixIsSkippedNotMatched is the behaviour D71's
// module-build guard exists for, exercised through Match rather than by
// calling moduleBuildBound directly — the helper being right proves nothing
// if nothing calls it (CLAUDE.md's own recurring-defect warning).
//
// The fixture's only advisory range fixes at a modular RPM build
// ("module+el" — nodejs:20's real spelling per the D46 upstream table). The
// RPM comparer would happily ORDER that string against the installed version
// (D46: '+' is an ordinary separator to rpmvercmp, so nothing here is
// malformed) — which is exactly the trap: a comparer that CAN order the two
// strings would silently produce a verdict for a comparison the version alone
// cannot answer, because neither side names which module stream it belongs
// to. The guard must intercept before AffectsVersion is ever called for this
// entry.
func TestMatch_RockyModuleBuildFixIsSkippedNotMatched(t *testing.T) {
	const eco = "Rocky Linux:9"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00nodejs": {{
				ID:       "RLSA-2026:0001",
				Database: "RLSA",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "nodejs",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "1:20.20.2-2.module+el9.6.0+24220+c44c288d"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "rocky", VersionID: "9.4"},
		Packages: []pkgmeta.Package{
			// An installed modular build from an OLDER stream context. Above the
			// mainline fix by byte order alone (a real rpm comparison would call
			// this "greater") is not the point: no comparison should be attempted
			// at all, because the fixed bound's stream is unknown.
			{Name: "nodejs", Version: "1:20.18.1-1.module+el9.5.0+21542+abc12345", Ecosystem: eco,
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
		t.Errorf("Findings = %d, want 0 — a module-build fix must not be judged "+
			"as a mainline comparison would judge it", len(res.Findings))
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d entries, want exactly 1 (nodejs, not bash): %+v",
			len(res.Skipped), res.Skipped)
	}
	s := res.Skipped[0]
	if s.Package.Name != "nodejs" {
		t.Errorf("skipped %q, want nodejs — bash carries no module marker and "+
			"must still be evaluated", s.Package.Name)
	}
	if s.AdvisoryID != "RLSA-2026:0001" {
		t.Errorf("AdvisoryID = %q, want RLSA-2026:0001 — this is a per-advisory "+
			"skip, not a whole-package one", s.AdvisoryID)
	}
	if s.Cause != SkipAdvisory {
		t.Errorf("Cause = %q, want %q — the advisory's own bound is what could "+
			"not be resolved, not the installed version", s.Cause, SkipAdvisory)
	}
	if !strings.Contains(s.Reason, "module+el9.6.0") {
		t.Errorf("Reason = %q, want it to quote the module-tagged bound", s.Reason)
	}
}

// TestMatch_RockyMainlineFixIsEvaluated is the other half, and it is the row
// that fails if the detector is too eager. Without it, a check that fired on
// every Rocky Linux advisory would turn every scan into skips and the test
// above would still pass.
func TestMatch_RockyMainlineFixIsEvaluated(t *testing.T) {
	const eco = "Rocky Linux:9"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00bash": {{
				ID:       "RLSA-2026:0002",
				Database: "RLSA",
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
		Distro: &pkgmeta.Distro{ID: "rocky", VersionID: "9.4"},
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
		t.Fatalf("Skipped = %+v, want none — 5.1.8-9.el9 carries no module marker",
			res.Skipped)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if got := res.Findings[0].Advisory.ID; got != "RLSA-2026:0002" {
		t.Errorf("Advisory.ID = %q, want RLSA-2026:0002", got)
	}
}

// TestRpmModuleBuild is the detector's own table, written around the two ways
// it can be wrong: missing a marker lets a module build be silently ordered
// (the exact miss the whole guard exists to prevent), and inventing one turns
// an ordinary RPM release into a skip.
func TestRpmModuleBuild(t *testing.T) {
	for _, tt := range []struct {
		name string
		v    string
		want bool
	}{
		{"Red Hat's own spelling", "1:20.20.2-2.module+el9.6.0+24220+c44c288d", true},
		{"AlmaLinux's spelling", "0:1.0-1.module_el8.5.0+119+9a9ec082", true},
		{"an ordinary RHEL EVR", "0:7.76.1-26.el9_3.2", false},
		{"an ordinary Rocky EVR", "1:8.0.26-1.el8_6", false},
		{"the OSV introduced sentinel", "0", false},
		{"empty", "", false},
		// Adversarial: the word "module" alone, with neither real marker, must
		// not trip the detector — a package or advisory genuinely named
		// "module-something" is not a modular build.
		{"the word module with no el marker", "1.0-1.module-tools", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := rpmModuleBuild(tt.v); got != tt.want {
				t.Errorf("rpmModuleBuild(%q) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}

// TestModuleBuildBound_ChecksIntroducedFixedAndLastAffectedNotVersions pins
// the field scope: the three range-bound fields the walk actually compares
// against the installed version, and NOT the enumerated Versions list, whose
// own match mode (equality) carries none of the stream ambiguity a range
// bound does.
func TestModuleBuildBound_ChecksIntroducedFixedAndLastAffectedNotVersions(t *testing.T) {
	const modBuild = "1:20.20.2-2.module+el9.6.0+24220+c44c288d"
	for _, tt := range []struct {
		name string
		aff  advisory.Affected
		want bool
	}{
		{"module build in Fixed", advisory.Affected{Ranges: []advisory.Range{{
			Events: []advisory.Event{{Introduced: "0"}, {Fixed: modBuild}},
		}}}, true},
		{"module build in Introduced", advisory.Affected{Ranges: []advisory.Range{{
			Events: []advisory.Event{{Introduced: modBuild}},
		}}}, true},
		{"module build in LastAffected", advisory.Affected{Ranges: []advisory.Range{{
			Events: []advisory.Event{{Introduced: "0"}, {LastAffected: modBuild}},
		}}}, true},
		{"module build only in Versions, not Ranges", advisory.Affected{
			Versions: []string{modBuild},
		}, false},
		{"no module marker anywhere", advisory.Affected{Ranges: []advisory.Range{{
			Events: []advisory.Event{{Introduced: "0"}, {Fixed: "5.1.8-9.el9"}},
		}}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, got := moduleBuildBound(tt.aff)
			if got != tt.want {
				t.Errorf("moduleBuildBound(...) ok = %v, want %v", got, tt.want)
			}
		})
	}
}
