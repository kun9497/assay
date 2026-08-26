package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// TestMatch_ArchPacmanComparerIsWired is the caller-first proof for D97's
// version.go clause, mirroring TestMatch_AzureLinuxRPMComparerIsWired and
// TestMatch_AmazonRPMComparerIsWired exactly: version.For("Arch:rolling")
// must actually be reached through Match, not merely resolve in isolation
// (version.TestFor_ArchRollingResolvesPacman already covers that half).
// Deleting the "Arch:rolling" entry from version.go's registry turns this
// into a coverage skip (SkipCoverage, "no version comparer") instead of a
// finding, and this is the only test in this package that would notice.
//
// The two package rows also pin pacman's own divergence from rpmvercmp
// (internal/version/pacman.go's own doc comment, measured against the live
// feed): "1.0rc-1" orders BELOW "1.0-1" under pacman's rules but ABOVE it
// under rpm's, so a package sitting between the two really does prove
// pacman ran rather than some other comparer silently substituting.
func TestMatch_ArchPacmanComparerIsWired(t *testing.T) {
	const eco = "Arch:rolling"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00somepkg": {{
				ID:       "AVG-3001",
				Database: "AVG",
				Aliases:  []string{"CVE-2026-77001"},
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "somepkg",
					Ranges: []advisory.Range{{
						Type:   advisory.RangeEcosystem,
						Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0-1"}},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "arch"},
		Packages: []pkgmeta.Package{
			// Below the fix under EITHER comparer's rules -- the ordinary
			// positive control.
			{Name: "somepkg", Version: "0.9-1", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "somepkg"}},
			// pacman's own "a remaining alpha string never beats an empty
			// one" rule (vercmp(8)'s documented chain) orders "1.0rc-1"
			// BELOW "1.0-1" -- still vulnerable under pacman, but rpmvercmp
			// would call this ALREADY FIXED (its own "2.0.1a" > "2.0.1"
			// rule), so a finding here can only come from pacman actually
			// running.
			{Name: "somepkg", Version: "1.0rc-1", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "somepkg"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	for _, s := range res.Skipped {
		if s.Cause == SkipCoverage {
			t.Fatalf("somepkg was skipped for coverage (%q) -- version.For(%q) is not wired", s.Reason, eco)
		}
	}
	if len(res.Findings) != 2 {
		t.Fatalf("Findings = %d, want exactly 2 (both rows sit below the fix under pacman's own rules): %+v",
			len(res.Findings), res.Findings)
	}
}

// TestMatch_ArchBaseRoutedAdvisoryMatchedNameIsBase is D8's exact analogue
// for pacman: an advisory naming elfutils (Arch's own pkgbase) must reach
// an installed libelf package through Package.Source, exactly the way
// TestMatch_SourcePackageReachesTheAdvisory pins it for Alpine's o: origin
// -- and the resulting Finding's MatchedName must be the BASE name
// (elfutils), not the installed package's own name (libelf), so a reader
// can tell which name the advisory was actually written against (D10).
func TestMatch_ArchBaseRoutedAdvisoryMatchedNameIsBase(t *testing.T) {
	const eco = "Arch:rolling"
	adv := advisory.Advisory{
		ID:       "AVG-3002",
		Database: "AVG",
		Aliases:  []string{"CVE-2026-77002"},
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      "elfutils",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "0.197-1"}},
			}},
		}},
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		eco + "\x00elfutils": {adv},
	}}

	p := pkgmeta.Package{Name: "libelf", Version: "0.196-1", Ecosystem: eco,
		Source: &pkgmeta.SourcePackage{Name: "elfutils"}}

	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1: an elfutils advisory must reach libelf "+
			"through Package.Source; got %+v", len(res.Findings), res.Findings)
	}
	if got := res.Findings[0].MatchedName; got != "elfutils" {
		t.Errorf("MatchedName = %q, want %q", got, "elfutils")
	}
	if res.Findings[0].Package.Name != "libelf" {
		t.Errorf("Package.Name = %q, want libelf (the installed package, unchanged)", res.Findings[0].Package.Name)
	}
	if res.Findings[0].MatchedViaProvides {
		t.Error("MatchedViaProvides = true, want false: this is a D8 source-package join, not D95's apk provides one")
	}
}

// TestMatch_ArchVulnerableStatusYieldsNotFixedFinding drives D97's
// "Vulnerable" status shape (buildAdvisories in internal/provider/arch: a
// fix-less range carrying FixState NotFixed) through Match, mirroring
// TestMatch_FixStateFlowsFromRangeThroughToRating's own proof that D52's
// FixState machinery is generic, ecosystem-agnostic wiring -- this pins
// that Arch's OWN shape reaches it, not just Red Hat's/SUSE's.
func TestMatch_ArchVulnerableStatusYieldsNotFixedFinding(t *testing.T) {
	const eco = "Arch:rolling"
	notFixed := advisory.Advisory{
		ID:       "AVG-2907",
		Database: "AVG",
		Aliases:  []string{"CVE-2026-77003"},
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      "djvulibre",
			Ranges: []advisory.Range{{
				Type:     advisory.RangeEcosystem,
				Events:   []advisory.Event{{Introduced: "0"}},
				FixState: advisory.FixStateNotFixed,
			}},
		}},
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		eco + "\x00djvulibre": {notFixed},
	}}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{
			{Name: "djvulibre", Version: "3.5.28-6", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "djvulibre"}},
		},
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if got := res.Findings[0].Ratings[0].FixState; got != advisory.FixStateNotFixed {
		t.Errorf("Rating.FixState = %q, want %q -- Arch's own \"Vulnerable\" status is the positive "+
			"evidence D52 requires, not an inference from an absent fixed version", got, advisory.FixStateNotFixed)
	}
	if got := res.Findings[0].FixState(); got != advisory.FixStateNotFixed {
		t.Errorf("Finding.FixState() = %q, want %q", got, advisory.FixStateNotFixed)
	}
}

// TestMatch_ArchTestingStatusYieldsFixedVersion drives D97's "Testing"
// status shape through Match: the fix exists in the testing repository, so
// buildAdvisories emits an ordinary FIXED range (no FixState) exactly as it
// does for "Fixed" -- proven here by an installed version below that fix
// producing a finding whose Rating resolves to FixStateFixed, and one AT
// the fix producing none.
func TestMatch_ArchTestingStatusYieldsFixedVersion(t *testing.T) {
	const eco = "Arch:rolling"
	// This is the exact shape internal/provider/arch's buildAdvisories
	// emits for status "Testing": a Range carrying a real Fixed event and
	// no FixState at all (FixState is stored ONLY on fix-less ranges,
	// advisory.Range.FixState's own doc comment).
	fixedInTesting := advWithRange("AVG-9001", eco, "openssl", "0", "3.5.5-1", advisory.RangeEcosystem)
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		eco + "\x00openssl": {fixedInTesting},
	}}

	below, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{
			{Name: "openssl", Version: "3.5.4-1", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "openssl"}},
		},
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(below.Findings) != 1 {
		t.Fatalf("Findings (below the testing fix) = %d, want 1", len(below.Findings))
	}
	if got := below.Findings[0].Ratings[0].FixState; got != advisory.FixStateFixed {
		t.Errorf("Rating.FixState = %q, want %q -- a Testing-status range has a real fixed "+
			"version, so it resolves fixed by construction (fixStateOf)", got, advisory.FixStateFixed)
	}
	if got := below.Findings[0].Ratings[0].Fixed; got != "3.5.5-1" {
		t.Errorf("Rating.Fixed = %q, want %q", got, "3.5.5-1")
	}

	atFix, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{
			{Name: "openssl", Version: "3.5.5-1", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "openssl"}},
		},
	})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(atFix.Findings) != 0 {
		t.Errorf("Findings (at the testing fix) = %d, want 0 -- a package already at the fixed "+
			"version must not be reported vulnerable", len(atFix.Findings))
	}
}
