package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// modAdv builds one advisory with a single module-scoped affected entry —
// the shape the D80 Red Hat provider emits. IDs and package names are chosen
// not to collide as substrings (CLAUDE.md).
func modAdv(id, eco, name, stream, fixed string) advisory.Advisory {
	return advisory.Advisory{
		ID:       id,
		Database: "REDHAT",
		Affected: []advisory.Affected{{
			Ecosystem:    eco,
			Name:         name,
			ModuleStream: stream,
			Ranges: []advisory.Range{{
				Type: advisory.RangeEcosystem,
				Events: []advisory.Event{
					{Introduced: "0"},
					{Fixed: fixed},
				},
			}},
		}},
	}
}

// TestMatch_StreamMatchedModuleFixMatches drives the whole D80 happy path
// through Match: a package installed from nodejs:18 is judged against a
// nodejs:18-scoped fix and nothing else. Two installed versions pin the two
// halves of the tail-truncation rule: one is below the fix by its PREFIX and
// must match; the other has the identical prefix and differs only in its
// (lower) tail, and must not — a matcher ordering full EVRs would call it
// vulnerable by MBS hash, D25's forbidden tie-break wearing version clothing.
func TestMatch_StreamMatchedModuleFixMatches(t *testing.T) {
	const eco = "Red Hat:8"
	const fixedEVR = "1:18.20.8-1.module+el8.10.0+23091+f8fc3a53"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00nodejs": {modAdv("TEST-MOD-0001", eco, "nodejs", "nodejs:18", fixedEVR)},
		},
	}

	t.Run("below the fix by prefix", func(t *testing.T) {
		target := pkgmeta.Target{
			Distro: &pkgmeta.Distro{ID: "rhel", VersionID: "8.10"},
			Packages: []pkgmeta.Package{{
				Name: "nodejs", Version: "1:18.20.7-1.module+el8.10.0+11111+aaaaaaaa",
				Ecosystem: eco, ModuleStream: "nodejs:18",
				Source: &pkgmeta.SourcePackage{Name: "nodejs"},
			}},
		}
		res, err := New(store).Match(target)
		if err != nil {
			t.Fatalf("Match: %v", err)
		}
		if len(res.Skipped) != 0 {
			t.Fatalf("Skipped = %+v, want none — same stream is a sound comparison", res.Skipped)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("Findings = %d, want 1", len(res.Findings))
		}
		f := res.Findings[0]
		if f.Advisory.ID != "TEST-MOD-0001" {
			t.Errorf("Advisory.ID = %q, want TEST-MOD-0001", f.Advisory.ID)
		}
		// D10: the evidence must quote the advisory's REAL fixed build, not
		// the truncated string the comparison ran on — the report tells
		// someone what to upgrade to.
		if f.Evidence.Fixed != fixedEVR {
			t.Errorf("Evidence.Fixed = %q, want the full module EVR %q", f.Evidence.Fixed, fixedEVR)
		}
	})

	t.Run("same prefix, tail differs only", func(t *testing.T) {
		// The installed tail is LOWER than the fix's (11111 < 23091): a
		// matcher ordering full EVRs would call this vulnerable on tail
		// alone, so this row goes red if the truncation is removed.
		target := pkgmeta.Target{
			Distro: &pkgmeta.Distro{ID: "rhel", VersionID: "8.10"},
			Packages: []pkgmeta.Package{{
				Name: "nodejs", Version: "1:18.20.8-1.module+el8.10.0+11111+aaaaaaaa",
				Ecosystem: eco, ModuleStream: "nodejs:18",
				Source: &pkgmeta.SourcePackage{Name: "nodejs"},
			}},
		}
		res, err := New(store).Match(target)
		if err != nil {
			t.Fatalf("Match: %v", err)
		}
		if len(res.Findings) != 0 {
			t.Errorf("Findings = %+v, want none — the prefix equals the fix, and the "+
				"tail must decide nothing", res.Findings)
		}
		if len(res.Skipped) != 0 {
			t.Errorf("Skipped = %+v, want none", res.Skipped)
		}
	})
}

// TestMatch_StreamScopingIsMutual holds the inapplicability rules, all
// silent: a different stream's fix, a streamed fix against a non-modular
// package, and a plain mainline fix against a module package each say
// nothing about the package at hand — none is a finding and none is a skip,
// the same silence a sibling ecosystem's entry gets.
func TestMatch_StreamScopingIsMutual(t *testing.T) {
	const eco = "Red Hat:8"
	plain := advisory.Advisory{
		ID:       "TEST-MOD-0004",
		Database: "REDHAT",
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      "nodejs",
			Ranges: []advisory.Range{{
				Type: advisory.RangeEcosystem,
				Events: []advisory.Event{
					{Introduced: "0"},
					{Fixed: "1:18.99.0-1.el8"},
				},
			}},
		}},
	}
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00nodejs": {
				modAdv("TEST-MOD-0003", eco, "nodejs", "nodejs:20", "1:20.99.0-1.module+el8.10.0+22222+bbbbbbbb"),
				plain,
			},
		},
	}

	t.Run("module package sees neither other-stream nor mainline", func(t *testing.T) {
		target := pkgmeta.Target{
			Distro: &pkgmeta.Distro{ID: "rhel", VersionID: "8.10"},
			Packages: []pkgmeta.Package{{
				Name: "nodejs", Version: "1:18.20.7-1.module+el8.10.0+11111+aaaaaaaa",
				Ecosystem: eco, ModuleStream: "nodejs:18",
				Source: &pkgmeta.SourcePackage{Name: "nodejs"},
			}},
		}
		res, err := New(store).Match(target)
		if err != nil {
			t.Fatalf("Match: %v", err)
		}
		if len(res.Findings) != 0 || len(res.Skipped) != 0 {
			t.Errorf("Findings = %+v, Skipped = %+v; want both empty — a nodejs:20 fix and "+
				"a mainline fix are both inapplicable to a nodejs:18 install",
				res.Findings, res.Skipped)
		}
	})

	t.Run("non-modular package sees only the mainline entry", func(t *testing.T) {
		target := pkgmeta.Target{
			Distro: &pkgmeta.Distro{ID: "rhel", VersionID: "8.10"},
			Packages: []pkgmeta.Package{{
				Name: "nodejs", Version: "1:18.20.7-1.el8",
				Ecosystem: eco,
				Source:    &pkgmeta.SourcePackage{Name: "nodejs"},
			}},
		}
		res, err := New(store).Match(target)
		if err != nil {
			t.Fatalf("Match: %v", err)
		}
		if len(res.Findings) != 1 || res.Findings[0].Advisory.ID != "TEST-MOD-0004" {
			t.Fatalf("Findings = %+v, want exactly the mainline advisory TEST-MOD-0004", res.Findings)
		}
		if len(res.Skipped) != 0 {
			t.Errorf("Skipped = %+v, want none — the nodejs:20 entry is silently inapplicable",
				res.Skipped)
		}
	})
}

// TestMatch_ModuleBuildWithNoStreamIsNotEvaluated holds decision ② of D80:
// a module-tagged version arriving with no readable stream is reported not
// evaluated at the PACKAGE level — never mistaken for a non-modular package,
// which would silently judge it against mainline bounds. The sibling package
// proves the skip does not poison the scan.
func TestMatch_ModuleBuildWithNoStreamIsNotEvaluated(t *testing.T) {
	const eco = "Red Hat:8"
	store := &fakeStore{
		covers: []string{eco},
		byKey: map[string][]advisory.Advisory{
			eco + "\x00sed": {{
				ID:       "TEST-MOD-0005",
				Database: "REDHAT",
				Affected: []advisory.Affected{{
					Ecosystem: eco,
					Name:      "sed",
					Ranges: []advisory.Range{{
						Type: advisory.RangeEcosystem,
						Events: []advisory.Event{
							{Introduced: "0"},
							{Fixed: "4.5-6.el8"},
						},
					}},
				}},
			}},
		},
	}
	target := pkgmeta.Target{
		Distro: &pkgmeta.Distro{ID: "rhel", VersionID: "8.10"},
		Packages: []pkgmeta.Package{
			{Name: "nodejs", Version: "1:18.20.7-1.module+el8.10.0+11111+aaaaaaaa",
				Ecosystem: eco,
				Source:    &pkgmeta.SourcePackage{Name: "nodejs"}},
			{Name: "sed", Version: "4.5-5.el8", Ecosystem: eco,
				Source: &pkgmeta.SourcePackage{Name: "sed"}},
		},
	}
	res, err := New(store).Match(target)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %+v, want exactly the label-less module build", res.Skipped)
	}
	s := res.Skipped[0]
	if s.Package.Name != "nodejs" {
		t.Errorf("skipped %q, want nodejs", s.Package.Name)
	}
	if s.Cause != SkipCoverage {
		t.Errorf("Cause = %q, want %q", s.Cause, SkipCoverage)
	}
	if !strings.Contains(s.Reason, "module stream") {
		t.Errorf("Reason = %q, want it to name the missing module stream", s.Reason)
	}
	if len(res.Findings) != 1 || res.Findings[0].Package.Name != "sed" {
		t.Fatalf("Findings = %+v, want exactly sed's — the skip must not poison the scan",
			res.Findings)
	}
}
