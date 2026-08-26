package arch

import "testing"

// strPtr is a small helper so table rows below can write `strPtr("1.0-1")`
// rather than taking the address of a loop variable by hand.
func strPtr(s string) *string { return &s }

// TestBuildAdvisories_EmptyNameIsDroppedAndCounted covers the defensive
// branch arch_test.go's Fetch-level tests cannot reach through valid JSON
// alone (the live feed never sends an empty name, 2,444/2,444 measured):
// a group with no AVG id is not one D25's grouping or --explain could ever
// reach, so it must be dropped rather than emitted under an empty ID.
func TestBuildAdvisories_EmptyNameIsDroppedAndCounted(t *testing.T) {
	out, st := buildAdvisories([]row{
		{Name: "", Packages: []string{"pkg"}, Status: "Fixed", Fixed: strPtr("1.0-1")},
	})
	if len(out) != 0 {
		t.Errorf("out = %+v, want none", out)
	}
	if st.SkippedNoName != 1 {
		t.Errorf("SkippedNoName = %d, want 1", st.SkippedNoName)
	}
}

// TestBuildAdvisories_UnusableFixedIsDroppedAndCounted covers the defensive
// branch for a "Fixed" or "Testing" row whose own fixed field is nil or
// empty despite the status claiming a fix exists (not observed live: 0 of
// 2,151 Fixed rows and 0 of 0 Testing rows measured 2026-08-26) -- nothing
// a Comparer could place inside a range.
func TestBuildAdvisories_UnusableFixedIsDroppedAndCounted(t *testing.T) {
	empty := ""
	out, st := buildAdvisories([]row{
		{Name: "AVG-1", Packages: []string{"pkg"}, Status: "Fixed", Fixed: nil},
		{Name: "AVG-2", Packages: []string{"pkg"}, Status: "Testing", Fixed: &empty},
	})
	if len(out) != 0 {
		t.Errorf("out = %+v, want none", out)
	}
	if st.SkippedUnusableFixed != 2 {
		t.Errorf("SkippedUnusableFixed = %d, want 2", st.SkippedUnusableFixed)
	}
}

// TestBuildAdvisories_EmptyPackageNameIsDroppedButSiblingsSurvive covers the
// defensive branch for one empty entry inside packages[] alongside a real
// one (not observed live: 0 empty entries across every packages[] slice
// measured 2026-08-26) -- the empty entry must not become a lookup key that
// can only ever miss, but a real sibling in the same group must still
// produce a finding.
func TestBuildAdvisories_EmptyPackageNameIsDroppedButSiblingsSurvive(t *testing.T) {
	out, st := buildAdvisories([]row{
		{Name: "AVG-3", Packages: []string{"", "realpkg"}, Status: "Fixed", Fixed: strPtr("1.0-1")},
	})
	if len(out) != 1 {
		t.Fatalf("out = %+v, want 1 advisory", out)
	}
	if len(out[0].Affected) != 1 || out[0].Affected[0].Name != "realpkg" {
		t.Errorf("Affected = %+v, want exactly [realpkg]", out[0].Affected)
	}
	if st.SkippedEmptyPackage != 1 {
		t.Errorf("SkippedEmptyPackage = %d, want 1", st.SkippedEmptyPackage)
	}
}

// TestBuildAdvisories_AllPackagesEmptyDropsTheWholeGroup covers the
// boundary TestBuildAdvisories_EmptyPackageNameIsDroppedButSiblingsSurvive
// approaches from the other side: every package name empty leaves nothing
// to attach a range to, so the whole group must be dropped rather than
// emitted with zero Affected entries.
func TestBuildAdvisories_AllPackagesEmptyDropsTheWholeGroup(t *testing.T) {
	out, st := buildAdvisories([]row{
		{Name: "AVG-4", Packages: []string{""}, Status: "Fixed", Fixed: strPtr("1.0-1")},
	})
	if len(out) != 0 {
		t.Errorf("out = %+v, want none", out)
	}
	if st.SkippedNoUsablePackage != 1 {
		t.Errorf("SkippedNoUsablePackage = %d, want 1", st.SkippedNoUsablePackage)
	}
}

// TestBuildAdvisories_SortedByID pins deterministic output -- a set of
// identifier strings whose only job here is a reproducible Fetch, the same
// reasoning photon.buildAdvisories' own doc comment gives for sorting its
// cveOrder slice.
func TestBuildAdvisories_SortedByID(t *testing.T) {
	out, _ := buildAdvisories([]row{
		{Name: "AVG-200", Packages: []string{"p"}, Status: "Fixed", Fixed: strPtr("1.0-1")},
		{Name: "AVG-100", Packages: []string{"p"}, Status: "Fixed", Fixed: strPtr("1.0-1")},
	})
	if len(out) != 2 || out[0].ID != "AVG-100" || out[1].ID != "AVG-200" {
		t.Errorf("out = %+v, want [AVG-100, AVG-200] in that order", out)
	}
}
