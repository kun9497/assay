package photon

import (
	"strings"
	"testing"
)

// --- direct tests of the ingestion helpers, for branches photon_test.go's
// Fetch-level tests cannot reach through one httptest fixture each
// (CLAUDE.md: caller first, then the helper directly for what the caller
// cannot reach) ---

func TestClassifyID(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want idClass
	}{
		{"CVE-2026-10001", idCVE},
		{"CVE-2000-0546", idCVE},    // four-digit sequence, the short shape
		{"CVE-2017-1000001", idCVE}, // seven-digit sequence, the long shape
		{"BDSA-2025-0719", idBDSA},
		{"BDSA-2016-1038", idBDSA},
		{"Re", idSentinel},
		{"UNK-1", idSentinel},
		{"UNK-2", idSentinel},
		{"", idSentinel},
		{"CVE-26-1", idSentinel},       // year must be four digits
		{"cve-2026-10001", idSentinel}, // case-sensitive: never observed lowercase live
	} {
		if got := classifyID(tc.id); got != tc.want {
			t.Errorf("classifyID(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

// TestProcessMajor_CountsEveryDrop drives processMajor directly against one
// row of each shape this package recognizes, and checks every counter in
// stats -- Fetch-level tests only ever check WHICH advisories survive, never
// the counts a build's own progress line reports, so a regression that
// mis-attributed a drop to the wrong counter (BDSADropped counted as
// SentinelDropped, say) would pass every photon_test.go assertion.
func TestProcessMajor_CountsEveryDrop(t *testing.T) {
	rows := []row{
		{CVEID: "CVE-2026-10001", Pkg: "krb5", ResVer: "1.20.2-9.ph5", Status: "Fixed"},
		{CVEID: "CVE-2026-10002", Pkg: "curl", Status: "Not Affected"},
		{CVEID: "BDSA-2025-0719", Pkg: "krb5", ResVer: "1.17-15.ph4", Status: "Fixed"},
		{CVEID: "UNK-1", Pkg: "curl", Status: "Not Affected"},
		{CVEID: "CVE-2026-10003", Pkg: "", ResVer: "1.0-1.ph5", Status: "Fixed"}, // no package name
		{CVEID: "CVE-2026-10004", Pkg: "openssl", ResVer: "NA", Status: "Fixed"}, // unusable res_ver
		{CVEID: "CVE-2026-10005", Pkg: "openssl", Status: "Withdrawn"},           // unrecognized status
	}
	var st stats
	result := processMajor(rows, &st)

	if st.Records != len(rows) {
		t.Errorf("Records = %d, want %d", st.Records, len(rows))
	}
	if st.BDSADropped != 1 {
		t.Errorf("BDSADropped = %d, want 1", st.BDSADropped)
	}
	if st.SentinelDropped != 1 {
		t.Errorf("SentinelDropped = %d, want 1", st.SentinelDropped)
	}
	if st.SkippedNoPackage != 1 {
		t.Errorf("SkippedNoPackage = %d, want 1", st.SkippedNoPackage)
	}
	if st.SkippedUnusableFixed != 1 {
		t.Errorf("SkippedUnusableFixed = %d, want 1", st.SkippedUnusableFixed)
	}
	if st.UnrecognizedStatus != 1 {
		t.Errorf("UnrecognizedStatus = %d, want 1", st.UnrecognizedStatus)
	}
	// FixedRows/NotAffectedRows count only rows that reach the status
	// switch -- a BDSA or sentinel id is dropped by classifyID BEFORE that
	// point (via `continue`), so BDSA-2025-0719's own "Fixed" row and
	// UNK-1's own "Not Affected" row are never added to either counter; they
	// are counted once, into BDSADropped/SentinelDropped, above.
	if st.FixedRows != 2 { // krb5 and openssl's unusable-res_ver row
		t.Errorf("FixedRows = %d, want 2", st.FixedRows)
	}
	if st.NotAffectedRows != 1 { // curl only
		t.Errorf("NotAffectedRows = %d, want 1", st.NotAffectedRows)
	}
	// Only CVE-2026-10001/krb5 survives into the result: curl is
	// Not-Affected-only, the BDSA and sentinel rows were dropped before a
	// key was ever built for them, the no-package row was skipped, and
	// openssl's only Fixed row had an unusable res_ver.
	if len(result) != 1 {
		t.Fatalf("processMajor result = %+v, want exactly one surviving key", result)
	}
	got, ok := result[pkgKey{CVE: "CVE-2026-10001", Pkg: "krb5"}]
	if !ok {
		t.Fatalf("result missing CVE-2026-10001/krb5: %+v", result)
	}
	if len(got) != 1 || !got["1.20.2-9.ph5"] {
		t.Errorf("CVE-2026-10001/krb5 fixed set = %v, want {1.20.2-9.ph5}", got)
	}
}

// TestProcessMajor_FixedWinsConflictIsCountedOnce proves the conflict
// counter fires exactly once per KEY, not once per row -- a key with two
// Not-Affected rows and one Fixed row must still count as ONE conflicting
// key, mirroring how the real feed's duplicate rows were measured (4,170
// exact-duplicate rows in the 5.0 feed alone, 2026-08-26).
func TestProcessMajor_FixedWinsConflictIsCountedOnce(t *testing.T) {
	rows := []row{
		{CVEID: "CVE-2026-10001", Pkg: "krb5", Status: "Not Affected"},
		{CVEID: "CVE-2026-10001", Pkg: "krb5", Status: "Not Affected"}, // duplicate Not-Affected row
		{CVEID: "CVE-2026-10001", Pkg: "krb5", ResVer: "1.20.2-9.ph5", Status: "Fixed"},
	}
	var st stats
	result := processMajor(rows, &st)
	if st.FixedWinsConflicts != 1 {
		t.Errorf("FixedWinsConflicts = %d, want 1 (one conflicting KEY, regardless of row count)", st.FixedWinsConflicts)
	}
	if len(result) != 1 {
		t.Fatalf("result = %+v, want exactly one key", result)
	}
}

// TestProcessMajor_MultiFixedVersionKeysCountsDistinctVersionsOnly proves
// the OTHER counter processMajor maintains does not fire for a duplicate
// row repeating the SAME res_ver -- only genuinely distinct fixed versions
// for one key should count, matching how buildAdvisories only ever emits
// distinct Range entries (photon_test.go's
// TestFetch_MultipleFixedVersionsBecomeMultipleRanges proves the positive
// case; this is the negative one no Fetch-level fixture reaches, since a
// duplicate Range would be silently harmless to the emitted advisory and so
// invisible at that layer).
func TestProcessMajor_MultiFixedVersionKeysCountsDistinctVersionsOnly(t *testing.T) {
	rows := []row{
		{CVEID: "CVE-2026-10001", Pkg: "krb5", ResVer: "1.20.2-9.ph5", Status: "Fixed"},
		{CVEID: "CVE-2026-10001", Pkg: "krb5", ResVer: "1.20.2-9.ph5", Status: "Fixed"}, // exact duplicate
	}
	var st stats
	result := processMajor(rows, &st)
	if st.MultiFixedVersionKeys != 0 {
		t.Errorf("MultiFixedVersionKeys = %d, want 0 -- both rows name the SAME version", st.MultiFixedVersionKeys)
	}
	got := result[pkgKey{CVE: "CVE-2026-10001", Pkg: "krb5"}]
	if len(got) != 1 {
		t.Errorf("fixed set = %v, want exactly one distinct version", got)
	}
}

// TestBuildAdvisories_EmptyInputEmitsNothing pins the base case: no majors
// carrying any surviving key produces no advisories, which is what lets
// Fetch's own zero-guard fire (photon_test.go's
// TestFetch_ZeroAdvisoriesAcrossAllMajorsErrors covers that half through the
// real HTTP path; this is the pure-function boundary underneath it).
func TestBuildAdvisories_EmptyInputEmitsNothing(t *testing.T) {
	got := buildAdvisories([]majorResult{{}, {}}, []string{"Photon OS:3", "Photon OS:4"})
	if len(got) != 0 {
		t.Errorf("buildAdvisories(empty) = %+v, want none", got)
	}
}

// TestBuildAdvisories_DeterministicOrder proves emission order is sorted by
// CVE, not map-iteration order -- a build's `assay db build` output and any
// future golden-file comparison depend on this being stable across runs.
func TestBuildAdvisories_DeterministicOrder(t *testing.T) {
	byMajor := []majorResult{{
		pkgKey{CVE: "CVE-2026-99999", Pkg: "z"}: {"1.0-1.ph5": true},
		pkgKey{CVE: "CVE-2026-10001", Pkg: "a"}: {"1.0-1.ph5": true},
		pkgKey{CVE: "CVE-2026-50000", Pkg: "m"}: {"1.0-1.ph5": true},
	}}
	got := buildAdvisories(byMajor, []string{"Photon OS:5"})
	want := []string{"PHOTON-CVE-2026-10001", "PHOTON-CVE-2026-50000", "PHOTON-CVE-2026-99999"}
	if len(got) != len(want) {
		t.Fatalf("buildAdvisories returned %d advisories, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("advisory[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}
}

// TestStatsString_NamesEveryCounter is a light smoke test that String()
// does not panic and mentions every drop category by its own words -- the
// build log is where an operator actually reads these, and a counter added
// to the struct but never wired into the format string would silently never
// print, the exact "helper is covered, nothing calls it" shape CLAUDE.md
// warns about, applied to a Sprintf format string instead of a function
// call.
func TestStatsString_NamesEveryCounter(t *testing.T) {
	s := stats{
		Records: 10, Advisories: 3, FixedRows: 5, NotAffectedRows: 2,
		BDSADropped: 1, SentinelDropped: 1, SkippedNoPackage: 1, SkippedUnusableFixed: 1,
		UnrecognizedStatus: 1, FixedWinsConflicts: 1, MultiFixedVersionKeys: 1,
	}
	out := s.String()
	for _, want := range []string{
		"10 record", "3 advisories", "5 Fixed rows", "2 Not-Affected rows",
		"1 BDSA-*", "garbled/sentinel", "no package name", "no usable res_ver",
		"Fixed/Not Affected", "Fixed won", "more than one distinct fixed version",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stats.String() = %q, does not mention %q", out, want)
		}
	}
}
