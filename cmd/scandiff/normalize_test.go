package main

import (
	"encoding/json"
	"testing"
)

// Fixtures below are trimmed from real captures taken against the published
// database (see the D93 seeding run's <capture>/*.json), keeping the exact
// field spellings read from internal/report/json.go and grype's own -o json
// output -- not guessed. Where the sampled captures never happened to
// exercise a branch (no `aliases`-based CVE link showed up in any of the 13
// targets measured), the fixture below is written by hand using the same
// real field name instead, and says so.

func TestIsCVE_MatchesOnlyBareCVEIdentifiers(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"CVE-2025-46394", true},
		{"CVE-2024-58251", true},
		// These each CONTAIN a valid CVE as a substring -- the exact shape
		// CLAUDE.md's substring-assertion warning calls out (ALPINE-CVE-...
		// contains CVE-...). isCVE anchors the regex at both ends
		// specifically so none of these count.
		{"ALPINE-CVE-2025-46394", false},
		{"CVE-2025-46394-extra", false},
		{"ALAS2023-2023-377", false},
		{"RLSA-2025:23343", false},
		{"GHSA-xxxx-yyyy-zzzz", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isCVE(c.id); got != c.want {
			t.Errorf("isCVE(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}

func TestAssayTuples_ExtractsCVEFromUpstream(t *testing.T) {
	// Trimmed from a real alpine:3.19 capture: Alpine's own OSV records carry
	// the CVE link in `upstream`, not `aliases` (D3's own reason for reading
	// both).
	const doc = `{
		"schemaVersion": 8,
		"findings": [
			{
				"package": {"name": "busybox", "version": "1.36.1-r20", "ecosystem": "Alpine:v3.19"},
				"advisory": {"id": "ALPINE-CVE-2024-58251", "upstream": ["CVE-2024-58251"]}
			}
		],
		"summary": {"notEvaluated": 0, "findings": 1}
	}`
	var d assayDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := assayTuples(d)
	want := tuple{Subject: "busybox", ID: "CVE-2024-58251"}
	if _, ok := set[want]; !ok || len(set) != 1 {
		t.Fatalf("assayTuples = %v, want exactly {%v}", set, want)
	}
}

func TestAssayTuples_ExtractsCVEFromAliases(t *testing.T) {
	// `aliases` never happened to carry a CVE link in any of the 13 sampled
	// captures (every one observed used `upstream` instead) -- this fixture
	// is hand-written using the real field name from
	// internal/report/json.go's AdvisoryRecord.Aliases, not a trim of an
	// observed document.
	const doc = `{
		"schemaVersion": 8,
		"findings": [
			{
				"package": {"name": "example-lib"},
				"advisory": {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2025-9001"]}
			}
		],
		"summary": {"notEvaluated": 0, "findings": 1}
	}`
	var d assayDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := assayTuples(d)
	want := tuple{Subject: "example-lib", ID: "CVE-2025-9001"}
	if _, ok := set[want]; !ok || len(set) != 1 {
		t.Fatalf("assayTuples = %v, want exactly {%v}", set, want)
	}
}

func TestAssayTuples_FallsBackToAdvisoryIDWhenNoCVEShapedIdentifier(t *testing.T) {
	// Trimmed from a real amazonlinux:2023 capture: Amazon's ALAS records
	// carry no aliases/upstream at all on this finding.
	const doc = `{
		"schemaVersion": 8,
		"findings": [
			{
				"package": {"name": "curl-minimal"},
				"advisory": {"id": "ALAS2023-2023-368"}
			}
		],
		"summary": {"notEvaluated": 0, "findings": 1}
	}`
	var d assayDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := assayTuples(d)
	want := tuple{Subject: "curl-minimal", ID: "ALAS2023-2023-368"}
	if _, ok := set[want]; !ok || len(set) != 1 {
		t.Fatalf("assayTuples = %v, want exactly {%v} (fallback to the bare advisory ID)", set, want)
	}
}

func TestAssayTuples_DedupsRepeatedCVEAcrossIDAliasesAndUpstream(t *testing.T) {
	// A finding whose advisory names the same CVE three different ways
	// (its own ID, an alias, AND upstream) must contribute exactly one
	// tuple, not three.
	const doc = `{
		"schemaVersion": 8,
		"findings": [
			{
				"package": {"name": "triple-named"},
				"advisory": {"id": "CVE-2026-4001", "aliases": ["CVE-2026-4001"], "upstream": ["CVE-2026-4001"]}
			}
		],
		"summary": {"notEvaluated": 0, "findings": 1}
	}`
	var d assayDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := assayTuples(d)
	if len(set) != 1 {
		t.Fatalf("assayTuples = %v, want exactly one deduped tuple", set)
	}
}

func TestGrypeTuples_ExtractsCVEFromVulnerabilityID(t *testing.T) {
	// Trimmed from a real alpine:3.19 grype capture.
	const doc = `{
		"matches": [
			{
				"vulnerability": {"id": "CVE-2025-60876"},
				"relatedVulnerabilities": [],
				"artifact": {"name": "busybox"}
			}
		]
	}`
	var d grypeDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := grypeTuples(d)
	want := tuple{Subject: "busybox", ID: "CVE-2025-60876"}
	if _, ok := set[want]; !ok || len(set) != 1 {
		t.Fatalf("grypeTuples = %v, want exactly {%v}", set, want)
	}
}

func TestGrypeTuples_ExtractsRelatedVulnerabilities(t *testing.T) {
	// Trimmed from a real amazonlinux:2023 grype capture: grype's own
	// vulnerability.id is the non-CVE distro advisory (ALAS2023-2023-377),
	// and the CVE it wraps shows up only in relatedVulnerabilities.
	const doc = `{
		"matches": [
			{
				"vulnerability": {"id": "ALAS2023-2023-377"},
				"relatedVulnerabilities": [{"id": "CVE-2023-38545"}],
				"artifact": {"name": "curl-minimal"}
			}
		]
	}`
	var d grypeDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := grypeTuples(d)
	want := tuple{Subject: "curl-minimal", ID: "CVE-2023-38545"}
	if _, ok := set[want]; !ok || len(set) != 1 {
		t.Fatalf("grypeTuples = %v, want exactly {%v} (the non-CVE vulnerability.id must NOT also appear as a tuple)", set, want)
	}
}

func TestGrypeTuples_FallsBackToVulnerabilityIDWhenNoCVEShapedIdentifier(t *testing.T) {
	// Trimmed from a real amazonlinux:2023 grype capture: an ALAS advisory
	// with no CVE-shaped identifier anywhere on the match.
	const doc = `{
		"matches": [
			{
				"vulnerability": {"id": "ALAS2023-2024-558"},
				"relatedVulnerabilities": [],
				"artifact": {"name": "libcurl-minimal"}
			}
		]
	}`
	var d grypeDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := grypeTuples(d)
	want := tuple{Subject: "libcurl-minimal", ID: "ALAS2023-2024-558"}
	if _, ok := set[want]; !ok || len(set) != 1 {
		t.Fatalf("grypeTuples = %v, want exactly {%v} (fallback to the bare vulnerability.id)", set, want)
	}
}

func TestGrypeTuples_DedupsRepeatedCVEAcrossVulnerabilityAndRelated(t *testing.T) {
	const doc = `{
		"matches": [
			{
				"vulnerability": {"id": "CVE-2026-5001"},
				"relatedVulnerabilities": [{"id": "CVE-2026-5001"}, {"id": "CVE-2026-5001"}],
				"artifact": {"name": "dup-artifact"}
			}
		]
	}`
	var d grypeDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := grypeTuples(d)
	if len(set) != 1 {
		t.Fatalf("grypeTuples = %v, want exactly one deduped tuple", set)
	}
}

func TestAssaySummary_NotEvaluatedFieldParses(t *testing.T) {
	const doc = `{"schemaVersion": 8, "findings": [], "summary": {"notEvaluated": 7, "findings": 0}}`
	var d assayDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.Summary.NotEvaluated != 7 {
		t.Errorf("Summary.NotEvaluated = %d, want 7", d.Summary.NotEvaluated)
	}
}

func TestCompareSets_AgreeOnlyAssayOnlyGrype(t *testing.T) {
	a := map[tuple]struct{}{
		{Subject: "pkg1", ID: "CVE-2026-0001"}: {},
		{Subject: "pkg2", ID: "CVE-2026-0002"}: {}, // only assay
	}
	g := map[tuple]struct{}{
		{Subject: "pkg1", ID: "CVE-2026-0001"}: {},
		{Subject: "pkg3", ID: "CVE-2026-0003"}: {}, // only grype
	}
	agree, onlyAssay, onlyGrype := compareSets(a, g)
	if agree != 1 || onlyAssay != 1 || onlyGrype != 1 {
		t.Errorf("compareSets = (%d, %d, %d), want (1, 1, 1)", agree, onlyAssay, onlyGrype)
	}
}

func TestCompareSets_EmptyBothSides(t *testing.T) {
	agree, onlyAssay, onlyGrype := compareSets(map[tuple]struct{}{}, map[tuple]struct{}{})
	if agree != 0 || onlyAssay != 0 || onlyGrype != 0 {
		t.Errorf("compareSets = (%d, %d, %d), want (0, 0, 0)", agree, onlyAssay, onlyGrype)
	}
}

// --- D105: trivy's own document shape --------------------------------------

func TestTrivyTuples_ExtractsFromOSPkgsResult(t *testing.T) {
	const doc = `{
		"Results": [
			{
				"Class": "os-pkgs",
				"Vulnerabilities": [
					{"PkgName": "busybox", "VulnerabilityID": "CVE-2025-60876"}
				]
			}
		]
	}`
	var d trivyDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := trivyTuples(d)
	want := tuple{Subject: "busybox", ID: "CVE-2025-60876"}
	if _, ok := set[want]; !ok || len(set) != 1 {
		t.Fatalf("trivyTuples = %v, want exactly {%v}", set, want)
	}
}

func TestTrivyTuples_ExtractsFromLangPkgsResult(t *testing.T) {
	const doc = `{
		"Results": [
			{
				"Class": "lang-pkgs",
				"Vulnerabilities": [
					{"PkgName": "lodash", "VulnerabilityID": "CVE-2021-23337"}
				]
			}
		]
	}`
	var d trivyDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := trivyTuples(d)
	want := tuple{Subject: "lodash", ID: "CVE-2021-23337"}
	if _, ok := set[want]; !ok || len(set) != 1 {
		t.Fatalf("trivyTuples = %v, want exactly {%v}", set, want)
	}
}

func TestTrivyTuples_MultipleResultClassesCombine(t *testing.T) {
	const doc = `{
		"Results": [
			{"Class": "os-pkgs", "Vulnerabilities": [{"PkgName": "openssl", "VulnerabilityID": "CVE-2026-0001"}]},
			{"Class": "lang-pkgs", "Vulnerabilities": [{"PkgName": "requests", "VulnerabilityID": "CVE-2026-0002"}]}
		]
	}`
	var d trivyDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := trivyTuples(d)
	if len(set) != 2 {
		t.Fatalf("trivyTuples = %v, want 2 tuples across both result classes", set)
	}
}

// TestTrivyTuples_SUSEAdvisoryIDFallsBackToReferenceCVEs holds the SUSE
// join: trivy keys SLE findings by patch advisory (SUSE-SU-...), never a
// CVE, and the CVE appears only inside References URLs. Measured on the
// D105 seeding run: bci156's 58 real trivy findings joined as ZERO tuples
// under CVE-only extraction, and the differential wrongly read as "trivy
// found nothing" -- this test is what makes that misreading impossible to
// reintroduce. Two CVEs in one entry's references become two tuples; a
// reference with no CVE contributes nothing.
func TestTrivyTuples_SUSEAdvisoryIDFallsBackToReferenceCVEs(t *testing.T) {
	const doc = `{
		"Results": [
			{"Class": "os-pkgs", "Vulnerabilities": [
				{"PkgName": "libopenssl3", "VulnerabilityID": "SUSE-SU-2026:0319-1",
				 "References": [
					"https://www.suse.com/security/cve/CVE-2026-41337.html",
					"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023978.html",
					"https://www.suse.com/security/cve/CVE-2026-52208.html"
				 ]}
			]}
		]
	}`
	var d trivyDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := trivyTuples(d)
	wantA := tuple{Subject: "libopenssl3", ID: "CVE-2026-41337"}
	wantB := tuple{Subject: "libopenssl3", ID: "CVE-2026-52208"}
	if _, ok := set[wantA]; !ok {
		t.Errorf("trivyTuples = %v, want it to contain %v (CVE from the first reference URL)", set, wantA)
	}
	if _, ok := set[wantB]; !ok {
		t.Errorf("trivyTuples = %v, want it to contain %v (CVE from the third reference URL)", set, wantB)
	}
	if len(set) != 2 {
		t.Errorf("trivyTuples = %v, want exactly 2 tuples (the CVE-less mailing-list URL contributes nothing)", set)
	}
}

func TestTrivyTuples_DropsNonCVEShapedIDs(t *testing.T) {
	// Trivy sometimes carries its own non-CVE advisory ID (a GHSA it chose
	// not to resolve to a CVE). Unlike assayTuples/grypeTuples, there is no
	// bare-ID fallback here -- a non-CVE trivy ID whose references also name
	// no CVE can never agree with anything assay reports, so keeping it
	// would only inflate noise.
	const doc = `{
		"Results": [
			{"Class": "lang-pkgs", "Vulnerabilities": [
				{"PkgName": "example-lib", "VulnerabilityID": "GHSA-aaaa-bbbb-cccc",
				 "References": ["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"]},
				{"PkgName": "example-lib", "VulnerabilityID": "CVE-2026-1234"}
			]}
		]
	}`
	var d trivyDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := trivyTuples(d)
	if len(set) != 1 {
		t.Fatalf("trivyTuples = %v, want exactly 1 tuple (the non-CVE GHSA id must be dropped)", set)
	}
	want := tuple{Subject: "example-lib", ID: "CVE-2026-1234"}
	if _, ok := set[want]; !ok {
		t.Errorf("missing tuple %+v", want)
	}
}

func TestTrivyTuples_DedupsRepeatedTuple(t *testing.T) {
	const doc = `{
		"Results": [
			{"Class": "os-pkgs", "Vulnerabilities": [
				{"PkgName": "curl", "VulnerabilityID": "CVE-2026-5000"}
			]},
			{"Class": "os-pkgs", "Vulnerabilities": [
				{"PkgName": "curl", "VulnerabilityID": "CVE-2026-5000"}
			]}
		]
	}`
	var d trivyDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := trivyTuples(d)
	if len(set) != 1 {
		t.Fatalf("trivyTuples = %v, want exactly one deduped tuple", set)
	}
}

func TestTrivyTuples_NoResultsIsZeroTuplesNotError(t *testing.T) {
	// A clean image: trivy's document has no Results key at all.
	const doc = `{}`
	var d trivyDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := trivyTuples(d)
	if len(set) != 0 {
		t.Fatalf("trivyTuples = %v, want zero tuples for a document with no Results", set)
	}
}

func TestTrivyTuples_NullVulnerabilitiesIsZeroTuplesNotError(t *testing.T) {
	// A Result present (e.g. a "secret" or "config" class, or an os-pkgs
	// class that simply found nothing) but its Vulnerabilities key is
	// explicitly null rather than an empty array or absent.
	const doc = `{
		"Results": [
			{"Class": "os-pkgs", "Vulnerabilities": null},
			{"Class": "secret"}
		]
	}`
	var d trivyDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := trivyTuples(d)
	if len(set) != 0 {
		t.Fatalf("trivyTuples = %v, want zero tuples, not an error, for null/absent Vulnerabilities", set)
	}
}

func TestAssayTuples_ExtractsCVEFromRatingAdvisoryIDs(t *testing.T) {
	// Trimmed from the real alma9 seeding capture (seed-capture/alma9.assay.json):
	// AlmaLinux's ALSA records carry NO aliases or upstream at all -- the CVE
	// link lives in `related`, which the JSON document does not expose, but
	// the NVD/EPSS annotations that attach THROUGH related (D71's whole point)
	// carry the CVE as their own advisoryId. Without reading the ratings
	// column, every Alma and Oracle finding joins on its bare ALSA-/ELSA- ID,
	// which grype never mints -- agreement pinned to zero on two whole
	// ecosystems, which is what the first seeding run measured.
	const doc = `{
		"schemaVersion": 8,
		"findings": [
			{
				"package": {"name": "openssl-libs", "version": "3.2.2-6.el9_5", "ecosystem": "AlmaLinux:9"},
				"advisory": {"id": "ALSA-2026:42736"},
				"ratings": [
					{"database": "ALSA", "advisoryId": "ALSA-2026:42736"},
					{"database": "EPSS", "advisoryId": "CVE-2026-54369"},
					{"database": "NVD", "advisoryId": "CVE-2026-54369"},
					{"database": "NVD", "advisoryId": "CVE-2026-54370"}
				]
			}
		],
		"summary": {"notEvaluated": 0, "findings": 1}
	}`
	var d assayDocument
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	set := assayTuples(d)
	for _, want := range []tuple{
		{Subject: "openssl-libs", ID: "CVE-2026-54369"},
		{Subject: "openssl-libs", ID: "CVE-2026-54370"},
	} {
		if _, ok := set[want]; !ok {
			t.Errorf("missing tuple %+v", want)
		}
	}
	// The bare-ID fallback must NOT fire once the ratings supplied real CVEs:
	// a tuple keyed on ALSA-2026:42736 can never match anything grype
	// reports, so keeping it would only inflate onlyAssay noise.
	if _, ok := set[tuple{Subject: "openssl-libs", ID: "ALSA-2026:42736"}]; ok {
		t.Error("bare advisory-ID tuple present despite CVE-shaped rating advisoryIds")
	}
	if len(set) != 2 {
		t.Errorf("len(set) = %d, want 2", len(set))
	}
}
