package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/version"
)

// update regenerates the golden file when true. The default (false) path
// must still fail on a mismatch — a golden test that silently rewrites its
// own expectation on disagreement proves nothing, so this flag exists only
// for deliberate, reviewed updates (`go test ./internal/report/... -update`),
// never for the default `go test ./...` CI runs.
var update = flag.Bool("update", false, "update golden files")

// goldenFixture is shared by the golden-file test and the drift-check test
// below it, so both exercise the identical input: one finding matched
// through the source package (D8) with a full Evidence and locations, one
// finding with an unrated (Unknown, D17) severity matched under Upstream
// (D3) rather than Aliases, one multi-source finding whose Ratings disagree
// (D25), and two Skipped entries — one whole-package (empty AdvisoryID) and
// one advisory-scoped — so every field the brief asks JSON to carry that the
// table cannot is actually exercised.
//
// Every finding here carries a Ratings slice, single-source or multi-source
// but never empty, because that is the one state Match itself is documented
// never to produce (matcher.go's own Finding.Ratings comment) — the golden
// file is meant to be a byte-for-byte record of real tool output, so it must
// not encode a shape the tool cannot actually emit.
func goldenFixture() (matcher.Result, cyclonedx.Stats) {
	res := matcher.Result{
		Findings: []matcher.Finding{
			{
				Package: pkgmeta.Package{
					Name: "libssl3", Version: "3.1.4-r5", Ecosystem: "Alpine:v3.19",
					PURL:   "pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64",
					Source: &pkgmeta.SourcePackage{Name: "openssl", Version: "3.1.4-r5"},
					Locations: []pkgmeta.Location{
						{Path: "lib/apk/db/installed", LayerDigest: "sha256:abc123"},
					},
				},
				Advisory: advisory.Advisory{
					ID:      "CVE-2024-12345",
					Aliases: []string{"GHSA-xxxx-yyyy-zzzz"},
					Summary: "OpenSSL heap overflow",
				},
				Evidence: version.Evidence{
					RangeType:  advisory.RangeEcosystem,
					Introduced: "0",
					Fixed:      "3.1.4-r6",
					Reason:     "3.1.4-r5 is at or above any earlier version and below the fix 3.1.4-r6",
				},
				MatchedName: "openssl",
				Severity:    severity.Critical,
				Score:       9.8,
				// Match always populates at least one Rating (D25); a Finding
				// literal with none is a state the tool itself never produces.
				// This is an ALPINE finding (matched through the source
				// package, D8), so its one source is attributed to ALPINE, and
				// its Fixed matches the Evidence.Fixed above — a single-source
				// finding's one rating and its Evidence agree by construction.
				Ratings: []matcher.Rating{
					{Database: "ALPINE", AdvisoryID: "CVE-2024-12345", Severity: severity.Critical, Score: 9.8, Fixed: "3.1.4-r6"},
				},
			},
			{
				Package: pkgmeta.Package{
					Name: "example.com/bar", Version: "v1.2.3", Ecosystem: "Go",
					PURL: "pkg:golang/example.com/bar@v1.2.3",
				},
				Advisory: advisory.Advisory{
					ID:       "GHSA-abcd",
					Upstream: []string{"CVE-2023-99999"},
				},
				Evidence: version.Evidence{
					RangeType:    advisory.RangeSemver,
					Introduced:   "0",
					LastAffected: "2.0.0",
					Reason:       "v1.2.3 is at or above any earlier version and at or below 2.0.0",
				},
				MatchedName: "example.com/bar",
				Severity:    severity.Unknown,
				Score:       0,
				// Same reasoning as the libssl3 finding above: Match never
				// produces an empty Ratings. This one source is GHSA (matching
				// Advisory.ID), unrated, and gives no fixed version — matching
				// the Evidence above, which bounds by LastAffected rather than
				// a Fixed event because none is known. Fixed left at its zero
				// value on purpose: RatingRecord.Fixed has no `omitempty`, so
				// the golden file below must show `"fixed": ""` for this one,
				// not omit the key.
				Ratings: []matcher.Rating{
					{Database: "GHSA", AdvisoryID: "GHSA-abcd", Severity: severity.Unknown, Score: 0},
				},
			},
			// A third, multi-source finding (D25): the Django CVE the roadmap's
			// own D25 measurement cites, where GHSA carries a CVSS vector and
			// PYSEC does not. Severity/Score are the highest across Ratings
			// (GHSA's), and the Ratings array is what the golden file exists to
			// pin — every source kept, not collapsed to the winner.
			{
				Package: pkgmeta.Package{
					Name: "django", Version: "3.2.12", Ecosystem: "PyPI",
					PURL: "pkg:pypi/django@3.2.12",
				},
				Advisory: advisory.Advisory{
					ID:      "GHSA-w24h-v9qh-8gxj",
					Aliases: []string{"CVE-2022-28347"},
					Summary: "Django SQL injection via QuerySet.explain()",
				},
				Evidence: version.Evidence{
					RangeType:  advisory.RangeSemver,
					Introduced: "0",
					Fixed:      "2.2.28",
					Reason:     "3.2.12 is at or above any earlier version and below the fix 2.2.28",
				},
				MatchedName: "django",
				Severity:    severity.Critical,
				Score:       9.8,
				Ratings: []matcher.Rating{
					{Database: "GHSA", AdvisoryID: "GHSA-w24h-v9qh-8gxj", Severity: severity.Critical, Score: 9.8, Fixed: "2.2.28"},
					{Database: "PYSEC", AdvisoryID: "PYSEC-2022-191", Severity: severity.Unknown, Score: 0, Fixed: "2.2.28"},
				},
			},
		},
		Skipped: []matcher.Skipped{
			{
				Package: pkgmeta.Package{Name: "x", Version: "1.0.0", Ecosystem: "Go"},
				Reason:  "no version comparer for ecosystem \"bogus\"",
			},
			{
				Package:    pkgmeta.Package{Name: "y", Version: "2.0.0", Ecosystem: "Go"},
				AdvisoryID: "GHSA-bad",
				Reason:     "comparing 2.0.0: invalid version",
			},
		},
	}
	cat := cyclonedx.Stats{Components: 6, Cataloged: 5, SkippedNoPURL: 1}
	return res, cat
}

// TestJSON_Golden pins the exact byte shape of --output json. Every change to
// the document — a field added, renamed, or reordered — has to be a
// deliberate edit to the committed golden file, not something that silently
// starts matching a new shape.
func TestJSON_Golden(t *testing.T) {
	res, cat := goldenFixture()
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cat); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	got := buf.Bytes()

	golden := filepath.Join("testdata", "scan.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("JSON output does not match the committed golden file (run with -update "+
			"to regenerate, then review the diff before committing it):\n--- got ---\n%s\n--- want ---\n%s",
			got, want)
	}
}

// TestJSON_SchemaVersionIsPresentAndStable gives a consumer a field to check
// before trusting the rest of the shape — a document with no version field
// at all cannot be told apart from one whose shape simply changed.
func TestJSON_SchemaVersionIsPresentAndStable(t *testing.T) {
	var buf bytes.Buffer
	if _, err := JSON(&buf, matcher.Result{}, cyclonedx.Stats{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", doc.SchemaVersion)
	}
}

// TestJSON_Deterministic: two renders of the same Result must be byte for
// byte identical, which is design goal #3 (a format that churns cannot be
// diffed in CI). Findings and Skipped arrive pre-sorted from the matcher, so
// this also guards against JSON introducing map-based iteration anywhere in
// the encode path.
func TestJSON_Deterministic(t *testing.T) {
	res, cat := goldenFixture()
	var first, second bytes.Buffer
	if _, err := JSON(&first, res, cat); err != nil {
		t.Fatal(err)
	}
	if _, err := JSON(&second, res, cat); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Error("JSON output is not deterministic")
	}
}

// TestJSON_CountsMatchTable is the drift guard the brief asks for: JSON
// carries "the same counts the summary prints", and this proves it by
// running the identical input through both renderers and comparing the
// Summary each returns, rather than trusting that two independent
// computations of "how many were evaluated" happen to agree.
func TestJSON_CountsMatchTable(t *testing.T) {
	res, cat := goldenFixture()
	var tableBuf, jsonBuf bytes.Buffer
	tableSum, err := Table(&tableBuf, res, cat)
	if err != nil {
		t.Fatal(err)
	}
	jsonSum, err := JSON(&jsonBuf, res, cat)
	if err != nil {
		t.Fatal(err)
	}
	if tableSum != jsonSum {
		t.Errorf("Table summary %+v != JSON summary %+v — the two counted differently", tableSum, jsonSum)
	}
}

// TestJSON_CarriesWhatTheTableCannot: the full Evidence, the source package
// (D8), the layer digest, and the score alongside the band. The table only
// ever shows the fixed version and a formatted "band (score)" string; a
// consumer of the JSON needs the raw fields to build its own policy.
func TestJSON_CarriesWhatTheTableCannot(t *testing.T) {
	res, cat := goldenFixture()
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cat); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Findings) != 3 {
		t.Fatalf("Findings = %d, want 3", len(doc.Findings))
	}
	f := doc.Findings[0]
	if f.Package.Source == nil || f.Package.Source.Name != "openssl" {
		t.Errorf("Package.Source = %+v, want Name openssl (D8)", f.Package.Source)
	}
	if len(f.Package.Locations) != 1 || f.Package.Locations[0].LayerDigest != "sha256:abc123" {
		t.Errorf("Package.Locations = %+v, want the layer digest", f.Package.Locations)
	}
	if f.Score != 9.8 {
		t.Errorf("Score = %v, want 9.8 alongside the band", f.Score)
	}
	if f.Severity != "critical" {
		t.Errorf("Severity = %q, want the band name, not a numeric iota", f.Severity)
	}
	if f.Evidence.Fixed != "3.1.4-r6" || f.Evidence.Introduced != "0" ||
		f.Evidence.RangeType != "ECOSYSTEM" || f.Evidence.Reason == "" {
		t.Errorf("Evidence = %+v, want the full evidence carried through", f.Evidence)
	}

	// Summary carries the same counts Table's own summary line prints.
	if doc.Summary.Components != 6 || doc.Summary.Evaluated != 4 ||
		doc.Summary.NotEvaluated != 2 || doc.Summary.IncompleteChecks != 1 ||
		doc.Summary.Findings != 3 || doc.Summary.UnknownSeverity != 1 {
		t.Errorf("Summary = %+v, want {6 4 2 1 3 1}", doc.Summary)
	}
}

// TestJSON_CarriesFullRatingsArray: JSON is the machine-readable view a
// filter would read from (D25), so it keeps every source's rating, not just
// the one Severity/Score picked — the opposite of the table's single
// SEVERITY cell. Checked both by content (every field of both ratings, in
// full) and by order (index 0 is GHSA, index 1 is PYSEC — the sorted order
// matcher.sortRatings produces), so a mutation that drops the array, keeps
// only the winner, or re-sorts it (e.g. through an intermediate map) is
// caught here directly rather than only surfacing as an opaque byte-diff in
// the golden test.
func TestJSON_CarriesFullRatingsArray(t *testing.T) {
	res, cat := goldenFixture()
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cat); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 3 {
		t.Fatalf("Findings = %d, want 3", len(doc.Findings))
	}
	f := doc.Findings[2] // the multi-source Django finding goldenFixture appends
	if len(f.Ratings) != 2 {
		t.Fatalf("Ratings = %d entries, want 2 — JSON must not collapse to the winner", len(f.Ratings))
	}
	ghsa := f.Ratings[0]
	if ghsa.Database != "GHSA" || ghsa.AdvisoryID != "GHSA-w24h-v9qh-8gxj" ||
		ghsa.Severity != "critical" || ghsa.Score != 9.8 || ghsa.Fixed != "2.2.28" {
		t.Errorf("Ratings[0] = %+v, want the GHSA rating in full", ghsa)
	}
	pysec := f.Ratings[1]
	if pysec.Database != "PYSEC" || pysec.AdvisoryID != "PYSEC-2022-191" ||
		pysec.Severity != "unknown" || pysec.Score != 0 || pysec.Fixed != "2.2.28" {
		t.Errorf("Ratings[1] = %+v, want the PYSEC rating in full", pysec)
	}
}

// TestJSON_RatingsIsEmptyArrayNotNullWhenAbsent pins the null-vs-empty-array
// boundary (TestJSON_EmptyResultHasEmptyArraysNotNull's own discipline, one
// level down, on a per-finding field instead of Document's top-level
// arrays). Match itself never produces a Finding with zero Ratings (D25),
// so this fixture — a Finding built directly, with none — is not a state a
// real scan reaches; it is worth pinning anyway because findingRecord has no
// special case for it: `make([]RatingRecord, 0, len(f.Ratings))` plus a
// range over a nil slice already does the right thing, and this is what
// would catch a change that broke that for the zero-length boundary
// specifically.
func TestJSON_RatingsIsEmptyArrayNotNullWhenAbsent(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-no-ratings"},
		Severity: severity.High,
		Score:    7.5,
	}}}
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"ratings": []`) {
		t.Errorf(`output does not contain "ratings": [] for a finding with no Ratings:%s`, out)
	}
	if strings.Contains(out, "null") {
		t.Errorf("output contains a null where jq expects an array:\n%s", out)
	}
}

// TestJSON_RatingFixedKeyIsPresentEvenWhenEmpty: RatingRecord.Fixed has no
// omitempty, on purpose — a source that gave no fixed version is exactly the
// interesting case (disagreeing fixed versions are half of D25's own
// measurement), and omitempty would make that indistinguishable from a
// document that predates the field. This is the test that would have caught
// json.go:107 carrying `,omitempty` when json.go:56-67 argues the opposite
// for the neighbouring Score field: without it, adding or removing
// omitempty on Fixed was invisible to the whole suite (TestJSON_Golden's
// fixture never gave a rating an empty Fixed either).
func TestJSON_RatingFixedKeyIsPresentEvenWhenEmpty(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-no-fix-yet"},
		Severity: severity.High,
		Score:    7.5,
		Ratings: []matcher.Rating{
			{Database: "GHSA", AdvisoryID: "GHSA-no-fix-yet", Severity: severity.High, Score: 7.5},
		},
	}}}
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 || len(doc.Findings[0].Ratings) != 1 {
		t.Fatalf("Findings/Ratings shape = %+v, want one finding with one rating", doc.Findings)
	}
	if got := doc.Findings[0].Ratings[0].Fixed; got != "" {
		t.Errorf("Ratings[0].Fixed = %q, want empty string (a rating with no fix)", got)
	}
	// The unmarshal above cannot tell "" from an absent key, so the presence
	// of the key itself is asserted against the raw bytes.
	if !strings.Contains(buf.String(), `"fixed": ""`) {
		t.Errorf(`output does not contain "fixed": "" — the key must be present even when`+
			" empty, not omitted:\n%s", buf.String())
	}
}

// TestJSON_CarriesSkippedEntries: the JSON document has to cover what
// Table's "Not evaluated:" block shows too, not just the findings table —
// otherwise a consumer piping --output json into jq loses information a
// human reading the table still gets. Asserted directly, not only through
// the golden byte-diff, so a regression here fails with a message that
// names the missing field rather than just "bytes differ".
func TestJSON_CarriesSkippedEntries(t *testing.T) {
	res, cat := goldenFixture()
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cat); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Skipped) != 2 {
		t.Fatalf("Skipped = %d entries, want 2", len(doc.Skipped))
	}
	if doc.Skipped[0].AdvisoryID != "" || doc.Skipped[0].Package.Name != "x" {
		t.Errorf("Skipped[0] = %+v, want the whole-package skip (empty AdvisoryID) for %q", doc.Skipped[0], "x")
	}
	if doc.Skipped[1].AdvisoryID != "GHSA-bad" || doc.Skipped[1].Package.Name != "y" {
		t.Errorf("Skipped[1] = %+v, want the advisory-scoped skip for %q", doc.Skipped[1], "y")
	}
}

// TestJSON_UnknownSeverityIsNotCoerced: the second finding's Severity must
// render as "unknown", never a coerced real band — the exact D17 coercion
// table.go's own formatSeverity guards against, reached here through a
// different renderer.
func TestJSON_UnknownSeverityIsNotCoerced(t *testing.T) {
	res, cat := goldenFixture()
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cat); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Findings[1].Severity != "unknown" {
		t.Errorf("Findings[1].Severity = %q, want %q", doc.Findings[1].Severity, "unknown")
	}
}

// TestJSON_EmptyResultHasEmptyArraysNotNull: a clean scan (no findings, no
// skips) must still render "findings": [] and "skipped": [], never null.
// `jq '.findings | length'` errors out on null, and a clean scan piped into
// jq is the stated use case for --output json — the one fixture the golden
// test exercises always has two of each, so a nil-slice regression there
// would go unnoticed without a dedicated empty-input case.
func TestJSON_EmptyResultHasEmptyArraysNotNull(t *testing.T) {
	var buf bytes.Buffer
	if _, err := JSON(&buf, matcher.Result{}, cyclonedx.Stats{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"findings": []`) {
		t.Errorf(`output does not contain "findings": [] for an empty result:%s`, out)
	}
	if !strings.Contains(out, `"skipped": []`) {
		t.Errorf(`output does not contain "skipped": [] for an empty result:%s`, out)
	}
	if strings.Contains(out, "null") {
		t.Errorf("output contains a null where jq expects an array:\n%s", out)
	}
}
