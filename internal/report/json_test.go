package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
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
// (D3) rather than Aliases, and two Skipped entries — one whole-package
// (empty AdvisoryID) and one advisory-scoped — so every field the brief asks
// JSON to carry that the table cannot is actually exercised.
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
	cat := cyclonedx.Stats{Components: 5, Cataloged: 4, SkippedNoPURL: 1}
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
	if len(doc.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2", len(doc.Findings))
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
	if doc.Summary.Components != 5 || doc.Summary.Evaluated != 3 ||
		doc.Summary.NotEvaluated != 2 || doc.Summary.IncompleteChecks != 1 ||
		doc.Summary.Findings != 2 || doc.Summary.UnknownSeverity != 1 {
		t.Errorf("Summary = %+v, want {5 3 2 1 2 1}", doc.Summary)
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
