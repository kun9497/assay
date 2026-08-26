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
				// KISA's prose about the same CVE (D3), on the Alpine finding
				// because Alpine is where the overlap actually is — 279 of the
				// 413 CVEs KISA and this database share. The other two findings
				// deliberately gain nothing, which is the ordinary case at a
				// 2.4% overlap and is what makes "enrichment": [] part of the
				// committed shape rather than a case no fixture reaches.
				Enrichment: []matcher.Enrichment{kisaEnrichment()},
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
				// PYSEC's fixed version differs from GHSA's on purpose. With
				// both at 2.2.28 every rating in every fixture matched its own
				// finding's Evidence.Fixed, so a renderer reading the fixed
				// version off the winning record instead of off each rating —
				// exactly the collapse this field exists to prevent — produced
				// byte-identical output and the golden file blessed it.
				//
				// A third rating, NVD (D27): an annotation, not a matched
				// record, so its own AdvisoryID is the CVE itself (matching
				// matcher.go's own annotate()) and Fixed is empty — NIST was
				// asked only what the CVE is worth, never which version fixes
				// it. URL is the one field only an annotation carries; the two
				// OSV ratings above leave it empty because their AdvisoryID
				// already names something to look up.
				Ratings: []matcher.Rating{
					{Database: "GHSA", AdvisoryID: "GHSA-w24h-v9qh-8gxj", Severity: severity.Critical, Score: 9.8, Fixed: "2.2.28"},
					{Database: "NVD", AdvisoryID: "CVE-2022-28347", Severity: severity.Critical, Score: 9.8,
						URL: "https://nvd.nist.gov/vuln/detail/CVE-2022-28347"},
					{Database: "PYSEC", AdvisoryID: "PYSEC-2022-191", Severity: severity.Unknown, Score: 0, Fixed: "2.2.27"},
				},
			},
		},
		// D36: all three causes, so the golden pins each one and a renderer
		// that dropped the field could not produce byte-identical output. The
		// zero value of SkipCause is the empty string, which is exactly what an
		// unwired field looks like — a fixture leaving any of these unset would
		// prove nothing about the wiring.
		Skipped: []matcher.Skipped{
			{
				Package: pkgmeta.Package{Name: "x", Version: "1.0.0", Ecosystem: "Go"},
				Reason:  "no version comparer for ecosystem \"bogus\"",
				Cause:   matcher.SkipCoverage,
			},
			{
				Package:    pkgmeta.Package{Name: "y", Version: "2.0.0", Ecosystem: "Go"},
				AdvisoryID: "GHSA-bad",
				Reason:     `the advisory's range bound "not-a-version" could not be read: invalid version`,
				Cause:      matcher.SkipAdvisory,
			},
			{
				Package:    pkgmeta.Package{Name: "z", Version: "not-a-version", Ecosystem: "Go"},
				AdvisoryID: "GHSA-target",
				Reason:     `this package's own version "not-a-version" could not be read: invalid version`,
				Cause:      matcher.SkipTarget,
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
	if _, err := JSON(&buf, res, cat, EOLStatus{}); err != nil {
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
	if _, err := JSON(&buf, matcher.Result{}, cyclonedx.Stats{}, EOLStatus{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	// Pinned against the package constant rather than a second literal. The
	// two were separate numbers until D52 and drifted the moment D48 bumped
	// one of them: this assertion still read `want 4` while comparing against
	// 5, so its failure message named a version nothing had used for two
	// slices. A message that can go stale independently of what it asserts is
	// worse than no message.
	if doc.SchemaVersion != schemaVersion {
		t.Errorf("SchemaVersion = %d, want %d — bump the constant and this "+
			"document's own changelog together", doc.SchemaVersion, schemaVersion)
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
	if _, err := JSON(&first, res, cat, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	if _, err := JSON(&second, res, cat, EOLStatus{}); err != nil {
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
	tableSum, err := Table(&tableBuf, res, cat, EOLStatus{})
	if err != nil {
		t.Fatal(err)
	}
	jsonSum, err := JSON(&jsonBuf, res, cat, EOLStatus{})
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
	if _, err := JSON(&buf, res, cat, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Findings) != 3 {
		t.Fatalf("Findings = %d, want 5", len(doc.Findings))
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
		doc.Summary.NotEvaluated != 2 || doc.Summary.IncompleteChecks != 2 ||
		doc.Summary.Findings != 3 || doc.Summary.UnknownSeverity != 1 {
		t.Errorf("Summary = %+v, want components=6 evaluated=4 notEvaluated=2 incompleteChecks=2 findings=3 unknownSeverity=1", doc.Summary)
	}
	// D36: one of the three matcher skips is the target's fault and two are
	// not, so a field that simply mirrored IncompleteChecks — or that counted
	// every skip — would be wrong here rather than coincidentally right.
	//
	// D38 adds the cataloger's own skips, which are the target's data by
	// construction. The fixture carries one (SkippedNoPURL), so the expected
	// total is 2 and the two sources are distinguishable: a change that dropped
	// either half moves this number.
	if doc.Summary.TargetIncomplete != 2 {
		t.Errorf("Summary.TargetIncomplete = %d, want 2 — one matcher skip caused by the target plus one cataloger skip", doc.Summary.TargetIncomplete)
	}
}

// TestJSON_CarriesFullRatingsArray: JSON is the machine-readable view a
// filter would read from (D25), so it keeps every source's rating, not just
// the one Severity/Score picked — the opposite of the table's single
// SEVERITY cell. Checked both by content (every field of all three ratings,
// in full) and by order (index 0 is GHSA, index 1 is NVD, index 2 is PYSEC —
// the sorted order matcher.sortRatings produces), so a mutation that drops
// the array, keeps only the winner, or re-sorts it (e.g. through an
// intermediate map) is caught here directly rather than only surfacing as an
// opaque byte-diff in the golden test.
//
// The NVD entry (D27) is what makes this the URL round-trip test too: it is
// the one rating in this fixture with a non-empty URL and an empty Fixed —
// exactly an annotation's shape, never a matched record's — so a mutation
// that drops RatingRecord.URL, or that carries Evidence.Fixed onto an
// annotation instead of leaving it empty, is caught here rather than only in
// the golden byte-diff.
func TestJSON_CarriesFullRatingsArray(t *testing.T) {
	res, cat := goldenFixture()
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cat, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 3 {
		t.Fatalf("Findings = %d, want 5", len(doc.Findings))
	}
	f := doc.Findings[2] // the multi-source Django finding goldenFixture appends
	if len(f.Ratings) != 3 {
		t.Fatalf("Ratings = %d entries, want 4 — JSON must not collapse to the winner", len(f.Ratings))
	}
	ghsa := f.Ratings[0]
	if ghsa.Database != "GHSA" || ghsa.AdvisoryID != "GHSA-w24h-v9qh-8gxj" ||
		ghsa.Severity != "critical" || ghsa.Score != 9.8 || ghsa.Fixed != "2.2.28" || ghsa.URL != "" {
		t.Errorf("Ratings[0] = %+v, want the GHSA rating in full (URL empty — an advisory names itself)", ghsa)
	}
	nvd := f.Ratings[1]
	if nvd.Database != "NVD" || nvd.AdvisoryID != "CVE-2022-28347" ||
		nvd.Severity != "critical" || nvd.Score != 9.8 || nvd.Fixed != "" ||
		nvd.URL != "https://nvd.nist.gov/vuln/detail/CVE-2022-28347" {
		t.Errorf("Ratings[1] = %+v, want the NVD annotation in full "+
			"(empty Fixed, a URL — the one place a reader can check it)", nvd)
	}
	pysec := f.Ratings[2]
	if pysec.Database != "PYSEC" || pysec.AdvisoryID != "PYSEC-2022-191" ||
		pysec.Severity != "unknown" || pysec.Score != 0 || pysec.Fixed != "2.2.27" || pysec.URL != "" {
		t.Errorf("Ratings[2] = %+v, want the PYSEC rating in full", pysec)
	}
	// Each rating's fixed version comes from its OWN record. The finding's
	// Evidence carries the winner's, so a renderer that read it from there
	// would emit 2.2.28 twice — every source appearing to agree about
	// remediation, which is the collapse this array exists to prevent.
	if pysec.Fixed == ghsa.Fixed {
		t.Errorf("both ratings report fixed %q, so this test cannot tell a "+
			"per-rating fixed version from one taken off the winner", ghsa.Fixed)
	}
}

// TestJSON_RatingRecordCarriesEPSSAndKEVFields is D86's caller-first proof
// for the JSON renderer: matcher.Rating's typed EPSS/KEV fields must reach
// RatingRecord, not just exist on the type nothing populates. A finding
// carries a plain GHSA rating, a separate EPSS rating and a separate KEV
// rating — the shape a real scan produces once EPSS_ENABLE/KEV_ENABLE have
// run (each source keyed under its own "<CVE>\x00<Source>" in the store).
func TestJSON_RatingRecordCarriesEPSSAndKEVFields(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "libfoo", Version: "1.0.0", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-epsskev-json"},
		Severity: severity.High,
		Score:    7.5,
		Ratings: []matcher.Rating{
			{Database: "GHSA", AdvisoryID: "GHSA-epsskev-json", Severity: severity.High, Score: 7.5, Fixed: "2.0.0"},
			// Severity: Unknown, NoSeverityOpinion: true -- what
			// matcher.annotate() actually sets for a stored rating with no
			// Severity entries (matcher.go), not the zero value (None).
			{Database: "EPSS", Severity: severity.Unknown, NoSeverityOpinion: true,
				EPSS: 0.62345, EPSSPercentile: 0.81111, EPSSModel: "v2026.06.15"},
			{Database: "KEV", Severity: severity.Unknown, NoSeverityOpinion: true,
				KEV: true, KEVDateAdded: "2026-03-15", KEVRansomware: "Known"},
		},
	}}}
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 || len(doc.Findings[0].Ratings) != 3 {
		t.Fatalf("Findings/Ratings shape = %+v, want one finding with three ratings", doc.Findings)
	}
	rs := doc.Findings[0].Ratings

	epssRow, kevRow := rs[1], rs[2]
	if epssRow.Database != "EPSS" || epssRow.EPSS != 0.62345 ||
		epssRow.EPSSPercentile != 0.81111 || epssRow.EPSSModel != "v2026.06.15" {
		t.Errorf("EPSS rating = %+v, want EPSS=0.62345 EPSSPercentile=0.81111 EPSSModel=v2026.06.15", epssRow)
	}
	if epssRow.KEV || epssRow.KEVDateAdded != "" || epssRow.KEVRansomware != "" {
		t.Errorf("EPSS rating carries KEV fields it should not: %+v", epssRow)
	}
	if kevRow.Database != "KEV" || !kevRow.KEV || kevRow.KEVDateAdded != "2026-03-15" || kevRow.KEVRansomware != "Known" {
		t.Errorf("KEV rating = %+v, want KEV=true KEVDateAdded=2026-03-15 KEVRansomware=Known", kevRow)
	}
	if kevRow.EPSS != 0 || kevRow.EPSSModel != "" {
		t.Errorf("KEV rating carries EPSS fields it should not: %+v", kevRow)
	}

	// The raw bytes, not just the unmarshaled struct: proves the keys are
	// actually spelled "epss"/"kevDateAdded"/etc in the wire format, which a
	// json tag typo could break while every unmarshal-based assertion above
	// stayed green (Go's decoder is case-insensitive and tolerates unknown
	// fields, so a struct-only check cannot catch a renamed key).
	out := buf.String()
	for _, want := range []string{
		`"epss": 0.62345`, `"epssPercentile": 0.81111`, `"epssModel": "v2026.06.15"`,
		`"kev": true`, `"kevDateAdded": "2026-03-15"`, `"kevRansomware": "Known"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
}

// TestJSON_EPSSKEVFieldsOmittedWhenAbsent is the omitempty half: an ordinary
// rating from any OTHER source must not carry six zero/empty EPSS/KEV keys —
// RatingRecord's own doc comment explains why that departs from every other
// field's no-omitempty convention on this type (six columns of noise on
// every rating from every source that is not EPSS or KEV).
func TestJSON_EPSSKEVFieldsOmittedWhenAbsent(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-no-epsskev"},
		Severity: severity.High,
		Score:    7.5,
		Ratings: []matcher.Rating{
			{Database: "GHSA", AdvisoryID: "GHSA-no-epsskev", Severity: severity.High, Score: 7.5, Fixed: "2.0.0"},
		},
	}}}
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, key := range []string{`"epss"`, `"epssPercentile"`, `"epssModel"`, `"kev"`, `"kevDateAdded"`, `"kevRansomware"`} {
		if strings.Contains(out, key) {
			t.Errorf("output contains %q for a rating from a source that never sets it:\n%s", key, out)
		}
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
	if _, err := JSON(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}); err != nil {
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
	if _, err := JSON(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}); err != nil {
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
	if _, err := JSON(&buf, res, cat, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Skipped) != 3 {
		t.Fatalf("Skipped = %d entries, want 3", len(doc.Skipped))
	}
	if doc.Skipped[0].AdvisoryID != "" || doc.Skipped[0].Package.Name != "x" {
		t.Errorf("Skipped[0] = %+v, want the whole-package skip (empty AdvisoryID) for %q", doc.Skipped[0], "x")
	}
	if doc.Skipped[1].AdvisoryID != "GHSA-bad" || doc.Skipped[1].Package.Name != "y" {
		t.Errorf("Skipped[1] = %+v, want the advisory-scoped skip for %q", doc.Skipped[1], "y")
	}
	// D36: the cause reaches the document, per record. Asserted on all three
	// because they are the three distinct values — a wiring that emitted one
	// constant would satisfy any single check.
	for i, want := range []matcher.SkipCause{matcher.SkipCoverage, matcher.SkipAdvisory, matcher.SkipTarget} {
		if got := doc.Skipped[i].Cause; got != want {
			t.Errorf("Skipped[%d].Cause = %q, want %q", i, got, want)
		}
	}
}

// TestJSON_UnknownSeverityIsNotCoerced: the second finding's Severity must
// render as "unknown", never a coerced real band — the exact D17 coercion
// table.go's own formatSeverity guards against, reached here through a
// different renderer.
func TestJSON_UnknownSeverityIsNotCoerced(t *testing.T) {
	res, cat := goldenFixture()
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cat, EOLStatus{}); err != nil {
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
// D52: FixState flows from Range through Rating to the JSON document,
// spelled as one of the four words — never an empty string, never omitted —
// on both the finding (the strongest claim any source made) and each of its
// ratings (what that one source said). Table-driven over the four states.
func TestJSON_FixStateIsOneOfFourWordsOnEveryFindingAndRating(t *testing.T) {
	find := func(id string, rating matcher.Rating) matcher.Finding {
		return matcher.Finding{
			Package:  pkgmeta.Package{Name: id, Version: "1", Ecosystem: "Red Hat:9"},
			Advisory: advisory.Advisory{ID: id},
			Severity: severity.High,
			Score:    7.5,
			Ratings:  []matcher.Rating{rating},
		}
	}
	res := matcher.Result{Findings: []matcher.Finding{
		{
			Package:  pkgmeta.Package{Name: "fixed", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "RH-FIXED-1"},
			Evidence: version.Evidence{Fixed: "2.0.0"},
			Severity: severity.High,
			Score:    7.5,
			Ratings:  []matcher.Rating{{Database: "GHSA", AdvisoryID: "RH-FIXED-1", Fixed: "2.0.0"}},
		},
		// FixState left at its zero value — the ordinary case for every
		// provider but Red Hat's CSAF VEX feed.
		find("RH-UNKNOWN-1", matcher.Rating{Database: "OSV", AdvisoryID: "RH-UNKNOWN-1"}),
		find("RH-NOTFIXED-1", matcher.Rating{Database: "REDHAT", AdvisoryID: "RH-NOTFIXED-1", FixState: advisory.FixStateNotFixed}),
		find("RH-WONTFIX-1", matcher.Rating{Database: "REDHAT", AdvisoryID: "RH-WONTFIX-1", FixState: advisory.FixStateWontFix}),
	}}
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cyclonedx.Stats{Components: 4, Cataloged: 4}, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Findings) != 4 {
		t.Fatalf("Findings = %d, want 4", len(doc.Findings))
	}
	byID := make(map[string]FindingRecord, len(doc.Findings))
	for _, f := range doc.Findings {
		byID[f.Advisory.ID] = f
	}
	for _, tt := range []struct{ id, want string }{
		{"RH-FIXED-1", "fixed"},
		{"RH-UNKNOWN-1", "unknown"},
		{"RH-NOTFIXED-1", "not-fixed"},
		{"RH-WONTFIX-1", "wont-fix"},
	} {
		f, ok := byID[tt.id]
		if !ok {
			t.Fatalf("no finding for %q in %+v", tt.id, byID)
		}
		if f.FixState != tt.want {
			t.Errorf("%s: FindingRecord.FixState = %q, want %q", tt.id, f.FixState, tt.want)
		}
		if len(f.Ratings) != 1 {
			t.Fatalf("%s: Ratings = %d entries, want 1", tt.id, len(f.Ratings))
		}
		if got := f.Ratings[0].FixState; got != tt.want {
			t.Errorf("%s: RatingRecord.FixState = %q, want %q", tt.id, got, tt.want)
		}
	}
}

// D52: RatingRecord.FixState is r.FixState.String(), not string(r.FixState)
// — the difference shows only on the store's own empty-string spelling of
// unknown (advisory.go's own doc comment on FixStateUnknown), and unmarshalling
// into the struct cannot tell "the encoder wrote an empty string" apart from
// "the encoder wrote nothing at all"; a zero-value Go string field reads back
// identically either way. Checked against the raw bytes for exactly that
// reason.
func TestJSON_RatingFixStateResolvesTheStoredEmptyStringToUnknown(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "RH-ZERO-VALUE-1"},
		Severity: severity.High,
		Score:    7.5,
		// FixState left at its zero value on purpose — the STORED spelling
		// of unknown (D52), not the already-resolved word.
		Ratings: []matcher.Rating{{Database: "OSV", AdvisoryID: "RH-ZERO-VALUE-1"}},
	}}}
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, `"fixState": ""`) {
		t.Errorf("a stored zero-value FixState was written to JSON as an empty string, "+
			"not resolved to \"unknown\":\n%s", out)
	}
	// Two fixState keys in this document: one on the finding, one on its
	// single rating. Counting them catches a key silently omitted, which a
	// struct-unmarshal check (nil vs "") cannot distinguish from "present and
	// empty".
	if n := strings.Count(out, `"fixState"`); n != 2 {
		t.Errorf(`"fixState" key appears %d times, want 2 (finding + one rating) — `+
			"present on both, never omitted:\n%s", n, out)
	}
	if n := strings.Count(out, `"fixState": "unknown"`); n != 2 {
		t.Errorf(`"fixState": "unknown" appears %d times, want 2:\n%s`, n, out)
	}
}

func TestJSON_EmptyResultHasEmptyArraysNotNull(t *testing.T) {
	var buf bytes.Buffer
	if _, err := JSON(&buf, matcher.Result{}, cyclonedx.Stats{}, EOLStatus{}); err != nil {
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

// TestJSON_MatchedViaProvidesIsInTheDocument holds D95's rendering promise on
// the JSON side the same way explain.go's and sarif.go's own tests hold
// theirs: a consumer reading matchedName != package.name must be able to
// tell the apk-provides join from D8's source-package indirection, and the
// distinction must be a typed field, not something inferred from prose. No
// omitempty, on MatchedName's own reasoning one field up: an absent bool
// would be ambiguous between "direct or D8 match" and "this document
// predates the field".
func TestJSON_MatchedViaProvidesIsInTheDocument(t *testing.T) {
	res := matcher.Result{
		Findings: []matcher.Finding{{
			Package: pkgmeta.Package{Name: "liberica26-lite-jdk", Version: "26.0.2.1_p1-r0",
				Ecosystem: "Alpaquita:stream"},
			Advisory: advisory.Advisory{ID: "BELL-TEST-90001", Database: "BELL",
				Upstream: []string{"CVE-2026-73001"}},
			Evidence: version.Evidence{RangeType: advisory.RangeEcosystem,
				Introduced: "0", Fixed: "26.0.2.1_p1-r1",
				Reason: "below the fix"},
			MatchedName:        "openjdk26-lite-jdk",
			MatchedViaProvides: true,
			Severity:           severity.High,
			Ratings: []matcher.Rating{{Database: "BELL", AdvisoryID: "BELL-TEST-90001",
				Severity: severity.High, Fixed: "26.0.2.1_p1-r1"}},
		}},
	}
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cyclonedx.Stats{}, EOLStatus{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(doc.Findings))
	}
	if !doc.Findings[0].MatchedViaProvides {
		t.Error("matchedViaProvides = false, want true — the JSON document cannot " +
			"tell a provides join from a D8 source join without it")
	}
	// The key itself must be present even when false (shape must not vary):
	// serialize a direct match and look for the literal key.
	res.Findings[0].MatchedViaProvides = false
	buf.Reset()
	if _, err := JSON(&buf, res, cyclonedx.Stats{}, EOLStatus{}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"matchedViaProvides":`)) {
		t.Error(`document omits "matchedViaProvides" when false — an absent bool is ` +
			"ambiguous between a direct match and a pre-D95 document")
	}
}
