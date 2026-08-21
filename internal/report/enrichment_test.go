package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
)

// What a KISA notice carries (D3): Korean prose and a link, with no severity,
// no ecosystem and no package name.
//
// The three payload values carry deliberately non-nesting tokens, and none of
// them contains a CVE ID. Korean text, nesting identifiers and a URL holding
// the notice id would otherwise all sit in the same row here, and this
// repository has been bitten repeatedly by an assertion satisfied from a
// neighbouring column: as written, a check for the title cannot pass from the
// summary, the link, or the identifier the join used.
const (
	kisaTitle   = "제목-오픈소스-라이브러리-보안-업데이트-권고"
	kisaSummary = "개요-원격에서-임의의-코드를-실행할-수-있는-결함이-발견되었습니다"
	kisaURL     = "https://knvd.krcert.or.kr/info/vuln/notice/detail?id=99887"
	// D33. Non-zero on purpose: Claims is an int, so a fixture leaving it at
	// its zero value would let a renderer that never reads the field produce
	// byte-identical output. It is also a value that appears nowhere else in
	// the fixture — not in the id, the version, or any count — so an assertion
	// on it cannot pass from another column.
	kisaClaims = 47
)

func kisaEnrichment() matcher.Enrichment {
	return matcher.Enrichment{
		Source: "KISA", Title: kisaTitle, Summary: kisaSummary, URL: kisaURL,
		Claims: kisaClaims,
	}
}

// footnoteLine returns the table footnote beginning with marker, or "" when
// the table printed none. Matched on the line's own first characters rather
// than by searching the whole output for the marker: `+` and `*` both occur
// inside cells, so a Contains check over the output would answer from a row.
func footnoteLine(out, marker string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, marker+" ") {
			return l
		}
	}
	return ""
}

// --- the table: a marker and a footnote, never the text itself ---

// An enriched row is marked, the footnote names who wrote the text, and the
// text itself stays out of the table. Korean is double-width in a fixed-width
// terminal while tabwriter counts bytes, so a title in a cell misaligns every
// column after it — and the misalignment is invisible to the code that
// produced it.
func TestTable_MarksAnEnrichedFindingAndNamesItsSource(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		{
			Package:    pkgmeta.Package{Name: "libssl3", Version: "3.1.4-r5", Ecosystem: "Alpine:v3.19"},
			Advisory:   advisory.Advisory{ID: "ALPINE-2025-0001"},
			Severity:   severity.High,
			Score:      7.5,
			Ratings:    []matcher.Rating{{Database: "ALPINE", AdvisoryID: "ALPINE-2025-0001", Severity: severity.High, Score: 7.5}},
			Enrichment: []matcher.Enrichment{kisaEnrichment()},
		},
		{
			Package:  pkgmeta.Package{Name: "busybox", Version: "1.36.1-r15", Ecosystem: "Alpine:v3.19"},
			Advisory: advisory.Advisory{ID: "ALPINE-2025-0002"},
			Severity: severity.Medium,
			Score:    5.0,
			Ratings:  []matcher.Rating{{Database: "ALPINE", AdvisoryID: "ALPINE-2025-0002", Severity: severity.Medium, Score: 5.0}},
		},
	}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 2, Cataloged: 2}, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Resolving the enriched row by the full cell content is the assertion:
	// cellAt matches a row on its ADVISORY cell exactly, so this fails if the
	// marker is missing, is attached to some other column, or is a different
	// glyph. Reading SEVERITY back at the same time proves the marker did not
	// land there — that column belongs to the disagreement marker, and
	// enrichment says nothing about the band (D3).
	if got := cellAt(t, out, "ALPINE-2025-0001 "+enrichmentMarker, "SEVERITY"); got != "high (7.5)" {
		t.Errorf("SEVERITY column of the enriched row = %q, want %q — the enrichment "+
			"marker belongs on ADVISORY, not here", got, "high (7.5)")
	}
	// ...and the row nothing enriched carries no marker at all.
	if got := cellAt(t, out, "ALPINE-2025-0002", "ADVISORY"); got != "ALPINE-2025-0002" {
		t.Errorf("ADVISORY column of the un-enriched row = %q, want it unmarked", got)
	}

	want := enrichmentMarker + " also described by KISA; see --explain <id> for the text"
	if got := footnoteLine(out, enrichmentMarker); got != want {
		t.Errorf("footnote = %q, want %q\nfull output:\n%s", got, want, out)
	}

	// The text itself is --explain's job. A title in a cell would misalign the
	// table, and a summary would drown it.
	for _, s := range []string{kisaTitle, kisaSummary, kisaURL} {
		if strings.Contains(out, s) {
			t.Errorf("the table carries the Korean text itself (%q); it must carry a "+
				"marker and a footnote only:\n%s", s, out)
		}
	}
}

// A footnote nobody's row earned is worse than no footnote — the rule the
// disagreement marker already follows, applied to this one.
func TestTable_NoEnrichmentNoMarkerAndNoFootnote(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "svc", Version: "1.0.0", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-unenriched"},
		Severity: severity.High,
		Score:    7.5,
		Ratings:  []matcher.Rating{{Database: "GHSA", AdvisoryID: "GHSA-unenriched", Severity: severity.High, Score: 7.5}},
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if got := cellAt(t, out, "GHSA-unenriched", "ADVISORY"); got != "GHSA-unenriched" {
		t.Errorf("ADVISORY column = %q, want the bare id — nothing enriched this", got)
	}
	if got := footnoteLine(out, enrichmentMarker); got != "" {
		t.Errorf("the table printed an enrichment footnote no row earned: %q", got)
	}
	if strings.Contains(out, "also described by") {
		t.Errorf("output claims another source described a finding nothing enriched:\n%s", out)
	}
}

// Every source named once, sorted, however the findings happened to be
// ordered. Two runs over one result must agree (design goal #3), and the
// sources arrive in finding order, which is not source order.
func TestTable_EnrichmentFootnoteNamesEverySourceOnceSorted(t *testing.T) {
	jpcert := matcher.Enrichment{
		Source: "JPCERT", Title: "JPCERT-title", Summary: "JPCERT-summary",
		URL: "https://jvn.jp/en/jp/JVN00000000/",
	}
	finding := func(id string, e ...matcher.Enrichment) matcher.Finding {
		return matcher.Finding{
			Package:    pkgmeta.Package{Name: "p" + id, Version: "1.0.0", Ecosystem: "Go"},
			Advisory:   advisory.Advisory{ID: id},
			Severity:   severity.Medium,
			Score:      5.0,
			Ratings:    []matcher.Rating{{Database: "GHSA", AdvisoryID: id, Severity: severity.Medium, Score: 5.0}},
			Enrichment: e,
		}
	}
	// KISA first and twice, JPCERT once and second: an unsorted join would
	// read "KISA, JPCERT" and an undeduplicated one "KISA, JPCERT, KISA".
	res := matcher.Result{Findings: []matcher.Finding{
		finding("GHSA-1", kisaEnrichment()),
		finding("GHSA-2", jpcert),
		finding("GHSA-3", kisaEnrichment()),
	}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 3, Cataloged: 3}, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	want := enrichmentMarker + " also described by JPCERT, KISA; see --explain <id> for the text"
	if got := footnoteLine(out, enrichmentMarker); got != want {
		t.Errorf("footnote = %q, want %q\nfull output:\n%s", got, want, out)
	}
	if n := strings.Count(out, "also described by"); n != 1 {
		t.Errorf("footnote appears %d times, want exactly 1:\n%s", n, out)
	}
}

// The two markers are independent facts about one row and must not displace
// each other: the sources disagreed about the band AND someone published prose.
// A single shared marker, or one written over the other, would lose one of
// them — and they live in different columns precisely so a reader can tell
// which is which.
func TestTable_EnrichmentAndDisagreementMarkersCoexist(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "django", Version: "3.2.12", Ecosystem: "PyPI"},
		Advisory: advisory.Advisory{ID: "GHSA-both"},
		Severity: severity.Critical,
		Score:    9.8,
		Ratings: []matcher.Rating{
			{Database: "GHSA", AdvisoryID: "GHSA-both", Severity: severity.Critical, Score: 9.8},
			{Database: "PYSEC", AdvisoryID: "PYSEC-both", Severity: severity.Unknown},
		},
		Enrichment: []matcher.Enrichment{kisaEnrichment()},
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if got := cellAt(t, out, "GHSA-both "+enrichmentMarker, "SEVERITY"); got != "critical (9.8) "+disagreementMarker {
		t.Errorf("SEVERITY column = %q, want %q — both markers, in their own columns",
			got, "critical (9.8) "+disagreementMarker)
	}
	if got := footnoteLine(out, disagreementMarker); got == "" {
		t.Error("the disagreement footnote disappeared once the row was also enriched")
	}
	if got := footnoteLine(out, enrichmentMarker); got == "" {
		t.Error("the enrichment footnote disappeared once the row also disagreed")
	}
}

// --- --explain: the text in full, which is where this feature pays off ---

// TestExplain_PrintsTheEnrichmentInFull pins all three payload fields as
// rendered lines, each resolved by its own label. Nothing else in the output
// restates any of them, so each assertion can only be satisfied by the line it
// names — and Summary in particular has no other reader anywhere in the suite:
// the store round-trip that would otherwise hold it asserts only Title and URL,
// so `json:"-"` on advisory.Enrichment.Summary would empty every stored Korean
// overview and this is the assertion that goes red.
func TestExplain_PrintsTheEnrichmentInFull(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:     pkgmeta.Package{Name: "libssl3", Version: "3.1.4-r5", Ecosystem: "Alpine:v3.19"},
		Advisory:    advisory.Advisory{ID: "ALPINE-2025-0001"},
		Identifiers: []string{"ALPINE-2025-0001", "CVE-2025-46394"},
		Severity:    severity.High,
		Score:       7.5,
		Ratings: []matcher.Rating{
			{Database: "ALPINE", AdvisoryID: "ALPINE-2025-0001", Severity: severity.High, Score: 7.5, Fixed: "3.1.4-r6"},
		},
		Enrichment: []matcher.Enrichment{kisaEnrichment()},
	}}}
	var buf bytes.Buffer
	// Looked up by the CVE, which is the identifier a KISA record joins on and
	// the one a reader would have copied out of the table's ALIASES column.
	n, err := Explain(&buf, res, "CVE-2025-46394")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}
	out := buf.String()

	for _, tt := range []struct{ prefix, want string }{
		{"enrichment:", "enrichment: KISA"},
		{"  title:", "  title:    " + kisaTitle},
		{"  summary:", "  summary:  " + kisaSummary},
		{"  link:", "  link:     " + kisaURL},
	} {
		if got := explainLine(t, out, tt.prefix); got != tt.want {
			t.Errorf("line %q = %q, want %q\nfull output:\n%s", tt.prefix, got, tt.want, out)
		}
	}

	// Below the account of the match, not spliced into it. Everything above
	// "result:" is why this package matched; enrichment is evidence of nothing
	// (D3), and a reader who stops at "result:" has still read the whole match.
	lines := strings.Split(out, "\n")
	resultAt, enrichmentAt := -1, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "result:") {
			resultAt = i
		}
		if strings.HasPrefix(l, "enrichment:") {
			enrichmentAt = i
		}
	}
	if resultAt == -1 || enrichmentAt == -1 || enrichmentAt < resultAt {
		t.Errorf("enrichment at line %d, result at line %d — the prose must come after "+
			"the evidence, not inside it:\n%s", enrichmentAt, resultAt, out)
	}
}

// The workflow the table's own footnote advertises: mark a row, tell the reader
// to run `--explain <id>`, and have the cell they copy actually work.
//
// The marker lands inside the ADVISORY cell, which is --explain's input, so
// before trimCellMarker existed this printed `no finding matches advisory or
// alias "ALPINE-2025-0001 +"` and exited 2 — the report's own instruction
// failing on the report's own output.
//
// The string handed to Explain is READ OUT OF THE RENDERED TABLE rather than
// written out here: cellAt fails the test unless a row's ADVISORY cell is
// exactly that text, so this pins the two renderers to each other. A change to
// how the marker is attached breaks this test rather than quietly breaking the
// workflow.
func TestExplain_ResolvesTheAdvisoryCellAReaderCopied(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:     pkgmeta.Package{Name: "libssl3", Version: "3.1.4-r5", Ecosystem: "Alpine:v3.19"},
		Advisory:    advisory.Advisory{ID: "ALPINE-2025-0001"},
		Identifiers: []string{"ALPINE-2025-0001", "CVE-2025-46394"},
		Severity:    severity.High,
		Score:       7.5,
		Ratings: []matcher.Rating{
			{Database: "ALPINE", AdvisoryID: "ALPINE-2025-0001", Severity: severity.High, Score: 7.5},
		},
		Enrichment: []matcher.Enrichment{kisaEnrichment()},
	}}}
	var table bytes.Buffer
	if _, err := Table(&table, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	cell := cellAt(t, table.String(), "ALPINE-2025-0001 "+enrichmentMarker, "ADVISORY")
	if cell == "ALPINE-2025-0001" {
		t.Fatalf("the ADVISORY cell carries no marker, so this test cannot tell a "+
			"trimmed lookup from an untrimmed one:\n%s", table.String())
	}

	for _, id := range []string{
		cell,                                 // exactly what the table rendered
		"ALPINE-2025-0001",                   // the bare id, which must keep working
		"CVE-2025-46394 " + enrichmentMarker, // an alias, marker and all
	} {
		t.Run(id, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := Explain(&buf, res, id)
			if err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Fatalf("Explain(%q) found %d findings, want 1 — the table's footnote "+
					"sends a reader here with this exact string", id, n)
			}
			if got := explainLine(t, buf.String(), "advisory:"); got != "advisory: ALPINE-2025-0001" {
				t.Errorf("explained %q, want the ALPINE-2025-0001 finding", got)
			}
		})
	}
}

// trimCellMarker's own boundaries. The trim is safe only because a marker is
// preceded by a space and advisory identifiers contain none — so the cases that
// must NOT be trimmed matter as much as the ones that must.
func TestTrimCellMarker(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"GHSA-1 +", "GHSA-1"},                             // the ADVISORY cell
		{"critical (9.8) *", "critical (9.8)"},             // the SEVERITY cell, for free
		{"GHSA-1  +", "GHSA-1"},                            // padding a reader may have copied
		{"GHSA-1 + ", "GHSA-1"},                            // ...and trailing padding
		{"GHSA-1", "GHSA-1"},                               // untouched
		{"CVE-2024-12345", "CVE-2024-12345"},               // untouched
		{"ALPINE-CVE-2025-46394", "ALPINE-CVE-2025-46394"}, // a nesting id, untouched
		// No space, so this is a string a reader typed rather than a cell they
		// copied. Trimming it would be inventing an identifier they did not ask
		// for, and --explain answering exit 2 for a typo is the correct answer.
		{"CVE-2024-1+", "CVE-2024-1+"},
		// A bare marker is not an identifier with a marker; there is nothing
		// underneath it to find.
		{"+", "+"},
		{"*", "*"},
	} {
		if got := trimCellMarker(tt.in); got != tt.want {
			t.Errorf("trimCellMarker(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Most findings gain nothing (the measured KISA overlap is 2.4%), so the block
// has to be absent rather than empty — an "enrichment:" heading with nothing
// under it reads as a lookup that failed.
func TestExplain_NoEnrichmentPrintsNoBlock(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "svc", Version: "1.0.0", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-unenriched-explain"},
		Severity: severity.High,
		Score:    7.5,
	}}}
	var buf bytes.Buffer
	if _, err := Explain(&buf, res, "GHSA-unenriched-explain"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "enrichment:") {
		t.Errorf("output carries an enrichment block for a finding with none:\n%s", buf.String())
	}
}

// enrichmentLines' own unit test: which lines a record produces, and which it
// leaves out.
func TestEnrichmentLines(t *testing.T) {
	t.Run("every field present", func(t *testing.T) {
		got := enrichmentLines([]matcher.Enrichment{kisaEnrichment()})
		want := []string{
			"enrichment: KISA",
			"  title:    " + kisaTitle,
			"  summary:  " + kisaSummary,
			"  link:     " + kisaURL,
			"  scope:    this notice covers 47 vulnerabilities, not only this one",
		}
		assertLines(t, got, want)
	})

	// D33: the scope line is what separates prose about this vulnerability from
	// a monthly bulletin that happened to list it. It is printed only above one
	// — a notice about a single CVE has nothing to disclose, and a line saying
	// so on every record would train a reader to skip the block.
	t.Run("a notice about one CVE discloses no scope", func(t *testing.T) {
		got := enrichmentLines([]matcher.Enrichment{
			{Source: "KISA", Title: kisaTitle, URL: kisaURL, Claims: 1},
		})
		want := []string{
			"enrichment: KISA",
			"  title:    " + kisaTitle,
			"  link:     " + kisaURL,
		}
		assertLines(t, got, want)
	})

	// Zero is "this source does not report breadth", which is not the same as
	// one and must not render as a claim about scope either way.
	t.Run("unreported breadth discloses no scope", func(t *testing.T) {
		got := enrichmentLines([]matcher.Enrichment{
			{Source: "KISA", Title: kisaTitle, URL: kisaURL},
		})
		for _, l := range got {
			if strings.Contains(l, "scope:") {
				t.Errorf("rendered %q for a record whose breadth is unreported", l)
			}
		}
	})

	// A notice whose overview could not be extracted still has a headline and a
	// link. Blank "summary:" lines would read as a rendering fault; the source
	// is named regardless, because unattributed prose in a vulnerability report
	// is worse than none.
	t.Run("empty summary is dropped, not printed blank", func(t *testing.T) {
		got := enrichmentLines([]matcher.Enrichment{
			{Source: "KISA", Title: kisaTitle, URL: kisaURL},
		})
		want := []string{
			"enrichment: KISA",
			"  title:    " + kisaTitle,
			"  link:     " + kisaURL,
		}
		assertLines(t, got, want)
	})

	t.Run("nothing at all renders nothing", func(t *testing.T) {
		if got := enrichmentLines(nil); len(got) != 0 {
			t.Errorf("enrichmentLines(nil) = %q, want no lines", got)
		}
	})

	// Two sources are two blocks, each headed by its own name, in the order
	// the matcher sorted them. One heading with four values under it would
	// attribute the second source's text to the first.
	t.Run("two records are two attributed blocks", func(t *testing.T) {
		got := enrichmentLines([]matcher.Enrichment{
			{Source: "JPCERT", Title: "JPCERT-title", URL: "https://jvn.jp/en/jp/JVN00000000/"},
			kisaEnrichment(),
		})
		want := []string{
			"enrichment: JPCERT",
			"  title:    JPCERT-title",
			"  link:     https://jvn.jp/en/jp/JVN00000000/",
			"enrichment: KISA",
			"  title:    " + kisaTitle,
			"  summary:  " + kisaSummary,
			"  link:     " + kisaURL,
			"  scope:    this notice covers 47 vulnerabilities, not only this one",
		}
		assertLines(t, got, want)
	})
}

// assertLines compares rendered lines element for element, so a failure names
// the line that differs instead of reporting that two slices are unequal.
func assertLines(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d:\n  got  %q\n  want %q", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// --- JSON: a new key, carrying every field ---

// The machine-readable view keeps the whole record, the way it keeps every
// rating (D25) rather than just the winner: a consumer building its own report
// needs the text, not a flag saying text exists.
func TestJSON_CarriesEnrichmentInFull(t *testing.T) {
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
		t.Fatalf("Findings = %d, want 3", len(doc.Findings))
	}
	f := doc.Findings[0] // the Alpine finding goldenFixture enriches
	if len(f.Enrichment) != 1 {
		t.Fatalf("Enrichment = %d entries, want 1: %+v", len(f.Enrichment), f.Enrichment)
	}
	want := EnrichmentRecord{
		Source: "KISA", Title: kisaTitle, Summary: kisaSummary, URL: kisaURL,
		Claims: kisaClaims,
	}
	if f.Enrichment[0] != want {
		t.Errorf("Enrichment[0] = %+v, want %+v", f.Enrichment[0], want)
	}
	// Nothing enriched the other two, and enrichment is per finding rather than
	// per document — a record attached to every finding would be worse than none.
	if len(doc.Findings[1].Enrichment) != 0 || len(doc.Findings[2].Enrichment) != 0 {
		t.Errorf("enrichment leaked onto findings that carry none: %+v / %+v",
			doc.Findings[1].Enrichment, doc.Findings[2].Enrichment)
	}
}

// The null-vs-empty-array boundary, the discipline
// TestJSON_RatingsIsEmptyArrayNotNullWhenAbsent applies to the neighbouring
// field. Most findings gain no enrichment, so this is the ordinary shape rather
// than an edge case: `jq '.findings[].enrichment | length'` must work on a
// document where nothing was enriched.
func TestJSON_EnrichmentIsEmptyArrayNotNullWhenAbsent(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-no-enrichment"},
		Severity: severity.High,
		Score:    7.5,
		Ratings: []matcher.Rating{
			{Database: "GHSA", AdvisoryID: "GHSA-no-enrichment", Severity: severity.High, Score: 7.5},
		},
	}}}
	var buf bytes.Buffer
	if _, err := JSON(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"enrichment": []`) {
		t.Errorf(`output does not contain "enrichment": [] for a finding with none:%s`, out)
	}
	if strings.Contains(out, "null") {
		t.Errorf("output contains a null where jq expects an array:\n%s", out)
	}
}
