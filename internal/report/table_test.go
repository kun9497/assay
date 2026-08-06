package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/version"
)

// columnStarts returns the offset at which each column's text begins, read off
// the tabwriter-rendered header.
//
// Offsets, not a split on runs of whitespace. tabwriter aligns every row to the
// same column offsets, so reading them once from the header and slicing each
// row at the same places survives an EMPTY cell — which a split does not: with
// no version to print, "svc  Go  GHSA-1  critical (9.8)  -  -" collapses by one
// column and every field after the gap answers for its neighbour. That is the
// wrong-column pass this helper exists to prevent, reintroduced inside the
// helper, and it would be quiet: "-" is the printed filler for two different
// columns, so the wrong cell can hold the value the test expects.
//
// A single space does not separate columns; the header holds "FIXED IN".
func columnStarts(header string) []int {
	var starts []int
	for i := 0; i < len(header); {
		if header[i] != ' ' {
			if len(starts) == 0 {
				starts = append(starts, i)
			}
			i++
			continue
		}
		j := i
		for j < len(header) && header[j] == ' ' {
			j++
		}
		if j-i >= 2 && j < len(header) {
			starts = append(starts, j)
		}
		i = j
	}
	return starts
}

// cellAt resolves a column by its header NAME rather than a hardcoded index,
// then returns that column's value in the row whose ADVISORY cell is exactly
// advisoryID. Resolving by name means the test still pins the right thing if an
// unrelated column is inserted or reordered; it fails when the column asked for
// stops lining up with the value it is supposed to hold — SEVERITY and ALIASES
// swapped while the header row was left alone, say.
//
// The row is matched on the ADVISORY cell, not on the line containing the ID
// anywhere. Advisory IDs nest (GHSA-1 is inside GHSA-10) and the same ID
// appears again in the "Not evaluated" block, so a substring match over the
// whole output can select a line that is not the finding's row at all.
func cellAt(t *testing.T, out, advisoryID, column string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	starts := columnStarts(lines[0])
	names := make([]string, len(starts))
	for i := range starts {
		names[i] = sliceColumn(lines[0], starts, i)
	}

	idx, advisoryIdx := -1, -1
	for i, h := range names {
		if h == column {
			idx = i
		}
		if h == "ADVISORY" {
			advisoryIdx = i
		}
	}
	if idx == -1 {
		t.Fatalf("no %q column in header %v:\n%s", column, names, out)
	}
	if advisoryIdx == -1 {
		t.Fatalf("no ADVISORY column to identify rows by, header %v:\n%s", names, out)
	}

	for _, l := range lines[1:] {
		if sliceColumn(l, starts, advisoryIdx) != advisoryID {
			continue
		}
		return sliceColumn(l, starts, idx)
	}
	t.Fatalf("no row has advisory %q in its ADVISORY column:\n%s", advisoryID, out)
	return ""
}

// sliceColumn cuts column i out of a rendered line using the header's offsets.
func sliceColumn(line string, starts []int, i int) string {
	if i >= len(starts) || starts[i] >= len(line) {
		// Past the end of this line: tabwriter does not pad the final cell,
		// so a trailing empty column simply is not there.
		return ""
	}
	end := len(line)
	if i+1 < len(starts) && starts[i+1] < end {
		end = starts[i+1]
	}
	return strings.TrimSpace(line[starts[i]:end])
}

// The helper's own regression test. An empty cell used to collapse the split
// and hand back a neighbouring column's value with no error — the wrong-column
// pass, inside the thing built to catch it. A package with no version renders
// an empty VERSION cell, which is also a real state: the cataloger reports
// packages it could not version.
func TestCellAt_AnEmptyCellDoesNotShiftTheColumns(t *testing.T) {
	var buf bytes.Buffer
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "svc", Version: "", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-empty"},
		Severity: severity.Critical,
		Score:    9.8,
	}}}
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, tt := range []struct{ column, want string }{
		{"PACKAGE", "svc"},
		{"VERSION", ""},
		{"ECOSYSTEM", "Go"},
		{"ADVISORY", "GHSA-empty"},
		{"SEVERITY", "critical (9.8)"},
		{"ALIASES", "-"},
		{"FIXED IN", "-"},
	} {
		if got := cellAt(t, out, "GHSA-empty", tt.column); got != tt.want {
			t.Errorf("cellAt(%s) = %q, want %q\nrendered:\n%s", tt.column, got, tt.want, out)
		}
	}
}

// Advisory IDs nest, and the row has to be found by its ADVISORY cell rather
// than by the ID appearing anywhere on the line.
func TestCellAt_PicksTheRowByItsAdvisoryCell(t *testing.T) {
	var buf bytes.Buffer
	res := matcher.Result{Findings: []matcher.Finding{
		{
			Package:  pkgmeta.Package{Name: "a", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-10"},
			Severity: severity.Low, Score: 2.0,
		},
		{
			Package:  pkgmeta.Package{Name: "b", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-1"},
			Severity: severity.High, Score: 7.5,
		},
	}}
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 2, Cataloged: 2}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// GHSA-1 is a substring of GHSA-10, which is rendered first. A substring
	// match over the line would answer with GHSA-10's severity.
	if got := cellAt(t, out, "GHSA-1", "SEVERITY"); got != "high (7.5)" {
		t.Errorf("cellAt(GHSA-1, SEVERITY) = %q, want high (7.5) - it matched the GHSA-10 row", got)
	}
	if got := cellAt(t, out, "GHSA-10", "SEVERITY"); got != "low (2.0)" {
		t.Errorf("cellAt(GHSA-10, SEVERITY) = %q, want low (2.0)", got)
	}
}

func TestTable_Findings(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "github.com/foo/bar", Version: "v1.2.3", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-hit", Summary: "Code injection"},
		Evidence: version.Evidence{Introduced: "0", Fixed: "1.5.0", Reason: "below the fix 1.5.0"},
		// A real band is given explicitly. Match always sets one; leaving it
		// at the zero value here would render "none (0.0)" for a finding that
		// was simply never asked about severity, which is the same coercion
		// D17 forbids, reached through a fixture instead of a code path.
		Severity: severity.High,
		Score:    7.5,
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"github.com/foo/bar", "v1.2.3", "GHSA-hit", "1.5.0"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestTable_SkippedCountsAreVisible(t *testing.T) {
	// A scan that could not evaluate 40 packages must not read as clean.
	res := matcher.Result{Skipped: []matcher.Skipped{{
		Package: pkgmeta.Package{Name: "apache2", Version: "2.4.54-r0", Ecosystem: "Alpine:v3.19"},
		Reason:  "no version comparer for ecosystem \"Alpine:v3.19\"",
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{
		Components: 42, Cataloged: 1, SkippedUnsupportedEcosystem: 40, SkippedNoPURL: 1,
	}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "40") {
		t.Errorf("cataloger skip count missing from summary:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "not evaluated") {
		t.Errorf("summary never says anything was left unevaluated:\n%s", out)
	}
}

func TestTable_NothingEvaluatedIsNotReportedAsClean(t *testing.T) {
	// Every component skipped, nothing judged. "No known vulnerabilities found"
	// is the sentence a genuinely clean scan prints, and a reader who greps the
	// first line cannot tell the two apart.
	var buf bytes.Buffer
	if _, err := Table(&buf, matcher.Result{}, cyclonedx.Stats{
		Components: 42, Cataloged: 0, SkippedUnsupportedEcosystem: 42,
	}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(strings.ToLower(out), "no known vulnerabilities") {
		t.Errorf("a scan that evaluated nothing must not use the clean wording:\n%s", out)
	}
	if !strings.Contains(out, "NOT a clean result") {
		t.Errorf("output must say plainly this is not a clean result:\n%s", out)
	}
}

func TestTable_CountsAddUp(t *testing.T) {
	// evaluated + not evaluated must equal components seen. A package that was
	// cataloged and then wholly skipped by the matcher used to land in both.
	res := matcher.Result{Skipped: []matcher.Skipped{{
		Package: pkgmeta.Package{Name: "x", Version: "1.0.0", Ecosystem: "Go"},
		Reason:  "no version comparer",
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 3, Cataloged: 1, SkippedNoPURL: 2}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(),
		"3 component(s) seen, 0 evaluated, 0 finding(s), 3 not evaluated") {
		t.Errorf("summary does not account for every component:\n%s", buf.String())
	}
}

func TestTable_SummaryDrivesTheExitCode(t *testing.T) {
	// Trustworthy() is what scancmd turns into an exit code, so a mutation that
	// always returns true has to fail here. Nothing else covers it.
	var buf bytes.Buffer
	sum, err := Table(&buf, matcher.Result{}, cyclonedx.Stats{
		Components: 5, Cataloged: 0, SkippedUnsupportedEcosystem: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Trustworthy() {
		t.Error("a scan that evaluated nothing reported itself trustworthy; CI would read exit 0")
	}

	// An empty document is vacuously fine, and the wording must agree with that.
	buf.Reset()
	sum, err = Table(&buf, matcher.Result{}, cyclonedx.Stats{})
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Trustworthy() {
		t.Error("an empty document is not untrustworthy, there was simply nothing to do")
	}
	if strings.Contains(buf.String(), "NOT a clean result") {
		t.Errorf("wording contradicts the exit code for an empty document:\n%s", buf.String())
	}
}

func TestTable_FindingCarriesItsAliases(t *testing.T) {
	// Dedup keeps one record per vulnerability, so a CVE matched under a GHSA
	// record is only reachable through the alias column. Dropping the column
	// makes `assay scan | grep CVE-...` silently find nothing.
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:     pkgmeta.Package{Name: "Jinja2", Version: "2.11.2", Ecosystem: "PyPI"},
		Advisory:    advisory.Advisory{ID: "GHSA-g3rq-g295-4j3m", Aliases: []string{"CVE-2020-28493"}},
		Identifiers: []string{"CVE-2020-28493", "GHSA-g3rq-g295-4j3m"},
		Evidence:    version.Evidence{Fixed: "2.11.3"},
		Severity:    severity.High,
		Score:       7.5,
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "CVE-2020-28493") {
		t.Errorf("the CVE this finding was matched under is absent from the report:\n%s", buf.String())
	}
}

func TestTable_AdvisoryScopedSkipIsAlwaysShown(t *testing.T) {
	// Everything evaluated, nothing found, but one advisory could not be judged.
	// Gating the detail block on the unevaluated count alone hid this entirely,
	// reintroducing one advisory at a time the silence the block exists to break.
	res := matcher.Result{Skipped: []matcher.Skipped{{
		Package:    pkgmeta.Package{Name: "x", Version: "1.0.0", Ecosystem: "Go"},
		AdvisoryID: "GHSA-unevaluable",
		Reason:     `the advisory's range bound "not-a-version" could not be read: invalid version`,
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "GHSA-unevaluable") {
		t.Errorf("the advisory that could not be judged is missing from the report:\n%s", out)
	}
	if !strings.Contains(out, "NOT a clean result") {
		t.Errorf("an incomplete check must not read as a clean scan:\n%s", out)
	}
}

func TestTable_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Table(&buf, matcher.Result{}, cyclonedx.Stats{Components: 3, Cataloged: 3}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(strings.ToLower(out), "no known vulnerabilities") {
		t.Errorf("clean scan should say so plainly:\n%s", out)
	}
}

func TestTable_Deterministic(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		{Package: pkgmeta.Package{Name: "a", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-1"}, Severity: severity.High, Score: 7.5},
		{Package: pkgmeta.Package{Name: "b", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-2"}, Severity: severity.Medium, Score: 5.0},
	}}
	var first, second bytes.Buffer
	if _, err := Table(&first, res, cyclonedx.Stats{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Table(&second, res, cyclonedx.Stats{}); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Error("Table output is not deterministic")
	}
}

// D8/D10: when the advisory was written against the source package, the report
// must name it. Otherwise the reader looks up the advisory, finds no mention of
// the package the table blamed, and cannot tell a real finding from a bug.
func TestTable_ShowsTheSourcePackageWhenItIsWhatMatched(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package: pkgmeta.Package{
			Name: "libssl3", Version: "3.1.4-r5", Ecosystem: "Alpine:v3.19",
			Source: &pkgmeta.SourcePackage{Name: "openssl"},
		},
		// The ID deliberately does not contain "openssl". An ID like
		// CVE-2024-openssl satisfies the substring check below on its own, so
		// the assertion passed with the source package unprinted.
		Advisory:    advisory.Advisory{ID: "CVE-2024-12345"},
		MatchedName: "openssl",
		Severity:    severity.High,
		Score:       7.5,
	}}}

	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "libssl3") {
		t.Errorf("output does not name the installed package:\n%s", out)
	}
	if !strings.Contains(out, "libssl3 (openssl)") {
		t.Errorf("output does not name the source package the advisory was written "+
			"against, so the finding cannot be checked:\n%s", out)
	}
}

// A package that matched under its own name must not gain a redundant
// parenthetical — noise in the common case buries the case that matters.
func TestTable_DoesNotRepeatTheNameWhenItMatchedDirectly(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:     pkgmeta.Package{Name: "busybox", Version: "1.36.1-r15", Ecosystem: "Alpine:v3.19"},
		Advisory:    advisory.Advisory{ID: "CVE-2024-busybox"},
		MatchedName: "busybox",
		Severity:    severity.High,
		Score:       7.5,
	}}}

	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "busybox (busybox)") {
		t.Errorf("direct match printed a redundant source package:\n%s", buf.String())
	}
}

// D3: which field carries the CVE depends on the ecosystem, and the two measured
// dumps are exact mirror images — Go puts it in aliases with upstream empty on
// all 8,510 records, Alpine puts it in upstream with aliases empty on all 4,405.
// Reading either field alone makes `assay scan | grep CVE-…` find nothing for
// half the ecosystems.
func TestTable_FindingCarriesIdentifiersFromAliasesAndUpstream(t *testing.T) {
	tests := []struct {
		name string
		adv  advisory.Advisory
		want string
	}{
		{
			name: "Go shape: the CVE is in aliases",
			adv: advisory.Advisory{
				ID:      "GHSA-xxxx-yyyy-zzzz",
				Aliases: []string{"CVE-2024-11111"},
			},
			want: "CVE-2024-11111",
		},
		{
			// The advisory ID deliberately does NOT contain the CVE. Alpine's
			// real IDs are "ALPINE-CVE-2025-46394", which has the bare CVE as a
			// substring, so asserting Contains against the real shape passes
			// from the ADVISORY column alone and never tests upstream at all.
			name: "Alpine shape: the CVE is in upstream, aliases empty",
			adv: advisory.Advisory{
				ID:       "ALPINE-2025-0001",
				Upstream: []string{"CVE-2025-46394"},
			},
			want: "CVE-2025-46394",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Identifiers is what Match populates and what the column reads,
			// so the fixture builds it the way Match does: every name every
			// joined record answers to, from aliases AND upstream (D3).
			ids := append([]string{tt.adv.ID}, tt.adv.Aliases...)
			ids = append(ids, tt.adv.Upstream...)
			res := matcher.Result{Findings: []matcher.Finding{{
				Package:     pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "e"},
				Advisory:    tt.adv,
				Identifiers: ids,
				Severity:    severity.High,
				Score:       7.5,
			}}}
			var buf bytes.Buffer
			if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("output does not carry %q, so `assay scan | grep %s` finds "+
					"nothing:\n%s", tt.want, tt.want, buf.String())
			}
		})
	}
}

// The advisory's own ID is already its own column; repeating it under other
// identifiers is noise, and a duplicate between the two fields must collapse.
func TestTable_OtherIdentifiersAreDeduplicated(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package: pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "e"},
		Advisory: advisory.Advisory{
			ID:       "ALPINE-CVE-2025-46394",
			Aliases:  []string{"CVE-2025-46394"},
			Upstream: []string{"CVE-2025-46394", "ALPINE-CVE-2025-46394"},
		},
		// Repeats on purpose, as Match hands them over before dedupSorted:
		// two records describing one vulnerability name most of the same
		// identifiers, so overlap is the normal case, not the odd one.
		Identifiers: []string{
			"ALPINE-CVE-2025-46394", "CVE-2025-46394",
			"CVE-2025-46394", "ALPINE-CVE-2025-46394",
		},
		Severity: severity.High,
		Score:    7.5,
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "CVE-2025-46394"); n != 2 {
		// Twice: once inside the ADVISORY column's ALPINE-CVE-… and once as the
		// bare CVE. A third occurrence means the two fields were concatenated
		// without dedup.
		t.Errorf("CVE-2025-46394 appears %d times, want 2:\n%s", n, buf.String())
	}
}

// A scan where most packages were never checked must not print the clean
// headline. Gating only on advisory-scoped skips warned loudly about one
// unevaluable advisory and said nothing when 15 of 17 packages went unchecked.
func TestTable_UncheckedPackagesBreakTheCleanHeadline(t *testing.T) {
	res := matcher.Result{Skipped: []matcher.Skipped{
		{Package: pkgmeta.Package{Name: "a", Version: "1", Ecosystem: "Alpine:v3.99"},
			Reason: `ecosystem "Alpine:v3.99" is not in this database`},
		{Package: pkgmeta.Package{Name: "b", Version: "1", Ecosystem: "Alpine:v3.99"},
			Reason: `ecosystem "Alpine:v3.99" is not in this database`},
	}}
	var buf bytes.Buffer
	// Three cataloged; two the matcher never checked, so one was evaluated.
	sum, err := Table(&buf, res, cyclonedx.Stats{Components: 3, Cataloged: 3})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "No known vulnerabilities") {
		t.Errorf("clean headline printed while 2 of 3 packages went unchecked:\n%s", out)
	}
	if !strings.Contains(out, "NOT a clean result") {
		t.Errorf("output must say plainly this is not a clean result:\n%s", out)
	}
	// The exit code is deliberately unchanged: one evaluated package means the
	// run is still trustworthy by D11's rule, and widening that is a separate
	// decision recorded for slice 4.
	if !sum.Trustworthy() {
		t.Error("Trustworthy() changed; this fix is about the wording, not the gate")
	}
}

// The cataloger's drops reach the headline too. Keying the wording on the
// matcher's skip count alone left the same hole open through the other door:
// 15 of 17 components never producing a package printed the clean sentence
// because the matcher, having seen only 2, had nothing to skip.
func TestTable_ComponentsTheCatalogerDroppedBreakTheCleanHeadline(t *testing.T) {
	var buf bytes.Buffer
	sum, err := Table(&buf, matcher.Result{}, cyclonedx.Stats{
		Components: 17, Cataloged: 2, SkippedNoPURL: 15,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "No known vulnerabilities") {
		t.Errorf("clean headline printed while 15 of 17 components were dropped "+
			"before the matcher ever saw them:\n%s", out)
	}
	if !strings.Contains(out, "NOT a clean result") {
		t.Errorf("output must say plainly this is not a clean result:\n%s", out)
	}
	// Still trustworthy: two packages were genuinely evaluated. This is about
	// the sentence, not the gate.
	if !sum.Trustworthy() {
		t.Error("Trustworthy() changed; this is a wording fix")
	}
}

// D13: the band and its score are rendered together, and Unknown must not
// print a fabricated score. "unknown (0.0)" would read as a real rating of
// zero — the exact coercion D17 exists to forbid — so Unknown gets no
// parenthetical at all.
func TestFormatSeverity(t *testing.T) {
	if got := formatSeverity(severity.Critical, 9.8); got != "critical (9.8)" {
		t.Errorf("formatSeverity(critical, 9.8) = %q, want %q", got, "critical (9.8)")
	}
	if got := formatSeverity(severity.Unknown, 0); got != "unknown" {
		t.Errorf("formatSeverity(unknown, 0) = %q, want %q", got, "unknown")
	}
}

// The findings table must show the severity a reader would use to triage —
// the band together with the score behind it, not just one or the other.
func TestTable_SeverityColumn(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "svc", Version: "1.0.0", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-sev"},
		Severity: severity.Critical,
		Score:    9.8,
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "SEVERITY") {
		t.Errorf("header is missing the SEVERITY column:\n%s", out)
	}
	if !strings.Contains(out, "critical (9.8)") {
		t.Errorf("row does not show the band and score together:\n%s", out)
	}
}

// Neither assertion in TestTable_SeverityColumn pins WHERE the severity cell
// sits, only that it exists somewhere in the output. A reorder of the
// Fprintf args that left the header alone — SEVERITY and ALIASES swapped,
// say — would pass it: "SEVERITY" is still in the header text and
// "critical (9.8)" is still in the row text, just under the wrong column.
// Readers triage by column position, so that swap is a real failure, not a
// cosmetic one. This resolves every column by its header name and checks the
// value landed where the header claims.
func TestTable_ColumnOrderMatchesHeader(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:     pkgmeta.Package{Name: "svc", Version: "1.0.0", Ecosystem: "Go"},
		Advisory:    advisory.Advisory{ID: "GHSA-sev", Aliases: []string{"CVE-2024-00001"}},
		Identifiers: []string{"CVE-2024-00001", "GHSA-sev"},
		Evidence:    version.Evidence{Fixed: "2.0.0"},
		Severity:    severity.Critical,
		Score:       9.8,
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	want := map[string]string{
		"PACKAGE":   "svc",
		"VERSION":   "1.0.0",
		"ECOSYSTEM": "Go",
		"ADVISORY":  "GHSA-sev",
		"SEVERITY":  "critical (9.8)",
		"ALIASES":   "CVE-2024-00001",
		"FIXED IN":  "2.0.0",
	}
	for column, wantVal := range want {
		if got := cellAt(t, out, "GHSA-sev", column); got != wantVal {
			t.Errorf("column %q = %q, want %q — SEVERITY and ALIASES must not be "+
				"swapped:\n%s", column, got, wantVal, out)
		}
	}
}

// D17: the unknown-severity count belongs in the summary on every run, not
// only when it is non-zero. A count that appears conditionally teaches
// readers not to look for it, which is the same failure as a threshold that
// silently excludes what it could not judge.
func TestTable_UnknownSeverityCountIsAlwaysPrinted(t *testing.T) {
	var buf bytes.Buffer
	sum, err := Table(&buf, matcher.Result{}, cyclonedx.Stats{Components: 1, Cataloged: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "0 unknown severity") {
		t.Errorf("summary omits the unknown-severity count when it is zero:\n%s", buf.String())
	}
	if sum.UnknownSeverity != 0 {
		t.Errorf("Summary.UnknownSeverity = %d, want 0", sum.UnknownSeverity)
	}
}

// The count must actually track findings whose severity could not be rated,
// not just be present. Task 5's --fail-on-unknown reads Summary.UnknownSeverity
// directly, so a Summary that always reports 0 would pass the test above while
// making that flag inert.
func TestTable_UnknownSeverityCountReflectsFindings(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		{Package: pkgmeta.Package{Name: "a", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-1"}, Severity: severity.Unknown},
		{Package: pkgmeta.Package{Name: "b", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-2"}, Severity: severity.Critical, Score: 9.8},
	}}
	var buf bytes.Buffer
	sum, err := Table(&buf, res, cyclonedx.Stats{Components: 2, Cataloged: 2})
	if err != nil {
		t.Fatal(err)
	}
	if sum.UnknownSeverity != 1 {
		t.Errorf("Summary.UnknownSeverity = %d, want 1", sum.UnknownSeverity)
	}
	if !strings.Contains(buf.String(), "1 unknown severity") {
		t.Errorf("summary line does not carry the unknown-severity count:\n%s", buf.String())
	}
	// The row itself must say "unknown", not a coerced real band. A mutation
	// that forced Unknown to Low before formatting would leave the summary
	// line above untouched (it is driven from Finding.Severity directly, not
	// from the rendered row) while the table quietly claimed a 0.0-adjacent
	// rating for a finding nothing rated — the report contradicting itself.
	if got := cellAt(t, buf.String(), "GHSA-1", "SEVERITY"); got != "unknown" {
		t.Errorf("GHSA-1's SEVERITY column = %q, want \"unknown\"", got)
	}
}

// TestSourcesDisagree is the direct unit test for the predicate the table's
// marker and footnote are both driven by. "Disagree" means the Severity
// bands differ, and nothing else: two ratings with the same band but
// different scores or fixed versions have not disagreed by this table's own
// definition (that finer-grained detail is --explain's job, D10).
func TestSourcesDisagree(t *testing.T) {
	for _, tt := range []struct {
		name    string
		ratings []matcher.Rating
		want    bool
	}{
		{"no ratings (pre-D25 fixture)", nil, false},
		{"one rating", []matcher.Rating{{Database: "GHSA", Severity: severity.Critical}}, false},
		{
			"two ratings, same band, different score and fixed version",
			[]matcher.Rating{
				{Database: "GHSA", Severity: severity.High, Score: 7.5, Fixed: "1.0.0"},
				{Database: "PYSEC", Severity: severity.High, Score: 7.2, Fixed: "1.1.0"},
			},
			false,
		},
		{
			"two ratings, different band",
			[]matcher.Rating{
				{Database: "GHSA", Severity: severity.Critical, Score: 9.8},
				{Database: "PYSEC", Severity: severity.Unknown},
			},
			true,
		},
		{
			"three ratings, the third breaks agreement between the first two",
			[]matcher.Rating{
				{Database: "ALPINE", Severity: severity.High},
				{Database: "GHSA", Severity: severity.High},
				{Database: "PYSEC", Severity: severity.Low},
			},
			true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := sourcesDisagree(tt.ratings); got != tt.want {
				t.Errorf("sourcesDisagree(%+v) = %v, want %v", tt.ratings, got, tt.want)
			}
		})
	}
}

// TestTable_MarksSeverityWhenSourcesDisagree: D25's whole point is that
// disagreement between sources is not silently collapsed. The table keeps
// one row and one SEVERITY cell, but a cell whose sources gave different
// bands has to say so, or the aggregate reads as unanimous when it is not.
func TestTable_MarksSeverityWhenSourcesDisagree(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "django", Version: "3.2.12", Ecosystem: "PyPI"},
		Advisory: advisory.Advisory{ID: "GHSA-w24h-v9qh-8gxj"},
		Severity: severity.Critical,
		Score:    9.8,
		Ratings: []matcher.Rating{
			{Database: "GHSA", AdvisoryID: "GHSA-w24h-v9qh-8gxj", Severity: severity.Critical, Score: 9.8, Fixed: "2.2.28"},
			{Database: "PYSEC", AdvisoryID: "PYSEC-2022-191", Severity: severity.Unknown, Fixed: "2.2.28"},
		},
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if got := cellAt(t, out, "GHSA-w24h-v9qh-8gxj", "SEVERITY"); got != "critical (9.8) *" {
		t.Errorf("SEVERITY column = %q, want %q", got, "critical (9.8) *")
	}
	if !strings.Contains(out, "--explain") {
		t.Errorf("output does not point the reader at --explain for the detail:\n%s", out)
	}
}

// TestTable_NoMarkerWhenSourcesAgree: a difference in score or fixed version
// alone is not the disagreement this marker exists to flag — only the two
// sources landing on different bands is. Marking every finding with more
// than one source, agreeing or not, would make the marker meaningless.
//
// Also covers the whole-scan footnote absence for both ways a finding can
// fail to disagree: GHSA-agree has two sources that land on the same band,
// GHSA-solo has exactly one. Neither earns a marker, and — since neither
// row does — the scan-level footnote must not appear at all. (A fixture
// using a real single-Rating Finding here, rather than one Match itself
// could never produce, matters: Match always populates at least one
// Rating (D25), so a zero-Ratings Finding was never a real "single-source"
// case to begin with.)
func TestTable_NoMarkerWhenSourcesAgree(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		{
			Package:  pkgmeta.Package{Name: "svc", Version: "1.0.0", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-agree"},
			Severity: severity.High,
			Score:    7.5,
			Ratings: []matcher.Rating{
				{Database: "GHSA", AdvisoryID: "GHSA-agree", Severity: severity.High, Score: 7.5, Fixed: "1.0.0"},
				{Database: "PYSEC", AdvisoryID: "PYSEC-agree", Severity: severity.High, Score: 7.2, Fixed: "1.1.0"},
			},
		},
		{
			Package:  pkgmeta.Package{Name: "lib", Version: "2.0.0", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-solo"},
			Severity: severity.Critical,
			Score:    9.8,
			Ratings: []matcher.Rating{
				{Database: "GHSA", AdvisoryID: "GHSA-solo", Severity: severity.Critical, Score: 9.8, Fixed: "2.1.0"},
			},
		},
	}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 2, Cataloged: 2}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if got := cellAt(t, out, "GHSA-agree", "SEVERITY"); got != "high (7.5)" {
		t.Errorf("SEVERITY column = %q, want %q (no marker — the sources agree on the band)", got, "high (7.5)")
	}
	if got := cellAt(t, out, "GHSA-solo", "SEVERITY"); got != "critical (9.8)" {
		t.Errorf("SEVERITY column = %q, want %q (no marker — a single source has nothing to disagree with)", got, "critical (9.8)")
	}
	if strings.Contains(out, "disagree") || strings.Contains(out, "--explain") {
		t.Errorf("no finding disagreed, but the output claims a disagreement or carries its footnote:\n%s", out)
	}
}

// TestTable_NoMarkerWithASingleRating: the brief is explicit that a finding
// with one rating never gets the marker — there is nothing for a single
// source to disagree with.
func TestTable_NoMarkerWithASingleRating(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "svc", Version: "1.0.0", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-solo"},
		Severity: severity.Critical,
		Score:    9.8,
		Ratings: []matcher.Rating{
			{Database: "GHSA", AdvisoryID: "GHSA-solo", Severity: severity.Critical, Score: 9.8, Fixed: "1.0.0"},
		},
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if got := cellAt(t, out, "GHSA-solo", "SEVERITY"); got != "critical (9.8)" {
		t.Errorf("SEVERITY column = %q, want %q (no marker with one source)", got, "critical (9.8)")
	}
	if strings.Contains(out, "disagree") {
		t.Errorf("output claims a disagreement with only one source:\n%s", out)
	}
}

// TestTable_FootnoteOnlyWhenSomeoneDisagrees: the footnote is printed at
// most once, and only when at least one row actually earned the marker — a
// scan with no disagreeing findings must not carry a footnote explaining a
// marker that never appears. Mixing one disagreeing and one agreeing
// finding in the same result also proves the marker is per-row, not
// per-scan: only GHSA-mixed-disagree gets it.
func TestTable_FootnoteOnlyWhenSomeoneDisagrees(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		{
			Package:  pkgmeta.Package{Name: "a", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-mixed-disagree"},
			Severity: severity.Critical,
			Score:    9.8,
			Ratings: []matcher.Rating{
				{Database: "GHSA", AdvisoryID: "GHSA-mixed-disagree", Severity: severity.Critical, Score: 9.8},
				{Database: "PYSEC", AdvisoryID: "PYSEC-mixed-disagree", Severity: severity.Unknown},
			},
		},
		{
			Package:  pkgmeta.Package{Name: "b", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-mixed-agree"},
			Severity: severity.Medium,
			Score:    5.0,
			Ratings: []matcher.Rating{
				{Database: "GHSA", AdvisoryID: "GHSA-mixed-agree", Severity: severity.Medium, Score: 5.0},
			},
		},
	}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 2, Cataloged: 2}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if got := cellAt(t, out, "GHSA-mixed-disagree", "SEVERITY"); got != "critical (9.8) *" {
		t.Errorf("SEVERITY column = %q, want %q", got, "critical (9.8) *")
	}
	if got := cellAt(t, out, "GHSA-mixed-agree", "SEVERITY"); got != "medium (5.0)" {
		t.Errorf("SEVERITY column = %q, want %q (single source, no marker)", got, "medium (5.0)")
	}
	if n := strings.Count(out, "sources disagree"); n != 1 {
		t.Errorf("footnote appears %d times, want exactly 1:\n%s", n, out)
	}
}

// The whole-scan "no footnote when nobody disagrees" case (both the
// single-source and the multi-source-but-unanimous ways a finding can fail
// to disagree) is folded into TestTable_NoMarkerWhenSourcesAgree above,
// rather than kept as a separate test here: a standalone version of it
// previously used a Finding with zero Ratings, a state Match itself never
// produces (D25), to stand in for "single-source" — a case its neighbour
// now covers with a real single-Rating fixture instead.

// D38 counts the cataloger's own skips into TargetIncomplete, and one of them
// must stay out: an ecosystem assay does not support is assay's coverage, not
// the caller's data, and no amount of editing their manifest changes it.
//
// Asserted as a unit rather than through a scan, because no fixture directory
// produces a cataloger-side unsupported-ecosystem skip — which is exactly why
// adding it to the sum survived a first mutation round.
func TestSummary_TargetIncompleteExcludesUnsupportedEcosystem(t *testing.T) {
	for _, tc := range []struct {
		name string
		cat  cyclonedx.Stats
		want int
	}{
		{"no version is the caller's data",
			cyclonedx.Stats{Components: 1, SkippedNoVersion: 1}, 1},
		{"no purl is the caller's data",
			cyclonedx.Stats{Components: 1, SkippedNoPURL: 1}, 1},
		{"an unsupported ecosystem is not",
			cyclonedx.Stats{Components: 1, SkippedUnsupportedEcosystem: 1}, 0},
		{"and the three do not merge",
			cyclonedx.Stats{Components: 3, SkippedNoVersion: 1, SkippedNoPURL: 1, SkippedUnsupportedEcosystem: 1}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			sum, err := Table(&buf, matcher.Result{}, tc.cat)
			if err != nil {
				t.Fatal(err)
			}
			if sum.TargetIncomplete != tc.want {
				t.Errorf("TargetIncomplete = %d, want %d for %+v", sum.TargetIncomplete, tc.want, tc.cat)
			}
		})
	}
}
