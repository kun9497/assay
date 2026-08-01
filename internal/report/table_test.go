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

func TestTable_Findings(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "github.com/foo/bar", Version: "v1.2.3", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-hit", Summary: "Code injection"},
		Evidence: version.Evidence{Introduced: "0", Fixed: "1.5.0", Reason: "below the fix 1.5.0"},
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
		Package:  pkgmeta.Package{Name: "Jinja2", Version: "2.11.2", Ecosystem: "PyPI"},
		Advisory: advisory.Advisory{ID: "GHSA-g3rq-g295-4j3m", Aliases: []string{"CVE-2020-28493"}},
		Evidence: version.Evidence{Fixed: "2.11.3"},
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
		Reason:     "comparing 1.0.0: invalid version",
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
			Advisory: advisory.Advisory{ID: "GHSA-1"}},
		{Package: pkgmeta.Package{Name: "b", Version: "1", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-2"}},
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
			res := matcher.Result{Findings: []matcher.Finding{{
				Package:  pkgmeta.Package{Name: "p", Version: "1", Ecosystem: "e"},
				Advisory: tt.adv,
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
}
