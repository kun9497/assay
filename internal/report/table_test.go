package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
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
