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
