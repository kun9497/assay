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
)

// TestTable_ColorizesSeverityByBand pins D107's exact palette, one row per
// band, and checks the span is RESET-TERMINATED: code, then exactly the
// severity text formatSeverity itself would print, then ansiReset and
// nothing else in between. A version that colored the word but forgot the
// reset (or reset too early, leaving the score plain) would still pass a
// looser "contains the code somewhere" check; this does not.
func TestTable_ColorizesSeverityByBand(t *testing.T) {
	for _, tc := range []struct {
		name     string
		band     severity.Band
		score    float64
		wantCode string
	}{
		{"critical", severity.Critical, 9.8, ansiBoldRed},
		{"high", severity.High, 7.5, ansiRed},
		{"medium", severity.Medium, 5.0, ansiYellow},
		{"low", severity.Low, 2.0, ansiDim},
		{"unknown", severity.Unknown, 0, ansiDim},
		{"none", severity.None, 0, ansiDim},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := matcher.Result{Findings: []matcher.Finding{{
				Package:  pkgmeta.Package{Name: "pkg", Version: "1.0.0", Ecosystem: "Go"},
				Advisory: advisory.Advisory{ID: "GHSA-color-" + tc.name},
				Severity: tc.band,
				Score:    tc.score,
			}}}
			var buf bytes.Buffer
			if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}, true); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			wantSpan := tc.wantCode + formatSeverity(tc.band, tc.score) + ansiReset
			if !strings.Contains(out, wantSpan) {
				t.Errorf("output does not contain the reset-terminated %s span %q:\n%s", tc.name, wantSpan, out)
			}
		})
	}
}

// TestTable_ColorizeFalseNeverEmitsAnEscapeByte is the direct renderer-level
// counterpart to scancmd's TestRun_Colorize: every existing Table( ... ,
// false) call across this package's test suite already proves the default
// is byte-identical to pre-D107 output by construction (they were the
// original assertions, untouched); this pins the same claim as its own
// named test, for a caller that finds this file first.
func TestTable_ColorizeFalseNeverEmitsAnEscapeByte(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "pkg", Version: "1.0.0", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-color-off"},
		Severity: severity.Critical,
		Score:    9.8,
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}, false); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(buf.String(), '\x1b') {
		t.Errorf("colorize=false must never emit an ESC byte:\n%q", buf.String())
	}
}

// TestTable_FindingsCountIsBoldOnlyWhenNonZero: D107's own reasoning for
// why a zero count stays plain (table.go's comment beside wrapSGR's call
// site) — a bold "0 finding(s)" would draw the eye to the one line that
// most needs to read as unremarkable.
func TestTable_FindingsCountIsBoldOnlyWhenNonZero(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{{
		Package:  pkgmeta.Package{Name: "pkg", Version: "1.0.0", Ecosystem: "Go"},
		Advisory: advisory.Advisory{ID: "GHSA-count-bold"},
		Severity: severity.Low,
		Score:    2.0,
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}, true); err != nil {
		t.Fatal(err)
	}
	if want := ansiBold + "1 finding(s)" + ansiReset; !strings.Contains(buf.String(), want) {
		t.Errorf("output does not bold the finding count %q:\n%s", want, buf.String())
	}

	buf.Reset()
	if _, err := Table(&buf, matcher.Result{}, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), ansiBold) {
		t.Errorf("a clean scan's \"0 finding(s)\" must not be bolded:\n%s", buf.String())
	}
}

// TestTable_DimsSuppressedAndNotEvaluatedHeaders: the two "informational
// line" spans D107's brief names explicitly. Each header must be dimmed AND
// reset before the block's own per-entry detail lines, which stay plain —
// TestTable_SuppressedDetailLinesStayPlain, just below, is what proves that
// second half rather than assuming it.
func TestTable_DimsSuppressedAndNotEvaluatedHeaders(t *testing.T) {
	res := matcher.Result{Suppressed: []matcher.Suppressed{{
		Finding: matcher.Finding{
			Package:  pkgmeta.Package{Name: "pkg", Version: "1.0.0", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-suppressed"},
		},
		Reason: "false positive",
		Source: "ignore-file",
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}, true); err != nil {
		t.Fatal(err)
	}
	if want := ansiDim + "Suppressed (1), not counted toward the verdict:" + ansiReset; !strings.Contains(buf.String(), want) {
		t.Errorf("suppressed header not dimmed %q:\n%s", want, buf.String())
	}

	buf.Reset()
	if _, err := Table(&buf, matcher.Result{}, cyclonedx.Stats{
		Components: 3, Cataloged: 1, SkippedUnsupportedEcosystem: 2,
	}, EOLStatus{}, true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if want := ansiDim + "Not evaluated:" + ansiReset; !strings.Contains(out, want) {
		t.Errorf("not-evaluated header not dimmed %q:\n%s", want, out)
	}
	if want := ansiDim + "  2 package(s) in an unsupported ecosystem" + ansiReset; !strings.Contains(out, want) {
		t.Errorf("skipped-count line not dimmed %q:\n%s", want, out)
	}
}

// TestTable_SuppressedDetailLinesStayPlain: the per-suppression reason is
// exactly the text a reader is meant to read carefully (color.go's own
// comment beside the Suppressed header's wrapSGR call), so it must NOT be
// dimmed alongside the header above it — this is the negative half of
// TestTable_DimsSuppressedAndNotEvaluatedHeaders, checked separately so a
// change that (wrongly) dims the whole block turns THIS test red even
// though the header assertion above would still pass.
func TestTable_SuppressedDetailLinesStayPlain(t *testing.T) {
	res := matcher.Result{Suppressed: []matcher.Suppressed{{
		Finding: matcher.Finding{
			Package:  pkgmeta.Package{Name: "pkg", Version: "1.0.0", Ecosystem: "Go"},
			Advisory: advisory.Advisory{ID: "GHSA-suppressed-detail"},
		},
		Reason: "a reason worth reading",
		Source: "ignore-file",
	}}}
	var buf bytes.Buffer
	if _, err := Table(&buf, res, cyclonedx.Stats{Components: 1, Cataloged: 1}, EOLStatus{}, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "a reason worth reading") {
		t.Fatalf("suppressed detail line missing entirely:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), ansiDim+"  pkg") {
		t.Errorf("suppressed detail line must stay plain, not dimmed:\n%s", buf.String())
	}
}
