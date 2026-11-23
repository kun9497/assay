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
	"github.com/kun9497/assay/internal/version"
)

// QA 2026-11-20. GitHub reads severity from the rule, and the rule was the
// first finding's: a critical install of one package showed under the high
// band of another. Either order gives one rule.
func TestSARIF_ARuleIsBuiltFromEveryFindingThatSharesIt(t *testing.T) {
	f := func(v, fixed string, band severity.Band, score, epss float64, state advisory.FixState) matcher.Finding {
		return matcher.Finding{
			Package:  pkgmeta.Package{Name: "requests", Version: v, Ecosystem: "PyPI", PURL: "pkg:pypi/requests@" + v},
			Advisory: advisory.Advisory{ID: "CVE-2024-0001"}, Severity: band, Score: score,
			Evidence: version.Evidence{Introduced: "0", Fixed: fixed, FixState: state},
			Ratings:  []matcher.Rating{{Fixed: fixed, FixState: state, EPSS: epss, EPSSModel: "m", Database: "EPSS", Severity: band, Score: score}},
		}
	}
	high := f("1.0.0", "2.0.0", severity.High, 7.5, 0.9, advisory.FixStateFixed)
	crit := f("3.0.0", "", severity.Critical, 9.8, 0.1, advisory.FixStateWontFix)
	unrated := f("4.0.0", "5.0.0", severity.Unknown, 0, 0, advisory.FixStateFixed)
	var first string
	for n, res := range []matcher.Result{
		{Findings: []matcher.Finding{high, crit, unrated}},
		{Findings: []matcher.Finding{unrated, crit, high}},
		{Findings: []matcher.Finding{high, unrated}, Suppressed: []matcher.Suppressed{{Finding: crit, Reason: "r", Source: "vex"}}},
	} {
		var buf bytes.Buffer
		if _, err := SARIF(&buf, res, cyclonedx.Stats{Components: 3, Cataloged: 3}, nil, "t", "v", EOLStatus{}, Coverage{}); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Rules []struct {
							ID         string
							Help       struct{ Text string }
							Properties map[string]any
						}
					}
				}
			}
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		rules := doc.Runs[0].Tool.Driver.Rules
		if len(rules) == 0 || !strings.HasPrefix(rules[0].ID, "CVE-2024-0001") {
			t.Fatalf("rules = %+v", rules)
		}
		r := rules[0]
		if r.Properties["security-severity"] != "9.8" || r.Properties["unfixable"] != true || r.Properties["epss"] != 0.9 {
			t.Errorf("%d: properties %v, want 9.8, unfixable, epss 0.9", n, r.Properties)
		}
		if purls, _ := r.Properties["purls"].([]any); len(purls) != 3 {
			t.Errorf("%d: purls %v, want all three", n, purls)
		}
		for _, v := range []string{"1.0.0", "3.0.0", "4.0.0"} {
			if !strings.Contains(r.Help.Text, v) {
				t.Errorf("%d: help does not name %s:%s", n, v, r.Help.Text)
			}
		}
		b, _ := json.Marshal(r)
		if first == "" {
			first = string(b)
		}
		if string(b) != first {
			t.Errorf("%d: the rule depends on order:%s%s", n, string(rune(10)), b)
		}
	}
}

// The worst finding has a fix and another does not: the rule says so.
func TestSARIF_ARuleIsUnfixableWhenAnyOfItsFindingsIs(t *testing.T) {
	f := func(v, fixed string, score float64, state advisory.FixState) matcher.Finding {
		return matcher.Finding{
			Package: pkgmeta.Package{Name: "x", Version: v, Ecosystem: "PyPI"}, Advisory: advisory.Advisory{ID: "CVE-1"},
			Severity: severity.High, Score: score, Evidence: version.Evidence{Fixed: fixed, FixState: state},
			Ratings: []matcher.Rating{{Fixed: fixed, FixState: state}},
		}
	}
	r := groupRule("r", []matcher.Finding{f("1", "2", 8.9, advisory.FixStateFixed), f("3", "", 7.1, advisory.FixStateWontFix)})
	if r.Properties["unfixable"] != true || r.Properties["fixState"] != "wont-fix" || r.Properties["security-severity"] != "8.9" {
		t.Errorf("properties %v", r.Properties)
	}
}

// QA 2026-11-20: a finding seen only among the suppressed has its rule, and
// the CVE of one filed under another id reaches SARIF through its help.
func TestSARIF_ASuppressedOnlyFindingDeclaresItsRule(t *testing.T) {
	f := matcher.Finding{
		Package:     pkgmeta.Package{Name: "x", Version: "1", Ecosystem: "npm", PURL: "pkg:npm/x@1"},
		Advisory:    advisory.Advisory{ID: "GHSA-q", Aliases: []string{"CVE-2031-77"}},
		Identifiers: []string{"CVE-2031-77", "GHSA-q"}, Severity: severity.High, Score: 7,
		Ratings: []matcher.Rating{{Database: "GHSA", AdvisoryID: "GHSA-q"}, {Database: "NVD", AdvisoryID: "CVE-2031-77"}},
	}
	var buf bytes.Buffer
	if _, err := SARIF(&buf, matcher.Result{Suppressed: []matcher.Suppressed{{Finding: f, Reason: "r"}}},
		cyclonedx.Stats{Components: 1, Cataloged: 1}, nil, "t", "v", EOLStatus{}, Coverage{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Tool    struct{ Driver struct{ Rules []sarifRule } }
			Results []struct{ RuleID string }
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc.Runs[0]
	if len(run.Results) != 1 || len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != run.Results[0].RuleID {
		t.Fatalf("results %+v, rules %+v", run.Results, run.Tool.Driver.Rules)
	}
	r := run.Tool.Driver.Rules[0]
	for _, want := range []string{"Also known as: CVE-2031-77", "Sources:", "NVD CVE-2031-77"} {
		if !strings.Contains(r.Help.Text, want) {
			t.Errorf("help does not say %q:%s", want, r.Help.Text)
		}
	}
	if p, _ := r.Properties["purls"].([]any); len(p) != 1 || p[0] != "pkg:npm/x@1" {
		t.Errorf("purls %v", r.Properties["purls"])
	}
}
