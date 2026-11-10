package matcher

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// A package a cataloger marked Unevaluable is one target-cause skip with that
// reason, and no advisory is judged for it -- even one it would match.
func TestMatch_UnevaluablePackageIsOneTargetSkip(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00x": {advWithRange("GHSA-hit", "Go", "x", "0", "2.0.0", advisory.RangeSemver)},
	}}
	p := pkg("x", "1.0.0", "Go")
	p.Unevaluable = "contradictory source versions"
	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v, want none: the package was not judged", res.Findings)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Cause != SkipTarget || res.Skipped[0].Reason != "contradictory source versions" || res.Skipped[0].AdvisoryID != "" {
		t.Errorf("skipped = %+v, want one whole-package target skip with the reason", res.Skipped)
	}
}

// A package whose ecosystem the database does not cover stays a coverage
// skip -- with its remedy -- even when its listings also contradicted each
// other: --fail-on-incomplete=target must not blame the caller for a
// package the database could never judge (D36).
func TestMatch_UnevaluableInAnUncoveredEcosystemIsACoverageSkip(t *testing.T) {
	s := fakeStore{covers: []string{"Go"}}
	p := pkg("x", "1.0.0", "npm")
	p.Unevaluable = "contradictory source versions"
	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Cause != SkipCoverage {
		t.Errorf("skipped = %+v, want one coverage skip", res.Skipped)
	}
}
