package matcher

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
)

// fakeStore keeps the matcher testable without a database.
type fakeStore struct {
	byKey map[string][]advisory.Advisory
}

func (f fakeStore) Lookup(ecosystem, name string) ([]advisory.Advisory, error) {
	return f.byKey[ecosystem+"\x00"+name], nil
}
func (f fakeStore) LookupBySource(ecosystem, name string) ([]advisory.Advisory, error) {
	return nil, nil
}
func (f fakeStore) Meta() (store.Meta, error) { return store.Meta{}, nil }
func (f fakeStore) Close() error              { return nil }

func advWithRange(id, eco, name, introduced, fixed string, rt advisory.RangeType) advisory.Advisory {
	return advisory.Advisory{
		ID:   id,
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      name,
			Ranges: []advisory.Range{{
				Type: rt,
				Events: []advisory.Event{
					{Introduced: introduced},
					{Fixed: fixed},
				},
			}},
		}},
	}
}

func pkg(name, version, eco string) pkgmeta.Package {
	return pkgmeta.Package{Name: name, Version: version, Ecosystem: eco}
}

func TestMatch_Hit(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00github.com/foo/bar": {
			advWithRange("GHSA-hit", "Go", "github.com/foo/bar", "0", "1.5.0", advisory.RangeSemver),
		},
	}}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("github.com/foo/bar", "v1.2.3", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Advisory.ID != "GHSA-hit" {
		t.Errorf("Advisory.ID = %q", f.Advisory.ID)
	}
	// Evidence must explain the match, not merely assert it (D10).
	if f.Evidence.Fixed != "1.5.0" {
		t.Errorf("Evidence.Fixed = %q, want 1.5.0", f.Evidence.Fixed)
	}
	if !strings.Contains(f.Evidence.Reason, "1.5.0") {
		t.Errorf("Evidence.Reason = %q, should name the boundary that decided it", f.Evidence.Reason)
	}
}

func TestMatch_Miss(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00github.com/foo/bar": {
			advWithRange("GHSA-fixed", "Go", "github.com/foo/bar", "0", "1.5.0", advisory.RangeSemver),
		},
	}}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("github.com/foo/bar", "v1.5.0", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %+v, want none: the fixed version is not affected", res.Findings)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("Skipped = %+v, want none: a clean miss is not a skip", res.Skipped)
	}
}

func TestMatch_UnparseableVersionIsSkippedNotClean(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00github.com/foo/bar": {
			advWithRange("GHSA-x", "Go", "github.com/foo/bar", "0", "1.5.0", advisory.RangeSemver),
		},
	}}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("github.com/foo/bar", "not-a-version", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %+v, want none", res.Findings)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1: an unparseable version must surface, not vanish", len(res.Skipped))
	}
	if res.Skipped[0].Reason == "" {
		t.Error("Skipped.Reason is empty")
	}
}

func TestMatch_FindingOnOneVersionDoesNotEraseSkipOnAnother(t *testing.T) {
	// Two installed versions of the same package. One matches; the other
	// cannot be evaluated. Identifying packages by name alone would let the
	// first one's finding suppress the second one's skip, reporting an
	// unevaluated package as clean. Nested node_modules produce this shape
	// routinely.
	broken := advWithRange("GHSA-broken", "npm", "lodash", "0", "not-a-version", advisory.RangeSemver)
	old := advWithRange("GHSA-old", "npm", "lodash", "0", "4.17.21", advisory.RangeSemver)
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"npm\x00lodash": {old, broken},
	}}
	target := pkgmeta.Target{Packages: []pkgmeta.Package{
		pkg("lodash", "4.17.20", "npm"), // inside old's range
		pkg("lodash", "4.17.21", "npm"), // at the fix, so only broken applies
	}}

	res, err := New(s).Match(target)
	if err != nil {
		t.Fatal(err)
	}
	var skippedFor2021 bool
	for _, sk := range res.Skipped {
		if sk.Package.Version == "4.17.21" {
			skippedFor2021 = true
		}
	}
	if !skippedFor2021 {
		t.Errorf("4.17.21 could not be evaluated but produced no Skipped entry; got %+v", res.Skipped)
	}

	// Reversing the input must not change the outcome.
	target.Packages[0], target.Packages[1] = target.Packages[1], target.Packages[0]
	rev, err := New(s).Match(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(rev.Skipped) != len(res.Skipped) || len(rev.Findings) != len(res.Findings) {
		t.Errorf("result depends on package order: %d/%d vs %d/%d",
			len(res.Findings), len(res.Skipped), len(rev.Findings), len(rev.Skipped))
	}
}

func TestMatch_UnevaluableAdvisorySurvivesAlongsideAFinding(t *testing.T) {
	// One package, two advisories: one matches, one has a malformed bound. The
	// user must learn about both. The unevaluated one may carry the higher
	// severity or a higher fix floor, which would make the remediation shown
	// next to the visible finding wrong.
	hit := advWithRange("GHSA-hit", "Go", "x", "0", "2.0.0", advisory.RangeSemver)
	bad := advWithRange("GHSA-unevaluable", "Go", "x", "0", "not-a-version", advisory.RangeSemver)
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Go\x00x": {hit, bad}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("x", "1.0.0", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Advisory.ID != "GHSA-hit" {
		t.Errorf("Findings = %+v, want one GHSA-hit", res.Findings)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %+v, want one entry for GHSA-unevaluable", res.Skipped)
	}
	if res.Skipped[0].AdvisoryID != "GHSA-unevaluable" {
		t.Errorf("Skipped.AdvisoryID = %q, want GHSA-unevaluable — a reason that does not "+
			"name the advisory leaves the user nothing to investigate", res.Skipped[0].AdvisoryID)
	}
}

func TestMatch_UnsupportedEcosystemIsSkipped(t *testing.T) {
	res, err := New(fakeStore{}).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("apache2", "2.4.54-r0", "Alpine:v3.19")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1", len(res.Skipped))
	}
	if !strings.Contains(res.Skipped[0].Reason, "Alpine:v3.19") {
		t.Errorf("Skipped.Reason = %q, should name the ecosystem", res.Skipped[0].Reason)
	}
}

func TestMatch_DeduplicatesAdvisoryPerPackage(t *testing.T) {
	// The same advisory can be reachable more than once. One package plus one
	// advisory is one finding.
	a := advWithRange("GHSA-dupe", "Go", "x", "0", "2.0.0", advisory.RangeSemver)
	a.Affected = append(a.Affected, a.Affected[0])
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Go\x00x": {a, a}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("x", "1.0.0", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("Findings = %d, want 1", len(res.Findings))
	}
}

func TestMatch_Deterministic(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00b": {advWithRange("GHSA-2", "Go", "b", "0", "9.0.0", advisory.RangeSemver)},
		"Go\x00a": {advWithRange("GHSA-1", "Go", "a", "0", "9.0.0", advisory.RangeSemver)},
	}}
	target := pkgmeta.Target{Packages: []pkgmeta.Package{
		pkg("b", "1.0.0", "Go"), pkg("a", "1.0.0", "Go"),
	}}
	first, err := New(s).Match(target)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(s).Match(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2", len(first.Findings))
	}
	for i := range first.Findings {
		if first.Findings[i].Advisory.ID != second.Findings[i].Advisory.ID {
			t.Fatal("Match is not deterministic across runs")
		}
	}
	if first.Findings[0].Package.Name != "a" {
		t.Errorf("Findings[0].Package = %q, want a (sorted)", first.Findings[0].Package.Name)
	}
}
