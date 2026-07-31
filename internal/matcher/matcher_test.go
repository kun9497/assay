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
	// Normalizes like the real store does, so a test can hand the matcher a
	// raw (un-normalized) package name and still get a hit — matching the
	// contract Bolt.Lookup actually implements.
	return f.byKey[ecosystem+"\x00"+pkgmeta.NormalizeName(ecosystem, name)], nil
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

func TestMatch_SkipsAreDeduplicatedPerAdvisory(t *testing.T) {
	// One advisory carrying two Affected entries for the same package, both
	// with malformed bounds. Measured across real data, 145 of 313 Django
	// records repeat affected entries for one package, so this shape is
	// routine rather than pathological — and a skip per entry would bury the
	// rest of the report in identical lines.
	bad := advWithRange("GHSA-twice", "Go", "x", "0", "not-a-version", advisory.RangeSemver)
	bad.Affected = append(bad.Affected, bad.Affected[0])
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Go\x00x": {bad, bad}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("x", "1.0.0", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 {
		t.Errorf("Skipped = %d entries, want 1 per (package, advisory); got %+v",
			len(res.Skipped), res.Skipped)
	}
}

func TestMatch_AliasedAdvisoriesReportOnce(t *testing.T) {
	// OSV's Go ecosystem carries the same vulnerability under both a GHSA and
	// a GO- identifier, each declaring the other as an alias. Reporting both
	// doubled every Go finding in a real scan against grype without adding any
	// information.
	ghsa := advWithRange("GHSA-c3h9-896r-86jm", "Go", "github.com/gogo/protobuf",
		"0", "1.3.2", advisory.RangeSemver)
	ghsa.Aliases = []string{"GO-2021-0053"}
	go1 := advWithRange("GO-2021-0053", "Go", "github.com/gogo/protobuf",
		"0", "1.3.2", advisory.RangeSemver)
	go1.Aliases = []string{"GHSA-c3h9-896r-86jm"}
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00github.com/gogo/protobuf": {ghsa, go1},
	}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("github.com/gogo/protobuf", "v1.3.1", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("Findings = %d, want 1: the two records are the same vulnerability; got %+v",
			len(res.Findings), res.Findings)
	}

	// A second package must still get its own finding for the same advisory:
	// the dedup is per package, not scan-wide. Built as its own value rather
	// than by mutating ghsa, because a struct copied into a map before its
	// fields are reassigned keeps the old ones — a trap that made an earlier
	// version of this test unpassable regardless of the implementation.
	shared := advisory.Advisory{
		ID:      "GHSA-shared",
		Aliases: []string{"GO-shared"},
		Kind:    advisory.KindVulnerability,
		Affected: []advisory.Affected{
			{Ecosystem: "Go", Name: "a", Ranges: ghsa.Affected[0].Ranges},
			{Ecosystem: "Go", Name: "b", Ranges: ghsa.Affected[0].Ranges},
		},
	}
	s2 := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00a": {shared},
		"Go\x00b": {shared},
	}}
	res2, err := New(s2).Match(pkgmeta.Target{Packages: []pkgmeta.Package{
		pkg("a", "1.0.0", "Go"), pkg("b", "1.0.0", "Go"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Findings) != 2 {
		t.Errorf("Findings = %d, want 2: dedup must be per package, not scan-wide", len(res2.Findings))
	}
}

func TestMatch_ForeignEcosystemEntryNeverReachesTheComparer(t *testing.T) {
	// Records are now stored whole, so one advisory can carry entries for
	// several ecosystems and a PyPI lookup can return a record holding npm
	// ranges. Feeding an npm version string to the PEP 440 comparer would be a
	// wrong answer, not an error. Convert used to strip these; the guard now
	// lives here, so the test does too.
	mixed := advisory.Advisory{
		ID:   "GHSA-mixed",
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{
			// Fixed high enough that the installed 3.2 falls INSIDE this range
			// under PEP 440. An npm-shaped bound that merely fails to match would
			// leave the test green with the guard deleted — and v1.16.3 does not
			// fail: this repo's PEP 440 grammar begins with v?, so Compare("3.2",
			// "v1.16.3") is a clean 1 and the entry is silently judged unaffected.
			{Ecosystem: "npm", Name: "django", Ranges: []advisory.Range{{
				Type:   advisory.RangeSemver,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "9.0.0"}},
			}}},
			{Ecosystem: "PyPI", Name: "django", Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "3.2.1"}},
			}}},
		},
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{"PyPI\x00django": {mixed}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("django", "3.2", "PyPI")},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1 from the PyPI entry only; got %+v",
			len(res.Findings), res.Findings)
	}
	// This is the assertion that kills the guard: with the ecosystem filter
	// removed the npm entry is reached first, matches, and breaks out with its
	// own fixed version.
	if f := res.Findings[0].Evidence.Fixed; f != "3.2.1" {
		t.Errorf("Evidence.Fixed = %q, want 3.2.1 — a foreign entry decided this finding", f)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("Skipped = %+v, want none: a foreign entry is filtered, not skipped", res.Skipped)
	}
}

func TestMatch_PyPINameIsNormalizedBeforeFiltering(t *testing.T) {
	// syft emits pkg:pypi/Jinja2 while OSV stores jinja2. The store hands back
	// the advisory either way, so the last thing that can drop it is the
	// matcher's own affected filter — this fails if that filter stops
	// normalizing, which no other test covers.
	// The advisory name is deliberately NOT already normalized and the package
	// name is spelled differently again. The filter normalizes both sides, so a
	// fixture that pre-normalized either one would leave that half a no-op and
	// mutate green.
	adv := advWithRange("GHSA-zope", "PyPI", "Zope.Interface", "0", "5.5.0", advisory.RangeEcosystem)
	s := fakeStore{byKey: map[string][]advisory.Advisory{"PyPI\x00zope-interface": {adv}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("Zope_Interface", "5.4.0", "PyPI")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1: every PEP 503 spelling names one package, "+
			"and the filter must normalize BOTH sides; got %+v", len(res.Findings), res.Findings)
	}
}

func TestMatch_UnsupportedEcosystemIsSkipped(t *testing.T) {
	// Debian, not Alpine: Alpine gained a comparer in slice 2a, and an example
	// that quietly becomes supported stops testing what it claims to. Debian is
	// a recorded deferral, so it stays unsupported until someone decides
	// otherwise — and if they do, this test is where they will find out it needs
	// a new example.
	res, err := New(fakeStore{}).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("openssl", "3.0.11-1~deb12u2", "Debian:12")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1", len(res.Skipped))
	}
	if !strings.Contains(res.Skipped[0].Reason, "Debian:12") {
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
