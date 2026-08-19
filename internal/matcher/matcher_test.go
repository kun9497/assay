package matcher

import (
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/store"
)

// fakeStore keeps the matcher testable without a database.
type fakeStore struct {
	byKey map[string][]advisory.Advisory
	// covers models what the real store records (D20). When unset it is
	// derived from byKey, so a test that does not care about coverage gets the
	// honest answer for the data it supplied rather than an empty set that
	// would skip everything.
	covers []string
	// ratings is what RatingsFor serves, keyed by CVE (D27). Empty in every
	// fixture that predates it, which is the honest default: a database with
	// no NVD sync has no ratings.
	ratings     map[string][]advisory.Rating
	ratingCalls map[string]int
	// enrichment is what EnrichmentFor serves, keyed by CVE (D3), and
	// enrichmentCalls counts the asks exactly as ratingCalls does. Empty in
	// every fixture that predates it — a database built without KISA enabled
	// has no enrichment, and that is the ordinary case rather than a
	// degenerate one: the measured overlap is 2.4% of the corpus.
	enrichment      map[string][]advisory.Enrichment
	enrichmentCalls map[string]int
}

func (f fakeStore) Covers() (map[string]bool, error) {
	out := map[string]bool{}
	if f.covers != nil {
		for _, e := range f.covers {
			out[e] = true
		}
		return out, nil
	}
	for k := range f.byKey {
		eco, _, _ := strings.Cut(k, "\x00")
		out[eco] = true
	}
	return out, nil
}

func (f fakeStore) Lookup(ecosystem, name string) ([]advisory.Advisory, error) {
	// Normalizes like the real store does, so a test can hand the matcher a
	// raw (un-normalized) package name and still get a hit — matching the
	// contract Bolt.Lookup actually implements.
	return f.byKey[ecosystem+"\x00"+pkgmeta.NormalizeName(ecosystem, name)], nil
}
func (f fakeStore) Meta() (store.Meta, error) { return store.Meta{}, nil }
func (f fakeStore) Close() error              { return nil }

// RatingsFor serves the ratings a fixture supplied and counts the asks, so a
// test can pin that the matcher resolves one CVE once rather than once per
// identifier that happens to name it.
//
// A value receiver, like the rest of fakeStore. The counter still survives back
// to the test because a map is a reference type: incrementing through a copy of
// the struct writes to the same map. A fixture that does not want to count
// leaves ratingCalls nil, which the guard below skips - so an uncounted fixture
// is silent rather than a panic.
func (f fakeStore) RatingsFor(cve string) ([]advisory.Rating, error) {
	if f.ratingCalls != nil {
		f.ratingCalls[cve]++
	}
	return f.ratings[cve], nil
}

// EachRating exists only to satisfy store.Store -- nothing in the matcher's
// own tests walks the whole bucket, that is dbcmd.Update's job (the seeded
// `db build` path), not the matcher's. Sorted anyway, matching
// Bolt.EachRating's own key-order contract, so a fixture that DID depend on
// order would fail here rather than only in production.
func (f fakeStore) EachRating(fn func(advisory.Rating) error) error {
	cves := make([]string, 0, len(f.ratings))
	for cve := range f.ratings {
		cves = append(cves, cve)
	}
	sort.Strings(cves)
	for _, cve := range cves {
		for _, r := range f.ratings[cve] {
			if err := fn(r); err != nil {
				return err
			}
		}
	}
	return nil
}

// EnrichmentFor serves the enrichment a fixture supplied and counts the asks,
// mirroring RatingsFor above -- same value receiver, same reference-type
// counter, same nil-map guard so an uncounted fixture is silent rather than a
// panic.
//
// It deliberately does NOT sort what it returns, even though Bolt.EnrichmentFor
// does. The store's sort is per CVE; a finding carrying two enriched CVEs
// receives two independently-sorted answers and nothing about their
// concatenation is ordered, so the matcher owns that ordering and a fake that
// pre-sorted would hide whether it does it.
func (f fakeStore) EnrichmentFor(cve string) ([]advisory.Enrichment, error) {
	if f.enrichmentCalls != nil {
		f.enrichmentCalls[cve]++
	}
	return f.enrichment[cve], nil
}

// EachEnrichment exists only to satisfy store.Store -- nothing in the matcher
// walks the whole bucket, that is dbcmd's job. Sorted anyway, matching
// Bolt.EachEnrichment's key-order contract, for the reason EachRating gives.
func (f fakeStore) EachEnrichment(fn func(advisory.Enrichment) error) error {
	cves := make([]string, 0, len(f.enrichment))
	for cve := range f.enrichment {
		cves = append(cves, cve)
	}
	sort.Strings(cves)
	for _, cve := range cves {
		for _, e := range f.enrichment[cve] {
			if err := fn(e); err != nil {
				return err
			}
		}
	}
	return nil
}

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

// D30. An unreadable entry in an advisory's enumerated Versions list no longer
// fails the advisory — but the verdict it produces was reached over data that
// was not read, and CI must be told. This is the point where the guarantee
// could go quiet: AffectsVersion hands back the unreadable entries, and if the
// matcher drops them the scan reports a confident clean answer instead.
func TestMatch_UnreadableListedVersionStillReportsIncomplete(t *testing.T) {
	// "0.9-stable" is real PyPI advisory data (trac). The installed version is
	// perfectly readable and matches nothing here, so before D30 this package
	// came back unevaluable, and the risk after it is that it comes back
	// silently clean.
	adv := advisory.Advisory{
		ID:   "PYSEC-junk",
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{
			Ecosystem: "PyPI",
			Name:      "trac",
			Versions:  []string{"0.9-stable", "1.0"},
		}},
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{"PyPI\x00trac": {adv}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("trac", "3.0", "PyPI")},
	})
	if err != nil {
		t.Fatalf("Match error = %v, want nil: one bad listed version must not fail the scan", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %+v, want none: 3.0 is not listed", res.Findings)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1: a verdict reached over an unread entry is incomplete, and CI gates on this", len(res.Skipped))
	}
	// Assert the entry that could not be read, not merely that some text was
	// produced. The advisory ID and package name are both present in this
	// fixture, so a Reason that named only those would still be non-empty
	// while saying nothing about what went unread.
	if got := res.Skipped[0].Reason; !strings.Contains(got, `"0.9-stable"`) {
		t.Errorf("Skipped[0].Reason = %q, want it to name the entry that could not be read", got)
	}
	if got := res.Skipped[0].AdvisoryID; got != "PYSEC-junk" {
		t.Errorf("Skipped[0].AdvisoryID = %q, want PYSEC-junk: the skip belongs to the advisory it came from", got)
	}
}

// The companion to the test above: the same shape with a readable list must
// stay silent. Without this, a matcher that recorded a skip unconditionally
// would satisfy the assertions above and turn every enumerated advisory into
// an incomplete result.
func TestMatch_ReadableListedVersionsReportNoSkip(t *testing.T) {
	adv := advisory.Advisory{
		ID:   "PYSEC-clean",
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{
			Ecosystem: "PyPI",
			Name:      "trac",
			Versions:  []string{"0.9", "1.0"},
		}},
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{"PyPI\x00trac": {adv}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("trac", "3.0", "PyPI")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("Skipped = %+v, want none: every listed version here parses", res.Skipped)
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

// D8: the advisory names the source package; the installed package is a binary
// one. Nine of the fifteen packages in alpine:3.19 have an origin package that
// differs, including libssl3 and libcrypto3 both sourced from openssl. Losing
// this produces false NEGATIVES, which are silent.
func TestMatch_SourcePackageReachesTheAdvisory(t *testing.T) {
	adv := advWithRange("CVE-2024-openssl", "Alpine:v3.19", "openssl",
		"0", "3.1.4-r6", advisory.RangeEcosystem)
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Alpine:v3.19\x00openssl": {adv},
	}}

	p := pkg("libssl3", "3.1.4-r5", "Alpine:v3.19")
	p.Source = &pkgmeta.SourcePackage{Name: "openssl"}

	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1: an openssl advisory must reach libssl3 "+
			"through Package.Source; got %+v", len(res.Findings), res.Findings)
	}
	// Explainability (D10): "libssl3 is vulnerable" is not checkable without
	// naming the package the advisory was actually written against.
	if got := res.Findings[0].MatchedName; got != "openssl" {
		t.Errorf("MatchedName = %q, want %q", got, "openssl")
	}
}

// The binary name still matches when it is the one the advisory names, and
// MatchedName must then be the package's own name rather than empty.
func TestMatch_BinaryNameStillMatchesDirectly(t *testing.T) {
	adv := advWithRange("CVE-2024-busybox", "Alpine:v3.19", "busybox",
		"0", "1.36.1-r16", advisory.RangeEcosystem)
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Alpine:v3.19\x00busybox": {adv},
	}}

	p := pkg("busybox", "1.36.1-r15", "Alpine:v3.19")
	p.Source = &pkgmeta.SourcePackage{Name: "busybox"}

	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1: one advisory reached through two names "+
			"is still one finding; got %+v", len(res.Findings), res.Findings)
	}
	if got := res.Findings[0].MatchedName; got != "busybox" {
		t.Errorf("MatchedName = %q, want %q", got, "busybox")
	}
}

// An advisory reachable under BOTH names is one finding, not two.
func TestMatch_SourceAndBinaryNameDoNotDoubleReport(t *testing.T) {
	adv := advWithRange("CVE-2024-both", "Alpine:v3.19", "openssl",
		"0", "3.1.4-r6", advisory.RangeEcosystem)
	// The same advisory is reachable under the binary name too.
	adv.Affected = append(adv.Affected, advisory.Affected{
		Ecosystem: "Alpine:v3.19",
		Name:      "libssl3",
		Ranges:    adv.Affected[0].Ranges,
	})
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Alpine:v3.19\x00openssl": {adv},
		"Alpine:v3.19\x00libssl3": {adv},
	}}

	p := pkg("libssl3", "3.1.4-r5", "Alpine:v3.19")
	p.Source = &pkgmeta.SourcePackage{Name: "openssl"}

	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("Findings = %d, want 1: the same advisory reached under two "+
			"names is one finding; got %+v", len(res.Findings), res.Findings)
	}
}

// A source-named advisory must NOT match a package whose source is different,
// or D8 turns a false negative into a false positive.
func TestMatch_SourceNameDoesNotMatchAcrossPackages(t *testing.T) {
	adv := advWithRange("CVE-2024-openssl", "Alpine:v3.19", "openssl",
		"0", "3.1.4-r6", advisory.RangeEcosystem)
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Alpine:v3.19\x00openssl": {adv},
	}}

	p := pkg("busybox", "1.36.1-r15", "Alpine:v3.19")
	p.Source = &pkgmeta.SourcePackage{Name: "busybox"}

	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0: an openssl advisory must not reach "+
			"busybox; got %+v", len(res.Findings), res.Findings)
	}
}

// A package with no ecosystem — the distro had no OSV key — is reported as
// skipped with a reason, never folded into a clean verdict (D11).
func TestMatch_UnkeyablePackageIsSkippedNotClean(t *testing.T) {
	p := pkg("libssl3", "3.1.4-r5", "")
	res, err := New(fakeStore{}).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1", len(res.Skipped))
	}
	if res.Skipped[0].Reason == "" {
		t.Error("skip carries no reason; the count alone tells nobody what to fix")
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(res.Findings))
	}
}

// TestMatch_FindingIdentifiersIncludeUpstream drives Match(), not lookupIDs
// directly (D3: "read both aliases and upstream"). identifiers() -- the
// grouping key -- is deliberately upstream-blind
// (TestIdentifiers_ExcludesUpstream below), and every existing --explain /
// annotate test either hand-builds Finding.Identifiers or uses a fixture that
// already carries the CVE in Aliases, so nothing running Match ever checked
// that Finding.Identifiers itself carries Upstream. This fixture is
// Alpine-shaped on purpose: Aliases empty, the CVE only in Upstream, exactly
// the measured shape of all 4,405 real Alpine records. Losing Upstream here
// silently disconnects such a finding from the CVE that --explain's lookup,
// a `scan | grep CVE-…`, and NVD/KISA's own CVE join all depend on.
func TestMatch_FindingIdentifiersIncludeUpstream(t *testing.T) {
	a := advisory.Advisory{
		ID:       "ALPINE-CVE-2026-1",
		Kind:     advisory.KindVulnerability,
		Upstream: []string{"CVE-2026-1"}, // no Aliases at all -- Alpine's own shape
		Affected: []advisory.Affected{{
			Ecosystem: "Go",
			Name:      "github.com/foo/upstreamonly",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeSemver,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.5.0"}},
			}},
		}},
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00github.com/foo/upstreamonly": {a},
	}}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("github.com/foo/upstreamonly", "v1.2.3", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	var gotUpstream bool
	for _, id := range res.Findings[0].Identifiers {
		if id == "CVE-2026-1" {
			gotUpstream = true
		}
	}
	if !gotUpstream {
		t.Errorf("Identifiers = %v, want CVE-2026-1 from Upstream (D3) -- --explain and a "+
			"CVE-keyed grep both read this field", res.Findings[0].Identifiers)
	}
}

// D41's source-version comparison, driven through Match rather than only
// checked at the cataloger that populates Source (dpkgdb_test's "this is the
// version D41 compares"). Every existing matcher fixture sets Source with a
// Name only, so `compareVersion = p.Source.Version` never actually differed
// from `compareVersion = p.Version` in anything that ran Match --
// TestMatch_SourcePackageReachesTheAdvisory above leaves Source.Version
// empty, which takes the "same as the binary version" branch either way.
//
// This is the real bookworm shape D41's own comment names: bsdutils's
// installed BINARY carries an epoch a binNMU added (1:2.38.1-5+deb12u3)
// while the SOURCE package -- which is what OSV's Debian advisories are
// written against -- does not (2.38.1-5+deb12u2, still short of the fix).
// Comparing the binary version against the source-namespace bound sorts it
// ABOVE every fixed version on the epoch alone, regardless of the upstream
// release -- a silent false negative on the 13-15% of Debian packages whose
// binary and source versions diverge this way.
func TestMatch_IndirectLookupComparesTheSourceVersion(t *testing.T) {
	adv := advWithRange("DEBIAN-CVE-2026-1", "Debian:12", "util-linux",
		"0", "2.38.1-5+deb12u3", advisory.RangeEcosystem)
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Debian:12\x00util-linux": {adv},
	}}

	p := pkg("bsdutils", "1:2.38.1-5+deb12u3", "Debian:12")
	p.Source = &pkgmeta.SourcePackage{Name: "util-linux", Version: "2.38.1-5+deb12u2"}

	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1: the SOURCE version 2.38.1-5+deb12u2 is inside "+
			"[0, 2.38.1-5+deb12u3); comparing the BINARY version 1:2.38.1-5+deb12u3 "+
			"(a later binNMU's epoch) sorts it above the fix regardless of the upstream "+
			"release and misses this false negative; got %+v (skipped %+v)",
			len(res.Findings), res.Findings, res.Skipped)
	}
	if got := res.Findings[0].Advisory.ID; got != "DEBIAN-CVE-2026-1" {
		t.Errorf("Advisory.ID = %q, want DEBIAN-CVE-2026-1", got)
	}
}

// identifiers() feeds the dedup map, and it must NOT include Upstream. OSV
// defines upstream as "derived from", not "the same as", so collapsing on it
// suppresses a genuinely distinct advisory — a false negative, where an extra
// line is only noise. The distinction is easy to lose: D3 made upstream
// prominent for the report (which SHOULD show it), and "unify these two" is a
// plausible future edit. This is the tripwire for that edit.
func TestIdentifiers_ExcludesUpstream(t *testing.T) {
	a := advisory.Advisory{
		ID:       "ALPINE-CVE-2025-46394",
		Aliases:  []string{"GHSA-alias"},
		Upstream: []string{"CVE-2025-46394"},
	}
	for _, got := range identifiers(a) {
		if got == "CVE-2025-46394" {
			t.Fatalf("identifiers() returned the upstream ID %q. Dedup keyed on it "+
				"would suppress a distinct advisory that merely derives from the "+
				"same CVE. The report shows upstream (D3); identity must not.", got)
		}
	}
	// The ones it must carry, so the test cannot pass by returning nothing.
	want := map[string]bool{"ALPINE-CVE-2025-46394": true, "GHSA-alias": true}
	for _, got := range identifiers(a) {
		delete(want, got)
	}
	if len(want) != 0 {
		t.Errorf("identifiers() dropped %v", want)
	}
}

// D20: an ecosystem the database never ingested must be SKIPPED, not evaluated.
//
// This is the whole point. A lookup in an uningested ecosystem returns nothing,
// exactly like a lookup for a package with no advisories, and without the
// coverage check the matcher calls that clean. Measured before the fix: the
// same busybox at the same version, changing only the distro release from
// 3.19.9 to 3.25.0, went from one finding to "No known vulnerabilities found"
// at exit 0. The next Alpine minor release triggers it the day it ships.
func TestMatch_UncoveredEcosystemIsSkippedNotClean(t *testing.T) {
	adv := advWithRange("ALPINE-CVE-X", "Alpine:v3.19", "busybox",
		"0", "1.36.1-r21", advisory.RangeEcosystem)
	s := fakeStore{
		byKey:  map[string][]advisory.Advisory{"Alpine:v3.19\x00busybox": {adv}},
		covers: []string{"Alpine:v3.19"},
	}

	// Covered: the finding appears.
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("busybox", "1.36.1-r20", "Alpine:v3.19")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("covered release: Findings = %d, want 1", len(res.Findings))
	}

	// Uncovered: the same package, the same version, a release this database
	// has never held.
	res, err = New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("busybox", "1.36.1-r20", "Alpine:v3.25")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("uncovered release produced findings: %+v", res.Findings)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("uncovered release: Skipped = %d, want 1 — an ecosystem the "+
			"database never held is not an ecosystem with no vulnerabilities",
			len(res.Skipped))
	}
	// The reason has to name the gap, because the fix is `assay db update` and
	// nothing else in the output says so.
	if r := res.Skipped[0].Reason; !strings.Contains(r, "Alpine:v3.25") {
		t.Errorf("Skipped.Reason = %q, should name the ecosystem that is missing", r)
	}
	// A whole-package skip, so the report counts it as not evaluated and the
	// scan cannot read as clean (D11).
	if res.Skipped[0].AdvisoryID != "" {
		t.Errorf("Skipped.AdvisoryID = %q, want empty: the package was never "+
			"checked at all, not checked against one bad advisory",
			res.Skipped[0].AdvisoryID)
	}
}

// The coverage check must not fire for an ecosystem that IS held but happens to
// have no advisory for this package. That is a genuine clean result.
func TestMatch_CoveredEcosystemWithNoAdvisoryIsClean(t *testing.T) {
	s := fakeStore{
		byKey:  map[string][]advisory.Advisory{},
		covers: []string{"Alpine:v3.19"},
	}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("busybox", "1.36.1-r20", "Alpine:v3.19")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("Skipped = %+v, want none: the ecosystem was ingested and this "+
			"package simply has no advisories", res.Skipped)
	}
}

// A database that declares no coverage covers nothing, and every package must
// be skipped.
//
// This exists because the natural back-compat edit — `if len(covered) > 0 &&
// !covered[p.Ecosystem]`, "be lenient when we have no record" — restores the
// original defect wholesale and, without this test, leaves the suite green.
// An empty set is not missing information; it is the answer.
func TestMatch_DatabaseDeclaringNoCoverageSkipsEverything(t *testing.T) {
	adv := advWithRange("GHSA-x", "Go", "github.com/x/y", "0", "2.0.0", advisory.RangeSemver)
	s := fakeStore{
		byKey:  map[string][]advisory.Advisory{"Go\x00github.com/x/y": {adv}},
		covers: []string{}, // declared, and empty
	}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("github.com/x/y", "v1.0.0", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %+v; a database covering nothing cannot produce one", res.Findings)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1: an empty coverage set means nothing was "+
			"ingested, not that coverage is unknown", len(res.Skipped))
	}
}

// D13: severity is derived at match time from the advisory's own vectors, not
// read from a stored value. A record carrying several vectors takes the
// HIGHEST band — a finding is as severe as its worst rating, and taking the
// first OR the last vector would make the result depend on OSV's
// serialization order rather than on the vulnerability.
//
// Both orderings are exercised, not just one. A fixture ordered
// medium-then-critical only pins "don't just take the first" — a mutation
// that instead keeps only the LAST vector (`vectors[len(vectors)-1:]`, or
// equivalently `vectors[1:]` on a two-element slice) passes it by
// coincidence, because the last vector happens to already be the highest.
// The reversed fixture below makes the last vector the lower one, so that
// mutation is caught too.
func TestMatch_FindingCarriesTheHighestSeverity(t *testing.T) {
	adv := advWithRange("GHSA-sev", "Go", "x", "0", "2.0.0", advisory.RangeSemver)
	adv.Severity = []advisory.Severity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}, // medium, 6.5
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, // critical, 9.8
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Go\x00x": {adv}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("x", "1.0.0", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != severity.Critical || f.Score != 9.8 {
		t.Errorf("Severity/Score = %v/%.1f, want critical/9.8 — the finding must "+
			"take the worst of its several vectors, not the first", f.Severity, f.Score)
	}

	// Same two vectors, critical serialized FIRST this time and medium last.
	// A "keep only the last vector" mutation would pass the case above by
	// coincidence and only fail here.
	rev := advWithRange("GHSA-sev-rev", "Go", "w", "0", "2.0.0", advisory.RangeSemver)
	rev.Severity = []advisory.Severity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, // critical, 9.8
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}, // medium, 6.5
	}
	s2 := fakeStore{byKey: map[string][]advisory.Advisory{"Go\x00w": {rev}}}
	res2, err := New(s2).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("w", "1.0.0", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res2.Findings))
	}
	f2 := res2.Findings[0]
	if f2.Severity != severity.Critical || f2.Score != 9.8 {
		t.Errorf("Severity/Score = %v/%.1f, want critical/9.8 (vectors reversed) — "+
			"the finding must take the worst vector regardless of which end of the "+
			"slice it is serialized on", f2.Severity, f2.Score)
	}
}

// Half of all advisories carry no severity vector at all (D17). That must
// come out as Unknown, not as the zero value of Band, which is None — a real
// band meaning "rated zero". Coercing an absent rating to a low band is
// exactly the failure D17 exists to prevent.
func TestMatch_FindingWithNoSeverityVectorsIsUnknown(t *testing.T) {
	adv := advWithRange("GHSA-unrated", "Go", "y", "0", "2.0.0", advisory.RangeSemver)
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Go\x00y": {adv}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("y", "1.0.0", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if f := res.Findings[0]; f.Severity != severity.Unknown || f.Score != 0 {
		t.Errorf("Severity/Score = %v/%.1f, want unknown/0.0", f.Severity, f.Score)
	}
}

// D17 again, but the common real shape: a record that DOES carry a severity
// entry, just not one severity.Of can score — a bare CVSS_V2 vector, which
// severity.Of does not understand (it dispatches on "CVSS:3." / "CVSS:4."
// prefixes only). The zero-entries case above never exercises this path, and
// it is the one that matters most: a coercion bug here is invisible, because
// None sits inside the --fail-on ordering and is not counted by
// Summary.UnknownSeverity, so --fail-on-unknown would not see it either.
func TestMatch_UnscorableSeverityVectorIsUnknownNotNone(t *testing.T) {
	adv := advWithRange("GHSA-v2only", "Go", "z", "0", "2.0.0", advisory.RangeSemver)
	adv.Severity = []advisory.Severity{
		{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
	}
	s := fakeStore{byKey: map[string][]advisory.Advisory{"Go\x00z": {adv}}}

	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("z", "1.0.0", "Go")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if f := res.Findings[0]; f.Severity != severity.Unknown || f.Score != 0 {
		t.Errorf("Severity/Score = %v/%.1f, want unknown/0.0 — a PRESENT but "+
			"unscorable vector must not be coerced to none", f.Severity, f.Score)
	}
}

// D36. The cause has to be set from the error's own classification, not
// guessed. Both directions run through the real comparer, so the mapping is
// exercised end to end rather than against a hand-built error.
func TestMatch_SkipCauseSeparatesAdvisoryFromTarget(t *testing.T) {
	// The bound is malformed; the installed version is fine.
	badBound := advWithRange("GHSA-badbound", "Go", "x", "0", "not-a-version", advisory.RangeSemver)
	// The installed version is malformed; the bounds are fine.
	goodBound := advWithRange("GHSA-goodbound", "Go", "y", "0", "2.0.0", advisory.RangeSemver)

	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Go\x00x": {badBound},
		"Go\x00y": {goodBound},
	}}
	res, err := New(s).Match(pkgmeta.Target{Packages: []pkgmeta.Package{
		pkg("x", "1.0.0", "Go"),
		pkg("y", "not-a-version", "Go"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]SkipCause{}
	for _, s := range res.Skipped {
		got[s.Package.Name] = s.Cause
	}
	if got["x"] != SkipAdvisory {
		t.Errorf("x (malformed bound, good version) cause = %q, want %q", got["x"], SkipAdvisory)
	}
	if got["y"] != SkipTarget {
		t.Errorf("y (good bound, malformed version) cause = %q, want %q", got["y"], SkipTarget)
	}
	// The two must not collapse: a mapping that returned one constant would
	// satisfy either check alone.
	if got["x"] == got["y"] {
		t.Errorf("both skips reported cause %q; the distinction is the whole feature", got["x"])
	}
}

// An ecosystem this database does not cover is neither party's malformed data,
// and must not be reported as the caller's — otherwise `--fail-on-incomplete=
// target` fires on a stale database, which is exactly the false alarm D36
// exists to remove.
func TestMatch_UncoveredEcosystemIsCoverageNotTarget(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{}, covers: []string{"Go"}}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("requests", "2.0.0", "PyPI")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %d, want 1", len(res.Skipped))
	}
	if got := res.Skipped[0].Cause; got != SkipCoverage {
		t.Errorf("cause = %q, want %q", got, SkipCoverage)
	}
}

// D52: Red Hat's CSAF VEX feed distinguishes "the vendor has decided never to
// fix this" from "no fix yet". Finding.FixState is the strongest claim across
// every source's rating, wont-fix outranking not-fixed outranking unknown.
//
// Both orderings of {not-fixed, wont-fix} sit in the same table rather than
// one apiece. A single ordering cannot tell a real precedence rule from
// "whichever rating happened to be last" — the exact defect D25 already
// forbids for ties elsewhere in this package, and FixState answers to the
// same rule.
func TestFinding_FixState_Precedence(t *testing.T) {
	tests := []struct {
		name    string
		ratings []Rating
		want    advisory.FixState
	}{
		{
			name: "wont-fix listed before not-fixed",
			ratings: []Rating{
				{Database: "REDHAT", FixState: advisory.FixStateWontFix},
				{Database: "OSV", FixState: advisory.FixStateNotFixed},
			},
			want: advisory.FixStateWontFix,
		},
		{
			// Same two ratings, reversed. An implementation that just kept the
			// last state it saw would pass the row above and flip on this one.
			name: "not-fixed listed before wont-fix",
			ratings: []Rating{
				{Database: "OSV", FixState: advisory.FixStateNotFixed},
				{Database: "REDHAT", FixState: advisory.FixStateWontFix},
			},
			want: advisory.FixStateWontFix,
		},
		{
			name: "not-fixed outranks unknown",
			ratings: []Rating{
				{Database: "OSV", FixState: advisory.FixStateNotFixed},
				{Database: "GHSA", FixState: advisory.FixStateUnknown},
			},
			want: advisory.FixStateNotFixed,
		},
		{
			name: "unknown and unknown stays unknown",
			ratings: []Rating{
				{Database: "OSV", FixState: advisory.FixStateUnknown},
				{Database: "GHSA", FixState: advisory.FixStateUnknown},
			},
			want: advisory.FixStateUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Every rating here carries no Fixed version, so Unfixable() is
			// true and FixState() actually has to walk Ratings rather than
			// short-circuit on the guard the next test covers.
			f := Finding{Ratings: tt.ratings}
			if got := f.FixState(); got != tt.want {
				t.Errorf("FixState() = %q, want %q", got, tt.want)
			}
		})
	}
}

// A rating naming a fixed version makes the finding Fixed outright, without
// consulting any rating's FixState — including its own. Built with the fixed
// rating BESIDE a wont-fix one, so an implementation that let a wont-fix
// sibling outvote a real fix is caught rather than passing on a fixture where
// there was nothing to outvote.
func TestFinding_FixState_FixedRatingWinsOverWontFixSibling(t *testing.T) {
	f := Finding{Ratings: []Rating{
		{Database: "GHSA", Fixed: "2.0.0", FixState: advisory.FixStateFixed},
		{Database: "REDHAT", FixState: advisory.FixStateWontFix},
	}}
	if got := f.FixState(); got != advisory.FixStateFixed {
		t.Errorf("FixState() = %q, want %q: a rating with a fixed version must "+
			"win outright, not be outvoted by an unfixable sibling", got, advisory.FixStateFixed)
	}
}

// Finding.Ratings' own doc says a Finding built by hand — tests included —
// must populate it explicitly, and nothing stops that hand-built Rating from
// leaving FixState at its Go zero value. That zero value must resolve to the
// named Unknown state, not surface as a distinct, unnamed fourth value the
// way the store's own empty spelling would if nothing resolved it (advisory.
// FixState.String documents the store's side of the same rule).
func TestFinding_FixState_ZeroValueRatingIsUnknown(t *testing.T) {
	f := Finding{Ratings: []Rating{{Database: "OSV", FixState: ""}}}
	// Compared and printed as the raw underlying string, not through
	// FixState.String(): that method resolves "" to "unknown" for every
	// caller, which would make a leaked empty string print identically to a
	// correct result and hide the exact bug this test exists to catch.
	if got := f.FixState(); string(got) != string(advisory.FixStateUnknown) {
		t.Errorf("FixState() = %q (raw %q), want %q", got, string(got), advisory.FixStateUnknown)
	}
	// advisory.FixStateUnknown must itself be the non-empty word, or this test
	// would pass by asserting "" == "" and prove nothing about resolution.
	if advisory.FixStateUnknown == "" {
		t.Fatal("advisory.FixStateUnknown is the empty string; this test cannot tell resolution from silence")
	}
}

// advWithFixState builds an advisory whose range carries NO fixed event — the
// only shape a Range is allowed to store a FixState on (D52's own doc on
// advisory.Range.FixState) — unlike advWithRange, which always adds one. It
// exists so a fixture can pin the Range -> version.Evidence -> matcher.Rating
// wiring instead of the ordinary "has a fix" path advWithRange already covers.
func advWithFixState(id, eco, name, introduced string, fs advisory.FixState, rt advisory.RangeType) advisory.Advisory {
	return advisory.Advisory{
		ID:   id,
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{
			Ecosystem: eco,
			Name:      name,
			Ranges: []advisory.Range{{
				Type:     rt,
				Events:   []advisory.Event{{Introduced: introduced}},
				FixState: fs,
			}},
		}},
	}
}

// This is the only test in the package that drives FixState through the real
// Match path rather than building a Finding by hand — everything above stops
// at Finding.FixState() itself. Deleting `ev.FixState = r.FixState` in
// version.InRange, or the assignment in matcher.fixStateOf, leaves every
// other FixState test in this file green because they never call Match.
func TestMatch_FixStateFlowsFromRangeThroughToRating(t *testing.T) {
	// A fix-less range carrying Red Hat's own "the vendor will not fix this"
	// statement (D52) — the shape only Red Hat's CSAF VEX feed produces today.
	wontFix := advWithFixState("RHSA-wontfix", "Red Hat:9", "openssl", "0",
		advisory.FixStateWontFix, advisory.RangeEcosystem)
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		"Red Hat:9\x00openssl": {wontFix},
	}}
	res, err := New(s).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("openssl", "1.0.0-1.el9", "Red Hat:9")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if got := res.Findings[0].Ratings[0].FixState; got != advisory.FixStateWontFix {
		t.Errorf("Rating.FixState = %q, want %q: the range's stored state must "+
			"reach the rating unchanged", got, advisory.FixStateWontFix)
	}

	// A range that HAS a fixed event is fixed by construction whatever it
	// stores — fixStateOf's whole reason for existing — with the installed
	// version sitting below that fix.
	fixed := advWithRange("RHSA-fixed", "Red Hat:9", "curl", "0", "8.0.0-1.el9", advisory.RangeEcosystem)
	s2 := fakeStore{byKey: map[string][]advisory.Advisory{
		"Red Hat:9\x00curl": {fixed},
	}}
	res2, err := New(s2).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{pkg("curl", "7.0.0-1.el9", "Red Hat:9")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res2.Findings))
	}
	if got := res2.Findings[0].Ratings[0].FixState; got != advisory.FixStateFixed {
		t.Errorf("Rating.FixState = %q, want %q", got, advisory.FixStateFixed)
	}
}
