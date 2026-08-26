package matcher

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
)

// Two databases routinely describe one vulnerability and disagree about it:
// 8,893 of 19,715 measured CVE groups carry more than one record, and in 5,693
// of those the sources land on different severity bands. These tests pin what a
// finding does with that (D25).

const (
	vecCritical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // 9.8
	vecMedium   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" // 6.5
)

// key mirrors fakeStore's own composite key. Built with string(rune(0)) rather
// than written as an escape sequence: a literal NUL typed into a file has
// three times on this branch become the byte it was meant to denote, once
// costing a compile error inside the comment warning about the other two
// (CLAUDE.md).
func key(eco, name string) string { return eco + string(rune(0)) + name }

// The live shape, simplified: both records describe CVE-2022-28347 in Django
// 3.2.x, GHSA carrying a CVSS vector and PYSEC carrying none.
//
// Linked here only through the CVE they both alias, which is weaker than the
// real records — those cross-alias each other, checked against OSV:
//
//	GHSA-w24h-v9qh-8gxj  aliases [BIT-django-2022-28347 CVE-2022-28347 PYSEC-2022-191]
//	PYSEC-2022-191       aliases [BIT-django-2022-28347 CVE-2022-28347 GHSA-w24h-v9qh-8gxj]
//
// The weaker link is deliberate. Naming each other is the easy case; sharing
// only a CVE is what a KISA record and a GHSA record will have in common, and
// it is the case the old code missed entirely — keyed on the record's own ID,
// it produced two findings for one vulnerability. Testing the shape that
// already worked would have left that unpinned.
func ghsaRec() advisory.Advisory {
	a := advWithRange("GHSA-w24h-v9qh-8gxj", "PyPI", "django", "0", "3.2.13",
		advisory.RangeEcosystem)
	a.Database = "GHSA"
	a.Aliases = []string{"CVE-2022-28347"}
	a.Severity = []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}}
	return a
}

func pysecRec() advisory.Advisory {
	a := advWithRange("PYSEC-2022-191", "PyPI", "django", "0", "3.2.13",
		advisory.RangeEcosystem)
	a.Database = "PYSEC"
	a.Aliases = []string{"CVE-2022-28347"}
	// No Severity at all — this is what PYSEC records look like, and it is the
	// whole reason the aggregate matters.
	return a
}

// twoSources holds one vulnerability twice, in the order given.
func twoSources(first, second advisory.Advisory) fakeStore {
	return fakeStore{byKey: map[string][]advisory.Advisory{
		key("PyPI", "django"): {first, second},
	}}
}

func djangoTarget() pkgmeta.Target {
	return pkgmeta.Target{Packages: []pkgmeta.Package{pkg("django", "3.2.12", "PyPI")}}
}

// The measured case: two records, one vulnerability, different bands. Both are
// kept, and the finding is as severe as the worst of them.
func TestMatch_KeepsEverySourcesRating(t *testing.T) {
	res, err := New(twoSources(ghsaRec(), pysecRec())).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 — the two records are one vulnerability", len(res.Findings))
	}
	f := res.Findings[0]
	if len(f.Ratings) != 2 {
		t.Fatalf("got %d ratings, want 2: %+v", len(f.Ratings), f.Ratings)
	}
	if f.Severity != severity.Critical {
		t.Errorf("Severity = %v, want critical — the highest across sources", f.Severity)
	}
	got := map[string]severity.Band{}
	for _, r := range f.Ratings {
		got[r.Database] = r.Severity
	}
	if got["GHSA"] != severity.Critical {
		t.Errorf("GHSA rating = %v, want critical", got["GHSA"])
	}
	if got["PYSEC"] != severity.Unknown {
		t.Errorf("PYSEC rating = %v, want unknown — that record carries no vector", got["PYSEC"])
	}
}

// The ordering dependency this change exists to remove. The same two records
// are fed in BOTH orders and the finding must come out identical — every part
// of it, not just the verdict, because the report prints the advisory ID, the
// summary and the fixed version off Advisory and Evidence.
func TestMatch_AFindingDoesNotDependOnRecordOrder(t *testing.T) {
	forward, err := New(twoSources(ghsaRec(), pysecRec())).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := New(twoSources(pysecRec(), ghsaRec())).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(forward.Findings) != 1 || len(reversed.Findings) != 1 {
		t.Fatalf("findings: forward %d, reversed %d", len(forward.Findings), len(reversed.Findings))
	}
	a, b := forward.Findings[0], reversed.Findings[0]
	if a.Severity != b.Severity {
		t.Errorf("Severity depends on record order: %v vs %v", a.Severity, b.Severity)
	}
	// Compared as rendered strings so a failure names the difference rather
	// than reporting "not deeply equal".
	if fmt.Sprint(a.Ratings) != fmt.Sprint(b.Ratings) {
		t.Errorf("Ratings depend on record order:\n  forward  %v\n  reversed %v", a.Ratings, b.Ratings)
	}
	if a.Advisory.ID != b.Advisory.ID {
		t.Errorf("the displayed advisory depends on record order: %s vs %s",
			a.Advisory.ID, b.Advisory.ID)
	}
	if a.Evidence != b.Evidence {
		t.Errorf("Evidence depends on record order: %+v vs %+v", a.Evidence, b.Evidence)
	}
}

// Which record is displayed is the one that set the band, so the report agrees
// with itself: it says critical, and the advisory it shows is the one saying
// so. Asserted on the ID, because the ID is what the table, the JSON and
// --explain all print.
func TestMatch_TheDisplayedRecordIsTheOneThatSetTheBand(t *testing.T) {
	for _, order := range []struct {
		name          string
		first, second advisory.Advisory
	}{
		{"rated record first", ghsaRec(), pysecRec()},
		{"unrated record first", pysecRec(), ghsaRec()},
	} {
		t.Run(order.name, func(t *testing.T) {
			res, err := New(twoSources(order.first, order.second)).Match(djangoTarget())
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(res.Findings))
			}
			f := res.Findings[0]
			if f.Advisory.ID != "GHSA-w24h-v9qh-8gxj" {
				t.Errorf("displayed advisory = %s, want the GHSA record — it is the "+
					"one that rated this critical", f.Advisory.ID)
			}
			if f.Advisory.Database != "GHSA" {
				t.Errorf("displayed Database = %q, want GHSA", f.Advisory.Database)
			}
		})
	}
}

// Two sources that BOTH rated it, differently. This is the plain reading of
// "the finding is as severe as its worst rating", and every other test here
// pairs a rated source with an unrated one — which the unrated branch of
// beats() answers before the scores are ever compared. Without this the score
// comparison could be inverted and nothing would notice.
func TestMatch_TheHigherOfTwoRatedSourcesWins(t *testing.T) {
	medium := ghsaRec()
	medium.Severity = []advisory.Severity{{Type: "CVSS_V3", Score: vecMedium}}
	high := pysecRec()
	high.Severity = []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}}

	for _, order := range []struct {
		name          string
		first, second advisory.Advisory
	}{
		{"lower first", medium, high},
		{"higher first", high, medium},
	} {
		t.Run(order.name, func(t *testing.T) {
			res, err := New(twoSources(order.first, order.second)).Match(djangoTarget())
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(res.Findings))
			}
			f := res.Findings[0]
			if f.Severity != severity.Critical || f.Score != 9.8 {
				t.Errorf("Severity/Score = %v/%.1f, want critical/9.8 — the worse of "+
					"the two ratings", f.Severity, f.Score)
			}
			// The record that rated it critical is PYSEC here, which also sorts
			// LAST among the ratings. A displayed record taken from the front of
			// the sorted list would show the medium one instead.
			if f.Advisory.ID != "PYSEC-2022-191" {
				t.Errorf("displayed advisory = %s, want PYSEC-2022-191 — it is the "+
					"record that rated this critical", f.Advisory.ID)
			}
			var got []string
			for _, r := range f.Ratings {
				got = append(got, fmt.Sprintf("%s=%v", r.Database, r.Severity))
			}
			want := []string{"GHSA=medium", "PYSEC=critical"}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("ratings = %v, want %v — each source keeps its own band",
					got, want)
			}
		})
	}
}

// D17 through the aggregate: a source that rated nothing must not pull a rated
// finding down. unknown is outside the ordering, not below it — so the
// aggregate of {critical, unknown} is critical, not unknown and not none.
func TestMatch_AnUnratedSourceDoesNotDiluteARatedOne(t *testing.T) {
	res, err := New(twoSources(ghsaRec(), pysecRec())).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != severity.Critical {
		t.Fatalf("Severity = %v, want critical", f.Severity)
	}
	if f.Score != 9.8 {
		t.Errorf("Score = %.1f, want 9.8 — the score of the band that won", f.Score)
	}
}

// ...and a vulnerability every source left unrated is still unknown, never
// coerced into a band (D17).
func TestMatch_AllSourcesUnratedIsUnknown(t *testing.T) {
	a, b := pysecRec(), pysecRec()
	b.ID, b.Database = "GO-2022-0999", "GO"
	res, err := New(twoSources(a, b)).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	if f.Severity != severity.Unknown {
		t.Errorf("Severity = %v, want unknown — no source rated it", f.Severity)
	}
	if f.Score != 0 {
		t.Errorf("Score = %.1f, want 0", f.Score)
	}
	if len(f.Ratings) != 2 {
		t.Errorf("got %d ratings, want 2 — both sources are still recorded", len(f.Ratings))
	}
	// Nothing separates these two on severity, so the displayed record comes
	// down to the tiebreak. Without one it would be whichever the store listed
	// first, which is the defect in miniature.
	if f.Advisory.ID != "GO-2022-0999" {
		t.Errorf("displayed advisory = %s, want GO-2022-0999 — with both sources "+
			"unrated the tie breaks on database name, and GO sorts before PYSEC",
			f.Advisory.ID)
	}
}

// Two records from ONE database, equally unrated, differing only in their ID.
// Every earlier tiebreak has run out, so this is the last one — and without it
// the winner is whichever record the index happened to list first.
func TestMatch_TwoRecordsFromOneDatabaseBreakTheTieOnID(t *testing.T) {
	lo, hi := pysecRec(), pysecRec()
	lo.ID, hi.ID = "PYSEC-2022-101", "PYSEC-2022-999"
	for _, order := range []struct {
		name          string
		first, second advisory.Advisory
	}{
		{"lower id first", lo, hi},
		{"higher id first", hi, lo},
	} {
		t.Run(order.name, func(t *testing.T) {
			res, err := New(twoSources(order.first, order.second)).Match(djangoTarget())
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(res.Findings))
			}
			f := res.Findings[0]
			if f.Advisory.ID != "PYSEC-2022-101" {
				t.Errorf("displayed advisory = %s, want PYSEC-2022-101", f.Advisory.ID)
			}
			var ids []string
			for _, r := range f.Ratings {
				ids = append(ids, r.AdvisoryID)
			}
			want := []string{"PYSEC-2022-101", "PYSEC-2022-999"}
			if fmt.Sprint(ids) != fmt.Sprint(want) {
				t.Errorf("rating order = %v, want %v — one database, so the sort "+
					"falls through to the advisory ID", ids, want)
			}
		})
	}
}

// Three records where the third names identifiers from two groups that were
// built separately. Merging them is what keeps the FINDING COUNT independent
// of arrival order: joining the first group and leaving the second standing
// gives two findings one way round and one the other.
func TestMatch_ARecordLinkingTwoGroupsMergesThem(t *testing.T) {
	mk := func(id, database, alias string) advisory.Advisory {
		a := advWithRange(id, "PyPI", "django", "0", "3.2.13", advisory.RangeEcosystem)
		a.Database, a.Aliases = database, []string{alias}
		return a
	}
	a := mk("GHSA-aaaa", "GHSA", "CVE-2022-0001")
	b := mk("PYSEC-2022-2", "PYSEC", "CVE-2022-0002")
	c := mk("GO-2022-0003", "GO", "CVE-2022-0001")
	c.Aliases = []string{"CVE-2022-0001", "CVE-2022-0002"}
	// The band lives on the record in the group that gets ABSORBED when the
	// linking record arrives last. A merge that keeps the surviving group's
	// winner would report this critical vulnerability as unrated.
	b.Severity = []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}}

	// d reaches the merged finding only through an identifier that belonged to
	// the ABSORBED group. That is what exercises absorb's repointing loop:
	// without it the group map still points PYSEC-2022-2 at the emptied entry,
	// d lands there, and the finding count goes back to depending on arrival
	// order. BIT- records alias sibling IDs like this routinely.
	d := mk("BIT-django-1", "BIT", "PYSEC-2022-2")

	for _, order := range []struct {
		name string
		recs []advisory.Advisory
	}{
		{"linking record last", []advisory.Advisory{a, b, c, d}},
		{"linking record first", []advisory.Advisory{c, a, b, d}},
		{"linking record between", []advisory.Advisory{a, c, b, d}},
		{"absorbed group's id arrives after the merge", []advisory.Advisory{a, b, c, d}},
		{"absorbed group's id arrives before it", []advisory.Advisory{a, b, d, c}},
	} {
		t.Run(order.name, func(t *testing.T) {
			s := fakeStore{byKey: map[string][]advisory.Advisory{
				key("PyPI", "django"): order.recs,
			}}
			res, err := New(s).Match(djangoTarget())
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) != 1 {
				t.Fatalf("got %d findings, want 1 — the linking record names both "+
					"of the others' CVEs and the fourth names an identifier from "+
					"the group that got absorbed, so all four are one vulnerability",
					len(res.Findings))
			}
			var ids []string
			for _, r := range res.Findings[0].Ratings {
				ids = append(ids, r.AdvisoryID)
			}
			want := []string{"BIT-django-1", "GHSA-aaaa", "GO-2022-0003", "PYSEC-2022-2"}
			if fmt.Sprint(ids) != fmt.Sprint(want) {
				t.Errorf("ratings = %v, want %v", ids, want)
			}
			f := res.Findings[0]
			if f.Severity != severity.Critical {
				t.Errorf("Severity = %v, want critical — the only rated record is "+
					"in the group that gets absorbed", f.Severity)
			}
			if f.Advisory.ID != "PYSEC-2022-2" {
				t.Errorf("displayed advisory = %s, want PYSEC-2022-2 — merging must "+
					"carry the absorbed group's winner across, not keep its own",
					f.Advisory.ID)
			}
		})
	}
}

// A single-source finding still has exactly one rating. Ratings is never empty,
// so no renderer has to special-case its absence — an empty slice would make
// "no source said anything" indistinguishable from "we dropped them".
func TestMatch_ASingleSourceStillProducesOneRating(t *testing.T) {
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		key("PyPI", "django"): {ghsaRec()},
	}}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	if len(f.Ratings) != 1 {
		t.Fatalf("got %d ratings, want 1: %+v", len(f.Ratings), f.Ratings)
	}
	if f.Ratings[0].Database != "GHSA" || f.Ratings[0].AdvisoryID != "GHSA-w24h-v9qh-8gxj" {
		t.Errorf("rating = %+v, want it attributed to the record it came from", f.Ratings[0])
	}
}

// Ratings are sorted. The point of this change is to stop depending on
// incidental ordering; emitting them in whatever order the index listed would
// reintroduce exactly that, one layer up, in the output instead of the verdict.
func TestMatch_RatingsAreSorted(t *testing.T) {
	goRec := pysecRec()
	goRec.ID, goRec.Database = "GO-2022-0001", "GO"
	s := fakeStore{byKey: map[string][]advisory.Advisory{
		// Deliberately not in sorted order.
		key("PyPI", "django"): {pysecRec(), goRec, ghsaRec()},
	}}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range res.Findings[0].Ratings {
		got = append(got, r.Database)
	}
	want := []string{"GHSA", "GO", "PYSEC"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("rating order = %v, want %v", got, want)
	}
}

// Each rating carries the fixed version its OWN record gives, because a
// source's remediation belongs to that source. Taking it from the winning
// record would make every source appear to agree.
//
// Sources agreeing on the fixed version is in fact the common case — 2,210 of
// 8,893 measured multi-record groups differ, and Django's fifteen agree
// unanimously — which is exactly why this needs a test. The field is right by
// construction on almost every real finding, so a version that read it off the
// winner would look correct nearly everywhere.
func TestMatch_EachRatingCarriesItsOwnFixedVersion(t *testing.T) {
	late := pysecRec()
	late.Affected[0].Ranges[0].Events[1].Fixed = "3.2.14"
	res, err := New(twoSources(ghsaRec(), late)).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	fixes := map[string]string{}
	for _, r := range res.Findings[0].Ratings {
		fixes[r.Database] = r.Fixed
	}
	if fixes["GHSA"] != "3.2.13" || fixes["PYSEC"] != "3.2.14" {
		t.Errorf("fixed versions = %v, want GHSA 3.2.13 and PYSEC 3.2.14 — each "+
			"rating reports what its own record says", fixes)
	}
}

// nvdRating is the shape an NVD sync leaves in the store: a CVE and a vector,
// with no package, no range and no fixed version. That absence is the whole
// reason D27 narrows what a finding may display.
func nvdRating(cve, vector string) advisory.Rating {
	return advisory.Rating{
		CVE:      cve,
		Source:   "NVD",
		Severity: []advisory.Severity{{Type: "CVSS_V3", Score: vector}},
		URL:      "https://nvd.nist.gov/vuln/detail/" + cve,
	}
}

// The case D27 exists for. Every OSV source left this unrated, so today it
// reports unknown and trips no threshold at all - scanning assay's own binary,
// --fail-on low exits 0 on exactly this shape. NVD rated it.
func TestMatch_AnNVDRatingRaisesAnOtherwiseUnratedFinding(t *testing.T) {
	s := twoSources(pysecRec(), pysecRec()) // neither carries a vector
	s.ratings = map[string][]advisory.Rating{
		"CVE-2022-28347": {nvdRating("CVE-2022-28347", vecCritical)},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Severity != severity.Critical || f.Score != 9.8 {
		t.Errorf("Severity/Score = %v/%.1f, want critical/9.8 - NVD rated what no "+
			"OSV source did", f.Severity, f.Score)
	}
	got := map[string]severity.Band{}
	for _, r := range f.Ratings {
		got[r.Database] = r.Severity
	}
	if got["NVD"] != severity.Critical {
		t.Errorf("ratings = %v, want NVD among them at critical", got)
	}
	if got["PYSEC"] != severity.Unknown {
		t.Errorf("PYSEC rating = %v, want unknown - NVD's score is NVD's, and "+
			"attaching it to a source that said nothing would invent agreement",
			got["PYSEC"])
	}
	// Sorted, including the annotation. Annotations are appended after the OSV
	// ratings, so sortRatings has to run AFTER annotate - and nothing else
	// would notice if it moved back above: "NVD" sorts before "PYSEC", the
	// JSON renderer documents that it relies on this order, and the golden
	// file would change without any test naming why.
	var order []string
	for _, r := range f.Ratings {
		order = append(order, r.Database)
	}
	// One PYSEC, not two: twoSources hands the same record twice and seen[a.ID]
	// collapses it, which is the dedup working rather than a fixture mistake.
	if fmt.Sprint(order) != fmt.Sprint([]string{"NVD", "PYSEC"}) {
		t.Errorf("rating order = %v, want [NVD PYSEC] - sorted after the "+
			"annotation is attached, not before", order)
	}
	// What an annotation carries, and what it must not. NIST was asked what a
	// CVE is worth, not which version fixes this package: a Fixed taken from
	// the finding's own evidence would have the report claim NIST published a
	// remediation it never published, which is the defect D27 exists to avoid.
	var nvd Rating
	for _, r := range f.Ratings {
		if r.Database == "NVD" {
			nvd = r
		}
	}
	if nvd.Fixed != "" {
		t.Errorf("the NVD rating carries Fixed=%q; NIST published no remediation "+
			"for this package and the report must not say it did", nvd.Fixed)
	}
	if nvd.AdvisoryID != "CVE-2022-28347" {
		t.Errorf("AdvisoryID = %q, want the CVE - an annotation has no advisory "+
			"of its own to name", nvd.AdvisoryID)
	}
	if nvd.URL == "" {
		t.Error("the NVD rating carries no URL, so the breakdown asserts what NIST " +
			"says and offers nowhere to check it")
	}
}

// TestMatch_ARatedNVDAnnotationIsNotMarkedNoSeverityOpinion pins the
// direction of NoSeverityOpinion: it marks an ANNOTATION that expressed no
// severity opinion (D86: EPSS/KEV rows), not one that did. Both an NVD row
// and an EPSS row are attached the same way, through annotate()'s single
// loop over RatingsFor — nvdRating's vector gives annotate() a real Severity
// slice, so len(r.Severity) == 0 is false there, while the EPSS row carries
// none. report.sourcesDisagree treats NoSeverityOpinion=true as "skip this
// row when comparing bands", so marking the RATED NVD row as opinionless
// too would silently hide it from the disagreement check it exists to feed.
// No test before this one reads NoSeverityOpinion at all:
// TestMatch_AnNVDRatingRaisesAnOtherwiseUnratedFinding above checks
// Severity, Score, Fixed and URL on the same NVD rating but never this
// field, and epsskev_test.go's only assertion is that EPSS/KEV rows ARE
// marked — true either way under this mutation, since it can only turn a
// false into a true, never the reverse.
func TestMatch_ARatedNVDAnnotationIsNotMarkedNoSeverityOpinion(t *testing.T) {
	s := twoSources(pysecRec(), pysecRec())
	s.ratings = map[string][]advisory.Rating{
		"CVE-2022-28347": {
			nvdRating("CVE-2022-28347", vecCritical),
			{CVE: "CVE-2022-28347", Source: "EPSS", EPSS: 0.94432, EPSSModel: "v-test"},
		},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	var nvd, epss Rating
	for _, r := range res.Findings[0].Ratings {
		switch r.Database {
		case "NVD":
			nvd = r
		case "EPSS":
			epss = r
		}
	}
	if nvd.NoSeverityOpinion {
		t.Errorf("NVD rating has NoSeverityOpinion = true, want false — it carries a real "+
			"CVSS vector (%s) and must count in report.sourcesDisagree's band comparison", vecCritical)
	}
	if !epss.NoSeverityOpinion {
		t.Errorf("EPSS rating has NoSeverityOpinion = false, want true — it carries no " +
			"severity vector at all, the actual case the field exists to mark")
	}
}

// ...and it is never the displayed record, however high it scores. An NVD
// rating carries no Evidence, no matched range and no fixed version, because
// the match came from OSV and NIST was only asked for a score. Displaying it
// would put an advisory on screen with nothing behind it, against goal #1.
func TestMatch_AnNVDRatingIsNeverTheDisplayedRecord(t *testing.T) {
	s := twoSources(pysecRec(), pysecRec())
	s.ratings = map[string][]advisory.Rating{
		"CVE-2022-28347": {nvdRating("CVE-2022-28347", vecCritical)},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	if !strings.HasPrefix(f.Advisory.ID, "PYSEC-") {
		t.Errorf("displayed advisory = %q, want the matched PYSEC record", f.Advisory.ID)
	}
	// The evidence of the record we actually compared against has to survive.
	// Asserted on the value, not on non-emptiness: an NVD rating supplies no
	// fixed version at all, so "not empty" would pass on anything.
	if f.Evidence.Fixed != "3.2.13" {
		t.Errorf("Evidence.Fixed = %q, want 3.2.13 from the matched record - the "+
			"finding must keep the evidence of what it compared", f.Evidence.Fixed)
	}
	if f.MatchedName != "django" {
		t.Errorf("MatchedName = %q, want django", f.MatchedName)
	}
}

// D17 in both directions, through the new source: NVD rating an unrelated CVE
// changes nothing, and NVD rating nothing at all leaves a rated finding alone.
func TestMatch_AnNVDRatingForAnotherCVEChangesNothing(t *testing.T) {
	with := twoSources(ghsaRec(), pysecRec())
	with.ratings = map[string][]advisory.Rating{
		"CVE-9999-9999": {nvdRating("CVE-9999-9999", vecCritical)},
	}
	a, err := New(with).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(twoSources(ghsaRec(), pysecRec())).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(a.Findings) != fmt.Sprint(b.Findings) {
		t.Errorf("a rating for an unrelated CVE changed the finding:\n  %v\n  %v",
			a.Findings, b.Findings)
	}
}

// One CVE, asked once - not once per identifier that names it. A finding
// commonly carries the same CVE in both aliases and upstream (D3), and on a
// real scan this is a store read per finding, not per alias.
func TestMatch_ACVEIsResolvedOnceNotPerIdentifier(t *testing.T) {
	// One record carrying the aliases a real GHSA record carries - the header
	// of this file records the measured set for this very CVE:
	// [BIT-django-2022-28347 CVE-2022-28347 PYSEC-2022-191]. So Identifiers
	// holds four names of which exactly one is a CVE, which is what the filter
	// below has to act on.
	//
	// Two records linked only through upstream would NOT have worked here:
	// grouping deliberately excludes upstream (see identifiers), so they stay
	// two findings and each looks the CVE up once - correct behaviour, wrong
	// fixture for this property.
	rec := ghsaRec()
	rec.Aliases = []string{"BIT-django-2022-28347", "CVE-2022-28347", "PYSEC-2022-191"}
	s := fakeStore{
		byKey:       map[string][]advisory.Advisory{key("PyPI", "django"): {rec}},
		ratings:     map[string][]advisory.Rating{"CVE-2022-28347": {nvdRating("CVE-2022-28347", vecMedium)}},
		ratingCalls: map[string]int{},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range res.Findings[0].Ratings {
		if r.Database == "NVD" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("NVD appears %d times in Ratings, want 1", n)
	}
	if s.ratingCalls["CVE-2022-28347"] != 1 {
		t.Errorf("the store was asked about one CVE %d times, want 1",
			s.ratingCalls["CVE-2022-28347"])
	}
	// ...and nothing that is not a CVE was looked up at all. Counting only the
	// CVE's own calls leaves the filter unheld: dropping it keeps that count at
	// 1 while adding a store read for every GHSA, PYSEC and BIT identifier the
	// finding carries. Identical results, several times the reads, and no test
	// would notice.
	for id, n := range s.ratingCalls {
		if !strings.HasPrefix(id, "CVE-") {
			t.Errorf("the store was asked about %q (%d times) - only CVE "+
				"identifiers reach a rating source", id, n)
		}
	}
	if len(s.ratingCalls) != 1 {
		t.Errorf("looked up %d identifiers, want 1 - the finding carries several "+
			"(its own id plus three aliases), and exactly one is a CVE: %v",
			len(s.ratingCalls), s.ratingCalls)
	}
}

// A rating that scores nothing must not displace one that does, and must not
// make a rated finding look unrated (D17). NVD carrying an unscorable vector
// is the shape that tests it.
func TestMatch_AnUnscorableNVDRatingDoesNotDiluteARatedFinding(t *testing.T) {
	s := twoSources(ghsaRec(), pysecRec()) // GHSA is critical
	s.ratings = map[string][]advisory.Rating{
		"CVE-2022-28347": {nvdRating("CVE-2022-28347", "not-a-vector")},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	if f.Severity != severity.Critical {
		t.Errorf("Severity = %v, want critical - a source that scored nothing must "+
			"not pull a rated finding down", f.Severity)
	}
	if f.Advisory.ID != "GHSA-w24h-v9qh-8gxj" {
		t.Errorf("displayed advisory = %s, want the GHSA record", f.Advisory.ID)
	}
}

// The invariant D25 established and D27 must not break: a finding is as severe
// as its worst rating, counting the annotated ones. Asserted across a mixed set
// rather than on one pair, because the annotation path updates Severity through
// a different branch than the OSV join does and the two must agree.
func TestMatch_SeverityIsTheHighestAcrossEveryRatingIncludingAnnotations(t *testing.T) {
	medium := ghsaRec()
	medium.Severity = []advisory.Severity{{Type: "CVSS_V3", Score: vecMedium}}
	s := twoSources(medium, pysecRec()) // medium + unrated
	s.ratings = map[string][]advisory.Rating{
		"CVE-2022-28347": {nvdRating("CVE-2022-28347", vecCritical)},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[0]
	var best severity.Band
	var bestScore float64
	for _, r := range f.Ratings {
		if r.Severity != severity.Unknown && r.Score > bestScore {
			best, bestScore = r.Severity, r.Score
		}
	}
	if f.Severity != best || f.Score != bestScore {
		t.Errorf("Severity/Score = %v/%.1f, but the highest rating is %v/%.1f: %+v",
			f.Severity, f.Score, best, bestScore, f.Ratings)
	}
	if f.Severity != severity.Critical {
		t.Errorf("Severity = %v, want critical from the NVD annotation", f.Severity)
	}
}

// A store failure while annotating fails the scan. Reporting a finding whose
// band is lower than the data would have made it is the silent wrong answer
// this project exists to avoid, and it would look exactly like a clean result.
func TestMatch_ARatingStoreErrorFailsTheScan(t *testing.T) {
	s := failingRatings{fakeStore: twoSources(ghsaRec(), pysecRec())}
	if _, err := New(s).Match(djangoTarget()); err == nil {
		t.Fatal("Match returned nil error when the rating store failed - a finding " +
			"rated lower than the data allows must not read as a clean result")
	}
}

// failingRatings answers every rating lookup with an error, so the scan's
// handling of a broken store is exercised without a broken store.
type failingRatings struct{ fakeStore }

func (failingRatings) RatingsFor(string) ([]advisory.Rating, error) {
	return nil, errors.New("ratings bucket unreadable")
}
