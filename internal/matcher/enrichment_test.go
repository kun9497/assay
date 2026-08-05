package matcher

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
)

// KISA describes a vulnerability in Korean prose and joins to a finding on the
// CVE alone (D3). These tests pin what a finding does with that, and — far more
// importantly — what it must not do: an enrichment record carries no band, no
// ecosystem and no package name, so nothing derived from one may reach a
// verdict.

// The three payload fields carry deliberately non-nesting tokens. Korean text,
// CVE IDs and a URL containing the notice id all sit in the same record here,
// and this repository has repeatedly been bitten by an assertion that passed
// from a neighbouring column: no value below is a substring of any other, and
// none of them contains a CVE ID, so an assertion about the title cannot be
// satisfied by the summary, the link, or the identifier the join used.
const (
	kisaTitle   = "제목-오픈소스-라이브러리-보안-업데이트-권고"
	kisaSummary = "개요-원격에서-임의의-코드를-실행할-수-있는-결함이-발견되었습니다"
	kisaURL     = "https://knvd.krcert.or.kr/info/vuln/notice/detail?id=99887"
)

// kisaNotice is the shape a KISA sync leaves in the store: a CVE, Korean prose
// and a link, with no severity, no ecosystem and no package name. That absence
// is the whole of D3 — there is nothing in this record a band could be derived
// from even by a mistake.
func kisaNotice(cve string) advisory.Enrichment {
	return advisory.Enrichment{
		CVE:     cve,
		Source:  "KISA",
		Title:   kisaTitle,
		Summary: kisaSummary,
		URL:     kisaURL,
	}
}

// Enrichment attaches on the CVE, exactly as ratings do — and through an ALIAS
// rather than the record's own ID, which is the only link a KISA record and a
// GHSA one will ever have (D3). The matched record here is GHSA-w24h-v9qh-8gxj
// and the notice is filed under CVE-2022-28347.
func TestMatch_AttachesEnrichmentByCVE(t *testing.T) {
	s := twoSources(ghsaRec(), pysecRec())
	s.enrichment = map[string][]advisory.Enrichment{
		"CVE-2022-28347": {kisaNotice("CVE-2022-28347")},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if len(f.Enrichment) != 1 {
		t.Fatalf("got %d enrichment records, want 1: %+v", len(f.Enrichment), f.Enrichment)
	}
	// Every field, exactly. Asserting only that something attached would leave
	// Summary unheld — and Summary is one of the three things this feature
	// exists to deliver.
	want := Enrichment{Source: "KISA", Title: kisaTitle, Summary: kisaSummary, URL: kisaURL}
	if f.Enrichment[0] != want {
		t.Errorf("Enrichment[0] = %+v, want %+v", f.Enrichment[0], want)
	}
	// ...and the finding is otherwise exactly what it was without any of this.
	if f.Severity != severity.Critical || f.Score != 9.8 {
		t.Errorf("Severity/Score = %v/%.1f, want critical/9.8 — enrichment carries no "+
			"band and must not have touched this", f.Severity, f.Score)
	}
	if len(f.Ratings) != 2 {
		t.Errorf("got %d ratings, want 2 — enrichment is not a rating and must not "+
			"appear among them: %+v", len(f.Ratings), f.Ratings)
	}
	if f.Advisory.ID != "GHSA-w24h-v9qh-8gxj" {
		t.Errorf("displayed advisory = %s, want the GHSA record — a notice with no "+
			"package name can never be the record a finding displays", f.Advisory.ID)
	}
}

// A notice about some other CVE attaches nothing. Without this, "enrichment
// attaches" would be satisfied by attaching every notice in the database to
// every finding.
func TestMatch_EnrichmentForAnotherCVEIsNotAttached(t *testing.T) {
	s := twoSources(ghsaRec(), pysecRec())
	s.enrichment = map[string][]advisory.Enrichment{
		"CVE-9999-9999": {kisaNotice("CVE-9999-9999")},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Findings[0].Enrichment); n != 0 {
		t.Errorf("got %d enrichment records on a finding whose CVE nothing enriched, "+
			"want 0: %+v", n, res.Findings[0].Enrichment)
	}
}

// verdictFixture builds one store and one target rich enough that "the two runs
// agree" is a real claim: a critical multi-source finding, an unrated
// single-source finding, an advisory that cannot be evaluated at all
// (advisory-scoped skip) and a package in an ecosystem with no comparer
// (whole-package skip). Every quantity a gate reads — the band, the score, the
// finding count, the skip counts and their kinds — has something to disagree
// about.
//
// withEnrichment is the ONLY difference between the two stores this returns.
// Enrichment lands on both the rated and the unrated finding, because the
// unrated one is precisely where an enrichment that could set a band would show
// up: it is the finding whose band nothing else has claimed.
func verdictFixture(withEnrichment bool) (fakeStore, pkgmeta.Target) {
	unrated := advWithRange("GHSA-unrated", "PyPI", "flask", "0", "2.0.0",
		advisory.RangeEcosystem)
	unrated.Database = "GHSA"
	unrated.Aliases = []string{"CVE-2024-0001"}

	// A fixed bound no comparer can parse, so this package is evaluated and one
	// advisory against it is not — the advisory-scoped skip.
	broken := advWithRange("GHSA-broken", "PyPI", "broken", "0", "not-a-version",
		advisory.RangeEcosystem)
	broken.Database = "GHSA"

	s := fakeStore{byKey: map[string][]advisory.Advisory{
		key("PyPI", "django"): {ghsaRec(), pysecRec()},
		key("PyPI", "flask"):  {unrated},
		key("PyPI", "broken"): {broken},
	}}
	if withEnrichment {
		s.enrichment = map[string][]advisory.Enrichment{
			"CVE-2022-28347": {kisaNotice("CVE-2022-28347")},
			"CVE-2024-0001":  {kisaNotice("CVE-2024-0001")},
		}
	}
	target := pkgmeta.Target{Packages: []pkgmeta.Package{
		pkg("django", "3.2.12", "PyPI"),
		pkg("flask", "1.0.0", "PyPI"),
		pkg("broken", "1.0.0", "PyPI"),
		// No comparer for this ecosystem, so the whole package is skipped.
		pkg("ghost", "1.0.0", "bogus"),
	}}
	return s, target
}

// TestMatch_EnrichmentChangesNoVerdict is the property this task exists to
// hold (D3). The same target is matched against two stores differing ONLY in
// enrichment, and the two results are compared with Enrichment zeroed on both
// sides: every other field of every finding, every skip, and every quantity a
// --fail-on gate reads must be identical.
//
// Zeroing rather than ignoring particular fields is deliberate. A comparison
// listing the fields it checks silently stops covering anything Finding gains
// later; this one covers whatever the type holds, and only ever excuses the one
// field enrichment is allowed to write.
//
// The exit-code half of the same property is held end to end, through a real
// database and a real scan, by TestRun_EnrichmentChangesNoVerdict in
// internal/scancmd — this package cannot import report or scancmd without a
// cycle, so the summary counts are re-derived here from the findings instead.
func TestMatch_EnrichmentChangesNoVerdict(t *testing.T) {
	withStore, target := verdictFixture(true)
	withoutStore, _ := verdictFixture(false)

	with, err := New(withStore).Match(target)
	if err != nil {
		t.Fatal(err)
	}
	without, err := New(withoutStore).Match(target)
	if err != nil {
		t.Fatal(err)
	}

	// The test is worthless unless the enriched run actually gained something:
	// two runs that both attached nothing agree trivially, and this whole
	// comparison would pass with the feature deleted. Asserted first, and on
	// the payload rather than on a count, so it also fails if the records
	// attached but arrived empty.
	var enriched int
	for _, f := range with.Findings {
		for _, e := range f.Enrichment {
			if e.Source == "KISA" && e.Summary == kisaSummary {
				enriched++
			}
		}
	}
	if enriched != 2 {
		t.Fatalf("the enriched run attached %d KISA records, want 2 — with nothing "+
			"attached this comparison proves nothing", enriched)
	}
	for _, f := range without.Findings {
		if len(f.Enrichment) != 0 {
			t.Fatalf("the un-enriched run attached %+v — the two fixtures differ in "+
				"more than enrichment", f.Enrichment)
		}
	}

	if len(with.Findings) != len(without.Findings) {
		t.Fatalf("finding count changed with enrichment: %d vs %d",
			len(with.Findings), len(without.Findings))
	}
	if !reflect.DeepEqual(with.Skipped, without.Skipped) {
		t.Errorf("the skip list changed with enrichment:\n  with    %+v\n  without %+v",
			with.Skipped, without.Skipped)
	}

	for i := range with.Findings {
		a, b := with.Findings[i], without.Findings[i]
		// Named first so a band or score change reports itself in those words
		// rather than as an opaque struct diff — this is the failure the whole
		// test exists to name.
		if a.Severity != b.Severity || a.Score != b.Score {
			t.Errorf("finding %d (%s): severity/score changed with enrichment: "+
				"%v/%.1f vs %v/%.1f", i, a.Advisory.ID, a.Severity, a.Score, b.Severity, b.Score)
		}
		a.Enrichment, b.Enrichment = nil, nil
		if !reflect.DeepEqual(a, b) {
			t.Errorf("finding %d differs beyond its enrichment:\n  with    %+v\n  without %+v",
				i, a, b)
		}
	}

	// The two counts every gate reads, re-derived the way report.Summarize and
	// scancmd.verdict derive them: how many findings could not be rated
	// (--fail-on-unknown) and how many sit at or above each band (--fail-on).
	// A summary that agreed on the findings but not on these would still change
	// an exit code.
	for _, band := range []severity.Band{
		severity.None, severity.Low, severity.Medium, severity.High, severity.Critical,
	} {
		if x, y := atOrAbove(with.Findings, band), atOrAbove(without.Findings, band); x != y {
			t.Errorf("findings at or above %v: %d with enrichment, %d without — "+
				"--fail-on %v would change verdict", band, x, y, band)
		}
	}
	if x, y := unratedCount(with.Findings), unratedCount(without.Findings); x != y {
		t.Errorf("unrated findings: %d with enrichment, %d without — --fail-on-unknown "+
			"would change verdict", x, y)
	}
}

// atOrAbove counts the findings a --fail-on band would trip on, exactly as
// scancmd.verdict does.
func atOrAbove(fs []Finding, band severity.Band) int {
	n := 0
	for _, f := range fs {
		if f.Severity.AtOrAbove(band) {
			n++
		}
	}
	return n
}

// unratedCount counts what report.Summary.UnknownSeverity counts, the figure
// --fail-on-unknown reads.
func unratedCount(fs []Finding) int {
	n := 0
	for _, f := range fs {
		if f.Severity == severity.Unknown {
			n++
		}
	}
	return n
}

// Enrichment is sorted by source and exact repeats are dropped.
//
// Both properties are exercised on the shape that actually produces them in
// production, not one a fake alone could reach. A finding grouping two CVEs
// gets one store answer per CVE, appended in identifier order, so the order of
// the CONCATENATION is decided here and nowhere else — the store's own
// per-CVE sort cannot help. And one KISA notice naming several CVEs becomes one
// stored record per CVE (knvd.convert), so a finding carrying both CVEs
// receives the same notice twice.
func TestMatch_EnrichmentIsSortedAndDeduplicated(t *testing.T) {
	rec := advWithRange("GHSA-two-cves", "PyPI", "django", "0", "3.2.13",
		advisory.RangeEcosystem)
	rec.Database = "GHSA"
	rec.Aliases = []string{"CVE-2022-0001", "CVE-2022-0002"}

	// The same notice, filed under both of the CVEs it names. The two stored
	// records differ in exactly one field — CVE — which matcher.Enrichment does
	// not carry, so they arrive identical and must collapse. This is not a
	// contrived pair: it is precisely what knvd.convert emits for one notice
	// naming two CVEs.
	noticeA := kisaNotice("CVE-2022-0001")
	noticeB := kisaNotice("CVE-2022-0002")
	// A hypothetical second enricher — only KISA exists today, and the
	// ordering rule is what is being pinned rather than this source. Chosen so
	// that source order and title order DISAGREE: "US-CERT" sorts after "KISA",
	// while an ASCII title sorts before a Korean one (Go compares strings by
	// byte, and Hangul is far above ASCII). Without that, a comparator keyed on
	// the title alone would produce the same answer as one keyed on the source,
	// and this test could not tell the documented key from a fallback.
	other := advisory.Enrichment{
		Source: "US-CERT", Title: "US-CERT-advisory-title", Summary: "US-CERT-summary",
		URL: "https://www.cisa.gov/news-events/alerts/AA00-000A",
	}

	s := fakeStore{
		byKey: map[string][]advisory.Advisory{key("PyPI", "django"): {rec}},
		enrichment: map[string][]advisory.Enrichment{
			// CVE-2022-0001 sorts first among the identifiers, so the append
			// order is KISA, US-CERT, KISA. Only the sort can bring the two
			// KISA records together, and only then can the dedup see them.
			"CVE-2022-0001": {noticeA},
			"CVE-2022-0002": {other, noticeB},
		},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	got := res.Findings[0].Enrichment
	if len(got) != 2 {
		t.Fatalf("got %d enrichment records, want 2 — one notice named both CVEs and "+
			"must not be listed twice: %+v", len(got), got)
	}
	var sources []string
	for _, e := range got {
		sources = append(sources, e.Source)
	}
	if fmt.Sprint(sources) != fmt.Sprint([]string{"KISA", "US-CERT"}) {
		t.Errorf("enrichment order = %v, want [KISA US-CERT] — sorted by SOURCE, not "+
			"by title and not in the order the finding's identifiers sort in", sources)
	}
	// The deduplicated survivor keeps its payload; a dedup that compared only
	// the source would collapse two genuinely different notices into one.
	if got[0] != (Enrichment{Source: "KISA", Title: kisaTitle, Summary: kisaSummary, URL: kisaURL}) {
		t.Errorf("the surviving KISA record = %+v, want the notice in full", got[0])
	}
}

// Two different notices about one CVE are two things a reader wants, so only
// EXACT repeats collapse. Without this, "deduplicate" could be implemented as
// "one record per source" and nothing would notice.
func TestMatch_TwoDifferentNoticesAboutOneCVEBothSurvive(t *testing.T) {
	first := kisaNotice("CVE-2022-28347")
	second := kisaNotice("CVE-2022-28347")
	// Sorts after kisaTitle, and demonstrably so: Go compares strings by byte,
	// which for UTF-8 is code-point order, and 후 (U+D6C4) is above 오 (U+C624).
	// This pins determinism, not a linguistic collation — no reader should read
	// Korean alphabetical order into it.
	second.Title = "제목-후속-보안-공지"
	second.URL = "https://knvd.krcert.or.kr/info/vuln/notice/detail?id=11223"

	s := twoSources(ghsaRec(), pysecRec())
	s.enrichment = map[string][]advisory.Enrichment{
		"CVE-2022-28347": {second, first}, // deliberately not in sorted order
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	got := res.Findings[0].Enrichment
	if len(got) != 2 {
		t.Fatalf("got %d enrichment records, want 2 — two different notices about one "+
			"CVE are two records: %+v", len(got), got)
	}
	if got[0].Title != kisaTitle || got[1].Title != "제목-후속-보안-공지" {
		t.Errorf("titles = [%q %q], want the sort to have ordered them — they were "+
			"supplied the other way round", got[0].Title, got[1].Title)
	}
}

// One CVE, asked once — and nothing that is not a CVE asked at all. This is
// TestMatch_ACVEIsResolvedOnceNotPerIdentifier's property for the second store
// read in the same loop: that test counts only rating calls, so moving the
// enrichment read outside the CVE- guard, or inside a per-alias loop, would
// leave it green while multiplying the reads on every real scan.
func TestMatch_EnrichmentIsAskedOnlyForCVEIdentifiersAndOnlyOnce(t *testing.T) {
	rec := ghsaRec()
	rec.Aliases = []string{"BIT-django-2022-28347", "CVE-2022-28347", "PYSEC-2022-191"}
	s := fakeStore{
		byKey:           map[string][]advisory.Advisory{key("PyPI", "django"): {rec}},
		enrichment:      map[string][]advisory.Enrichment{"CVE-2022-28347": {kisaNotice("CVE-2022-28347")}},
		enrichmentCalls: map[string]int{},
	}
	res, err := New(s).Match(djangoTarget())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Findings[0].Enrichment); n != 1 {
		t.Errorf("got %d enrichment records, want 1", n)
	}
	if s.enrichmentCalls["CVE-2022-28347"] != 1 {
		t.Errorf("the store was asked about one CVE %d times, want 1",
			s.enrichmentCalls["CVE-2022-28347"])
	}
	for id, n := range s.enrichmentCalls {
		if !strings.HasPrefix(id, "CVE-") {
			t.Errorf("the store was asked for enrichment on %q (%d times) — only CVE "+
				"identifiers reach an enrichment source", id, n)
		}
	}
	if len(s.enrichmentCalls) != 1 {
		t.Errorf("looked up %d identifiers, want 1 — the finding carries four and "+
			"exactly one is a CVE: %v", len(s.enrichmentCalls), s.enrichmentCalls)
	}
}

// A store failure while reading enrichment fails the scan, exactly as a failed
// rating lookup does.
//
// This is NOT in tension with D3. D3 governs what stored enrichment may do to a
// verdict — nothing — and a read that errored produced no enrichment to have an
// opinion. What it produced is evidence that the database this scan is reading
// is damaged, which is what exit 2 means (D11); and the matcher has no stderr,
// so swallowing it would report the damage to nobody.
func TestMatch_AnEnrichmentStoreErrorFailsTheScan(t *testing.T) {
	s := failingEnrichment{fakeStore: twoSources(ghsaRec(), pysecRec())}
	if _, err := New(s).Match(djangoTarget()); err == nil {
		t.Fatal("Match returned nil error when the enrichment store failed — a scan " +
			"reading a damaged database must not report a clean result")
	} else if !strings.Contains(err.Error(), "enrichment bucket unreadable") {
		// The cause, not just the wrapper: an error that dropped what actually
		// failed would leave a reader with nothing to act on.
		t.Errorf("error = %q, want the store's own failure carried through", err)
	}
}

// failingEnrichment answers every enrichment lookup with an error, so the
// scan's handling of a broken bucket is exercised without a broken database.
type failingEnrichment struct{ fakeStore }

func (failingEnrichment) EnrichmentFor(string) ([]advisory.Enrichment, error) {
	return nil, errors.New("enrichment bucket unreadable")
}
