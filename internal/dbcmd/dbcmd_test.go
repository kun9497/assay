package dbcmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// ratingSourceLine returns the RATING SOURCE table's row for name: the
// first line whose FIRST whitespace-separated field is exactly name, not a
// substring match — the same nesting hazard CLAUDE.md calls out (a longer
// name that merely starts with name must not match).
func ratingSourceLine(t *testing.T, out, name string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == name {
			return line
		}
	}
	t.Fatalf("no RATING SOURCE row for %q in:\n%s", name, out)
	return ""
}

// errBoom is a fixed sentinel a fakeAnnotator/fakeProvider can return, so a
// failure test asserts on a specific, known error rather than "any error".
var errBoom = errors.New("boom")

type fakeProvider struct {
	name string
	advs []advisory.Advisory
	// covers is what this provider reports having fetched (D20). A provider
	// reporting none builds a database that refuses every scan, so a test
	// leaving it empty is testing that rather than what it means to.
	covers []string
}

func (f fakeProvider) Name() string { return f.name }

func (f fakeProvider) Fetch(_ context.Context, emit func(advisory.Advisory) error) (store.Provenance, error) {
	for _, a := range f.advs {
		if err := emit(a); err != nil {
			return store.Provenance{}, err
		}
	}
	return store.Provenance{
		Ecosystems: f.covers,
		Source:     "https://example.test/all.zip",
		DataAsOf:   time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC),
		Records:    len(f.advs),
	}, nil
}

// fakeAnnotator stands in for provider.nvd.Provider (D27): it never touches
// the network, so a test using it proves Update's own wiring — that it calls
// Annotate at all and writes what comes back through PutRating — without
// depending on internal/provider/nvd, which is out of scope for this task and
// already covered by its own tests.
type fakeAnnotator struct {
	name    string
	ratings []advisory.Rating
	err     error // returned by Annotate instead of emitting anything, if set
}

func (f fakeAnnotator) Name() string { return f.name }

func (f fakeAnnotator) Annotate(_ context.Context, emit func(advisory.Rating) error) (store.Provenance, error) {
	if f.err != nil {
		return store.Provenance{}, f.err
	}
	for _, r := range f.ratings {
		if err := emit(r); err != nil {
			return store.Provenance{}, err
		}
	}
	return store.Provenance{
		Source:   "https://example.test/nvd",
		DataAsOf: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
		Records:  len(f.ratings),
	}, nil
}

func TestUpdateThenStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-x", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, []provider.Provider{p}, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := out.String()
	// Coverage decides which packages can be evaluated at all (D20), and this
	// is the only place it is visible without running a scan and reading why
	// it refused.
	if !strings.Contains(s, "covers:") || !strings.Contains(s, "Go") {
		t.Errorf("status does not report what the database covers:\n%s", s)
	}
	// Which databases a rating could be attributed to (D25), visible without
	// running a scan. Asserting the rendered pair, not either half alone,
	// since "GHSA" nested inside another field would satisfy a bare Contains.
	if !strings.Contains(s, "databases: GHSA") {
		t.Errorf("status does not report which databases are present:\n%s", s)
	}
	// Status reports upstream data time, which is the number that tells you
	// whether the data is stale (D12).
	if !strings.Contains(s, "2026-07-29") {
		t.Errorf("Status output missing DataAsOf:\n%s", s)
	}
	if !strings.Contains(s, "osv") {
		t.Errorf("Status output missing provider name:\n%s", s)
	}
	// No annotator ran, so the ratings: line must say so plainly rather than
	// being absent (the same "nothing covered says so" discipline
	// coverageSummary and databasesSummary already follow) or, worse, being
	// silently blank.
	if !strings.Contains(s, "ratings:   nothing") {
		t.Errorf("status does not report that no rating source has run:\n%s", s)
	}
}

// TestUpdate_RunsAnnotatorsAndPersistsRatings is the direct wiring check
// (D27): Update must actually call Annotate, not just construct the
// annotators slice and never touch it, and what Annotate emits must be
// readable back through Store.RatingsFor once the build is done — the same
// database a scan will later open (D14: a scan never fetches anything, so
// this is the only place NVD's opinion can enter).
func TestUpdate_RunsAnnotatorsAndPersistsRatings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-y", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	a := fakeAnnotator{name: "NVD", ratings: []advisory.Rating{
		{CVE: "CVE-2026-1", Source: "NVD", Severity: []advisory.Severity{
			{Type: "CVSS_V31", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		}},
	}}

	var out, errOut bytes.Buffer
	code := Update(context.Background(), path, []provider.Provider{p}, []provider.Annotator{a}, &out, &errOut)
	if code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.RatingsFor("CVE-2026-1")
	if err != nil {
		t.Fatal(err)
	}
	// Asserted field by field rather than just a length check: a mutation
	// that runs Annotate but discards what it returns, or writes it under
	// the wrong CVE, would still pass a bare "len == 1".
	if len(got) != 1 {
		t.Fatalf("RatingsFor(CVE-2026-1) = %d ratings, want 1 - Annotate ran but its "+
			"output was never persisted", len(got))
	}
	if got[0].Source != "NVD" {
		t.Errorf("rating Source = %q, want %q", got[0].Source, "NVD")
	}
}

// TestUpdate_AnnotatorFailureLeavesAnExistingDatabaseUntouched: a failing
// annotator must fail the whole build exactly like a failing provider does.
// A database holding advisories but silently missing the ratings a
// configured annotator was supposed to add would look complete and
// under-report every band NVD would otherwise have raised - the exact
// silent failure D14/D11 exist to rule out for a provider, one door over.
//
// Proven against a database that ALREADY EXISTS before the failing Update
// runs, not a fresh t.TempDir() with nothing in it: the real guarantee is
// that a pre-existing, working database survives a failed rebuild attempt
// untouched (dbcmd.go's own comment: "the live database is untouched either
// way"), which "no file appears" cannot tell apart from "correctly refused
// with nothing to protect". This mirrors TestUpdateReplacesAtomically's own
// two-Update shape, except the second Update here fails.
func TestUpdate_AnnotatorFailureLeavesAnExistingDatabaseUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnerability.db")

	first := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-first", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, []provider.Provider{first}, nil, &out, &errOut); code != 0 {
		t.Fatalf("initial Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	// A second Update at the SAME path, whose provider would replace the
	// advisory but whose annotator fails. If the pre-existing database were
	// disturbed at all, this is the record that would prove it -
	// "GHSA-second-should-never-appear" must never be found.
	second := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-second-should-never-appear", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	a := fakeAnnotator{name: "NVD", err: errBoom}
	out.Reset()
	errOut.Reset()
	code := Update(context.Background(), path, []provider.Provider{second}, []provider.Annotator{a}, &out, &errOut)
	if code != 2 {
		t.Fatalf("second Update = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "NVD") {
		t.Errorf("stderr does not name the failing annotator:\n%s", errOut.String())
	}

	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("the pre-existing database must still open cleanly after the failed "+
			"second Update: %v", err)
	}
	defer db.Close()
	got, err := db.Lookup("Go", "github.com/a/b")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "GHSA-first" {
		t.Errorf("Lookup = %+v, want only the FIRST build's advisory - a failed second "+
			"Update must leave the pre-existing database exactly as it was", got)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(matches) != 0 {
		t.Errorf("leftover temp files after a failed annotator: %v", matches)
	}
}

func TestUpdateReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnerability.db")
	mk := func(id string) provider.Provider {
		return fakeProvider{name: "osv", advs: []advisory.Advisory{{
			ID: id, Source: "osv", Kind: advisory.KindVulnerability,
			Affected: []advisory.Affected{{Ecosystem: "Go", Name: "pkg"}},
		}}}
	}
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, []provider.Provider{mk("first")}, nil, &out, &errOut); code != 0 {
		t.Fatalf("first Update = %d: %s", code, errOut.String())
	}
	if code := Update(context.Background(), path, []provider.Provider{mk("second")}, nil, &out, &errOut); code != 0 {
		t.Fatalf("second Update = %d: %s", code, errOut.String())
	}

	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.Lookup("Go", "pkg")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "second" {
		t.Errorf("Lookup = %+v, want only the second build's advisory", got)
	}
	// No temporary file may survive a successful update.
	matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(matches) != 0 {
		t.Errorf("leftover temp files: %v", matches)
	}
}

func TestStatusWithoutDatabase(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Status(filepath.Join(t.TempDir(), "absent.db"), &out, &errOut)
	if code != 2 {
		t.Errorf("Status(absent) = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "db update") {
		t.Errorf("stderr should tell the user how to fix it:\n%s", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", out.String())
	}
}

// `covers:` is the only place coverage is visible without running a scan and
// reading why it refused, so its shape is part of the contract.
func TestCoverageSummary(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{
			// The whole point of collapsing: 23 releases must not bury the
			// three language ecosystems an operator also needs to see.
			name: "a family collapses to a range",
			in: []string{
				"Alpine:v3.19", "Alpine:v3.2", "Alpine:v3.24", "Alpine:v3.9",
				"Go", "PyPI", "npm",
			},
			want: "Go, PyPI, npm, Alpine:v3.2..v3.24 (4 releases)",
		},
		{
			// Numeric, not lexical. Sorted as whole strings this printed
			// "v3.10..v3.9" — a range that reads as covering nothing and
			// answers "is 3.25 inside?" backwards.
			name: "releases order numerically",
			in:   []string{"Alpine:v3.9", "Alpine:v3.10", "Alpine:v3.2"},
			want: "Alpine:v3.2..v3.10 (3 releases)",
		},
		{
			name: "a single release is not a range",
			in:   []string{"Alpine:v3.19"},
			want: "Alpine:v3.19",
		},
		{
			// A database covering nothing is the state D20 exists to make
			// visible, so it must not render as an empty string.
			name: "nothing covered says so",
			in:   nil,
			want: "nothing - every scan will report its packages as unevaluated",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := coverageSummary(tt.in); got != tt.want {
				t.Errorf("coverageSummary(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// `databases:` is the only place a rating's attributable source is visible
// without running a scan (D25), so its shape is part of the contract too.
func TestDatabasesSummary(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{
			// databasesSummary trusts its input's order rather than sorting
			// -- Bolt.SetMeta is what sorts Databases -- so an unsorted
			// input is joined unsorted, not alphabetized on the way out.
			name: "joins in the order given",
			in:   []string{"GHSA", "PYSEC", "ALPINE", "GO"},
			want: "GHSA, PYSEC, ALPINE, GO",
		},
		{
			name: "one database",
			in:   []string{"GHSA"},
			want: "GHSA",
		},
		{
			// A database holding no advisories is visible, not an empty
			// string that reads as "the line failed to render".
			name: "none present says so",
			in:   nil,
			want: "nothing - ratings will not be attributable to a source",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := databasesSummary(tt.in); got != tt.want {
				t.Errorf("databasesSummary(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// `ratings:` is the only place a rating's attributable authority is visible
// without running a scan (D27), matching databases:'s own shape and message
// convention, with a count per name appended (D12: "how many" is exactly
// the freshness/completeness question nothing else in db status answers for
// ratings). Takes counts derived from the ratings bucket, never
// Meta.Ratings' self-reported Provenance — see ratingsSummary's own doc
// comment for why.
func TestRatingsSummary(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]int
		want string
	}{
		{
			// Unlike databasesSummary, this input is a map — sorted here
			// rather than trusted pre-sorted, since Meta.RatingCounts is
			// derived with no ordering guarantee of its own the way
			// Bolt.SetMeta's Databases has.
			name: "sorts several sources and shows each count",
			in:   map[string]int{"NVD": 12345, "KISA": 40},
			want: "KISA (40), NVD (12345)",
		},
		{
			name: "one source",
			in:   map[string]int{"NVD": 7},
			want: "NVD (7)",
		},
		{
			// A source that ran and rated nothing must not appear at all
			// (an empty map is exactly what a caller-supplied-but-derived-
			// away entry looks like) - the defect this whole fix exists
			// for. A database no rating source has run against is visible,
			// not an empty string that reads as "the line failed to
			// render" — the same discipline coverageSummary/
			// databasesSummary already follow for their own empty case.
			name: "none present says so",
			in:   nil,
			want: "nothing - no CVE in this database has been rated by any authority",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ratingsSummary(tt.in); got != tt.want {
				t.Errorf("ratingsSummary(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestStatus_ShowsRatingSources: `db status` must show which authorities
// rated at least one CVE (D27) after a real Update run, the same "visible
// without running a scan" guarantee `databases:` already gives — the count
// alongside the name (D12: "how many" is exactly the freshness question),
// and a DATA AS OF for the source in the RATING SOURCE table. Deleting the
// ratings: line, the RATING SOURCE table, or wiring either to an
// always-empty value is the mutation this exists to catch.
func TestStatus_ShowsRatingSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-w", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	// Two ratings from NVD, so the count in "ratings:" is checkable against
	// something other than 1 (which could pass by a mutation that always
	// prints 1 for any non-empty source).
	a := fakeAnnotator{name: "NVD", ratings: []advisory.Rating{
		{CVE: "CVE-2026-2", Source: "NVD"},
		{CVE: "CVE-2026-3", Source: "NVD"},
	}}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, []provider.Provider{p}, []provider.Annotator{a}, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := out.String()
	// Asserted as the rendered pair with its count, not "NVD" alone:
	// CLAUDE.md's own substring-collision note (a short word inside
	// surrounding prose) is exactly the hazard a bare Contains(s, "NVD")
	// would risk here, and the count is the fact D27/D12 actually turn on.
	if !strings.Contains(s, "ratings:   NVD (2)") {
		t.Errorf("status does not report NVD as a rating source with its count:\n%s", s)
	}
	// The RATING SOURCE table is where DataAsOf lives (D12) - the "ratings:"
	// line alone cannot answer "how fresh is the NVD data in this database".
	// The row is resolved by its own first field, then checked field by
	// field (not by a bare Contains(s, "2"), which "2026-08-03" alone would
	// satisfy): this is the "NVD ran and rated 240,132 CVEs" case - a real,
	// positive count, not the "ran, rated nothing" wording the sibling test
	// checks for the opposite case.
	row := ratingSourceLine(t, s, "NVD")
	fields := strings.Fields(row)
	if !slices.Contains(fields, "2026-08-03") {
		t.Errorf("RATING SOURCE row for NVD is missing its DataAsOf:\n%q", row)
	}
	if !slices.Contains(fields, "2") {
		t.Errorf("RATING SOURCE row for NVD does not show its actual count (2):\n%q", row)
	}
	if strings.Contains(row, "rated nothing") {
		t.Errorf("RATING SOURCE row for NVD reads as having rated nothing, but it rated 2:\n%q", row)
	}
	if !strings.Contains(row, "https://example.test/nvd") {
		t.Errorf("RATING SOURCE row for NVD is missing its fetch URL:\n%q", row)
	}
}

// TestStatus_AnAnnotatorThatRatesNothingIsNotClaimedAsASource is the exact
// defect a review of this slice caught (D20's own hazard, one bucket over):
// an annotator that runs successfully but emits zero ratings must not make
// `ratings:` claim a source that rated something. Meta.RatingCounts is
// derived from the stored ratings bucket, so an annotator with nothing to
// show for itself simply is not in it - unlike the earlier, self-report-based
// design, where Records: 0 still left the name in the map and the line
// printed "ratings:   NVD" over an empty bucket.
//
// A re-review of this same fix caught a second occurrence one table down:
// the RATING SOURCE table still iterated Meta.Ratings (self-report) and only
// took RECORDS from RatingCounts, so a name present in Ratings but absent
// from RatingCounts still printed a named row with RECORDS 0 - the identical
// over-claim, one column over, that the summary line had just stopped
// making. D20/D26 forbid the opposite fix too (silently dropping the row),
// since "ran and got nothing" is itself worth surfacing - so this checks for
// the third rendering: present, named, and in words that cannot be read as
// "this source rated something".
func TestStatus_AnAnnotatorThatRatesNothingIsNotClaimedAsASource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-empty-ratings", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	// Ran successfully (nil error), emitted nothing - a legitimate "the feed
	// had nothing to say" outcome, not a failure.
	a := fakeAnnotator{name: "NVD", ratings: nil}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, []provider.Provider{p}, []provider.Annotator{a}, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := out.String()
	if strings.Contains(s, "ratings:   NVD") {
		t.Errorf("status claims NVD as a rating source, but it rated nothing:\n%s", s)
	}
	if !strings.Contains(s, "ratings:   nothing") {
		t.Errorf("status does not say plainly that nothing was rated:\n%s", s)
	}

	// The RATING SOURCE table: NVD ran (it is self-reported, DataAsOf and
	// SOURCE both present) but rated nothing (absent from RatingCounts). The
	// row must exist - D20/D26 forbid silently dropping "we looked and got
	// nothing" - but its RECORDS cell must read as a warning, not a count.
	row := ratingSourceLine(t, s, "NVD")
	if !strings.Contains(row, "rated nothing") {
		t.Errorf("RATING SOURCE row for NVD does not say it rated nothing:\n%q", row)
	}
	// The exact hazard: a bare "0" reads as "zero problems", not "something
	// may be wrong with the sync". RatingCounts can never itself store an
	// explicit zero (a key only exists once counts[source]++ has run at
	// least once), so a literal "0" token anywhere in this row could only
	// come from the old, reverted fallback (m.RatingCounts[name] defaulting
	// to 0 for a missing key) - checked as an exact field, not a substring,
	// since "2026-08-03" contains "0" several times over.
	if slices.Contains(strings.Fields(row), "0") {
		t.Errorf("RATING SOURCE row for NVD shows a bare 0, which reads as \"rated things\" "+
			"rather than \"ran and rated nothing\":\n%q", row)
	}
	if !slices.Contains(strings.Fields(row), "2026-08-03") {
		t.Errorf("RATING SOURCE row for NVD is missing its DataAsOf, even though it ran:\n%q", row)
	}
}

// TestStatus_AnAuthorityThatNeverRanHasNoRow is the third of the three
// states a reader must be able to tell apart at a glance (D27's review): an
// authority this database's build never configured at all must not appear
// in the RATING SOURCE table (or the ratings: line) — as opposed to one
// that ran and rated nothing, which DOES get a row (the sibling test
// above). Nothing ran here, so neither the line nor the table's header may
// appear at all.
func TestStatus_AnAuthorityThatNeverRanHasNoRow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-no-annotator", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, []provider.Provider{p}, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := out.String()
	if strings.Contains(s, "RATING SOURCE") {
		t.Errorf("status prints a RATING SOURCE table when no annotator ever ran:\n%s", s)
	}
	if strings.Contains(s, "NVD") {
		t.Errorf("status mentions NVD even though no annotator ran against this database:\n%s", s)
	}
}

// An unparseable release must not panic or vanish: an unexpected key shape
// should be visible in `db status`, not fatal to it.
func TestCoverageSummary_UnparseableReleaseSortsLast(t *testing.T) {
	got := coverageSummary([]string{"Alpine:v3.19", "Alpine:edge", "Alpine:v3.2"})
	if !strings.Contains(got, "3 releases") {
		t.Errorf("coverageSummary = %q; the unparseable release was dropped", got)
	}
	if !strings.Contains(got, "v3.2..edge") {
		t.Errorf("coverageSummary = %q; want the unparseable one sorted last", got)
	}
}
