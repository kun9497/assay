package dbcmd

import (
	"bytes"
	"context"
	"errors"
	"os"
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

// enrichmentSourceLine returns the ENRICHMENT SOURCE table's row for name.
//
// It cuts the output at that table's own heading first, then matches on the
// row's FIRST field exactly — the RATING SOURCE table sits directly above and
// nothing stops one authority appearing in both, so a plain first-field scan
// over the whole output could answer from the wrong table entirely. Same
// wrong-column hazard CLAUDE.md describes, one table up.
func enrichmentSourceLine(t *testing.T, out, name string) string {
	t.Helper()
	_, after, ok := strings.Cut(out, "ENRICHMENT SOURCE")
	if !ok {
		t.Fatalf("no ENRICHMENT SOURCE table in:\n%s", out)
	}
	for _, line := range strings.Split(after, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == name {
			return line
		}
	}
	t.Fatalf("no ENRICHMENT SOURCE row for %q in:\n%s", name, out)
	return ""
}

// countField counts how many of a rendered row's whitespace-separated fields
// are exactly want. Exact fields rather than strings.Count, so a word that
// merely appears inside a longer cell cannot inflate the total.
func countField(fields []string, want string) int {
	n := 0
	for _, f := range fields {
		if f == want {
			n++
		}
	}
	return n
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
	err     error  // returned by Annotate instead of emitting anything, if set
	window  string // what this run covered; empty means the annotator reported none
	// coversSince is the machine-comparable form of window. Left zero
	// WITH coversSinceKnown false, it reproduces a pre-upgrade database.
	coversSince      time.Time
	coversSinceKnown bool
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
		Source:           "https://example.test/nvd",
		DataAsOf:         time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
		Records:          len(f.ratings),
		Window:           f.window,
		CoversSince:      f.coversSince,
		CoversSinceKnown: f.coversSinceKnown || !f.coversSince.IsZero(),
	}, nil
}

// fakeEnricher stands in for provider/knvd (D3): it never touches the
// network, so a test using it proves Update's own wiring — that it calls
// Enrich at all and writes what comes back through PutEnrichment — without
// depending on internal/provider/knvd, which has its own tests and whose
// New() defaults BaseURL to the live KNVD endpoint.
type fakeEnricher struct {
	name    string
	records []advisory.Enrichment
	// err is returned by Enrich AFTER records have been emitted, so a test
	// can exercise the partial-run shape (some prose written, then the feed
	// fell over) as well as the total failure.
	err error
	// claims, when non-zero, is the Records count this enricher SELF-REPORTS,
	// whatever it actually emitted. It exists so a test can tell a count
	// derived from the enrichment bucket apart from one copied out of the
	// provenance — the over-claim Meta.Ratings made once already on this
	// branch, where `db status` named a source that had rated nothing.
	claims int
}

func (f fakeEnricher) Name() string { return f.name }

func (f fakeEnricher) Enrich(_ context.Context, emit func(advisory.Enrichment) error) (store.Provenance, error) {
	for _, e := range f.records {
		if err := emit(e); err != nil {
			return store.Provenance{}, err
		}
	}
	records := f.claims
	if records == 0 {
		records = len(f.records)
	}
	prov := store.Provenance{
		Source:   "https://example.test/knvd",
		DataAsOf: time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC),
		Records:  records,
	}
	if f.err != nil {
		// A fully populated Provenance is returned ALONGSIDE the error, on
		// purpose, and it is more hostile than any real enricher: knvd returns
		// a zero one. It is here so Update discarding what a failed run
		// reported about itself is an assertion rather than an accident of the
		// fixture — a run that did not finish cannot vouch for its own
		// freshness, and `db status` must not print a DATA AS OF for it (D12).
		return prov, f.err
	}
	return prov, nil
}

func TestUpdateThenStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-x", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, "", "", []provider.Provider{p}, nil, nil, &out, &errOut); code != 0 {
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
	if !strings.Contains(s, "databases:  GHSA") {
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
	if !strings.Contains(s, "ratings:    nothing") {
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
	code := Update(context.Background(), path, "", "", []provider.Provider{p}, []provider.Annotator{a}, nil, &out, &errOut)
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
	if code := Update(context.Background(), path, "", "", []provider.Provider{first}, nil, nil, &out, &errOut); code != 0 {
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
	code := Update(context.Background(), path, "", "", []provider.Provider{second}, []provider.Annotator{a}, nil, &out, &errOut)
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
	if code := Update(context.Background(), path, "", "", []provider.Provider{mk("first")}, nil, nil, &out, &errOut); code != 0 {
		t.Fatalf("first Update = %d: %s", code, errOut.String())
	}
	if code := Update(context.Background(), path, "", "", []provider.Provider{mk("second")}, nil, nil, &out, &errOut); code != 0 {
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
	if code := Update(context.Background(), path, "", "", []provider.Provider{p}, []provider.Annotator{a}, nil, &out, &errOut); code != 0 {
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
	if !strings.Contains(s, "ratings:    NVD (2)") {
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

// A bounded rating sync must say what it covered. Update rebuilds the
// database from empty, so a windowed run's window is that source's ENTIRE
// coverage rather than a delta on a fuller earlier pass — and without this
// column a database holding one day of NVD renders identically to one
// holding all of it, differing only in a RECORDS number no reader has a
// baseline for. That is D20's over-claim in its quietest form: every finding
// whose CVE fell outside the window keeps a lower band, and nothing says so.
func TestStatus_RatingSourceDisclosesTheWindowItCovered(t *testing.T) {
	for _, tc := range []struct {
		name, window, want string
	}{
		{"bounded", "modified 2026-07-04..2026-08-03", "modified 2026-07-04..2026-08-03"},
		{"whole feed", "the whole feed", "the whole feed"},
		// A database built before Window existed must not render a blank
		// cell, which reads as "no limit" — the one meaning it cannot have.
		{"not reported", "", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vulnerability.db")
			p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
				ID: "GHSA-x", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
				Affected: []advisory.Affected{{Ecosystem: "Go", Name: "x"}},
			}}}
			a := fakeAnnotator{
				name:    "NVD",
				ratings: []advisory.Rating{{CVE: "CVE-2026-2", Source: "NVD"}},
				window:  tc.window,
			}

			var out, errOut bytes.Buffer
			if code := Update(context.Background(), path, "", "", []provider.Provider{p}, []provider.Annotator{a}, nil, &out, &errOut); code != 0 {
				t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
			}
			out.Reset()
			if code := Status(path, &out, &errOut); code != 0 {
				t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
			}
			s := out.String()
			row := ratingSourceLine(t, s, "NVD")
			if !strings.Contains(row, tc.want) {
				t.Errorf("RATING SOURCE row for NVD = %q, want it to disclose the covered window %q", row, tc.want)
			}
			// The heading too, not just the cell: deleting the column from
			// the header leaves the value rendered under a neighbouring
			// label, which a row-only assertion passes on happily (verified
			// by mutation - it survived until this line existed).
			if !strings.Contains(s, "COVERED") {
				t.Errorf("RATING SOURCE table has no COVERED heading, so the window renders under another column:\n%s", s)
			}
		})
	}
}

// TestStatus_AnAnnotatorThatRatesNothingIsNotClaimedAsASource is the exact
// defect a review of this slice caught (D20's own hazard, one bucket over):
// an annotator that runs successfully but emits zero ratings must not make
// `ratings:` claim a source that rated something. Meta.RatingCounts is
// derived from the stored ratings bucket, so an annotator with nothing to
// show for itself simply is not in it - unlike the earlier, self-report-based
// design, where Records: 0 still left the name in the map and the line
// printed "ratings:    NVD" over an empty bucket.
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
	if code := Update(context.Background(), path, "", "", []provider.Provider{p}, []provider.Annotator{a}, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := out.String()
	if strings.Contains(s, "ratings:    NVD") {
		t.Errorf("status claims NVD as a rating source, but it rated nothing:\n%s", s)
	}
	if !strings.Contains(s, "ratings:    nothing") {
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
	if code := Update(context.Background(), path, "", "", []provider.Provider{p}, nil, nil, &out, &errOut); code != 0 {
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

// Seeding carries the RATINGS forward -- the seven-hour half -- while
// advisories are rebuilt from the providers every run.
//
// Both halves of that are load-bearing, and the second is the one that is
// easy to get wrong: an advisory the upstream archive no longer carries
// (withdrawn, D16) must be ABSENT from the rebuilt database. Nothing in
// the build removes a record no provider re-emitted, so a seeded advisory
// is a false positive with no expiry date.
func TestUpdate_SeedCarriesRatingsButNotAdvisories(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed.db")
	w, err := store.Create(seed)
	if err != nil {
		t.Fatal(err)
	}
	// This advisory stands in for one upstream has since withdrawn: it is
	// in the seed and this run's provider does not re-emit it.
	if err := w.Put(advisory.Advisory{
		ID: "GHSA-withdrawn-upstream", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "old"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2026-OLD", Source: "NVD"}); err != nil {
		t.Fatal(err)
	}
	w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {DataAsOf: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}},
		Ratings:   map[string]store.Provenance{"NVD": {Window: "modified 2026-07-05..2026-08-03"}},
	})
	w.Close()

	// This run fetches ONE advisory and rates ONE new CVE.
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-new", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "new"}},
	}}}
	a := fakeAnnotator{name: "NVD", window: "modified 2026-08-03..2026-08-04",
		ratings: []advisory.Rating{{CVE: "CVE-2026-NEW", Source: "NVD"}}}

	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), dst, seed, "",
		[]provider.Provider{p}, []provider.Annotator{a}, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	db, err := store.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// The expensive half survived...
	if rs, err := db.RatingsFor("CVE-2026-OLD"); err != nil || len(rs) != 1 {
		t.Errorf("RatingsFor(CVE-2026-OLD) = %v, %v; the seed's rating was lost, which is the whole point of seeding", rs, err)
	}
	// ...alongside this run's.
	if rs, err := db.RatingsFor("CVE-2026-NEW"); err != nil || len(rs) != 1 {
		t.Errorf("RatingsFor(CVE-2026-NEW) = %v, %v; this run's rating is missing", rs, err)
	}
	// ...and this run's advisory is there. Reached through Lookup, which is
	// how advisories are read -- there is no fetch-by-ID on the store, and
	// Lookup is what the matcher itself calls, so this asserts on the path
	// that actually decides findings.
	if got, err := db.Lookup("Go", "new"); err != nil || len(got) != 1 {
		t.Errorf("Lookup(Go, new) = %v, %v; this run's advisory is missing", got, err)
	}
	// But the seed's advisory is GONE, because no provider re-emitted it.
	// If this assertion ever fails, every withdrawn advisory in every seed
	// becomes a permanent false positive.
	if got, err := db.Lookup("Go", "old"); err != nil {
		t.Fatal(err)
	} else if len(got) != 0 {
		t.Errorf("Lookup(Go, old) = %v, want none: a seeded advisory survived a rebuild, so an advisory upstream withdraws can now never be removed", got)
	}
}

// A seeded build must say so. One that printed what a full build prints
// would be the same over-claim this project keeps re-learning (D20, D26).
//
// Two ratings, not one: asserting "seeded 1 rating" against a fixture with
// exactly one seeded rating cannot tell "the counter" from "the literal 1"
// -- replacing `seeded` in the Fprintf with a hardcoded 1 would still pass
// (fix round 1, item 4). "seeded 2" can only come from the real count.
func TestUpdate_SeededBuildDisclosesWhatItCarriedForward(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed.db")
	w, _ := store.Create(seed)
	w.PutRating(advisory.Rating{CVE: "CVE-2026-OLD-1", Source: "NVD"})
	w.PutRating(advisory.Rating{CVE: "CVE-2026-OLD-2", Source: "NVD"})
	w.SetMeta(store.Meta{})
	w.Close()

	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), dst, seed, "", nil, nil, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := errOut.String()
	if !strings.Contains(s, "seeded 2 rating") {
		t.Errorf("stderr does not say how many ratings were carried forward:\n%s", s)
	}
	if !strings.Contains(s, "advisories rebuilt") {
		t.Errorf("stderr does not say advisories were rebuilt rather than inherited:\n%s", s)
	}
}

// The disclosure must name what a human or an archived CI log actually
// recognizes -- the original --seed reference the CLI resolved -- not
// seedPath, which for `db build --seed <ref>` is a throwaway scratch file
// Pull wrote the artifact to (fix round 1, item 3). Asserted as the exact
// rendered phrase, and asserted ABSENT for the scratch path, so a mutation
// that silently falls back to seedPath even when seedRef is given cannot
// pass by accident (the seed variable's own temp path is unique enough
// that a stray match would mean exactly that regression).
func TestUpdate_SeededDisclosureNamesTheGivenReferenceNotTheScratchPath(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed.db")
	w, _ := store.Create(seed)
	w.PutRating(advisory.Rating{CVE: "CVE-2026-OLD", Source: "NVD"})
	w.SetMeta(store.Meta{})
	w.Close()

	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	ref := "ghcr.io/kun9497/assay-db:v6"
	if code := Update(context.Background(), dst, seed, ref, nil, nil, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := errOut.String()
	if !strings.Contains(s, "seeded 1 rating(s) from "+ref) {
		t.Errorf("stderr does not name the original reference:\n%s", s)
	}
	if strings.Contains(s, seed) {
		t.Errorf("stderr names the scratch seed path instead of (or alongside) the reference it was given:\n%s", s)
	}
}

// A seed that cannot be read fails the build. It must NOT fall back to
// building from empty: the scheduled builder passes --seed every night, so
// one registry outage would publish a one-day database over a complete one
// and every finding outside that day would quietly lose its NVD band. The
// failure has to be loud and the previous artifact has to stay published.
func TestUpdate_AnUnreadableSeedFailsRatherThanBuildingFromEmpty(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	missing := filepath.Join(t.TempDir(), "not-there.db")

	a := fakeAnnotator{name: "NVD", ratings: []advisory.Rating{{CVE: "CVE-2026-NEW", Source: "NVD"}}}

	var out, errOut bytes.Buffer
	code := Update(context.Background(), dst, missing, "", nil, []provider.Annotator{a}, nil, &out, &errOut)
	if code != 2 {
		t.Errorf("Update with an unreadable seed = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "not-there.db") {
		t.Errorf("stderr does not name the seed it could not read:\n%s", errOut.String())
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("a failed seeded build left a database behind; the next push would publish it")
	}
}

// A seeded build must not present the seed's coverage as this run's. If the
// seed holds 30 days of NVD and this run refreshed one, db status has to
// say so -- otherwise seeding trades a seven-hour build for a database that
// silently over-claims, which is D20's failure in a new place.
//
// This test used to assert the row showed only THIS run's window, and that
// expectation was itself the bug. A seeded database HOLDS the seed's
// ratings, so reporting the one-day fetch understates it -- and worse, the
// artifact then published a bound later than the one it replaced, which
// db push's coverage guard reads as a narrowing. The scheduled workflow
// would have published successfully on day one and been refused on day two.
// Coverage now describes what the database holds; see mergeRatingCoverage.
//
// Three seeded ratings, not one, and the RECORDS count is asserted as an
// exact FIELD, not `strings.Contains(row, "2")` (fix round 1, item 1): the
// rendered row is "NVD  2026-08-03  5  modified 2026-08-03..2026-08-04
// https://example.test/nvd", and "2026-08-03" alone contains "2" three
// times over, so the old assertion could not fail -- deleting the seed's
// EachRating->PutRating copy entirely (dropping the count from 5 to 2)
// left it green. 5 also cannot appear as a substring of either date in the
// row (its digits are 2,0,6,0,8,0,3,0,4), so even a stray Contains
// elsewhere in this row could not accidentally vouch for it.
func TestUpdate_SeededRunReportsTheWindowItActuallyFetched(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed.db")
	w, _ := store.Create(seed)
	w.PutRating(advisory.Rating{CVE: "CVE-2026-OLD-1", Source: "NVD"})
	w.PutRating(advisory.Rating{CVE: "CVE-2026-OLD-2", Source: "NVD"})
	w.PutRating(advisory.Rating{CVE: "CVE-2026-OLD-3", Source: "NVD"})
	w.SetMeta(store.Meta{
		Ratings: map[string]store.Provenance{"NVD": {Window: "modified 2026-07-05..2026-08-03"}},
	})
	w.Close()

	a := fakeAnnotator{name: "NVD", window: "modified 2026-08-03..2026-08-04",
		ratings: []advisory.Rating{
			{CVE: "CVE-2026-NEW-1", Source: "NVD"},
			{CVE: "CVE-2026-NEW-2", Source: "NVD"},
		}}

	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), dst, seed, "", nil, []provider.Annotator{a}, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	out.Reset()
	if code := Status(dst, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0", code)
	}
	row := ratingSourceLine(t, out.String(), "NVD")
	// The seed here records a Window but no CoversSince -- the shape a
	// database built before that field has -- so the merged coverage is
	// genuinely UNKNOWN and the row has to say so. Claiming this run's
	// one-day window would understate a database holding the seed's
	// thirty, and claiming thirty would assert a vintage nothing recorded.
	if !strings.Contains(row, "seed coverage not recorded") {
		t.Errorf("RATING SOURCE row = %q, want it to disclose that the seed's coverage is unknown", row)
	}
	// All five CVEs (3 seeded + 2 this run) are present, so the count is the
	// merged one -- the window narrowing must not be read as "the older
	// ratings were dropped". Field index 2 is RECORDS regardless of how many
	// words COVERED renders as ("RATING SOURCE\tDATA AS OF\tRECORDS\t..." --
	// only the trailing columns can contain embedded spaces).
	fields := strings.Fields(row)
	if len(fields) < 3 || fields[2] != "5" {
		t.Errorf("RATING SOURCE row = %q, want RECORDS field \"5\" (the merged count), got %v", row, fields)
	}
}

// The seed's Meta.Ratings provenance must survive a run where the
// annotator it describes does NOT execute at all -- the real nightly
// scenario this stands in for is NVD_ENABLE unset (or an NVD outage) on
// one scheduled build, so `dbUpdateAnnotators` returns nil and the
// annotator loop in Update never touches meta.Ratings["NVD"].
//
// Without the maps.Copy this test exists to cover (fix round 1, item 2:
// the Step 6 mutation only MOVED that line, it never covered deleting it
// outright), the ratings themselves still survive in the bucket via
// EachRating -- so RATING SOURCE still gets a row for NVD, self-reported
// DATA AS OF, COVERED and SOURCE all silently render "unknown" instead of
// the seed's real values, with no error anywhere. That is a worse defect
// than a missing row: it looks like a source that ran today and reported
// nothing about itself, not a source whose freshness was carried forward
// from the seed.
func TestUpdate_SeededMetaSurvivesWhenThisRunsAnnotatorDidNotRun(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "seed.db")
	w, _ := store.Create(seed)
	w.PutRating(advisory.Rating{CVE: "CVE-2026-OLD", Source: "NVD"})
	seedAsOf := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	w.SetMeta(store.Meta{
		Ratings: map[string]store.Provenance{"NVD": {
			Window:   "modified 2026-07-01..2026-08-01",
			DataAsOf: seedAsOf,
			Source:   "https://example.test/nvd-seed",
		}},
	})
	w.Close()

	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	// No annotators at all this run -- NVD_ENABLE unset for the night.
	if code := Update(context.Background(), dst, seed, "", nil, nil, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	out.Reset()
	if code := Status(dst, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0", code)
	}
	row := ratingSourceLine(t, out.String(), "NVD")
	// asOf is distinct from both dates inside the seed's window string, so
	// this cannot pass by matching the wrong column.
	if !strings.Contains(row, "2026-08-02") {
		t.Errorf("RATING SOURCE row = %q, want the seed's DATA AS OF (2026-08-02) carried forward, not unknown", row)
	}
	if !strings.Contains(row, "modified 2026-07-01..2026-08-01") {
		t.Errorf("RATING SOURCE row = %q, want the seed's COVERED window carried forward, not unknown", row)
	}
	if !strings.Contains(row, "https://example.test/nvd-seed") {
		t.Errorf("RATING SOURCE row = %q, want the seed's SOURCE carried forward, not unknown", row)
	}
}

// TestUpdate_RunsEnrichers is the direct wiring check for D3's third source
// kind: Update must actually call Enrich, not merely accept an enrichers
// slice and never touch it, and every field of what Enrich emits must be
// readable back through Store.EnrichmentFor once the build is done — the
// same database a scan will later open (D14: a scan never fetches anything,
// so a local `db build` is the only way KISA's prose can enter).
//
// Asserted field by field, not by length: Summary in particular is the one
// field Task 1's own round-trip test omitted, and a `json:"-"` on it would
// empty every Korean overview while leaving that suite green.
func TestUpdate_RunsEnrichers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-enriched", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	want := advisory.Enrichment{
		CVE:     "CVE-2026-46394",
		Source:  "KISA",
		Title:   "리눅스 커널 취약점 보안 업데이트 권고",
		Summary: "원격의 공격자가 임의 코드를 실행할 수 있는 취약점",
		URL:     "https://knvd.krcert.or.kr/info/vuln/notice/detail?id=99",
	}
	e := fakeEnricher{name: "KISA", records: []advisory.Enrichment{want}}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, "", "", []provider.Provider{p}, nil,
		[]provider.Enricher{e}, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.EnrichmentFor("CVE-2026-46394")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("EnrichmentFor(CVE-2026-46394) = %d record(s), want 1 — Enrich ran but "+
			"what it emitted was never persisted", len(got))
	}
	if got[0] != want {
		t.Errorf("stored enrichment = %+v, want %+v", got[0], want)
	}
	// And the enricher ran after (not instead of) the providers: the advisory
	// half of the same build must still be there.
	if advs, err := db.Lookup("Go", "github.com/a/b"); err != nil || len(advs) != 1 {
		t.Errorf("Lookup(Go, github.com/a/b) = %v, %v; the enricher displaced the advisory build", advs, err)
	}
}

// A failing enricher does NOT fail the build, unlike a failing provider or a
// failing annotator.
//
// The asymmetry is deliberate and it is the point of this test. Enrichment
// cannot change a verdict (D3), so losing it costs a reader some Korean text
// and costs the scan nothing — while failing the build would let an
// unreachable KISA endpoint stop a user getting any database at all, after
// an OSV fetch and possibly a seven-hour NVD pass have already succeeded.
//
// It is still reported: the warning names the enricher AND carries the cause,
// asserted as one string, because Contains(stderr, "enricher") alone would
// pass on a message that dropped the reason entirely (CLAUDE.md's
// wrapper-satisfies-the-assertion shape).
func TestUpdate_AFailingEnricherIsReportedButDoesNotFailTheBuild(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-survives-a-failed-enricher", Database: "GHSA", Source: "osv",
		Kind:     advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	e := fakeEnricher{name: "KISA", err: errBoom}

	var out, errOut bytes.Buffer
	code := Update(context.Background(), path, "", "", []provider.Provider{p}, nil,
		[]provider.Enricher{e}, &out, &errOut)
	if code != 0 {
		t.Fatalf("Update with a failing enricher = %d, want 0 — an unreachable enrichment "+
			"source must not stop a database being built (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "warning: enricher KISA: boom") {
		t.Errorf("stderr does not name the failing enricher and its cause:\n%s", errOut.String())
	}

	// The database was still installed, and holds this run's advisories.
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("a failing enricher left no usable database: %v", err)
	}
	defer db.Close()
	got, err := db.Lookup("Go", "github.com/a/b")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "GHSA-survives-a-failed-enricher" {
		t.Errorf("Lookup = %+v, want the advisory this build fetched", got)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(matches) != 0 {
		t.Errorf("leftover temp files after a failing enricher: %v", matches)
	}
}

// An enricher's self-reported Records count is not believed: `db status`
// reports what the enrichment bucket actually holds.
//
// This is the defect Meta.Ratings already shipped once on this branch —
// `db status` naming a source that had rated nothing, because the number came
// from the annotator's own Provenance instead of the stored data. A third
// source kind arriving next to it gets the derived treatment from the start.
//
// The fixture claims 999 and emits 2, so the two answers cannot be confused,
// and 999 is asserted ABSENT from the whole of `db status` — a self-reported
// count leaking into any column, not just this row, fails here.
func TestStatus_EnrichmentCountsAreDerivedFromTheBucketNotTheEnricher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-counted", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	e := fakeEnricher{name: "KISA", claims: 999, records: []advisory.Enrichment{
		{CVE: "CVE-2026-1000", Source: "KISA", Title: "제목 하나"},
		{CVE: "CVE-2026-2000", Source: "KISA", Title: "제목 둘"},
	}}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, "", "", []provider.Provider{p}, nil,
		[]provider.Enricher{e}, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := out.String()
	row := enrichmentSourceLine(t, s, "KISA")
	fields := strings.Fields(row)
	// Scoped to the KISA ROW, not to everything Status prints, and that is not
	// tidiness. Contains(s, "999") matched the temp directory in the output's
	// own path header: CI drew
	// /tmp/TestStatus_...2999817164/001/vulnerability.db and this test failed
	// on a run where nothing was wrong.
	//
	// Same family as the substring rule in CLAUDE.md, in the direction that
	// fails loudly rather than passing vacuously — which is the only reason it
	// was ever noticed. The row check below has the matching comment about why
	// it compares fields rather than substrings.
	if slices.Contains(fields, "999") || slices.Contains(fields, "(999)") {
		t.Errorf("status prints the enricher's self-reported count instead of what the "+
			"bucket holds: %q", row)
	}
	// RECORDS is checked as an exact FIELD rather than a substring:
	// "2026-08-05" contains "2" twice over, so Contains(row, "2") could not
	// fail whatever the count column held.
	if !slices.Contains(fields, "2") {
		t.Errorf("ENRICHMENT SOURCE row for KISA does not show its actual count (2):\n%q", row)
	}
	if !slices.Contains(fields, "2026-08-05") {
		t.Errorf("ENRICHMENT SOURCE row for KISA is missing its DataAsOf:\n%q", row)
	}
	if !strings.Contains(row, "https://example.test/knvd") {
		t.Errorf("ENRICHMENT SOURCE row for KISA is missing its fetch URL:\n%q", row)
	}
	if strings.Contains(row, "enriched nothing") {
		t.Errorf("ENRICHMENT SOURCE row for KISA reads as having enriched nothing, but it "+
			"wrote 2 records:\n%q", row)
	}
}

// An enricher that ran and enriched NOTHING is neither claimed as a source
// nor silently dropped — the third rendering the RATING SOURCE table already
// has to produce (D20/D26), one table down.
//
// "Ran and got nothing" is worth investigating and must stay visible, but it
// must not read as "this source enriched something" either. A bare 0 in the
// RECORDS cell reads as the second, so the cell is words. EnrichmentCounts
// can never store an explicit zero (a key exists only once counts[source]++
// has run), so a literal "0" token in this row could only come from a
// fallback that treats a missing key as a count.
func TestStatus_AnEnricherThatEnrichedNothingIsNotClaimedAsASource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-empty-enrichment", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	// Ran successfully (nil error), emitted nothing — a legitimate "the feed
	// had nothing this build could use" outcome, not a failure.
	e := fakeEnricher{name: "KISA", records: nil}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, "", "", []provider.Provider{p}, nil,
		[]provider.Enricher{e}, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	row := enrichmentSourceLine(t, out.String(), "KISA")
	if !strings.Contains(row, "enriched nothing") {
		t.Errorf("ENRICHMENT SOURCE row for KISA does not say it enriched nothing:\n%q", row)
	}
	if slices.Contains(strings.Fields(row), "0") {
		t.Errorf("ENRICHMENT SOURCE row for KISA shows a bare 0, which reads as \"enriched "+
			"things\" rather than \"ran and enriched nothing\":\n%q", row)
	}
	if !slices.Contains(strings.Fields(row), "2026-08-05") {
		t.Errorf("ENRICHMENT SOURCE row for KISA is missing its DataAsOf, even though it ran:\n%q", row)
	}
}

// An authority that never ran against this database has no ENRICHMENT SOURCE
// row at all — as opposed to one that ran and enriched nothing, which does
// (the sibling test above). Nothing enriched here, so neither the table nor
// its heading may appear.
func TestStatus_NoEnricherMeansNoEnrichmentTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-no-enricher", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, "", "", []provider.Provider{p}, nil, nil, &out, &errOut); code != 0 {
		t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := out.String()
	if strings.Contains(s, "ENRICHMENT SOURCE") {
		t.Errorf("status prints an ENRICHMENT SOURCE table when no enricher ever ran:\n%s", s)
	}
	if strings.Contains(s, "KISA") {
		t.Errorf("status mentions KISA even though no enricher ran against this database:\n%s", s)
	}
}

// A failed enrichment run is visible in `db status` whether or not it wrote
// anything first.
//
// The first version of this recorded nothing for a failed source, which
// produced the worst of both worlds: a PARTIAL failure still rendered a row
// (its records are in the bucket, so the derived half of the union answers
// for it) while a TOTAL failure rendered none at all. The same fault was
// visible or invisible depending on when the feed died, and a reader had no
// way to tell either shape from a healthy run — the partial one reads as a
// complete fetch of exactly that many records.
//
// The stderr warning is not a substitute: it scrolls past with the build,
// while the database is what anyone looks at afterwards, and a scan run a
// week later has only `db status` to go on.
func TestStatus_AFailedEnricherIsVisibleWhetherOrNotItWroteAnything(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []advisory.Enrichment
		err     error
		// wantCount is the number that must appear as its own field in the
		// row, or "" when the run wrote nothing at all.
		wantCount string
		// wantTail is a word from LATER in the error message that must land
		// on the same row, or "" when the message is a single line anyway.
		wantTail string
	}{
		{
			name:    "total failure",
			records: nil,
			err:     errBoom,
		},
		{
			name: "partial failure",
			records: []advisory.Enrichment{
				{CVE: "CVE-2026-1000", Source: "KISA", Title: "제목 하나"},
				{CVE: "CVE-2026-2000", Source: "KISA", Title: "제목 둘"},
			},
			err:       errBoom,
			wantCount: "2",
		},
		{
			// A message spanning lines must be folded into one. A tabwriter
			// row containing a newline does not render as an odd-looking
			// cell — it silently becomes two rows, the second unlabelled and
			// unaligned, so the cause ends up under a heading it has nothing
			// to do with and the table stops being readable at all.
			name: "a failure whose message spans lines",
			err:  errors.New("boom\nsecond line of the message"),
			// "second" can only appear on this row if the newline was
			// flattened; otherwise it starts a row of its own.
			wantTail: "second",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vulnerability.db")
			p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
				ID: "GHSA-failed-enricher", Database: "GHSA", Source: "osv",
				Kind:     advisory.KindVulnerability,
				Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
			}}}
			e := fakeEnricher{name: "KISA", records: tc.records, err: tc.err}

			var out, errOut bytes.Buffer
			if code := Update(context.Background(), path, "", "", []provider.Provider{p}, nil,
				[]provider.Enricher{e}, &out, &errOut); code != 0 {
				t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
			}
			out.Reset()
			errOut.Reset()
			if code := Status(path, &out, &errOut); code != 0 {
				t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
			}
			row := enrichmentSourceLine(t, out.String(), "KISA")

			// It says it failed, and it says why. The cause is asserted
			// separately from the word: a row that said "failed" with no
			// reason would leave an operator exactly where the missing row
			// left them.
			if !strings.Contains(row, "failed") {
				t.Errorf("ENRICHMENT SOURCE row for KISA does not say the run failed:\n%q", row)
			}
			if !strings.Contains(row, "boom") {
				t.Errorf("ENRICHMENT SOURCE row for KISA does not name the cause:\n%q", row)
			}
			// And it cannot be read as a healthy run that simply had nothing
			// to say — the wording the successful-but-empty case uses.
			if strings.Contains(row, "ran, enriched nothing") {
				t.Errorf("a FAILED enrichment run renders as a successful empty one:\n%q", row)
			}
			// Neither the freshness nor the fetch URL the enricher reported
			// may appear. The fixture returns both alongside its error, so a
			// row carrying either means Update believed a run that did not
			// finish (D12).
			fields := strings.Fields(row)
			if slices.Contains(fields, "2026-08-05") {
				t.Errorf("ENRICHMENT SOURCE row for KISA reports a DATA AS OF for a run that "+
					"did not finish:\n%q", row)
			}
			if slices.Contains(fields, "https://example.test/knvd") {
				t.Errorf("ENRICHMENT SOURCE row for KISA reports a fetch URL for a run that "+
					"did not finish:\n%q", row)
			}
			// And both say so in the SAME word rather than one of them going
			// blank. DATA AS OF and SOURCE are in the identical situation
			// here — neither was established — so one row with two
			// vocabularies for one fact is a reader's problem, and a blank
			// cell additionally reads as "nothing to say here" rather than
			// "not established".
			if n := countField(fields, "unknown"); n != 2 {
				t.Errorf("ENRICHMENT SOURCE row for KISA has %d \"unknown\" cell(s), want 2 "+
					"(DATA AS OF and SOURCE):\n%q", n, row)
			}
			if tc.wantTail != "" && !strings.Contains(row, tc.wantTail) {
				t.Errorf("the rest of a multi-line failure message is not on this row, so it "+
					"became a row of its own and broke the table:\n%q\nin:\n%s", row, out.String())
			}
			if tc.wantCount != "" && !slices.Contains(fields, tc.wantCount) {
				// The records that DID land are still worth stating: "2" and
				// "2 out of an unknown number" are different claims, and the
				// second is the one this row has to make.
				t.Errorf("ENRICHMENT SOURCE row for KISA does not show the %s record(s) that "+
					"landed before the failure:\n%q", tc.wantCount, row)
			}
		})
	}
}

// `db status`'s header block says whether anything in this database carries a
// localized notice, beside the ratings: line and read the same way.
//
// Without it, the only statement of D3's coverage is the ENRICHMENT SOURCE
// table further down, and its ABSENCE is what a reader would have to infer
// "nothing is enriched" from — an absence cannot say that, and the same gap
// on the ratings: line is one this command has already been fixed for.
//
// The count is asserted with its label attached ("enrichment: KISA (2)"), not
// as a bare "KISA": the ENRICHMENT SOURCE table two blocks down also holds
// that name and that number, so a substring assertion on either half would
// pass from the table with this line deleted entirely.
func TestStatus_HeaderSaysWhetherAnythingIsEnriched(t *testing.T) {
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-header-enrich", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}

	t.Run("when something is", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "vulnerability.db")
		// Claims 999, emits 2: the line must report the bucket, never the
		// self-report, for the reason RatingCounts' doc comment gives.
		e := fakeEnricher{name: "KISA", claims: 999, records: []advisory.Enrichment{
			{CVE: "CVE-2026-1000", Source: "KISA", Title: "제목 하나"},
			{CVE: "CVE-2026-2000", Source: "KISA", Title: "제목 둘"},
		}}
		var out, errOut bytes.Buffer
		if code := Update(context.Background(), path, "", "", []provider.Provider{p}, nil,
			[]provider.Enricher{e}, &out, &errOut); code != 0 {
			t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		out.Reset()
		errOut.Reset()
		if code := Status(path, &out, &errOut); code != 0 {
			t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		s := out.String()
		if !strings.Contains(s, "enrichment: KISA (2)") {
			t.Errorf("status has no enrichment: line naming the source and its count:\n%s", s)
		}
		if strings.Contains(s, "enrichment: KISA (999)") {
			t.Errorf("the enrichment: line reports the enricher's self-reported count:\n%s", s)
		}
	})

	t.Run("when nothing is", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "vulnerability.db")
		var out, errOut bytes.Buffer
		if code := Update(context.Background(), path, "", "", []provider.Provider{p}, nil, nil,
			&out, &errOut); code != 0 {
			t.Fatalf("Update = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		out.Reset()
		errOut.Reset()
		if code := Status(path, &out, &errOut); code != 0 {
			t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		s := out.String()
		// Stated, not omitted. A database with no enrichment is the normal
		// condition of every PULLED artifact (D29), and "no line at all" is
		// exactly the inference this line exists to stop a reader making.
		if !strings.Contains(s, "enrichment: nothing") {
			t.Errorf("status omits the enrichment: line when nothing is enriched, so the "+
				"absence of the table is the only thing that says so:\n%s", s)
		}
	})
}

// Both source tables render a MISSING source URL the same way.
//
// The ENRICHMENT SOURCE table arrived on this branch writing "unknown" where
// RATING SOURCE, directly above it, left the cell blank — two conventions for
// one absence, in adjacent tables, on one screen. A blank cell also reads as
// "there is nothing to say here" rather than "this was not established",
// which is the same mistake the COVERED column was already fixed for.
//
// The fixture is a database whose buckets hold records that its provenance
// never accounted for, which is the only way a derived-only row arises: the
// name is in RatingCounts/EnrichmentCounts (derived from the stored data) and
// absent from Ratings/Enrichment (self-reported), so p.Source is "".
func TestStatus_BothTablesNameAMissingSourceTheSameWay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2026-4242", Source: "NVD"}); err != nil {
		t.Fatal(err)
	}
	if err := w.PutEnrichment(advisory.Enrichment{CVE: "CVE-2026-4242", Source: "KISA", Title: "제목"}); err != nil {
		t.Fatal(err)
	}
	// No Ratings and no Enrichment provenance: both names are derived-only.
	if err := w.SetMeta(store.Meta{BuiltAt: time.Date(2026, 8, 5, 6, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := Status(path, &out, &errOut); code != 0 {
		t.Fatalf("Status = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	s := out.String()

	// The last field of each row is its SOURCE cell. Compared to each other
	// as well as to "unknown", because the requirement is agreement: pinning
	// only the literal would still pass if one table later moved to some
	// other word and the other did not.
	ratingFields := strings.Fields(ratingSourceLine(t, s, "NVD"))
	enrichFields := strings.Fields(enrichmentSourceLine(t, s, "KISA"))
	// Guarded rather than assumed: an empty SOURCE cell makes the row one
	// field SHORTER, so indexing the last field without checking the length
	// would silently read the COVERED column instead and find "unknown" there.
	if len(ratingFields) != 5 {
		t.Fatalf("RATING SOURCE row has %d fields, want 5 (name, as-of, records, covered, source) - "+
			"an empty SOURCE cell is exactly what makes it 4:\n%q", len(ratingFields), ratingSourceLine(t, s, "NVD"))
	}
	if len(enrichFields) != 4 {
		t.Fatalf("ENRICHMENT SOURCE row has %d fields, want 4 (name, as-of, records, source):\n%q",
			len(enrichFields), enrichmentSourceLine(t, s, "KISA"))
	}
	ratingSource := ratingFields[len(ratingFields)-1]
	enrichSource := enrichFields[len(enrichFields)-1]
	if ratingSource != enrichSource {
		t.Errorf("RATING SOURCE renders a missing source as %q and ENRICHMENT SOURCE as %q; "+
			"two adjacent tables must not read one absence two ways", ratingSource, enrichSource)
	}
	if ratingSource != "unknown" {
		t.Errorf("RATING SOURCE renders a missing source as %q, want \"unknown\" - the same word "+
			"its own DATA AS OF and COVERED columns already use for the same absence", ratingSource)
	}
}

// A bare major is a release. Alpine spells its releases "v3.19" and Debian
// spells the modern ones "12", and requiring the dot dropped every Debian
// release from 7 up into the lexical fallback — which printed "Debian:3.0..9"
// for a database covering 3.0 through 14, telling an operator the newest four
// releases were missing when they were the bulk of the archive.
func TestCompareRelease_BareMajorIsARelease(t *testing.T) {
	got := append([]string(nil), "14", "9", "3.0", "11", "7", "6.0", "10")
	slices.SortFunc(got, compareRelease)
	want := []string{"3.0", "6.0", "7", "9", "10", "11", "14"}
	if !slices.Equal(got, want) {
		t.Errorf("sorted = %v, want %v", got, want)
	}
	// Alpine's own form still sorts numerically, which is what the comparison
	// was written for.
	alpine := append([]string(nil), "v3.9", "v3.10", "v3.2", "v3.24")
	slices.SortFunc(alpine, compareRelease)
	if !slices.Equal(alpine, []string{"v3.2", "v3.9", "v3.10", "v3.24"}) {
		t.Errorf("alpine sorted = %v", alpine)
	}
	// And a genuinely unparseable release still sorts last rather than
	// corrupting the range.
	mixed := append([]string(nil), "edge", "12", "3.0")
	slices.SortFunc(mixed, compareRelease)
	if mixed[len(mixed)-1] != "edge" {
		t.Errorf("mixed = %v, want the unparseable one last", mixed)
	}
}
