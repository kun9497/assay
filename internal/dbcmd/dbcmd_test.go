package dbcmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

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

// TestUpdate_AnnotatorFailureRemovesTempAndExits2: a failing annotator must
// fail the whole build exactly like a failing provider does. A database
// holding advisories but silently missing the ratings a configured annotator
// was supposed to add would look complete and under-report every band NVD
// would otherwise have raised - the exact silent failure D14/D11 exist to
// rule out for a provider, one door over.
func TestUpdate_AnnotatorFailureRemovesTempAndExits2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-z", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	a := fakeAnnotator{name: "NVD", err: errBoom}

	var out, errOut bytes.Buffer
	code := Update(context.Background(), path, []provider.Provider{p}, []provider.Annotator{a}, &out, &errOut)
	if code != 2 {
		t.Fatalf("Update = %d, want 2 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "NVD") {
		t.Errorf("stderr does not name the failing annotator:\n%s", errOut.String())
	}
	// Neither the live database nor a leftover temp file may survive: a
	// database is either complete or absent, never half-built and mistaken
	// for complete (mirrors TestUpdateReplacesAtomically's own check).
	if _, err := os.Stat(path); err == nil {
		t.Error("a failed annotator left a database in place - a scan would read it as complete")
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
// convention.
func TestRatingsSummary(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]store.Provenance
		want string
	}{
		{
			// Unlike databasesSummary, this input is a map — sorted here
			// rather than trusted pre-sorted, since Meta.Ratings carries no
			// ordering guarantee of its own the way Bolt.SetMeta's Databases
			// does.
			name: "sorts several sources",
			in:   map[string]store.Provenance{"NVD": {}, "KISA": {}},
			want: "KISA, NVD",
		},
		{
			name: "one source",
			in:   map[string]store.Provenance{"NVD": {}},
			want: "NVD",
		},
		{
			// A database no rating source has run against is visible, not an
			// empty string that reads as "the line failed to render" — the
			// same discipline coverageSummary/databasesSummary already
			// follow for their own empty case.
			name: "none present says so",
			in:   nil,
			want: "nothing - no rating source has run against this database",
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
// without running a scan" guarantee `databases:` already gives. Deleting the
// ratings: line (or wiring it to an always-empty value) is the mutation this
// exists to catch.
func TestStatus_ShowsRatingSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-w", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}
	a := fakeAnnotator{name: "NVD", ratings: []advisory.Rating{
		{CVE: "CVE-2026-2", Source: "NVD"},
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
	// Asserted as the rendered pair, not "NVD" alone: CLAUDE.md's own
	// substring-collision note (a short word inside surrounding prose) is
	// exactly the hazard a bare Contains(s, "NVD") would risk here.
	if !strings.Contains(out.String(), "ratings:   NVD") {
		t.Errorf("status does not report NVD as a rating source:\n%s", out.String())
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
