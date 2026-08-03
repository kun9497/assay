package dbcmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

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

func TestUpdateThenStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	p := fakeProvider{name: "osv", covers: []string{"Go"}, advs: []advisory.Advisory{{
		ID: "GHSA-x", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "github.com/a/b"}},
	}}}

	var out, errOut bytes.Buffer
	if code := Update(context.Background(), path, []provider.Provider{p}, &out, &errOut); code != 0 {
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
	if !strings.Contains(s, "sources:  GHSA") {
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
	if code := Update(context.Background(), path, []provider.Provider{mk("first")}, &out, &errOut); code != 0 {
		t.Fatalf("first Update = %d: %s", code, errOut.String())
	}
	if code := Update(context.Background(), path, []provider.Provider{mk("second")}, &out, &errOut); code != 0 {
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
