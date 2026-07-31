package store

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

func sample(id, ecosystem, name string) advisory.Advisory {
	return advisory.Advisory{
		ID:       id,
		Source:   "osv",
		Kind:     advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: ecosystem, Name: name}},
	}
}

func buildTestDB(t *testing.T, advs ...advisory.Advisory) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, a := range advs {
		if err := w.Put(a); err != nil {
			t.Fatalf("Put(%s): %v", a.ID, err)
		}
	}
	err = w.SetMeta(Meta{
		BuiltAt: time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC),
		Providers: map[string]Provenance{
			"osv": {
				Source:   "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
				DataAsOf: time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC),
				Records:  len(advs),
			},
		},
	})
	if err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func TestLookup(t *testing.T) {
	path := buildTestDB(t,
		sample("GHSA-aaa", "Go", "github.com/foo/bar"),
		sample("GHSA-bbb", "Go", "github.com/foo/bar"),
		sample("GHSA-ccc", "npm", "lodash"),
	)
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	got, err := db.Lookup("Go", "github.com/foo/bar")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Lookup returned %d advisories, want 2", len(got))
	}
	ids := map[string]bool{got[0].ID: true, got[1].ID: true}
	if !ids["GHSA-aaa"] || !ids["GHSA-bbb"] {
		t.Errorf("Lookup returned %v, want GHSA-aaa and GHSA-bbb", ids)
	}

	none, err := db.Lookup("Go", "github.com/nobody/nothing")
	if err != nil {
		t.Fatalf("Lookup miss: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("Lookup miss returned %d advisories, want 0", len(none))
	}
}

func TestLookupDoesNotDuplicateRecords(t *testing.T) {
	// One advisory affecting three packages must be stored once and returned
	// under each key. This is the property that keeps the database from
	// growing 1.44x.
	multi := advisory.Advisory{
		ID:     "GHSA-multi",
		Source: "osv",
		Kind:   advisory.KindVulnerability,
		Affected: []advisory.Affected{
			{Ecosystem: "Go", Name: "a"},
			{Ecosystem: "Go", Name: "b"},
			{Ecosystem: "Go", Name: "c"},
		},
	}
	db, err := Open(buildTestDB(t, multi))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, name := range []string{"a", "b", "c"} {
		got, err := db.Lookup("Go", name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
		if len(got) != 1 || got[0].ID != "GHSA-multi" {
			t.Errorf("Lookup(%q) = %+v, want one GHSA-multi", name, got)
		}
	}
	if n := db.RecordCount(); n != 1 {
		t.Errorf("RecordCount = %d, want 1 (record stored once, not per package)", n)
	}
}

func TestLookupNormalizesPyPINames(t *testing.T) {
	// The advisory name is stored non-normalized and the lookup arrives in the
	// form syft emits, so this fails if EITHER the index write or the lookup
	// stops normalizing. Testing NormalizeName in isolation does not: the bug
	// was never in the function, it was in whether the two sides agreed.
	path := buildTestDB(t, advisory.Advisory{
		ID:       "PYSEC-1",
		Source:   "osv",
		Kind:     advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "PyPI", Name: "Zope.Interface"}},
	})
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, name := range []string{"zope.interface", "Zope.Interface", "zope_interface", "zope-interface"} {
		got, err := db.Lookup("PyPI", name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
		if len(got) != 1 {
			t.Errorf("Lookup(PyPI, %q) returned %d advisories, want 1 — every PEP 503 "+
				"spelling names the same package", name, len(got))
		}
	}

	// Go names are case-sensitive and must NOT be folded together.
	goPath := buildTestDB(t, sample("GHSA-go", "Go", "github.com/Foo/Bar"))
	gdb, err := Open(goPath)
	if err != nil {
		t.Fatal(err)
	}
	defer gdb.Close()
	if got, _ := gdb.Lookup("Go", "github.com/foo/bar"); len(got) != 0 {
		t.Errorf("Lookup(Go, lowercased) returned %d, want 0 — Go names are case-sensitive", len(got))
	}
}

func TestLookupFindsSourceKeyedAdvisories(t *testing.T) {
	// D8 through the ordinary index. OSV writes the SOURCE package name into
	// Affected[].Name for distro advisories -- 32,069 of 33,589 Alpine affected
	// entries carry ?arch=source -- so Put already indexes it and the matcher
	// reaches it by calling Lookup a second time with the source name. There is
	// no separate by-source bucket; slice 1 reserved one before the data was
	// measured.
	a := advisory.Advisory{
		ID:     "ALPINE-CVE-1",
		Source: "osv",
		Kind:   advisory.KindVulnerability,
		Affected: []advisory.Affected{
			// openssl is the source package; libssl3 is what is installed.
			{Ecosystem: "Alpine:v3.19", Name: "openssl"},
		},
	}
	// A PyPI name too, so the write and the read must agree on normalization.
	// The Alpine case cannot see that: NormalizeName is a no-op for it, so
	// either side could stop normalizing and the test would still pass.
	pypiAdv := advisory.Advisory{
		ID:     "PYSEC-src",
		Source: "osv",
		Kind:   advisory.KindVulnerability,
		Affected: []advisory.Affected{
			{Ecosystem: "PyPI", Name: "Zope.Interface"},
		},
	}

	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(pypiAdv); err != nil {
		t.Fatal(err)
	}
	// A writer that never calls SetMeta has not finished building, and Open
	// refuses such a database. Before ErrIncomplete existed this test passed
	// by relying on exactly the defect that check now closes.
	if err := w.SetMeta(Meta{BuiltAt: time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	got, err := db.Lookup("Alpine:v3.19", "openssl")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 1 || got[0].ID != "ALPINE-CVE-1" {
		t.Errorf("Lookup(Alpine:v3.19, openssl) = %+v, want ALPINE-CVE-1", got)
	}

	for _, spelling := range []string{"zope.interface", "Zope_Interface", "zope-interface"} {
		got, err := db.Lookup("PyPI", spelling)
		if err != nil {
			t.Fatalf("Lookup(PyPI, %q): %v", spelling, err)
		}
		if len(got) != 1 {
			t.Errorf("Lookup(PyPI, %q) returned %d, want 1: Put and Lookup must "+
				"agree on normalization", spelling, len(got))
		}
	}
}

func TestMeta(t *testing.T) {
	db, err := Open(buildTestDB(t, sample("GHSA-aaa", "Go", "x")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m, err := db.Meta()
	if err != nil {
		t.Fatalf("Meta: %v", err)
	}
	if m.Schema != SchemaVersion {
		t.Errorf("Meta.Schema = %d, want %d", m.Schema, SchemaVersion)
	}
	p, ok := m.Providers["osv"]
	if !ok {
		t.Fatal("Meta.Providers missing osv")
	}
	// DataAsOf must survive as upstream data time, distinct from BuiltAt (D12).
	if !p.DataAsOf.Equal(time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("DataAsOf = %v, want 2026-07-29", p.DataAsOf)
	}
	if !m.BuiltAt.After(p.DataAsOf) {
		t.Error("BuiltAt should be distinct from and later than DataAsOf in this fixture")
	}
}

func TestOpenMissing(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "absent.db"))
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Open(absent) err = %v, want ErrNotFound", err)
	}
}

func TestOpenIncomplete(t *testing.T) {
	// A build interrupted after Create and some Puts, before SetMeta. Its
	// buckets exist and its lookups would succeed with empty results, which is
	// indistinguishable from a clean scan — so Open must refuse it.
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(sample("GHSA-partial", "Go", "x")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil { // no SetMeta: the build never finished
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrIncomplete) {
		t.Errorf("Open(interrupted build) err = %v, want ErrIncomplete", err)
	}
}

func TestOpenSchemaMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.setSchemaForTest(SchemaVersion + 1); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("Open(mismatched) err = %v, want ErrSchemaMismatch", err)
	}
}

// D20: coverage is what the PROVIDERS reported, and specifically NOT every
// ecosystem named in a stored record.
//
// The distinction is the whole finding. Records deliberately keep affected
// entries for ecosystems that were never fetched (slice 1's cross-ecosystem
// fix), so deriving coverage from what Put indexed over-claims: on a real
// database built from Go, npm, PyPI and Alpine it certified Maven, NuGet,
// crates.io and five others. The day a Maven comparer lands, that set would
// vouch for a database holding 91 stray Maven keys and every Maven scan would
// report clean.
func TestMetaCoverageComesFromProvidersNotFromRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// One advisory naming two ecosystems. Only Go was fetched.
	if err := w.Put(advisory.Advisory{
		ID: "GHSA-both", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{
			{Ecosystem: "Go", Name: "github.com/x/y"},
			{Ecosystem: "Maven", Name: "org.x:y"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{
		BuiltAt: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC),
		Providers: map[string]Provenance{
			// Deliberately unsorted, and long enough that insertion order
			// cannot pass for sorted order by luck: against a 3-element map a
			// slices.Collect-instead-of-Sorted mutation survived 29 runs in 40.
			"osv": {Ecosystems: []string{
				"npm", "Go", "Alpine:v3.20", "PyPI", "Alpine:v3.19",
				"Alpine:v3.2", "Alpine:v3.9", "Alpine:v3.18",
			}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m, err := db.Meta()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Alpine:v3.18", "Alpine:v3.19", "Alpine:v3.2", "Alpine:v3.20",
		"Alpine:v3.9", "Go", "PyPI", "npm",
	}
	if !slices.Equal(m.Ecosystems, want) {
		t.Errorf("Meta.Ecosystems = %v, want %v (the providers' union, sorted)",
			m.Ecosystems, want)
	}
	covered, err := db.Covers()
	if err != nil {
		t.Fatal(err)
	}
	if covered["Maven"] {
		t.Error("Maven reported as covered. A record mentioning it was stored, " +
			"but no Maven archive was ever fetched, so a Maven lookup finding " +
			"nothing means nothing.")
	}
}

// Covers reports whether a lookup under this key can mean anything. Without it
// the matcher cannot tell "ingested, no advisories" from "never ingested", and
// the second reads as a clean scan.
func TestCovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "A-1", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Alpine:v3.19", Name: "busybox"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{
		BuiltAt:   time.Now(),
		Providers: map[string]Provenance{"osv": {Ecosystems: []string{"Alpine:v3.19"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	covered, err := db.Covers()
	if err != nil {
		t.Fatal(err)
	}
	if !covered["Alpine:v3.19"] {
		t.Error("Alpine:v3.19 was indexed but is not reported as covered")
	}
	// The release that ships next year, which this database has never seen.
	if covered["Alpine:v3.25"] {
		t.Error("Alpine:v3.25 reported as covered; nothing was ever stored under it")
	}
	if covered["PyPI"] {
		t.Error("PyPI reported as covered; this database holds only Alpine")
	}
}
