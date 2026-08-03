package store

import (
	"errors"
	"fmt"
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

// Both directions must refuse. A newer schema is the ordinary case (an old
// binary opening a database a newer one built). An OLDER schema is the one
// D25's bump exists for: it is what a pre-D25 database actually is, and
// accepting it would silently serve records with Database empty on every
// one. `Open` compares with `!=`, which happens to catch both today, but
// nothing pins the older direction on its own — a change to `m.Schema >
// SchemaVersion` (which reads, at a glance, like a reasonable
// forward-compatibility check) would accept every older database and the
// suite would stay green without this case.
func TestOpenSchemaMismatch(t *testing.T) {
	for _, tt := range []struct {
		name string
		v    int
	}{
		{"newer", SchemaVersion + 1},
		{"older", SchemaVersion - 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "v.db")
			w, err := Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.setSchemaForTest(tt.v); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path); !errors.Is(err, ErrSchemaMismatch) {
				t.Errorf("Open(schema %d, want %d) err = %v, want ErrSchemaMismatch", tt.v, SchemaVersion, err)
			}
		})
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

// D25: Databases is read from what this build actually stored, unlike
// Ecosystems (D20) which comes from provider self-report. A record's
// Database names only itself, so there is no foreign-ecosystem-style
// over-claim to guard against — scanning what was Put is the accurate
// answer, not an approximation of it.
//
// IDs are deliberately NOT alphabetized the same way their Database is.
// Real OSV IDs have the Database as their own prefix (GHSA-x has Database
// "GHSA"), which would make both Put() order and the by-id bucket's
// key-sorted iteration agree with the correctly-sorted Databases output for
// free — passing even if the explicit sort in SetMeta were dropped. Put()
// is also called in this same scrambled order, so neither "the order Put
// was called" nor "the order the bucket iterates" can pass for "sorted" by
// coincidence.
func TestMetaDatabasesComesFromStoredRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "REC-a1", Database: "PYSEC", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "PyPI", Name: "y"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "REC-m1", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "x"}},
	}); err != nil {
		t.Fatal(err)
	}
	// A second GHSA record: Databases must collapse this to one entry, not
	// list "GHSA" twice.
	if err := w.Put(advisory.Advisory{
		ID: "REC-m2", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "w"}},
	}); err != nil {
		t.Fatal(err)
	}
	// No Database set at all (as a pre-D25 record would arrive): must not
	// contribute an empty entry to the set.
	if err := w.Put(advisory.Advisory{
		ID: "REC-b1", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "z"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "REC-z1", Database: "ALPINE", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Alpine:v3.19", Name: "v"}},
	}); err != nil {
		t.Fatal(err)
	}
	// Put() order above and the by-id bucket's key order (REC-a1 < REC-b1 <
	// REC-m1 < REC-m2 < REC-z1) both discover PYSEC, then GHSA, then ALPINE
	// — the exact reverse of the correct, alphabetically-sorted answer.
	if err := w.SetMeta(Meta{
		BuiltAt:   time.Now(),
		Databases: []string{"should-be-ignored"},
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
	want := []string{"ALPINE", "GHSA", "PYSEC"}
	if !slices.Equal(m.Databases, want) {
		t.Errorf("Meta.Databases = %v, want %v (sorted, deduplicated, no empty "+
			"entry for the record with none, caller-supplied value ignored)",
			m.Databases, want)
	}
}

// SetMeta must not take the caller's word for coverage. The field is derived
// from Providers, and a caller that fills it in directly is ignored — that is
// what keeps a wrong caller from re-opening the hole D20 closed.
func TestSetMetaIgnoresACallerSuppliedEcosystems(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{
		BuiltAt:    time.Now(),
		Ecosystems: []string{"Maven", "NuGet", "everything-really"},
		Providers:  map[string]Provenance{"osv": {Ecosystems: []string{"Go"}}},
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
	if !slices.Equal(m.Ecosystems, []string{"Go"}) {
		t.Errorf("Meta.Ecosystems = %v, want [Go]: the caller's list must be "+
			"ignored in favour of what the providers reported", m.Ecosystems)
	}
}

// A rating round-trips, and is keyed on the CVE rather than on any advisory.
func TestPutRating_RoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	want := advisory.Rating{
		CVE:    "CVE-2026-39822",
		Source: "NVD",
		Severity: []advisory.Severity{
			{Type: "CVSS_V31", Score: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
		},
		URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-39822",
	}
	if err := w.PutRating(want); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{}); err != nil {
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
	got, err := db.RatingsFor("CVE-2026-39822")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d ratings, want 1", len(got))
	}
	// Asserted field by field, each with its own message: a single DeepEqual
	// reports "not equal" and leaves the reader to diff two structs, and the
	// fields here decide whether a band is derived at all.
	if got[0].CVE != want.CVE {
		t.Errorf("CVE = %q, want %q", got[0].CVE, want.CVE)
	}
	if got[0].Source != want.Source {
		t.Errorf("Source = %q, want %q", got[0].Source, want.Source)
	}
	if len(got[0].Severity) != 1 || got[0].Severity[0].Score != want.Severity[0].Score {
		t.Errorf("Severity = %+v, want the stored vector verbatim (D13)", got[0].Severity)
	}
	if got[0].URL != want.URL {
		t.Errorf("URL = %q, want %q", got[0].URL, want.URL)
	}
}

// A CVE nobody rated returns nothing and no error. "We have no rating" is a
// normal answer, not a failure - the matcher asks this for every finding.
func TestRatingsFor_UnknownCVEIsEmptyNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, _ := Create(path)
	w.SetMeta(Meta{})
	w.Close()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.RatingsFor("CVE-0000-00000")
	if err != nil {
		t.Fatalf("RatingsFor returned %v; an unrated CVE is a normal answer", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d ratings, want 0", len(got))
	}
}

// Several authorities can rate one CVE. They come back sorted by Source, so
// the report cannot vary between runs.
func TestRatingsFor_SeveralSourcesComeBackSorted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, _ := Create(path)
	// Written in an order that is NOT the sorted one, so the assertion below
	// fails if the sort is dropped rather than passing by luck.
	for _, s := range []string{"NVD", "KISA"} {
		if err := w.PutRating(advisory.Rating{CVE: "CVE-2025-1", Source: s}); err != nil {
			t.Fatal(err)
		}
	}
	w.SetMeta(Meta{})
	w.Close()
	db, _ := Open(path)
	defer db.Close()
	got, err := db.RatingsFor("CVE-2025-1")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range got {
		names = append(names, r.Source)
	}
	if fmt.Sprint(names) != fmt.Sprint([]string{"KISA", "NVD"}) {
		t.Errorf("sources = %v, want [KISA NVD] - sorted, so two runs agree", names)
	}
}

// Schema 6, and a database at any other version refuses rather than serving
// records with no ratings bucket - which would read as "nobody rated any of
// these" on a database that simply predates the field.
func TestSchemaVersionIs6(t *testing.T) {
	if SchemaVersion != 6 {
		t.Errorf("SchemaVersion = %d, want 6", SchemaVersion)
	}
}

// Re-putting the same (CVE, Source) replaces rather than duplicates.
// Correctness here rests entirely on the key being identical across both
// Puts -- bbolt overwrites whatever already sits at a key -- so this fails
// if a per-call component (a counter, a timestamp) ever leaked into the key.
func TestPutRating_RepputSameSourceReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	first := advisory.Rating{
		CVE:    "CVE-2025-1",
		Source: "NVD",
		Severity: []advisory.Severity{
			{Type: "CVSS_V31", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"},
		},
	}
	second := advisory.Rating{
		CVE:    "CVE-2025-1",
		Source: "NVD",
		Severity: []advisory.Severity{
			{Type: "CVSS_V31", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
	}
	if err := w.PutRating(first); err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(second); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{}); err != nil {
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
	got, err := db.RatingsFor("CVE-2025-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d ratings, want 1 - a re-Put of the same source must "+
			"replace, not add a second entry", len(got))
	}
	if len(got[0].Severity) != 1 || got[0].Severity[0].Score != second.Severity[0].Score {
		t.Errorf("Severity = %+v, want the SECOND Put's vector (%q) - a repeat "+
			"Put must win over the first", got[0].Severity, second.Severity[0].Score)
	}
}

// TestMetaRatingCountsComesFromStoredRatings mirrors
// TestMetaDatabasesComesFromStoredRecords exactly, one bucket over (D27):
// RatingCounts is read from what PutRating actually stored, keyed on the
// tail of "<CVE>\x00<Source>", not from any caller-supplied value — the same
// "derive it, don't trust self-report" fix Databases already applies to
// Advisory.Database.
func TestMetaRatingCountsComesFromStoredRatings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// NVD rates two CVEs, KISA rates one - deliberately uneven counts, so a
	// mutation that returns "1" for everyone (or the number of DISTINCT
	// CVEs instead of ratings) cannot pass by coincidence.
	for _, r := range []advisory.Rating{
		{CVE: "CVE-2026-1", Source: "NVD"},
		{CVE: "CVE-2026-2", Source: "NVD"},
		{CVE: "CVE-2026-1", Source: "KISA"},
	} {
		if err := w.PutRating(r); err != nil {
			t.Fatal(err)
		}
	}
	// A caller-supplied RatingCounts must be ignored exactly like a
	// caller-supplied Databases already is (TestMetaDatabasesComesFromStoredRecords).
	if err := w.SetMeta(Meta{
		BuiltAt:      time.Now(),
		RatingCounts: map[string]int{"should-be-ignored": 999},
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
	want := map[string]int{"NVD": 2, "KISA": 1}
	if len(m.RatingCounts) != len(want) || m.RatingCounts["NVD"] != 2 || m.RatingCounts["KISA"] != 1 {
		t.Errorf("Meta.RatingCounts = %v, want %v (derived from the ratings bucket, "+
			"caller-supplied value ignored)", m.RatingCounts, want)
	}
	if _, ok := m.RatingCounts["should-be-ignored"]; ok {
		t.Error("Meta.RatingCounts trusted the caller-supplied map instead of deriving it")
	}
}

// TestMetaRatingCountsIgnoresSelfReportedProvenance is the exact defect a
// review of this slice caught: an Annotator's own Provenance.Records is not
// ground truth, so a caller that fills in Meta.Ratings with a self-reported
// count wildly different from what was actually PutRating'd must not make
// RatingCounts (or, downstream, db status's ratings: line) repeat that
// claim. Records here is deliberately 0 for a source that DID rate
// something, and a large positive number for a source that rated nothing at
// all — the two ways self-report can lie in either direction.
func TestMetaRatingCountsIgnoresSelfReportedProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// NVD actually rated one CVE, but will self-report Records: 0 below -
	// the "ran and rated nothing" shape the review flagged.
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2026-9", Source: "NVD"}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{
		BuiltAt: time.Now(),
		Ratings: map[string]Provenance{
			"NVD":  {Records: 0},
			"KISA": {Records: 5000}, // claims 5000 ratings; none were ever PutRating'd
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
	if m.RatingCounts["NVD"] != 1 {
		t.Errorf(`RatingCounts["NVD"] = %d, want 1 - the self-reported Records:0 `+
			"must not suppress what was actually stored", m.RatingCounts["NVD"])
	}
	if _, ok := m.RatingCounts["KISA"]; ok {
		t.Errorf(`RatingCounts["KISA"] = %d present, want absent - KISA self-reported `+
			"5000 but rated nothing; the self-report must not be trusted", m.RatingCounts["KISA"])
	}
}
