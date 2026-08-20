package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

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

// TestLookup_PrefixEndsAtTheSeparator is D67's composite-key substring
// hazard, written first because Lookup is the CALLER whose behaviour the
// key format has to hold, not advisoryIndexPrefix in isolation: "openssl" is
// a byte-prefix of "openssl-foo", so a Seek prefix built without the
// trailing keySep would let a lookup for the shorter name also return the
// longer name's advisories -- CLAUDE.md's substring-collision class, moved
// into the index's key space (the plan's own words for it). bytes.HasPrefix
// bounding the cursor walk is the other half: dropping it would continue
// past this package's own keys into whatever sorts next in the bucket.
func TestLookup_PrefixEndsAtTheSeparator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "ALPINE-2025-0001", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Alpine:v3.19", Name: "openssl"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "ALPINE-2025-0002", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Alpine:v3.19", Name: "openssl-foo"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{BuiltAt: time.Now()}); err != nil {
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
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "ALPINE-2025-0001" {
		t.Errorf("Lookup(openssl) = %+v, want exactly ALPINE-2025-0001 -- a Seek prefix "+
			"missing its trailing separator would also return openssl-foo's advisory", got)
	}

	got, err = db.Lookup("Alpine:v3.19", "openssl-foo")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "ALPINE-2025-0002" {
		t.Errorf("Lookup(openssl-foo) = %+v, want exactly ALPINE-2025-0002 -- its own "+
			"advisory, not the shorter name's leaking the other way", got)
	}
}

// TestPut_RepeatedPutDoesNotDuplicateIndexEntry is D67's dedup guarantee
// exercised through Put directly rather than PutMany's batch (which
// TestPutMany_MatchesPutExactly already covers with a duplicate-ID row): a
// blind composite-key Put overwrites the same nil value on a repeat, so
// re-Putting one advisory must not make Lookup return it twice.
func TestPut_RepeatedPutDoesNotDuplicateIndexEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	a := sample("GHSA-repeat", "Go", "example.com/z")
	if err := w.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(a); err != nil { // the exact same advisory, re-Put
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{BuiltAt: time.Now()}); err != nil {
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
	got, err := db.Lookup("Go", "example.com/z")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("Lookup after two Puts of the same advisory = %d entries, want 1 -- "+
			"a re-Put must overwrite the same composite key, not add a second one", len(got))
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

// buildOldShapedFixture writes a bolt file directly through go.etcd.io/bbolt,
// bypassing every method on Bolt, in the PRE-D67 shape: bucketAdvisories
// keyed on "<eco>\x00<name>" with a JSON array of advisory IDs as its value
// -- exactly what a real database built before this slice looks like on
// disk. Nothing reachable through Create/Put can produce that shape any
// more once D67 lands, which is the whole reason this test writes the file
// by hand instead of building it through the store package's own API and
// then only patching the schema number: a fixture built that way would have
// the CURRENT (composite-key) index shape underneath an old schema label,
// proving nothing about whether a caller opening a real old artifact is
// safe.
func buildOldShapedFixture(t *testing.T, path string, advs []advisory.Advisory, ratings []advisory.Rating, schema int) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		byID := tx.Bucket(bucketByID)
		idx := tx.Bucket(bucketAdvisories)
		oldIndex := map[string][]string{}
		for _, a := range advs {
			blob, err := json.Marshal(a)
			if err != nil {
				return err
			}
			if err := byID.Put([]byte(a.ID), blob); err != nil {
				return err
			}
			for _, aff := range a.Affected {
				key := aff.Ecosystem + keySep + aff.Name
				oldIndex[key] = append(oldIndex[key], a.ID)
			}
		}
		for key, ids := range oldIndex {
			blob, err := json.Marshal(ids)
			if err != nil {
				return err
			}
			if err := idx.Put([]byte(key), blob); err != nil {
				return err
			}
		}
		ratingsBk := tx.Bucket(bucketRatings)
		for _, r := range ratings {
			blob, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if err := ratingsBk.Put([]byte(r.CVE+keySep+r.Source), blob); err != nil {
				return err
			}
		}
		metaBlob, err := json.Marshal(Meta{Schema: schema, BuiltAt: time.Now()})
		if err != nil {
			return err
		}
		return tx.Bucket(bucketMeta).Put([]byte("meta"), metaBlob)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestOpenSeedRatings_AcceptsOneSchemaBehind is the D67 bootstrap hazard
// (SchemaVersion's own doc comment, and dbcmd.Update's ratings-copy block):
// a v(N-1) artifact's ratings bucket did not change shape in the bump to N,
// so its ratings must still be readable even though its advisories index
// -- old JSON-array shaped in this fixture, exactly as a real one would be
// -- is not something this binary's Lookup could walk.
func TestOpenSeedRatings_AcceptsOneSchemaBehind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n-minus-1-seed.db")
	buildOldShapedFixture(t, path,
		[]advisory.Advisory{sample("GHSA-old-shape", "Go", "old")},
		[]advisory.Rating{{CVE: "CVE-2026-SEED", Source: "NVD"}},
		SchemaVersion-1)

	db, err := OpenSeedRatings(path)
	if err != nil {
		t.Fatalf("OpenSeedRatings(schema %d) = %v, want a database one schema "+
			"behind this binary's to open for ratings", SchemaVersion-1, err)
	}
	defer db.Close()

	got, err := db.RatingsFor("CVE-2026-SEED")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("RatingsFor(CVE-2026-SEED) = %+v, want the one seeded rating", got)
	}

	var n int
	if err := db.EachRating(func(advisory.Rating) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("EachRating visited %d ratings, want 1 -- this is what dbcmd.Update's "+
			"ratings-copy block actually calls against a seed", n)
	}
}

// TestOpenSeedRatings_RefusesTwoSchemasBehind: N-2 is refused exactly like
// Open refuses it. See OpenSeedRatings' own doc comment for why nothing
// widens the tolerance further just because N-1 turned out to be safe --
// this pins that the boundary is exactly one schema, not "old enough that
// nobody has one any more".
func TestOpenSeedRatings_RefusesTwoSchemasBehind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n-minus-2-seed.db")
	buildOldShapedFixture(t, path, nil,
		[]advisory.Rating{{CVE: "CVE-2026-TOO-OLD", Source: "NVD"}},
		SchemaVersion-2)

	if _, err := OpenSeedRatings(path); !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("OpenSeedRatings(schema %d) err = %v, want ErrSchemaMismatch", SchemaVersion-2, err)
	}
}

// TestOpenSeedRatings_RefusesNewerSchema pins the boundary from the other
// side: the whitelist above is exactly {N, N-1}, held from below by
// TestOpenSeedRatings_AcceptsOneSchemaBehind (N-1 accepted) and
// TestOpenSeedRatings_RefusesTwoSchemasBehind (N-2 refused), but nothing
// ever fed it a NEWER-than-binary seed. A future v(N+1) seed's ratings
// bucket carries no contract this binary has ever read -- the identical
// hazard TestOpenSchemaMismatch pins for Open, one function over -- so a
// whitelist collapsed to "anything from N-2 or older is refused" (which
// happens to also satisfy every case below it) would silently accept one.
func TestOpenSeedRatings_RefusesNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n-plus-1-seed.db")
	buildOldShapedFixture(t, path, nil,
		[]advisory.Rating{{CVE: "CVE-2026-TOO-NEW", Source: "NVD"}},
		SchemaVersion+1)

	db, err := OpenSeedRatings(path)
	if db != nil {
		defer db.Close()
	}
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("OpenSeedRatings(schema %d) err = %v, want ErrSchemaMismatch", SchemaVersion+1, err)
	}
}

// TestOpenSeedRatings_AcceptsCurrentSchema is the ordinary case outside a
// bootstrap: a same-schema seed must not become collateral damage from
// loosening the N-1 case above it.
func TestOpenSeedRatings_AcceptsCurrentSchema(t *testing.T) {
	path := buildTestDB(t, sample("GHSA-current", "Go", "x"))
	db, err := OpenSeedRatings(path)
	if err != nil {
		t.Fatalf("OpenSeedRatings on a current-schema database = %v, want nil", err)
	}
	db.Close()
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

// One CVE ID is a byte prefix of another -- CVE-2025-1 of CVE-2025-10 -- so
// a Seek over "<CVE>" without the separator, or a scan that forgets to stop
// at the end of the prefix, hands back a NEIGHBOUR's rating. That is not a
// cosmetic leak: the matcher feeds every rating to beats(), which takes the
// highest band, so an unrelated CVE's critical becomes this finding's
// severity and can push a scan over --fail-on. It is CLAUDE.md's substring
// hazard moved into the key space.
//
// No other fixture in this package puts more than one CVE in a database, so
// until this existed both guards in RatingsFor were unheld: dropping keySep
// from the prefix, and dropping the bytes.HasPrefix bound from the loop
// condition, each left the entire repository green.
func TestRatingsFor_DoesNotBleedAcrossCVEsSharingAPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, _ := Create(path)
	// CVE-2025-10 sorts immediately after CVE-2025-1 under a bare-prefix
	// Seek, so it is what an unbounded scan reaches first.
	for _, r := range []advisory.Rating{
		{CVE: "CVE-2025-1", Source: "NVD", URL: "own"},
		{CVE: "CVE-2025-10", Source: "NVD", URL: "neighbour"},
		{CVE: "CVE-2025-100", Source: "KISA", URL: "neighbour"},
	} {
		if err := w.PutRating(r); err != nil {
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
	// Asserted on the URL, not the source: "NVD" appears on the neighbour
	// too, so a count-plus-source check would pass on the wrong row.
	if len(got) != 1 || got[0].URL != "own" {
		t.Errorf("RatingsFor(CVE-2025-1) = %+v, want exactly the one rating whose URL is %q", got, "own")
	}
	// And the longer ID still finds its own, so the fix is a boundary rather
	// than an over-strict match.
	if got, err := db.RatingsFor("CVE-2025-10"); err != nil {
		t.Fatal(err)
	} else if len(got) != 1 || got[0].CVE != "CVE-2025-10" {
		t.Errorf("RatingsFor(CVE-2025-10) = %+v, want its own single rating", got)
	}
}

// Schema 9. A v8 database must be refused by Open rather than read with a
// cursor walk that silently finds nothing against its old JSON-array index
// (D67).
func TestSchemaVersionIs9(t *testing.T) {
	if SchemaVersion != 9 {
		t.Errorf("SchemaVersion = %d, want 9", SchemaVersion)
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

// Enrichment is keyed (CVE, Source) exactly as ratings are, so two sources
// can describe one CVE and re-putting one replaces rather than duplicates.
func TestPutEnrichment_RoundTripsAndReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []advisory.Enrichment{
		{CVE: "CVE-2026-1", Source: "KISA", Title: "첫 번째", Summary: "요약", URL: "https://example.test/1"},
		{CVE: "CVE-2026-1", Source: "KISA", Title: "고쳐 쓴 제목", Summary: "요약", URL: "https://example.test/1"},
		{CVE: "CVE-2026-10", Source: "KISA", Title: "이웃", Summary: "요약", URL: "https://example.test/10"},
	} {
		if err := w.PutEnrichment(e); err != nil {
			t.Fatal(err)
		}
	}
	w.SetMeta(Meta{})
	w.Close()

	db, _ := Open(path)
	defer db.Close()

	got, err := db.EnrichmentFor("CVE-2026-1")
	if err != nil {
		t.Fatal(err)
	}
	// One record, the second Put having replaced the first. Asserted on the
	// title, because the CVE and Source are what the key is made of and
	// would match either way.
	if len(got) != 1 || got[0].Title != "고쳐 쓴 제목" {
		t.Errorf("EnrichmentFor(CVE-2026-1) = %+v, want exactly the replaced record", got)
	}
	// CVE-2026-1 is a byte prefix of CVE-2026-10. The same trap RatingsFor
	// has: without the separator in the seek prefix, or without the
	// HasPrefix bound, the neighbour bleeds in.
	if got[0].URL != "https://example.test/1" {
		t.Errorf("EnrichmentFor(CVE-2026-1) returned the neighbour: %+v", got)
	}
	if got, err := db.EnrichmentFor("CVE-2026-10"); err != nil {
		t.Fatal(err)
	} else if len(got) != 1 || got[0].Title != "이웃" {
		t.Errorf("EnrichmentFor(CVE-2026-10) = %+v, want its own record", got)
	}
}

// An unenriched CVE is a normal answer, not a failure: the matcher asks for
// every finding and most CVEs have no Korean notice.
func TestEnrichmentFor_UnknownCVEIsEmptyNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, _ := Create(path)
	w.SetMeta(Meta{})
	w.Close()
	db, _ := Open(path)
	defer db.Close()
	got, err := db.EnrichmentFor("CVE-2026-999")
	if err != nil {
		t.Fatalf("EnrichmentFor returned an error for an unenriched CVE: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("EnrichmentFor = %+v, want empty", got)
	}
}

// StripEnrichment followed by CompactInto is the whole of D29's publish-side
// guarantee, and the assertions here are on the resulting BYTES rather than
// on what the bucket API answers about them.
//
// Reading it back through EnrichmentFor is what let the sixth bypass through:
// bbolt's DeleteBucket frees the pages holding those records without zeroing
// them, so a stripped-in-place file answers "nothing" to every query while
// the Korean text is still legible in it — and dbartifact.Pack gzips the
// whole file. So this checks the file the same way `gunzip | strings` would.
//
// Both halves are asserted, because either alone is wrong: the strip alone
// leaves the bytes behind, and the compaction alone faithfully copies live
// records across.
func TestCompactInto_LeavesNoStrippedBytesBehind(t *testing.T) {
	const secret = "원격의 공격자가 임의 코드를 실행할 수 있는 취약점"
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	w, err := Create(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(sample("ALPINE-2025-0001", "Alpine:v3.19", "openssl")); err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2025-46394", Source: "NVD"}); err != nil {
		t.Fatal(err)
	}
	// Enough records that no amount of page reuse during the strip's own
	// metadata rewrite could account for a clean result.
	for i := 0; i < 200; i++ {
		if err := w.PutEnrichment(advisory.Enrichment{
			CVE: fmt.Sprintf("CVE-2025-9%04d", i), Source: "KISA", Summary: secret,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetMeta(Meta{BuiltAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if err := StripEnrichment(src); err != nil {
		t.Fatal(err)
	}
	// The premise, checked rather than assumed: if a stripped file already
	// held none of these bytes, the compaction below would be proving nothing
	// and this test would pass for the wrong reason forever.
	if n := countInFile(t, src, secret); n == 0 {
		t.Fatalf("the stripped file already holds no copy of the enrichment text, so this test "+
			"cannot show that CompactInto is what removes it -- either bbolt stopped leaving "+
			"freed pages intact, or %s is no longer what the records carry", secret)
	}

	dst := filepath.Join(dir, "dst.db")
	if err := CompactInto(dst, src); err != nil {
		t.Fatal(err)
	}
	if n := countInFile(t, dst, secret); n != 0 {
		t.Errorf("the compacted file holds %d copies of the enrichment text: CompactInto copied "+
			"more than the live data, and everything it produces is published", n)
	}

	// ...and it is still the database. A CompactInto that produced an empty
	// file would satisfy the scan above.
	db, err := Open(dst)
	if err != nil {
		t.Fatalf("the compacted database does not open: %v", err)
	}
	defer db.Close()
	if got, err := db.Lookup("Alpine:v3.19", "openssl"); err != nil || len(got) != 1 {
		t.Errorf("Lookup on the compacted database = %v, %v; the compaction dropped the advisories", got, err)
	}
	if got, err := db.RatingsFor("CVE-2025-46394"); err != nil || len(got) != 1 {
		t.Errorf("RatingsFor on the compacted database = %v, %v; the compaction dropped the ratings", got, err)
	}
	// The enrichment bucket must still EXIST, empty. EnrichmentFor
	// dereferences it directly, so a compacted database missing it panics on
	// the first lookup a puller makes rather than answering "nothing".
	got, err := db.EnrichmentFor("CVE-2025-90000")
	if err != nil {
		t.Errorf("EnrichmentFor on the compacted database errored (%v); the empty bucket did not survive", err)
	}
	if len(got) != 0 {
		t.Errorf("EnrichmentFor on the compacted database = %+v, want empty", got)
	}
}

// CompactInto refuses to write into a file that already exists: bbolt's
// Compact CREATES each bucket as it walks, so a second run into the same path
// fails partway and leaves a half-written database behind rather than saying
// so up front.
//
// The assertion is on the message CompactInto itself produces, not on the
// words "already exists". bbolt's own failure ("bucket already exists",
// raised mid-walk) contains that phrase too, so the first version of this
// test passed with the guard deleted -- found by deleting it. The phrase
// "compact into" appears only in the up-front refusal: the wrapped bbolt
// error reads "compact <src> into <dst>", with the paths in between.
func TestCompactInto_RefusesAnExistingDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	w, err := Create(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(Meta{BuiltAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst.db")
	if err := CompactInto(dst, src); err != nil {
		t.Fatal(err)
	}
	err = CompactInto(dst, src)
	if err == nil {
		t.Fatal("CompactInto into an existing file succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "compact into") || !strings.Contains(err.Error(), "file already exists") {
		t.Errorf("CompactInto error = %q, want its own up-front refusal (\"compact into <dst>: file "+
			"already exists\") rather than a bbolt error raised partway through the walk", err)
	}
}

// countInFile reports how many times text appears in the raw bytes of path --
// the same view dbartifact.Pack takes of a database, and the one every
// bucket-level assertion about D29 cannot see.
func countInFile(t *testing.T, path, text string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(raw, []byte(text))
}
