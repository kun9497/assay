package store

import (
	"errors"
	"path/filepath"
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
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
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

func TestLookupBySource(t *testing.T) {
	a := advisory.Advisory{
		ID:     "ALPINE-CVE-1",
		Source: "osv",
		Kind:   advisory.KindVulnerability,
		Affected: []advisory.Affected{
			{Ecosystem: "Alpine:v3.19", Name: "apache2"},
		},
	}
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutSourceIndex("Alpine:v3.19", "apache2", a.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	got, err := db.LookupBySource("Alpine:v3.19", "apache2")
	if err != nil {
		t.Fatalf("LookupBySource: %v", err)
	}
	if len(got) != 1 || got[0].ID != "ALPINE-CVE-1" {
		t.Errorf("LookupBySource = %+v, want ALPINE-CVE-1", got)
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

func TestOpenSchemaMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.setSchemaForTest(SchemaVersion + 1); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("Open(mismatched) err = %v, want ErrSchemaMismatch", err)
	}
}
