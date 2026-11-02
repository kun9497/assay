package dbcmd

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// ratingsOnlySeedEOL is the seed's one EOL row. Every field is distinct from
// freshEOLRow's, so a reflect.DeepEqual against either cannot pass on the
// other's value.
var ratingsOnlySeedEOL = store.EOLRelease{
	DistroID: "alpine", Release: "3.17", EOLFrom: "2024-11-22",
	EOLLabel: "seed-catalog-label",
}

var ratingsOnlySeedEOLProv = store.Provenance{
	Source:   "https://example.test/seed-eol-catalog",
	DataAsOf: time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC),
	Records:  1,
}

var ratingsOnlySeedKNVDProv = store.Provenance{
	Source:   "https://example.test/seed-knvd",
	DataAsOf: time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC),
	Records:  1,
}

// ratingsOnlyMetaSeed is a seed database holding what a ratings-only build
// file-copies (D66) and must therefore keep the provenance of: one
// advisory, one EOL row with its provenance, and one enrichment record with
// its provenance.
func ratingsOnlyMetaSeed(t *testing.T) string {
	t.Helper()
	seed := filepath.Join(t.TempDir(), "seed.db")
	w, err := store.Create(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "GHSA-ro-eol", Database: "GHSA", Source: "osv", Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{Ecosystem: "Go", Name: "a"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.PutEnrichment(advisory.Enrichment{CVE: "CVE-2026-0101", Source: "KNVD", Title: "seed prose"}); err != nil {
		t.Fatal(err)
	}
	prov := ratingsOnlySeedEOLProv
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{
			"osv": {Source: "https://example.test/seed-osv", Ecosystems: []string{"Go"}, Records: 1},
		},
		Enrichment:    map[string]store.Provenance{"KNVD": ratingsOnlySeedKNVDProv},
		EOL:           []store.EOLRelease{ratingsOnlySeedEOL},
		EOLProvenance: &prov,
	}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return seed
}

func ratingsOnlyBuildMeta(t *testing.T, seed string, enrichers []provider.Enricher, eol provider.EOLSource) store.Meta {
	t.Helper()
	a := fakeAnnotator{name: "NVD", ratings: []advisory.Rating{{CVE: "CVE-2026-0202", Source: "NVD"}}}
	dst := filepath.Join(t.TempDir(), "vulnerability.db")
	var out, errOut bytes.Buffer
	if code := Update(context.Background(), dst, seed, "", true,
		nil, []provider.Annotator{a}, enrichers, eol, &out, &errOut); code != 0 {
		t.Fatalf("Update --ratings-only = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	db, err := store.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m, err := db.Meta()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Audit 2026-10-22 P4, re-verified 2026-11-02: a ratings-only build with no
// EOL source configured (EOL_ENABLE=0) wrote a fresh Meta over the seed's,
// so the seed's EOL catalog was gone and --fail-on-eol on the result warned
// instead of gating. The advisories are the seed's (D66); so is the catalog
// judged against them, until a configured source replaces it.
func TestUpdate_RatingsOnlyWithoutEOLSourceKeepsTheSeedsCatalog(t *testing.T) {
	m := ratingsOnlyBuildMeta(t, ratingsOnlyMetaSeed(t), nil, nil)

	if want := []store.EOLRelease{ratingsOnlySeedEOL}; !reflect.DeepEqual(m.EOL, want) {
		t.Errorf("Meta.EOL = %+v, want the seed's %+v", m.EOL, want)
	}
	if m.EOLProvenance == nil {
		t.Fatal("Meta.EOLProvenance = nil, want the seed's -- nil reads as \"no EOL source ever ran\"")
	}
	if !reflect.DeepEqual(*m.EOLProvenance, ratingsOnlySeedEOLProv) {
		t.Errorf("Meta.EOLProvenance = %+v, want the seed's %+v", *m.EOLProvenance, ratingsOnlySeedEOLProv)
	}
}

// A configured EOL source still wins: carrying the seed's catalog is the
// fallback for a build that fetched none, never a merge with a fresh one.
func TestUpdate_RatingsOnlyWithEOLSourceReplacesTheSeedsCatalog(t *testing.T) {
	fresh := store.EOLRelease{DistroID: "debian", Release: "12", EOLFrom: "2026-07-11", EOLLabel: "fresh-catalog-label"}
	m := ratingsOnlyBuildMeta(t, ratingsOnlyMetaSeed(t), nil,
		fakeEOLSource{name: "endoflife.date", rows: []store.EOLRelease{fresh}})

	if want := []store.EOLRelease{fresh}; !reflect.DeepEqual(m.EOL, want) {
		t.Errorf("Meta.EOL = %+v, want only the fresh %+v", m.EOL, want)
	}
	if m.EOLProvenance == nil || m.EOLProvenance.Source != "https://example.test/eol" {
		t.Errorf("Meta.EOLProvenance = %+v, want the fresh source's", m.EOLProvenance)
	}
}

// The enrichment bucket rides the same file copy, so its provenance must
// too: otherwise `db status` shows the seed's Korean prose with no DATA AS OF
// (a derived-only row), as if no source had vouched for it.
func TestUpdate_RatingsOnlyKeepsTheSeedsEnrichmentProvenance(t *testing.T) {
	m := ratingsOnlyBuildMeta(t, ratingsOnlyMetaSeed(t), nil, nil)
	if got, ok := m.Enrichment["KNVD"]; !ok || !reflect.DeepEqual(got, ratingsOnlySeedKNVDProv) {
		t.Errorf("Meta.Enrichment[KNVD] = %+v (present %v), want the seed's %+v", got, ok, ratingsOnlySeedKNVDProv)
	}
	if got := m.EnrichmentCounts["KNVD"]; got != 1 {
		t.Errorf("EnrichmentCounts[KNVD] = %d, want 1 (the seed's record, file-copied)", got)
	}
}

// An enricher that does run this time replaces its own entry, as it does on
// every other build.
func TestUpdate_RatingsOnlyRunningEnricherReplacesItsEntry(t *testing.T) {
	e := fakeEnricher{name: "KNVD", records: []advisory.Enrichment{{CVE: "CVE-2026-0303", Source: "KNVD", Title: "fresh"}}}
	m := ratingsOnlyBuildMeta(t, ratingsOnlyMetaSeed(t), []provider.Enricher{e}, nil)
	if got := m.Enrichment["KNVD"].Source; got != "https://example.test/knvd" {
		t.Errorf("Meta.Enrichment[KNVD].Source = %q, want the fresh run's", got)
	}
}
