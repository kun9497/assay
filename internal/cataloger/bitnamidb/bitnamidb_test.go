package bitnamidb

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// realPostgresDoc is a trimmed shape of the real
// opt/bitnami/postgresql/.spdx-postgresql.spdx marker pulled from
// docker.io/bitnami/postgresql:latest (Photon 5, 2026-08-27): the main
// application, one bundled C library (geos), and one bundled Java library
// whose OWN purl is Maven, not Bitnami — the exact shape D99 says must be
// dropped.
const realPostgresDoc = `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3",
  "name":"SPDX document for PostgreSQL 18.6.0",
  "packages":[
    {"name":"postgresql","SPDXID":"SPDXRef-postgresql","versionInfo":"18.6.0-3",
     "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
       "referenceLocator":"pkg:bitnami/postgresql@18.6.0-3?arch=amd64&distro=photon-5"}]},
    {"name":"geos","SPDXID":"SPDXRef-geos","versionInfo":"3.14.1",
     "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
       "referenceLocator":"pkg:bitnami/geos@3.14.1?arch=amd64&distro=photon-5"}]},
    {"name":"org.postgresql:pljava","SPDXID":"SPDXRef-Package-pljava","versionInfo":"1.6.10",
     "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
       "referenceLocator":"pkg:maven/org.postgresql/pljava@1.6.10"}]}
  ],
  "relationships":[
    {"spdxElementId":"SPDXRef-postgresql","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-geos"}
  ]}`

// TestParseSPDXMarker_BundledLibAlongsideMainApp is the caller-first proof
// that ParseSPDXMarker returns the main application AND its bundled library
// from one marker document -- not just the app spdx.Parse's own tests
// already cover generically. Deleting bitnamidb's own filter-and-relocate
// step (calling spdx.Parse directly and returning target.Packages
// unfiltered) would let the Maven pljava entry through too, which the
// second half of this test catches.
func TestParseSPDXMarker_BundledLibAlongsideMainApp(t *testing.T) {
	pkgs, err := ParseSPDXMarker(strings.NewReader(realPostgresDoc), "opt/bitnami/postgresql/.spdx-postgresql.spdx")
	if err != nil {
		t.Fatalf("ParseSPDXMarker: %v", err)
	}
	byName := map[string]pkgmeta.Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	pg, ok := byName["postgresql"]
	if !ok {
		t.Fatalf("postgresql not catalogued; have %+v", pkgs)
	}
	if pg.Ecosystem != "Bitnami" || pg.Version != "18.6.0-3" {
		t.Errorf("postgresql = %+v, want Ecosystem=Bitnami Version=18.6.0-3", pg)
	}
	if len(pg.Locations) != 1 || pg.Locations[0].Path != "opt/bitnami/postgresql/.spdx-postgresql.spdx" {
		t.Errorf("postgresql.Locations = %+v, want the marker's own path, not spdx.Parse's \"sbom\" placeholder", pg.Locations)
	}
	geos, ok := byName["geos"]
	if !ok {
		t.Fatalf("bundled library geos not catalogued alongside the main app; have %+v", pkgs)
	}
	if geos.Ecosystem != "Bitnami" || geos.Version != "3.14.1" {
		t.Errorf("geos = %+v, want Ecosystem=Bitnami Version=3.14.1", geos)
	}
	if _, ok := byName["org.postgresql:pljava"]; ok {
		t.Error("org.postgresql:pljava was catalogued, want it dropped -- D99 keeps only pkg:bitnami-purled packages")
	}
	if len(pkgs) != 2 {
		t.Errorf("len(pkgs) = %d, want exactly 2 (postgresql + geos, pljava dropped): %+v", len(pkgs), pkgs)
	}
}

func TestParseSPDXMarker_MalformedDocument(t *testing.T) {
	if _, err := ParseSPDXMarker(strings.NewReader("not json"), "opt/bitnami/x/.spdx-x.spdx"); err == nil {
		t.Error("ParseSPDXMarker(malformed) = nil error, want one")
	}
}

const legacyJSON = `{"postgresql":{"arch":"amd64","distro":"debian-12","type":"NAMI","version":"17.5.0-14"}}`

func TestParseLegacyComponents(t *testing.T) {
	pkgs, err := ParseLegacyComponents(strings.NewReader(legacyJSON), "opt/bitnami/.bitnami_components.json")
	if err != nil {
		t.Fatalf("ParseLegacyComponents: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("len(pkgs) = %d, want 1: %+v", len(pkgs), pkgs)
	}
	p := pkgs[0]
	if p.Name != "postgresql" || p.Version != "17.5.0-14" || p.Ecosystem != "Bitnami" {
		t.Errorf("package = %+v, want Name=postgresql Version=17.5.0-14 Ecosystem=Bitnami", p)
	}
	if len(p.Locations) != 1 || p.Locations[0].Path != "opt/bitnami/.bitnami_components.json" {
		t.Errorf("Locations = %+v, want the json file's own path", p.Locations)
	}
}

func TestParseLegacyComponents_NoVersionIsSkipped(t *testing.T) {
	pkgs, err := ParseLegacyComponents(strings.NewReader(`{"broken":{"type":"NAMI"}}`), "path")
	if err != nil {
		t.Fatalf("ParseLegacyComponents: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("pkgs = %+v, want empty -- a component with no version cannot be evaluated", pkgs)
	}
}

func TestParseLegacyComponents_SortedByName(t *testing.T) {
	const doc = `{"zeta":{"version":"1.0.0"},"alpha":{"version":"2.0.0"}}`
	pkgs, err := ParseLegacyComponents(strings.NewReader(doc), "path")
	if err != nil {
		t.Fatalf("ParseLegacyComponents: %v", err)
	}
	if len(pkgs) != 2 || pkgs[0].Name != "alpha" || pkgs[1].Name != "zeta" {
		t.Errorf("pkgs = %+v, want [alpha, zeta] in sorted order", pkgs)
	}
}

func TestParseLegacyComponents_MalformedDocument(t *testing.T) {
	if _, err := ParseLegacyComponents(strings.NewReader("not json"), "path"); err == nil {
		t.Error("ParseLegacyComponents(malformed) = nil error, want one")
	}
}

// TestMerge_DedupesIdenticalNameAndVersion pins D99's measured shape: a real
// legacy image carries the SAME (name, version) pair in BOTH its SPDX marker
// and its legacy JSON, and Merge must count it once, keeping the SPDX side
// (which also carries Locations pointed at the richer document).
func TestMerge_DedupesIdenticalNameAndVersion(t *testing.T) {
	spdxPkgs := []pkgmeta.Package{
		{Name: "postgresql", Version: "17.5.0-14", Ecosystem: "Bitnami",
			Locations: []pkgmeta.Location{{Path: "opt/bitnami/postgresql/.spdx-postgresql.spdx"}}},
	}
	legacyPkgs := []pkgmeta.Package{
		{Name: "postgresql", Version: "17.5.0-14", Ecosystem: "Bitnami",
			Locations: []pkgmeta.Location{{Path: "opt/bitnami/.bitnami_components.json"}}},
	}
	got := Merge(spdxPkgs, legacyPkgs)
	if len(got) != 1 {
		t.Fatalf("Merge = %+v, want exactly 1 (deduped)", got)
	}
	if got[0].Locations[0].Path != "opt/bitnami/postgresql/.spdx-postgresql.spdx" {
		t.Errorf("Merge kept the wrong side's Location: %+v, want the SPDX marker's path", got[0].Locations)
	}
}

// TestMerge_LegacyOnlyComponentSurvives proves the "always read both" rule
// actually adds coverage rather than being a no-op dedup pass: a component
// the JSON names but no SPDX marker in the image covers must still reach the
// inventory.
func TestMerge_LegacyOnlyComponentSurvives(t *testing.T) {
	spdxPkgs := []pkgmeta.Package{
		{Name: "postgresql", Version: "17.5.0-14", Ecosystem: "Bitnami"},
	}
	legacyPkgs := []pkgmeta.Package{
		{Name: "postgresql", Version: "17.5.0-14", Ecosystem: "Bitnami"},
		{Name: "some-other-component", Version: "1.0.0", Ecosystem: "Bitnami"},
	}
	got := Merge(spdxPkgs, legacyPkgs)
	if len(got) != 2 {
		t.Fatalf("Merge = %+v, want 2 (postgresql deduped, some-other-component kept)", got)
	}
	names := map[string]bool{}
	for _, p := range got {
		names[p.Name] = true
	}
	if !names["some-other-component"] {
		t.Error("some-other-component was dropped; the legacy-only component must survive Merge")
	}
}

// TestMerge_DifferentVersionsAreNotDeduped proves the dedup key is (name,
// version), not name alone -- two different versions of the same-named
// component (which should never happen for one image, but Merge itself must
// not silently collapse it) both survive.
func TestMerge_DifferentVersionsAreNotDeduped(t *testing.T) {
	spdxPkgs := []pkgmeta.Package{{Name: "postgresql", Version: "18.6.0-3", Ecosystem: "Bitnami"}}
	legacyPkgs := []pkgmeta.Package{{Name: "postgresql", Version: "17.5.0-14", Ecosystem: "Bitnami"}}
	got := Merge(spdxPkgs, legacyPkgs)
	if len(got) != 2 {
		t.Errorf("Merge = %+v, want 2 (different versions are different packages)", got)
	}
}
