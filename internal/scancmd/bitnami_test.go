package scancmd

import (
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// osReleaseDebian12 is a trimmed real Debian 12 /etc/os-release -- the
// frozen "bitnamilegacy" image base (D99), unlike current Bitnami images
// which are Photon-based (osReleasePhoton5, rpm_test.go).
const osReleaseDebian12 = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
`

// bitnamiSPDXDoc renders a minimal but real-shaped Bitnami SPDX marker: the
// main application, mirroring the trimmed fixture bitnamidb_test.go's own
// realPostgresDoc uses.
func bitnamiSPDXDoc(name, version, distro string) string {
	return `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","packages":[` +
		`{"name":"` + name + `","SPDXID":"SPDXRef-` + name + `","versionInfo":"` + version + `",` +
		`"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",` +
		`"referenceLocator":"pkg:bitnami/` + name + `@` + version + `?arch=amd64&distro=` + distro + `"}]}]}`
}

// TestCatalogFromImage_BitnamiPackagesAlongsideDistro is D99's caller-first
// dual-inventory proof (D7): a Bitnami image is a REAL distro (Photon here,
// via the existing rpmdb fixture rpm_test.go already established) PLUS
// whatever applications Bitnami installed under /opt/bitnami, and one scan
// must report BOTH halves in a single Target -- not just what
// bitnamidb.ParseSPDXMarker returns for one marker file in isolation
// (bitnamidb_test.go already covers that half), and not just what the
// existing Photon rpm path returns on its own
// (TestCatalogFromImage_PhotonPackagesAreKeyed already covers THAT half).
// Deleting the catalogBitnami call in catalogFromImage would leave the
// Photon packages present and silently drop every Bitnami one, which only a
// test that checks for BOTH ecosystems in one Target can catch.
func TestCatalogFromImage_BitnamiPackagesAlongsideDistro(t *testing.T) {
	img := rpmImage(t, map[string]string{
		osReleasePath:              osReleasePhoton5,
		"var/lib/rpm/rpmdb.sqlite": fixtureBytes(t, rpmFixture),
		"opt/bitnami/postgresql/.spdx-postgresql.spdx": bitnamiSPDXDoc("postgresql", "18.6.0-3", "photon-5"),
	})
	target, stats, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	var photonCount, bitnamiCount int
	var bitnamiPkg pkgmeta.Package
	for _, p := range target.Packages {
		switch p.Ecosystem {
		case "Photon OS:5":
			photonCount++
		case "Bitnami":
			bitnamiCount++
			bitnamiPkg = p
		}
	}
	if photonCount != 6 {
		t.Errorf("Photon OS:5 packages = %d, want 6 (the same rpm fixture "+
			"TestCatalogFromImage_PhotonPackagesAreKeyed pins)", photonCount)
	}
	if bitnamiCount != 1 {
		t.Fatalf("Bitnami packages = %d, want 1: %+v", bitnamiCount, target.Packages)
	}
	if bitnamiPkg.Name != "postgresql" || bitnamiPkg.Version != "18.6.0-3" {
		t.Errorf("Bitnami package = %+v, want postgresql 18.6.0-3", bitnamiPkg)
	}
	if len(bitnamiPkg.Locations) != 1 || bitnamiPkg.Locations[0].Path != "opt/bitnami/postgresql/.spdx-postgresql.spdx" {
		t.Errorf("Locations = %+v, want the marker's own tar path", bitnamiPkg.Locations)
	}
	if bitnamiPkg.Locations[0].LayerDigest != "sha256:rpm" {
		t.Errorf("LayerDigest = %q, want sha256:rpm (D10 evidence)", bitnamiPkg.Locations[0].LayerDigest)
	}
	if stats.Cataloged != 7 {
		t.Errorf("stats.Cataloged = %d, want 7 (6 Photon + 1 Bitnami)", stats.Cataloged)
	}
	if target.Distro == nil || target.Distro.ID != "photon" {
		t.Errorf("Distro = %+v, want ID photon -- Bitnami is not a distro and must not override it", target.Distro)
	}
}

// TestCatalogFromImage_BitnamiLegacyFallbackDedupedAgainstSPDX drives the
// legacy-JSON path through the full image pipeline, and pins the dedup rule
// bitnamidb.Merge's own tests cover in isolation: a real legacy image
// carries BOTH the JSON and an SPDX marker naming the identical (name,
// version) pair, and the merged inventory must count it once, not twice.
func TestCatalogFromImage_BitnamiLegacyFallbackDedupedAgainstSPDX(t *testing.T) {
	img := rpmImage(t, map[string]string{
		osReleasePath: osReleaseDebian12,
		dpkgDBPath: "Package: bash\n" +
			"Status: install ok installed\n" +
			"Version: 5.2.15-2+b13\n\n",
		"opt/bitnami/postgresql/.spdx-postgresql.spdx": bitnamiSPDXDoc("postgresql", "17.5.0-14", "debian-12"),
		bitnamiLegacyPath: `{"postgresql":{"arch":"amd64","distro":"debian-12","type":"NAMI","version":"17.5.0-14"}}`,
	})
	target, _, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	var bitnamiCount int
	for _, p := range target.Packages {
		if p.Ecosystem == "Bitnami" {
			bitnamiCount++
			if p.Name != "postgresql" || p.Version != "17.5.0-14" {
				t.Errorf("Bitnami package = %+v, want postgresql 17.5.0-14", p)
			}
		}
	}
	if bitnamiCount != 1 {
		t.Fatalf("Bitnami packages = %d, want exactly 1 (the SPDX marker and the legacy JSON "+
			"name the identical (name, version) pair and must be deduped): %+v", bitnamiCount, target.Packages)
	}
}

// TestCatalogFromImage_BitnamiAbsentIsNotAnError proves an ordinary,
// non-Bitnami image is unaffected: /opt/bitnami simply does not exist, and
// that must not be an error the way an rpm distro with no database is.
func TestCatalogFromImage_BitnamiAbsentIsNotAnError(t *testing.T) {
	img := rpmImage(t, map[string]string{
		osReleasePath:              osReleasePhoton5,
		"var/lib/rpm/rpmdb.sqlite": fixtureBytes(t, rpmFixture),
	})
	target, stats, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Cataloged != 6 {
		t.Errorf("stats.Cataloged = %d, want 6 (unchanged from the Photon-only case)", stats.Cataloged)
	}
	for _, p := range target.Packages {
		if p.Ecosystem == "Bitnami" {
			t.Errorf("a Bitnami package was catalogued from an image with no /opt/bitnami: %+v", p)
		}
	}
}
