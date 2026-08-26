package scancmd

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/source"
)

// osReleaseArch is verbatim from a real mirror.gcr.io/library/archlinux pull
// (measured 2026-08-26): no VERSION_ID at all, only BUILD_ID=rolling.
// Deliberately included here rather than a synthetic os-release with a
// VERSION_ID, so a test using this fixture cannot pass by accident of
// VERSION_ID being present -- distro.go's "arch" case (D97) must route on ID
// alone.
const osReleaseArch = `NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
`

// archDesc renders a minimal but real desc-file body: name, version and
// base, the three fields pacmandb.ParseDesc actually reads.
func archDesc(name, version, base string) string {
	return "%NAME%\n" + name + "\n\n%VERSION%\n" + version + "\n\n%BASE%\n" + base + "\n\n"
}

// archImage wraps one set of tar entries as a single-layer image, mirroring
// rpmImage/apk's own test helpers in this package.
func archImage(t *testing.T, files map[string]string) *source.Image {
	t.Helper()
	return &source.Image{Layers: []source.Layer{imageLayer(t, "sha256:arch", files)}}
}

// TestCatalogFromImage_PacmanPackagesAreKeyed is D97's own version of
// TestCatalogFromImage_PhotonPackagesAreKeyed: a real-shaped pacman local
// database, read through catalogFromImage end to end, proving distro.go's
// "arch" routing is what actually reaches a cataloged package's Ecosystem
// field -- not just what Distro.Ecosystem() returns in isolation
// (pkgmeta's own TestDistroEcosystem_Arch already covers that half) or what
// pacmandb.ParseDesc returns for one file in isolation (pacmandb_test.go
// already covers that half too). Also proves ALPM_DB_VERSION, a sibling
// FILE directly inside local/ that is not a package directory, does not
// become a phantom package.
func TestCatalogFromImage_PacmanPackagesAreKeyed(t *testing.T) {
	img := archImage(t, map[string]string{
		osReleasePath:                             osReleaseArch,
		"var/lib/pacman/local/acl-2.4.0-1/desc":   archDesc("acl", "2.4.0-1", "acl"),
		"var/lib/pacman/local/bash-5.3.15-1/desc": archDesc("bash", "5.3.15-1", "bash"),
		"var/lib/pacman/local/ALPM_DB_VERSION":    "9\n",
	})
	target, stats, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Cataloged != 2 {
		t.Fatalf("cataloged %d packages, want 2 (ALPM_DB_VERSION must not become a package): %+v",
			stats.Cataloged, target.Packages)
	}
	byName := map[string]string{}
	for _, p := range target.Packages {
		byName[p.Name] = p.Version
		if p.Ecosystem != "Arch:rolling" {
			t.Errorf("%s has ecosystem %q, want Arch:rolling", p.Name, p.Ecosystem)
		}
	}
	if got := byName["acl"]; got != "2.4.0-1" {
		t.Errorf("acl version = %q, want 2.4.0-1", got)
	}
	if got := byName["bash"]; got != "5.3.15-1" {
		t.Errorf("bash version = %q, want 5.3.15-1", got)
	}
	if target.Distro == nil || target.Distro.ID != "arch" {
		t.Errorf("Distro = %+v, want ID arch", target.Distro)
	}
}

// TestCatalogFromImage_PacmanBaseDiffersSetsSource is D8's exact analogue,
// driven through the full image-scan pipeline rather than pacmandb.ParseDesc
// alone: libelf's own BASE (elfutils) must reach the cataloged package's
// Source field, which is what makes an elfutils-named advisory reachable
// from an installed libelf package at all.
func TestCatalogFromImage_PacmanBaseDiffersSetsSource(t *testing.T) {
	img := archImage(t, map[string]string{
		osReleasePath: osReleaseArch,
		"var/lib/pacman/local/libelf-0.196-1/desc": archDesc("libelf", "0.196-1", "elfutils"),
	})
	target, _, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("cataloged %d packages, want 1", len(target.Packages))
	}
	p := target.Packages[0]
	if p.Source == nil || p.Source.Name != "elfutils" {
		t.Fatalf("libelf Source = %+v, want Name elfutils", p.Source)
	}
	if p.Source.Version != "" {
		t.Errorf("libelf Source.Version = %q, want empty (D8: pacman BASE carries no version)", p.Source.Version)
	}
}

// TestCatalogFromImage_PacmanSetsLayerDigest proves diffID reaches every
// pacman-cataloged package's Location -- D10's evidence requirement, mirroring
// TestCatalogFromImage_SetsLayerDigestFromTheLayer for apk.
func TestCatalogFromImage_PacmanSetsLayerDigest(t *testing.T) {
	img := archImage(t, map[string]string{
		osReleasePath:                           osReleaseArch,
		"var/lib/pacman/local/acl-2.4.0-1/desc": archDesc("acl", "2.4.0-1", "acl"),
	})
	target, _, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("cataloged %d packages, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Locations[0].LayerDigest; got != "sha256:arch" {
		t.Errorf("LayerDigest = %q, want sha256:arch", got)
	}
	if got := target.Packages[0].Locations[0].Path; got != "var/lib/pacman/local/acl-2.4.0-1/desc" {
		t.Errorf("Location.Path = %q, want the desc file's own tar path", got)
	}
}

// TestCatalogFromImage_PacmanDistroWithNoDatabase mirrors
// TestCatalogFromImage_RPMDistroWithNoDatabase/PhotonDistroWithNoDatabase:
// an Arch image with no pacman database at all must error naming what was
// looked for, never silently catalog zero packages as a clean scan (D11).
func TestCatalogFromImage_PacmanDistroWithNoDatabase(t *testing.T) {
	img := archImage(t, map[string]string{osReleasePath: osReleaseArch})
	_, _, err := catalogFromImage("test-image", img)
	if err == nil {
		t.Fatal("an Arch image with no pacman database was catalogued without error")
	}
	if !strings.Contains(err.Error(), "var/lib/pacman/local") {
		t.Errorf("error %q does not mention the pacman database location", err)
	}
}
