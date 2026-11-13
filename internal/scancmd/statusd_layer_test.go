package scancmd

import (
	"context"
	"testing"

	"github.com/kun9497/assay/internal/source"
)

// Main QA of ef0bc1a (2026-11-13): a distroless image's status.d stanzas
// arrive one per layer, and the report had put the first stanza's layer on
// every package. Each package's location names the layer its own stanza
// came from; the single-file dpkg status still names its one layer.
func TestCatalogFromImage_StatusDPackagesCarryTheirOwnLayer(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:layer-a", map[string]string{osReleasePath: osReleaseDebian12Bookworm, dpkgStatusDir + "/base-files": stanzaOf("base-files", "12.4+deb12u9")}),
		imageLayer(t, "sha256:layer-b", map[string]string{dpkgStatusDir + "/tzdata": stanzaOf("tzdata", "2024a-0+deb12u1")}),
		imageLayer(t, "sha256:layer-c", map[string]string{dpkgStatusDir + "/netbase": stanzaOf("netbase", "6.4")}),
	}}
	target, _, _, err := catalogFromImage(context.Background(), "test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"base-files": "sha256:layer-a", "tzdata": "sha256:layer-b", "netbase": "sha256:layer-c"}
	if len(target.Packages) != len(want) {
		t.Fatalf("%d packages, want %d: %+v", len(target.Packages), len(want), target.Packages)
	}
	for _, p := range target.Packages {
		if len(p.Locations) != 1 || p.Locations[0].Path != dpkgStatusDir+"/"+p.Name || p.Locations[0].LayerDigest != want[p.Name] {
			t.Errorf("%s: locations = %+v, want path %s in layer %s", p.Name, p.Locations, dpkgStatusDir+"/"+p.Name, want[p.Name])
		}
	}

	single := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:lower", map[string]string{osReleasePath: osReleaseDebian12Bookworm}),
		imageLayer(t, "sha256:upper", map[string]string{dpkgDBPath: dpkgOpensslAndGlibc}),
	}}
	target, _, _, err = catalogFromImage(context.Background(), "test-image", single)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range target.Packages {
		if len(p.Locations) != 1 || p.Locations[0].LayerDigest != "sha256:upper" {
			t.Errorf("%s from the single dpkg status: locations = %+v, want layer sha256:upper", p.Name, p.Locations)
		}
	}
}

// The same rule for pacman's one-desc-per-package database.
func TestCatalogFromImage_PacmanPackagesCarryTheirOwnLayer(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:base", map[string]string{osReleasePath: osReleaseArch, "var/lib/pacman/local/acl-2.4.0-1/desc": archDesc("acl", "2.4.0-1", "acl")}),
		imageLayer(t, "sha256:added", map[string]string{"var/lib/pacman/local/bash-5.3.15-1/desc": archDesc("bash", "5.3.15-1", "bash")}),
	}}
	target, _, _, err := catalogFromImage(context.Background(), "test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"acl": "sha256:base", "bash": "sha256:added"}
	if len(target.Packages) != len(want) {
		t.Fatalf("%d packages, want %d: %+v", len(target.Packages), len(want), target.Packages)
	}
	for _, p := range target.Packages {
		if len(p.Locations) != 1 || p.Locations[0].LayerDigest != want[p.Name] {
			t.Errorf("%s: locations = %+v, want layer %s", p.Name, p.Locations, want[p.Name])
		}
	}
}

func stanzaOf(name, version string) string {
	return "Package: " + name + "\nStatus: install ok installed\nArchitecture: all\nVersion: " + version + "\n"
}
