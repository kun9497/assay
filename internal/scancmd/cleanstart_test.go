package scancmd

import (
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/source"
)

// apkRecordCleanStartMarker is the apk installed-db record for D101's own
// marker package, real-shaped: name, version, architecture and origin, the
// same fields apkOneRecord carries. Measured present, by this exact name,
// in 11/11 real pulled CleanStart images (busybox, kafka, mariadb, mysql,
// nginx, node, postgres, python, redis, ruby, rust).
const apkRecordCleanStartMarker = `P:clnstrt-baselayout
V:1.0-r0
A:x86_64
o:clnstrt-baselayout

`

// apkRecordCleanStartPostgres is verbatim-shaped from a real pulled
// docker.io/cleanstart/postgres image's own apk installed db (measured
// 2026-08-27): the installed package is "postgresql18", never named
// "postgresql" anywhere on its own record, but its `p:` provides clause
// declares the bare, unversioned name "postgresql" -- which is exactly the
// package name CleanStart's own live OSV feed authors 11 advisories
// against (CLEANSTART-2026-AI42483 and others). This is D95's "provides
// bridge" shape (an advisory reachable ONLY through a sibling package's
// provides clause, not through the installed package's own Name or D8
// Source), confirmed to occur in CleanStart's real feed rather than
// assumed by analogy to Alpaquita/Liberica.
const apkRecordCleanStartPostgres = `P:postgresql18
V:18.6-r0
A:x86_64
o:postgresql18
p:postgresql

`

// TestCatalogFromImage_CleanStartMarkerRoutesEcosystem is D101's own version
// of TestCatalogFromImage_PacmanPackagesAreKeyed: a real-shaped apk
// installed db carrying the "clnstrt-baselayout" marker and NO
// /etc/os-release at all, read through catalogFromImage end to end, proving
// the marker probe wired into catalogFromImage -- not just
// pkgmeta.Distro.Ecosystem() in isolation (TestDistroEcosystem_CleanStart
// already covers that half) -- is what actually reaches a cataloged
// package's Ecosystem field.
func TestCatalogFromImage_CleanStartMarkerRoutesEcosystem(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:cleanstart", map[string]string{
			apkDBPath: apkRecordCleanStartMarker + apkRecordCleanStartPostgres,
		}),
	}}
	target, stats, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatalf("catalogFromImage: %v (want a no-os-release CleanStart image to catalog cleanly)", err)
	}
	if target.Distro == nil || target.Distro.ID != "cleanstart" {
		t.Fatalf("Distro = %+v, want ID cleanstart", target.Distro)
	}
	if len(target.Packages) != 2 {
		t.Fatalf("Packages = %d, want 2: %+v", len(target.Packages), target.Packages)
	}
	byName := map[string]pkgmeta.Package{}
	for _, p := range target.Packages {
		byName[p.Name] = p
	}
	marker, ok := byName["clnstrt-baselayout"]
	if !ok {
		t.Fatalf("marker package not cataloged: %+v", target.Packages)
	}
	if marker.Ecosystem != "CleanStart" {
		t.Errorf("marker Ecosystem = %q, want CleanStart (D101's distro.go routing)", marker.Ecosystem)
	}
	pg, ok := byName["postgresql18"]
	if !ok {
		t.Fatalf("postgresql18 package not cataloged: %+v", target.Packages)
	}
	if pg.Ecosystem != "CleanStart" {
		t.Errorf("postgresql18 Ecosystem = %q, want CleanStart", pg.Ecosystem)
	}
	if len(pg.Provides) != 1 || pg.Provides[0] != "postgresql" {
		t.Errorf("postgresql18 Provides = %v, want [postgresql] (D95's bridge, apk-generic, reused by D101)", pg.Provides)
	}
	if pg.Locations[0].LayerDigest != "sha256:cleanstart" {
		t.Errorf("LayerDigest = %q, want sha256:cleanstart", pg.Locations[0].LayerDigest)
	}
	if stats.Cataloged != 2 {
		t.Errorf("stats = %+v, want Cataloged=2", stats)
	}
}

// TestCatalogFromImage_PlainApkDBIsNotCleanStart is D101's adversarial test:
// an ordinary apk image with no os-release and no "clnstrt-baselayout"
// package must NOT be routed to CleanStart. This is the same fixture
// TestCatalogFromImage_NoOSReleaseStillCatalogsPackages already exercises
// (apkOneRecord carries no marker), asserted here under a name that says
// what property it is guarding: the marker probe must be narrow enough that
// a plain Alpine-shaped apk db is never misrouted.
func TestCatalogFromImage_PlainApkDBIsNotCleanStart(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:layer1", map[string]string{
			apkDBPath: apkOneRecord, // no clnstrt-baselayout anywhere in this db
		}),
	}}
	target, _, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro != nil {
		t.Errorf("Distro = %+v, want nil: no marker and no os-release means no distro identity", target.Distro)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "" {
		t.Errorf("Ecosystem = %q, want empty: a plain Alpine-shaped apk db must not resolve CleanStart", got)
	}
}

// TestCatalogFromImage_RealOSReleaseWinsOverCleanStartMarker is D101's
// precedence test: CleanStart itself never ships both a real os-release and
// the marker, but if an image somehow carried both, the real os-release
// must win -- the marker probe is gated behind an `else if`, reached only
// when os-release was absent entirely, so it can never override a distro
// the image made an actual positive statement about.
func TestCatalogFromImage_RealOSReleaseWinsOverCleanStartMarker(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:alpine-with-marker", map[string]string{
			osReleasePath: osReleaseAlpine319,
			apkDBPath:     apkRecordCleanStartMarker + apkOneRecord,
		}),
	}}
	target, _, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro == nil || target.Distro.ID != "alpine" {
		t.Fatalf("Distro = %+v, want ID alpine (a real os-release must always win)", target.Distro)
	}
	for _, p := range target.Packages {
		if p.Ecosystem != "Alpine:v3.19" {
			t.Errorf("%s Ecosystem = %q, want Alpine:v3.19: the CleanStart marker must not override a real os-release",
				p.Name, p.Ecosystem)
		}
	}
}
