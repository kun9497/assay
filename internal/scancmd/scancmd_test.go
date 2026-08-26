package scancmd

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/source"
	"github.com/kun9497/assay/internal/store"
)

func TestRun_MissingDatabase(t *testing.T) {
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o600)

	var out, errOut bytes.Buffer
	code := Run(context.Background(), filepath.Join(t.TempDir(), "absent.db"), sbom, Options{}, &out, &errOut)
	if code != 2 {
		t.Errorf("Run without a database = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "db update") {
		t.Errorf("stderr should point at the fix:\n%s", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", out.String())
	}
}

// A target with no scheme prefix and no file on disk is, by Classify's
// own contract, a registry reference — never an "SBOM that happens to be
// missing". A bare unprefixed path here would only fail locally by accident:
// on Windows because backslashes do not parse as a reference, and even on
// POSIX only because t.TempDir() happens to embed this test's own (capitalized)
// name, which is not a stable property to depend on — a lowercase test name,
// or a differently-shaped temp path, parses fine and reaches a real registry.
// An explicit docker-archive: prefix makes the classification unambiguous and
// keeps the failure local, the same fix applied to the sibling in
// cmd/assay/main_test.go.
func TestRun_MissingSBOM(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), filepath.Join(t.TempDir(), "absent.db"),
		"docker-archive:"+filepath.Join(t.TempDir(), "absent.cdx.json"), Options{}, &out, &errOut)
	if code != 2 {
		t.Errorf("Run with a missing SBOM = %d, want 2", code)
	}
}

// --- test fixtures shared by the image-path tests below ---

const osReleaseAlpine319 = `ID=alpine
VERSION_ID=3.19.9
PRETTY_NAME="Alpine Linux v3.19"
`

// osReleaseWolfi is verbatim from a real cgr.dev/chainguard/wolfi-base:latest
// pull (measured 2026-08-22). VERSION_ID is a frozen build-tooling artifact
// ("20230201") every cgr.dev image ships, deliberately included here rather
// than omitted, so a test using this fixture cannot pass by accident of
// VERSION_ID being empty -- distro.go's "wolfi" case (D88) must ignore it
// outright, not merely tolerate its absence.
const osReleaseWolfi = `ID=wolfi
NAME="Wolfi"
PRETTY_NAME="Wolfi"
VERSION_ID="20230201"
HOME_URL="https://wolfi.dev"
BUG_REPORT_URL="https://github.com/wolfi-dev/os/issues"
`

// osReleaseMinimOS is verbatim from a real reg.mini.dev/nginx:latest pull
// (measured 2026-08-26). VERSION_ID is a frozen build-tooling artifact
// ("20241031"), the same wolfi-style shape osReleaseWolfi carries above --
// included for the identical reason: distro.go's "minimos" case (D92) must
// ignore it outright, not merely tolerate its absence.
const osReleaseMinimOS = `ID=minimos
NAME="MinimOS"
PRETTY_NAME="MinimOS"
VERSION_ID="20241031"
HOME_URL="https://minimus.io"
BUG_REPORT_URL="https://support.minimus.io"
`

// One apk record, minimal but real-shaped: name, version, architecture, and
// origin (D8). The name deliberately differs from the origin — busybox-binsh
// -> busybox is one of the six real alpine:3.19 packages that diverge from
// their source (task 4) — so any assertion that Source.Name survived cannot
// pass by coincidence of the two strings being equal. The trailing blank line
// matches the real file's own record separator.
const apkOneRecord = `P:busybox-binsh
V:1.36.1-r15
A:x86_64
o:busybox

`

// buildTar packs files into one uncompressed tar, matching how a layer's
// contents look on the wire — real image tests do not need compression to
// exercise the code under test.
//
// Iterating a map has no defined order, which is fine here because nothing in
// this package's tests depends on entry order within one layer. It would not
// be fine for a whiteout and the file it names: internal/source/walk_test.go
// hit exactly that trap (a whiteout's position within its own layer decides
// whether a correct reader ignores it) and had to split its builder into an
// unordered layerOf and an order-preserving layerOfOrdered. Do not put a
// whiteout in this map without doing the same here.
func buildTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// imageLayer wraps files as a source.Layer directly, for tests that drive
// catalogFromImage without going through a real registry, tarball, or layout.
func imageLayer(t *testing.T, diffID string, files map[string]string) source.Layer {
	t.Helper()
	raw := buildTar(t, files)
	return source.Layer{
		DiffID: diffID,
		Open:   func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil },
	}
}

// writeImageTar writes files as the single layer of a real docker-archive
// tarball at path, built entirely in-process (go-containerregistry's
// tarball + mutate + empty, never pkg/v1/daemon — D19). This is what lets
// TestRun_TargetKinds exercise the docker-archive: prefix through Run itself,
// with no network reached at any point.
func writeImageTar(t *testing.T, path string, files map[string]string) {
	t.Helper()
	raw := buildTar(t, files)

	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	if err != nil {
		t.Fatalf("LayerFromOpener: %v", err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("AppendLayers: %v", err)
	}
	ref, err := name.ParseReference("scancmd-test:latest")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	if err := tarball.WriteToFile(path, ref, img); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
}

// testDB builds an empty but complete database: SetMeta is what marks a build
// finished (store.ErrIncomplete otherwise), so the image-path tests below
// reach the matcher and report rather than tripping the missing-database exit.
// testDB declares coverage of the ecosystems these tests scan (D20).
//
// A database declaring none used to serve here, because a lookup that found
// nothing counted as a clean evaluation. That is exactly the silent false
// negative D20 closes: every package now lands in "not evaluated" instead, and
// a test asserting a package was evaluated would be asserting the old bug.
func testDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Coverage is declared the way a provider declares it (D20), not inferred
	// from stored records.
	covered := []string{"Alpine:v3.19", "Go", "npm", "PyPI"}
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: covered}},
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// The three target kinds reach three different loaders, and an SBOM path
// still works exactly as it did before this slice.
func TestRun_TargetKinds(t *testing.T) {
	dbPath := testDB(t)

	t.Run("SBOM path", func(t *testing.T) {
		sbom := filepath.Join(t.TempDir(), "s.cdx.json")
		if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), dbPath, sbom, Options{}, &out, &errOut); code != 0 {
			t.Errorf("Run(sbom) = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		if !strings.Contains(out.String(), "no components") {
			t.Errorf("stdout = %q, want the empty-document message", out.String())
		}
	})

	t.Run("docker-archive tarball path", func(t *testing.T) {
		tarPath := filepath.Join(t.TempDir(), "image.tar")
		writeImageTar(t, tarPath, map[string]string{
			osReleasePath: osReleaseAlpine319,
			apkDBPath:     apkOneRecord,
		})
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), dbPath, "docker-archive:"+tarPath, Options{}, &out, &errOut); code != 0 {
			t.Errorf("Run(docker-archive) = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		if !strings.Contains(out.String(), "1 package") {
			t.Errorf("stdout = %q, want the one apk package to have been evaluated", out.String())
		}
		// Pins article()'s TargetImage branch specifically: "a image" is the
		// literal grammar bug an unpinned image kind would let through, and
		// this is the only test in the package that reaches TargetImage
		// through Run with a real, valid, cataloged image - every other
		// image-path test here either errors before the disclosure (proving
		// nothing about article()) or is the SBOM/go-binary/directory kinds.
		if !strings.Contains(errOut.String(), "as an image") {
			t.Errorf("stderr = %q, want it to disclose the target as an image (grammar: "+
				"\"an\", not \"a\")", errOut.String())
		}
	})

	t.Run("registry reference path", func(t *testing.T) {
		// A string with no scheme prefix and no file on disk falls through to
		// the registry loader (source.Classify). This one is
		// syntactically invalid, so it fails while being parsed AS a
		// reference rather than while being opened as a file or a socket —
		// proof of which loader it reached, without ever touching the
		// network.
		var out, errOut bytes.Buffer
		code := Run(context.Background(), dbPath, "NOT a valid ref!!", Options{}, &out, &errOut)
		if code != 2 {
			t.Errorf("Run(invalid ref) = %d, want 2", code)
		}
		if !strings.Contains(errOut.String(), "parse reference") {
			t.Errorf("stderr = %q, want it to name reference parsing, proving "+
				"this reached the registry loader and not the SBOM path", errOut.String())
		}
	})
}

// TestRun_SPDXTargetIsRouted proves the SPDX sniff added to classify.go and
// scancmd's own TargetSBOM branch (D84) actually reaches spdx.Parse: an
// inline SPDX-2.3 document's one Go package, on the database's Go coverage,
// is both cataloged AND matched against a real advisory — not merely
// accepted as valid JSON, which "no components" (the empty-document message)
// would also satisfy.
//
// Deleting either sniff branch sends this document into cyclonedx.Parse
// instead, which fails outright: an SPDX document carries no "bomFormat"
// key, so BOMFormat decodes to "" and cyclonedx.Parse's own check rejects it
// — exit 2, not the exit-0/1-finding result asserted here.
func TestRun_SPDXTargetIsRouted(t *testing.T) {
	dbPath := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-spdx-routed", pkg: "spdxrouted", fixed: "2.0.0", vectors: []string{vecCritical}},
	})
	// No DESCRIBES relationship here on purpose: SPDX-2.3 does not require
	// one, and this document's only package must NOT be mistaken for the
	// document-root pseudo-package (D84) — pointing DESCRIBES at the sole
	// real package (rather than a separate, synthetic root) would exclude
	// it, proving nothing about routing at all.
	const doc = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
	  {"name":"spdxrouted","SPDXID":"SPDXRef-Package-spdxrouted","versionInfo":"1.0.0",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:golang/example.com/spdxrouted@1.0.0"}]}]}`
	path := filepath.Join(t.TempDir(), "s.spdx.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := Run(context.Background(), dbPath, path, Options{}, &out, &errOut); code != 0 {
		t.Fatalf("Run(spdx) = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(out.String(), "1 finding") {
		t.Errorf("stdout = %q, want the GHSA-spdx-routed finding matched off the SPDX document's purl",
			out.String())
	}
}

// A target we cannot read is exit 2 with a message naming the target, never a
// clean empty scan (D11).
func TestRun_UnreadableTargetExits2(t *testing.T) {
	dbPath := testDB(t)
	target := "docker-archive:" + filepath.Join(t.TempDir(), "absent.tar")

	var out, errOut bytes.Buffer
	code := Run(context.Background(), dbPath, target, Options{}, &out, &errOut)
	if code != 2 {
		t.Errorf("Run(unreadable image) = %d, want 2", code)
	}
	if out.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", out.String())
	}
	if !strings.Contains(errOut.String(), target) {
		t.Errorf("stderr = %q, want it to name the target %q", errOut.String(), target)
	}
}

// An image with no os-release yields packages with no ecosystem, which the
// report already turns into "not evaluated" and exit 2 — not 0 with an empty
// inventory (D11).
func TestRun_ImageWithoutOSReleaseIsNotClean(t *testing.T) {
	dbPath := testDB(t)
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, map[string]string{
		apkDBPath: apkOneRecord, // no etc/os-release at all
	})

	var out, errOut bytes.Buffer
	code := Run(context.Background(), dbPath, "docker-archive:"+tarPath, Options{}, &out, &errOut)
	if code != 2 {
		t.Errorf("Run(image without os-release) = %d, want 2 (stdout: %s, stderr: %s)",
			code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "NOT a clean result") {
		t.Errorf("stdout = %q, want the report to say this is not clean", out.String())
	}
}

// The same holds for an image with no /lib/apk/db/installed at all: this is
// now a catalog error (I1), not a fabricated component count, but Run must
// still map it to exit 2 the same way. This test asserts only the exit code —
// TestCatalogFromImage_NoApkDBReturnsError below is what pins the error text.
func TestRun_ImageWithoutApkDBIsNotClean(t *testing.T) {
	dbPath := testDB(t)
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, map[string]string{
		osReleasePath: osReleaseAlpine319, // ecosystem resolves; no apk db at all
	})

	var out, errOut bytes.Buffer
	code := Run(context.Background(), dbPath, "docker-archive:"+tarPath, Options{}, &out, &errOut)
	if code != 2 {
		t.Errorf("Run(image without apk db) = %d, want 2 (stdout: %s, stderr: %s)",
			code, out.String(), errOut.String())
	}
}

// Location.LayerDigest must name the layer the apk database was actually read
// from, not just any layer in the image. Two layers with different digests
// pin that: os-release lives in the base layer and the apk database in the
// upper one, so a mutation that hardcodes img.Layers[0]'s digest reports the
// wrong one. This also carries D8 (Package.Source, load-bearing per the
// brief) and D7 (Distro belongs to the Target) through the one place that
// mutates what apkdb and osrelease returned — apkdb's own tests and
// matcher_test.go guard their own ends of this seam, but neither asserts what
// catalogFromImage does to the result in between.
func TestCatalogFromImage_SetsLayerDigestFromTheLayer(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:base", map[string]string{
			osReleasePath: osReleaseAlpine319,
		}),
		imageLayer(t, "sha256:top", map[string]string{
			apkDBPath: apkOneRecord,
		}),
	}}
	target, _, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}

	if target.Distro == nil || target.Distro.ID != "alpine" || target.Distro.VersionID != "3.19.9" {
		t.Errorf("Distro = %+v, want alpine 3.19.9 (D7: the distro belongs to the Target)", target.Distro)
	}

	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	p := target.Packages[0]
	if len(p.Locations) != 1 || p.Locations[0].LayerDigest != "sha256:top" {
		t.Errorf("Locations = %+v, want LayerDigest sha256:top (the layer the apk "+
			"database actually came from, not sha256:base)", p.Locations)
	}
	// apkOneRecord's origin differs from its own name (busybox-binsh -> busybox,
	// as in the real alpine:3.19 image) specifically so this cannot pass by
	// coincidence of source and binary sharing a name.
	if p.Source == nil || p.Source.Name != "busybox" {
		t.Errorf("Source = %+v, want Name busybox (D8, through catalogFromImage)", p.Source)
	}
}

// TestCatalogFromImage_ApkDBUnderUsrLibPhysicalPath is D88's caller-first
// test: Wolfi and Chainguard images physically store the apk database at
// usr/lib/apk/db/installed behind a `lib -> usr/lib` symlink, and
// Image.Files follows a symlink that IS the requested tar entry but never
// one on a DIRECTORY COMPONENT of a requested path (the same limitation
// rpmDBDirs' own comment names for /var/lib/rpm) -- so `lib/apk/db/installed`
// alone finds nothing in these images' layers. Before D88, this exact
// fixture hard-errored "no supported package database found" (exit 2); this
// pins that it now catalogs. Deleting apkDBPathUsrLib from apkDBPaths (or
// the findAPKDB probe that reads it) turns this red while every existing
// Alpine test in this file — which never has anything under usr/lib/apk —
// stays green, proving the traditional path is unaffected.
func TestCatalogFromImage_ApkDBUnderUsrLibPhysicalPath(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:wolfi", map[string]string{
			osReleasePath:   osReleaseWolfi,
			apkDBPathUsrLib: apkOneRecord, // no lib/apk/db/installed at all
		}),
	}}
	target, stats, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatalf("catalogFromImage: %v (want the physical usr/lib path to be found)", err)
	}
	if target.Distro == nil || target.Distro.ID != "wolfi" {
		t.Fatalf("Distro = %+v, want ID wolfi", target.Distro)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	p := target.Packages[0]
	if p.Ecosystem != "Wolfi" {
		t.Errorf("Ecosystem = %q, want Wolfi (D88's distro.go routing)", p.Ecosystem)
	}
	if p.Locations[0].LayerDigest != "sha256:wolfi" {
		t.Errorf("LayerDigest = %q, want sha256:wolfi", p.Locations[0].LayerDigest)
	}
	// D8 rides free: the apk cataloger reads the same `o:` field regardless
	// of which of the two paths the database was found under.
	if p.Source == nil || p.Source.Name != "busybox" {
		t.Errorf("Source = %+v, want Name busybox (D8)", p.Source)
	}
	if stats.Cataloged != 1 {
		t.Errorf("stats = %+v, want Cataloged=1", stats)
	}
}

// TestCatalogFromImage_ApkDBUnderUsrLibPhysicalPath_MinimOS is D92's own
// cheap row on the same fixture pattern: the usr/lib apk path trap the test
// above closed for Wolfi/Chainguard was already closed generically by D88's
// apkDBPaths probe -- nothing in findAPKDB is Wolfi/Chainguard-specific --
// but nothing had exercised it with a MinimOS os-release until now. A real
// reg.mini.dev/nginx image was verified live to use exactly this layout.
func TestCatalogFromImage_ApkDBUnderUsrLibPhysicalPath_MinimOS(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:minimos", map[string]string{
			osReleasePath:   osReleaseMinimOS,
			apkDBPathUsrLib: apkOneRecord, // no lib/apk/db/installed at all
		}),
	}}
	target, stats, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatalf("catalogFromImage: %v (want the physical usr/lib path to be found)", err)
	}
	if target.Distro == nil || target.Distro.ID != "minimos" {
		t.Fatalf("Distro = %+v, want ID minimos", target.Distro)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	p := target.Packages[0]
	if p.Ecosystem != "MinimOS" {
		t.Errorf("Ecosystem = %q, want MinimOS (D92's distro.go routing)", p.Ecosystem)
	}
	if p.Locations[0].LayerDigest != "sha256:minimos" {
		t.Errorf("LayerDigest = %q, want sha256:minimos", p.Locations[0].LayerDigest)
	}
	// D8 rides free here too: the apk cataloger reads the same `o:` field
	// regardless of distro.
	if p.Source == nil || p.Source.Name != "busybox" {
		t.Errorf("Source = %+v, want Name busybox (D8)", p.Source)
	}
	if stats.Cataloged != 1 {
		t.Errorf("stats = %+v, want Cataloged=1", stats)
	}
}

// TestCatalogFromImage_ApkDBPrefersTraditionalPathOverPhysical: an image
// carrying both is not a shape anything ships, but the probe order should
// still be deterministic and match the preference dpkgStatusDir's own
// comment states for the single-file-vs-directory case -- the traditional
// path first, so a mutation that reordered apkDBPaths would be silent on
// every other test here (none of them supplies both paths at once).
func TestCatalogFromImage_ApkDBPrefersTraditionalPathOverPhysical(t *testing.T) {
	const usrLibRecord = `P:usrlib-record
V:9.9.9-r9
A:x86_64
o:usrlib-origin

`
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:both", map[string]string{
			apkDBPath:       apkOneRecord, // busybox-binsh / busybox
			apkDBPathUsrLib: usrLibRecord, // usrlib-record / usrlib-origin
		}),
	}}
	target, _, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1 -- exactly one of the two databases should be read", len(target.Packages))
	}
	if got := target.Packages[0].Name; got != "busybox-binsh" {
		t.Errorf("Packages[0].Name = %q, want busybox-binsh (the traditional lib/apk/db/installed "+
			"path), not the usr/lib physical one", got)
	}
}

// No /etc/os-release must not empty the inventory: packages are still
// cataloged, with an empty Ecosystem, so the matcher and report can mark them
// not evaluated (D11) instead of the scan silently reading as clean.
func TestCatalogFromImage_NoOSReleaseStillCatalogsPackages(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:layer1", map[string]string{
			apkDBPath: apkOneRecord,
		}),
	}}
	target, stats, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro != nil {
		t.Errorf("Distro = %+v, want nil: no os-release was present", target.Distro)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1: an unreadable distro must not empty the inventory", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "" {
		t.Errorf("Ecosystem = %q, want empty", got)
	}
	if stats.Cataloged != 1 || stats.Components != 1 {
		t.Errorf("stats = %+v, want Cataloged=1 Components=1", stats)
	}
}

// A distro whose Ecosystem() errors (edge, in this case) must leave packages
// unkeyed, never guess a substitute ecosystem string.
func TestCatalogFromImage_UnsupportedEcosystemIsNotGuessed(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:layer1", map[string]string{
			osReleasePath: "ID=alpine\nVERSION_ID=edge\n", // edge has no OSV ecosystem
			apkDBPath:     apkOneRecord,
		}),
	}}
	target, _, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "" {
		t.Errorf("Ecosystem = %q, want empty: Ecosystem() errored and must not be guessed", got)
	}
}

// No /lib/apk/db/installed at all, with a distro that DID resolve, must be an
// error naming what was looked for (I1) — not a fabricated non-zero component
// count. An image is never "nothing to see" the way an empty SBOM legitimately
// can be, but inventing a component to say so would fabricate the exact thing
// cyclonedx.Stats' own contract forbids: a package that was never cataloged
// becomes indistinguishable from one with no vulnerabilities.
func TestCatalogFromImage_NoApkDBReturnsError(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{
		imageLayer(t, "sha256:layer1", map[string]string{
			osReleasePath: osReleaseAlpine319,
		}),
	}}
	target, stats, err := catalogFromImage("test-image", img)
	if err == nil {
		t.Fatal("catalogFromImage succeeded with no apk database; want an error")
	}
	if !strings.Contains(err.Error(), apkDBPath) {
		t.Errorf("err = %q, want it to name %q — what was looked for", err, apkDBPath)
	}
	if !strings.Contains(err.Error(), "test-image") {
		t.Errorf("err = %q, want it to name the image", err)
	}
	if len(target.Packages) != 0 || stats.Components != 0 || stats.Cataloged != 0 {
		t.Errorf("got target=%+v stats=%+v on error, want zero values", target, stats)
	}
}

// The CLI contract, end to end: a target whose ecosystem this database never
// held exits 2 and says which one and what to do (D20, D11).
//
// The matcher test covers the decision; nothing covered the consequence.
// Disabling the coverage check entirely used to fail only in internal/matcher,
// so the behaviour the command line actually promises was unasserted.
func TestRun_UncoveredEcosystemExits2WithInstructions(t *testing.T) {
	dbPath := testDB(t) // covers Alpine:v3.19, Go, npm, PyPI — not v3.99

	sbom := filepath.Join(t.TempDir(), "future.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
	 "components":[
	  {"type":"operating-system","name":"alpine","version":"3.99.0",
	   "properties":[{"name":"syft:distro:id","value":"alpine"},
	                 {"name":"syft:distro:versionID","value":"3.99.0"}]},
	  {"type":"library","name":"busybox","version":"1.36.1-r20",
	   "purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := Run(context.Background(), dbPath, sbom, Options{}, &out, &errOut); code != 2 {
		t.Fatalf("Run = %d, want 2 (stdout: %s)", code, out.String())
	}
	if strings.Contains(out.String(), "No known vulnerabilities") {
		t.Errorf("clean wording for an ecosystem the database never held:\n%s", out.String())
	}
	// The user's next action has to be in the output; nothing else says it.
	if !strings.Contains(out.String(), "Alpine:v3.99") {
		t.Errorf("output does not name the missing ecosystem:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "db update") {
		t.Errorf("output does not say how to fix it:\n%s", out.String())
	}
}

// --- fixtures for TestRun_ExitCodeMatrix ---

// vecCritical and vecMedium are real vectors already pinned elsewhere in this
// repository (internal/matcher/matcher_test.go) against their exact bands and
// scores ("critical, 9.8" and "medium, 6.5"), so reusing them here does not
// depend on this package re-deriving what internal/severity already owns.
const (
	vecCritical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	vecMedium   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
)

// Addressable severity.Band values for Options.FailOn, which takes a pointer
// so "not requested" (nil) is distinguishable from severity.None, a real,
// requestable threshold and also Band's zero value.
var (
	bandNone     = severity.None
	bandLow      = severity.Low
	bandMedium   = severity.Medium
	bandHigh     = severity.High
	bandCritical = severity.Critical
)

// matrixAdv is one advisory for the exit-code matrix below, affecting Go
// package "example.com/<pkg>" at versions [0, fixed) - UNLESS pkg already
// contains "/", in which case it is a real module path (go.etcd.io/bbolt)
// used verbatim, so a go-binary target can be matched against a genuine
// dependency instead of a name nothing ever imports. Leaving fixed empty
// asks for a malformed bound ("not-a-version") instead: version.SemVer
// rejects it, so the matcher records an advisory-scoped skip
// (report.Summary.IncompleteChecks) for the package rather than a finding —
// a package that WAS evaluated, just not completely.
type matrixAdv struct {
	id      string
	pkg     string
	fixed   string
	vectors []string // CVSS vectors; nil -> the finding's severity is Unknown
	// aliases are the other identifiers this record claims. Records that share
	// one describe a single vulnerability, so they become several ratings on
	// one finding rather than several findings (D25). Without this there is no
	// way to build the shape the aggregate exists for.
	aliases []string
	// unfixable, when true, gives the range an Introduced event and NO Fixed
	// event at all (D48/D52) - the shape Red Hat's CSAF VEX feed emits
	// 1,278,384 times: affected at every version, nothing to upgrade to. This
	// is deliberately a separate signal from fixed == "", which already means
	// something else in this fixture builder (a malformed bound that produces
	// an advisory-scoped skip, not a finding) - reusing that would make it
	// impossible to ask for a genuinely unfixable finding here.
	unfixable bool
	// fixState is stored on the range only when unfixable is true (D52); it is
	// ignored otherwise. Left at its zero value it is the empty string, which
	// is the store's own spelling of "unknown" (advisory.go's own doc comment)
	// - the state every source but Red Hat's feed leaves an unfixable finding
	// in - so a fixture asking for "unfixable, no stated reason" does not need
	// to spell out FixStateUnknown itself.
	fixState advisory.FixState
}

// buildMatrixDB writes advisories into a fresh database that covers "Go"
// only. That is enough for every fixture below: the one unsupported-ecosystem
// package in the "full" fixture never reaches the matcher at all, so its
// ecosystem never needs to be covered.
func buildMatrixDB(t *testing.T, advisories []matrixAdv) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, adv := range advisories {
		// D52's shape takes priority over the "empty fixed -> malformed bound"
		// convention below: an unfixable fixture wants an Introduced-only
		// range, not a Fixed event of any kind, malformed or otherwise.
		var events []advisory.Event
		var rangeFixState advisory.FixState
		if adv.unfixable {
			events = []advisory.Event{{Introduced: "0"}}
			rangeFixState = adv.fixState
		} else {
			fixed := adv.fixed
			if fixed == "" {
				fixed = "not-a-version"
			}
			events = []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}
		}
		var sev []advisory.Severity
		for _, v := range adv.vectors {
			sev = append(sev, advisory.Severity{Type: "CVSS_V3", Score: v})
		}
		// Every fixture pkg so far has been a bare synthetic name
		// ("critical", "medium", ...), which is why prefixing it under
		// "example.com/" is safe. A pkg that already contains "/" is a real
		// module path handed in on purpose - go.etcd.io/bbolt, a genuine
		// dependency, so a go-binary or directory target can be matched
		// against a real finding rather than a fixture-shaped one - and
		// prefixing that would produce a name nothing ever imports.
		//
		// Named "affected", not "name": this package already imports
		// go-containerregistry's "name" package above, and shadowing it here
		// compiles cleanly today only because nothing in this function
		// happens to need that import.
		affected := "example.com/" + adv.pkg
		if strings.Contains(adv.pkg, "/") {
			affected = adv.pkg
		}
		// The authoring database, which the OSV provider derives from the
		// identifier's prefix at ingest (D25). Derived the same way here
		// rather than carried as another fixture field, so a record named
		// GHSA-… in a test is a GHSA record in the store, as it would be.
		database, _, _ := strings.Cut(adv.id, "-")
		a := advisory.Advisory{
			ID:       adv.id,
			Kind:     advisory.KindVulnerability,
			Aliases:  adv.aliases,
			Database: database,
			Affected: []advisory.Affected{{
				Ecosystem: "Go",
				Name:      affected,
				Ranges: []advisory.Range{{
					Type:     advisory.RangeSemver,
					Events:   events,
					FixState: rangeFixState,
				}},
			}},
			Severity: sev,
		}
		if err := w.Put(a); err != nil {
			t.Fatalf("Put(%s): %v", adv.id, err)
		}
	}
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Go"}}},
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// matrixPkg is one SBOM component for the exit-code matrix below. purlType
// "cargo" is deliberately unsupported (pkgmeta.EcosystemForPURLType has no
// entry for it): the cataloger drops it before the matcher ever sees it,
// which is the simplest way to produce a component the report counts as not
// evaluated, without a second database-coverage scenario.
type matrixPkg struct {
	name, purlType string
}

// buildMatrixSBOM writes a CycloneDX document naming each package at version
// 1.0.0 — inside every matrixAdv range above, which all open at "0".
func buildMatrixSBOM(t *testing.T, pkgs []matrixPkg) string {
	t.Helper()
	comps := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		purl := fmt.Sprintf("pkg:cargo/%s@1.0.0", p.name)
		if p.purlType != "cargo" {
			purl = fmt.Sprintf("pkg:%s/example.com/%s@1.0.0", p.purlType, p.name)
		}
		comps = append(comps, fmt.Sprintf(
			`{"type":"library","name":%q,"version":"1.0.0","purl":%q}`, p.name, purl))
	}
	doc := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[%s]}`,
		strings.Join(comps, ","))
	path := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// putRating opens the database dbPath already names — the one buildMatrixDB
// just built and closed — and writes one rating into it. This is what `db
// update` will have left behind once an annotator (D27) has run: a scan
// never fetches anything itself (D14), so a test proving a rating reaches
// the gate has to put it in the SAME database Run will open, not somewhere
// Run never reads from.
//
// store.Create, not store.Open: RatingsFor's caller needs a Writer, and
// Create's own CreateBucketIfNotExists calls are no-ops against buckets that
// already exist, so reopening an already-built database this way neither
// erases nor duplicates what buildMatrixDB already wrote.
func putRating(t *testing.T, dbPath string, r advisory.Rating) {
	t.Helper()
	w, err := store.Create(dbPath)
	if err != nil {
		t.Fatalf("open %s to add a rating: %v", dbPath, err)
	}
	if err := w.PutRating(r); err != nil {
		t.Fatalf("PutRating: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestRun_AnNVDRatingReachesTheGate is the end-to-end shape of D27, through
// Run: a finding no OSV source rated reaches --fail-on high because NVD
// rated it.
//
// The gate is checked through the DEFAULT table renderer, exactly the
// realistic path (`assay scan ... --fail-on high`, no --explain) the
// roadmap's own measurement describes. Naming the source, on the other
// hand, is checked through --explain rather than the table: table.go's
// SEVERITY cell deliberately collapses to one band per row and marks
// disagreement with `*` rather than naming sources (see table.go's own
// sourcesDisagree/disagreementMarker comments) — --explain is where D27
// promises a reader can see which authority raised the band ("--explain
// lists it in the per-source breakdown, which is where a reader looks for
// exactly this" — the roadmap's own D27 text). verdict() does not depend on
// which renderer ran (D11: the renderer is chosen, not a different notion
// of what the scan found), so checking through --explain here still proves
// the same gate trips.
func TestRun_AnNVDRatingReachesTheGate(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "PYSEC-1", pkg: "unrated", fixed: "2.0.0", aliases: []string{"CVE-2025-9"}},
	})
	// The rating is written into the SAME database, because a scan never
	// fetches anything (D14) - this is what `db update` will have left behind.
	putRating(t, db, advisory.Rating{CVE: "CVE-2025-9", Source: "NVD",
		Severity: []advisory.Severity{{Type: "CVSS_V31", Score: vecCritical}}})
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "unrated", purlType: "golang"}})

	high := severity.High
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, sbom, Options{FailOn: &high}, &out, &errOut); code != 1 {
		t.Errorf("Run = %d, want 1 - NVD rated this critical, so --fail-on high "+
			"must trip; stdout:\n%s", code, out.String())
	}

	// Same database, same finding, --explain by the CVE NVD rated - the one
	// renderer that names the source (see the doc comment above).
	out.Reset()
	errOut.Reset()
	code := Run(context.Background(), db, sbom,
		Options{FailOn: &high, Explain: "CVE-2025-9"}, &out, &errOut)
	if code != 1 {
		t.Errorf("Run with --explain = %d, want 1\nstdout:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "NVD") {
		t.Errorf("the report does not name NVD as a source:\n%s", out.String())
	}
}

// TestRun_ExitCodeMatrix states, once and in one place, every combination of
// the three --fail-on* gates that changes the exit code: findings at and
// below a threshold, an unrated finding, an unevaluated package, an
// incompletely-checked one, each flag on and off, and D11's 2 > 1 > 0
// precedence between them. This is the contract CI depends on.
func TestRun_ExitCodeMatrix(t *testing.T) {
	// "full": a critical finding, a medium finding, an unrated finding, one
	// package the cataloger dropped (unsupported ecosystem -> NotEvaluated),
	// and one advisory this database cannot evaluate ("badcompare", a
	// malformed fixed version -> IncompleteChecks). Every gate has something
	// to fire on at once, which is what the precedence cases need.
	full := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "GHSA-critical", pkg: "critical", fixed: "2.0.0", vectors: []string{vecCritical}},
			{id: "GHSA-medium", pkg: "medium", fixed: "2.0.0", vectors: []string{vecMedium}},
			{id: "GHSA-unknownsev", pkg: "unknownsev", fixed: "2.0.0"}, // no vectors -> Unknown
			{id: "GHSA-badcompare", pkg: "badcompare"},                 // fixed == "" -> malformed
		})
		sbom = buildMatrixSBOM(t, []matrixPkg{
			{name: "critical", purlType: "golang"},
			{name: "medium", purlType: "golang"},
			{name: "unknownsev", purlType: "golang"},
			{name: "badcompare", purlType: "golang"},
			{name: "somecrate", purlType: "cargo"}, // dropped by the cataloger
		})
		return db, sbom
	}

	// "belowThreshold": one medium finding, nothing incomplete. Isolates
	// "does not trip" from full's always-present critical finding.
	belowThreshold := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "GHSA-medium", pkg: "medium", fixed: "2.0.0", vectors: []string{vecMedium}},
		})
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "medium", purlType: "golang"}})
		return db, sbom
	}

	// "unknownOnly": one unrated finding, nothing else. Isolates D17's "not
	// even --fail-on none" guarantee from full's critical/medium findings.
	unknownOnly := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "GHSA-unknownsev", pkg: "unknownsev", fixed: "2.0.0"},
		})
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "unknownsev", purlType: "golang"}})
		return db, sbom
	}

	// "clean": fully evaluated, nothing found, nothing incomplete.
	clean := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, nil)
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "notvulnerable", purlType: "golang"}})
		return db, sbom
	}

	// "incompleteOnly": IncompleteChecks > 0, NotEvaluated == 0 - the package
	// itself IS evaluated (Go, covered, a comparer exists); only the one
	// advisory naming it has a bound the comparer rejects. Isolates the
	// IncompleteChecks half of FailOnIncomplete's OR from full's
	// always-present cataloger-dropped package.
	incompleteOnly := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "GHSA-badcompare", pkg: "badcompare"}, // fixed == "" -> malformed
		})
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "badcompare", purlType: "golang"}})
		return db, sbom
	}

	// "notEvaluatedOnly": NotEvaluated > 0, IncompleteChecks == 0 - a second,
	// unrelated package the cataloger drops (unsupported purl type), with no
	// advisory anywhere that could produce an advisory-scoped skip. Isolates
	// the NotEvaluated half of FailOnIncomplete's OR from full's
	// always-present badcompare advisory.
	notEvaluatedOnly := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, nil)
		sbom = buildMatrixSBOM(t, []matrixPkg{
			{name: "notvulnerable", purlType: "golang"},
			{name: "somecrate", purlType: "cargo"}, // dropped by the cataloger
		})
		return db, sbom
	}

	cases := []struct {
		name    string
		fixture func(t *testing.T) (db, sbom string)
		opts    Options
		want    int
	}{
		{"no flags: exit 0 is unchanged even with findings present", full, Options{}, 0},
		{"--fail-on high trips on the critical finding", full, Options{FailOn: &bandHigh}, 1},
		{"--fail-on critical trips exactly at the threshold", full, Options{FailOn: &bandCritical}, 1},
		{"--fail-on-unknown trips on its own", full, Options{FailOnUnknown: true}, 1},
		{"--fail-on-incomplete trips on its own", full, Options{FailOnIncomplete: true}, 2},
		{"precedence: incomplete beats fail-on (D11, 2 > 1)", full,
			Options{FailOn: &bandCritical, FailOnIncomplete: true}, 2},
		{"precedence: incomplete beats fail-on-unknown (D11, 2 > 1)", full,
			Options{FailOnUnknown: true, FailOnIncomplete: true}, 2},
		{"precedence: all three gates set together still exits 2, not 1", full,
			Options{FailOn: &bandLow, FailOnUnknown: true, FailOnIncomplete: true}, 2},

		{"--fail-on critical does not trip on a below-threshold finding", belowThreshold,
			Options{FailOn: &bandCritical}, 0},
		{"--fail-on medium trips exactly at the boundary", belowThreshold,
			Options{FailOn: &bandMedium}, 1},

		{"an unknown finding never trips --fail-on none (D17) - the opposite reading is intuitive",
			unknownOnly, Options{FailOn: &bandNone}, 0},
		{"an unknown finding never trips when --fail-on is not set at all", unknownOnly, Options{}, 0},
		{"--fail-on-unknown is the flag that catches what --fail-on none does not",
			unknownOnly, Options{FailOnUnknown: true}, 1},

		{"--fail-on-incomplete does not fire when nothing is incomplete", clean,
			Options{FailOnIncomplete: true}, 0},
		{"a clean scan with every gate on still exits 0", clean,
			Options{FailOn: &bandNone, FailOnUnknown: true, FailOnIncomplete: true}, 0},

		// Both halves of FailOnIncomplete's OR, each pinned on its own so a
		// mutation that drops either one - "simplifying" to just NotEvaluated,
		// or just IncompleteChecks - cannot pass by only ever being exercised
		// alongside the other half in the "full" fixture.
		{"--fail-on-incomplete fires on IncompleteChecks alone, no NotEvaluated", incompleteOnly,
			Options{FailOnIncomplete: true}, 2},
		{"--fail-on-incomplete fires on NotEvaluated alone, no IncompleteChecks", notEvaluatedOnly,
			Options{FailOnIncomplete: true}, 2},

		// --fail-on-unknown must not degenerate into "fail on any rated
		// finding": every other row either has an unrated finding present
		// (fires under the correct behaviour and a broken one alike) or no
		// findings at all. belowThreshold has only a rated (medium) finding.
		{"--fail-on-unknown does not trip when every finding is rated", belowThreshold,
			Options{FailOnUnknown: true}, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, sbom := tc.fixture(t)
			var out, errOut bytes.Buffer
			got := Run(context.Background(), db, sbom, tc.opts, &out, &errOut)
			if got != tc.want {
				t.Errorf("Run() = %d, want %d\nstdout:\n%s\nstderr:\n%s",
					got, tc.want, out.String(), errOut.String())
			}
		})
	}
}

// TestRun_FailOnUnfixableWontFixGate is the D52 analogue of the exit-code
// matrix above, kept separate rather than folded into it because it needs
// its own fixture shape (matrixAdv.unfixable) that none of that matrix's
// rows use.
//
// Every fixture finding here carries a vector (vecCritical), never left
// unrated: an unrated unfixable finding would also trip --fail-on-unknown,
// and a row that could fire for either reason would not isolate the flag
// this test exists to check.
func TestRun_FailOnUnfixableWontFixGate(t *testing.T) {
	// wontFixOnly: one finding, unfixable, and the vendor has said so (D52).
	wontFixOnly := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "RHSA-wontfix", pkg: "wontfix", vectors: []string{vecCritical},
				unfixable: true, fixState: advisory.FixStateWontFix},
		})
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "wontfix", purlType: "golang"}})
		return db, sbom
	}
	// notFixedOnly: unfixable, but no source has said it never will be -
	// affected with no fix published yet. This is the fixture that matters
	// most in this test: an implementation that gated
	// FailOnUnfixableWontFix on Unfixable() alone, without reading FixState,
	// would trip on this row exactly as it does on wontFixOnly - the brief's
	// own warning about the first half passing alone.
	notFixedOnly := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "RHSA-notfixed", pkg: "notfixed", vectors: []string{vecCritical},
				unfixable: true, fixState: advisory.FixStateNotFixed},
		})
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "notfixed", purlType: "golang"}})
		return db, sbom
	}
	// unknownStateOnly: unfixable, FixState left at the store's own zero
	// value (empty string) rather than spelled out - the shape every source
	// but Red Hat's feed leaves an unfixable finding in.
	unknownStateOnly := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "GHSA-unknownfix", pkg: "unknownfix", vectors: []string{vecCritical}, unfixable: true},
		})
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "unknownfix", purlType: "golang"}})
		return db, sbom
	}
	// incompleteWithWontFix: a wont-fix finding AND a second, unrelated
	// package the cataloger drops (unsupported purl type) - the shape D11's
	// precedence needs, a scan that is both incomplete and carries a
	// wont-fix finding.
	incompleteWithWontFix := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "RHSA-wontfix-incomplete", pkg: "wontfixincomplete", vectors: []string{vecCritical},
				unfixable: true, fixState: advisory.FixStateWontFix},
		})
		sbom = buildMatrixSBOM(t, []matrixPkg{
			{name: "wontfixincomplete", purlType: "golang"},
			{name: "somecrate", purlType: "cargo"}, // dropped by the cataloger
		})
		return db, sbom
	}

	cases := []struct {
		name    string
		fixture func(t *testing.T) (db, sbom string)
		opts    Options
		want    int
	}{
		{"a wont-fix finding does not trip the gate when the flag is not given at all",
			wontFixOnly, Options{}, 0},

		{"--fail-on-unfixable=wont-fix trips on a wont-fix finding",
			wontFixOnly, Options{FailOnUnfixableWontFix: true}, 1},

		// The case the brief calls out by name: a broad implementation that
		// gated on Unfixable() alone, ignoring FixState, would also exit 1
		// here and this row would be the only thing to catch it.
		{"--fail-on-unfixable=wont-fix does NOT trip on a not-fixed-only result",
			notFixedOnly, Options{FailOnUnfixableWontFix: true}, 0},
		{"--fail-on-unfixable=wont-fix does NOT trip when the only unfixable finding's state is unknown",
			unknownStateOnly, Options{FailOnUnfixableWontFix: true}, 0},

		// The broad gate (D48) is unchanged by D52's narrower one: it still
		// fires on every shape of unfixable finding, wont-fix or not.
		{"the broad --fail-on-unfixable still trips on a not-fixed-only result",
			notFixedOnly, Options{FailOnUnfixable: true}, 1},
		{"the broad --fail-on-unfixable still trips on a wont-fix finding too",
			wontFixOnly, Options{FailOnUnfixable: true}, 1},

		// D11: 2 > 1 > 0. An incomplete scan outranks its own findings, so the
		// wont-fix gate below must never be allowed to report 1 here.
		{"precedence: incomplete beats fail-on-unfixable=wont-fix (D11, 2 > 1)",
			incompleteWithWontFix,
			Options{FailOnIncomplete: true, FailOnUnfixableWontFix: true}, 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, sbom := tc.fixture(t)
			var out, errOut bytes.Buffer
			got := Run(context.Background(), db, sbom, tc.opts, &out, &errOut)
			if got != tc.want {
				t.Errorf("Run() = %d, want %d\nstdout:\n%s\nstderr:\n%s",
					got, tc.want, out.String(), errOut.String())
			}
		})
	}
}

// TestRun_FailOnKEVAndEPSSGates is D86's analogue of
// TestRun_FailOnUnfixableWontFixGate just above, on its own table shape: a
// finding's KEV/EPSS rows enter through a rating (D27's shape, exactly like
// TestRun_AnNVDRatingReachesTheGate's NVD one), never through the advisory
// itself, so every fixture here builds the advisory with buildMatrixDB and
// then attaches the exploit-signal rating with putRating.
func TestRun_FailOnKEVAndEPSSGates(t *testing.T) {
	// kevListed: one finding, and CISA's catalog lists its CVE.
	kevListed := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "PYSEC-kev", pkg: "kevlisted", fixed: "2.0.0",
				aliases: []string{"CVE-2025-9001"}, vectors: []string{vecMedium}},
		})
		putRating(t, db, advisory.Rating{CVE: "CVE-2025-9001", Source: "KEV",
			KEV: true, KEVDateAdded: "2025-01-01", KEVRansomware: "Known"})
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "kevlisted", purlType: "golang"}})
		return db, sbom
	}
	// notKevListed: a finding with no KEV rating at all -- isolates "the flag
	// does nothing when nothing is listed" from kevListed's always-present row.
	notKevListed := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "PYSEC-nokev", pkg: "notkevlisted", fixed: "2.0.0", vectors: []string{vecMedium}},
		})
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "notkevlisted", purlType: "golang"}})
		return db, sbom
	}
	// highEPSS: one finding, EPSS-scored well above the 0.5 threshold every
	// row below uses.
	highEPSS := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "PYSEC-hiepss", pkg: "highepss", fixed: "2.0.0",
				aliases: []string{"CVE-2025-9002"}, vectors: []string{vecMedium}},
		})
		putRating(t, db, advisory.Rating{CVE: "CVE-2025-9002", Source: "EPSS",
			EPSS: 0.94, EPSSPercentile: 0.99, EPSSModel: "v-test"})
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "highepss", purlType: "golang"}})
		return db, sbom
	}
	// lowEPSS: EPSS-scored, but below the threshold -- isolates "scored but
	// not high enough" from an absent score entirely.
	lowEPSS := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "PYSEC-loepss", pkg: "lowepss", fixed: "2.0.0",
				aliases: []string{"CVE-2025-9003"}, vectors: []string{vecMedium}},
		})
		putRating(t, db, advisory.Rating{CVE: "CVE-2025-9003", Source: "EPSS",
			EPSS: 0.1, EPSSPercentile: 0.2, EPSSModel: "v-test"})
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "lowepss", purlType: "golang"}})
		return db, sbom
	}
	// noEPSS: a finding with no EPSS rating at all -- D17's "absent stays
	// absent" case. Even the loosest possible threshold (0.0, "fail on
	// anything EPSS has scored") must not trip on a finding EPSS never
	// scored, which is the whole reason MaxEPSS returns an ok bool rather
	// than treating a missing score as probability zero.
	noEPSS := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "PYSEC-noepss", pkg: "noepss", fixed: "2.0.0", vectors: []string{vecMedium}},
		})
		sbom = buildMatrixSBOM(t, []matrixPkg{{name: "noepss", purlType: "golang"}})
		return db, sbom
	}
	// kevAndIncomplete: a KEV-listed finding AND a second, unrelated package
	// the cataloger drops (unsupported purl type) -- the shape D11's
	// precedence needs.
	kevAndIncomplete := func(t *testing.T) (db, sbom string) {
		db = buildMatrixDB(t, []matrixAdv{
			{id: "PYSEC-kevinc", pkg: "kevincomplete", fixed: "2.0.0",
				aliases: []string{"CVE-2025-9004"}, vectors: []string{vecMedium}},
		})
		putRating(t, db, advisory.Rating{CVE: "CVE-2025-9004", Source: "KEV", KEV: true})
		sbom = buildMatrixSBOM(t, []matrixPkg{
			{name: "kevincomplete", purlType: "golang"},
			{name: "somecrate", purlType: "cargo"}, // dropped by the cataloger
		})
		return db, sbom
	}

	threshold := 0.5
	zeroThreshold := 0.0

	cases := []struct {
		name    string
		fixture func(t *testing.T) (db, sbom string)
		opts    Options
		want    int
	}{
		{"a KEV-listed finding does not trip the gate when the flag is not given", kevListed, Options{}, 0},
		{"--fail-on-kev trips on a KEV-listed finding", kevListed, Options{FailOnKEV: true}, 1},
		{"--fail-on-kev does not trip when nothing is KEV-listed", notKevListed, Options{FailOnKEV: true}, 0},

		{"--fail-on-epss 0.5 trips at 0.94", highEPSS, Options{FailOnEPSS: &threshold}, 1},
		{"--fail-on-epss 0.5 does not trip at 0.1", lowEPSS, Options{FailOnEPSS: &threshold}, 0},
		{"--fail-on-epss never trips on a finding EPSS never scored, even at the loosest threshold (D17)",
			noEPSS, Options{FailOnEPSS: &zeroThreshold}, 0},

		// D11: 2 > 1 > 0. An incomplete scan outranks a KEV/EPSS finding
		// exactly as it outranks every other exit-1 gate.
		{"precedence: incomplete beats fail-on-kev (D11, 2 > 1)",
			kevAndIncomplete, Options{FailOnIncomplete: true, FailOnKEV: true}, 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, sbom := tc.fixture(t)
			var out, errOut bytes.Buffer
			got := Run(context.Background(), db, sbom, tc.opts, &out, &errOut)
			if got != tc.want {
				t.Errorf("Run() = %d, want %d\nstdout:\n%s\nstderr:\n%s",
					got, tc.want, out.String(), errOut.String())
			}
		})
	}
}

// TestRun_OutputJSON is the wiring test for Options.Output == "json": Run
// must call report.JSON instead of report.Table, and --output json must not
// merely add JSON alongside the table — `assay scan ... --output json | jq`
// requires the JSON document to be the ONLY thing on stdout.
func TestRun_OutputJSON(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-json-medium", pkg: "jsonmedium", fixed: "2.0.0", vectors: []string{vecMedium}},
	})
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "jsonmedium", purlType: "golang"}})

	t.Run("plain --output json exits 0 and writes only the document", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, sbom, Options{Output: "json"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("Run() = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
		}
		var doc report.Document
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
		}
		if doc.SchemaVersion != 8 {
			t.Errorf("SchemaVersion = %d, want 8", doc.SchemaVersion)
		}
		if len(doc.Findings) != 1 || doc.Findings[0].Advisory.ID != "GHSA-json-medium" {
			t.Errorf("Findings = %+v, want the one medium finding", doc.Findings)
		}
		// The table's own header would prove Run fell back to Table instead
		// of replacing it, silently defeating the "ONLY thing on stdout"
		// contract --output json exists to uphold.
		if strings.Contains(out.String(), "PACKAGE") {
			t.Errorf("stdout contains the table header; --output json must replace "+
				"Table entirely:\n%s", out.String())
		}
	})

	// A dropped Output field on the way into Run would silently fall back to
	// Table while still honouring FailOn — this pins that --output json and
	// --fail-on compose, not just that each works alone.
	t.Run("--output json still honours --fail-on", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, sbom, Options{Output: "json", FailOn: &bandMedium}, &out, &errOut)
		if code != 1 {
			t.Fatalf("Run() = %d, want 1 (exitFindings)\nstdout:\n%s\nstderr:\n%s",
				code, out.String(), errOut.String())
		}
		var doc report.Document
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("stdout is not valid JSON even though --fail-on tripped: %v\n%s", err, out.String())
		}
	})
}

// TestRun_OutputSARIF is the run()-seam wiring check for --output sarif,
// mirroring TestRun_OutputJSON above. report.SARIF has a thorough direct
// suite (internal/report/sarif_test.go) and cmd/assay's own tests only
// assert that parseScanArgs sets Options.Output == "sarif" -- nothing
// anywhere drives Run (or the CLI's run()) with sarif output, so the
// opts.Output == "sarif" case in Run's renderer switch is held by nothing:
// changing that comparison to any other string (or deleting the case) falls
// through to the default Table renderer and leaves the whole suite green,
// silently handing a SARIF-format request a human table instead.
func TestRun_OutputSARIF(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-sarif-medium", pkg: "sarifmedium", fixed: "2.0.0", vectors: []string{vecMedium}},
	})
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "sarifmedium", purlType: "golang"}})

	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, sbom, Options{Output: "sarif"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("Run() = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
	}
	// The SARIF-specific top-level shape (report/sarif.go's unexported
	// sarifDocument: "$schema" and the SARIF spec version), which the plain
	// table and the plain JSON document ("schemaVersion", an int, per
	// report/json.go) do not carry.
	if !strings.Contains(out.String(), `"$schema"`) || !strings.Contains(out.String(), `"version": "2.1.0"`) {
		t.Errorf("stdout does not look like a SARIF document:\n%s", out.String())
	}
	if strings.Contains(out.String(), `"schemaVersion"`) {
		t.Errorf("stdout carries the plain JSON renderer's field; --output sarif "+
			"must replace it entirely:\n%s", out.String())
	}
	// The table's own header would prove Run fell back to Table instead of
	// replacing it, the same fallback TestRun_OutputJSON's identical check
	// guards against for --output json.
	if strings.Contains(out.String(), "PACKAGE") {
		t.Errorf("stdout contains the table header; --output sarif must replace "+
			"Table entirely:\n%s", out.String())
	}
}

// TestRun_Explain is the wiring test for Options.Explain: Run must call
// report.Explain instead of report.Table/JSON, the verdict (--fail-on* gates,
// D11) must still apply on top of it, and an identifier matching nothing
// must be exit 2 with stdout untouched rather than a quiet, empty success.
func TestRun_Explain(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-explain-wired", pkg: "explainwired", fixed: "2.0.0", vectors: []string{vecCritical}},
	})
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "explainwired", purlType: "golang"}})

	t.Run("matching id: writes the explanation, table replaced entirely", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, sbom, Options{Explain: "GHSA-explain-wired"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("Run() = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
		}
		if !strings.Contains(out.String(), "GHSA-explain-wired") {
			t.Errorf("stdout does not contain the explanation:\n%s", out.String())
		}
		if strings.Contains(out.String(), "PACKAGE") {
			t.Errorf("stdout contains the table header; --explain must replace "+
				"Table entirely:\n%s", out.String())
		}
	})

	// Explain mode is a different renderer, not a different verdict: a
	// dropped opts.FailOn on the way into the explain branch of Run would
	// silently pass this test's baseline row but fail here.
	t.Run("--explain plus --fail-on still trips the gate", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, sbom,
			Options{Explain: "GHSA-explain-wired", FailOn: &bandCritical}, &out, &errOut)
		if code != 1 {
			t.Fatalf("Run() = %d, want 1 (exitFindings): --explain must not bypass "+
				"the verdict\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
		}
	})

	t.Run("no finding matches the given id: exit 2, stdout untouched", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, sbom, Options{Explain: "GHSA-does-not-exist"}, &out, &errOut)
		if code != 2 {
			t.Fatalf("Run() = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
		}
		if out.Len() != 0 {
			t.Errorf("stdout polluted on a no-match explain: %q", out.String())
		}
		if !strings.Contains(errOut.String(), "GHSA-does-not-exist") {
			t.Errorf("stderr = %q, want it to name the identifier that matched nothing", errOut.String())
		}
	})
}

// TestRun_FailOnIncompleteAndUnknownAgreeAcrossRenderers is the drift guard
// for F3: Run picks exactly one of report.Table / report.JSON /
// report.Explain, but whichever it picks, the Summary that reaches verdict()
// has to be the SAME Summary that renderer actually computed (via
// report.Summarize, directly or through Table/JSON's own call to it) —
// never a second, independently-derived Summary that could silently drift
// from what the renderer itself found.
//
// The refactor that pulled Summarize out of Table was justified by exactly
// this "one computation, not two" reasoning; this test is that guarantee
// checked one level up, at the exit code. --fail-on is deliberately NOT one
// of the gates exercised here: verdict()'s FailOn arm reads res.Findings
// directly and never touches sum at all, so a composition test built only
// on --fail-on would stay green even if a renderer's sum were replaced by
// nonsense — it would give false confidence rather than real coverage.
// --fail-on-incomplete and --fail-on-unknown are the two gates that read sum
// (NotEvaluated/IncompleteChecks and UnknownSeverity respectively), so they
// are the ones that can actually observe the drift.
//
// The fixture carries all three conditions the exit-code matrix cares about
// at once: an unrated finding (UnknownSeverity), a package whose one
// advisory has an unparsable bound (IncompleteChecks), and a package the
// cataloger drops before the matcher ever sees it (NotEvaluated). --explain
// targets the unrated finding's own advisory, so the explain path finds a
// real match (n > 0) rather than short-circuiting on "nothing matched"
// before verdict() is ever reached.
// Explain shows one finding, so on its own it says nothing about the rest of
// the scan. The table prints the counts and the "Not evaluated" block and the
// JSON document carries them in `summary`; explain had neither, on either
// stream, so `--explain X` against a partially-evaluated target printed a
// confident explanation and exited 0 with the gap disclosed nowhere. CLAUDE.md:
// packages that cannot be evaluated are "never folded silently into a clean
// verdict".
func TestRun_ExplainDisclosesAnIncompleteScan(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-explain-partial", pkg: "explainpartial", fixed: "2.0.0", vectors: []string{vecCritical}},
	})
	// One package the database covers, one in an ecosystem it does not - so
	// the scan produces a finding AND leaves a package unevaluated.
	sbom := buildMatrixSBOM(t, []matrixPkg{
		{name: "explainpartial", purlType: "golang"},
		{name: "somecrate", purlType: "cargo"},
	})

	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, sbom, Options{Explain: "GHSA-explain-partial"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("Run = %d, want 0 (no gate was asked for); stderr:\n%s", code, errOut.String())
	}
	// The explanation itself still owns stdout alone.
	if !strings.Contains(out.String(), "GHSA-explain-partial") {
		t.Errorf("stdout is missing the explanation:\n%s", out.String())
	}
	// ...and the warning is on stderr, so `--explain X > file` still yields a
	// clean explanation while a human at a terminal sees the caveat.
	if strings.Contains(out.String(), "NOT complete") {
		t.Errorf("the incompleteness warning went to stdout:\n%s", out.String())
	}
	if !strings.Contains(errOut.String(), "NOT complete") {
		t.Errorf("stderr does not disclose that the scan was incomplete:\n%s", errOut.String())
	}
	// The count itself, not just the word: a warning that always says the same
	// thing regardless of how much went unchecked is not a disclosure.
	if !strings.Contains(errOut.String(), "1 package(s) not evaluated") {
		t.Errorf("stderr does not say HOW MUCH went unevaluated:\n%s", errOut.String())
	}
}

// The other half of the gate. The fixture above produces NotEvaluated only, so
// keying the warning on that count alone survives it - the same shape that hid
// half of --fail-on-incomplete's condition one task earlier. Here every package
// IS evaluated and one advisory cannot be judged, so only IncompleteChecks is
// non-zero.
func TestRun_ExplainDisclosesAnIncompleteCheck(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-explain-check", pkg: "explaincheck", fixed: "2.0.0", vectors: []string{vecCritical}},
		{id: "GHSA-explain-bad", pkg: "explaincheck"}, // fixed == "" -> malformed -> IncompleteChecks
	})
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "explaincheck", purlType: "golang"}})

	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, sbom,
		Options{Explain: "GHSA-explain-check"}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0; stderr:\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "1 check(s) incomplete") {
		t.Errorf("stderr does not disclose the incomplete check:\n%s", errOut.String())
	}
}

// The mirror: a fully-evaluated scan must not print the warning, or it becomes
// noise every reader learns to skip.
func TestRun_ExplainIsQuietWhenTheScanIsComplete(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-explain-full", pkg: "explainfull", fixed: "2.0.0", vectors: []string{vecCritical}},
	})
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "explainfull", purlType: "golang"}})

	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, sbom, Options{Explain: "GHSA-explain-full"}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0; stderr:\n%s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "NOT complete") {
		t.Errorf("a complete scan warned about incompleteness:\n%s", errOut.String())
	}
}

// buildRoutingDB writes one advisory per name, each affecting Go ecosystem
// package name (verbatim, no "example.com/" prefixing - unlike buildMatrixDB,
// this needs real, unprefixed names: "stdlib" itself, and a real module
// path), at versions [0, 99.0.0). Used by TestRun_RoutesEachTargetKind so
// each row's scan produces exactly one real finding naming the package that
// row's OWN cataloger reached — buildMatrixDB(t, nil) (no advisories at all)
// cannot distinguish "the right cataloger ran" from "any cataloger returned
// any non-empty component count", since Summary.Components is nonzero the
// moment a single package is cataloged, wrong package or not.
func buildRoutingDB(t *testing.T, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i, n := range names {
		if err := w.Put(advisory.Advisory{
			ID:   fmt.Sprintf("GHSA-routing-%d", i),
			Kind: advisory.KindVulnerability,
			Affected: []advisory.Affected{{
				Ecosystem: "Go",
				Name:      n,
				Ranges: []advisory.Range{{
					Type:   advisory.RangeSemver,
					Events: []advisory.Event{{Introduced: "0"}, {Fixed: "99.0.0"}},
				}},
			}},
			Severity: []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}},
		}); err != nil {
			t.Fatalf("Put(%s): %v", n, err)
		}
	}
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Go"}}},
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// Each of the four kinds reaches its own cataloger. A kind routed to the
// wrong parser is the failure D22 exists to prevent, and the error it then
// produces names the wrong problem - a binary handed to the CycloneDX parser
// reports a malformed document.
//
// The assertion is on what each scan FOUND - the exact package named in the
// finding, read back out of tt.wantPkg - not merely that some cataloger
// returned a nonzero component count: every one of these exits 0 and, with
// no seeded advisory naming its package, would also report a nonzero
// Components count if routed to the WRONG cataloger, as long as that wrong
// cataloger found anything at all to catalog. buildRoutingDB seeds one
// advisory per row's own real package name so each row's finding can be
// checked against tt.wantPkg specifically.
func TestRun_RoutesEachTargetKind(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.test/app\n\nrequire github.com/routed/dep v1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5",`+
		`"version":1,"components":[{"type":"library","name":"sbomonly","version":"1.0.0",`+
		`"purl":"pkg:golang/example.com/sbomonly@1.0.0"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	db := buildRoutingDB(t, "stdlib", "github.com/routed/dep", "example.com/sbomonly")

	for _, tt := range []struct {
		name   string
		target string
		// The exact substring the disclosure line must contain for this
		// kind, article and all - source.TargetKind.String() itself, so a
		// row can only pass by naming its OWN kind (unlike a bare "as a
		// go-binary" fallback disjunct, which is satisfied by any row's
		// stderr and would let a directory or sbom row silently pass
		// through the go-binary check).
		wantDisclosure string
		// A package name that appears ONLY when this kind's cataloger ran.
		// Distinct strings with no substring relationship between them, so a
		// row cannot pass from another row's output.
		wantPkg string
	}{
		{"go binary", "file:" + self, "as a go-binary", "stdlib"},
		{"directory", "dir:" + dir, "as a directory", "github.com/routed/dep"},
		{"sbom", "sbom:" + sbom, "as an sbom", "example.com/sbomonly"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), db, tt.target,
				Options{Output: "json"}, &out, &errOut); code != 0 {
				t.Fatalf("Run = %d, want 0; stderr:\n%s", code, errOut.String())
			}
			var doc struct {
				Findings []struct {
					Package struct {
						Name string `json:"name"`
					} `json:"package"`
				} `json:"findings"`
				Summary struct {
					Components int `json:"components"`
				} `json:"summary"`
			}
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("stdout is not one JSON document: %v\n%s", err, out.String())
			}
			if doc.Summary.Components == 0 {
				t.Fatalf("%s produced no components; it was routed to the wrong cataloger\n%s",
					tt.name, out.String())
			}
			// The real assertion: not just "a cataloger ran", but "THIS
			// row's own cataloger ran" - read back via the package name the
			// seeded advisory actually matched.
			if len(doc.Findings) != 1 {
				t.Fatalf("%s produced %d finding(s), want exactly 1 (the seeded advisory "+
					"against %q)\n%s", tt.name, len(doc.Findings), tt.wantPkg, out.String())
			}
			if got := doc.Findings[0].Package.Name; got != tt.wantPkg {
				t.Errorf("%s cataloged package %q, want %q - routed to the wrong cataloger",
					tt.name, got, tt.wantPkg)
			}
			// The scan reports how it classified the target, so assert on
			// that too: it is the thing D22 promises is visible.
			if !strings.Contains(errOut.String(), tt.wantDisclosure) {
				t.Errorf("stderr does not contain %q:\n%s", tt.wantDisclosure, errOut.String())
			}
		})
	}
}

// The kind is disclosed, on stderr, so stdout stays a clean document and
// `--output json | jq` is unaffected. A wrong guess must be visible in the
// output rather than inferred from a confusing downstream error.
func TestRun_ReportsHowTheTargetWasClassified(t *testing.T) {
	db := buildMatrixDB(t, nil)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.test/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, dir, Options{}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0; stderr:\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "as a directory") {
		t.Errorf("stderr does not say how the target was classified:\n%s", errOut.String())
	}
	// Not on stdout: that belongs to the report.
	if strings.Contains(out.String(), "as a directory") {
		t.Errorf("the classification went to stdout:\n%s", out.String())
	}
}

// A directory scan says what go.mod is and is not. Without it the 11-of-52
// gap is invisible and a clean directory scan reads as a clean project - the
// silent partial coverage D20 and D21 exist to prevent, arriving through a
// new door.
func TestRun_ADirectoryScanStatesItsLimitation(t *testing.T) {
	db := buildMatrixDB(t, nil)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.test/app\n\nrequire github.com/a/b v1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	Run(context.Background(), db, dir, Options{}, &out, &errOut)
	for _, want := range []string{"go.mod", "not what a build links", "binary"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr missing %q - the limitation is not stated:\n%s", want, errOut.String())
		}
	}
}

// ...and a binary scan does not carry that warning, because it has no such
// gap. A caveat printed on every scan is a caveat readers learn to skip.
func TestRun_ABinaryScanDoesNotWarnAboutGoMod(t *testing.T) {
	db := buildMatrixDB(t, nil)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	Run(context.Background(), db, "file:"+self, Options{}, &out, &errOut)
	if strings.Contains(errOut.String(), "not what a build links") {
		t.Errorf("a binary scan carried the go.mod caveat:\n%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "as a go-binary") {
		t.Errorf("stderr does not say the target was read as a binary:\n%s", errOut.String())
	}
}

// The classification must be visible even when the cataloger THEN fails -
// that is precisely when a reader most needs it: a typo'd path or a
// directory missing its go.mod otherwise reports only a confusing
// downstream error ("dial tcp: lookup .: no such host" for a mistyped path
// that fell through to the registry loader; "read go.mod: ... no such file"
// for an empty directory) with no hint of what assay guessed the target
// was. Printing the disclosure only after the cataloger succeeds means every
// error path returns 2 before it is ever reached - this is that gap, closed.
func TestRun_DisclosesTheKindEvenWhenTheCatalogerFails(t *testing.T) {
	db := buildMatrixDB(t, nil)

	t.Run("go-binary target that cannot be read", func(t *testing.T) {
		var out, errOut bytes.Buffer
		target := "file:" + filepath.Join(t.TempDir(), "absent.bin")
		if code := Run(context.Background(), db, target, Options{}, &out, &errOut); code != 2 {
			t.Fatalf("Run = %d, want 2", code)
		}
		assertDisclosurePrecedesError(t, errOut.String(), "as a go-binary")
	})

	t.Run("directory target with no go.mod", func(t *testing.T) {
		var out, errOut bytes.Buffer
		target := "dir:" + t.TempDir() // an empty directory: no go.mod at all
		if code := Run(context.Background(), db, target, Options{}, &out, &errOut); code != 2 {
			t.Fatalf("Run = %d, want 2", code)
		}
		assertDisclosurePrecedesError(t, errOut.String(), "as a directory")
	})
}

// assertDisclosurePrecedesError asserts both that want (the disclosure
// substring) appears in stderr AND that it appears strictly BEFORE the
// "error:" line - not merely that both are present somewhere in the stream.
// Ordering is the entire point of this test: a `defer` around the
// disclosure's Fprintf would make it print at function return, after the
// error line, and a presence-only check ("stderr contains X" and, in a
// second assertion, "stderr contains error:") would not catch that at all,
// since both substrings would still be present - just in the wrong order,
// which is exactly the "confusing downstream error" shape F1 exists to fix.
func assertDisclosurePrecedesError(t *testing.T, stderr, want string) {
	t.Helper()
	di := strings.Index(stderr, want)
	if di < 0 {
		t.Fatalf("stderr does not disclose the classification despite the failure:\n%s", stderr)
	}
	ei := strings.Index(stderr, "error:")
	if ei < 0 {
		t.Fatalf("stderr does not contain an error line at all:\n%s", stderr)
	}
	if di >= ei {
		t.Errorf("disclosure (%q at byte %d) did not precede the error line (at byte %d):\n%s",
			want, di, ei, stderr)
	}
}

// buildBBoltBinary compiles a tiny throwaway program that imports
// go.etcd.io/bbolt - a real dependency already in this repository's module
// cache (internal/store's own choice, D4), so no network fetch - and returns
// the resulting binary's path.
//
// This deliberately does NOT scan os.Executable() (this package's own `go
// test` binary), unlike the sibling routing tests above. Measured: this
// package's own compiled test binary's build info reports zero dependencies
// - only the main module and stdlib - even though the binary is genuinely
// linked against go.etcd.io/bbolt through internal/store. Reproduced on an
// unrelated, throwaway module with no connection to this repository, so it
// is a property of `go test`-built binaries for a package that is not
// itself `package main` on this toolchain, not something scancmd.Run or
// gobinary.Parse get wrong - a real `go build` binary does not have this
// gap, which is exactly what internal/cataloger/gobinary's own
// TestParse_ReportsLinkedDependencies fixture already relies on. Building
// one here the same way is what makes a genuine, non-fixture-shaped finding
// observable through Run for a go-binary target, in an environment where
// self-scanning cannot.
func buildBBoltBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH; this test needs a toolchain to build its fixture")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.test/scanned\n\ngo 1.26\n\nrequire go.etcd.io/bbolt v1.5.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\n\nimport _ \"go.etcd.io/bbolt\"\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(dir, "app.bin.exe")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", bin, ".")
	cmd.Dir = dir
	// GOFLAGS=-mod=mod lets the build resolve from the module cache without
	// its own go.sum; GOPROXY=off makes a cache miss an honest skip rather
	// than a silent network fetch (matching
	// internal/cataloger/gobinary/gobinary_test.go's runGoBuild).
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off", "GOSUMDB=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "module lookup disabled by GOPROXY=off") {
			t.Skipf("go build failed (%v); fixture needs a module not in the local cache:\n%s", err, out)
		}
		t.Fatalf("go build failed (%v):\n%s", err, out)
	}
	return bin
}

// The gates are the contract, and a new target kind that reaches a different
// verdict path would break them silently. Both target kinds this test's own
// name promises genuinely reach go.etcd.io/bbolt: the binary links it for
// real (buildBBoltBinary), and the directory's go.mod requires it directly -
// gomod.Parse needs no toolchain to see that, so no `go build` is needed for
// this half.
func TestRun_GatesApplyToBinaryAndDirectoryTargets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.test/gated\n\ngo 1.26\n\nrequire go.etcd.io/bbolt v1.5.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// An advisory against a module both target kinds below genuinely reach.
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-binary-hit", pkg: "go.etcd.io/bbolt", fixed: "99.0.0", vectors: []string{vecCritical}},
	})

	none := severity.None
	gates := []struct {
		name string
		opts Options
		want int
	}{
		{"no flags", Options{}, 0},
		{"--fail-on none trips on a critical finding", Options{FailOn: &none}, 1},
	}
	runGates := func(t *testing.T, target string) {
		t.Helper()
		for _, tt := range gates {
			t.Run(tt.name, func(t *testing.T) {
				var out, errOut bytes.Buffer
				if got := Run(context.Background(), db, target, tt.opts, &out, &errOut); got != tt.want {
					t.Errorf("Run = %d, want %d; stdout:\n%s\nstderr:\n%s",
						got, tt.want, out.String(), errOut.String())
				}
			})
		}
	}

	// buildBBoltBinary is called INSIDE the go-binary branch's own t.Run,
	// not once at the top of the function shared by both branches: it calls
	// t.Skip when `go` is not on PATH, and a Skip on the parent *testing.T
	// aborts everything that follows in the same function - including the
	// directory branch below, whose own comment already says it needs no
	// toolchain at all. Scoping the skip to its own subtest is what lets a
	// toolchain-less runner still exercise the directory half; the previous
	// shape silently lost exactly that coverage in exactly the environment
	// where nobody would notice. Same shape as Task 2's F3 (a git-availability
	// skip erasing an unrelated sibling case's coverage).
	t.Run("go-binary target", func(t *testing.T) {
		bin := buildBBoltBinary(t)
		runGates(t, "file:"+bin)
	})

	t.Run("directory target", func(t *testing.T) {
		runGates(t, "dir:"+dir)
	})
}

func TestRun_FailOnIncompleteAndUnknownAgreeAcrossRenderers(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-renderer-unknownsev", pkg: "rendererunknownsev", fixed: "2.0.0"}, // no vectors -> Unknown
		{id: "GHSA-renderer-badcompare", pkg: "rendererbadcompare"},                 // fixed == "" -> malformed -> IncompleteChecks
	})
	sbom := buildMatrixSBOM(t, []matrixPkg{
		{name: "rendererunknownsev", purlType: "golang"},
		{name: "rendererbadcompare", purlType: "golang"},
		{name: "renderersomecrate", purlType: "cargo"}, // dropped by the cataloger -> NotEvaluated
	})

	renderers := []struct {
		name string
		opts Options // Output/Explain only; the gate under test is merged in below
	}{
		{"table", Options{}},
		{"json", Options{Output: "json"}},
		{"explain", Options{Explain: "GHSA-renderer-unknownsev"}},
	}
	gates := []struct {
		name string
		set  func(*Options)
		want int
	}{
		{"--fail-on-incomplete", func(o *Options) { o.FailOnIncomplete = true }, 2},
		{"--fail-on-unknown", func(o *Options) { o.FailOnUnknown = true }, 1},
	}

	for _, r := range renderers {
		for _, g := range gates {
			t.Run(r.name+"/"+g.name, func(t *testing.T) {
				opts := r.opts // copy: Options is a plain value type
				g.set(&opts)
				var out, errOut bytes.Buffer
				got := Run(context.Background(), db, sbom, opts, &out, &errOut)
				if got != g.want {
					t.Errorf("renderer=%s gate=%s: Run() = %d, want %d\nstdout:\n%s\nstderr:\n%s",
						r.name, g.name, got, g.want, out.String(), errOut.String())
				}
			})
		}
	}
}

// The scenario D25 exists for, driven through Run: one source rates a finding
// critical, another rates the same vulnerability not at all, and --fail-on
// critical must exit 1 whichever record the store lists first.
//
// Both orders are exercised because only one of them used to fail. The store
// returns advisories in the order the package index lists them, which is the
// order the provider walked the archives in — so before the aggregate, the
// unrated record winning meant the finding reported unknown, unknown never
// trips a threshold (D17), and CI went green on a critical vulnerability.
func TestRun_FailOnUsesTheHighestSourceRegardlessOfOrder(t *testing.T) {
	rec := func(id string, rated bool) matrixAdv {
		a := matrixAdv{id: id, pkg: "shared", fixed: "2.0.0",
			aliases: []string{"CVE-2022-28347"}}
		if rated {
			a.vectors = []string{vecCritical}
		}
		return a
	}
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "shared", purlType: "golang"}})

	// Which database carries the vector is varied as well as which record the
	// store returns first. Pinning it on GHSA would leave the rated record
	// always sorting first among the ratings, and a gate reading "the first
	// rating" rather than the highest would pass every case.
	for _, who := range []struct {
		name        string
		ghsaIsRated bool
	}{
		{"rated by the database that sorts first", true},
		{"rated by the database that sorts last", false},
	} {
		ghsa := rec("GHSA-w24h-v9qh-8gxj", who.ghsaIsRated)
		pysec := rec("PYSEC-2022-191", !who.ghsaIsRated)
		cases := []struct {
			name string
			recs []matrixAdv
		}{
			{"GHSA record first", []matrixAdv{ghsa, pysec}},
			{"PYSEC record first", []matrixAdv{pysec, ghsa}},
		}
		for _, tc := range cases {
			t.Run(who.name+", "+tc.name, func(t *testing.T) {
				critical := severity.Critical
				var out, errOut bytes.Buffer
				code := Run(context.Background(), buildMatrixDB(t, tc.recs), sbom,
					Options{FailOn: &critical}, &out, &errOut)
				if code != 1 {
					t.Errorf("Run = %d, want 1 — one source rates this critical, so "+
						"the finding is critical whichever record came back first "+
						"and whichever database rated it; stdout:\n%s",
						code, out.String())
				}
			})
		}
	}
}

// The mirror of it, and the boundary D17 draws: a finding every source left
// unrated does not trip --fail-on even at the lowest threshold, however many
// sources reported it. Three unrated ratings do not add up to a rated finding.
func TestRun_ManyUnratedSourcesStillDoNotTripFailOn(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "PYSEC-2022-191", pkg: "unrated", fixed: "2.0.0", aliases: []string{"CVE-2022-28347"}},
		{id: "PYSEC-2022-192", pkg: "unrated", fixed: "2.0.0", aliases: []string{"CVE-2022-28347"}},
		{id: "GO-2022-0001", pkg: "unrated", fixed: "2.0.0", aliases: []string{"CVE-2022-28347"}},
	})
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "unrated", purlType: "golang"}})

	none := severity.None
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, sbom,
		Options{FailOn: &none}, &out, &errOut); code != 0 {
		t.Errorf("Run = %d, want 0 — unknown never trips a threshold (D17), "+
			"however many sources reported it; stdout:\n%s", code, out.String())
	}
	// The three records are one vulnerability, so they are one finding with
	// three ratings. Asserted because without it the test would also pass on a
	// build that produced three separate unknown findings — which trips no
	// threshold either, and would leave the aggregate untested.
	unratedRows := strings.Count(out.String(), "example.com/unrated")
	if unratedRows != 1 {
		t.Errorf("the report shows %d rows for this package, want 1 — the three "+
			"records share a CVE, so they are one finding carrying three "+
			"ratings; stdout:\n%s", unratedRows, out.String())
	}
}

// The ordering claim, proven at the seam a user actually reads: the same
// advisories written to the store in opposite order produce byte-identical
// JSON.
//
// This is the property D25 exists to establish, and it is asserted on the
// whole document rather than on the verdict, because the verdict was only ever
// half of it — the report also prints the advisory ID, its summary, and the
// fixed version, all taken from one record. The store returns advisories in
// the order the package index lists them, and that order is the order the
// provider walked the OSV archives in, so "reversed" here is the same
// difference a re-run of `assay db update` could produce.
//
// Every rating in the fixture disagrees with its sibling on something the
// document shows: the band, the score, and the fixed version. If any of those
// were still taken from whichever record arrived first, the two documents
// would differ.
func TestRun_JSONIsIdenticalWhenRecordOrderIsReversed(t *testing.T) {
	recs := []matrixAdv{
		{id: "GHSA-w24h-v9qh-8gxj", pkg: "shared", fixed: "2.0.0",
			vectors: []string{vecCritical}, aliases: []string{"CVE-2022-28347"}},
		{id: "PYSEC-2022-191", pkg: "shared", fixed: "3.1.0",
			vectors: []string{vecMedium}, aliases: []string{"CVE-2022-28347"}},
		{id: "GO-2022-0001", pkg: "shared", fixed: "2.5.0",
			aliases: []string{"CVE-2022-28347"}},
	}
	reversed := make([]matrixAdv, len(recs))
	for i, r := range recs {
		reversed[len(recs)-1-i] = r
	}
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "shared", purlType: "golang"}})

	render := func(order []matrixAdv) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), buildMatrixDB(t, order), sbom,
			Options{Output: "json"}, &out, &errOut); code != 0 {
			t.Fatalf("Run = %d, want 0; stderr: %s", code, errOut.String())
		}
		return out.String()
	}

	forward, backward := render(recs), render(reversed)
	if forward != backward {
		t.Errorf("the JSON depends on the order records were written:\n"+
			"--- records forward ---\n%s\n--- records reversed ---\n%s",
			forward, backward)
	}
	// Guards the guard. If grouping broke and the three records came out as
	// three single-rating findings, the comparison above would still pass —
	// the documents stay byte-identical because sortFindings is a total order
	// — and this test would be checking nothing. Counting ratings alone does
	// not catch that: three findings carrying one rating each also counts
	// three. The finding count is what distinguishes them.
	var doc struct {
		Findings []struct {
			Ratings []struct {
				Database string `json:"database"`
			} `json:"ratings"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(forward), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(doc.Findings) != 1 || len(doc.Findings[0].Ratings) != 3 {
		t.Errorf("fixture produced %d finding(s) with %v ratings, want 1 finding "+
			"carrying 3 — the comparison above is vacuous unless the three "+
			"records became one multi-source finding; document:\n%s",
			len(doc.Findings), func() []int {
				var n []int
				for _, f := range doc.Findings {
					n = append(n, len(f.Ratings))
				}
				return n
			}(), forward)
	}
}

// An identifier this scan's own JSON prints must resolve through --explain.
//
// D25 merges records that were separate findings before it, and the losing
// record's identifiers then stop being reachable through Finding.Advisory. The
// regression that produced: `--output json` emits PYSEC-2022-191 in
// ratings[].advisoryId, and `--explain PYSEC-2022-191` answered exit 2 — "the
// result cannot be trusted" (D11) — for a scan that ran perfectly.
//
// Every identifier is exercised, not just the losing one, because the fix
// moves the lookup set off the advisory and onto the finding; getting the
// winner or the shared CVE wrong in the move would be just as bad.
func TestRun_ExplainResolvesEveryIdentifierTheScanPrints(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-w24h-v9qh-8gxj", pkg: "shared", fixed: "2.0.0",
			vectors: []string{vecCritical}, aliases: []string{"CVE-2022-28347"}},
		// Deliberately does NOT alias the GHSA record, only the shared CVE.
		// The live records cross-alias, which hides this entirely.
		{id: "PYSEC-2022-191", pkg: "shared", fixed: "2.0.0",
			aliases: []string{"CVE-2022-28347"}},
	})
	sbom := buildMatrixSBOM(t, []matrixPkg{{name: "shared", purlType: "golang"}})

	for _, id := range []string{
		"GHSA-w24h-v9qh-8gxj", // the winner, displayed
		"CVE-2022-28347",      // the alias both records share
		"PYSEC-2022-191",      // the losing record — the regression
	} {
		t.Run(id, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, sbom, Options{Explain: id}, &out, &errOut)
			if code != 0 {
				t.Fatalf("--explain %s = %d, want 0; stderr: %s", id, code, errOut.String())
			}
			// The explanation must be of the merged finding, not of some other
			// row that happened to match. Asserted on the rendered pair rather
			// than on either identifier alone, since PYSEC-2022-191 also
			// appears in the breakdown's own rating line.
			if !strings.Contains(out.String(), "advisory: GHSA-w24h-v9qh-8gxj") {
				t.Errorf("--explain %s did not explain the merged finding:\n%s", id, out.String())
			}
		})
	}
}

// putEnrichment writes one KISA record into the database dbPath already names,
// the way putRating above writes a rating and for the same reason: a scan never
// fetches anything (D14), so a test proving Korean prose reaches a report has
// to put it in the SAME database Run will open. store.Create rather than
// store.Open, again as putRating explains -- the Writer half is what carries
// PutEnrichment, and Create's CreateBucketIfNotExists calls are no-ops against
// buckets that already exist.
func putEnrichment(t *testing.T, dbPath string, e advisory.Enrichment) {
	t.Helper()
	w, err := store.Create(dbPath)
	if err != nil {
		t.Fatalf("open %s to add enrichment: %v", dbPath, err)
	}
	if err := w.PutEnrichment(e); err != nil {
		t.Fatalf("PutEnrichment: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// What one KISA notice carries (D3). Non-nesting tokens, and none of them
// contains a CVE ID or the notice id, so an assertion about the summary cannot
// be satisfied by the title, by the link, or by the identifier the join ran on.
const (
	kisaTitle   = "제목-오픈소스-라이브러리-보안-업데이트-권고"
	kisaSummary = "개요-원격에서-임의의-코드를-실행할-수-있는-결함이-발견되었습니다"
	kisaURL     = "https://knvd.krcert.or.kr/info/vuln/notice/detail?id=99887"
)

func kisaNotice(cve string) advisory.Enrichment {
	return advisory.Enrichment{
		CVE: cve, Source: "KISA", Title: kisaTitle, Summary: kisaSummary, URL: kisaURL,
	}
}

// TestRun_KISAEnrichmentReachesEveryRenderer is D3 end to end, through a real
// bbolt database: `db build` writes a notice, a scan joins it to a finding on
// the CVE, and each of the three renderers shows what it is supposed to.
//
// It goes through the store rather than a fake on purpose. advisory.Enrichment
// is JSON-encoded into the bucket, so the path from PutEnrichment to a rendered
// line is what proves the payload survives storage -- a `json:"-"` on Summary
// would empty every stored Korean overview, and until this test existed nothing
// anywhere read that field back.
func TestRun_KISAEnrichmentReachesEveryRenderer(t *testing.T) {
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-enriched", pkg: "enriched", fixed: "2.0.0",
			vectors: []string{vecCritical}, aliases: []string{"CVE-2025-9"}},
		// A second finding nothing enriched, so every "the text is present"
		// assertion below has a row it must NOT be coming from.
		{id: "GHSA-plain", pkg: "plain", fixed: "2.0.0", vectors: []string{vecMedium}},
	})
	putEnrichment(t, db, kisaNotice("CVE-2025-9"))
	sbom := buildMatrixSBOM(t, []matrixPkg{
		{name: "enriched", purlType: "golang"},
		{name: "plain", purlType: "golang"},
	})

	t.Run("--explain prints the title, summary and link in full", func(t *testing.T) {
		var out, errOut bytes.Buffer
		// Looked up by the CVE the notice was filed under -- the identifier a
		// reader would have copied out of the table's ALIASES column.
		if code := Run(context.Background(), db, sbom,
			Options{Explain: "CVE-2025-9"}, &out, &errOut); code != 0 {
			t.Fatalf("Run = %d, want 0; stderr: %s", code, errOut.String())
		}
		for _, want := range []string{
			"enrichment: KISA",
			"  title:    " + kisaTitle,
			"  summary:  " + kisaSummary,
			"  link:     " + kisaURL,
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("--explain output is missing %q:\n%s", want, out.String())
			}
		}
		// Results to stdout, diagnostics to stderr; the prose is a result.
		if strings.Contains(errOut.String(), kisaSummary) {
			t.Errorf("the Korean text reached stderr:\n%s", errOut.String())
		}
	})

	// The workflow the footnote advertises, through the real CLI seam: read the
	// table, copy the marked ADVISORY cell, run --explain with it. Before the
	// marker was trimmed this answered `no finding matches advisory or alias
	// "GHSA-enriched +"` and exit 2 -- the report instructing a reader to run a
	// command that fails on the report's own output.
	t.Run("--explain accepts the marked ADVISORY cell verbatim", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), db, sbom,
			Options{Explain: "GHSA-enriched +"}, &out, &errOut)
		if code != 0 {
			t.Fatalf("Run(--explain %q) = %d, want 0; stderr: %s",
				"GHSA-enriched +", code, errOut.String())
		}
		if !strings.Contains(out.String(), "advisory: GHSA-enriched") {
			t.Errorf("the copied cell did not explain the finding it was copied from:\n%s",
				out.String())
		}
	})

	t.Run("the table marks the row and names the source", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), db, sbom, Options{}, &out, &errOut); code != 0 {
			t.Fatalf("Run = %d, want 0; stderr: %s", code, errOut.String())
		}
		if !strings.Contains(out.String(), "+ also described by KISA") {
			t.Errorf("the table does not name KISA in a footnote:\n%s", out.String())
		}
		if !strings.Contains(out.String(), "GHSA-enriched +") {
			t.Errorf("the enriched row is not marked:\n%s", out.String())
		}
		// The marker is per row: the finding nothing enriched must not get one.
		if strings.Contains(out.String(), "GHSA-plain +") {
			t.Errorf("the un-enriched row is marked too:\n%s", out.String())
		}
		if strings.Contains(out.String(), kisaTitle) || strings.Contains(out.String(), kisaSummary) {
			t.Errorf("the table carries the Korean text itself:\n%s", out.String())
		}
	})

	t.Run("--output json carries the whole record", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), db, sbom,
			Options{Output: "json"}, &out, &errOut); code != 0 {
			t.Fatalf("Run = %d, want 0; stderr: %s", code, errOut.String())
		}
		var doc report.Document
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
		}
		var enriched []report.EnrichmentRecord
		for _, f := range doc.Findings {
			if f.Advisory.ID == "GHSA-enriched" {
				enriched = f.Enrichment
				continue
			}
			if len(f.Enrichment) != 0 {
				t.Errorf("finding %s gained enrichment nothing filed for it: %+v",
					f.Advisory.ID, f.Enrichment)
			}
		}
		want := report.EnrichmentRecord{
			Source: "KISA", Title: kisaTitle, Summary: kisaSummary, URL: kisaURL,
		}
		if len(enriched) != 1 || enriched[0] != want {
			t.Errorf("enrichment = %+v, want [%+v]", enriched, want)
		}
	})
}

// TestRun_EnrichmentChangesNoVerdict is the property this whole feature is
// constrained by (D3), held where it actually matters: at the exit code, across
// every gate, through two real databases whose ONLY difference is a KISA record.
//
// The matcher-level half of this lives in
// internal/matcher.TestMatch_EnrichmentChangesNoVerdict, which compares the
// findings themselves. This one compares what CI reads -- the exit code and the
// summary counts -- because those are computed by report and scancmd, which that
// test cannot reach without an import cycle.
func TestRun_EnrichmentChangesNoVerdict(t *testing.T) {
	// Every gate has something to fire on: a critical finding, an unrated one,
	// an advisory that cannot be evaluated, and a package the cataloger drops.
	// Enrichment lands on the UNRATED finding as well as the rated one, because
	// the unrated finding is where an enrichment that could set a band would
	// show up first -- nothing else has claimed one there.
	advisories := []matrixAdv{
		{id: "GHSA-critical", pkg: "critical", fixed: "2.0.0",
			vectors: []string{vecCritical}, aliases: []string{"CVE-2025-9"}},
		{id: "GHSA-unrated", pkg: "unrated", fixed: "2.0.0", aliases: []string{"CVE-2025-8"}},
		{id: "GHSA-badcompare", pkg: "badcompare"}, // malformed bound -> incomplete check
	}
	sbom := buildMatrixSBOM(t, []matrixPkg{
		{name: "critical", purlType: "golang"},
		{name: "unrated", purlType: "golang"},
		{name: "badcompare", purlType: "golang"},
		{name: "somecrate", purlType: "cargo"}, // dropped by the cataloger
	})

	withDB := buildMatrixDB(t, advisories)
	putEnrichment(t, withDB, kisaNotice("CVE-2025-9"))
	putEnrichment(t, withDB, kisaNotice("CVE-2025-8"))
	withoutDB := buildMatrixDB(t, advisories)

	// Non-vacuity first. Two databases that both enrich nothing agree
	// trivially, and every comparison below would pass with the feature
	// deleted. Asserted on the payload, so it fails too if records attached but
	// arrived empty.
	var probe, probeErr bytes.Buffer
	if code := Run(context.Background(), withDB, sbom, Options{Output: "json"}, &probe, &probeErr); code != 0 {
		t.Fatalf("probe run = %d, want 0; stderr: %s", code, probeErr.String())
	}
	var probeDoc report.Document
	if err := json.Unmarshal(probe.Bytes(), &probeDoc); err != nil {
		t.Fatalf("probe output is not valid JSON: %v", err)
	}
	attached := 0
	for _, f := range probeDoc.Findings {
		for _, e := range f.Enrichment {
			if e.Source == "KISA" && e.Summary == kisaSummary {
				attached++
			}
		}
	}
	if attached != 2 {
		t.Fatalf("the enriched database attached %d KISA records, want 2 -- with "+
			"nothing attached this test proves nothing:\n%s", attached, probe.String())
	}

	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"no flags", Options{}},
		{"--fail-on critical", Options{FailOn: &bandCritical}},
		{"--fail-on high", Options{FailOn: &bandHigh}},
		// The gate an invented band would move first: an enrichment that
		// contributed a severity would stop the unrated finding being unrated.
		{"--fail-on-unknown", Options{FailOnUnknown: true}},
		{"--fail-on none (D17: unknown trips nothing)", Options{FailOn: &bandNone}},
		{"--fail-on-incomplete", Options{FailOnIncomplete: true}},
		{"every gate at once", Options{
			FailOn: &bandLow, FailOnUnknown: true, FailOnIncomplete: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// --output json on both sides, so the summary counts can be
			// compared as well as the exit code. A renderer is chosen, never a
			// different notion of what the scan found (D11), so this is the
			// same verdict the table would reach.
			opts := tc.opts
			opts.Output = "json"

			var withOut, withErr bytes.Buffer
			withCode := Run(context.Background(), withDB, sbom, opts, &withOut, &withErr)
			var withoutOut, withoutErr bytes.Buffer
			withoutCode := Run(context.Background(), withoutDB, sbom, opts, &withoutOut, &withoutErr)

			if withCode != withoutCode {
				t.Errorf("exit code %d with enrichment, %d without -- a reader's "+
					"convenience moved a gate\nwith stderr: %s\nwithout stderr: %s",
					withCode, withoutCode, withErr.String(), withoutErr.String())
			}
			var withDoc, withoutDoc report.Document
			if err := json.Unmarshal(withOut.Bytes(), &withDoc); err != nil {
				t.Fatalf("enriched output is not valid JSON: %v", err)
			}
			if err := json.Unmarshal(withoutOut.Bytes(), &withoutDoc); err != nil {
				t.Fatalf("un-enriched output is not valid JSON: %v", err)
			}
			if withDoc.Summary != withoutDoc.Summary {
				t.Errorf("summary %+v with enrichment, %+v without",
					withDoc.Summary, withoutDoc.Summary)
			}
			// Per finding as well, so a band that moved somewhere the summary
			// happens to net out is still caught.
			if len(withDoc.Findings) != len(withoutDoc.Findings) {
				t.Fatalf("finding count %d with enrichment, %d without",
					len(withDoc.Findings), len(withoutDoc.Findings))
			}
			for i := range withDoc.Findings {
				a, b := withDoc.Findings[i], withoutDoc.Findings[i]
				if a.Severity != b.Severity || a.Score != b.Score {
					t.Errorf("finding %s: %s/%.1f with enrichment, %s/%.1f without",
						a.Advisory.ID, a.Severity, a.Score, b.Severity, b.Score)
				}
			}
		})
	}
}

// D36. The whole point of the narrowed gate is that it does NOT fire on
// upstream data the caller cannot fix. Both directions are asserted, because a
// gate that fires on everything and a gate that fires on nothing each satisfy
// exactly one of them.
func TestVerdict_FailOnIncompleteTargetIgnoresAdvisoryDefects(t *testing.T) {
	// One advisory-caused skip, nothing wrong with the scanned artifact. This
	// is the shape of 85 range bounds in the live database.
	advisoryOnly := report.Summary{NotEvaluated: 0, IncompleteChecks: 1, TargetIncomplete: 0}
	// The same scan, plus one package whose own version will not parse.
	withTarget := report.Summary{NotEvaluated: 0, IncompleteChecks: 2, TargetIncomplete: 1}

	for _, tc := range []struct {
		name string
		opts Options
		sum  report.Summary
		want int
	}{
		{"narrow gate stays quiet on an advisory defect",
			Options{FailOnIncompleteTarget: true}, advisoryOnly, 0},
		{"narrow gate fires on the caller's own data",
			Options{FailOnIncompleteTarget: true}, withTarget, 2},
		// The broad gate is contract and must be untouched by D36 (D11): a
		// pipeline relying on it would silently stop failing.
		{"broad gate still fires on an advisory defect",
			Options{FailOnIncomplete: true}, advisoryOnly, 2},
		{"broad gate still fires on the caller's own data",
			Options{FailOnIncomplete: true}, withTarget, 2},
		// Neither flag set is still exit 0, however incomplete the scan was.
		{"no gate, no failure", Options{}, withTarget, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := verdict(tc.opts, tc.sum, nil, report.EOLStatus{}); got != tc.want {
				t.Errorf("verdict = %d, want %d (summary %+v)", got, tc.want, tc.sum)
			}
		})
	}
}

// D11's 2 > 1 > 0 precedence applies to FailOnIncompleteTarget exactly as it
// does to the broad FailOnIncomplete gate above (both rows of that table set
// FailOnIncomplete alongside FailOn/FailOnUnknown) — but no row anywhere
// arms FailOnIncompleteTarget alongside an exit-1 gate that is ALSO true, so
// an ordering defect between the narrow gate and FailOn/FailOnUnknown is
// invisible to the suite. Two independent shapes of that defect were found
// by mutation testing, and each row below is aimed at one:
//
//   - narrowing the guard itself to `&& opts.FailOn == nil` returns 1
//     instead of 2 whenever --fail-on is also armed and its own finding
//     trips it;
//   - swapping the guard below FailOnUnknown's returns 1 instead of 2
//     whenever --fail-on-unknown is also armed and UnknownSeverity > 0.
//
// Both defects make verdict return 1; only 2 is correct under D11, so this
// is not "presence of some exit code" but the exact code.
func TestVerdict_FailOnIncompleteTargetOutranksExitOneGates(t *testing.T) {
	bandHigh := severity.High
	sum := report.Summary{TargetIncomplete: 1, UnknownSeverity: 1}
	// A finding that would itself trip --fail-on high on its own, so the
	// narrowed-guard mutation (which only stops gating when FailOn is set)
	// has something to fall through to.
	findings := []matcher.Finding{{Severity: severity.Critical}}

	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"alongside --fail-on, armed with a finding that would itself trip it",
			Options{FailOnIncompleteTarget: true, FailOn: &bandHigh}},
		{"alongside --fail-on-unknown, with an unrated finding present",
			Options{FailOnIncompleteTarget: true, FailOnUnknown: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := verdict(tc.opts, sum, findings, report.EOLStatus{}); got != 2 {
				t.Errorf("verdict = %d, want 2 -- the caller's own incomplete "+
					"data (D36) must outrank a finding-based exit-1 gate (D11), "+
					"regardless of which other gate is also armed", got)
			}
		})
	}
}

// A whole-package skip caused by the target counts too. TargetIncomplete is
// deliberately not a subtotal of IncompleteChecks — it cuts across both kinds —
// and a gate reading IncompleteChecks instead would miss this case entirely.
func TestVerdict_FailOnIncompleteTargetCountsWholePackageSkips(t *testing.T) {
	sum := report.Summary{NotEvaluated: 1, IncompleteChecks: 0, TargetIncomplete: 1}
	if got := verdict(Options{FailOnIncompleteTarget: true}, sum, nil, report.EOLStatus{}); got != 2 {
		t.Errorf("verdict = %d, want 2: a whole-package skip the caller caused must gate", got)
	}
}
