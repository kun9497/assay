package scancmd

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/kun9497/assay/internal/source"
	"github.com/kun9497/assay/internal/store"
)

func TestRun_MissingDatabase(t *testing.T) {
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o600)

	var out, errOut bytes.Buffer
	code := Run(context.Background(), filepath.Join(t.TempDir(), "absent.db"), sbom, &out, &errOut)
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

// A target with no scheme prefix and no file on disk is, by ClassifyTarget's
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
		"docker-archive:"+filepath.Join(t.TempDir(), "absent.cdx.json"), &out, &errOut)
	if code != 2 {
		t.Errorf("Run with a missing SBOM = %d, want 2", code)
	}
}

// --- test fixtures shared by the image-path tests below ---

const osReleaseAlpine319 = `ID=alpine
VERSION_ID=3.19.9
PRETTY_NAME="Alpine Linux v3.19"
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
func testDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.SetMeta(store.Meta{}); err != nil {
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
		if code := Run(context.Background(), dbPath, sbom, &out, &errOut); code != 0 {
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
		if code := Run(context.Background(), dbPath, "docker-archive:"+tarPath, &out, &errOut); code != 0 {
			t.Errorf("Run(docker-archive) = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		if !strings.Contains(out.String(), "1 package") {
			t.Errorf("stdout = %q, want the one apk package to have been evaluated", out.String())
		}
	})

	t.Run("registry reference path", func(t *testing.T) {
		// A string with no scheme prefix and no file on disk falls through to
		// the registry loader (source.ClassifyTarget). This one is
		// syntactically invalid, so it fails while being parsed AS a
		// reference rather than while being opened as a file or a socket —
		// proof of which loader it reached, without ever touching the
		// network.
		var out, errOut bytes.Buffer
		code := Run(context.Background(), dbPath, "NOT a valid ref!!", &out, &errOut)
		if code != 2 {
			t.Errorf("Run(invalid ref) = %d, want 2", code)
		}
		if !strings.Contains(errOut.String(), "parse reference") {
			t.Errorf("stderr = %q, want it to name reference parsing, proving "+
				"this reached the registry loader and not the SBOM path", errOut.String())
		}
	})
}

// A target we cannot read is exit 2 with a message naming the target, never a
// clean empty scan (D11).
func TestRun_UnreadableTargetExits2(t *testing.T) {
	dbPath := testDB(t)
	target := "docker-archive:" + filepath.Join(t.TempDir(), "absent.tar")

	var out, errOut bytes.Buffer
	code := Run(context.Background(), dbPath, target, &out, &errOut)
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
	code := Run(context.Background(), dbPath, "docker-archive:"+tarPath, &out, &errOut)
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
	code := Run(context.Background(), dbPath, "docker-archive:"+tarPath, &out, &errOut)
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
