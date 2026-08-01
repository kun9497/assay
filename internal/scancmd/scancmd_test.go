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
	})

	t.Run("registry reference path", func(t *testing.T) {
		// A string with no scheme prefix and no file on disk falls through to
		// the registry loader (source.ClassifyTarget). This one is
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

// matrixAdv is one advisory for the exit-code matrix below, always affecting
// Go package "example.com/<pkg>" at versions [0, fixed). Leaving fixed empty
// asks for a malformed bound ("not-a-version") instead: version.SemVer
// rejects it, so the matcher records an advisory-scoped skip
// (report.Summary.IncompleteChecks) for the package rather than a finding —
// a package that WAS evaluated, just not completely.
type matrixAdv struct {
	id      string
	pkg     string
	fixed   string
	vectors []string // CVSS vectors; nil -> the finding's severity is Unknown
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
		fixed := adv.fixed
		if fixed == "" {
			fixed = "not-a-version"
		}
		var sev []advisory.Severity
		for _, v := range adv.vectors {
			sev = append(sev, advisory.Severity{Type: "CVSS_V3", Score: v})
		}
		// Every fixture pkg so far has been a bare synthetic name
		// ("critical", "medium", ...), which is why prefixing it under
		// "example.com/" is safe. A pkg that already contains "/" is a real
		// module path handed in on purpose - go.etcd.io/bbolt, a genuine
		// dependency this test binary links, so a go-binary target can be
		// matched against a real finding rather than a fixture-shaped one -
		// and prefixing that would produce a name nothing ever imports.
		name := "example.com/" + adv.pkg
		if strings.Contains(adv.pkg, "/") {
			name = adv.pkg
		}
		a := advisory.Advisory{
			ID:   adv.id,
			Kind: advisory.KindVulnerability,
			Affected: []advisory.Affected{{
				Ecosystem: "Go",
				Name:      name,
				Ranges: []advisory.Range{{
					Type:   advisory.RangeSemver,
					Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}},
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
		if doc.SchemaVersion != 1 {
			t.Errorf("SchemaVersion = %d, want 1", doc.SchemaVersion)
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

// Each of the four kinds reaches its own cataloger. A kind routed to the
// wrong parser is the failure D22 exists to prevent, and the error it then
// produces names the wrong problem - a binary handed to the CycloneDX parser
// reports a malformed document.
//
// The assertion is on what each scan FOUND, not on the exit code: every one
// of these exits 0, so an exit-code assertion would pass with all four routed
// to the same parser.
func TestRun_RoutesEachTargetKind(t *testing.T) {
	db := buildMatrixDB(t, nil)
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
		`"purl":"pkg:golang/example.com/sbomonly\n1.0.0"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name   string
		target string
		// A package name that appears ONLY when this kind's cataloger ran.
		// Distinct strings with no substring relationship between them, so a
		// row cannot pass from another row's output.
		wantPkg string
	}{
		{"go binary", "file:" + self, "stdlib"},
		{"directory", "dir:" + dir, "github.com/routed/dep"},
		{"sbom", "sbom:" + sbom, "example.com/sbomonly"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), db, tt.target,
				Options{Output: "json"}, &out, &errOut); code != 0 {
				t.Fatalf("Run = %d, want 0; stderr:\n%s", code, errOut.String())
			}
			var doc struct {
				Findings []struct{} `json:"findings"`
				Summary  struct {
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
			// The scan reports how it classified the target, so assert on
			// that too: it is the thing D22 promises is visible.
			if !strings.Contains(errOut.String(), "as a "+tt.name) &&
				!strings.Contains(errOut.String(), "as a go-binary") {
				t.Errorf("stderr does not name the kind:\n%s", errOut.String())
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
// verdict path would break them silently. The binary scanned genuinely links
// go.etcd.io/bbolt (buildBBoltBinary), so the finding is real rather than
// fixture-shaped.
func TestRun_GatesApplyToBinaryAndDirectoryTargets(t *testing.T) {
	bin := buildBBoltBinary(t)
	// An advisory against a module this binary genuinely links.
	db := buildMatrixDB(t, []matrixAdv{
		{id: "GHSA-binary-hit", pkg: "go.etcd.io/bbolt", fixed: "99.0.0", vectors: []string{vecCritical}},
	})

	none := severity.None
	for _, tt := range []struct {
		name string
		opts Options
		want int
	}{
		{"no flags", Options{}, 0},
		{"--fail-on none trips on a critical finding", Options{FailOn: &none}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if got := Run(context.Background(), db, "file:"+bin, tt.opts, &out, &errOut); got != tt.want {
				t.Errorf("Run = %d, want %d; stdout:\n%s\nstderr:\n%s",
					got, tt.want, out.String(), errOut.String())
			}
		})
	}
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
