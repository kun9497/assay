package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/source"
)

// D119's caller tests. Every one goes through Run against a real target — an
// in-memory registry, an oci-dir: layout, a docker-archive: tarball — because
// the selector is only worth anything if the path that pulls actually uses
// it: a perfect choosePlatform with remote.WithPlatform still on the pull
// would pass every test in internal/source.
//
// Every image in an index is DISTINGUISHABLE by its package count — the image
// for platform N carries N apk packages — and each test asserts the count the
// scan evaluated, not only that it succeeded. Success alone holds whichever
// child was scanned.

// platImage is an Alpine 3.19 image with n apk packages whose config says
// plat. An empty plat leaves the config's OS and architecture unset.
func platImage(t *testing.T, plat v1.Platform, n int) v1.Image {
	t.Helper()
	var db strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&db, "P:pkg%d\nV:1.0.%d-r0\nA:x86_64\no:pkg%d\n\n", i, i, i)
	}
	raw := buildTar(t, map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: db.String()})
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = plat.OS, plat.Architecture, plat.Variant
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	return img
}

func plat(s string) v1.Platform {
	parts := strings.Split(s, "/")
	p := v1.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	return p
}

// entry is one child of a test index: an image of `pkgs` packages whose
// descriptor says `desc` (the config says the same unless cfg is set).
type entry struct {
	desc string
	pkgs int
}

// buildIndex makes an index of entries, returning it and each child's
// manifest digest by package count.
func buildIndex(t *testing.T, entries ...entry) (v1.ImageIndex, map[int]string) {
	t.Helper()
	digests := map[int]string{}
	var adds []mutate.IndexAddendum
	for _, e := range entries {
		p := plat(e.desc)
		img := platImage(t, p, e.pkgs)
		d, err := img.Digest()
		if err != nil {
			t.Fatal(err)
		}
		digests[e.pkgs] = d.String()
		pp := p
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &pp}})
	}
	return mutate.AppendManifests(empty.Index, adds...), digests
}

func digestOf(t *testing.T, d interface{ Digest() (v1.Hash, error) }) string {
	t.Helper()
	h, err := d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return h.String()
}

// openRegistry is an in-memory registry that admits everything.
func openRegistry(t *testing.T) *authRegistry {
	t.Helper()
	return newAuthRegistryFunc(t, func(*http.Request) int { return 0 })
}

func pushIndex(t *testing.T, host, repo string, idx v1.ImageIndex) string {
	t.Helper()
	ref := host + "/" + repo
	if err := remote.WriteIndex(mustRef(t, ref), idx); err != nil {
		t.Fatalf("push index: %v", err)
	}
	return ref
}

func pushImage(t *testing.T, host, repo string, img v1.Image) string {
	t.Helper()
	ref := host + "/" + repo
	if err := remote.Write(mustRef(t, ref), img); err != nil {
		t.Fatalf("push image: %v", err)
	}
	return ref
}

// setHost points source.HostPlatform at p for one test.
func setHost(t *testing.T, p string) {
	t.Helper()
	orig := source.HostPlatform
	source.HostPlatform = func() v1.Platform { return plat(p) }
	t.Cleanup(func() { source.HostPlatform = orig })
}

// scanJSON runs a JSON scan with --platform p ("" for none) and decodes the
// document when the scan produced one.
func scanJSON(t *testing.T, target, p string) (doc report.Document, stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), testDB(t), target, Options{Output: "json", Platform: p}, &out, &errOut)
	if code != 2 {
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("stdout is not a JSON document: %v\n%s\nstderr: %s", err, out.String(), errOut.String())
		}
	}
	return doc, out.String(), errOut.String(), code
}

// wantImage asserts the scan exited 0, read the child with `pkgs` packages,
// and recorded `want` in the JSON image object.
func wantImage(t *testing.T, doc report.Document, stderr string, code, pkgs int, want report.ImageRecord) {
	t.Helper()
	if code != 0 {
		t.Fatalf("Run = %d, want 0\nstderr: %s", code, stderr)
	}
	if doc.Summary.Components != pkgs {
		t.Errorf("scanned an image of %d package(s), want the one of %d: the wrong child was chosen\nstderr: %s",
			doc.Summary.Components, pkgs, stderr)
	}
	if doc.Image == nil {
		t.Fatalf("JSON has no image object")
	}
	if *doc.Image != want {
		t.Errorf("image = %+v\n want %+v", *doc.Image, want)
	}
}

// recordLine is D119's stderr line, as a whole line, so it cannot pass on a
// substring of some other line that happens to name the same digest.
func recordLine(ref, platform, manifest, index, compatibleWith string) string {
	s := "image " + ref + ": " + platform + ", manifest " + manifest
	if index != "" {
		s += ", from index " + index
	}
	if compatibleWith != "" {
		s += " (compatible with " + compatibleWith + ")"
	}
	return "\n" + s + "\n"
}

// hasLine reports whether stderr carries line as a whole line.
func hasLine(stderr, line string) bool { return strings.Contains("\n"+stderr, line) }

// The headline defect: go-containerregistry's WithPlatform(linux/arm) takes
// the FIRST arm entry — v6 here, as on alpine, node and registry — while
// docker and grype take v7. Bare arm is arm/v7 (containerd).
func TestRun_PlatformBareArmPicksV7NotTheFirstArmEntry(t *testing.T) {
	isolateCredentials(t)
	ar := openRegistry(t)
	idx, d := buildIndex(t,
		entry{"linux/amd64", 1}, entry{"linux/arm/v6", 2}, entry{"linux/arm/v7", 3}, entry{"linux/arm64/v8", 4})
	ref := pushIndex(t, ar.host, "multi:arm", idx)

	doc, out, errOut, code := scanJSON(t, ref, "linux/arm")
	wantImage(t, doc, errOut, code, 3, report.ImageRecord{
		Platform: "linux/arm/v7", RequestedPlatform: "linux/arm/v7", Match: report.ImageMatchExact,
		ManifestDigest: d[3], IndexDigest: digestOf(t, idx),
	})
	if want := recordLine(ref, "linux/arm/v7", d[3], digestOf(t, idx), ""); !hasLine(errOut, want) {
		t.Errorf("stderr lacks the record line %q:\n%s", want, errOut)
	}
	// stdout is the document and nothing else (stream discipline).
	if strings.Contains(out, "image "+ref+":") || strings.Contains(out, "warning:") {
		t.Errorf("stdout carries a stderr line:\n%s", out)
	}
}

// What `docker` prints and what people copy, against the 10 of 44 surveyed
// indexes whose arm64 entry carries no variant: arm64/v8 IS arm64.
func TestRun_PlatformArm64V8MatchesAVariantlessArm64(t *testing.T) {
	isolateCredentials(t)
	ar := openRegistry(t)
	idx, d := buildIndex(t, entry{"linux/amd64", 1}, entry{"linux/arm64", 2})
	ref := pushIndex(t, ar.host, "multi:arm64", idx)

	doc, _, errOut, code := scanJSON(t, ref, "linux/arm64/v8")
	wantImage(t, doc, errOut, code, 2, report.ImageRecord{
		Platform: "linux/arm64", RequestedPlatform: "linux/arm64", Match: report.ImageMatchExact,
		ManifestDigest: d[2], IndexDigest: digestOf(t, idx),
	})
}

// The one fallback: an arm/v7 host runs a v6 image, and docker chose it
// (measured, D119). Recorded as compatible, never as exact.
func TestRun_PlatformArmV7FallsBackToV6AsCompatible(t *testing.T) {
	isolateCredentials(t)
	ar := openRegistry(t)
	idx, d := buildIndex(t, entry{"linux/amd64", 1}, entry{"linux/arm/v6", 2})
	ref := pushIndex(t, ar.host, "multi:v6", idx)

	doc, _, errOut, code := scanJSON(t, ref, "linux/arm/v7")
	wantImage(t, doc, errOut, code, 2, report.ImageRecord{
		Platform: "linux/arm/v6", RequestedPlatform: "linux/arm/v7", Match: report.ImageMatchCompatible,
		ManifestDigest: d[2], IndexDigest: digestOf(t, idx),
	})
	if want := recordLine(ref, "linux/arm/v6", d[2], digestOf(t, idx), "linux/arm/v7"); !hasLine(errOut, want) {
		t.Errorf("stderr lacks the compatible record line %q:\n%s", want, errOut)
	}
}

// remote.Image looks only at the top level, so a nested index failed from a
// registry while oci-dir: already walked it. And exact-first is over the
// WHOLE tree: an arm/v6 met first at the top must not beat an arm/v7 nested
// below it.
func TestRun_PlatformNestedIndexFromARegistry(t *testing.T) {
	isolateCredentials(t)
	ar := openRegistry(t)
	inner, d := buildIndex(t, entry{"linux/amd64", 3}, entry{"linux/arm/v7", 2})
	v6 := platImage(t, plat("linux/arm/v6"), 1)
	v6p := plat("linux/arm/v6")
	outer := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: v6, Descriptor: v1.Descriptor{Platform: &v6p}},
		mutate.IndexAddendum{Add: inner},
	)
	ref := pushIndex(t, ar.host, "nested:latest", outer)

	doc, _, errOut, code := scanJSON(t, ref, "linux/arm/v7")
	// The index recorded is the one that listed the manifest: the inner one.
	wantImage(t, doc, errOut, code, 2, report.ImageRecord{
		Platform: "linux/arm/v7", RequestedPlatform: "linux/arm/v7", Match: report.ImageMatchExact,
		ManifestDigest: d[2], IndexDigest: digestOf(t, inner),
	})

	// The nested amd64 is reachable too, by the host default.
	setHost(t, "linux/amd64")
	doc, _, errOut, code = scanJSON(t, ref, "")
	wantImage(t, doc, errOut, code, 3, report.ImageRecord{
		Platform: "linux/amd64", RequestedPlatform: "linux/amd64", Match: report.ImageMatchExact,
		ManifestDigest: d[3], IndexDigest: digestOf(t, inner),
	})
}

// A miss is exit 2 naming what the index offers, normalised and sorted, with
// attestations left out.
func TestRun_PlatformMissIsExit2NamingTheOffers(t *testing.T) {
	isolateCredentials(t)
	ar := openRegistry(t)
	idx, _ := buildIndex(t, entry{"linux/arm64/v8", 1}, entry{"linux/amd64", 2}, entry{"unknown/unknown", 3})
	ref := pushIndex(t, ar.host, "multi:miss", idx)

	_, out, errOut, code := scanJSON(t, ref, "linux/s390x")
	if code != 2 {
		t.Fatalf("Run = %d, want 2\nstderr: %s", code, errOut)
	}
	if want := "error: " + ref + " has no linux/s390x image; it offers linux/amd64, linux/arm64\n"; !strings.Contains(errOut, want) {
		t.Errorf("stderr lacks %q:\n%s", want, errOut)
	}
	if out != "" {
		t.Errorf("stdout = %q, want nothing on exit 2", out)
	}

	// Without the flag the same miss says how to choose.
	setHost(t, "linux/riscv64")
	_, _, errOut, code = scanJSON(t, ref, "")
	if code != 2 || !strings.Contains(errOut, "has no linux/riscv64 image; it offers linux/amd64, linux/arm64; pass --platform") {
		t.Errorf("Run = %d, want 2 with a --platform hint\nstderr: %s", code, errOut)
	}
}

// A single image is compared by its config. Asked for explicitly, a mismatch
// is exit 2 naming both; on the host default it is the only image there, so
// it is scanned, warned about and recorded as mismatch.
func TestRun_PlatformSingleImageFromARegistry(t *testing.T) {
	isolateCredentials(t)
	ar := openRegistry(t)
	img := platImage(t, plat("linux/arm64"), 2)
	ref := pushImage(t, ar.host, "single:arm64", img)
	dg := digestOf(t, img)

	t.Run("explicit mismatch is exit 2", func(t *testing.T) {
		_, out, errOut, code := scanJSON(t, ref, "linux/amd64")
		if code != 2 {
			t.Fatalf("Run = %d, want 2\nstderr: %s", code, errOut)
		}
		if want := "error: " + ref + " is a single linux/arm64 image; --platform asked for linux/amd64\n"; !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
		if out != "" {
			t.Errorf("stdout = %q, want nothing", out)
		}
	})
	t.Run("host default mismatch is scanned with a warning", func(t *testing.T) {
		setHost(t, "linux/amd64")
		doc, out, errOut, code := scanJSON(t, ref, "")
		wantImage(t, doc, errOut, code, 2, report.ImageRecord{
			Platform: "linux/arm64", RequestedPlatform: "linux/amd64", Match: report.ImageMatchMismatch,
			ManifestDigest: dg,
		})
		want := "warning: image " + ref + " is linux/arm64 only, not this host's linux/amd64; scanning it, " +
			"as it is the only image there - pass --platform linux/arm64 to say that is intended, " +
			"or --platform linux/amd64 to refuse it\n"
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks the mismatch warning %q:\n%s", want, errOut)
		}
		if want := recordLine(ref, "linux/arm64", dg, "", ""); !hasLine(errOut, want) {
			t.Errorf("stderr lacks the record line %q:\n%s", want, errOut)
		}
		if strings.Contains(out, "warning") {
			t.Errorf("the warning reached stdout:\n%s", out)
		}
	})
	t.Run("explicit match is exact with no index", func(t *testing.T) {
		doc, _, errOut, code := scanJSON(t, ref, "linux/aarch64")
		wantImage(t, doc, errOut, code, 2, report.ImageRecord{
			Platform: "linux/arm64", RequestedPlatform: "linux/arm64", Match: report.ImageMatchExact,
			ManifestDigest: dg,
		})
		if strings.Contains(errOut, "warning") {
			t.Errorf("an exact single image warned:\n%s", errOut)
		}
	})
}

// The layout path reads the same seam and the same selector. The host is set
// to a platform no CI machine is, so a comparison against runtime.GOARCH
// would miss it; the explicit pick is a third platform.
func TestRun_PlatformOCILayoutHonoursFlagAndSeam(t *testing.T) {
	isolateCredentials(t)
	dir := filepath.Join(t.TempDir(), "layout")
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	digests := map[int]string{}
	for i, p := range []string{"linux/amd64", "linux/arm64", "linux/riscv64"} {
		img := platImage(t, plat(p), i+1)
		digests[i+1] = digestOf(t, img)
		var opts []layout.Option
		if p != "linux/riscv64" {
			// riscv64's descriptor carries no platform: judged by its config.
			opts = append(opts, layout.WithPlatform(plat(p)))
		}
		if err := lp.AppendImage(img, opts...); err != nil {
			t.Fatal(err)
		}
	}
	target := "oci-dir:" + dir

	setHost(t, "linux/riscv64")
	doc, _, errOut, code := scanJSON(t, target, "")
	// No IndexDigest: the layout's index.json is its table of contents.
	wantImage(t, doc, errOut, code, 3, report.ImageRecord{
		Platform: "linux/riscv64", RequestedPlatform: "linux/riscv64", Match: report.ImageMatchExact,
		ManifestDigest: digests[3],
	})

	doc, _, errOut, code = scanJSON(t, target, "linux/arm64/v8")
	wantImage(t, doc, errOut, code, 2, report.ImageRecord{
		Platform: "linux/arm64", RequestedPlatform: "linux/arm64", Match: report.ImageMatchExact,
		ManifestDigest: digests[2],
	})

	_, _, errOut, code = scanJSON(t, target, "linux/arm/v7")
	if code != 2 || !strings.Contains(errOut, "has no linux/arm/v7 image; it offers linux/amd64, linux/arm64, linux/riscv64\n") {
		t.Errorf("Run = %d, want 2 naming the three offers\nstderr: %s", code, errOut)
	}
}

// A docker archive is one image, judged as a registry single image is.
func TestRun_PlatformDockerArchive(t *testing.T) {
	isolateCredentials(t)
	write := func(img v1.Image) string {
		path := filepath.Join(t.TempDir(), "image.tar")
		if err := tarball.WriteToFile(path, mustRef(t, "scancmd-test:latest"), img); err != nil {
			t.Fatal(err)
		}
		return "docker-archive:" + path
	}
	arm := platImage(t, plat("linux/arm64"), 2)
	target := write(arm)
	setHost(t, "linux/amd64")

	t.Run("explicit mismatch is exit 2", func(t *testing.T) {
		_, _, errOut, code := scanJSON(t, target, "linux/amd64")
		if code != 2 || !strings.Contains(errOut, "is a single linux/arm64 image; --platform asked for linux/amd64") {
			t.Errorf("Run = %d, want 2 naming both platforms\nstderr: %s", code, errOut)
		}
	})
	t.Run("host default mismatch warns", func(t *testing.T) {
		doc, _, errOut, code := scanJSON(t, target, "")
		wantImage(t, doc, errOut, code, 2, report.ImageRecord{
			Platform: "linux/arm64", RequestedPlatform: "linux/amd64", Match: report.ImageMatchMismatch,
			ManifestDigest: digestOf(t, arm),
		})
		if !strings.Contains(errOut, "warning: image "+target+" is linux/arm64 only, not this host's linux/amd64") {
			t.Errorf("stderr lacks the mismatch warning:\n%s", errOut)
		}
	})
	t.Run("a config naming no platform is unchecked", func(t *testing.T) {
		bare := platImage(t, v1.Platform{}, 1)
		target := write(bare)
		doc, _, errOut, code := scanJSON(t, target, "linux/arm64")
		wantImage(t, doc, errOut, code, 1, report.ImageRecord{
			Platform: "", RequestedPlatform: "linux/arm64", Match: report.ImageMatchUnchecked,
			ManifestDigest: digestOf(t, bare),
		})
		want := "warning: image " + target + ": its config names no OS or architecture, so its platform " +
			"could not be checked against linux/arm64\n"
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
		if want := recordLine(target, "unknown platform", digestOf(t, bare), "", ""); !hasLine(errOut, want) {
			t.Errorf("stderr lacks the record line %q:\n%s", want, errOut)
		}
	})
}

// --platform on a target with no platform to choose is exit 2, never
// silently ignored — and a malformed value reaching Run is refused there too.
func TestRun_PlatformRefusedOffTheImagePath(t *testing.T) {
	isolateCredentials(t)
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	writeFileT(t, sbom, `{"bomFormat":"CycloneDX","components":[]}`)
	dir := t.TempDir()
	writeFileT(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.22\n")

	for _, tc := range []struct{ target, kind string }{
		{sbom, "an sbom"},
		{"dir:" + dir, "a directory"},
	} {
		_, out, errOut, code := scanJSON(t, tc.target, "linux/arm64")
		if code != 2 {
			t.Errorf("%s: Run = %d, want 2\nstderr: %s", tc.kind, code, errOut)
		}
		if want := "error: --platform applies only to an image; " + tc.target + " is " + tc.kind + "\n"; !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
		if out != "" {
			t.Errorf("stdout = %q, want nothing", out)
		}
	}

	img := platImage(t, plat("linux/arm64"), 1)
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(path, mustRef(t, "scancmd-test:latest"), img); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"linux", "linux/arm64:10.0", "linux/arm/v7/extra", "/arm64", "linux/", "windows/amd64"} {
		_, _, errOut, code := scanJSON(t, "docker-archive:"+path, bad)
		if code != 2 || !strings.Contains(errOut, "error: --platform: ") {
			t.Errorf("--platform %q: Run = %d, want 2 with a --platform error\nstderr: %s", bad, code, errOut)
		}
	}
}

// D118 still holds on the path D119 rewrote: the platform-selected child's
// manifest and its blobs are fetched with the credential, not only the top
// index. The gate admits the tag's index anonymously and refuses everything
// fetched by digest — the child manifest, its config and layers — without
// the credential.
func TestRun_PlatformIndexChildIsPulledWithCredentials(t *testing.T) {
	var childAuthed atomic.Int64
	gate := func(r *http.Request) int {
		if strings.Contains(r.URL.Path, "/manifests/") && !strings.Contains(r.URL.Path, "/manifests/sha256:") {
			return 0
		}
		if !acceptBasic(r.Header.Get("Authorization")) {
			return http.StatusUnauthorized
		}
		if strings.Contains(r.URL.Path, "/manifests/sha256:") {
			childAuthed.Add(1)
		}
		return 0
	}
	idx, d := buildIndex(t, entry{"linux/amd64", 1}, entry{"linux/arm64", 2})

	t.Run("anonymous is an AuthError", func(t *testing.T) {
		isolateCredentials(t)
		ar := newAuthRegistryFunc(t, gate)
		ref := pushIndex(t, ar.host, "private/multi:1", idx)
		ar.locked.Store(true)

		_, out, errOut, code := scanJSON(t, ref, "linux/arm64")
		if code != 2 {
			t.Fatalf("Run = %d, want 2\nstderr: %s", code, errOut)
		}
		for _, want := range []string{
			"registry " + ar.host + " answered 401 Unauthorized",
			"no credentials were offered",
		} {
			if !strings.Contains(errOut, want) {
				t.Errorf("stderr lacks %q:\n%s", want, errOut)
			}
		}
		if out != "" {
			t.Errorf("stdout = %q, want nothing", out)
		}
	})
	t.Run("with credentials the chosen child is pulled", func(t *testing.T) {
		isolateCredentials(t)
		ar := newAuthRegistryFunc(t, gate)
		ref := pushIndex(t, ar.host, "private/multi:1", idx)
		ar.locked.Store(true)
		childAuthed.Store(0)
		t.Setenv("ASSAY_REGISTRY_AUTH_USERNAME", regUser)
		t.Setenv("ASSAY_REGISTRY_AUTH_PASSWORD", regPass)

		doc, out, errOut, code := scanJSON(t, ref, "linux/arm64")
		wantImage(t, doc, errOut, code, 2, report.ImageRecord{
			Platform: "linux/arm64", RequestedPlatform: "linux/arm64", Match: report.ImageMatchExact,
			ManifestDigest: d[2], IndexDigest: digestOf(t, idx),
		})
		if childAuthed.Load() == 0 {
			t.Error("no child manifest was fetched with the credential")
		}
		assertNoSecrets(t, out, errOut)
	})
}

// The JSON record's match strings are source's, passed through unchanged;
// the report's constants are their documentation and must not drift.
func TestPlatformMatchConstantsAgree(t *testing.T) {
	for _, p := range [][2]string{
		{source.MatchExact, report.ImageMatchExact},
		{source.MatchCompatible, report.ImageMatchCompatible},
		{source.MatchUnchecked, report.ImageMatchUnchecked},
		{source.MatchMismatch, report.ImageMatchMismatch},
	} {
		if p[0] != p[1] {
			t.Errorf("source %q != report %q", p[0], p[1])
		}
	}
}

// Only image targets carry the object: an SBOM's document omits it.
func TestRun_PlatformJSONOmitsImageForAnSBOM(t *testing.T) {
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	writeFileT(t, sbom, `{"bomFormat":"CycloneDX","components":[]}`)
	var out, errOut bytes.Buffer
	Run(context.Background(), testDB(t), sbom, Options{Output: "json"}, &out, &errOut)
	if strings.Contains(out.String(), `"image"`) {
		t.Errorf("an SBOM scan's document carries an image object:\n%s", out.String())
	}
	if strings.Contains(errOut.String(), "image ") && strings.Contains(errOut.String(), ", manifest ") {
		t.Errorf("an SBOM scan printed an image record line:\n%s", errOut.String())
	}
}

func writeFileT(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
