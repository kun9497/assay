package scancmd

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/kun9497/assay/internal/report"
)

// D119 review fixes, held at the caller: the one-image layout branch, the
// single-image check's normalisation, ladder and descriptor fallback, the
// normalisation of a platform-less layout entry's config, and D118's refusal
// on a platform-less index child.

// writeLayout writes imgs into a fresh oci-dir: layout, each with the
// descriptor platform at the same position in descs ("" for none), and
// returns the scan target.
func writeLayout(t *testing.T, imgs []v1.Image, descs []string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "layout")
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	for i, img := range imgs {
		var opts []layout.Option
		if descs[i] != "" {
			opts = append(opts, layout.WithPlatform(plat(descs[i])))
		}
		if err := lp.AppendImage(img, opts...); err != nil {
			t.Fatal(err)
		}
	}
	return "oci-dir:" + dir
}

func writeArchive(t *testing.T, img v1.Image) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(path, mustRef(t, "scancmd-test:latest"), img); err != nil {
		t.Fatal(err)
	}
	return "docker-archive:" + path
}

// A one-image layout is a single image, judged as a docker archive is: on the
// host default a foreign image is scanned as a mismatch, not refused as an
// index miss. riscv64 so the image is foreign to every host this runs on.
func TestRun_PlatformOneImageLayoutIsASingleImage(t *testing.T) {
	isolateCredentials(t)
	setHost(t, "linux/amd64")
	img := platImage(t, plat("linux/riscv64"), 2)
	for _, desc := range []string{"", "linux/riscv64"} {
		target := writeLayout(t, []v1.Image{img}, []string{desc})

		doc, _, errOut, code := scanJSON(t, target, "")
		wantImage(t, doc, errOut, code, 2, report.ImageRecord{
			Platform: "linux/riscv64", RequestedPlatform: "linux/amd64", Match: report.ImageMatchMismatch,
			ManifestDigest: digestOf(t, img),
		})
		if want := "warning: image " + target + " is linux/riscv64 only, not this host's linux/amd64"; !strings.Contains(errOut, want) {
			t.Errorf("descriptor %q: stderr lacks %q:\n%s", desc, want, errOut)
		}

		_, _, errOut, code = scanJSON(t, target, "linux/amd64")
		if want := "error: " + target + " is a single linux/riscv64 image; --platform asked for linux/amd64\n"; code != 2 || !strings.Contains(errOut, want) {
			t.Errorf("descriptor %q: Run = %d, want 2 with %q\nstderr: %s", desc, code, want, errOut)
		}
	}
}

// A one-image layout whose config names no platform is judged by its
// descriptor's: refused when another is asked for, exact when it is asked
// for — never scanned as unchecked while the descriptor says what it is.
func TestRun_PlatformOneImageLayoutFallsBackToTheDescriptor(t *testing.T) {
	isolateCredentials(t)
	bare := platImage(t, v1.Platform{}, 1)
	target := writeLayout(t, []v1.Image{bare}, []string{"linux/arm64"})

	_, _, errOut, code := scanJSON(t, target, "linux/amd64")
	if want := "error: " + target + " is a single linux/arm64 image; --platform asked for linux/amd64\n"; code != 2 || !strings.Contains(errOut, want) {
		t.Errorf("Run = %d, want 2 with %q\nstderr: %s", code, want, errOut)
	}

	doc, _, errOut, code := scanJSON(t, target, "linux/arm64")
	wantImage(t, doc, errOut, code, 1, report.ImageRecord{
		Platform: "linux/arm64", RequestedPlatform: "linux/arm64", Match: report.ImageMatchExact,
		ManifestDigest: digestOf(t, bare),
	})
}

// A single image's config is normalised before comparing: arm64/v8 and
// aarch64 are arm64, x86_64 is amd64.
func TestRun_PlatformSingleImageConfigIsNormalised(t *testing.T) {
	isolateCredentials(t)
	for _, tc := range []struct{ cfg, req, want string }{
		{"linux/arm64/v8", "linux/arm64", "linux/arm64"},
		{"linux/aarch64", "linux/arm64", "linux/arm64"},
		{"linux/x86_64", "linux/amd64", "linux/amd64"},
	} {
		img := platImage(t, plat(tc.cfg), 1)
		doc, _, errOut, code := scanJSON(t, writeArchive(t, img), tc.req)
		wantImage(t, doc, errOut, code, 1, report.ImageRecord{
			Platform: tc.want, RequestedPlatform: tc.req, Match: report.ImageMatchExact,
			ManifestDigest: digestOf(t, img),
		})
	}
}

// The compatibility ladder applies to a single image as to an index: an
// arm/v7 host runs the v6 image. It never climbs.
func TestRun_PlatformSingleImageLadder(t *testing.T) {
	isolateCredentials(t)
	v6 := platImage(t, plat("linux/arm/v6"), 1)
	doc, _, errOut, code := scanJSON(t, writeArchive(t, v6), "linux/arm/v7")
	wantImage(t, doc, errOut, code, 1, report.ImageRecord{
		Platform: "linux/arm/v6", RequestedPlatform: "linux/arm/v7", Match: report.ImageMatchCompatible,
		ManifestDigest: digestOf(t, v6),
	})

	v7 := platImage(t, plat("linux/arm/v7"), 1)
	target := writeArchive(t, v7)
	_, _, errOut, code = scanJSON(t, target, "linux/arm/v6")
	if want := "is a single linux/arm/v7 image; --platform asked for linux/arm/v6"; code != 2 || !strings.Contains(errOut, want) {
		t.Errorf("Run = %d, want 2 with %q\nstderr: %s", code, want, errOut)
	}
}

// A layout entry with no descriptor platform is judged by its config, and
// that config is normalised before comparing: arm64/v8 is arm64, x86_64 is
// amd64.
func TestRun_PlatformLayoutConfigIsNormalised(t *testing.T) {
	isolateCredentials(t)
	amd := platImage(t, plat("linux/x86_64"), 1)
	arm := platImage(t, plat("linux/arm64/v8"), 2)
	target := writeLayout(t, []v1.Image{amd, arm}, []string{"", ""})

	doc, _, errOut, code := scanJSON(t, target, "linux/arm64")
	wantImage(t, doc, errOut, code, 2, report.ImageRecord{
		Platform: "linux/arm64", RequestedPlatform: "linux/arm64", Match: report.ImageMatchExact,
		ManifestDigest: digestOf(t, arm),
	})
	doc, _, errOut, code = scanJSON(t, target, "linux/amd64")
	wantImage(t, doc, errOut, code, 1, report.ImageRecord{
		Platform: "linux/amd64", RequestedPlatform: "linux/amd64", Match: report.ImageMatchExact,
		ManifestDigest: digestOf(t, amd),
	})
}

// D118 on a platform-less index child: to judge it the walk reads its
// manifest and config, and a 401 on either is a refusal the scan reports as
// such — not skipped as unreadable, which would end in a "has no image" miss.
//
// The index also carries a riscv64 entry with a descriptor platform, which the
// walk never reads. It is what makes a skipped refusal visible: without it,
// skipping every platform-less child leaves nothing offered, and the
// nothing-readable error wraps the refusal and reaches AuthError anyway.
func TestRun_PlatformPlatformlessChildRefusalIsAuthError(t *testing.T) {
	amd := platImage(t, plat("linux/amd64"), 1)
	arm := platImage(t, plat("linux/arm64"), 2)
	riscv := platImage(t, plat("linux/riscv64"), 3)
	riscvPlat := plat("linux/riscv64")
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: riscv, Descriptor: v1.Descriptor{Platform: &riscvPlat}},
		mutate.IndexAddendum{Add: amd, Descriptor: v1.Descriptor{}},
		mutate.IndexAddendum{Add: arm, Descriptor: v1.Descriptor{}},
	)
	var configs []string
	for _, img := range []v1.Image{amd, arm} {
		h, err := img.ConfigName()
		if err != nil {
			t.Fatal(err)
		}
		configs = append(configs, "/blobs/"+h.String())
	}
	authed := func(r *http.Request) int {
		if acceptBasic(r.Header.Get("Authorization")) {
			return 0
		}
		return http.StatusUnauthorized
	}

	for _, tc := range []struct {
		name string
		gate func(*http.Request) int
	}{
		// The tag's index is served; every child manifest is refused, so
		// the refusal arrives from the index's Image.
		{"child manifest", func(r *http.Request) int {
			if strings.Contains(r.URL.Path, "/manifests/sha256:") {
				return authed(r)
			}
			return 0
		}},
		// Every manifest is served; only the config blobs are refused, so
		// the refusal arrives from ConfigFile.
		{"config blob", func(r *http.Request) int {
			for _, c := range configs {
				if strings.HasSuffix(r.URL.Path, c) {
					return authed(r)
				}
			}
			return 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateCredentials(t)
			ar := newAuthRegistryFunc(t, tc.gate)
			ref := pushIndex(t, ar.host, "private/bare:1", idx)
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
			if strings.Contains(errOut, "has no linux/arm64 image") || strings.Contains(errOut, "could not be read") {
				t.Errorf("the refusal was skipped as an unreadable entry:\n%s", errOut)
			}
			if out != "" {
				t.Errorf("stdout = %q, want nothing", out)
			}

			// With the credential the same index resolves by config.
			t.Setenv("ASSAY_REGISTRY_AUTH_USERNAME", regUser)
			t.Setenv("ASSAY_REGISTRY_AUTH_PASSWORD", regPass)
			doc, out, errOut, code := scanJSON(t, ref, "linux/arm64")
			wantImage(t, doc, errOut, code, 2, report.ImageRecord{
				Platform: "linux/arm64", RequestedPlatform: "linux/arm64", Match: report.ImageMatchExact,
				ManifestDigest: digestOf(t, arm), IndexDigest: digestOf(t, idx),
			})
			assertNoSecrets(t, out, errOut)
		})
	}
}
