package source

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		ref  string
		want kind
	}{
		{"docker-archive:image.tar", kindTarball},
		{"oci-dir:./layout", kindLayout},
		{"alpine:3.19", kindRegistry},
		{"ghcr.io/owner/repo@sha256:" + strings.Repeat("a", 64), kindRegistry},
		{"registry.example.com:5000/team/app:v1", kindRegistry},
	}
	for _, tt := range tests {
		if got := classify(tt.ref); got != tt.want {
			t.Errorf("classify(%q) = %v, want %v", tt.ref, got, tt.want)
		}
	}
}

// A host:port registry reference and a docker-archive prefix both contain a
// colon. Splitting on the first colon without checking against a fixed scheme
// set would route registry.example.com:5000/... to the tarball loader, and the
// error the user sees would be about a missing file rather than a registry.
func TestClassify_HostPortIsNotAScheme(t *testing.T) {
	for _, ref := range []string{
		"registry.example.com:5000/team/app:v1",
		"localhost:5000/app",
		"alpine:3.19",
	} {
		if got := classify(ref); got != kindRegistry {
			t.Errorf("classify(%q) = %v, want kindRegistry", ref, got)
		}
	}
}

// An unprefixed argument naming a file that exists is an SBOM, which is how
// slice 2a's behaviour survives. Deciding registry-first would make
// `assay scan ./alpine.cdx.json` try to pull a repository by that name.
func TestClassifyTarget_ExistingFileIsAnSBOM(t *testing.T) {
	f := t.TempDir() + "/sbom.cdx.json"
	if err := writeFile(f, "{}"); err != nil {
		t.Fatal(err)
	}
	if got := ClassifyTarget(f); got != TargetSBOM {
		t.Errorf("ClassifyTarget(existing file) = %v, want TargetSBOM", got)
	}
	if got := ClassifyTarget("alpine:3.19"); got != TargetImage {
		t.Errorf("ClassifyTarget(image ref) = %v, want TargetImage", got)
	}
	// An explicit prefix wins even if a file of that name happens to exist.
	if got := ClassifyTarget("docker-archive:" + f); got != TargetImage {
		t.Errorf("ClassifyTarget(prefixed) = %v, want TargetImage", got)
	}
}

// Each layer's Open must close over its own layer. Go 1.22 made loop variables
// per-iteration so this is safe today, but the failure mode if it ever changes
// is every layer serving the last layer's bytes — an inventory that looks
// plausible and is wrong, which no other test would catch.
func TestFromV1_EachLayerOpensItsOwnBytes(t *testing.T) {
	img, err := fromV1(fakeImage{layers: []fakeLayer{
		{diff: "sha256:aaa", body: "layer-a"},
		{diff: "sha256:bbb", body: "layer-b"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Layers) != 2 {
		t.Fatalf("Layers = %d, want 2", len(img.Layers))
	}
	for i, want := range []string{"layer-a", "layer-b"} {
		rc, err := img.Layers[i].Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if string(b) != want {
			t.Errorf("Layers[%d].Open() = %q, want %q", i, b, want)
		}
	}
}

// The diff ID is the uncompressed digest. Using Digest() instead would compile
// and produce a plausible-looking hex string that matches nothing syft reports.
func TestFromV1_UsesDiffIDNotDigest(t *testing.T) {
	img, err := fromV1(fakeImage{layers: []fakeLayer{{diff: "sha256:diffid", body: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := img.Layers[0].DiffID; got != "sha256:diffid" {
		t.Errorf("DiffID = %q, want the uncompressed digest sha256:diffid", got)
	}
}

// An index whose only entries are attestations has no filesystem to scan.
// Falling back to the first entry would produce an empty package list and a
// clean-looking report.
func TestImageFromIndex_RefusesUnknownPlatformOnly(t *testing.T) {
	_, err := imageFromIndex(fakeIndex{platforms: []string{"unknown/unknown"}}, "test")
	if err == nil {
		t.Fatal("selected an unknown/unknown manifest; those carry no filesystem")
	}
	if !strings.Contains(err.Error(), runtime.GOARCH) {
		t.Errorf("error %q does not say which platform was wanted", err)
	}
	// The positive match already excludes unknown/unknown, so the error above
	// fires with or without the skip. What the skip is FOR is the message: an
	// operator reading "it offers unknown/unknown" learns nothing, and the
	// entries are not images at all. Assert the message the skip produces.
	if strings.Contains(err.Error(), "unknown") {
		t.Errorf("error %q offers unknown/unknown as if it were a choice; "+
			"attestation manifests are not images", err)
	}
}

// An index carrying a real platform alongside attestations must still list the
// real one, so the operator learns what the image actually has.
func TestImageFromIndex_ErrorNamesTheRealPlatformsOnly(t *testing.T) {
	_, err := imageFromIndex(fakeIndex{platforms: []string{
		"unknown/unknown", "linux/riscv64", "unknown/unknown",
	}}, "test")
	if err == nil {
		t.Fatal("selected a riscv64 image on this host")
	}
	if !strings.Contains(err.Error(), "linux/riscv64") {
		t.Errorf("error %q does not name the platform that was on offer", err)
	}
	if strings.Contains(err.Error(), "unknown") {
		t.Errorf("error %q lists attestation manifests as platforms", err)
	}
}

// D14, as narrowed for this slice: a scan of a local target makes no network
// call at all. That is the air-gapped path, and it is a property of the code
// rather than of anyone's intention — nothing else here would notice a
// remote. call added to the tarball or layout branch.
//
// The check is a transport that fails any request, installed on the default
// client. A local load must not touch it; only the registry branch may.
func TestOpen_LocalTargetsMakeNoNetworkCall(t *testing.T) {
	var reached int
	trap := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		reached++
		return nil, fmt.Errorf("network call to %s on a local target", r.URL)
	})

	// BOTH transports. go-containerregistry's remote package does not use
	// http.DefaultTransport — it has its own remote.DefaultTransport — so
	// trapping only the standard one leaves the single path that can actually
	// reach a registry uninstrumented. The first version of this test did
	// exactly that and passed with a live remote.Image() call smuggled into the
	// oci-dir branch, which is the case it exists to forbid.
	restoreStd, restoreRemote := http.DefaultTransport, remote.DefaultTransport
	http.DefaultTransport, remote.DefaultTransport = trap, trap
	t.Cleanup(func() {
		http.DefaultTransport, remote.DefaultTransport = restoreStd, restoreRemote
	})

	for _, ref := range []string{
		"docker-archive:" + filepath.Join(t.TempDir(), "absent.tar"),
		"oci-dir:" + filepath.Join(t.TempDir(), "absent"),
	} {
		// The load fails — the paths do not exist — but the point is where it
		// fails. A network call would be counted before the error surfaced.
		_, _ = Open(context.Background(), ref)
	}
	if reached != 0 {
		t.Errorf("a local target made %d network call(s); D14 forbids any", reached)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// `skopeo copy --all` writes a layout whose child is itself an index. The
// first version failed on it with "it offers " and an empty list — an error
// naming nothing at all.
func TestImageFromIndex_DescendsIntoNestedIndexes(t *testing.T) {
	inner := fakeIndex{platforms: []string{"linux/" + runtime.GOARCH}}
	outer := fakeIndex{children: map[string]fakeIndex{strings.Repeat("a", 64): inner}}
	if _, err := imageFromIndex(outer, "nested"); err != nil {
		t.Errorf("imageFromIndex on a nested index: %v", err)
	}
}

// A single-image layout carries a descriptor with no platform; the image's own
// config still says what it is. Discarding those entries made oci-dir: fail on
// the shape layout.Write produces.
func TestImageFromIndex_ReadsPlatformFromTheConfigWhenTheDescriptorHasNone(t *testing.T) {
	hex := strings.Repeat("b", 64)
	idx := fakeIndex{
		noPlatform: []string{hex},
		images:     map[string]v1.Image{hex: configImage{os: "linux", arch: runtime.GOARCH}},
	}
	if _, err := imageFromIndex(idx, "single"); err != nil {
		t.Errorf("imageFromIndex on a platform-less descriptor: %v", err)
	}
}

// ...and it must still refuse the wrong architecture rather than take it.
func TestImageFromIndex_ConfigPlatformIsStillChecked(t *testing.T) {
	hex := strings.Repeat("c", 64)
	idx := fakeIndex{
		noPlatform: []string{hex},
		images:     map[string]v1.Image{hex: configImage{os: "linux", arch: "riscv64"}},
	}
	_, err := imageFromIndex(idx, "single")
	if err == nil {
		t.Fatal("accepted a riscv64 image on this host")
	}
	if !strings.Contains(err.Error(), "linux/riscv64") {
		t.Errorf("error %q does not name what the layout actually holds", err)
	}
}
