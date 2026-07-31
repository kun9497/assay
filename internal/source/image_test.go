package source

import (
	"io"
	"runtime"
	"strings"
	"testing"
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
}
