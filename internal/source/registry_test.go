package source

import (
	"context"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// remote.Image defaults to linux/amd64 and never consults the host, so the
// platform has to be stated. Without it, `assay scan alpine:3.19` on an arm64
// machine scans the amd64 image: a full package list, just not the one that
// runs, and no error anywhere.
//
// A local registry serving a multi-platform index is the only way to see this;
// a fake index cannot, because the bug is that the index-walking code is never
// reached on this path at all.
func TestOpen_RegistrySelectsTheHostPlatform(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	// Two single-layer images with distinguishable layer counts, published
	// under one index: one for this host, one for a platform we are not.
	hostImg, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	otherImg, err := random.Image(64, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Ask for a platform this machine is NOT. On an amd64 host, wanting amd64
	// makes the library's default the right answer by accident, and dropping
	// the explicit platform would pass.
	want := "arm64"
	if runtime.GOARCH == "arm64" {
		want = "amd64"
	}
	hostPlatform = func() v1.Platform { return v1.Platform{OS: "linux", Architecture: want} }
	t.Cleanup(func() {
		hostPlatform = func() v1.Platform {
			return v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
		}
	})

	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: hostImg, Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: "linux", Architecture: want}}},
		mutate.IndexAddendum{Add: otherImg, Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: "linux", Architecture: runtime.GOARCH}}},
		// An attestation manifest, as real indexes carry.
		mutate.IndexAddendum{Add: otherImg, Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"}}},
	)

	ref, err := name.ParseReference(host + "/multi:latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(ref.Context().Tag("latest"), idx); err != nil {
		t.Fatal(err)
	}

	img, err := Open(context.Background(), ref.String())
	if err != nil {
		t.Fatal(err)
	}
	// The wanted platform's image has one layer; the other has three.
	if len(img.Layers) != 1 {
		t.Errorf("pulled %d layers, want 1: the requested platform was ignored "+
			"and the library's default was used, which on a non-amd64 host means "+
			"scanning a full package list for a machine this is not", len(img.Layers))
	}
}
