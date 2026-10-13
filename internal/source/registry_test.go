package source

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
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
	// The pull now consults D118's chain; keep the developer's own docker
	// login and its credential helper out of a test about platforms.
	isolateEnv(t)
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

// D118's wording reaches a refusal that comes after Open has returned: the
// layer blob is fetched when the cataloger opens the layer, and a registry
// that serves the manifest and config but refuses the blob (a pull policy, a
// credential revoked mid-scan) must still answer as an *AuthError.
func TestOpen_RegistryLayerBlobRefusalIsAuthError(t *testing.T) {
	isolateEnv(t)
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", runtime.GOARCH
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	ls, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	layerDigest, err := ls[0].Digest()
	if err != nil {
		t.Fatal(err)
	}

	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	var locked atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if locked.Load() && strings.HasSuffix(r.URL.Path, "/blobs/"+layerDigest.String()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"errors":[{"code":"DENIED","message":"requested access to the resource is denied"}]}`)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	ref, err := name.ParseReference(host + "/private/app:1")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	locked.Store(true)

	out, err := Open(context.Background(), ref.String())
	if err != nil {
		t.Fatalf("Open: %v (the manifest and config are served; only the layer blob is refused)", err)
	}
	if len(out.Layers) != 1 {
		t.Fatalf("got %d layers, want 1", len(out.Layers))
	}
	rc, err := out.Layers[0].Open()
	if err == nil {
		rc.Close()
		t.Fatal("layer Open succeeded against a refused blob")
	}
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("layer Open error is not an *AuthError: %v", err)
	}
	if ae.Status != http.StatusForbidden || ae.Registry != host {
		t.Errorf("AuthError = {Status %d, Registry %q}, want {403, %q}", ae.Status, ae.Registry, host)
	}
}
