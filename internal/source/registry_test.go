package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
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
	HostPlatform = func() v1.Platform { return v1.Platform{OS: "linux", Architecture: want} }
	t.Cleanup(func() {
		HostPlatform = func() v1.Platform {
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

	img, err := Open(context.Background(), ref.String(), "")
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

	out, err := Open(context.Background(), ref.String(), "")
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

// QA 2026-11-02 (#24): on the registry path the library reads the config blob
// whole and bounds it only by the size the manifest declares -- the
// registry's own word. The manifest is already in hand when the config is
// first wanted, so a declared size past MaxConfigBytes is refused before the
// blob is asked for: the test's registry serves the real image under a
// manifest forged to declare a 256 MiB config, and counts requests for the
// config blob. Without the check the library fetches the blob and fails on
// the size mismatch -- also an error, which is why the request count is the
// assertion that tells the two apart, not the error alone.
func TestOpen_RegistryRefusesADeclaredOversizedConfigBeforeFetchingIt(t *testing.T) {
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
	raw, err := img.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	var m v1.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	const declared = 256 << 20
	m.Config.Size = declared
	forged, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	forgedDigest, _, err := v1.SHA256(bytes.NewReader(forged))
	if err != nil {
		t.Fatal(err)
	}
	mt, err := img.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	cfgName, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}

	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	var armed atomic.Bool
	var configRequests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if armed.Load() && strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Content-Type", string(mt))
			w.Header().Set("Docker-Content-Digest", forgedDigest.String())
			w.Header().Set("Content-Length", strconv.Itoa(len(forged)))
			if r.Method != http.MethodHead {
				_, _ = w.Write(forged)
			}
			return
		}
		// Counted only once armed: remote.Write's own HEAD of the config,
		// checking whether it must upload it, is not a fetch by Open.
		if armed.Load() && strings.HasSuffix(r.URL.Path, "/blobs/"+cfgName.String()) {
			configRequests.Add(1)
		}
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	ref, err := name.ParseReference(host + "/forged/config:1")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	armed.Store(true)

	_, err = Open(context.Background(), ref.String(), "")
	if err == nil {
		t.Fatal("Open succeeded against a manifest declaring a 256 MiB config")
	}
	if want := ConfigLimitError(declared).Error(); !strings.Contains(err.Error(), want) {
		t.Errorf("err = %q, want it to carry %q", err, want)
	}
	if n := configRequests.Load(); n != 0 {
		t.Errorf("the config blob was requested %d time(s); the declared size must be refused "+
			"before the blob is fetched, or the bound is the registry's declaration", n)
	}
}

// fetchTrap is a fakeImage whose config must never be fetched: the test it
// serves declares the config oversized, and a RawConfigFile call is the
// defect itself, not a step on the way to the error.
type fetchTrap struct {
	fakeImage
	t *testing.T
}

func (f fetchTrap) RawConfigFile() ([]byte, error) {
	f.t.Fatal("RawConfigFile was called: the config was fetched before its declared size was checked")
	return nil, nil
}

// The other two sites that read a config. configDiffIDs is on every image
// path, so the diff-id check is where a tarball or layout meets the limit;
// collectCandidates reads a config to judge a platform-less index entry, and
// an oversized one is skipped and recorded, the way any unreadable entry is,
// rather than fetched.
func TestConfigSize_IsCheckedAtEveryConfigRead(t *testing.T) {
	t.Run("configDiffIDs refuses before RawConfigFile", func(t *testing.T) {
		img := fetchTrap{fakeImage: fakeImage{declaredConfig: MaxConfigBytes + 1}, t: t}
		_, err := configDiffIDs(img, 0)
		if want := ConfigLimitError(MaxConfigBytes + 1).Error(); err == nil || err.Error() != want {
			t.Errorf("err = %v, want %q", err, want)
		}
	})

	t.Run("exactly the limit is read", func(t *testing.T) {
		ids, err := configDiffIDs(fakeImage{declaredConfig: MaxConfigBytes}, 0)
		if err != nil || len(ids) != 0 {
			t.Errorf("configDiffIDs(config of exactly the limit) = %v, %v; want it read", ids, err)
		}
	})

	t.Run("collectCandidates skips and records the entry", func(t *testing.T) {
		hex := strings.Repeat("c", 64)
		idx := fakeIndex{
			noPlatform: []string{hex},
			images:     map[string]v1.Image{hex: configImage{os: "linux", arch: runtime.GOARCH, configSize: MaxConfigBytes + 1}},
		}
		var cands []candidate
		var skipped []unreadable
		if err := collectCandidates(idx, "index", v1.Hash{}, nil, 0, &cands, &skipped); err != nil {
			t.Fatalf("collectCandidates: %v", err)
		}
		if len(cands) != 0 {
			t.Errorf("candidates = %+v, want none: the entry's config was declared past the limit", cands)
		}
		if len(skipped) != 1 || skipped[0].digest.Hex != hex || !strings.Contains(skipped[0].err.Error(), "per-config limit") {
			t.Errorf("skipped = %+v, want the one entry recorded with the limit's error", skipped)
		}
	})
}
