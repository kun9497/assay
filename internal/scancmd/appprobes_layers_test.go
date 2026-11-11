package scancmd

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/kun9497/assay/internal/source"
)

// D160 at the caller, across layers: where a probed package's bytes came from
// is evidence (D10), and an entry in a newer layer that is not a Go binary
// -- a symlink, a chmod -x copy, a wrapper script -- shadows a Go binary a
// lower layer left at the same path. Single-layer fixtures cannot show either.

// repoBBoltVersion reads go.etcd.io/bbolt's version from the repository's own
// go.mod, so the Go fixtures build from the module cache the repo already
// filled whatever version it is at.
func repoBBoltVersion(t *testing.T) string {
	t.Helper()
	mod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read repo go.mod: %v", err)
	}
	m := regexp.MustCompile(`go\.etcd\.io/bbolt (v[0-9][^\s]*)`).FindSubmatch(mod)
	if m == nil {
		t.Fatal("repo go.mod does not require go.etcd.io/bbolt")
	}
	return string(m[1])
}

// probeLayer is one layer's entries; link names a symlink target.
type probeLayerEntry struct {
	name, link string
	body       []byte
	mode       int64
	// hard makes link a hardlink to an archive path instead of a symlink.
	hard bool
	// dir makes an explicit directory entry (no body, no link).
	dir bool
}

// writeLayeredProbeImage writes a docker-archive of several layers, lowest
// first, and returns each layer's diff id as the report spells it.
func writeLayeredProbeImage(t *testing.T, path string, layers ...[]probeLayerEntry) []string {
	t.Helper()
	img := v1.Image(empty.Image)
	var diffIDs []string
	for _, entries := range layers {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range entries {
			if e.dir {
				if err := tw.WriteHeader(&tar.Header{Name: e.name + "/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if e.link != "" {
				kind := byte(tar.TypeSymlink)
				if e.hard {
					kind = tar.TypeLink
				}
				if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o777, Typeflag: kind, Linkname: e.link}); err != nil {
					t.Fatal(err)
				}
				continue
			}
			mode := e.mode
			if mode == 0 {
				mode = 0o644
			}
			if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: mode, Size: int64(len(e.body)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		raw := buf.Bytes()
		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil })
		if err != nil {
			t.Fatalf("LayerFromOpener: %v", err)
		}
		d, err := layer.DiffID()
		if err != nil {
			t.Fatal(err)
		}
		diffIDs = append(diffIDs, d.String())
		if img, err = mutate.AppendLayers(img, layer); err != nil {
			t.Fatalf("AppendLayers: %v", err)
		}
	}
	ref, err := name.ParseReference("scancmd-probe-layers:latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := tarball.WriteToFile(path, ref, img); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	return diffIDs
}

func alpineLayer() []probeLayerEntry {
	return []probeLayerEntry{{name: osReleasePath, body: []byte(osReleaseAlpine319)}, {name: apkDBPath, body: []byte(apkOneRecord)}}
}

// Each probed package is located in the layer that holds its file, not in
// the layer the OS database came from.
func TestRun_D160_ProbedPackagesAreLocatedInTheirOwnLayer(t *testing.T) {
	bin, err := os.ReadFile(buildLinuxBBoltBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	ids := writeLayeredProbeImage(t, tarPath,
		alpineLayer(),
		[]probeLayerEntry{
			{name: "usr/lib/node_modules/npm/node_modules/minimatch/package.json", body: []byte(`{"name":"minimatch","version":"3.0.4"}`)},
			{name: "usr/bin/tool", body: bin, mode: 0o755},
		},
		[]probeLayerEntry{{name: "usr/lib/node_modules/npm/package.json", body: []byte(`{"name":"npm","version":"8.19.4"}`)}},
	)
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d\nstderr: %s", code, errOut.String())
	}
	doc := decodeProbe(t, out.String())
	got := map[string]string{}
	for _, f := range doc.Findings {
		for _, l := range f.Package.Locations {
			got[f.Package.Name] = l.LayerDigest
		}
	}
	if got["minimatch"] != ids[1] || got["go.etcd.io/bbolt"] != ids[1] {
		t.Errorf("layer digests = %v, want minimatch and bbolt both in the middle layer %s (layers: %v)", got, ids[1], ids)
	}
	// Every (devel) main module is left out of the component count by the
	// probe (not a thing the image could have versioned), so an image with
	// one Go binary and two npm packages is fully evaluated.
	if doc.Summary.NotEvaluated != 0 {
		t.Errorf("summary = %+v, want notEvaluated 0: the binary's unstamped main module is not a component here", doc.Summary)
	}
}

// A newer layer's entry at the binary's path -- a symlink, the same bytes
// without the execute bit, a wrapper script under the floor -- is what the
// image ships there, and the lower layer's Go binary is not cataloged.
func TestRun_D160_ANewerNonBinaryAtThePathShadowsTheGoBinaryBelow(t *testing.T) {
	bin, err := os.ReadFile(buildLinuxBBoltBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		upper probeLayerEntry
	}{
		{"symlink", probeLayerEntry{name: "usr/bin/tool", link: "tool.real"}},
		{"chmod -x copy", probeLayerEntry{name: "usr/bin/tool", body: bin, mode: 0o644}},
		{"wrapper under the floor", probeLayerEntry{name: "usr/bin/tool", body: []byte("#!/bin/sh\nexec tool.real\n"), mode: 0o755}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeLayeredProbeImage(t, tarPath, alpineLayer(),
				[]probeLayerEntry{{name: "usr/bin/tool", body: bin, mode: 0o755}},
				[]probeLayerEntry{tc.upper},
			)
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut); code != 0 {
				t.Fatalf("Run = %d\nstderr: %s", code, errOut.String())
			}
			for _, f := range decodeProbe(t, out.String()).Findings {
				if f.Package.Name == "go.etcd.io/bbolt" {
					t.Errorf("bbolt finding at %+v: the lower layer's binary surfaced under a newer %s", f.Package.Locations, tc.name)
				}
			}
		})
	}
}

// An executable larger than the per-file limit is not a Go binary this scan
// may read: declined at its header, never read, and the scan goes on --
// where reading it would have failed the whole image (D112), OS verdict
// included. A package.json over the limit IS read and fails as every other
// bounded read does.
func TestRun_D160_OversizeExecutableIsDeclinedNotFatal(t *testing.T) {
	lowerLimit(t, &source.MaxFileBytes, 4<<10)
	bigELF := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{'x'}, 5000)...)
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeLayeredProbeImage(t, tarPath, append(alpineLayer(), probeLayerEntry{name: "usr/bin/huge", body: bigELF, mode: 0o755}))
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0: an oversize executable is declined, not read\nstderr: %s", code, errOut.String())
	}

	tarPath2 := filepath.Join(t.TempDir(), "image2.tar")
	writeLayeredProbeImage(t, tarPath2, append(alpineLayer(), probeLayerEntry{name: "usr/lib/node_modules/x/package.json", body: bytes.Repeat([]byte{'{'}, 5000)}))
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath2, Options{Output: "json"}, &out, &errOut); code != 2 {
		t.Fatalf("Run = %d, want 2: a package.json over the per-file limit is a bounded read (D112)\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "usr/lib/node_modules/x/package.json exceeds the 4 KiB per-file limit (D112)") {
		t.Errorf("stderr does not name the oversize package.json:\n%s", errOut.String())
	}
}

// A package.json shorter than the sniff's four bytes is read, not an error,
// and -- being unparseable -- a counted skip.
func TestRun_D160_TinyPackageJSONIsASkipNotAnError(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeLayeredProbeImage(t, tarPath, append(alpineLayer(),
		probeLayerEntry{name: "usr/lib/node_modules/x/package.json", body: []byte("{}")},
		probeLayerEntry{name: "usr/lib/node_modules/y/package.json", body: nil},
	))
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0\nstderr: %s", code, errOut.String())
	}
	if s := decodeProbe(t, out.String()).Summary; s.Components != 3 || s.NotEvaluated != 2 {
		t.Errorf("summary = %+v, want 3 components (busybox + two package.json) and 2 not evaluated", s)
	}
}

// Two Go binaries list their packages in path order, so two scans of one
// image agree byte for byte (design goal #3 reaches the inventory).
func TestCatalogApplicationProbes_BinariesInPathOrder(t *testing.T) {
	bin, err := os.ReadFile(buildLinuxBBoltBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	img := &source.Image{Layers: []source.Layer{layerWithModes(t, "sha256:bins", []probeLayerEntry{
		{name: "usr/sbin/zeta", body: bin, mode: 0o755},
		{name: "usr/bin/alpha", body: bin, mode: 0o755},
	})}}
	pkgs, _, _, err := catalogApplicationProbes(context.Background(), img, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, p := range pkgs {
		if p.Name == "go.etcd.io/bbolt" {
			paths = append(paths, p.Locations[0].Path)
		}
	}
	if len(paths) != 2 || paths[0] != "usr/bin/alpha" || paths[1] != "usr/sbin/zeta" {
		t.Errorf("bbolt locations = %v, want usr/bin/alpha before usr/sbin/zeta", paths)
	}
}

// layerWithModes is imageLayer for entries that carry a mode.
func layerWithModes(t *testing.T, diffID string, entries []probeLayerEntry) source.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if e.link != "" {
			if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: e.link}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: e.mode, Size: int64(len(e.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	return source.Layer{DiffID: diffID, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }}
}
