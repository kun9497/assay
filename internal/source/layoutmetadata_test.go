package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Open is the boundary used by a scan. A descriptor must bound the read,
// even if its blob is valid JSON with a matching digest and lots of padding.
func TestOpen_LayoutMetadataMustFitDescriptor(t *testing.T) {
	for _, kind := range []string{"manifest", "nested index"} {
		for _, tc := range []struct {
			name    string
			size    func(int64) int64
			padding int
			want    string
		}{
			{"exact size", func(n int64) int64 { return n }, 0, ""},
			{"negative", func(int64) int64 { return -1 }, 0, "declares -1 bytes"},
			{"over limit", func(int64) int64 { return maxArchiveManifestBytes + 1 }, 0, "100 MiB limit"},
			{"shorter than declared", func(n int64) int64 { return n + 1 }, 0, "descriptor declares"},
			{"understated padded blob", func(int64) int64 { return 1 }, 20 << 20, "exceeds its declared size"},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				lp, err := layout.Write(dir, empty.Index)
				if err != nil {
					t.Fatal(err)
				}
				img := platformImage(t, plat("linux/amd64"))
				if err := lp.WriteImage(img); err != nil {
					t.Fatal(err)
				}
				raw, err := img.RawManifest()
				if err != nil {
					t.Fatal(err)
				}
				desc := v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: writeBlob(t, lp, raw), Size: int64(len(raw))}
				if kind == "nested index" {
					raw, err = json.Marshal(v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{desc}})
					if err != nil {
						t.Fatal(err)
					}
					desc.MediaType = types.OCIImageIndex
				}
				raw = append(raw, bytes.Repeat([]byte{' '}, tc.padding)...)
				desc.Digest = writeBlob(t, lp, raw)
				desc.Size = tc.size(int64(len(raw)))
				if err := lp.AppendDescriptor(desc); err != nil {
					t.Fatal(err)
				}
				_, err = Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
				if tc.want == "" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Open = %v, want %q", err, tc.want)
				}
			})
		}
	}
}

func TestOpen_LayoutRootIndexIsBounded(t *testing.T) {
	dir := t.TempDir()
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := lp.AppendImage(platformImage(t, plat("linux/amd64"))); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(dir, "index.json"), maxArchiveManifestBytes+1); err != nil {
		t.Fatal(err)
	}
	_, err = Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "100 MiB limit") {
		t.Fatalf("Open = %v, want root index limit", err)
	}
}

func TestOpen_LayoutMetadataHonorsCanceledContext(t *testing.T) {
	dir := t.TempDir()
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := lp.AppendImage(platformImage(t, plat("linux/amd64"))); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = Open(ctx, "oci-dir:"+dir, "linux/amd64")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open = %v, want context.Canceled", err)
	}
}

func TestOpen_LayoutRootIndexMustBeRegular(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "index.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Open = %v, want regular-file refusal", err)
	}
}

func TestLayoutMetadataReadBound(t *testing.T) {
	for _, n := range []int{7, 8, 9, 1024} {
		r := strings.NewReader(strings.Repeat(" ", n))
		raw, err := readLayoutMetadata(t.Context(), r, "fixture", 8)
		if n <= 8 {
			if err != nil || len(raw) != n {
				t.Fatalf("read %d: raw %d, err %v", n, len(raw), err)
			}
		} else if err == nil {
			t.Fatalf("read %d accepted an oversized blob", n)
		}
		if read := n - r.Len(); read > 9 {
			t.Fatalf("read %d bytes, bound 9", read)
		}
	}
}

func TestLayoutMetadataChecksContextDuringRead(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	r := &metadataCancelReader{cancel: cancel}
	_, err := readLayoutMetadata(ctx, r, "fixture", 1024)
	if !errors.Is(err, context.Canceled) || r.calls != 1 {
		t.Fatalf("err %v, reads %d; want canceled after one read", err, r.calls)
	}
}

type metadataCancelReader struct {
	cancel context.CancelFunc
	calls  int
}

func (r *metadataCancelReader) Read(p []byte) (int, error) {
	r.calls++
	r.cancel()
	p[0] = ' '
	return 1, nil
}

func TestLayoutDescriptorIsRefusedBeforeBlobOpen(t *testing.T) {
	for _, n := range []int64{-1, maxArchiveManifestBytes + 1} {
		for _, mt := range []types.MediaType{types.OCIManifestSchema1, types.OCIImageIndex} {
			d := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}, MediaType: mt, Size: n}
			idx := &boundedLayoutIndex{ctx: t.Context(), manifest: v1.IndexManifest{Manifests: []v1.Descriptor{d}}, openBlob: func(v1.Hash) (io.ReadCloser, error) {
				t.Fatal("opened a descriptor already known to exceed the bound")
				return nil, nil
			}}
			var err error
			if mt.IsIndex() {
				_, err = idx.ImageIndex(d.Digest)
			} else {
				_, err = idx.Image(d.Digest)
			}
			if err == nil {
				t.Fatalf("accepted %s size %d", mt, n)
			}
		}
	}
}

func TestLayoutImageAndIndexBoundTheirBlobReads(t *testing.T) {
	for _, mt := range []types.MediaType{types.OCIManifestSchema1, types.OCIImageIndex} {
		r := strings.NewReader(strings.Repeat(" ", 1024))
		d := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}, MediaType: mt, Size: 1}
		idx := &boundedLayoutIndex{ctx: t.Context(), manifest: v1.IndexManifest{Manifests: []v1.Descriptor{d}}, openBlob: func(v1.Hash) (io.ReadCloser, error) { return io.NopCloser(r), nil }}
		var err error
		if mt.IsIndex() {
			_, err = idx.ImageIndex(d.Digest)
		} else {
			_, err = idx.Image(d.Digest)
		}
		if err == nil || 1024-r.Len() != 2 {
			t.Fatalf("%s: err=%v bytesRead=%d, want rejection after 2 bytes", mt, err, 1024-r.Len())
		}
	}
}

func TestLayoutImageUsesCheckedManifestSnapshot(t *testing.T) {
	dir := t.TempDir()
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	original := platformImage(t, plat("linux/amd64"))
	if err := lp.AppendImage(original); err != nil {
		t.Fatal(err)
	}
	idx, err := openLayoutIndex(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	d := idx.manifest.Manifests[0]
	img, err := idx.Image(d.Digest)
	if err != nil {
		t.Fatal(err)
	}
	want, err := original.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", d.Digest.Algorithm, d.Digest.Hex), []byte("replaced"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := img.RawManifest()
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatalf("manifest was reopened: %q, %v", raw, err)
	}
	if _, err := img.ConfigFile(); err != nil {
		t.Fatal(err)
	}
	if _, err := img.Layers(); err != nil {
		t.Fatal(err)
	}
}

func TestOpen_LayoutDuplicateDescriptorsAgree(t *testing.T) {
	for _, shape := range []string{"images", "indexes", "different branches"} {
		for _, conflict := range []string{"size", "media type", "none"} {
			for _, reversed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/reversed=%t", shape, conflict, reversed), func(t *testing.T) {
					dir := t.TempDir()
					lp, err := layout.Write(dir, empty.Index)
					if err != nil {
						t.Fatal(err)
					}
					img := platformImage(t, plat("linux/amd64"))
					if err := lp.WriteImage(img); err != nil {
						t.Fatal(err)
					}
					raw, err := img.RawManifest()
					if err != nil {
						t.Fatal(err)
					}
					first := v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: writeBlob(t, lp, raw), Size: int64(len(raw))}
					wrap := func(d v1.Descriptor) v1.Descriptor {
						b, err := json.Marshal(v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{d}})
						if err != nil {
							t.Fatal(err)
						}
						return v1.Descriptor{MediaType: types.OCIImageIndex, Digest: writeBlob(t, lp, b), Size: int64(len(b))}
					}
					if shape != "images" {
						first = wrap(first)
					}
					second := first
					first.Platform = &v1.Platform{OS: "linux", Architecture: "arm64"}
					second.Platform = &v1.Platform{OS: "linux", Architecture: "amd64"}
					first.Annotations = map[string]string{"test": "first"}
					second.Annotations = map[string]string{"test": "second"}
					switch conflict {
					case "size":
						second.Size = 1
					case "media type":
						second.MediaType = types.DockerManifestSchema2
						if shape != "images" {
							second.MediaType = types.DockerManifestList
						}
					}
					if shape == "different branches" {
						first, second = wrap(first), wrap(second)
					}
					if reversed {
						first, second = second, first
					}
					if err := lp.AppendDescriptor(first); err != nil {
						t.Fatal(err)
					}
					if err := lp.AppendDescriptor(second); err != nil {
						t.Fatal(err)
					}
					_, err = Open(t.Context(), "oci-dir:"+dir, "linux/amd64")
					if conflict == "none" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil || !strings.Contains(err.Error(), "conflicting size or media type") {
						// A smaller bad descriptor met first may be rejected on
						// its own read before the other branch is reached.
						if !(shape == "different branches" && conflict == "size" && reversed && err != nil && strings.Contains(err.Error(), "exceeds its declared size")) {
							t.Fatalf("Open = %v, want contradictory descriptor refusal", err)
						}
					}
				})
			}
		}
	}
}
