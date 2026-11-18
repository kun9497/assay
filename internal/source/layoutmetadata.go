package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// The library reads local manifests and indexes whole, without the limit it
// applies to registry responses. Snapshot each one under the same 100 MiB
// ceiling as registry and Docker archive manifests, before JSON decoding.
// A checked file is never reopened by the library to construct the image.
type boundedLayoutIndex struct {
	ctx      context.Context
	openBlob func(v1.Hash) (io.ReadCloser, error)
	manifest v1.IndexManifest
}

func openLayoutIndex(ctx context.Context, dir string) (*boundedLayoutIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	filename := filepath.Join(dir, "index.json")
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("layout index.json is not a regular file")
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("layout index.json changed while opening")
	}
	if opened.Size() > maxArchiveManifestBytes {
		return nil, fmt.Errorf("layout index.json exceeds the %s limit (D112)", formatBytes(maxArchiveManifestBytes))
	}
	raw, err := readLayoutMetadata(ctx, f, "index.json", maxArchiveManifestBytes)
	if err != nil {
		return nil, err
	}
	var manifest v1.IndexManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	return &boundedLayoutIndex{ctx: ctx, openBlob: layout.Path(dir).Blob, manifest: manifest}, nil
}

func (idx *boundedLayoutIndex) IndexManifest() (*v1.IndexManifest, error) {
	return &idx.manifest, idx.ctx.Err()
}

func (idx *boundedLayoutIndex) descriptor(h v1.Hash) (v1.Descriptor, error) {
	for _, d := range idx.manifest.Manifests {
		if d.Digest == h {
			return d, nil
		}
	}
	return v1.Descriptor{}, fmt.Errorf("could not find descriptor in index: %s", h)
}

func (idx *boundedLayoutIndex) metadata(d v1.Descriptor) ([]byte, error) {
	if err := idx.ctx.Err(); err != nil {
		return nil, err
	}
	if d.Size < 0 || d.Size > maxArchiveManifestBytes {
		return nil, fmt.Errorf("layout metadata %s declares %d bytes, outside the 0 to %s limit (D112)", d.Digest, d.Size, formatBytes(maxArchiveManifestBytes))
	}
	r, err := idx.openBlob(d.Digest)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	raw, err := readLayoutMetadata(idx.ctx, r, d.Digest.String(), d.Size)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != d.Size {
		return nil, fmt.Errorf("layout metadata %s contains %d bytes, descriptor declares %d", d.Digest, len(raw), d.Size)
	}
	if err := checkManifestDigest(raw, d.Digest); err != nil {
		return nil, err
	}
	return raw, nil
}

// The extra byte distinguishes an exact-size blob from an understated one.
// Stat is only an early refusal for index.json; this read is the memory bound
// even if the same open file grows after its stat, or an opener has no Stat.
func readLayoutMetadata(ctx context.Context, r io.Reader, name string, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(&layoutContextReader{ctx: ctx, Reader: r}, limit+1))
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("layout metadata %s exceeds its declared size or %s limit (D112)", name, formatBytes(limit))
	}
	return raw, nil
}

func (idx *boundedLayoutIndex) Image(h v1.Hash) (v1.Image, error) {
	d, err := idx.descriptor(h)
	if err != nil {
		return nil, err
	}
	if d.MediaType != types.OCIManifestSchema1 && d.MediaType != types.DockerManifestSchema2 {
		return nil, fmt.Errorf("unexpected media type for %v: %s", h, d.MediaType)
	}
	raw, err := idx.metadata(d)
	if err != nil {
		return nil, err
	}
	var manifest v1.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	open := func(h v1.Hash) (io.ReadCloser, error) {
		if err := idx.ctx.Err(); err != nil {
			return nil, err
		}
		r, err := idx.openBlob(h)
		if err != nil {
			return nil, err
		}
		return &layoutContextReader{ctx: idx.ctx, Reader: r, Closer: r}, nil
	}
	img, err := partial.CompressedToImage(&layoutImageCore{raw: raw, manifest: manifest, mediaType: d.MediaType, openBlob: open})
	if err != nil {
		return nil, err
	}
	return layoutImage{Image: img, openBlob: open}, nil
}

func (idx *boundedLayoutIndex) ImageIndex(h v1.Hash) (indexReader, error) {
	d, err := idx.descriptor(h)
	if err != nil {
		return nil, err
	}
	if d.MediaType != types.OCIImageIndex && d.MediaType != types.DockerManifestList {
		return nil, fmt.Errorf("unexpected media type for %v: %s", h, d.MediaType)
	}
	raw, err := idx.metadata(d)
	if err != nil {
		return nil, err
	}
	var manifest v1.IndexManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	return &boundedLayoutIndex{ctx: idx.ctx, openBlob: idx.openBlob, manifest: manifest}, nil
}

// Only immutable, already-checked manifest bytes reach partial's image
// adapter. Its layer streams retain layout.Blob's regular-file checks and
// partial's gzip/zstd handling; the scan still verifies every diff ID (D123).
type layoutImageCore struct {
	raw       []byte
	manifest  v1.Manifest
	mediaType types.MediaType
	openBlob  func(v1.Hash) (io.ReadCloser, error)
}

func (img *layoutImageCore) MediaType() (types.MediaType, error) { return img.mediaType, nil }
func (img *layoutImageCore) RawManifest() ([]byte, error)        { return img.raw, nil }
func (img *layoutImageCore) RawConfigFile() ([]byte, error) {
	return readLayoutConfig(&img.manifest, img.openBlob)
}
func (img *layoutImageCore) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	if img.manifest.Config.Digest == h {
		return &layoutLayer{desc: img.manifest.Config, openBlob: img.openBlob}, nil
	}
	for _, d := range img.manifest.Layers {
		if d.Digest == h {
			return &layoutLayer{desc: d, openBlob: img.openBlob}, nil
		}
	}
	return nil, fmt.Errorf("could not find layer in image: %s", h)
}

type layoutLayer struct {
	desc     v1.Descriptor
	openBlob func(v1.Hash) (io.ReadCloser, error)
}

func (l *layoutLayer) Digest() (v1.Hash, error)            { return l.desc.Digest, nil }
func (l *layoutLayer) Size() (int64, error)                { return l.desc.Size, nil }
func (l *layoutLayer) MediaType() (types.MediaType, error) { return l.desc.MediaType, nil }
func (l *layoutLayer) Compressed() (io.ReadCloser, error)  { return l.openBlob(l.desc.Digest) }

type layoutContextReader struct {
	ctx context.Context
	io.Reader
	io.Closer
}

func (r *layoutContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}
