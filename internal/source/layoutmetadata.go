package source

import (
	"context"
	"encoding/json"
	"errors"
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
	ctx         context.Context
	openBlob    func(v1.Hash) (io.ReadCloser, error)
	manifest    v1.IndexManifest
	descriptors map[v1.Hash]layoutDescriptor
}

type layoutDescriptor struct {
	size      int64
	mediaType types.MediaType
}

func openLayoutIndex(ctx context.Context, dir string) (*boundedLayoutIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	filename := filepath.Join(dir, "index.json")
	// A link is followed, as the library's own read of this file did and as
	// blob reads still do: a layout in a symlink tree is a layout. Every rule
	// below is then held against what the link reaches. Lstat is consulted
	// only to say what was refused.
	link := ""
	if own, err := os.Lstat(filename); err == nil && own.Mode()&os.ModeSymlink != 0 {
		link = "a symbolic link to "
	}
	info, err := os.Stat(filename)
	if err != nil {
		if link != "" {
			return nil, fmt.Errorf("layout index.json is a symbolic link whose target cannot be read: %w", err)
		}
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("layout index.json is %s%s, not a regular file", link, layoutFileKind(info.Mode()))
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
	raw, err := readLayoutMetadata(ctx, f, maxArchiveManifestBytes)
	if errors.Is(err, errLayoutMetadataTooLong) {
		// The file grew past the stat above while it was being read.
		return nil, fmt.Errorf("layout index.json exceeds the %s limit (D112)", formatBytes(maxArchiveManifestBytes))
	}
	if err != nil {
		return nil, err
	}
	var manifest v1.IndexManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	idx := &boundedLayoutIndex{ctx: ctx, openBlob: layout.Path(dir).Blob, manifest: manifest}
	if err := idx.rememberDescriptors(); err != nil {
		return nil, err
	}
	return idx, nil
}

// A hash names one byte sequence and one type, even when several platform
// declarations refer to it. Validate the whole index before first-match
// lookup or visit-once can hide a contradictory later declaration. The map
// is shared with nested indexes so another branch cannot repeat the bypass.
//
// The refusal names the digest and both declarations: an index may list
// thousands of descriptors, and the pair can sit in two different files.
func (idx *boundedLayoutIndex) rememberDescriptors() error {
	if len(idx.manifest.Manifests) > maxIndexDescriptors {
		return fmt.Errorf("layout exceeds the %d-descriptor image index limit", maxIndexDescriptors)
	}
	if idx.descriptors == nil {
		idx.descriptors = make(map[v1.Hash]layoutDescriptor)
	}
	for _, d := range idx.manifest.Manifests {
		value := layoutDescriptor{size: d.Size, mediaType: d.MediaType}
		if old, ok := idx.descriptors[d.Digest]; ok && old != value {
			return fmt.Errorf("layout indexes declare %s twice and disagree: size %d, media type %q against size %d, media type %q",
				d.Digest, old.size, old.mediaType, value.size, value.mediaType)
		}
		idx.descriptors[d.Digest] = value
	}
	return nil
}

// layoutFileKind says what a path that is not a regular file is, so the
// refusal does not leave the reader to find out.
func layoutFileKind(m os.FileMode) string {
	switch {
	case m.IsDir():
		return "a directory"
	case m&os.ModeDevice != 0:
		return "a device"
	case m&os.ModeNamedPipe != 0:
		return "a named pipe"
	case m&os.ModeSocket != 0:
		return "a socket"
	}
	return "an irregular file (" + m.Type().String() + ")"
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
	raw, err := readLayoutMetadata(idx.ctx, r, d.Size)
	if errors.Is(err, errLayoutMetadataTooLong) {
		// A mismatch, not a limit: the bound here is the descriptor's own
		// size, which the image spec requires, and an omitted one decodes to
		// 0. Calling that a "0 bytes limit" named a limit nobody set.
		return nil, fmt.Errorf("layout metadata %s is longer than its descriptor declares (size %d)", d.Digest, d.Size)
	}
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

// errLayoutMetadataTooLong is readLayoutMetadata's over-read. Each caller
// words it, because only the caller knows whether its bound was the 100 MiB
// limit or a descriptor's declared size.
var errLayoutMetadataTooLong = errors.New("layout metadata is longer than its bound")

// The extra byte distinguishes an exact-size blob from an understated one.
// Stat is only an early refusal for index.json; this read is the memory bound
// even if the same open file grows after its stat, or an opener has no Stat.
func readLayoutMetadata(ctx context.Context, r io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(&layoutContextReader{ctx: ctx, Reader: r}, limit+1))
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errLayoutMetadataTooLong
	}
	return raw, nil
}

// layoutReadError marks a failure of this file's own reads on the way out of
// an index walk. The walk returns an index's error as it came, and a registry
// index's must stay that way to be recognised as a refusal (D118), so load
// cannot wrap everything the walk returns -- half of it names the target
// already. The mark lets nameLayoutError find the half that does not. The
// text is the cause's, unchanged.
type layoutReadError struct{ err error }

func (e *layoutReadError) Error() string { return e.err.Error() }
func (e *layoutReadError) Unwrap() error { return e.err }

// nameLayoutError gives a layout read failure the target it was read from.
// Only an error that is one at the top: a walk error that wraps one (a
// skipped entry's) was composed around the target already.
func nameLayoutError(ref string, err error) error {
	if _, ok := err.(*layoutReadError); ok {
		return fmt.Errorf("read oci layout %s: %w", ref, err)
	}
	return err
}

func (idx *boundedLayoutIndex) Image(h v1.Hash) (v1.Image, error) {
	img, err := idx.image(h)
	if err != nil {
		return nil, &layoutReadError{err}
	}
	return img, nil
}

func (idx *boundedLayoutIndex) ImageIndex(h v1.Hash) (indexReader, error) {
	child, err := idx.imageIndex(h)
	if err != nil {
		return nil, &layoutReadError{err}
	}
	return child, nil
}

func (idx *boundedLayoutIndex) image(h v1.Hash) (v1.Image, error) {
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

func (idx *boundedLayoutIndex) imageIndex(h v1.Hash) (*boundedLayoutIndex, error) {
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
	child := &boundedLayoutIndex{ctx: idx.ctx, openBlob: idx.openBlob, manifest: manifest, descriptors: idx.descriptors}
	if err := child.rememberDescriptors(); err != nil {
		return nil, err
	}
	return child, nil
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
