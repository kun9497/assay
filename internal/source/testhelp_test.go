package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

type fakeLayer struct {
	diff string
	body string
}

func (f fakeLayer) Digest() (v1.Hash, error) { return v1.NewHash("sha256:" + strings.Repeat("0", 64)) }
func (f fakeLayer) DiffID() (v1.Hash, error) {
	return v1.Hash{Algorithm: "sha256", Hex: strings.TrimPrefix(f.diff, "sha256:")}, nil
}
func (f fakeLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(f.body)), nil
}
func (f fakeLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(f.body)), nil
}
func (f fakeLayer) Size() (int64, error)                { return int64(len(f.body)), nil }
func (f fakeLayer) MediaType() (types.MediaType, error) { return types.OCILayer, nil }

type fakeImage struct {
	v1.Image // embedded as an interface: only what fromV1 reads is implemented
	layers   []fakeLayer
}

// The config and manifest fromV1 checks before trusting a diff id (D123):
// the config lists each layer's diff field, and the manifest names the
// config's real digest, so the chain is consistent and only a layer's own
// bytes can break it.
func (f fakeImage) ConfigFile() (*v1.ConfigFile, error) {
	cf := &v1.ConfigFile{RootFS: v1.RootFS{Type: "layers"}}
	for _, l := range f.layers {
		h, err := v1.NewHash(l.diff)
		if err != nil {
			return nil, err
		}
		cf.RootFS.DiffIDs = append(cf.RootFS.DiffIDs, h)
	}
	return cf, nil
}

func (f fakeImage) RawConfigFile() ([]byte, error) {
	cf, err := f.ConfigFile()
	if err != nil {
		return nil, err
	}
	return json.Marshal(cf)
}

func (f fakeImage) Manifest() (*v1.Manifest, error) {
	raw, err := f.RawConfigFile()
	if err != nil {
		return nil, err
	}
	d, _, err := v1.SHA256(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return &v1.Manifest{Config: v1.Descriptor{Digest: d}}, nil
}

// sha256Of is the real diff id of body, for fixtures whose layers are read to
// the end and so must hash to what their config says.
func sha256Of(body string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(body)))
}

func (f fakeImage) Layers() ([]v1.Layer, error) {
	out := make([]v1.Layer, 0, len(f.layers))
	for _, l := range f.layers {
		out = append(out, l)
	}
	return out, nil
}

// Implements indexReader, not v1.ImageIndex: that interface has a method named
// ImageIndex, so an embedded field of the same name shadows it.
type fakeIndex struct {
	platforms  []string             // descriptor platforms, in order
	noPlatform []string             // descriptors with no platform: hex -> config os/arch
	children   map[string]fakeIndex // hex -> nested index
	images     map[string]v1.Image  // hex -> image, for the no-platform path
	imageErrs  map[string]error     // hex -> what Image answers instead
}

func (f fakeIndex) Image(h v1.Hash) (v1.Image, error) {
	if err, ok := f.imageErrs[h.Hex]; ok {
		return nil, err
	}
	if img, ok := f.images[h.Hex]; ok {
		return img, nil
	}
	return fakeImage{}, nil
}

func (f fakeIndex) ImageIndex(h v1.Hash) (indexReader, error) {
	if child, ok := f.children[h.Hex]; ok {
		return child, nil
	}
	return nil, fmt.Errorf("no such index %s", h)
}

func (f fakeIndex) IndexManifest() (*v1.IndexManifest, error) {
	m := &v1.IndexManifest{}
	for _, p := range f.platforms {
		os_, arch, _ := strings.Cut(p, "/")
		m.Manifests = append(m.Manifests, v1.Descriptor{
			Platform: &v1.Platform{OS: os_, Architecture: arch},
		})
	}
	for _, hex := range f.noPlatform {
		m.Manifests = append(m.Manifests, v1.Descriptor{
			MediaType: types.OCIManifestSchema1,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: hex},
		})
	}
	for hex := range f.children {
		m.Manifests = append(m.Manifests, v1.Descriptor{
			MediaType: types.OCIImageIndex,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: hex},
		})
	}
	return m, nil
}

// configImage answers ConfigFile, which is how a descriptor with no platform
// still reveals what it is — or fails to, when err is set.
type configImage struct {
	v1.Image
	os, arch, variant string
	err               error
}

func (c configImage) ConfigFile() (*v1.ConfigFile, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &v1.ConfigFile{OS: c.os, Architecture: c.arch, Variant: c.variant}, nil
}
