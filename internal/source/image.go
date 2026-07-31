package source

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// TargetKind says whether a scan argument names an SBOM to read or an image to
// pull apart. It exists because `assay scan X` has to mean both, and the wrong
// guess produces an error about the wrong subject.
type TargetKind int

const (
	TargetSBOM TargetKind = iota
	TargetImage
)

// ClassifyTarget decides in a fixed order: an explicit scheme prefix, then an
// existing file, then a registry reference.
//
// The order is the point. Deciding "registry" first makes `assay scan
// ./alpine.cdx.json` try to pull a repository of that name, and the user is
// told about registries when their actual problem is a path. Deciding "file"
// first would make an explicit docker-archive: prefix unreachable.
func ClassifyTarget(ref string) TargetKind {
	if classify(ref) != kindRegistry {
		return TargetImage
	}
	if _, err := os.Stat(ref); err == nil {
		return TargetSBOM
	}
	return TargetImage
}

type kind int

const (
	kindRegistry kind = iota
	kindTarball
	kindLayout
)

// Schemes are matched against a fixed set rather than by splitting on the first
// colon. Registry references contain colons of their own — a tag
// (alpine:3.19), a digest (repo@sha256:…), and a host port
// (registry.example.com:5000/team/app) — so "everything before the first colon
// is a scheme" routes real images to the tarball loader.
const (
	schemeTarball = "docker-archive:"
	schemeLayout  = "oci-dir:"
)

func classify(ref string) kind {
	switch {
	case strings.HasPrefix(ref, schemeTarball):
		return kindTarball
	case strings.HasPrefix(ref, schemeLayout):
		return kindLayout
	}
	return kindRegistry
}

// Open resolves a target to its layers. A registry reference reaches the
// network; the other two never do (D14).
//
// The context is honoured on the registry path. go-containerregistry's default
// transport sets no overall deadline, so without one a black-holed registry
// hangs the scan with nothing to cancel it.
func Open(ctx context.Context, ref string) (*Image, error) {
	img, err := load(ctx, ref)
	if err != nil {
		return nil, err
	}
	return fromV1(img)
}

func load(ctx context.Context, ref string) (v1.Image, error) {
	// Errors below name `ref`, not the path trimmed out of it: a user who typed
	// docker-archive:x.tar should see that back, not a bare x.tar they never
	// wrote.
	switch classify(ref) {
	case kindTarball:
		p := strings.TrimPrefix(ref, schemeTarball)
		img, err := tarball.ImageFromPath(p, nil)
		if err != nil {
			return nil, fmt.Errorf("read docker archive %s: %w", ref, err)
		}
		return img, nil

	case kindLayout:
		p := strings.TrimPrefix(ref, schemeLayout)
		idx, err := layout.ImageIndexFromPath(p)
		if err != nil {
			return nil, fmt.Errorf("read oci layout %s: %w", ref, err)
		}
		return imageFromIndex(v1Index{idx}, p)

	default:
		r, err := name.ParseReference(ref)
		if err != nil {
			return nil, fmt.Errorf("parse reference %q: %w", ref, err)
		}
		// remote.Image defaults to linux/amd64 and never consults the host, so
		// on an arm64 machine `assay scan alpine:3.19` would quietly scan the
		// amd64 image: a full package list, just not the one that runs. The
		// platform is stated rather than defaulted.
		img, err := remote.Image(r,
			remote.WithContext(ctx),
			remote.WithPlatform(hostPlatform()),
		)
		if err != nil {
			return nil, fmt.Errorf("pull %s: %w", ref, err)
		}
		return img, nil
	}
}

// indexReader is the slice of v1.ImageIndex that platform selection needs.
// Narrowing it here keeps the test double to two methods, and v1.ImageIndex
// cannot be embedded in one anyway — it carries a method named ImageIndex,
// which an embedded field of that name shadows.
type indexReader interface {
	IndexManifest() (*v1.IndexManifest, error)
	Image(v1.Hash) (v1.Image, error)
	// ImageIndex returns indexReader rather than v1.ImageIndex so a test double
	// can satisfy it. Go has no covariant returns, so the real type is adapted
	// by v1Index below rather than used directly.
	ImageIndex(v1.Hash) (indexReader, error)
}

// hostPlatform is a variable so a test can ask for a platform this machine is
// not. Hard-coding runtime.GOARCH makes the "we forgot to state the platform"
// bug invisible on an amd64 host, because the library's default happens to be
// the right answer there — and amd64 is where it will be tested.
var hostPlatform = func() v1.Platform {
	return v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
}

// v1Index adapts go-containerregistry's index to indexReader, narrowing the
// recursive method's return type as it goes.
type v1Index struct{ idx v1.ImageIndex }

func (w v1Index) IndexManifest() (*v1.IndexManifest, error) { return w.idx.IndexManifest() }
func (w v1Index) Image(h v1.Hash) (v1.Image, error)         { return w.idx.Image(h) }
func (w v1Index) ImageIndex(h v1.Hash) (indexReader, error) {
	c, err := w.idx.ImageIndex(h)
	if err != nil {
		return nil, err
	}
	return v1Index{c}, nil
}

// imageFromIndex picks this host's platform out of a multi-platform index.
//
// Scanning the wrong architecture's image is a wrong answer that looks like a
// right one — it produces a full package list, just not the one that is
// running — so a miss is an error naming what was on offer, never a fallback
// to the first entry.
func imageFromIndex(idx indexReader, what string) (v1.Image, error) {
	img, offered, err := searchIndex(idx, what, 0)
	if err != nil {
		return nil, err
	}
	if img != nil {
		return img, nil
	}
	if len(offered) == 0 {
		return nil, fmt.Errorf("%s contains no image for any platform; wanted linux/%s",
			what, runtime.GOARCH)
	}
	return nil, fmt.Errorf("%s has no linux/%s image; it offers %s",
		what, runtime.GOARCH, strings.Join(offered, ", "))
}

// maxIndexDepth bounds nesting. `skopeo copy --all` writes an index whose
// children are themselves indexes, and a malformed one could cycle.
const maxIndexDepth = 4

// searchIndex walks an index, descending into nested ones, and returns the
// image for this host if it finds one along with the platforms it saw.
//
// Two shapes appear in real layouts and neither has a usable Platform on the
// descriptor: a nested index (a manifest-list export), and a single image whose
// descriptor carries only a ref-name annotation. Both used to fail with "it
// offers " and an empty list — an error naming nothing, which tells an operator
// only that something went wrong.
func searchIndex(idx indexReader, what string, depth int) (v1.Image, []string, error) {
	if depth >= maxIndexDepth {
		return nil, nil, fmt.Errorf("%s nests indexes more than %d deep", what, maxIndexDepth)
	}
	m, err := idx.IndexManifest()
	if err != nil {
		return nil, nil, err
	}

	var offered []string
	for _, d := range m.Manifests {
		if d.MediaType.IsIndex() {
			child, err := idx.ImageIndex(d.Digest)
			if err != nil {
				return nil, nil, err
			}
			img, childOffered, err := searchIndex(child, what, depth+1)
			if err != nil {
				return nil, nil, err
			}
			offered = append(offered, childOffered...)
			if img != nil {
				return img, offered, nil
			}
			continue
		}

		p := d.Platform
		if p == nil {
			// No platform on the descriptor. The image's own config still
			// carries one, so ask it rather than discarding the entry — a
			// single-image layout written by layout.Write lands here.
			img, err := idx.Image(d.Digest)
			if err != nil {
				continue
			}
			cf, err := img.ConfigFile()
			if err != nil {
				continue
			}
			if cf.OS == "linux" && cf.Architecture == runtime.GOARCH {
				return img, offered, nil
			}
			if cf.OS != "" && cf.Architecture != "" && cf.OS != "unknown" {
				offered = append(offered, cf.OS+"/"+cf.Architecture)
			}
			continue
		}
		// Attestation and SBOM manifests are carried in the same index with
		// platform unknown/unknown — alpine:3.19 has several among its 14.
		// They contain no filesystem, so selecting one yields an empty scan,
		// and listing them as options tells an operator nothing.
		if p.OS == "unknown" || p.Architecture == "unknown" {
			continue
		}
		offered = append(offered, p.OS+"/"+p.Architecture)
		if p.OS == "linux" && p.Architecture == runtime.GOARCH {
			img, err := idx.Image(d.Digest)
			return img, offered, err
		}
	}
	return nil, offered, nil
}

func fromV1(img v1.Image) (*Image, error) {
	ls, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("read layers: %w", err)
	}
	out := &Image{Layers: make([]Layer, 0, len(ls))}
	for _, l := range ls {
		// DiffID, not Digest: Digest is the compressed blob's digest and is a
		// different value for the same layer.
		d, err := l.DiffID()
		if err != nil {
			return nil, fmt.Errorf("read layer diff id: %w", err)
		}
		out.Layers = append(out.Layers, Layer{
			DiffID: d.String(),
			Open:   func() (io.ReadCloser, error) { return l.Uncompressed() },
		})
	}
	return out, nil
}
