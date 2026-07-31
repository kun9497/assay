package source

import (
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
func Open(ref string) (*Image, error) {
	img, err := load(ref)
	if err != nil {
		return nil, err
	}
	return fromV1(img)
}

func load(ref string) (v1.Image, error) {
	switch classify(ref) {
	case kindTarball:
		p := strings.TrimPrefix(ref, schemeTarball)
		img, err := tarball.ImageFromPath(p, nil)
		if err != nil {
			return nil, fmt.Errorf("read docker archive %s: %w", p, err)
		}
		return img, nil

	case kindLayout:
		p := strings.TrimPrefix(ref, schemeLayout)
		idx, err := layout.ImageIndexFromPath(p)
		if err != nil {
			return nil, fmt.Errorf("read oci layout %s: %w", p, err)
		}
		return imageFromIndex(idx, p)

	default:
		r, err := name.ParseReference(ref)
		if err != nil {
			return nil, fmt.Errorf("parse reference %q: %w", ref, err)
		}
		img, err := remote.Image(r)
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
}

// imageFromIndex picks this host's platform out of a multi-platform index.
//
// Scanning the wrong architecture's image is a wrong answer that looks like a
// right one — it produces a full package list, just not the one that is
// running — so a miss is an error naming what was on offer, never a fallback
// to the first entry.
func imageFromIndex(idx indexReader, what string) (v1.Image, error) {
	m, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	var offered []string
	for _, d := range m.Manifests {
		p := d.Platform
		if p == nil {
			continue
		}
		// Attestation and SBOM manifests are carried in the same index with
		// platform unknown/unknown — alpine:3.19 has several among its 14.
		// They contain no filesystem, so selecting one yields an empty scan.
		if p.OS == "unknown" || p.Architecture == "unknown" {
			continue
		}
		offered = append(offered, p.OS+"/"+p.Architecture)
		if p.OS == "linux" && p.Architecture == runtime.GOARCH {
			return idx.Image(d.Digest)
		}
	}
	return nil, fmt.Errorf("%s has no linux/%s image; it offers %s",
		what, runtime.GOARCH, strings.Join(offered, ", "))
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
