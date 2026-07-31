// Package source turns a scan target into the layers and metadata a cataloger
// needs. It is the only place that knows a target can be a registry reference,
// a tarball, or a directory; everything downstream sees the same Image.
package source

import "io"

// Layer is one filesystem layer, identified by its DIFF ID — the digest of the
// uncompressed tar, which is what an image config lists in rootfs.diff_ids.
//
// This is deliberately not the manifest's layer digest, which covers the
// COMPRESSED blob and is a different value: for alpine:3.19 the manifest says
// sha256:17a39c0ba978… while the diff ID is sha256:0b44b2151d78…. syft and
// grype report the diff ID, and slice 2a's fixture carries it, so using the
// other one would make every cross-tool comparison and every "which layer
// introduced this package" answer quietly wrong.
type Layer struct {
	DiffID string
	// Open returns the layer's uncompressed tar stream. It is a function rather
	// than a reader because layers are read at most once each, in reverse
	// order, and a registry layer should not be fetched until it is reached.
	Open func() (io.ReadCloser, error)
}

// Image is layers in the order the config lists them: base first.
//
// Callers resolving file contents must walk it in REVERSE, because a later
// layer wins and may delete what an earlier one installed. Files() does that;
// nothing else should iterate this slice directly.
type Image struct {
	Layers []Layer
}
