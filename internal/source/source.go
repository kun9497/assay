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

	// read is the bytes Files, FilesUnder, FilesNamed and FilesMatching have
	// copied out of this image so far, against MaxScanBytes (D112).
	//
	// It lives on the Image because the Image is the scan: scancmd opens one
	// per scan and every pass of that scan is a method on it, so the counter's
	// lifetime is exactly the bound's. A package-level counter would carry
	// one scan's total into the next in any process that runs two, and a
	// budget passed as a parameter would add an argument to all four methods
	// to carry what the receiver already does. The zero value is a fresh
	// budget, so an Image built by hand — every test fixture — starts at 0
	// like one from Open.
	//
	// Not safe for concurrent use, like the rest of a scan's reads: one scan
	// reads its image from one goroutine.
	read int64
}
