package source

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// D123: a layer is checked against its diff id before anything read out of it
// counts.
//
// Measured 2026-10-20 (external review, re-measured): go-containerregistry
// verifies a registry blob's digest only on the Read that returns the blob's
// EOF, and readLayer stopped at the tar end-of-archive marker, which comes
// before it -- so the check never ran, and a layer served under a pinned
// digest with other bytes in it scanned clean under that digest, uncompressed,
// gzip or zstd, no padding needed. oci-dir and docker-archive are worse: the
// library never verifies their blobs at all, so draining alone could not
// cover them.
//
// The diff id is checked rather than the blob digest because it closes every
// path with one rule. It is the sha256 of the UNCOMPRESSED tar, listed in the
// image config, whose own digest the manifest names: a pinned registry
// manifest is verified by the library, and fromV1 checks the config against
// the manifest itself, so manifest -> config -> diff id -> these bytes is one
// unbroken chain. And it is what containerd checks when it unpacks a layer,
// so an image this rejects is one docker would not run either.
//
// The diff id has to come from the CONFIG. go-containerregistry's
// v1.Layer.DiffID() for an oci-dir or docker-archive layer hashes the layer's
// own bytes when the layer cannot say otherwise (measured: a forged layout
// blob reported the forged content's hash as its diff id), so checking the
// bytes against it checks them against themselves.

// LayerDigestError is a layer whose bytes are not the ones its diff id names.
// The scan stops with exit 2 (D11): the image read is not the image named, and
// a verdict about it would be a verdict about the wrong thing.
type LayerDigestError struct {
	DiffID string // what the image config says the layer is
	Got    string // what the bytes read hash to
}

func (e *LayerDigestError) Error() string {
	return fmt.Sprintf("layer %s content does not match: its uncompressed bytes hash to %s, "+
		"so the image read is not the image its digest names (D123)", e.DiffID, e.Got)
}

// verifyDiffID wraps a layer's uncompressed stream so that reading it to EOF
// either confirms it hashes to want or fails with a LayerDigestError on that
// final Read. Nothing is checked on Close: a reader closed early has not
// proved anything, and readLayer drains to EOF for exactly that reason.
func verifyDiffID(rc io.ReadCloser, want v1.Hash) (io.ReadCloser, error) {
	var h hash.Hash
	switch want.Algorithm {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		rc.Close()
		// Unverifiable is refused, not waved through: OCI names sha256 and
		// sha512, and a diff id in anything else cannot be checked here.
		return nil, fmt.Errorf("layer %s: diff id algorithm %q cannot be verified (D123)", want, want.Algorithm)
	}
	return &diffIDReader{rc: rc, h: h, want: want}, nil
}

type diffIDReader struct {
	rc   io.ReadCloser
	h    hash.Hash
	want v1.Hash
}

func (r *diffIDReader) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	r.h.Write(p[:n])
	if errors.Is(err, io.EOF) {
		got := v1.Hash{Algorithm: r.want.Algorithm, Hex: fmt.Sprintf("%x", r.h.Sum(nil))}
		if got != r.want {
			return n, &LayerDigestError{DiffID: r.want.String(), Got: got.String()}
		}
	}
	return n, err
}

func (r *diffIDReader) Close() error { return r.rc.Close() }

// drainLayer reads what is left of a layer stream after the tar reader has
// stopped at its end-of-archive marker, so the stream reaches EOF and every
// check that runs there runs: the diff id above, and on the registry path the
// library's own blob digest and size check and the compressor's trailer.
//
// ctx is checked between chunks, so a stream with an arbitrarily long tail
// after the archive end is bounded by --timeout like every other read (D112);
// the bytes are discarded, so they cost no memory and no MaxScanBytes budget.
func drainLayer(ctx context.Context, r io.Reader) error {
	buf := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := r.Read(buf)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// ConfigDigestError is an image config whose bytes are not the ones the
// manifest names -- the link above the diff ids, checked for the same reason.
type ConfigDigestError struct {
	Want, Got string
}

func (e *ConfigDigestError) Error() string {
	return fmt.Sprintf("image config does not match the manifest: the manifest names %s, its bytes hash to %s (D123)",
		e.Want, e.Got)
}

// configDiffIDs returns the diff ids the image config lists, after checking
// the config's bytes against the digest the manifest gives it.
func configDiffIDs(img v1.Image, layers int) ([]v1.Hash, error) {
	m, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	raw, err := img.RawConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if m.Config.Digest.Algorithm != "sha256" {
		return nil, fmt.Errorf("image config digest algorithm %q cannot be verified (D123)", m.Config.Digest.Algorithm)
	}
	if got := fmt.Sprintf("sha256:%x", sha256.Sum256(raw)); got != m.Config.Digest.String() {
		return nil, &ConfigDigestError{Want: m.Config.Digest.String(), Got: got}
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	ids := cf.RootFS.DiffIDs
	if len(ids) != layers {
		return nil, fmt.Errorf("image config lists %d diff ids for %d layers, so its layers cannot be verified (D123)",
			len(ids), layers)
	}
	return ids, nil
}
