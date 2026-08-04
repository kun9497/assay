// Package dbartifact packs a built vulnerability database into an OCI image
// and unpacks it again. It is what makes a database something a builder
// publishes once rather than something every user spends seven hours
// rebuilding (D28).
//
// It knows nothing about registries, the CLI, or bolt. Packing is moving
// bytes: a Pack that understood the database format could not round-trip a
// file written by a newer schema, which is exactly the case a client needs
// to detect and refuse rather than misread.
package dbartifact

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	// MediaTypeLayer says the single layer is a gzipped bolt file. The
	// +gzip is not decorative: static.NewLayer stores bytes verbatim, so
	// whatever compression happens is done here and has to be declared.
	MediaTypeLayer = "application/vnd.assay.db.layer.v1+gzip"
	// MediaTypeConfig marks the manifest's config blob. OCI requires a
	// config descriptor even when there is nothing runtime-ish to say, and
	// a distinct type keeps this artifact from being mistaken for a
	// runnable image by anything that inspects it.
	MediaTypeConfig = "application/vnd.assay.db.config.v1+json"

	// Metadata lives in manifest annotations rather than the config blob,
	// because a client can read the manifest without downloading the
	// layer. A schema mismatch is the ordinary case for an out-of-date
	// binary, and finding out after a 60 MB download is the wrong order.
	AnnotationSchema   = "dev.assay.schema-version"
	AnnotationBuiltAt  = "dev.assay.built-at"
	AnnotationDataAsOf = "dev.assay.data-as-of"
)

// Meta is what a puller can learn before committing to the download.
type Meta struct {
	SchemaVersion int
	// BuiltAt is when this artifact was assembled; DataAsOf is when the
	// UPSTREAM data it holds was current. They are separate for the reason
	// D12 gives: a mirror serving a three-month-old snapshot fetched today
	// has a recent BuiltAt and an old DataAsOf, and judging freshness by
	// the former reports stale data as fresh.
	BuiltAt  time.Time
	DataAsOf time.Time
}

// Pack reads the database at dbPath and returns a single-layer OCI image.
func Pack(dbPath string, m Meta) (v1.Image, error) {
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, fmt.Errorf("read database: %w", err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, fmt.Errorf("compress database: %w", err)
	}
	// Closed explicitly rather than deferred: gzip writes its footer on
	// Close, and a deferred Close runs after buf has already been handed
	// to static.NewLayer -- producing a layer that is missing its last
	// bytes and fails to decompress only on the puller's machine.
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("compress database: %w", err)
	}

	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.MediaType(MediaTypeConfig))
	img, err = mutate.Append(img, mutate.Addendum{
		Layer:     static.NewLayer(buf.Bytes(), types.MediaType(MediaTypeLayer)),
		MediaType: types.MediaType(MediaTypeLayer),
	})
	if err != nil {
		return nil, fmt.Errorf("append database layer: %w", err)
	}
	annotated := mutate.Annotations(img, map[string]string{
		AnnotationSchema:   strconv.Itoa(m.SchemaVersion),
		AnnotationBuiltAt:  m.BuiltAt.UTC().Format(time.RFC3339),
		AnnotationDataAsOf: m.DataAsOf.UTC().Format(time.RFC3339),
	})
	out, ok := annotated.(v1.Image)
	if !ok {
		return nil, fmt.Errorf("annotating produced %T, not a v1.Image", annotated)
	}
	return out, nil
}

// MetaOf reads what Pack recorded, from the manifest alone.
func MetaOf(img v1.Image) (Meta, error) {
	mf, err := img.Manifest()
	if err != nil {
		return Meta{}, fmt.Errorf("read manifest: %w", err)
	}
	raw, ok := mf.Annotations[AnnotationSchema]
	if !ok {
		return Meta{}, fmt.Errorf("manifest has no %s annotation: this is not an assay database artifact", AnnotationSchema)
	}
	schema, err := strconv.Atoi(raw)
	if err != nil {
		return Meta{}, fmt.Errorf("%s is %q, not a number", AnnotationSchema, raw)
	}
	m := Meta{SchemaVersion: schema}
	// Timestamps are best-effort on read: a missing or malformed one is
	// reported as zero rather than failing the pull. The schema version is
	// the field correctness depends on; these two are for display, and
	// refusing a usable database because its BuiltAt was malformed would
	// trade a real capability for a cosmetic guarantee.
	if t, err := time.Parse(time.RFC3339, mf.Annotations[AnnotationBuiltAt]); err == nil {
		m.BuiltAt = t
	}
	if t, err := time.Parse(time.RFC3339, mf.Annotations[AnnotationDataAsOf]); err == nil {
		m.DataAsOf = t
	}
	return m, nil
}

// Unpack writes the database held by img to destPath.
func Unpack(img v1.Image, destPath string) error {
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("read layers: %w", err)
	}
	for _, l := range layers {
		mt, err := l.MediaType()
		if err != nil {
			return fmt.Errorf("read layer media type: %w", err)
		}
		if string(mt) != MediaTypeLayer {
			continue
		}
		rc, err := l.Compressed()
		if err != nil {
			return fmt.Errorf("open layer: %w", err)
		}
		defer rc.Close()
		zr, err := gzip.NewReader(rc)
		if err != nil {
			return fmt.Errorf("decompress database: %w", err)
		}
		defer zr.Close()
		f, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("create %s: %w", destPath, err)
		}
		defer f.Close()
		if _, err := io.Copy(f, zr); err != nil {
			return fmt.Errorf("write database: %w", err)
		}
		return f.Close()
	}
	return fmt.Errorf("no layer of type %s: this is not an assay database artifact", MediaTypeLayer)
}
