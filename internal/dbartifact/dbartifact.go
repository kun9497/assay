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

	// SourceRepo is this project's own repository, written into every artifact
	// as AnnotationSource. Hardcoded for the same reason dbcmd.DefaultRef is:
	// there is one assay, it publishes to one place, and deriving this from the
	// push target would be wrong anyway -- the artifact is `assay-db` and the
	// repository is `assay`.
	SourceRepo = "https://github.com/kun9497/assay"

	// Metadata lives in manifest annotations rather than the config blob,
	// because a client can read the manifest without downloading the
	// layer. A schema mismatch is the ordinary case for an out-of-date
	// binary, and finding out after a 60 MB download is the wrong order.
	// AnnotationSource is the OCI standard key for "the repository this came
	// from", and GHCR reads it to link a package to a repository. That linkage
	// is not cosmetic: a workflow's GITHUB_TOKEN can only touch packages linked
	// to its own repository, so an unlinked package makes the scheduled publish
	// fail with DENIED however its permissions are declared -- which is exactly
	// what happened on 2026-08-04 and 2026-08-05, after the first artifact was
	// bootstrapped by hand with a personal token and therefore linked to
	// nothing.
	//
	// Written on every push rather than only the first, because the linkage is
	// a property of the package that a re-bootstrap under a new schema tag has
	// to re-establish.
	AnnotationSource = "org.opencontainers.image.source"

	AnnotationSchema   = "dev.assay.schema-version"
	AnnotationBuiltAt  = "dev.assay.built-at"
	AnnotationDataAsOf = "dev.assay.data-as-of"
	// AnnotationDataAsOfSource names the provider whose DataAsOf set the
	// floor above — attribution, not data: absent on artifacts published
	// before it existed, and a reader treats absence as "unattributed", never
	// as an error (the D12 date alone is still the promise).
	AnnotationDataAsOfSource = "dev.assay.data-as-of-source"
	// RatingsSince and RatingCount exist so a publisher can tell, from the
	// manifest alone, whether the artifact it is about to push covers LESS
	// than the one already published. Reading that from the layer would
	// mean downloading the database to decide whether to overwrite it.
	//
	// An absent RatingsSince means unbounded -- the whole feed -- which is
	// broader than any date. That is also what a database built before
	// these annotated looks like, so the guard treats a missing value as
	// "unknown" rather than "unbounded"; see dbcmd.Push.
	AnnotationRatingsSince = "dev.assay.ratings-since"
	AnnotationRatingCount  = "dev.assay.rating-count"
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
	// DataAsOfSource is which provider's Provenance set DataAsOf ("amazon").
	// Empty on artifacts published before the annotation existed.
	DataAsOfSource string
	// RatingsSince is the narrowest bound across rating sources: the
	// latest date any of them was limited to. Zero WITH RatingsSinceKnown
	// means no rating source was bounded at all.
	RatingsSince time.Time
	// RatingsSinceKnown separates "unbounded" from "not recorded".
	//
	// Collapsing them was a real bug, caught by pushing to the live
	// registry: a database built before CoversSince existed has a zero
	// bound, and publishing that as "the whole feed" made a 30-day
	// artifact claim complete coverage in its own manifest. An artifact
	// that cannot substantiate a coverage claim must make none.
	RatingsSinceKnown bool
	// RatingCount is how many ratings the database holds. Zero is a real,
	// publishable value -- a database with no rating source is legitimate
	// -- but publishing zero OVER a non-zero artifact destroys the seed
	// every later delta builds on.
	RatingCount int
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
	anns := map[string]string{
		AnnotationSchema:      strconv.Itoa(m.SchemaVersion),
		AnnotationSource:      SourceRepo,
		AnnotationBuiltAt:     m.BuiltAt.UTC().Format(time.RFC3339),
		AnnotationDataAsOf:    m.DataAsOf.UTC().Format(time.RFC3339),
		AnnotationRatingCount: strconv.Itoa(m.RatingCount),
	}
	// Attribution rides only when known: an empty value would be
	// indistinguishable from a malformed one to a reader, and the field is
	// optional by design (see its constant's comment).
	if m.DataAsOfSource != "" {
		anns[AnnotationDataAsOfSource] = m.DataAsOfSource
	}
	// Omitted rather than guessed when the database does not record it.
	if m.RatingsSinceKnown {
		anns[AnnotationRatingsSince] = ratingsSinceValue(m.RatingsSince)
	}
	annotated := mutate.Annotations(img, anns)
	out, ok := annotated.(v1.Image)
	if !ok {
		return nil, fmt.Errorf("annotating produced %T, not a v1.Image", annotated)
	}
	return out, nil
}

// unboundedRatings is what AnnotationRatingsSince carries when no rating
// source was limited. A word rather than an empty string, because an empty
// annotation is indistinguishable from an absent one, and "unbounded" and
// "this artifact predates the annotation" must not compare equal -- one is
// the broadest possible coverage, the other is unknown.
const unboundedRatings = "unbounded"

func ratingsSinceValue(t time.Time) string {
	if t.IsZero() {
		return unboundedRatings
	}
	return t.UTC().Format(time.RFC3339)
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
	m.DataAsOfSource = mf.Annotations[AnnotationDataAsOfSource]
	if raw, ok := mf.Annotations[AnnotationRatingsSince]; ok {
		if raw == unboundedRatings {
			m.RatingsSinceKnown = true
		} else if t, err := time.Parse(time.RFC3339, raw); err == nil {
			m.RatingsSince, m.RatingsSinceKnown = t, true
		}
	}
	if n, err := strconv.Atoi(mf.Annotations[AnnotationRatingCount]); err == nil {
		m.RatingCount = n
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
