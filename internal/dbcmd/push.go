package dbcmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/store"
)

// Push publishes the database at dbPath to ref (D28). It is the builder's
// half of the slice: one machine spends the hours, everyone else pulls the
// result in seconds.
//
// The artifact's freshness comes from the database's own recorded
// provenance, never from the clock. Stamping time.Now() here would make
// every re-push of an old database look current, which is the exact
// failure D12 separates DataAsOf from BuiltAt to prevent.
func Push(ctx context.Context, dbPath, ref string, force bool, stdout, stderr io.Writer) int {
	if _, err := os.Stat(dbPath); err != nil {
		fmt.Fprintf(stderr, "error: no database at %s: %v\n", dbPath, err)
		fmt.Fprintln(stderr, "  build one first with `assay db build`")
		return 2
	}
	db, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: open database: %v\n", err)
		return 2
	}
	meta, err := db.Meta()
	if err != nil {
		db.Close()
		fmt.Fprintf(stderr, "error: read database metadata: %v\n", err)
		return 2
	}
	db.Close()

	incoming := dbartifact.Meta{
		SchemaVersion:     store.SchemaVersion,
		BuiltAt:           meta.BuiltAt,
		DataAsOf:          oldestDataAsOf(meta),
		RatingsSince:      ratingBound(meta),
		RatingsSinceKnown: ratingBoundKnown(meta),
		RatingCount:       totalRatings(meta),
	}
	img, err := dbartifact.Pack(dbPath, incoming)
	if err != nil {
		fmt.Fprintf(stderr, "error: pack database: %v\n", err)
		return 2
	}

	target, err := name.ParseReference(ref)
	if err != nil {
		fmt.Fprintf(stderr, "error: %q is not a valid reference: %v\n", ref, err)
		return 2
	}
	// Checked before writing, against the manifest only -- remote.Image is
	// lazy, so this costs one request rather than the published database.
	//
	// The failure it prevents is real and was going to happen: the daily
	// workflow seeds from this same tag and pushes back to it, so a full
	// build published while a delta run is in flight gets overwritten
	// minutes later by an artifact seeded from the OLD one. Seven hours of
	// coverage disappears, nothing errors, and db status keeps reporting
	// the narrower window truthfully -- it says what the artifact holds,
	// not that it used to hold more.
	if code := refuseCoverageRegression(ctx, target, incoming, force, stderr); code != 0 {
		return code
	}
	fmt.Fprintf(stderr, "pushing to %s…\n", target)
	if err := remote.Write(target, img,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		fmt.Fprintf(stderr, "error: push: %v\n", err)
		return 2
	}
	digest, err := img.Digest()
	if err != nil {
		fmt.Fprintf(stderr, "error: read digest: %v\n", err)
		return 2
	}
	// The digest goes to stdout because it is the result -- a caller
	// pinning this build in a manifest wants to capture it, and stream
	// discipline says a capturable result is not a diagnostic.
	fmt.Fprintf(stdout, "%s@%s\n", target.Context().Name(), digest)
	return 0
}

// oldestDataAsOf is "the oldest upstream wins" (D12), the same rule the NVD
// provider applies across its own pages: an artifact is only as fresh as its
// stalest component. Taking the newest would let one recently-synced
// provider vouch for a database whose other half is months old.
//
// Both provenance buckets are consulted, not just Providers: Ratings is
// where NVD's own DataAsOf lives, and --seed carries Ratings forward without
// touching Providers (D-seed rebuilds every advisory but layers ratings from
// the seed). A build on 2026-11-01 seeded from an August database and run
// without NVD_ENABLE has fresh Providers and three-month-old Ratings; taking
// only the former would publish DataAsOf = 2026-11-01 while every CVE first
// rated in September silently reads as unknown and stops tripping
// --fail-on. Folding Ratings into the same minimum is what this function's
// own "an artifact is only as fresh as its stalest component" already
// promises — it just was not keeping that promise for half of Meta.
func oldestDataAsOf(m store.Meta) time.Time {
	var oldest time.Time
	consider := func(p store.Provenance) {
		if p.DataAsOf.IsZero() {
			return
		}
		if oldest.IsZero() || p.DataAsOf.Before(oldest) {
			oldest = p.DataAsOf
		}
	}
	for _, p := range m.Providers {
		consider(p)
	}
	for _, p := range m.Ratings {
		consider(p)
	}
	return oldest
}

// narrowestRatingBound is the latest bound across rating sources, which is
// the one that limits the artifact. Zero means no rating source was bounded
// -- the whole feed -- and that is broader than any date, so it wins only
// if every source is unbounded.
func ratingBound(m store.Meta) time.Time {
	var narrowest time.Time
	for _, p := range m.Ratings {
		if p.CoversSince.IsZero() {
			continue
		}
		if narrowest.IsZero() || p.CoversSince.After(narrowest) {
			narrowest = p.CoversSince
		}
	}
	return narrowest
}

// totalRatings counts what the database actually holds, from the derived
// counts rather than any self-report (D20).
func totalRatings(m store.Meta) int {
	n := 0
	for _, c := range m.RatingCounts {
		n += c
	}
	return n
}

// refuseCoverageRegression stops a push that would publish less than what is
// already published. Returns 0 to proceed, 2 to stop.
//
// Absent or unreadable published metadata is not a regression: the tag may
// not exist yet (the first push), the registry may be unreachable, or the
// artifact may predate these annotations. None of those is evidence that
// coverage is shrinking, and refusing on them would make the guard fail
// closed against a first publish -- so it proceeds and says why.
func refuseCoverageRegression(ctx context.Context, target name.Reference, incoming dbartifact.Meta, force bool, stderr io.Writer) int {
	published, err := remote.Image(target,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		fmt.Fprintf(stderr, "no published artifact to compare against (%v); publishing\n", err)
		return 0
	}
	cur, err := dbartifact.MetaOf(published)
	if err != nil {
		fmt.Fprintf(stderr, "published artifact carries no readable metadata (%v); publishing\n", err)
		return 0
	}

	var why string
	switch {
	case incoming.RatingCount < cur.RatingCount:
		// Fewer, not merely none. The first version only refused zero, and
		// that hole was found by walking into it: a 2,903-rating artifact
		// replaced a 23,433-rating one on the live registry, during the very
		// run that was demonstrating this guard. Zero is the loudest case,
		// not the only one.
		//
		// A drop is not ambiguous in normal operation. A seeded build
		// carries the published ratings forward and adds to them, so the
		// count only ever grows; a smaller number means the seed was not
		// used, or covered less. Both are exactly what this refuses.
		why = fmt.Sprintf("the published artifact holds %d rating(s) and this one holds %d",
			cur.RatingCount, incoming.RatingCount)
	case !cur.RatingsSinceKnown || !incoming.RatingsSinceKnown:
		// One side does not record its coverage, so the dates cannot be
		// compared. The rating-count check above still applies.
		return 0
	case cur.RatingsSince.IsZero() && !incoming.RatingsSince.IsZero():
		why = fmt.Sprintf("the published artifact covers the whole feed and this one starts at %s",
			incoming.RatingsSince.UTC().Format("2006-01-02"))
	case !cur.RatingsSince.IsZero() && incoming.RatingsSince.After(cur.RatingsSince):
		why = fmt.Sprintf("the published artifact covers from %s and this one only from %s",
			cur.RatingsSince.UTC().Format("2006-01-02"), incoming.RatingsSince.UTC().Format("2006-01-02"))
	default:
		return 0
	}

	if force {
		fmt.Fprintf(stderr, "warning: %s; publishing anyway because --force was given\n", why)
		return 0
	}
	fmt.Fprintf(stderr, "error: this would narrow published coverage: %s\n", why)
	fmt.Fprintln(stderr, "  a narrower artifact becomes the seed every later build layers onto,")
	fmt.Fprintln(stderr, "  so what it drops is not recovered by the next run")
	fmt.Fprintln(stderr, "  pass --force if you mean to replace it")
	return 2
}

// ratingBoundKnown reports whether the bound above can be substantiated.
//
// A rating source that recorded a Window but no CoversSince predates that
// field, and its zero bound means "not recorded", not "unbounded". Publishing
// the difference as unbounded is how a 30-day artifact came to claim the
// whole feed in its own manifest — caught by pushing to the live registry,
// not by any test. An artifact that cannot substantiate a coverage claim
// makes none, and the guard treats a missing claim as uncomparable rather
// than as maximal.
func ratingBoundKnown(m store.Meta) bool {
	for _, p := range m.Ratings {
		if p.CoversSince.IsZero() && p.Window != "" {
			return false
		}
	}
	return true
}
