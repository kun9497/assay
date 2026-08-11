package dbcmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	// D29: enrichment is built locally and never published.
	//
	// KISA's site is all-rights-reserved with no 공공누리 mark. That does not
	// restrict SCANNING with the data; it restricts REDISTRIBUTING it, and
	// this function redistributes. So `db build` fills the enrichment bucket,
	// the lines below empty it, and `db update` therefore never delivers it —
	// anyone who wants the Korean text runs their own `db build`.
	//
	// REVERSING D29 IS DELETING THE stripEnrichment CALL BELOW (the seam over
	// store.StripEnrichment). Nothing else moves: the compaction that follows
	// it copies whatever is live at that point, so with the strip gone the
	// records simply come across. The data already lives in the same database
	// as everything else precisely so that publishing it, once the licence
	// question resolves, is a deletion rather than a restructure.
	//
	// Packed from a COPY, never from the live database. Stripping in place
	// would take the prose away from the one machine allowed to have it, and
	// would rewrite a file a concurrent scan may be reading.
	staged, cleanup, err := stagedCopy(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: stage database for publishing: %v\n", err)
		return 2
	}
	defer cleanup()
	if err := stripEnrichment(staged); err != nil {
		// Fatal, not a warning. Publishing an artifact whose enrichment could
		// not be removed is the licensing violation this guard exists to
		// prevent, and "we tried" is not a defence.
		fmt.Fprintf(stderr, "error: strip enrichment before publishing: %v\n", err)
		return 2
	}
	// The strip is not the whole of it, and believing it was is how the sixth
	// D29 bypass got this far. The staged copy is byte-identical to the live
	// database, so deleting the bucket only FREES the pages holding KISA's
	// prose — dbartifact.Pack reads the whole file, freed pages and all, and
	// `gunzip | strings` on the published layer recovers the Korean text
	// verbatim. Measured on this tree: 200 records stripped that way left 546
	// occurrences of them in the result.
	//
	// So the file that actually gets packed is built by copying the live data
	// OUT, into a file that never held a record to begin with. The order is
	// load-bearing: compacting before the strip would copy the records across
	// as live data.
	//
	// A second file in the same scratch directory rather than a rewrite of the
	// staged one, because compaction writes into a database it creates.
	packPath := filepath.Join(filepath.Dir(staged), "publishable.db")
	if err := compactInto(packPath, staged); err != nil {
		// Fatal for the same reason the strip's failure is: falling back to
		// the staged copy here would publish exactly the bytes this step
		// exists to leave behind.
		fmt.Fprintf(stderr, "error: compact database for publishing: %v\n", err)
		return 2
	}

	img, err := dbartifact.Pack(packPath, incoming)
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

// stripEnrichment is store.StripEnrichment, and the seam Push calls it
// through, so a test can force the failure branch below.
//
// It is a package variable for the same reason renameFn is one: the failure
// cannot be provoked with a fixture. The path handed to it was created by
// stagedCopy moments earlier, so making bbolt refuse to open it means racing
// the copy or corrupting a file mid-function. And this is an error path whose
// mis-handling is a licensing violation rather than a wrong number — a
// `return 2` downgraded to a warning publishes the unstripped copy — so
// leaving it unreachable by any test was not an option.
var stripEnrichment = store.StripEnrichment

// compactInto is store.CompactInto, and a seam for the same reason
// stripEnrichment is one: its failure cannot be provoked with a fixture (both
// paths it touches were created by this function moments earlier), and
// mis-handling it is the same licensing violation — a `return 2` downgraded
// to a warning would pack the staged copy, whose freed pages still hold every
// record the strip just "removed".
var compactInto = store.CompactInto

// stagedCopy copies the database to a scratch file the caller may modify
// freely, and returns the copy's path with a cleanup that removes the whole
// scratch directory.
//
// It exists so the D29 strip has somewhere to happen that is not the live
// database. A scratch DIRECTORY rather than a sibling temp file, matching how
// `db build --seed` stages its pull: the copy is not a database anyone should
// discover, it must not collide with the "<db>.tmp" name Update and Pull both
// use for a half-installed one, and the directory is also where the
// compaction writes the file that is actually packed.
//
// Streamed rather than read whole: dbartifact.Pack already holds the file and
// its gzip in memory, and a ~244 MB database does not need a third copy of
// itself alongside them.
func stagedCopy(dbPath string) (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "assay-push-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }
	src, err := os.Open(dbPath)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	defer src.Close()
	path = filepath.Join(dir, "vulnerability.db")
	dst, err := os.Create(path)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		cleanup()
		return "", nil, err
	}
	// Closed explicitly, not deferred: the copy is opened again immediately
	// (by StripEnrichment, which takes bbolt's exclusive lock), and on Windows
	// that fails outright while this handle is still open.
	if err := dst.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
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
//
// Meta.Enrichment is deliberately NOT consulted, and that is not the same
// oversight in a third place. Freshness describes what the artifact CARRIES,
// and the artifact carries no enrichment at all (D29 — it is stripped just
// below). A stale KISA fetch dragging the published DataAsOf backwards would
// make every puller believe the advisories they did receive are older than
// they are, on the strength of data they did not.
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
	case cur.RatingCount == 0:
		// A published artifact with NO ratings has no coverage window to
		// narrow, whatever its RatingsSince says. Zero means "no lower
		// bound", which reads as whole-feed coverage — and a build that never
		// ran the NVD provider records exactly that while covering nothing at
		// all. This is the same ambiguity RatingsSinceKnown was added for, one
		// field over, and it was found the same way: by walking into it. The
		// v8 artifact was bootstrapped by hand from a build without
		// NVD_ENABLE, and every nightly publish after it was refused for
		// narrowing a window the seed did not have.
		//
		// The rating-count check above still applies and is the one that
		// matters here: an incoming artifact cannot hold FEWER than zero, so
		// nothing is being let through that the count would have caught.
		return 0
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
// A rating source with CoversSinceKnown false predates that field, and its
// zero bound means "not recorded", not "unbounded". Publishing
// the difference as unbounded is how a 30-day artifact came to claim the
// whole feed in its own manifest — caught by pushing to the live registry,
// not by any test. An artifact that cannot substantiate a coverage claim
// makes none, and the guard treats a missing claim as uncomparable rather
// than as maximal.
func ratingBoundKnown(m store.Meta) bool {
	for _, p := range m.Ratings {
		if !p.CoversSinceKnown {
			return false
		}
	}
	return true
}
