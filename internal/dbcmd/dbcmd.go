// Package dbcmd implements every `assay db` subcommand: `db build` (Update
// rebuilds from the providers -- the name predates D28 and now undersells
// what it does), `db update` (Pull, downloads the published artifact),
// `db status`, `db push` (publishes an artifact) and `db ref`.
package dbcmd

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/provider"
	"github.com/kun9497/assay/internal/store"
)

// Update rebuilds the database from every provider, then runs every
// annotator (D27) — an authority that rates a CVE rather than naming an
// affected package — writing its opinions through PutRating. It builds into a
// temporary file and renames over the live database, so a concurrent scan
// never observes a partial write.
//
// Annotators run after the advisory providers, matching the order the brief
// describes, but nothing about the result depends on it: ratings are keyed on
// CVE in their own bucket, entirely independent of which advisories Put has
// already written, so swapping the two loops produces an identical database
// (verified: internal/dbcmd's own mutation check swaps them and the suite
// stays green). The order is kept as the stated, documented contract anyway,
// since a future annotator is not guaranteed to share that independence.
//
// seedPath, when non-empty, names a previously built database (typically
// pulled from a published artifact) whose RATINGS bucket only is copied into
// this build, after the providers run and before the annotators do. Ratings
// only, and deliberately so: advisories are rebuilt from the providers above
// regardless of seedPath, because nothing here removes a record no provider
// re-emitted, and a seeded advisory upstream has since withdrawn (D16) would
// be a false positive with no expiry. Ratings have no such failure — NVD
// does not delete CVEs, a revised score changes lastModified so the next
// delta overwrites it, and a rating for a CVE no advisory matches is
// unreachable (Matcher.annotate only asks about identifiers a finding
// already carries) — which is what makes copying them forward sound where
// copying advisories forward would not be. This is the seven-hour half a
// six-hour scheduled build cannot otherwise afford.
//
// Ratings have no such failure — NVD does not delete CVEs, a revised score
// changes lastModified so the next delta overwrites it, and a rating for a
// CVE no advisory matches is unreachable (Matcher.annotate only asks about
// identifiers a finding already carries) — which is what makes copying them
// forward sound where copying advisories forward would not be. That
// soundness assumes the rating is a FACT fixed by a past scoring event,
// which is what NVD's CVSS vector, KISA's grading and every OSV record's
// severity all are. EPSS and KEV are the exception (D86, see
// perishableRatingSources below): an EPSS score is a daily-rescored
// probability with no "revised score" concept — there is only today's
// number — and a KEV catalog entry can be REMOVED, something a carry-forward
// has no way to notice since nothing here re-reads CISA's current list. Both
// are excluded from the record-by-record ratings copy a few paragraphs down
// and re-fetched fresh by their own annotator every build (EPSS_ENABLE/
// KEV_ENABLE default ON, main.go).
//
// NOT excluded from ratingsOnly's own copy just below, which is a whole-FILE
// copy rather than a record-by-record one and so has no per-record hook to
// exclude anything at. In the ordinary case that is harmless: EPSS_ENABLE
// and KEV_ENABLE default ON, so their annotators re-run and overwrite every
// carried-forward row with a fresh fetch regardless. It stops being
// harmless only if a `--ratings-only` build ALSO sets EPSS_ENABLE=0 or
// KEV_ENABLE=0 — a build asking to re-rate with NVD alone would then still
// carry the seed's stale EPSS/KEV rows forward verbatim. Narrow enough
// (--ratings-only is D65's own backfill-only flag) that it is recorded here
// rather than fixed: closing it needs bucket-level surgery on the copied
// file, not a filter on a stream this path never reads record by record.
//
// seedRef is what every message about the seed NAMES it as, instead of
// seedPath. The CLI's `db build --seed <ref>` pulls the reference to a
// throwaway scratch file before calling Update (Update itself only ever
// reads a local path), so seedPath there is something like
// "/tmp/assay-seed-183739/seed.db" -- meaningless in an archived CI log,
// and useless for identifying which published artifact was actually
// carried forward. Empty falls back to seedPath itself, which is what
// every direct caller in this package's own tests passes as a real,
// already-meaningful path.
//
// enrichers run last and are the one source kind whose failure does NOT fail
// the build; see the loop itself for why that asymmetry is deliberate. What
// they write never leaves this machine — `db push` strips the enrichment
// bucket from the copy it publishes (D29).
//
// ratingsOnly (D66) skips the provider loop entirely and carries the seed's
// advisories forward as a FILE COPY rather than a record-by-record one: the
// seed's own file becomes this build's tmp file directly, and only the
// annotators below still run against it. It exists to make a D65 backfill
// slice affordable — every other build rebuilds OSV (~54 minutes) and Red
// Hat (~21 minutes) regardless of what changed, and a slice's whole point is
// the NVD window alone. It requires seedPath (there is nothing to carry
// forward without one) and at least one configured annotator (otherwise the
// build changes nothing) — both refused at the very top of the function,
// before anything touches disk, same D60 class as the empty-artifact
// bootstrap incident this project has already paid for once.
//
// The carried advisories' provenance is the seed's, not this run's: unlike
// the ratings-only-copy path a few paragraphs up (which rebuilds advisories
// from providers every time and so reports THIS run's fetch), a
// ratings-only build never fetched an advisory at all, so `db status` must
// report the freshness the seed actually had.
func Update(ctx context.Context, dbPath, seedPath, seedRef string, ratingsOnly bool, providers []provider.Provider, annotators []provider.Annotator, enrichers []provider.Enricher, eolSource provider.EOLSource, stdout, stderr io.Writer) int {
	// Both refusals are the D60 class: an empty-advisory database published
	// over a real one, or a build that changes nothing arriving as success.
	// Checked first, before MkdirAll or anything else touches disk — a
	// ratings-only invocation that cannot proceed must fail exactly as fast
	// as a normal one that never got as far as a network call.
	if ratingsOnly {
		if seedPath == "" {
			fmt.Fprintln(stderr, "error: --ratings-only requires --seed <ref>: without a seed "+
				"there are no advisories at all, and an empty-advisory database published over "+
				"a real one is exactly the D60 bootstrap incident again")
			return 2
		}
		// No separate "did this build produce any advisories" guard exists in
		// Update today for the non-ratings-only path to worry about
		// misfiring here — the only place that matters is the final "database
		// updated: N advisories" line, and that total already sums
		// meta.Providers, which a ratings-only build populates from the
		// seed's own Provenance (see below) rather than from an emit count.
		if len(annotators) == 0 {
			fmt.Fprintln(stderr, "error: --ratings-only with no rating annotator configured "+
				"would change nothing from the seed — enable one (e.g. NVD_ENABLE=1) or drop the flag")
			return 2
		}
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "error: create database directory: %v\n", err)
		return 2
	}
	tmp := dbPath + ".tmp"
	_ = os.Remove(tmp)

	// What every message about the seed calls it, ratings-only or not — see
	// seedRef's own doc comment above for why (a throwaway scratch path is
	// meaningless in an archived CI log).
	label := seedPath
	if seedRef != "" {
		label = seedRef
	}

	var seedMeta store.Meta
	if ratingsOnly {
		// Read BEFORE the copy below and before the annotators run: this is
		// what supplies meta.Providers verbatim and meta.Ratings' starting
		// point a few lines down.
		sm, err := readSeedMeta(seedPath)
		if err != nil {
			fmt.Fprintf(stderr, "error: read seed %s: %v\n", label, err)
			return 2
		}
		seedMeta = sm
		fmt.Fprintf(stderr, "advisories carried from seed %s: this build re-rates, it does not re-fetch\n", label)
		// D66: a file copy, not a record copy. The seed's advisories are
		// wanted verbatim — buckets, index and all — so there is nothing to
		// decide record by record the way the ratings-copy block below does
		// for a normal seeded build.
		if err := copyFile(seedPath, tmp); err != nil {
			os.Remove(tmp)
			fmt.Fprintf(stderr, "error: copy seed %s: %v\n", label, err)
			return 2
		}
	}

	// store.Create on a path that already holds a complete database (the
	// copy just made, for a ratings-only build) opens it read-write and only
	// ensures its buckets exist — it does not wipe (internal/store/bolt.go,
	// Create's own doc comment). On every other build tmp does not exist
	// yet, and this is the ordinary from-empty path it always was.
	w, err := store.Create(tmp)
	if err != nil {
		// bolt.Open can create the file before a later step fails, so clean up
		// here too rather than relying on the next run to sweep it.
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: create database: %v\n", err)
		return 2
	}

	meta := store.Meta{
		BuiltAt:    time.Now().UTC(),
		Providers:  map[string]store.Provenance{},
		Ratings:    map[string]store.Provenance{},
		Enrichment: map[string]store.Provenance{},
	}
	if ratingsOnly {
		// The advisories ARE the seed's, so their provenance must be too
		// (D66) — SetMeta derives Ecosystems from this map (D20), and a scan
		// must see the same coverage `db status` showed against the seed,
		// not an empty one because no provider ran this time.
		maps.Copy(meta.Providers, seedMeta.Providers)
		// The starting point mergeRatingCoverage builds on in the annotator
		// loop below, exactly like the existing ratings-copy block: an
		// annotator that does not run this time keeps the seed's window, one
		// that does run merges with it instead of replacing it.
		maps.Copy(meta.Ratings, seedMeta.Ratings)
	}

	// D56. Which stage a build spends its time in is not guessable from the
	// outside, and it stopped being an idle question when the publish job
	// went from 29 minutes to 85 after Ubuntu landed — one run was cancelled
	// at the 120-minute timeout with no way to say which provider to blame.
	//
	// Recorded for FAILED stages too. A provider that died after 40 minutes
	// is the most useful timing in the run and the one a summary printed
	// only on success would always be missing.
	buildStarted := time.Now()
	var timings []stageTiming
	// D66: providers do not run at all in a ratings-only build — the seed's
	// advisories, already sitting in tmp from the file copy above, are what
	// this build carries forward.
	if !ratingsOnly {
		for _, p := range providers {
			fmt.Fprintf(stderr, "fetching %s…\n", p.Name())
			started := time.Now()
			// D56. The store write is timed SEPARATELY from the fetch, because a
			// provider's total says nothing about which half to fix and the two
			// answers point in opposite directions.
			//
			// The emit callback runs inside Fetch, so every Put is already counted
			// in the provider's elapsed time. Measured 2026-08-13: OSV alone was
			// 48m16s of a 50m51s build, and nothing in that number said whether it
			// was the 601 MB download or the one bolt transaction Put opens per
			// advisory, 149,495 of them. Concurrency fixes the first and would
			// make the second worse — bolt allows one write transaction at a time,
			// so parallel fetches queue at exactly this callback.
			var stored time.Duration
			// D57. Buffered and written in batches rather than one transaction per
			// advisory. The buffer lives here rather than in the store so that
			// nothing holds a bolt write transaction across calls — SetMeta,
			// PutRating and PutEnrichment all open their own, and a long-lived one
			// would deadlock against them.
			//
			// The error a caller sees may belong to an earlier advisory in the
			// batch, which is the cost of the trade and is why PutMany is all or
			// nothing: a partially written batch would leave a database that looks
			// complete and holds less.
			batch := make([]advisory.Advisory, 0, putBatchSize)
			flush := func() error {
				if len(batch) == 0 {
					return nil
				}
				t0 := time.Now()
				err := w.PutMany(batch)
				stored += time.Since(t0)
				batch = batch[:0]
				return err
			}
			prov, err := p.Fetch(ctx, func(a advisory.Advisory) error {
				batch = append(batch, a)
				// A mutation of this flush SURVIVES the suite, and that is a true
				// equivalent rather than a gap: the tail flush below stores every
				// record either way, so nothing observable changes. What it protects
				// is the memory bound — without it the buffer grows to the whole
				// corpus, roughly 150,000 advisories, and putBatchSize means nothing.
				// Stated here so it reads as a decision rather than as an untested
				// branch.
				if len(batch) < putBatchSize {
					return nil
				}
				return flush()
			})
			// The tail, and it must run even when Fetch failed: a provider that
			// died mid-archive still emitted everything before the failure, and
			// dropping that silently would make a partial fetch look like a smaller
			// upstream. The build fails either way — what matters is that the
			// count in the timing table is the count that was actually written.
			if ferr := flush(); ferr != nil && err == nil {
				err = ferr
			}
			timings = append(timings, stageTiming{
				Kind: "provider", Name: p.Name(), Elapsed: time.Since(started),
				Records: prov.Records, Stored: stored, Failed: err != nil})
			if err != nil {
				w.Close()
				os.Remove(tmp)
				fmt.Fprintf(stderr, "error: provider %s: %v\n", p.Name(), err)
				reportTimings(stderr, timings, buildStarted)
				return 2
			}
			meta.Providers[p.Name()] = prov
		}
	}

	// Seeding, if requested: ratings only, copied BEFORE the annotators run
	// so a delta below overwrites the entries it re-fetched and leaves the
	// rest (see Update's own doc comment for why advisories are deliberately
	// excluded). w is still the empty-then-provider-filled temp store here —
	// nothing about the advisory build above changes for a seeded run, which
	// is what keeps a withdrawn advisory absent rather than reintroduced.
	//
	// Skipped for a ratings-only build: that seed was already copied whole,
	// advisories and ratings both, before store.Create ran above, so this
	// record-by-record ratings copy would be redundant at best and would
	// overwrite meta.Ratings (already primed from seedMeta) with a second
	// read of the same seed at worst.
	if seedPath != "" && !ratingsOnly {
		// label (computed above, once for every path) is what all messages
		// call the seed — the original --seed reference, never the throwaway
		// scratch path.
		//
		// store.OpenSeedRatings, not store.Open (D67): this block reads only
		// EachRating and Meta below, never the advisories index, so a seed one
		// schema behind this binary's is exactly as usable here as a current
		// one -- see OpenSeedRatings' own doc comment for why that is safe for
		// ratings specifically and why the ratings-only path a few paragraphs
		// up must NOT make the same swap.
		src, err := store.OpenSeedRatings(seedPath)
		if err != nil {
			w.Close()
			os.Remove(tmp)
			fmt.Fprintf(stderr, "error: open seed %s: %v\n", label, err)
			return 2
		}
		seeded := 0
		copyErr := src.EachRating(func(r advisory.Rating) error {
			// D86: EPSS and KEV are excluded from the seed copy -- see
			// perishableRatingSources' own doc comment for why a
			// daily-rescored probability or a catalog membership must never
			// ride forward from yesterday's artifact the way NVD's CVSS
			// opinion does.
			if perishableRatingSources[r.Source] {
				return nil
			}
			seeded++
			return w.PutRating(r)
		})
		seedMeta, metaErr := src.Meta()
		src.Close()
		if copyErr != nil {
			w.Close()
			os.Remove(tmp)
			fmt.Fprintf(stderr, "error: read seed ratings: %v\n", copyErr)
			return 2
		}
		if metaErr != nil {
			// In practice unreachable today: store.Open above already read
			// and validated Meta once (its own schema-version guard), so a
			// second Meta() read against the same, still-open-read-only
			// database failing here would mean the file changed or became
			// unreadable between those two calls. Treated as fatal rather
			// than skipped anyway: silently proceeding with an empty
			// seedMeta.Ratings would leave every one of the seed's rating
			// authorities un-merged, and `db status` would render every
			// column for a source that DID run overnight as "unknown" with
			// no error at all -- the exact silent freshness loss D12 exists
			// to catch elsewhere, reintroduced here by a swallowed error
			// instead of a missing field.
			w.Close()
			os.Remove(tmp)
			fmt.Fprintf(stderr, "error: read seed metadata %s: %v\n", label, metaErr)
			return 2
		}
		// The seed's rating provenance is the starting point, so an annotator
		// this run did NOT run keeps the seed's window rather than vanishing
		// from `db status`. One that DID run overwrites its entry in the loop
		// below -- MERGED with it, not replacing it, so the entry describes
		// what the database holds rather than only what this run fetched
		// (see mergeRatingCoverage). This copy must still happen BEFORE the
		// annotator loop, never after.
		// Enrichment is deliberately NOT carried forward, and unlike
		// advisories that is a cost decision rather than a correctness one.
		// A published artifact has none to carry (D29 strips it), and a
		// seed built locally would only hold what its own build fetched — so
		// a nightly `db build --seed` run without KISA_ENABLE simply has no
		// Korean prose, silently, until the next run that sets it. That is
		// affordable because the whole KNVD walk is ~41 requests and under a
		// minute: re-fetching is cheaper than the machinery to inherit it,
		// where ratings genuinely cost seven hours. If enrichment ever grows
		// a cost like that, this is the line that has to change.
		//
		// EPSS/KEV coverage is excluded from this merge too, for the same
		// reason the ratings copy above excludes their rows (D86,
		// perishableRatingSources' own doc comment): a build whose EPSS/KEV
		// annotator did not run this time must report "not covered" rather
		// than the seed's stale window claiming current coverage for data
		// that was never actually re-fetched.
		for name, p := range seedMeta.Ratings {
			if perishableRatingSources[name] {
				continue
			}
			meta.Ratings[name] = p
		}
		fmt.Fprintf(stderr, "seeded %d rating(s) from %s; advisories rebuilt from source\n", seeded, label)
	}

	// Annotators run after the advisory providers (see Update's own doc
	// comment on why the order is kept even though nothing here depends on
	// it). A failing annotator fails the whole build exactly like a failing
	// provider does: a database holding advisories but missing the ratings a
	// configured annotator was supposed to add would look complete and
	// quietly under-report every band it would otherwise have raised.
	for _, a := range annotators {
		fmt.Fprintf(stderr, "annotating with %s…\n", a.Name())
		started := time.Now()
		prov, err := a.Annotate(ctx, func(r advisory.Rating) error { return w.PutRating(r) })
		timings = append(timings, stageTiming{
			Kind: "annotator", Name: a.Name(), Elapsed: time.Since(started),
			Records: prov.Records, Failed: err != nil})
		if err != nil {
			w.Close()
			os.Remove(tmp)
			fmt.Fprintf(stderr, "error: annotator %s: %v\n", a.Name(), err)
			reportTimings(stderr, timings, buildStarted)
			return 2
		}
		meta.Ratings[a.Name()] = mergeRatingCoverage(meta.Ratings[a.Name()], prov)
	}

	// Enrichers run last, and a failing one does NOT fail the build.
	//
	// That is the opposite of what the two loops above do, deliberately, so
	// do not "fix" it to match them. An advisory or a rating changes what a
	// scan concludes, so a database missing one a configured source was
	// supposed to supply looks complete and under-reports — which is why
	// those abort. Enrichment cannot reach a verdict at all (D3): it is a
	// Korean title, a summary and a link hung off a finding that exists
	// either way. Losing it costs a reader some text; aborting the build
	// would let an unreachable KISA endpoint deny a user any database at
	// all, and would do it AFTER an OSV fetch and possibly a seven-hour NVD
	// pass had already succeeded.
	//
	// A failure is still RECORDED, not merely warned about: the entry carries
	// Provenance.Error and nothing else, so `db status` renders a row saying
	// this source did not finish. Warning on stderr alone is not enough —
	// the build's output scrolls past, while the database is what anyone
	// looks at afterwards, and D20's rule is that a source which did not
	// deliver must not be indistinguishable from one that was never
	// configured.
	//
	// Writing nothing was the first version and it was worse than either
	// alternative. Records an enricher managed to emit before failing stay in
	// the bucket (they are harmless by construction — nothing here reaches a
	// verdict), so the derived half of `db status`'s union already produced a
	// row for a PARTIAL failure while a TOTAL one produced none: the same
	// fault visible or invisible depending on when the feed died.
	for _, e := range enrichers {
		fmt.Fprintf(stderr, "enriching with %s…\n", e.Name())
		started := time.Now()
		prov, err := e.Enrich(ctx, func(en advisory.Enrichment) error { return w.PutEnrichment(en) })
		timings = append(timings, stageTiming{
			Kind: "enricher", Name: e.Name(), Elapsed: time.Since(started),
			Records: prov.Records, Failed: err != nil})
		if err != nil {
			fmt.Fprintf(stderr, "warning: enricher %s: %v\n", e.Name(), err)
			// Whatever the enricher returned alongside its error is
			// discarded: a run that failed cannot vouch for its own DataAsOf
			// or record count, and rendering a freshness date for a fetch
			// that did not finish is exactly the over-claim D12 exists to
			// stop. The failure itself is the only thing recorded.
			meta.Enrichment[e.Name()] = store.Provenance{Error: oneLine(err.Error())}
			continue
		}
		meta.Enrichment[e.Name()] = prov
	}

	// EOLSource runs last, after enrichers, and — unlike an enricher — its
	// failure DOES fail the build (D87). The two enricher-loop paragraphs
	// above explain why KISA's failure must not: nothing it writes can ever
	// reach a verdict. End-of-life data is the opposite: it feeds
	// `--fail-on-eol` directly, and it is meant to ride the published
	// artifact the way KISA's prose deliberately never does (D29) — a build
	// that shipped without it would leave the gate silently unable to
	// answer, rather than loudly refusing to publish a database that cannot
	// back up the flag it advertises.
	if eolSource != nil {
		fmt.Fprintf(stderr, "fetching end-of-life data from %s…\n", eolSource.Name())
		started := time.Now()
		rows, prov, err := eolSource.Fetch(ctx)
		timings = append(timings, stageTiming{
			Kind: "eol", Name: eolSource.Name(), Elapsed: time.Since(started),
			Records: prov.Records, Failed: err != nil})
		if err != nil {
			w.Close()
			os.Remove(tmp)
			fmt.Fprintf(stderr, "error: eol source %s: %v\n", eolSource.Name(), err)
			reportTimings(stderr, timings, buildStarted)
			return 2
		}
		meta.EOL = rows
		meta.EOLProvenance = &prov
	}

	if err := w.SetMeta(meta); err != nil {
		w.Close()
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: write metadata: %v\n", err)
		return 2
	}
	// Close before renaming: on Windows a rename over an open file fails, and
	// assuming POSIX semantics here leaves a half-built database in place.
	if err := w.Close(); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: close database: %v\n", err)
		return 2
	}
	if err := replace(tmp, dbPath); err != nil {
		// Deliberately NOT removed. It is a complete database that cost a
		// ~244 MB download, and losing that because a scan happened to be
		// running is a worse outcome than leaving a file behind. The live
		// database is untouched either way — a rename never half-applies.
		fmt.Fprintf(stderr, "error: replace database: %v\n", err)
		fmt.Fprintf(stderr, "the new database is complete and left at %s\n", tmp)
		fmt.Fprintln(stderr, "close any running scan and move it into place, or re-run `assay db build`")
		return 2
	}

	total := 0
	for _, p := range meta.Providers {
		total += p.Records
	}
	// Before the stdout line, so a reader watching a terminal sees the timing
	// attached to the run that produced it rather than after the result.
	reportTimings(stderr, timings, buildStarted)
	fmt.Fprintf(stdout, "database updated: %d advisories at %s\n", total, dbPath)
	// No second "N ratings from N source(s)" line here: the only trustworthy
	// rating count is the one Bolt.SetMeta just derived from the stored
	// bucket (Meta.RatingCounts), and Writer does not expose a way to read
	// it back after SetMeta returns. Printing a self-reported total here
	// would be exactly the over-claim `db status` was just fixed to refuse
	// (see Meta.Ratings' own doc comment) — `assay db status` is where the
	// derived, accurate count belongs, and it already shows it.
	return 0
}

// readSeedMeta opens seedPath just long enough to read its Meta record, for
// a ratings-only build (D66): this has to happen BEFORE copyFile below
// duplicates the file and BEFORE store.Create reopens the copy read-write,
// so a read-only handle on the original never overlaps with a write handle
// on the target.
func readSeedMeta(seedPath string) (store.Meta, error) {
	db, err := store.Open(seedPath)
	if err != nil {
		return store.Meta{}, err
	}
	defer db.Close()
	return db.Meta()
}

// copyFile duplicates the seed database wholesale for a ratings-only build
// (D66): its advisories are wanted verbatim, so the seed's own file —
// buckets, index and all — becomes this build's starting point rather than
// an empty store.Create followed by a record-by-record copy. Measured at
// ~64 MB for a full artifact today, small enough that io.Copy rather than
// anything more careful is the whole implementation: there is nothing to
// diff, every byte of the seed is wanted.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// oneLine flattens a message so it cannot break the table it is rendered
// into. A tabwriter row containing a newline is not a row with an odd-looking
// cell — it silently becomes two rows, one of them unaligned and unlabelled,
// and the value that mattered ends up under a column heading it has nothing
// to do with. Provider errors are single-line today; a wrapped one from a
// future source is not this function's caller's problem to remember.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// replaceWaits is replace's own retry schedule: the delay before each
// attempt, first one immediate. A package-level var, not a literal inside
// replace, so a test can shrink it to run in milliseconds instead of ~850ms
// while still exercising the real retry COUNT (fix round 2, finding 1) --
// reassigning this changes how long replace sleeps between attempts, not
// how many it makes, which stays len(replaceWaits) either way.
var replaceWaits = []time.Duration{0, 100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond}

// renameFn is os.Rename by default, and the seam replace calls through
// instead of calling os.Rename directly, so a test can count attempts (or
// force every one to fail) without needing a real locked or otherwise
// unrenameable file.
var renameFn = os.Rename

// replace renames src over dst, retrying briefly first.
//
// On Windows a rename over a file another process holds open fails outright,
// and a scan reading the database is exactly the case the temp-file dance
// exists to support. Readers are short-lived, so a few hundred milliseconds
// turns the common collision into a non-event.
func replace(src, dst string) error {
	var err error
	for _, wait := range replaceWaits {
		if wait > 0 {
			time.Sleep(wait)
		}
		if err = renameFn(src, dst); err == nil {
			return nil
		}
	}
	return err
}

// Status reports what is in the database and how current it is. It states
// facts and does not judge staleness — age enforcement is deferred, and the
// metadata it would need is already recorded.
func Status(dbPath string, stdout, stderr io.Writer) int {
	db, err := store.Open(dbPath)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSchemaMismatch) ||
			errors.Is(err, store.ErrIncomplete) {
			fmt.Fprintf(stderr, "error: %v\n", err)
			fmt.Fprintln(stderr, "run `assay db update` to download it, or `assay db build` to build it from source")
			return 2
		}
		fmt.Fprintf(stderr, "error: open database: %v\n", err)
		return 2
	}
	defer db.Close()

	m, err := db.Meta()
	if err != nil {
		fmt.Fprintf(stderr, "error: read metadata: %v\n", err)
		return 2
	}

	// The value column is one wider than the longest label, so adding
	// "databases:" below moved every line right by one rather than leaving
	// that one label unaligned — and adding "enrichment:" moved them all
	// right by one again.
	fmt.Fprintf(stdout, "path:       %s\n", dbPath)
	fmt.Fprintf(stdout, "schema:     v%d\n", m.Schema)
	fmt.Fprintf(stdout, "built:      %s\n", m.BuiltAt.Format(time.RFC3339))
	// What this database covers decides which packages can be evaluated at
	// all (D20). Without it here, coverage is discoverable only by running a
	// scan and reading why it refused.
	fmt.Fprintf(stdout, "covers:     %s\n", coverageSummary(m.Ecosystems))
	// Which databases a rating could be attributed to (D25), visible the same
	// way coverage is: without running a scan.
	//
	// Labelled "databases", not "sources", even though D25's prose and the
	// report both call these sources. This command already prints a SOURCE
	// column four lines down, and that one holds Provenance.Source — the URL a
	// provider fetched from. Two meanings of one word in a single screen of
	// output is the ambiguity D25 exists to remove, not one to reintroduce.
	// The stored field is Advisory.Database and the JSON key is "database", so
	// this is also what a reader would grep for. The path line above was
	// renamed to "path:" so the two no longer read as a pair.
	fmt.Fprintf(stdout, "databases:  %s\n", databasesSummary(m.Databases))
	// Which authorities have ACTUALLY rated at least one CVE (D27), with how
	// many — the same "visible without running a scan" reasoning as
	// databases: above, and the same line shape and padding, but read from
	// Meta.RatingCounts (derived from the stored ratings bucket), never from
	// Meta.Ratings' self-reported Provenance: an annotator that ran and
	// rated nothing must not make this line claim a source that rated
	// something (see RatingCounts' own doc comment in
	// internal/store/store.go).
	fmt.Fprintf(stdout, "ratings:    %s\n", ratingsSummary(m.RatingCounts))
	// And which have enriched one (D3), on its own line beside ratings: for
	// the same reason that one sits beside databases: — the ENRICHMENT SOURCE
	// table further down is the only other place this is stated, and a reader
	// skimming the header block would otherwise have to infer from the
	// absence of a table that there is no enrichment, which is not something
	// an absence can say.
	//
	// Derived from Meta.EnrichmentCounts, never from Meta.Enrichment's
	// self-reported Provenance, for the reason RatingCounts' own doc comment
	// gives: a source that ran and enriched nothing must not make this line
	// claim it enriched something.
	//
	// This line reads "nothing" on every PULLED database and that is correct,
	// not a defect to hide: `db push` strips the bucket and this provenance
	// (D29), so the artifact genuinely carries none. Saying so plainly is the
	// point — a user wondering why no finding shows a Korean title gets the
	// answer here rather than from a missing table.
	fmt.Fprintf(stdout, "enrichment: %s\n", enrichmentLine(m.EnrichmentCounts))
	// Distro end-of-life coverage (D87), on the same "visible without a scan"
	// reasoning every line above follows, and read straight from Meta.EOL —
	// there is no derived-vs-self-reported split to make here the way
	// Ratings/Enrichment need: eol.Fetch returns its rows and its Provenance
	// together, in one call, so there is nothing for a partial run to
	// under- or over-claim about a bucket a scan reads independently.
	fmt.Fprintf(stdout, "eol:        %s\n", eolSummary(m.EOL, m.EOLProvenance))
	fmt.Fprintln(stdout)

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PROVIDER\tDATA AS OF\tRECORDS\tSOURCE")
	// Sorted so the output is diffable across runs — map order is not.
	names := make([]string, 0, len(m.Providers))
	for name := range m.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := m.Providers[name]
		asOf := "unknown"
		if !p.DataAsOf.IsZero() {
			asOf = p.DataAsOf.Format("2006-01-02")
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", name, asOf, p.Records, p.Source)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "error: write status: %v\n", err)
		return 2
	}

	// A second, separately-headed table for rating sources (D27, D12): "how
	// fresh is the NVD data in this database" is not answerable from the
	// ratings: line alone (it names sources and counts, not dates), and
	// folding annotators into the PROVIDER table above would answer a
	// different question under one header — that table already means
	// "advisory providers", and Provider/Ecosystems (D20) is genuinely a
	// different claim than an annotator's CVE opinions ever make.
	//
	// Driven from the UNION of the derived set (Meta.RatingCounts, ground
	// truth for "did this authority rate anything") and the self-reported
	// set (Meta.Ratings, the only source for DATA AS OF and SOURCE, D12) —
	// not from Meta.Ratings alone. Under normal operation every derived name
	// is also a self-reported one (only an annotator dbcmd.Update recorded
	// in Ratings ever gets to call PutRating at all), so the union costs
	// nothing today; it is here so a future divergence fails toward showing
	// an extra row rather than toward silently dropping one.
	//
	// A name present in Ratings but absent from RatingCounts is an
	// annotator that ran and rated NOTHING — a state D20/D26 already treat
	// as one that must stay visible rather than being silently dropped
	// (hiding it would trade an over-claim for a silence), but it must not
	// read as "this source rated something" either: that was the exact
	// defect a review caught, one column over from the ratings: line fixed
	// earlier. So its RECORDS cell is words, not a bare 0 — a 0 rendered
	// here can ONLY mean this (RatingCounts never stores an explicit zero:
	// counts[source]++ only ever runs for a key that exists, so a present
	// entry is always >= 1) — spelling out plainly that the sync ran and
	// produced nothing, which is the thing worth investigating. A name
	// absent from BOTH sets never appears as a row at all: that is how "this
	// authority never ran against this database" reads, as opposed to a row
	// that says it ran and got nothing.
	ratingNameSet := make(map[string]struct{}, len(m.Ratings)+len(m.RatingCounts))
	for name := range m.Ratings {
		ratingNameSet[name] = struct{}{}
	}
	for name := range m.RatingCounts {
		ratingNameSet[name] = struct{}{}
	}
	if len(ratingNameSet) > 0 {
		fmt.Fprintln(stdout)
		rtw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		// COVERED is the annotator's analogue of the PROVIDER table's
		// ecosystem list: what this source was actually asked for. A bounded
		// NVD sync (D27's NVD_SINCE_DAYS) rebuilds from empty like every
		// other run, so its window is the whole of that source's coverage
		// rather than a delta on top of a fuller pass — and a database
		// holding one day of NVD is otherwise indistinguishable here from
		// one holding all of it, differing only in a RECORDS number nobody
		// has a baseline for (D20).
		fmt.Fprintln(rtw, "RATING SOURCE\tDATA AS OF\tRECORDS\tCOVERED\tSOURCE")
		ratingNames := make([]string, 0, len(ratingNameSet))
		for name := range ratingNameSet {
			ratingNames = append(ratingNames, name)
		}
		sort.Strings(ratingNames)
		for _, name := range ratingNames {
			p := m.Ratings[name] // self-report; zero value if this name is derived-only
			asOf := "unknown"
			if !p.DataAsOf.IsZero() {
				asOf = p.DataAsOf.Format("2006-01-02")
			}
			records := "ran, rated nothing - investigate the sync"
			if n, ok := m.RatingCounts[name]; ok {
				records = fmt.Sprintf("%d", n)
			}
			// "unknown" rather than an empty cell for a database built
			// before Window existed, or by a derived-only name with no
			// self-report: a blank column reads as "no limit", which is the
			// one thing it must not be mistaken for.
			covered := p.Window
			if covered == "" {
				covered = "unknown"
			}
			// SOURCE gets the same treatment, for the same reason and to
			// settle it the same way in both tables. A derived-only name has
			// no self-reported fetch URL, which is the identical situation
			// its missing DATA AS OF and COVERED are already in — rendering
			// two of the three as a word and the third as whitespace gives
			// one row two vocabularies for one fact, and a blank cell reads
			// as "there is nothing to say here" rather than "this was not
			// established".
			//
			// The ENRICHMENT SOURCE table below already did this. Leaving
			// this one blank is what made two adjacent tables disagree about
			// the same absence, so the convention moved here rather than the
			// other way round.
			source := p.Source
			if source == "" {
				source = "unknown"
			}
			fmt.Fprintf(rtw, "%s\t%s\t%s\t%s\t%s\n", name, asOf, records, covered, source)
		}
		if err := rtw.Flush(); err != nil {
			fmt.Fprintf(stderr, "error: write status: %v\n", err)
			return 2
		}
	}

	// A third table for enrichment sources (D3), beside RATING SOURCE and for
	// the same reason it is beside PROVIDER: these answer a different question
	// again. A provider says which package is affected, an annotator what a
	// CVE is worth, an enricher only what it is CALLED — so folding them
	// together would put three claims of different weight under one heading.
	//
	// It follows RATING SOURCE's conventions exactly, because the three states
	// a reader must tell apart are the same ones:
	//
	//   - a name in the derived set enriched something, and the row shows how
	//     many;
	//   - a name self-reported but absent from the derived set RAN and
	//     enriched nothing, which is worth investigating, so its RECORDS cell
	//     is words rather than a bare 0 (D20/D26 forbid dropping the row, and
	//     a 0 reads as "no problem" rather than "check the sync");
	//   - a name in neither never ran, and has no row at all.
	//
	// With a fourth this table has that RATING SOURCE does not need: a run
	// that FAILED. An enricher's failure does not fail the build (see
	// Update), so unlike an annotator's it leaves a database behind for
	// someone to read — and a source that died halfway must not be readable
	// as one that finished. Both shapes of failure say so, the partial one
	// alongside the count that did land, because "2 records" and "2 records
	// out of an unknown number" are different claims.
	//
	// There is no COVERED column: an enricher fetches the whole notice list
	// every build (~41 requests), so there is no window to disclose the way a
	// bounded NVD sync has one.
	//
	// Nothing here appears in a PULLED database: `db push` strips both the
	// bucket and this provenance (D29), so an artifact cannot claim a source
	// whose records it does not carry.
	enrichNameSet := make(map[string]struct{}, len(m.Enrichment)+len(m.EnrichmentCounts))
	for name := range m.Enrichment {
		enrichNameSet[name] = struct{}{}
	}
	for name := range m.EnrichmentCounts {
		enrichNameSet[name] = struct{}{}
	}
	if len(enrichNameSet) > 0 {
		fmt.Fprintln(stdout)
		etw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(etw, "ENRICHMENT SOURCE\tDATA AS OF\tRECORDS\tSOURCE")
		names := make([]string, 0, len(enrichNameSet))
		for name := range enrichNameSet {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			p := m.Enrichment[name] // self-report; zero value if this name is derived-only
			asOf := "unknown"
			if !p.DataAsOf.IsZero() {
				asOf = p.DataAsOf.Format("2006-01-02")
			}
			n, enriched := m.EnrichmentCounts[name]
			var records string
			switch {
			case p.Error != "" && enriched:
				// Partial. The count is real but it is not the whole of what
				// this source holds, and saying only "2" would present an
				// interrupted fetch as a complete one. The number keeps a
				// space after it so it is still a field of its own in the
				// rendered row -- "2," would not be, and a test asserting on
				// the count would have to know the punctuation.
				records = fmt.Sprintf("%d written, then failed - %s", n, p.Error)
			case p.Error != "":
				records = fmt.Sprintf("failed, enriched nothing - %s", p.Error)
			case enriched:
				records = fmt.Sprintf("%d", n)
			default:
				records = "ran, enriched nothing - investigate the sync"
			}
			// "unknown", not a blank cell, and the same word DATA AS OF uses
			// two columns over — and the same word the RATING SOURCE table
			// above now uses in its own SOURCE column, so the two tables read
			// one absence one way. See there for the reasoning; this is where
			// it was written first.
			source := p.Source
			if source == "" {
				source = "unknown"
			}
			fmt.Fprintf(etw, "%s\t%s\t%s\t%s\n", name, asOf, records, source)
		}
		if err := etw.Flush(); err != nil {
			fmt.Fprintf(stderr, "error: write status: %v\n", err)
			return 2
		}
	}
	return 0
}

// coverageSummary keeps 23 Alpine releases from burying the three language
// ecosystems, while still naming the range so an operator can see whether the
// release they are about to scan falls inside it.
func coverageSummary(ecos []string) string {
	if len(ecos) == 0 {
		return "nothing - every scan will report its packages as unevaluated"
	}
	var plain []string
	byFamily := map[string][]string{}
	for _, e := range ecos {
		fam, rel, ok := strings.Cut(e, ":")
		if !ok {
			plain = append(plain, e)
			continue
		}
		byFamily[fam] = append(byFamily[fam], rel)
	}
	out := append([]string{}, plain...)
	for _, f := range slices.Sorted(maps.Keys(byFamily)) {
		rs := byFamily[f]
		if len(rs) == 1 {
			out = append(out, f+":"+rs[0])
			continue
		}
		// Numeric, not lexical. Meta.Ecosystems is sorted as whole strings, so
		// taking its first and last here printed "Alpine:v3.10..v3.9" — a range
		// that reads as covering nothing and answers the operator's actual
		// question ("is 3.25 inside?") backwards.
		slices.SortFunc(rs, compareRelease)
		out = append(out, fmt.Sprintf("%s:%s..%s (%d releases)", f, rs[0], rs[len(rs)-1], len(rs)))
	}
	return strings.Join(out, ", ")
}

// databasesSummary lists which databases authored at least one stored
// advisory (D25), so an operator can see what a rating could be attributed
// to without running a scan. It joins comma-separated the same way
// coverageSummary does, but does not sort: dbs already arrives sorted, from
// Bolt.SetMeta, which is where Databases gets its ordering. There is also no
// "family:release" collapsing to do here — database names, unlike Alpine
// releases, don't nest into a family.
func databasesSummary(dbs []string) string {
	if len(dbs) == 0 {
		return "nothing - ratings will not be attributable to a source"
	}
	return strings.Join(dbs, ", ")
}

// ratingsSummary lists which authorities have ACTUALLY rated at least one
// CVE (D27), each with how many — same line shape and message convention as
// databasesSummary, a different set, and with a count per name since "how
// many" is exactly the freshness/completeness question D12 asks and nowhere
// else in db status answers for ratings.
//
// Takes counts, not Meta.Ratings' self-reported Provenance: unlike
// Databases, which comes to this function pre-sorted from Bolt.SetMeta,
// Meta.RatingCounts is a derived map with no ordering guarantee of its own,
// so this function sorts it itself. Trusting self-report here is exactly
// the defect this function exists to not repeat — see RatingCounts' own doc
// comment in internal/store/store.go for why counts must be derived rather
// than reported.
func ratingsSummary(counts map[string]int) string {
	if len(counts) == 0 {
		return "nothing - no CVE in this database has been rated by any authority"
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s (%d)", name, counts[name]))
	}
	return strings.Join(parts, ", ")
}

// enrichmentLine lists which sources have ACTUALLY enriched at least one CVE
// (D3), each with how many — the same shape, ordering and derived-not-reported
// rule as ratingsSummary one line up.
//
// Its empty message differs from ratingsSummary's, because the empty state
// means something different here. No ratings is a gap; no enrichment is the
// normal condition of every published artifact (D29), so the message names
// that rather than implying something went wrong.
func enrichmentLine(counts map[string]int) string {
	if len(counts) == 0 {
		return "nothing - no CVE in this database carries a localized notice, " +
			"which is what a pulled artifact always looks like (D29)"
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s (%d)", name, counts[name]))
	}
	return strings.Join(parts, ", ")
}

// eolSummary reports what Meta.EOL holds (D87): how many releases across how
// many distros, and when endoflife.date generated the data (D12) — the same
// "visible without running a scan" reasoning every other db status line
// above follows.
//
// Nil is the "no EOL data" state, and it reads differently from any count:
// a database built before D87, or built with EOL_ENABLE=0, decodes this
// field to nil (store.Meta.EOL's own doc comment), and a scan's
// `--fail-on-eol` warns about exactly this state rather than silently
// treating it as "not EOL" (scancmd's own EOL lookup).
func eolSummary(rows []store.EOLRelease, prov *store.Provenance) string {
	if len(rows) == 0 {
		return "nothing - this database carries no end-of-life data; run `assay db update`, " +
			"or build with EOL_ENABLE=1 (on by default)"
	}
	distros := map[string]struct{}{}
	for _, r := range rows {
		distros[r.DistroID] = struct{}{}
	}
	asOf := "unknown"
	if prov != nil && !prov.DataAsOf.IsZero() {
		asOf = prov.DataAsOf.Format("2006-01-02")
	}
	return fmt.Sprintf("%d release(s) across %d distro(s), generated %s", len(rows), len(distros), asOf)
}

// compareRelease orders "v3.9" below "v3.10". Anything it cannot parse sorts
// last rather than panicking: an unexpected key shape should be visible in the
// output, not fatal to `db status`.
func compareRelease(a, b string) int {
	am, an, aok := releaseParts(a)
	bm, bn, bok := releaseParts(b)
	switch {
	case !aok && !bok:
		return strings.Compare(a, b)
	case !aok:
		return 1
	case !bok:
		return -1
	}
	if am != bm {
		return cmp.Compare(am, bm)
	}
	return cmp.Compare(an, bn)
}

func releaseParts(rel string) (major, minor int, ok bool) {
	// A bare major is a release, not an unparseable string. Alpine spells its
	// releases "v3.19" and Debian spells the modern ones "12", and requiring
	// the dot dropped every Debian release from 7 up into the lexical fallback
	// — which printed "Debian:3.0..9" for a database that covers 3.0 through
	// 14, telling an operator the newest four releases were missing when they
	// were the bulk of the archive.
	maj, min, found := strings.Cut(strings.TrimPrefix(rel, "v"), ".")
	if !found {
		min = "0"
	}
	major, err := strconv.Atoi(maj)
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(min)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// perishableRatingSources names the D86 annotators whose data must never
// ride forward from a seed (Update's own doc comment on the "seedRef" block
// gives the full reasoning): EPSS is a probability rescored daily with no
// concept of a stable historical value the way a CVE's CVSS vector is, and a
// KEV catalog entry can be REMOVED by CISA, something copying a seed forward
// has no way to notice. Both re-fetch the whole feed on every build
// (EPSS_ENABLE/KEV_ENABLE default ON in cmd/assay/main.go, unlike NVD's
// opt-in), so excluding them here costs nothing a normal build was not
// already going to redo.
//
// A literal set of source-name strings, not a reference to epss.SourceName/
// kev.SourceName: this package takes provider.Annotator as an interface and
// otherwise names no concrete provider package at all -- cmd/assay/main.go's
// dbUpdateAnnotators is what constructs the concrete epss.Provider/
// kev.Provider values, and dbcmd itself never imports either package -- so
// two string literals is cheaper than breaking that separation for a
// comparison this narrow.
var perishableRatingSources = map[string]bool{"EPSS": true, "KEV": true}

// mergeRatingCoverage combines what a seed already held with what this run
// fetched, for one rating source.
//
// The annotator's own Provenance describes only its fetch: a nightly delta
// reports three days. But a seeded database holds the seed's ratings too, so
// replacing the entry outright made the artifact claim three days while
// holding thirty. Two things break.
//
// The claim is false, in the direction that matters least to a reader and
// most to a publisher -- and `db push`'s coverage guard reads exactly this.
// Day one publishes "since D-3"; day two seeds from it, reports "since D-3"
// against a now-later date, and the guard correctly sees a narrowing and
// refuses. The scheduled workflow would have stopped publishing on its
// second run, having worked perfectly on its first.
//
// So coverage is the BROADER of the two, because the ratings from both are
// present. Everything else -- Source, DataAsOf, Records -- stays this run's,
// which is what those fields mean.
func mergeRatingCoverage(seeded, fetched store.Provenance) store.Provenance {
	merged := fetched
	switch {
	case seeded.Window == "" && !seeded.CoversSinceKnown && seeded.CoversSince.IsZero():
		// Nothing was seeded for this source.
		return merged
	case !seeded.CoversSinceKnown:
		// The seed recorded coverage for a human and not for a machine --
		// a database built before CoversSince existed. Its vintage is
		// genuinely unknown, so the merged coverage is unknown too.
		// Claiming this run's narrow window would be false, and claiming
		// unbounded would be the over-claim `db push` already refuses to
		// make. Saying nothing is the only honest option.
		merged.CoversSince, merged.CoversSinceKnown = time.Time{}, false
		merged.Window = seeded.Window + " + this run (seed coverage not recorded)"
		return merged
	case !fetched.CoversSinceKnown:
		// This run does not record its own bound, so nothing can be
		// merged against the seed's.
		return merged
	case !fetched.CoversSince.IsZero() && seeded.CoversSince.Before(fetched.CoversSince):
		// An unbounded seed needs no case of its own: its zero CoversSince
		// sorts before every real date, so it wins here. An explicit branch
		// for it was written first and removed after a mutation proved it a
		// true equivalent -- disabling it changed nothing, because control
		// simply fell through to this comparison and produced the same
		// result. An untestable branch reads as an untested one forever.
		merged.CoversSince = seeded.CoversSince
		merged.Window = coverageLabel(seeded.CoversSince)
	case fetched.CoversSince.Before(seeded.CoversSince):
		// A backfill slice (D65): this run asked for an OLDER range than the
		// seed already covers. Whether that EXTENDS the covered span depends
		// on the two ranges meeting.
		//
		// Both branches are written out, and the second one is why. `merged`
		// starts as `fetched`, so falling through on a gap would leave the
		// SLICE's bounds in place -- a database claiming to cover from
		// December while holding nothing between April and August. The
		// over-claim this rule exists to prevent was the default.
		if touches(fetched, seeded) {
			merged.CoversSince = fetched.CoversSince
			merged.Window = coverageLabel(fetched.CoversSince)
		} else {
			merged.CoversSince = seeded.CoversSince
			merged.Window = coverageLabel(seeded.CoversSince) +
				" (an earlier slice is held but does not reach it)"
		}
		// Either way the span now runs to wherever the SEED reached, not to
		// where this slice stopped. Leaving the slice's end in place would
		// say the artifact covers nothing since April, which is false in the
		// direction that matters: it would make tomorrow's nightly run look
		// like it was widening coverage and the guard would let a narrower
		// artifact through.
		merged.CoversUntil, merged.CoversUntilKnown = seeded.CoversUntil, seeded.CoversUntilKnown
	}
	return merged
}

// touches reports whether a slice's window reaches the range the seed already
// covers, so the two describe one span rather than two with a hole between.
//
// This is the whole reason CoversUntil exists. Ratings from a slice land in
// the database whatever the answer here -- they are real and they are kept --
// but the CLAIM is what this decides, and claiming coverage across a hole is
// the over-claim the publish guard and `db status` both read. Run the slices
// out of order and coverage simply does not advance, which is a visible
// refusal rather than a database that says it covers a year it has four
// months of.
//
// An unrecorded end is treated as reaching the present, which is what every
// run before D65 did.
func touches(slice, seeded store.Provenance) bool {
	if !slice.CoversUntilKnown || slice.CoversUntil.IsZero() {
		return true
	}
	return !slice.CoversUntil.Before(seeded.CoversSince)
}

// coverageLabel renders a merged bound in the shape the providers use, so
// `db status` reads the same whether a build was seeded or not. Duplicating
// the format is deliberate: the alternative is a provider deciding how a
// merge it never saw should be described.
func coverageLabel(since time.Time) string {
	if since.IsZero() {
		return "the whole feed"
	}
	return fmt.Sprintf("modified %s..%s",
		since.UTC().Format("2006-01-02"), time.Now().UTC().Format("2006-01-02"))
}

// putBatchSize is how many advisories share one write transaction (D57).
//
// Bolt holds a transaction's dirty pages in memory until commit, so this is a
// memory bound as much as a batching one: at roughly 10 KB an advisory, a
// thousand is about 10 MB of pending write against a build that already
// streams a 6 GB corpus.
const putBatchSize = 1000
