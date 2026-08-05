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
// seedRef is what every message about the seed NAMES it as, instead of
// seedPath. The CLI's `db build --seed <ref>` pulls the reference to a
// throwaway scratch file before calling Update (Update itself only ever
// reads a local path), so seedPath there is something like
// "/tmp/assay-seed-183739/seed.db" -- meaningless in an archived CI log,
// and useless for identifying which published artifact was actually
// carried forward. Empty falls back to seedPath itself, which is what
// every direct caller in this package's own tests passes as a real,
// already-meaningful path.
func Update(ctx context.Context, dbPath, seedPath, seedRef string, providers []provider.Provider, annotators []provider.Annotator, stdout, stderr io.Writer) int {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "error: create database directory: %v\n", err)
		return 2
	}
	tmp := dbPath + ".tmp"
	_ = os.Remove(tmp)

	w, err := store.Create(tmp)
	if err != nil {
		// bolt.Open can create the file before a later step fails, so clean up
		// here too rather than relying on the next run to sweep it.
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: create database: %v\n", err)
		return 2
	}

	meta := store.Meta{
		BuiltAt:   time.Now().UTC(),
		Providers: map[string]store.Provenance{},
		Ratings:   map[string]store.Provenance{},
	}
	for _, p := range providers {
		fmt.Fprintf(stderr, "fetching %s…\n", p.Name())
		prov, err := p.Fetch(ctx, func(a advisory.Advisory) error { return w.Put(a) })
		if err != nil {
			w.Close()
			os.Remove(tmp)
			fmt.Fprintf(stderr, "error: provider %s: %v\n", p.Name(), err)
			return 2
		}
		meta.Providers[p.Name()] = prov
	}

	// Seeding, if requested: ratings only, copied BEFORE the annotators run
	// so a delta below overwrites the entries it re-fetched and leaves the
	// rest (see Update's own doc comment for why advisories are deliberately
	// excluded). w is still the empty-then-provider-filled temp store here —
	// nothing about the advisory build above changes for a seeded run, which
	// is what keeps a withdrawn advisory absent rather than reintroduced.
	if seedPath != "" {
		// What every message below calls the seed. See seedRef's own doc
		// comment on Update: the CLI passes the original --seed reference
		// here, since seedPath by itself is a throwaway scratch file no
		// human or CI log would recognize.
		label := seedPath
		if seedRef != "" {
			label = seedRef
		}
		src, err := store.Open(seedPath)
		if err != nil {
			w.Close()
			os.Remove(tmp)
			fmt.Fprintf(stderr, "error: open seed %s: %v\n", label, err)
			return 2
		}
		seeded := 0
		copyErr := src.EachRating(func(r advisory.Rating) error {
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
		maps.Copy(meta.Ratings, seedMeta.Ratings)
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
		prov, err := a.Annotate(ctx, func(r advisory.Rating) error { return w.PutRating(r) })
		if err != nil {
			w.Close()
			os.Remove(tmp)
			fmt.Fprintf(stderr, "error: annotator %s: %v\n", a.Name(), err)
			return 2
		}
		meta.Ratings[a.Name()] = mergeRatingCoverage(meta.Ratings[a.Name()], prov)
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
	// that one label unaligned.
	fmt.Fprintf(stdout, "path:      %s\n", dbPath)
	fmt.Fprintf(stdout, "schema:    v%d\n", m.Schema)
	fmt.Fprintf(stdout, "built:     %s\n", m.BuiltAt.Format(time.RFC3339))
	// What this database covers decides which packages can be evaluated at
	// all (D20). Without it here, coverage is discoverable only by running a
	// scan and reading why it refused.
	fmt.Fprintf(stdout, "covers:    %s\n", coverageSummary(m.Ecosystems))
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
	fmt.Fprintf(stdout, "databases: %s\n", databasesSummary(m.Databases))
	// Which authorities have ACTUALLY rated at least one CVE (D27), with how
	// many — the same "visible without running a scan" reasoning as
	// databases: above, and the same line shape and padding, but read from
	// Meta.RatingCounts (derived from the stored ratings bucket), never from
	// Meta.Ratings' self-reported Provenance: an annotator that ran and
	// rated nothing must not make this line claim a source that rated
	// something (see RatingCounts' own doc comment in
	// internal/store/store.go).
	fmt.Fprintf(stdout, "ratings:   %s\n", ratingsSummary(m.RatingCounts))
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
			fmt.Fprintf(rtw, "%s\t%s\t%s\t%s\t%s\n", name, asOf, records, covered, p.Source)
		}
		if err := rtw.Flush(); err != nil {
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
	maj, min, found := strings.Cut(strings.TrimPrefix(rel, "v"), ".")
	if !found {
		return 0, 0, false
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
	}
	return merged
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
