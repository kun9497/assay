// Package dbcmd implements `assay db update` and `assay db status`.
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
func Update(ctx context.Context, dbPath string, providers []provider.Provider, annotators []provider.Annotator, stdout, stderr io.Writer) int {
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
		meta.Ratings[a.Name()] = prov
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
		fmt.Fprintln(stderr, "close any running scan and move it into place, or re-run `assay db update`")
		return 2
	}

	total := 0
	for _, p := range meta.Providers {
		total += p.Records
	}
	fmt.Fprintf(stdout, "database updated: %d advisories at %s\n", total, dbPath)
	if len(meta.Ratings) > 0 {
		ratingsTotal := 0
		for _, p := range meta.Ratings {
			ratingsTotal += p.Records
		}
		fmt.Fprintf(stdout, "%d ratings from %d source(s)\n", ratingsTotal, len(meta.Ratings))
	}
	return 0
}

// replace renames src over dst, retrying briefly first.
//
// On Windows a rename over a file another process holds open fails outright,
// and a scan reading the database is exactly the case the temp-file dance
// exists to support. Readers are short-lived, so a few hundred milliseconds
// turns the common collision into a non-event.
func replace(src, dst string) error {
	var err error
	for _, wait := range []time.Duration{0, 100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond} {
		if wait > 0 {
			time.Sleep(wait)
		}
		if err = os.Rename(src, dst); err == nil {
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
			fmt.Fprintln(stderr, "run `assay db update` to build it")
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
	// Which authorities have rated at least one CVE (D27), the same "visible
	// without running a scan" reasoning as databases: above, and the same
	// line shape and padding — but a different set: an authority can rate a
	// CVE without authoring any stored advisory, so this cannot be read off
	// Databases, and Meta.Ratings is recorded separately (see its own doc
	// comment in internal/store/store.go).
	fmt.Fprintf(stdout, "ratings:   %s\n", ratingsSummary(m.Ratings))
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

// ratingsSummary lists which authorities have rated at least one CVE (D27) —
// same line shape and message convention as databasesSummary, a different
// set. Unlike Databases, Meta.Ratings is a map keyed by annotator name and
// populated directly by dbcmd.Update (store/store.go's own doc comment on
// why it is not derived by scanning a bucket the way Databases is), so this
// function sorts it itself rather than trusting an input Bolt.SetMeta
// already sorted.
func ratingsSummary(ratings map[string]store.Provenance) string {
	if len(ratings) == 0 {
		return "nothing - no rating source has run against this database"
	}
	names := make([]string, 0, len(ratings))
	for name := range ratings {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
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
