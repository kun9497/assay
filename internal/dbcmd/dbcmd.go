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

// Update rebuilds the database from every provider. It builds into a temporary
// file and renames over the live database, so a concurrent scan never observes
// a partial write.
func Update(ctx context.Context, dbPath string, providers []provider.Provider, stdout, stderr io.Writer) int {
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

	meta := store.Meta{BuiltAt: time.Now().UTC(), Providers: map[string]store.Provenance{}}
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

	fmt.Fprintf(stdout, "database: %s\n", dbPath)
	fmt.Fprintf(stdout, "schema:   v%d\n", m.Schema)
	fmt.Fprintf(stdout, "built:    %s\n", m.BuiltAt.Format(time.RFC3339))
	// What this database covers decides which packages can be evaluated at
	// all (D20). Without it here, coverage is discoverable only by running a
	// scan and reading why it refused.
	fmt.Fprintf(stdout, "covers:   %s\n", coverageSummary(m.Ecosystems))
	// Which databases a rating could be attributed to (D25), visible the same
	// way coverage is: without running a scan.
	fmt.Fprintf(stdout, "databases: %s\n", databasesSummary(m.Databases))
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
// to without running a scan. It shares coverageSummary's sorted,
// comma-joined style; there is no "family:release" collapsing to do here
// because database names, unlike Alpine releases, don't nest into a family.
func databasesSummary(dbs []string) string {
	if len(dbs) == 0 {
		return "nothing - ratings will not be attributable to a source"
	}
	return strings.Join(dbs, ", ")
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
