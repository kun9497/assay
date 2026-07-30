// Package dbcmd implements `assay db update` and `assay db status`.
package dbcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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
	if err := os.Rename(tmp, dbPath); err != nil {
		os.Remove(tmp)
		fmt.Fprintf(stderr, "error: replace database: %v\n", err)
		return 2
	}

	total := 0
	for _, p := range meta.Providers {
		total += p.Records
	}
	fmt.Fprintf(stdout, "database updated: %d advisories at %s\n", total, dbPath)
	return 0
}

// Status reports what is in the database and how current it is. It states
// facts and does not judge staleness — age enforcement is deferred, and the
// metadata it would need is already recorded.
func Status(dbPath string, stdout, stderr io.Writer) int {
	db, err := store.Open(dbPath)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrSchemaMismatch) {
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
