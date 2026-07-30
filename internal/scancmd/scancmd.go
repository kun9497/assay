// Package scancmd implements `assay scan`.
package scancmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/store"
)

// Run scans an SBOM file. Slice 1 has no --fail-on, so a completed scan exits
// 0 even with findings; the exit-2 paths are what matter here.
func Run(dbPath, target string, stdout, stderr io.Writer) int {
	f, err := os.Open(target)
	if err != nil {
		fmt.Fprintf(stderr, "error: open %s: %v\n", target, err)
		return 2
	}
	defer f.Close()

	inventory, cat, err := cyclonedx.Parse(f)
	if err != nil {
		fmt.Fprintf(stderr, "error: parse %s: %v\n", target, err)
		return 2
	}

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

	res, err := matcher.New(db).Match(inventory)
	if err != nil {
		fmt.Fprintf(stderr, "error: match: %v\n", err)
		return 2
	}
	sum, err := report.Table(stdout, res, cat)
	if err != nil {
		fmt.Fprintf(stderr, "error: write report: %v\n", err)
		return 2
	}
	// The report already said so in prose; exiting 0 anyway would let CI read a
	// scan that evaluated nothing as a pass (D11).
	if !sum.Trustworthy() {
		fmt.Fprintf(stderr,
			"error: none of the %d component(s) could be evaluated; this result cannot be trusted\n",
			sum.Components)
		return 2
	}
	return 0
}
