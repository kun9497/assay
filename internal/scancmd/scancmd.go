// Package scancmd implements `assay scan`.
package scancmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kun9497/assay/internal/cataloger/apkdb"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/osrelease"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/source"
	"github.com/kun9497/assay/internal/store"
)

// The two files an image cataloger reads, named as they appear as tar entries
// (no leading slash) — which is also the form Image.Files normalises its own
// keys to, so a lookup with a leading slash would just miss.
const (
	osReleasePath = "etc/os-release"
	apkDBPath     = "lib/apk/db/installed"
)

// Run scans an SBOM file or a container image — a registry reference, a
// docker-archive: tarball, or an oci-dir: layout — chosen by
// source.ClassifyTarget so one argument reaches the right loader. Slice 1 has
// no --fail-on, so a completed scan exits 0 even with findings; the exit-2
// paths are what matter here.
func Run(dbPath, target string, stdout, stderr io.Writer) int {
	var (
		inventory pkgmeta.Target
		cat       cyclonedx.Stats
	)

	if source.ClassifyTarget(target) == source.TargetImage {
		t, stats, err := catalogImage(target)
		if err != nil {
			fmt.Fprintf(stderr, "error: open %s: %v\n", target, err)
			return 2
		}
		inventory, cat = t, stats
	} else {
		f, err := os.Open(target)
		if err != nil {
			fmt.Fprintf(stderr, "error: open %s: %v\n", target, err)
			return 2
		}
		defer f.Close()

		t, stats, err := cyclonedx.Parse(f)
		if err != nil {
			fmt.Fprintf(stderr, "error: parse %s: %v\n", target, err)
			return 2
		}
		inventory, cat = t, stats
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

// catalogImage opens ref and builds a Target from it. It is a thin wrapper
// around catalogFromImage so tests can drive the cataloging logic directly,
// against a hand-built *source.Image, without going through a real registry,
// tarball, or layout.
func catalogImage(ref string) (pkgmeta.Target, cyclonedx.Stats, error) {
	img, err := source.Open(ref)
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, err
	}
	return catalogFromImage(img)
}

// catalogFromImage builds a Target the way syft does for the same image: the
// distro from /etc/os-release, packages from /lib/apk/db/installed, and each
// package's Location.LayerDigest from the layer the file it was read from
// actually belongs to (apkdb.Parse cannot set this itself — it never sees a
// layer, only a reader).
//
// A missing os-release, or one whose distro has no ecosystem, is not an
// error: the packages below are still cataloged, with an empty Ecosystem, so
// the matcher and report already treat them as not evaluated (D11). Returning
// early here with a nil error and an empty Target would instead print "no
// known vulnerabilities found" — a clean result for a scan that checked
// nothing.
func catalogFromImage(img *source.Image) (pkgmeta.Target, cyclonedx.Stats, error) {
	files, err := img.Files([]string{osReleasePath, apkDBPath})
	if err != nil {
		return pkgmeta.Target{}, cyclonedx.Stats{}, err
	}

	var (
		target    pkgmeta.Target
		ecosystem string
	)
	if f, ok := files[osReleasePath]; ok {
		d, err := osrelease.Parse(bytes.NewReader(f.Data))
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", osReleasePath, err)
		}
		target.Distro = &d
		if eco, err := d.Ecosystem(); err == nil {
			ecosystem = eco
		}
		// On error ecosystem stays "": apk packages are cataloged unkeyed below,
		// so the matcher reports them as skipped with a reason. Guessing a
		// substitute key here would turn "we cannot check this" into "this is
		// clean" — exactly the false negative D11 exists to prevent.
	}

	var stats cyclonedx.Stats
	if f, ok := files[apkDBPath]; ok {
		pkgs, err := apkdb.Parse(bytes.NewReader(f.Data), ecosystem)
		if err != nil {
			return pkgmeta.Target{}, cyclonedx.Stats{}, fmt.Errorf("parse %s: %w", apkDBPath, err)
		}
		for i := range pkgs {
			for j := range pkgs[i].Locations {
				pkgs[i].Locations[j].LayerDigest = f.DiffID
			}
		}
		target.Packages = pkgs
		stats.Cataloged = len(pkgs)
	}

	stats.Components = stats.Cataloged
	if stats.Components == 0 {
		// Unlike a CycloneDX document, which can legitimately list zero
		// components, an image is real filesystem content: there is no such
		// thing as a vacuously empty one. Leaving Components at 0 here would
		// let report.Table's "nothing to evaluate" branch — meant for a
		// genuinely empty SBOM — read a missing or empty package database, or
		// a distro this build does not support, as a clean scan instead of one
		// that evaluated nothing (D11).
		stats.Components = 1
	}

	return target, stats, nil
}
