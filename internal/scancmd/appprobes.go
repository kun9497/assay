package scancmd

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/cataloger/dpkgdb"
	"github.com/kun9497/assay/internal/cataloger/gobinary"
	"github.com/kun9497/assay/internal/cataloger/npminstalled"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/source"
)

// D160: the two fixed-location probes for application packages inside an
// image. An image scan inventories the OS and Bitnami's markers (D70, D99);
// the 2026-11-09 measurement of all 26 scanner-diff targets put every
// grype-only application tuple in exactly two places -- the global npm tree
// under usr/lib/node_modules and Go binaries directly in the standard bin
// directories -- and nothing in a lockfile, a jar or a Python dist-info. So
// the probes read those two places and nothing else, under D112's existing
// budget, and the scope record says per ecosystem what was probed, where, and
// what is still not read.

// goBinDirs are the directories the Go-binary probe reads, direct children
// only, fixed like npminstalled.Roots. The measured binaries (bci156's
// container-suseconnect, cleanstart's gosu, archlinux's captree) all sit in
// usr/bin; the other six are where a distro or an image author puts an
// executable they mean to be on PATH. A Go binary anywhere else -- /opt,
// /app, a language runtime's own tree -- is disclosed as not read.
var goBinDirs = []string{"usr/bin", "usr/local/bin", "bin", "sbin", "usr/sbin", "usr/libexec", "usr/local/sbin"}

// applicationEcosystemsNotRead are the application ecosystems the image path
// knows exist inside images and does not read, named so the disclosure can
// list them rather than say "others". Python's dist-info files on the
// measured images are all OS-package-owned (reading them without the package
// manager's file ownership would report every RPM-installed module twice),
// and 0 grype-only java or python tuples were measured; each is the next
// probe the day its D117 ceiling trips.
var applicationEcosystemsNotRead = []string{"PyPI", "Maven"}

// isELF is the sniff the Go probe hands ExecutablesIn: the four-byte ELF
// magic. A non-ELF executable in a bin directory (a shell script, a Python
// entry point) costs four bytes and is never read.
func isELF(head []byte) bool {
	return len(head) == 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F'
}

// catalogApplicationProbes runs both probes over img and returns their
// packages (each located at its image path with the layer it came from),
// their counts and the per-ecosystem scope records, in a stable order.
//
// Not finding anything is not an error, for catalogBitnami's reason: most
// images have no global npm tree and no Go binary in /usr/bin, and the probe
// says so with ScopeNone. An installed package.json with no version is
// counted in SkippedNoVersion (D36): a component whose version is unknown,
// not one silently dropped.
//
// owned is the file ownership the OS database already yielded (rpm, apk);
// osPkgs the OS inventory, for the dpkg and pacman lists this pass reads
// (D162). Both may be nil: the probes then locate without an owner.
func catalogApplicationProbes(ctx context.Context, img *source.Image, owned *fileOwners, osPkgs []pkgmeta.Package) ([]pkgmeta.Package, cyclonedx.Stats, []report.ApplicationScopeRecord, error) {
	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
		scope []report.ApplicationScopeRecord
	)

	// ONE pass over the layers for both probes (D123 makes every pass a full
	// read of every layer): package.json at any depth under the npm roots,
	// and executables directly in the bin directories whose first bytes are
	// ELF. A package.json is accepted at the sniff unread; a non-ELF
	// executable is declined there and costs four bytes. D162 adds the two
	// ownership roots to the same pass: dpkg's `.list` files and pacman's
	// `files`, accepted unread like a package.json.
	roots := append(append([]string{}, npminstalled.Roots...), goBinDirs...)
	roots = append(roots, dpkgdb.InfoDir, pacmanLocalDir)
	files, links, err := img.FilesProbedLinks(ctx, roots, mergedUsrDirs, probeCandidate, probeSniff)
	if err != nil {
		return nil, cyclonedx.Stats{}, nil, fmt.Errorf("application probes: %w", err)
	}

	if owned == nil {
		owned = newFileOwners(img)
	}
	// D162, revised by the 2026-11-10 QA: the merged-/usr twin spelling is
	// only true where this image makes it true -- a top-level `bin` (and
	// the rest) that is a symlink to its usr/ counterpart. The same pass saw
	// those entries (mergedUsrDirs are its exact names), so this costs no
	// extra layer read.
	owned.merged = mergedUsrIn(links)
	npmFiles := map[string][]byte{}
	layerOf := map[string]string{}
	type goBin struct {
		path string
		file source.FileFromLayer
	}
	var bins []goBin
	for _, p := range source.SortedNames(files) {
		f := files[p]
		switch {
		case isOwnershipList(p):
			owned.addList(p, f, osPkgs)
		case path.Base(p) == "package.json":
			npmFiles[p] = f.Data
			layerOf[p] = f.DiffID
		default:
			bins = append(bins, goBin{p, f})
		}
	}

	npmPkgs, npmStats := npminstalled.Catalog(npmFiles)
	for i := range npmPkgs {
		for j := range npmPkgs[i].Locations {
			npmPkgs[i].Locations[j].LayerDigest = layerOf[npmPkgs[i].Locations[j].Path]
		}
	}
	pkgs = append(pkgs, npmPkgs...)
	addStats(&stats, npmStats)
	scope = append(scope, report.ApplicationScopeRecord{
		Ecosystem: "npm", State: scopeState(npmStats.Components > 0), Roots: npminstalled.Roots,
	})

	// Sorted, so two scans of one image list the binaries' packages in one
	// order (design goal #3 reaches the inventory too).
	sort.Slice(bins, func(i, j int) bool { return bins[i].path < bins[j].path })
	goFound := false
	for _, b := range bins {
		t, s, err := gobinary.ParseBytes(b.file.Data, b.path)
		if err != nil {
			// An ELF that carries no Go build info is not a Go binary -- a C
			// program, a stripped runtime -- and so not a package: skipped
			// without a count, the way a non-ELF executable was skipped at
			// the sniff.
			continue
		}
		goFound = true
		for i := range t.Packages {
			for j := range t.Packages[i].Locations {
				t.Packages[i].Locations[j].LayerDigest = b.file.DiffID
			}
		}
		pkgs = append(pkgs, t.Packages...)
		addStats(&stats, s)
	}
	scope = append(scope, report.ApplicationScopeRecord{Ecosystem: "Go", State: scopeState(goFound), Roots: goBinDirs})

	for _, eco := range applicationEcosystemsNotRead {
		scope = append(scope, report.ApplicationScopeRecord{Ecosystem: eco, State: report.ScopeNotRead})
	}
	// D162: every probed location the OS inventory owns says so.
	owned.stamp(pkgs)
	return pkgs, stats, scope, nil
}

// probeCandidate is the one pass's match: a package.json anywhere under an
// npm root, or a regular file of at least a kilobyte with an execute bit
// directly inside a bin directory. The roots are told apart by the path
// itself, so one match serves both probes; which root a name is under was
// already decided by FilesProbed.
func probeCandidate(name string, h *tar.Header) bool {
	// A top-level merged-/usr directory name is observed only for its link
	// (mergedUsrIn): nothing is read from it here.
	for _, d := range mergedUsrDirs {
		if name == d {
			return h.Typeflag == tar.TypeSymlink
		}
	}
	// D162: a dpkg `.list` or a pacman `files` under its root, a regular
	// file; anything else under those roots (a `.md5sums`, a `desc`) is
	// declined here and never read.
	if isOwnershipList(name) {
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont:
			return h.Size <= source.MaxFileBytes
		}
		return false
	}
	if path.Base(name) == "package.json" {
		return underAny(name, npminstalled.Roots)
	}
	switch h.Typeflag {
	case tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont:
	default:
		return false
	}
	if h.Mode&0o111 == 0 || h.Size < minExecutableBytes {
		return false
	}
	// An executable the per-file limit would refuse is declined here, before
	// a byte of it is read: it cannot be a Go binary this scan may read, and
	// reading it only to fail the whole scan (the OS verdict with it) would
	// turn a 600 MiB C++ program in /usr/bin into exit 2 for the image. The
	// decline still shadows a lower layer's file at the name (FilesProbed's
	// scope rule), so nothing else surfaces in its place. Not disclosed as a
	// skip: it is not a package, and nothing says it is a Go binary.
	if h.Size > source.MaxFileBytes {
		return false
	}
	d := path.Clean(path.Dir(name))
	for _, dir := range goBinDirs {
		if d == dir {
			return true
		}
	}
	return false
}

// probeSniff accepts every package.json unread and an executable only when
// its first four bytes are the ELF magic.
func probeSniff(name string, head []byte) bool {
	if isOwnershipList(name) || path.Base(name) == "package.json" {
		return true
	}
	return isELF(head)
}

// minExecutableBytes is the smallest file the Go probe considers: no ELF
// with Go build info is shorter than a kilobyte, and the floor keeps wrapper
// scripts with the execute bit from being sniffed one by one.
const minExecutableBytes = 1024

func underAny(name string, roots []string) bool {
	for _, r := range roots {
		if strings.HasPrefix(name, r+"/") {
			return true
		}
	}
	return false
}

// scopeState is ScopeRead when a probe found something and ScopeNone when it
// ran and found nothing -- the D111 distinction catalogBitnami draws.
func scopeState(found bool) string {
	if found {
		return report.ScopeRead
	}
	return report.ScopeNone
}

// addStats folds one cataloger's counts into the image's.
func addStats(into *cyclonedx.Stats, s cyclonedx.Stats) {
	into.Components += s.Components
	into.Cataloged += s.Cataloged
	into.SkippedNoVersion += s.SkippedNoVersion
	into.SkippedNoPURL += s.SkippedNoPURL
	into.SkippedUnsupportedEcosystem += s.SkippedUnsupportedEcosystem
}

// applicationScopeNote is D141's stderr disclosure, rebuilt from the scope
// record (D160): what the probes read, where, and what is still not read,
// with the remedy for the latter. One function so the test that holds the
// wording holds the one that is printed.
func applicationScopeNote(w io.Writer, s *report.InventoryScopeRecord) {
	read, notRead := report.ApplicationScopeSentence(s)
	switch {
	case read == "":
		fmt.Fprintln(w, "note: an image scan reads OS packages (and Bitnami markers), not application "+
			"packages installed in the image -- npm, Python, Java and Go binaries were not checked")
	default:
		fmt.Fprintf(w, "note: an image scan reads OS packages (and Bitnami markers) plus %s; the other application "+
			"packages -- %s, node_modules elsewhere and Go binaries elsewhere -- were not checked\n", read, notRead)
	}
	fmt.Fprintln(w, "  scan the application's lockfile, directory or binary, or an SBOM of the image, "+
		"for those (D70, D160)")
}
