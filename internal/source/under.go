package source

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// FilesUnder returns every regular file directly inside dir, keyed by full
// path (D54).
//
// Files takes exact paths, which is the right shape for the three databases a
// scan wants by name. It cannot express a distroless image's dpkg database:
// that is /var/lib/dpkg/status.d, a DIRECTORY holding one stanza per package,
// and its contents are named after the packages — which is what the scan is
// trying to find out. The set has to be discovered rather than asked for.
//
// The layer semantics are the ones Files already implements and they are not
// optional here either. Layers are walked NEWEST FIRST so a later layer's copy
// of a stanza wins; a whiteout hides entries in the layers still to be read but
// not its own layer's; and an opaque marker on the directory hides everything
// beneath it in lower layers. A distroless image built by copying one base's
// status.d over another's is exactly where those rules decide the inventory.
//
// DIRECT children only. status.d is flat, and recursing would let some future
// image shape contribute files this cataloger would then try to parse as dpkg
// stanzas.
//
// Symlinks under dir are counted and NOT followed, and the count is returned so
// the caller can disclose it. Following one would mean another resolve pass per
// entry against a set that is itself being discovered; no distroless image
// measured carries one, and a silent skip of a package's stanza is the failure
// this project ranks worst. A non-zero count is something a reader can act on.
//
// Nothing is written to disk, for Files's reason: not extracting removes the
// path-traversal class rather than defending against it.
//
// D112's bounds hold here exactly as in Files: each file through MaxFileBytes,
// the image's MaxScanBytes budget, and ctx checked between tar entries. A
// distroless status.d is a directory of files an image author chose the size
// and number of.
func (img *Image) FilesUnder(ctx context.Context, dir string) (map[string]FileFromLayer, int, error) {
	prefix := normaliseEntry(dir)
	if prefix == "" || prefix == "." {
		// The image root. Refused rather than served: nothing wants every
		// regular file in an image, and a caller that asked for this by
		// accident would get an inventory-sized allocation.
		return nil, 0, fmt.Errorf("source: FilesUnder needs a directory, got %q", dir)
	}

	return img.collect(ctx, prefix, func(name string) bool {
		// Direct children only: path.Split leaves the trailing slash on the
		// directory half, so this rejects both a deeper file and the
		// directory entry itself.
		d, base := path.Split(name)
		return path.Clean(d) == prefix && base != ""
	})
}

// underHit is what one layer last wrote at a name collect is gathering.
type underHit struct {
	kind hitKind
	data []byte
	// linkname and hard describe a hitLink entry: its target as the tar
	// header spells it, and whether it is a hardlink.
	linkname string
	hard     bool
}

// Link is a link entry a probe pass found as the final entry at a name: what
// the image has there instead of a file. Target is the header's linkname as
// written (relative or absolute, not resolved); Hard is a hardlink, whose
// target is an archive path; DiffID is the layer that put it there.
type Link struct {
	Target string
	Hard   bool
	DiffID string
}

// collect is the walk FilesUnder, FilesNamed and FilesMatching share: every
// regular file under root that match accepts, with the layer semantics their
// doc comments give, and the number of links found where such a file would
// be. One walk rather than three copies, so a rule fixed in one cannot be left
// unfixed in the others -- they were copies, and the in-layer rule below had
// to be added to all three.
//
// Within ONE layer the last entry for a name wins, for Files's reason: every
// extractor leaves the later entry on disk (audit 2026-10-22 P4, re-verified
// 2026-11-02). So nothing is decided until the layer ends: last holds what
// the layer most recently wrote at each name -- a file, a link, something that
// is not a file, or a whiteout that removed what the layer wrote before it --
// and only then is it merged into what the upper layers already decided.
// Across layers the newest still wins, through found.
func (img *Image) collect(ctx context.Context, root string, match func(name string) bool) (map[string]FileFromLayer, int, error) {
	out, links, err := img.collectWith(ctx, []string{root}, func(name string, _ *tar.Header) bool { return match(name) }, nil, nil, false)
	return out, len(links), err
}

// underReplaced reports whether a strict ancestor of name is one an upper
// layer put a file or a link at (collectWith's replaced set).
func underReplaced(name string, replaced map[string]bool) bool {
	for p := path.Dir(name); p != "." && p != "/" && p != ""; p = path.Dir(p) {
		if replaced[p] {
			return true
		}
	}
	return false
}

// sniffBytes is how much of a candidate entry collectWith hands to sniff
// before deciding to read it: four bytes, the length of the ELF magic and
// of every other magic the image path cares about.
const sniffBytes = 4

// collectWith is collect over several roots in ONE pass, with the header in
// the match and an optional sniff (D160): match sees the tar header so a
// caller can select on mode and size (an executable of at least a kilobyte)
// as well as on name, and sniff sees the entry's name and first sniffBytes
// and says whether the rest is wanted. An entry sniff declines is not read
// further and not kept -- /usr/bin/bash costs four bytes, not its size -- but
// it still shadows a lower layer's copy of the name (A10): the image has a
// file here, just not one the caller wants. The sniffed bytes of a declined
// entry are not charged to the per-scan budget; they are bounded by
// sniffBytes times the entries matched. Several roots in one pass because a
// pass reads every layer to EOF (D123): the ten locations the image probes
// read would otherwise be ten passes.
//
// scope, when given, names the entries that are IN the caller's locations
// whether or not match wants them. A header-aware match can decline an
// entry a name-only match could not -- the same name as a wanted file, but
// a symlink, a 0644 copy, a wrapper script under the size floor -- and such
// an entry still means "the image has something else at this name" (A10):
// without the shadow, the lower layer's Go binary at that path would be
// returned as the image's, cataloged, and located in a layer the image's
// filesystem no longer shows. A declined in-scope entry is recorded hitGone
// (not hitLink: the probes discard the link count, and a link they could
// not follow is not a file they failed to read). The collect callers pass
// nil, since a name-only match cannot split one name two ways.
// keepTargets records each link's target and layer; the count-only callers
// (FilesUnder, FilesNamed, FilesMatching) pass false and the map holds empty
// Links, so they pay for a name per link and no more.
func (img *Image) collectWith(ctx context.Context, roots []string, match func(name string, h *tar.Header) bool, sniff func(name string, head []byte) bool, scope func(name string) bool, keepTargets bool) (map[string]FileFromLayer, map[string]Link, error) {
	out := map[string]FileFromLayer{}
	found := map[string]bool{}
	deleted := map[string]bool{}
	var opaque []string
	links := map[string]Link{}
	// replaced is every name an upper layer ended with a file or a link at:
	// the OCI changeset rules keep an existing path only when both it and
	// the new entry are directories, so a lower layer's entries BENEATH
	// such a name are gone from the filesystem without any whiteout -- a
	// package directory an upper layer replaced with a symlink still read
	// its old manifest as installed (QA 2026-11-11).
	replaced := map[string]bool{}

	for i := len(img.Layers) - 1; i >= 0; i-- {
		l := img.Layers[i]
		layerDeleted := map[string]bool{}
		var layerOpaque []string
		last := map[string]underHit{}
		// layerNonDir is every matched name this layer wrote a file or a
		// link at, whether or not an upper layer decided the name again
		// (found): it still replaced what lower layers hold beneath it.
		layerNonDir := map[string]bool{}

		err := readLayer(ctx, l, func(name string, h *tar.Header, r io.Reader) error {
			if underReplaced(name, replaced) {
				return nil
			}
			for _, root := range roots {
				shadowAncestors(last, name, root)
			}
			d, base := path.Split(name)
			switch {
			case base == whiteoutOpaque:
				// No effect on this layer's own entries in either order: both
				// untars clear only what lower layers put in the directory.
				layerOpaque = append(layerOpaque, path.Clean(d))
				return nil
			case strings.HasPrefix(base, whiteoutPrefix):
				w := path.Join(d, strings.TrimPrefix(base, whiteoutPrefix))
				layerDeleted[w] = true
				// A plain whiteout AFTER this layer's own entry removes it, as
				// the untar does when it reaches the marker (see resolvePass);
				// one before is overwritten by the entry that follows it.
				for n := range last {
					if n == w || strings.HasPrefix(n, w+"/") {
						last[n] = underHit{kind: hitGone}
					}
				}
				return nil
			}
			if !match(name, h) {
				if scope != nil && scope(name) && !found[name] && !isDeleted(name, deleted) && !underAnyOpaque(name, opaque) {
					last[name] = underHit{kind: hitGone}
				}
				return nil
			}
			// Checked BEFORE found[name], so a whiteout in a newer layer still
			// hides an older layer's copy of a file this pass has not seen.
			if isDeleted(name, deleted) || underAnyOpaque(name, opaque) {
				return nil
			}
			switch h.Typeflag {
			case tar.TypeSymlink, tar.TypeLink, tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont:
				layerNonDir[name] = true
			}
			if found[name] {
				return nil
			}
			switch h.Typeflag {
			case tar.TypeSymlink, tar.TypeLink:
				// Recorded so a lower layer's regular file does not take its
				// place: the link is what this image has at that path, and
				// silently substituting a shadowed file would report a package
				// version the image does not ship.
				last[name] = underHit{kind: hitLink, linkname: h.Linkname, hard: h.Typeflag == tar.TypeLink}
			case tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont:
				rd := r
				if sniff != nil {
					head := make([]byte, sniffBytes)
					n, err := io.ReadFull(r, head)
					if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
						return err
					}
					if !sniff(name, head[:n]) {
						last[name] = underHit{kind: hitGone}
						return nil
					}
					rd = io.MultiReader(bytes.NewReader(head[:n]), r)
				}
				b, err := img.readEntry(name, rd)
				if err != nil {
					return err
				}
				last[name] = underHit{kind: hitFile, data: b}
			default:
				// A directory, device or FIFO at this name: the image has no
				// file here, and a lower layer's copy is shadowed (A10).
				last[name] = underHit{kind: hitGone}
			}
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("read layer %s: %w", l.DiffID, err)
		}

		// A file or link here replaced whatever lower layers hold beneath
		// the name, whether or not an upper layer decided the name again (a
		// directory put back above a symlink holds only what that layer
		// wrote; PR #275 review). Merged after the layer: it hides lower
		// layers only.
		for name := range layerNonDir {
			replaced[name] = true
		}
		for name, hit := range last {
			// An ancestor mark for a name an upper layer already decided.
			if found[name] {
				continue
			}
			found[name] = true
			switch hit.kind {
			case hitFile:
				out[name] = FileFromLayer{Data: hit.data, DiffID: l.DiffID}
			case hitLink:
				// Recorded once per name the image ends up with a link at,
				// not per link entry: a link a later entry replaced is not
				// a file this scan failed to read.
				if keepTargets {
					links[name] = Link{Target: hit.linkname, Hard: hit.hard, DiffID: l.DiffID}
				} else {
					links[name] = Link{}
				}
			}
		}
		for k := range layerDeleted {
			deleted[k] = true
		}
		opaque = append(opaque, layerOpaque...)
	}
	return out, links, nil
}

// FilesNamed returns every regular file matching dir/*/filename — one level
// DEEPER than FilesUnder's direct children (D97).
//
// pacman's local package database is a directory of directories:
// /var/lib/pacman/local/<name>-<version>-<pkgrel>/desc, one subdirectory per
// installed package, each holding exactly one file worth reading. FilesUnder
// alone cannot express this: dir's own direct children are package
// subdirectories, not files, so a FilesUnder("var/lib/pacman/local") call
// would return nothing (subdirectories are not regular files) plus
// ALPM_DB_VERSION, a real direct-child FILE this cataloger must not try to
// parse as a package. FilesNamed matches PAST that middle directory
// component instead, so ALPM_DB_VERSION is excluded by construction — its
// base name is not "desc" AND it is not one path segment deeper than dir —
// without this function or its caller needing to special-case it.
//
// The package subdirectory names themselves (which is the whole point of
// discovering them rather than asking for them by name, FilesUnder's own
// doc comment) are recoverable from each result key's own path — the caller
// does not need a second return value for them.
//
// Layer semantics are copied from FilesUnder verbatim, for the identical
// reason: newest layer wins, a whiteout hides only the layers still to be
// read, and an opaque marker on a directory hides everything beneath it in
// lower layers. A distroless-style image built by copying one base's
// package database over another's is exactly where those rules decide the
// inventory, the same as they do for dpkg's status.d.
//
// Symlinks are counted and NOT followed, for FilesUnder's reason: no real
// pacman database measured carries one, and a silent skip of a package's
// desc file is the failure this project ranks worst.
//
// D112's bounds hold here for FilesUnder's reason.
func (img *Image) FilesNamed(ctx context.Context, dir, filename string) (map[string]FileFromLayer, int, error) {
	prefix := normaliseEntry(dir)
	if prefix == "" || prefix == "." {
		return nil, 0, fmt.Errorf("source: FilesNamed needs a directory, got %q", dir)
	}
	if filename == "" {
		return nil, 0, fmt.Errorf("source: FilesNamed needs a filename, got %q", filename)
	}

	return img.collect(ctx, prefix, func(name string) bool {
		// The file must be named exactly filename, AND its immediate parent
		// directory must itself be a direct child of prefix — one level
		// deeper than FilesUnder matches. path.Dir on the cleaned parent
		// strips exactly the package-subdirectory component, leaving prefix
		// on a match.
		d, base := path.Split(name)
		return base == filename && path.Dir(path.Clean(d)) == prefix
	})
}

// FilesMatching returns every regular file ANYWHERE under dir whose base
// name starts with prefix and ends with suffix (D99).
//
// Bitnami's own SPDX markers are why FilesUnder and FilesNamed both fall
// short: a marker file is named ".spdx-<component>.spdx" — the component
// name varies per file, so there is no single exact filename FilesNamed
// could be given — and one directory can hold SEVERAL of them at once
// (measured on a real redis image: common/.spdx-nss-wrapper.spdx sits beside
// common/.spdx-wait-for-port.spdx), which FilesNamed's own "at most one
// match per subdirectory" pacman shape does not express either.
//
// Matching is RECURSIVE — any depth under dir, not a fixed one level below
// it — chosen over a fixed-depth rule even though every marker measured
// 2026-08-27 across three real pulled images (postgresql, its legacy Debian
// twin, and redis) sits at exactly one level under opt/bitnami
// (opt/bitnami/<component>/.spdx-*.spdx): the walk below is already a full
// per-layer scan the way FilesUnder's is, so matching at any depth costs
// nothing extra over matching at exactly one, and it does not need a second
// new primitive the day Bitnami nests a marker one level deeper (a bundled
// library shipping its own sub-component, say). A fixed-depth-one rule would
// buy nothing today and would have to be revisited the first time reality
// disagreed with it.
//
// Layer semantics are copied from FilesUnder and FilesNamed verbatim, for
// the identical reason both give: newest layer wins, a whiteout hides only
// the layers still to be read, and an opaque marker on a directory hides
// everything beneath it in lower layers.
//
// Symlinks are counted and NOT followed, for FilesUnder's reason: the real
// ".spdx-<name>.json" siblings measured next to every ".spdx-<name>.spdx"
// marker are exactly this shape — a same-named symlink pointing at the real
// file — so a scan that silently followed them would double-catalog every
// marker under two different keys pointing at the same bytes.
//
// D112's bounds hold here for FilesUnder's reason, and matter more: this pass
// runs on every image scanned, Bitnami or not, and matches at any depth.
func (img *Image) FilesMatching(ctx context.Context, dir, prefix, suffix string) (map[string]FileFromLayer, int, error) {
	root := normaliseEntry(dir)
	if root == "" || root == "." {
		return nil, 0, fmt.Errorf("source: FilesMatching needs a directory, got %q", dir)
	}
	if prefix == "" && suffix == "" {
		return nil, 0, fmt.Errorf("source: FilesMatching needs a prefix or a suffix, got neither")
	}

	return img.collect(ctx, root, func(name string) bool {
		// ANY depth under root, not just a direct child: the file's parent
		// must be root itself or a descendant of it. Compared as a
		// path-segment prefix ("root/") rather than a bare string prefix, so
		// "opt/bitnami2" does not falsely match "opt/bitnami".
		d, base := path.Split(name)
		parent := path.Clean(d)
		if parent != root && !strings.HasPrefix(parent, root+"/") {
			return false
		}
		return base != "" && strings.HasPrefix(base, prefix) && strings.HasSuffix(base, suffix)
	})
}

// SortedNames orders a FilesUnder result. The map's own iteration order is
// random, and design goal #3 is output that does not churn between runs — an
// inventory whose package order moved every scan would make every report a
// meaningless diff.
func SortedNames(m map[string]FileFromLayer) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FilesProbed is the image probes' one pass (D160): every regular file
// under any of roots that match accepts -- match sees the tar header, so a
// caller can select on mode and size as well as on name -- and whose name and
// first four bytes sniff accepts; a declined entry costs those four bytes and
// is not read. One pass for every location, because a pass reads each layer
// to EOF (D123) and the probes' ten locations would otherwise be ten passes.
// Layer semantics are collect's: newest layer wins, whiteouts and opaque
// markers hide lower layers, and ANY entry under a root at a name -- a
// non-file, or a regular file match or sniff declines -- shadows a lower
// layer's file there (A10): the image has something else at that path.
//
// Symlinks under the roots are counted as every collect caller counts them;
// a probe that does not want them disclosed (a bin directory is mostly
// symlinks) discards the count. D112's bounds hold for the files that ARE
// read, exactly as in Files.
func (img *Image) FilesProbed(ctx context.Context, roots []string, match func(name string, h *tar.Header) bool, sniff func(name string, head []byte) bool) (map[string]FileFromLayer, int, error) {
	out, links, err := img.FilesProbedLinks(ctx, roots, nil, match, sniff)
	return out, len(links), err
}

// FilesProbedLinks is FilesProbed that also returns the link entries it
// found as the final entry at a matched name, with their targets and the
// layer that put them there, instead of only counting them. exact names
// entries outside the roots whose final symlink the pass records -- a
// top-level `bin` or `lib`, whose link says how the image lays out /usr
// (D162) -- at no extra pass. An exact name is never handed to match and
// never read: only a symlink there is recorded.
func (img *Image) FilesProbedLinks(ctx context.Context, roots, exact []string, match func(name string, h *tar.Header) bool, sniff func(name string, head []byte) bool) (map[string]FileFromLayer, map[string]Link, error) {
	if len(roots) == 0 {
		return nil, nil, fmt.Errorf("source: a probe pass needs at least one root")
	}
	norm := make([]string, 0, len(roots))
	for _, r := range roots {
		n := normaliseEntry(r)
		if n == "" || n == "." {
			return nil, nil, fmt.Errorf("source: a probe pass needs a directory, got %q", r)
		}
		norm = append(norm, n)
	}
	if match == nil || sniff == nil {
		return nil, nil, fmt.Errorf("source: a probe pass needs a match and a sniff")
	}
	exactSet := map[string]bool{}
	for _, e := range exact {
		exactSet[normaliseEntry(e)] = true
	}
	inScope := func(name string) bool {
		if exactSet[name] {
			return true
		}
		for _, r := range norm {
			if strings.HasPrefix(name, r+"/") {
				return true
			}
		}
		return false
	}
	return img.collectWith(ctx, norm, func(name string, h *tar.Header) bool {
		if exactSet[name] {
			return h.Typeflag == tar.TypeSymlink
		}
		return inScope(name) && match(name, h)
	}, sniff, inScope, true)
}
