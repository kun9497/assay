package source

import (
	"archive/tar"
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
func (img *Image) FilesUnder(dir string) (map[string]FileFromLayer, int, error) {
	prefix := normaliseEntry(dir)
	if prefix == "" || prefix == "." {
		// The image root. Refused rather than served: nothing wants every
		// regular file in an image, and a caller that asked for this by
		// accident would get an inventory-sized allocation.
		return nil, 0, fmt.Errorf("source: FilesUnder needs a directory, got %q", dir)
	}

	out := map[string]FileFromLayer{}
	found := map[string]bool{}
	deleted := map[string]bool{}
	var opaque []string
	symlinks := 0

	for i := len(img.Layers) - 1; i >= 0; i-- {
		l := img.Layers[i]
		layerDeleted := map[string]bool{}
		var layerOpaque []string

		err := readLayer(l, func(name string, h *tar.Header, r io.Reader) error {
			d, base := path.Split(name)
			switch {
			case base == whiteoutOpaque:
				layerOpaque = append(layerOpaque, path.Clean(d))
				return nil
			case strings.HasPrefix(base, whiteoutPrefix):
				layerDeleted[path.Join(d, strings.TrimPrefix(base, whiteoutPrefix))] = true
				return nil
			}
			// Direct children only: path.Split leaves the trailing slash on
			// the directory half, so this rejects both a deeper file and the
			// directory entry itself.
			if path.Clean(d) != prefix || base == "" {
				return nil
			}
			// Checked BEFORE found[name], so a whiteout in a newer layer still
			// hides an older layer's copy of a stanza this pass has not seen.
			if isDeleted(name, deleted) || underAnyOpaque(name, opaque) {
				return nil
			}
			if found[name] {
				return nil
			}
			switch h.Typeflag {
			case tar.TypeSymlink, tar.TypeLink:
				symlinks++
				// Marked found so a lower layer's regular file does not take
				// its place: the link is what this image has at that path, and
				// silently substituting a shadowed file would report a package
				// version the image does not ship.
				found[name] = true
				return nil
			case tar.TypeReg:
				b, err := io.ReadAll(r)
				if err != nil {
					return err
				}
				out[name] = FileFromLayer{Data: b, DiffID: l.DiffID}
				found[name] = true
				return nil
			}
			return nil
		})
		if err != nil {
			return nil, 0, fmt.Errorf("read layer %s: %w", l.DiffID, err)
		}

		for k := range layerDeleted {
			deleted[k] = true
		}
		opaque = append(opaque, layerOpaque...)
	}
	return out, symlinks, nil
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
