package source

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path"
	"strings"
)

// FileFromLayer is a file's contents together with the layer they came from.
// The layer is carried because it becomes Location.LayerDigest, and "which
// layer introduced this package" is the question a reader asks next.
type FileFromLayer struct {
	Data   []byte
	DiffID string
}

// Whiteout markers, from the OCI image-spec (layer.md).
//
// They are instructions to a reader assembling the filesystem, not files. A
// reader that returns them hands the next stage the literal bytes of a marker;
// a reader that ignores them reports packages that were uninstalled.
const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"
)

// maxSymlinkHops bounds link chasing. A cycle (a -> b -> a) would otherwise
// spin, and real images do not chain more than two or three deep.
const maxSymlinkHops = 8

// Files resolves each wanted path against the image's layers, following
// symlinks and hardlinks.
//
// Layers are walked NEWEST FIRST and each path is resolved at most once, which
// is what makes a later layer win. Whiteouts recorded on the way down apply
// only to the layers still to be read — the spec is explicit that a whiteout
// affects lower layers only, so one in the base layer must not hide a file a
// later layer installed. A hardlink is the one exception to newest-wins: its
// target is the inode of the layer that made the link, so it is resolved from
// that layer down and a later layer's rewrite of the target's name does not
// reach it (D130, see query).
//
// Symlinks are not optional to handle. /etc/os-release is a regular file in
// alpine:3.19 and a symlink to ../usr/lib/os-release in alpine:3.21,
// alpine:latest, debian:12 and ubuntu:24.04 — one layer of that image carries
// 335 symlinks against 191 regular files. Reading a symlink's tar entry yields
// zero bytes, so a reader that treats it as a file reports "found it, here is
// nothing" for a path it never resolved.
//
// Nothing is written to disk. A scan wants a couple of files out of each layer,
// so the tar is streamed and the wanted entries copied out in passing. Path
// traversal, symlink escape, and archive bombs are extraction vulnerabilities;
// not extracting removes the class rather than defending against it.
//
// A wanted path that no layer carries is absent from the result and is not an
// error: an image with no apk database is a real image, and what that means is
// the caller's decision.
//
// Every file copied out is bounded by MaxFileBytes and counted against the
// image's MaxScanBytes budget, and ctx is checked between tar entries (D112):
// an over-limit file, an exhausted budget or a cancelled context is an error,
// never a shorter result.
func (img *Image) Files(ctx context.Context, want []string) (map[string]FileFromLayer, error) {
	newest := len(img.Layers) - 1
	qs := make([]query, 0, len(want))
	for _, w := range want {
		n := normaliseEntry(w)
		qs = append(qs, query{path: n, want: n, top: newest, dir: path.Dir(n)})
	}

	out := make(map[string]FileFromLayer, len(want))
	for hop := 0; hop < maxSymlinkHops && len(qs) > 0; hop++ {
		next, err := img.resolvePass(ctx, qs, out)
		if err != nil {
			return nil, err
		}
		// Whatever comes back was a link; whatever came back nothing either
		// does not exist or was answered.
		qs = next
	}
	return out, nil
}

// query is one path still being resolved: the caller's name it will answer
// under, and the newest layer it may be satisfied from.
//
// top is what tells a hardlink from a symlink (D130). A symlink resolves by
// NAME at runtime, so its target is looked up from the newest layer down like
// any other path. A hardlink is a second name for the inode as it was in the
// layer that made the link: a later layer that whites out and rewrites the
// target's name has changed that name, not the inode the link still holds. So
// a hardlink found in layer i re-queues its target with top = i -- that layer
// and the ones beneath it, never above -- and the whiteouts above i do not
// apply to it either. Found by the 2026-10-20 external review (#4): a package
// database hardlinked from a scratch path that a later layer rewrote came
// back as the rewritten database.
//
// dir is the directory the name was reached THROUGH, which is what a relative
// symlink target resolves against: the kernel resolves it from the directory
// of the name being opened, and for a hardlink to a relative symlink that is
// the hardlink's directory, not the symlink entry's. For every chain without
// a hardlink the two coincide.
type query struct {
	path string
	want string
	top  int
	dir  string
}

// whiteout is one deletion marker and the layer that wrote it. A marker in
// layer j hides a name from a read of any layer below j -- for a query that
// may see layer j at all (q.top >= j).
type whiteout struct {
	name  string
	layer int
}

// resolvePass reads every layer once, newest first, answering queries whose
// path is a regular file and returning a follow-up query for each one that
// turned out to be a link. One tar entry may answer several queries: two
// wanted names that resolve to the same target both get it (the first
// implementation kept only the last requester per target path).
func (img *Image) resolvePass(ctx context.Context, qs []query, out map[string]FileFromLayer) ([]query, error) {
	var next []query
	done := make([]bool, len(qs))
	var deleted, opaque []whiteout

	for i := len(img.Layers) - 1; i >= 0; i-- {
		l := img.Layers[i]
		// Whiteouts found in THIS layer must not affect this layer's own
		// entries, so they are collected separately and merged after the pass.
		var layerDeleted, layerOpaque []whiteout

		err := readLayer(ctx, l, func(name string, h *tar.Header, r io.Reader) error {
			// An entry anywhere under a wanted path -- a file, a directory, a
			// whiteout or opaque marker inside it -- makes that path a
			// directory in this layer, and a directory is not the file the
			// query wants: the query ends here, unanswered, so no lower
			// layer's deleted copy answers it (audit A10). A file turned into
			// a directory writes "<name>/" and maybe "<name>/.wh..wh..opq",
			// never ".wh.<name>", so the whiteout rules do not see it.
			for k, q := range qs {
				if !done[k] && i <= q.top && strings.HasPrefix(name, q.path+"/") && !hiddenFrom(q.path, i, q.top, deleted, opaque) {
					done[k] = true
				}
			}
			dir, base := path.Split(name)
			switch {
			case base == whiteoutOpaque:
				layerOpaque = append(layerOpaque, whiteout{path.Clean(dir), i})
				return nil
			case strings.HasPrefix(base, whiteoutPrefix):
				layerDeleted = append(layerDeleted, whiteout{path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix)), i})
				return nil
			}
			var hits []int
			for k, q := range qs {
				if done[k] || q.path != name || i > q.top {
					continue
				}
				if hiddenFrom(name, i, q.top, deleted, opaque) {
					continue
				}
				hits = append(hits, k)
			}
			if len(hits) == 0 {
				return nil
			}
			switch h.Typeflag {
			case tar.TypeSymlink, tar.TypeLink:
				// Record the link and stop looking for this path: a lower
				// layer's copy is shadowed by the link that replaced it.
				//
				// The two kinds resolve differently, twice over. A symlink's
				// target is relative to the link's own directory; a hardlink's
				// is relative to the archive root -- treating a hardlink like a
				// symlink turns "usr/lib/os-release" into "etc/usr/lib/os-release"
				// and finds nothing. And a symlink's target is looked up from
				// the newest layer, a hardlink's from this one down (see query).
				hard := h.Typeflag == tar.TypeLink
				top := len(img.Layers) - 1
				if hard {
					top = i
				}
				// Per query, not per entry: two queries can reach one symlink
				// through different hardlinks and resolve its relative
				// target from different directories.
				for _, k := range hits {
					done[k] = true
					q := qs[k]
					target := resolveLink(q.dir, h.Linkname, hard)
					dir := q.dir // a hardlink keeps the directory it was reached through
					if !hard {
						dir = path.Dir(target)
					}
					next = append(next, query{path: target, want: q.want, top: top, dir: dir})
				}
				return nil
			case tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont:
				b, err := img.readEntry(name, r)
				if err != nil {
					return err
				}
				for _, k := range hits {
					done[k] = true
					out[qs[k].want] = FileFromLayer{Data: b, DiffID: l.DiffID}
				}
				return nil
			default:
				// A directory, device or FIFO at the wanted path: this layer
				// has something there that is not a file, so the path holds
				// no file to read, and a lower layer's copy is shadowed
				// (A10). The query ends unanswered, as for an absent file.
				for _, k := range hits {
					done[k] = true
				}
				return nil
			}
		})
		if err != nil {
			return nil, fmt.Errorf("read layer %s: %w", l.DiffID, err)
		}

		deleted = append(deleted, layerDeleted...)
		opaque = append(opaque, layerOpaque...)
	}
	return next, nil
}

// hiddenFrom reports whether a whiteout hides name from a read of layer i, for
// a query allowed to see layers up to top: the marker must sit above i (a
// whiteout affects lower layers only) and at or below top (a hardlink made in
// a lower layer never sees a later layer's deletions). The directory and
// opaque rules are isDeleted's and underAnyOpaque's.
func hiddenFrom(name string, i, top int, deleted, opaque []whiteout) bool {
	for _, d := range deleted {
		if d.layer > i && d.layer <= top && (name == d.name || strings.HasPrefix(name, d.name+"/")) {
			return true
		}
	}
	for _, o := range opaque {
		if o.layer > i && o.layer <= top && (o.name == "." || strings.HasPrefix(name, o.name+"/")) {
			return true
		}
	}
	return false
}

// resolveLink turns a link target into a path from the image root.
//
// A SYMLINK's relative target is relative to the directory the link was
// reached through (query.dir), which is why that directory is needed and not
// just the target. A HARDLINK's Linkname is always relative to the archive
// root instead, so joining it to any directory would invent a path that does
// not exist.
func resolveLink(dir, target string, hard bool) string {
	if hard || strings.HasPrefix(target, "/") {
		return normaliseEntry(target)
	}
	return normaliseEntry(path.Join(dir, target))
}

// isDeleted reports whether a whiteout covers this path.
//
// A whiteout names a path, and that path may be a directory: `RUN rm -rf
// /lib/apk` emits `lib/.wh.apk`, which deletes everything beneath it. Matching
// only exactly would leave the packages of a deleted apk database reported as
// installed.
func isDeleted(name string, deleted map[string]bool) bool {
	if deleted[name] {
		return true
	}
	for d := range deleted {
		if strings.HasPrefix(name, d+"/") {
			return true
		}
	}
	return false
}

// shadowAncestors records, as found, every directory strictly below root that
// name sits under: an entry at "root/x/y" in this layer makes "root/x" a
// directory here, so a lower layer's regular file "root/x" is shadowed and
// must not be returned (audit A10). A file turned into a directory carries no
// ".wh.<name>", so the whiteout rules never see it. Recorded whatever the
// entry is -- a file, a directory, a whiteout or opaque marker -- because each
// proves the directory exists in this layer; a whiteout that hides the
// directory itself also hides the lower file, so marking it is never wrong.
func shadowAncestors(found map[string]bool, name, root string) {
	if !strings.HasPrefix(name, root+"/") {
		return
	}
	for p := path.Dir(name); p != root && p != "." && p != "/"; p = path.Dir(p) {
		found[p] = true
	}
}

func underAnyOpaque(name string, dirs []string) bool {
	for _, d := range dirs {
		if d == "." {
			return true
		}
		if strings.HasPrefix(name, d+"/") {
			return true
		}
	}
	return false
}

// normaliseEntry makes tar names comparable. Builders disagree on the leading
// "./" and on trailing slashes for directories, and comparing raw names makes a
// lookup succeed or fail depending on which tool built the image — an empty
// inventory rather than an error.
func normaliseEntry(name string) string {
	n := path.Clean("/" + name)
	return strings.TrimPrefix(n, "/")
}

// readLayer streams one layer's tar entries to visit.
//
// ctx is checked before every entry (D112), so a cancelled or expired scan
// stops at the next entry rather than at the end of the layer — a layer is
// the unit an attacker controls the size of, and a scan makes several full
// passes over every one. The error is ctx's own, unwrapped here, so
// errors.Is still recognises it after each caller's "read layer <diff id>"
// wrapping names where the walk was.
//
// A single entry is not interrupted part-way. A wanted one is bounded in
// size by MaxFileBytes; an unwanted one is skipped by tar.Reader.Next, which
// reads through it before the next check runs, so a docker-archive or
// oci-dir layer holding one enormous entry delays an expired context by
// however long that entry takes to decompress. A registry layer does not
// have that gap: its blob is fetched on a request carrying the same context,
// so the read itself fails once the context is done.
func readLayer(ctx context.Context, l Layer, visit func(name string, h *tar.Header, r io.Reader) error) error {
	rc, err := l.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err == io.EOF {
			// The archive's end marker is not the stream's end: drain to EOF
			// so the layer's digest is checked before its entries count
			// (D123). Returning here was a clean scan of unverified bytes.
			return drainLayer(ctx, rc)
		}
		if err != nil {
			return err
		}
		// Directory entries are visited too: a directory at a wanted path, or
		// at a file's place in a lower layer, shadows that file (A10). Every
		// visitor reads only TypeReg entries as file content.
		if err := visit(normaliseEntry(h.Name), h, tr); err != nil {
			return err
		}
	}
}
