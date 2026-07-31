package source

import (
	"archive/tar"
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
// symlinks.
//
// Layers are walked NEWEST FIRST and each path is resolved at most once, which
// is what makes a later layer win. Whiteouts recorded on the way down apply
// only to the layers still to be read — the spec is explicit that a whiteout
// affects lower layers only, so one in the base layer must not hide a file a
// later layer installed.
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
func (img *Image) Files(want []string) (map[string]FileFromLayer, error) {
	// requested keeps the caller's names so the result is keyed the way they
	// asked, even when the bytes came from a link target several hops away.
	requested := make(map[string]string, len(want)) // resolved path -> caller's name
	pending := make(map[string]bool, len(want))
	for _, w := range want {
		n := normaliseEntry(w)
		requested[n] = n
		pending[n] = true
	}

	out := make(map[string]FileFromLayer, len(want))
	for hop := 0; hop < maxSymlinkHops && len(pending) > 0; hop++ {
		links, err := img.resolvePass(pending, requested, out)
		if err != nil {
			return nil, err
		}
		// Whatever is still pending either does not exist or was a symlink.
		next := make(map[string]bool, len(links))
		for from, target := range links {
			if _, done := out[requested[from]]; done {
				continue
			}
			requested[target] = requested[from]
			next[target] = true
		}
		pending = next
	}
	return out, nil
}

// resolvePass reads every layer once, filling out[] for pending paths that are
// regular files and returning the ones that turned out to be symlinks.
func (img *Image) resolvePass(
	pending map[string]bool,
	requested map[string]string,
	out map[string]FileFromLayer,
) (map[string]string, error) {
	links := map[string]string{}
	resolved := map[string]bool{}
	deleted := map[string]bool{}
	var opaque []string

	for i := len(img.Layers) - 1; i >= 0; i-- {
		l := img.Layers[i]
		// Whiteouts found in THIS layer must not affect this layer's own
		// entries, so they are collected separately and merged after the pass.
		layerDeleted := map[string]bool{}
		var layerOpaque []string

		err := readLayer(l, func(name string, h *tar.Header, r io.Reader) error {
			dir, base := path.Split(name)
			switch {
			case base == whiteoutOpaque:
				layerOpaque = append(layerOpaque, path.Clean(dir))
				return nil
			case strings.HasPrefix(base, whiteoutPrefix):
				layerDeleted[path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix))] = true
				return nil
			}
			if !pending[name] || resolved[name] {
				return nil
			}
			if isDeleted(name, deleted) || underAnyOpaque(name, opaque) {
				return nil
			}
			switch h.Typeflag {
			case tar.TypeSymlink, tar.TypeLink:
				// Record the link and stop looking for this path: a lower
				// layer's copy is shadowed by the link that replaced it.
				//
				// The two kinds resolve differently. A symlink's target is
				// relative to the link's own directory; a hardlink's is
				// relative to the archive root. Treating a hardlink like a
				// symlink turns "usr/lib/os-release" into
				// "etc/usr/lib/os-release" and finds nothing.
				links[name] = resolveLink(name, h.Linkname, h.Typeflag == tar.TypeLink)
				resolved[name] = true
				return nil
			case tar.TypeReg:
				b, err := io.ReadAll(r)
				if err != nil {
					return err
				}
				out[requested[name]] = FileFromLayer{Data: b, DiffID: l.DiffID}
				resolved[name] = true
				return nil
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("read layer %s: %w", l.DiffID, err)
		}

		for k := range layerDeleted {
			deleted[k] = true
		}
		opaque = append(opaque, layerOpaque...)
	}
	return links, nil
}

// resolveLink turns a link target into a path from the image root.
//
// A SYMLINK's relative target is relative to the directory holding the link,
// which is why the link's own path is needed and not just its target. A
// HARDLINK's Linkname is always relative to the archive root instead, so
// joining it to the link's directory would invent a path that does not exist.
func resolveLink(from, target string, hard bool) string {
	if hard || strings.HasPrefix(target, "/") {
		return normaliseEntry(target)
	}
	return normaliseEntry(path.Join(path.Dir(from), target))
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

func readLayer(l Layer, visit func(name string, h *tar.Header, r io.Reader) error) error {
	rc, err := l.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if err := visit(normaliseEntry(h.Name), h, tr); err != nil {
			return err
		}
	}
}
