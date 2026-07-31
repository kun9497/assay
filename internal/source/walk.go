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

// Files resolves each wanted path against the image's layers.
//
// Layers are walked NEWEST FIRST and each path is resolved at most once, which
// is what makes a later layer win. Whiteouts recorded on the way down apply
// only to the layers still to be read — the spec is explicit that a whiteout
// affects lower layers only, so one in the base layer must not hide a file a
// later layer installed.
//
// Nothing is written to disk. A scan wants two files out of each layer, so the
// tar is streamed and the wanted entries copied out in passing. Path traversal,
// symlink escape, and archive bombs are extraction vulnerabilities; not
// extracting removes the class rather than defending against it.
//
// A wanted path that no layer carries is absent from the result and is not an
// error: an image with no apk database is a real image, and what that means is
// the caller's decision.
func (img *Image) Files(want []string) (map[string]FileFromLayer, error) {
	wanted := make(map[string]bool, len(want))
	for _, w := range want {
		wanted[normaliseEntry(w)] = true
	}

	out := make(map[string]FileFromLayer, len(want))
	// deleted holds paths whitened out by a layer already read, so they apply
	// to lower layers only. opaque holds directories cleared the same way.
	deleted := map[string]bool{}
	var opaque []string

	for i := len(img.Layers) - 1; i >= 0; i-- {
		l := img.Layers[i]
		// Whiteouts found in THIS layer must not affect this layer's own
		// entries, so they are collected separately and merged after the pass.
		layerDeleted := map[string]bool{}
		var layerOpaque []string

		if err := readLayer(l, func(name string, r io.Reader) error {
			dir, base := path.Split(name)
			switch {
			case base == whiteoutOpaque:
				layerOpaque = append(layerOpaque, path.Clean(dir))
				return nil
			case strings.HasPrefix(base, whiteoutPrefix):
				layerDeleted[path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix))] = true
				return nil
			}
			if !wanted[name] || out[name].DiffID != "" {
				return nil
			}
			if deleted[name] || underAnyOpaque(name, opaque) {
				return nil
			}
			b, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			out[name] = FileFromLayer{Data: b, DiffID: l.DiffID}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("read layer %s: %w", l.DiffID, err)
		}

		for k := range layerDeleted {
			deleted[k] = true
		}
		opaque = append(opaque, layerOpaque...)
	}
	return out, nil
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

func readLayer(l Layer, visit func(name string, r io.Reader) error) error {
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
		if err := visit(normaliseEntry(h.Name), tr); err != nil {
			return err
		}
	}
}
