package source

import (
	"archive/tar"
	"testing"
)

// Release check 2026-11-11 (main 5197df4): the layer rules the resolver had
// still read wrong.

// An explicit directory entry at an ancestor in an upper layer replaces a
// lower layer's symlink there (the changeset rules merge only directory over
// directory): the database behind the old link is not read. A whiteout
// beside the directory reads the same; a directory over a directory keeps
// the lower files; a hardlink keeps the inode of the layer that made it.
func TestFiles_DirectoryAboveReplacesALowerSymlink(t *testing.T) {
	lower := layerOfOrdered(t, "sha256:base",
		sym("lib/apk/db", "/opt/old-apk"),
		entry{name: "opt/old-apk/installed", body: "OLD"},
	)
	t.Run("directory over the link", func(t *testing.T) {
		img := imageOf(lower, layerOfOrdered(t, "sha256:top", node("lib/apk/db", tar.TypeDir), entry{name: "lib/apk/db/README", body: "moved"}))
		if f, ok := filesOne(t, img, "lib/apk/db/installed"); ok {
			t.Errorf("got %q, want absent: the upper layer's directory replaced the link, and holds no installed", f.Data)
		}
	})
	t.Run("whiteout and directory over the link (control)", func(t *testing.T) {
		img := imageOf(lower, layerOfOrdered(t, "sha256:top", entry{name: "lib/apk/.wh.db"}, node("lib/apk/db", tar.TypeDir), entry{name: "lib/apk/db/README", body: "moved"}))
		if f, ok := filesOne(t, img, "lib/apk/db/installed"); ok {
			t.Errorf("got %q, want absent", f.Data)
		}
	})
	t.Run("directory over a directory keeps the lower files", func(t *testing.T) {
		img := imageOf(
			layerOfOrdered(t, "sha256:base", node("lib/apk/db", tar.TypeDir), entry{name: "lib/apk/db/installed", body: "LOWER"}),
			layerOfOrdered(t, "sha256:top", node("lib/apk/db", tar.TypeDir), entry{name: "lib/apk/db/README", body: "x"}),
		)
		if f, ok := filesOne(t, img, "lib/apk/db/installed"); !ok || string(f.Data) != "LOWER" {
			t.Errorf("got %q (present=%v), want LOWER: two directories merge", f.Data, ok)
		}
	})
	t.Run("an implied directory above does not replace the link", func(t *testing.T) {
		// Entries beneath the name with no entry for the name: the untar
		// creates the path through the existing link.
		img := imageOf(lower, layerOfOrdered(t, "sha256:top", entry{name: "lib/apk/db/README", body: "x"}))
		if f, ok := filesOne(t, img, "lib/apk/db/installed"); !ok || string(f.Data) != "OLD" {
			t.Errorf("got %q (present=%v), want OLD through the link", f.Data, ok)
		}
	})
	t.Run("a hardlink keeps its layer's inode under a later directory", func(t *testing.T) {
		img := imageOf(
			layerOfOrdered(t, "sha256:base", entry{name: "opt/db", body: "INODE"}, hard("lib/apk/db/installed", "opt/db")),
			layerOfOrdered(t, "sha256:top", node("opt", tar.TypeDir), entry{name: "opt/db", body: "REWRITTEN"}),
		)
		if f, ok := filesOne(t, img, "lib/apk/db/installed"); !ok || string(f.Data) != "INODE" {
			t.Errorf("got %q (present=%v), want INODE (D130)", f.Data, ok)
		}
	})
}

// A ".." inside a link target is applied only once the component before it
// is known (lazyDotDot): a symlink there re-roots the path first; a plain
// directory, explicit or implied, folds it after the pass.
func TestFiles_DotDotAfterALinkComponentIsLazy(t *testing.T) {
	t.Run("through a link: the .. applies to the link's target", func(t *testing.T) {
		img := imageOf(layerOfOrdered(t, "sha256:one",
			sym("opt/route", "/srv/nested/deep"),
			node("srv/nested/deep", tar.TypeDir),
			entry{name: "srv/nested/qa-db", body: "RIGHT"},
			entry{name: "opt/qa-db", body: "WRONG"},
			sym("lib/apk/db/installed", "/opt/route/../qa-db"),
		))
		f, ok := filesOne(t, img, "lib/apk/db/installed")
		if !ok || string(f.Data) != "RIGHT" {
			t.Errorf("got %q (present=%v), want RIGHT: opt/route leads to srv/nested/deep, whose parent holds qa-db", f.Data, ok)
		}
	})
	t.Run("through a plain directory: the .. folds", func(t *testing.T) {
		img := imageOf(layerOfOrdered(t, "sha256:one",
			node("opt/route", tar.TypeDir),
			entry{name: "opt/qa-db", body: "RIGHT"},
			sym("lib/apk/db/installed", "/opt/route/../qa-db"),
		))
		if f, ok := filesOne(t, img, "lib/apk/db/installed"); !ok || string(f.Data) != "RIGHT" {
			t.Errorf("got %q (present=%v), want RIGHT", f.Data, ok)
		}
	})
	t.Run("through an implied directory: the .. folds after the pass", func(t *testing.T) {
		img := imageOf(layerOfOrdered(t, "sha256:one",
			entry{name: "opt/route/x", body: "x"},
			entry{name: "opt/qa-db", body: "RIGHT"},
			sym("lib/apk/db/installed", "/opt/route/../qa-db"),
		))
		if f, ok := filesOne(t, img, "lib/apk/db/installed"); !ok || string(f.Data) != "RIGHT" {
			t.Errorf("got %q (present=%v), want RIGHT", f.Data, ok)
		}
	})
	t.Run("a .. that applies to the link's own directory folds at once", func(t *testing.T) {
		img := imageOf(layerOfOrdered(t, "sha256:one",
			entry{name: "usr/lib/os-release", body: "ID=alpine"},
			sym("etc/os-release", "../usr/lib/os-release"),
		))
		if f, ok := filesOne(t, img, "etc/os-release"); !ok || string(f.Data) != "ID=alpine" {
			t.Errorf("got %q (present=%v), want the file", f.Data, ok)
		}
	})
	t.Run("a wanted path given with .. is answered under the caller's spelling", func(t *testing.T) {
		img := imageOf(layerOfOrdered(t, "sha256:one",
			sym("opt/route", "/srv/nested/deep"),
			entry{name: "srv/nested/qa-db", body: "RIGHT"},
		))
		got, err := img.Files(t.Context(), []string{"opt/route/../qa-db"})
		if err != nil {
			t.Fatal(err)
		}
		if f, ok := got["opt/route/../qa-db"]; !ok || string(f.Data) != "RIGHT" {
			t.Errorf("got %v, want RIGHT under the given key", got)
		}
	})
}
