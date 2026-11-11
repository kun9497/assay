package source

import (
	"archive/tar"
	"testing"
)

// Release check 2026-11-11: a symlink at a strict ancestor of a wanted path
// re-roots the query, as the kernel continues at the link's target. The
// limitation deferred at PR #275 -- a target whose parent directory an upper
// layer replaced with a symlink was read from the lower layer's copy -- is
// closed here.
func TestFiles_SymlinkAtAnAncestorIsFollowed(t *testing.T) {
	t.Run("upper layer re-points the directory", func(t *testing.T) {
		img := imageOf(
			layerOfOrdered(t, "sha256:base",
				entry{name: "opt/current/package.json", body: "OLD"},
				entry{name: "opt/version2/package.json", body: "NEW"},
			),
			layerOfOrdered(t, "sha256:top", sym("opt/current", "/opt/version2")),
		)
		f, ok := filesOne(t, img, "opt/current/package.json")
		if !ok || string(f.Data) != "NEW" {
			t.Errorf("got %q (present=%v), want NEW: the upper layer's link at opt/current leads below it", f.Data, ok)
		}
		if f.ViaDiffID != "sha256:top" {
			t.Errorf("ViaDiffID = %q, want the link's layer", f.ViaDiffID)
		}
	})
	t.Run("relative target resolves from the ancestor's directory", func(t *testing.T) {
		img := imageOf(
			layerOfOrdered(t, "sha256:base",
				entry{name: "opt/current/package.json", body: "OLD"},
				entry{name: "opt/version2/package.json", body: "NEW"},
			),
			layerOfOrdered(t, "sha256:top", sym("opt/current", "version2")),
		)
		if f, ok := filesOne(t, img, "opt/current/package.json"); !ok || string(f.Data) != "NEW" {
			t.Errorf("got %q (present=%v), want NEW: `version2` is relative to opt/, the link's own directory", f.Data, ok)
		}
	})
	t.Run("a link two levels up", func(t *testing.T) {
		img := imageOf(
			layerOfOrdered(t, "sha256:base", entry{name: "usr/lib/sysimage/rpm/Packages", body: "DB"}),
			layerOfOrdered(t, "sha256:top", sym("var/lib/rpm", "../../usr/lib/sysimage/rpm")),
		)
		if f, ok := filesOne(t, img, "var/lib/rpm/Packages"); !ok || string(f.Data) != "DB" {
			t.Errorf("got %q (present=%v), want DB through var/lib/rpm -> ../../usr/lib/sysimage/rpm", f.Data, ok)
		}
	})
	t.Run("a regular file at an ancestor in an upper layer hides the lower tree", func(t *testing.T) {
		img := imageOf(
			layerOfOrdered(t, "sha256:base", entry{name: "usr/lib/node_modules/lodash/package.json", body: "OLD"}),
			layerOfOrdered(t, "sha256:top", entry{name: "usr/lib/node_modules/lodash", body: "a file now"}),
		)
		if f, ok := filesOne(t, img, "usr/lib/node_modules/lodash/package.json"); ok {
			t.Errorf("got %q, want absent: the path's parent is a file in the upper layer (A10)", f.Data)
		}
	})
	t.Run("same layer: the entry by name wins over the ancestor link", func(t *testing.T) {
		// A tar that carries `lib -> usr/lib` AND `lib/apk/db/installed`:
		// the untar writes the entry through the link, so the name reaches
		// it; read by name, as before this rule.
		img := imageOf(layerOfOrdered(t, "sha256:one",
			sym("lib", "usr/lib"),
			entry{name: "lib/apk/db/installed", body: "P:busybox"},
		))
		if f, ok := filesOne(t, img, "lib/apk/db/installed"); !ok || string(f.Data) != "P:busybox" {
			t.Errorf("got %q (present=%v), want the entry by name", f.Data, ok)
		}
	})
	t.Run("a directory entry at an ancestor decides nothing", func(t *testing.T) {
		img := imageOf(
			layerOfOrdered(t, "sha256:base", entry{name: "etc/os-release", body: "ID=alpine"}),
			layerOfOrdered(t, "sha256:top", node("etc", tar.TypeDir)),
		)
		if f, ok := filesOne(t, img, "etc/os-release"); !ok || string(f.Data) != "ID=alpine" {
			t.Errorf("got %q (present=%v), want the lower layer's file under an upper directory entry", f.Data, ok)
		}
	})
}
