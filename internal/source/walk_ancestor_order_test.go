package source

import (
	"archive/tar"
	"testing"
)

// QA 2026-11-20. One layer naming an ancestor twice: the later entry is what
// the untar leaves.
func TestFiles_TwoEntriesForOneAncestorInALayer(t *testing.T) {
	db := entry{name: "usr/lib/apk/db/installed", body: "DB"}
	old := entry{name: "lib/apk/db/installed", body: "OLD"}
	for name, tc := range map[string]struct {
		img  *Image
		want string // "" is absent
	}{
		"directory then link": {imageOf(layerOfOrdered(t, "sha256:a", db, node("lib/", tar.TypeDir), sym("lib", "usr/lib"))), "DB"},
		"link then directory": {imageOf(layerOfOrdered(t, "sha256:a", db, sym("lib", "usr/lib"), node("lib/", tar.TypeDir))), ""},
		"link, then directory, over a lower copy": {imageOf(
			layerOfOrdered(t, "sha256:a", old),
			layerOfOrdered(t, "sha256:b", db, sym("lib", "usr/lib"), node("lib/", tar.TypeDir))), "OLD"},
		"directory, then link, over a lower copy": {imageOf(
			layerOfOrdered(t, "sha256:a", old),
			layerOfOrdered(t, "sha256:b", db, node("lib/", tar.TypeDir), sym("lib", "usr/lib"))), "DB"},
		"a directory above replaces the link below": {imageOf(
			layerOfOrdered(t, "sha256:a", db, sym("lib", "usr/lib")),
			layerOfOrdered(t, "sha256:b", node("lib/", tar.TypeDir))), ""},
		"a directory then a file": {imageOf(
			layerOfOrdered(t, "sha256:a", old),
			layerOfOrdered(t, "sha256:b", node("lib/", tar.TypeDir), entry{name: "lib", body: "x"})), ""},
		"another ancestor's directory does not undo the link": {imageOf(
			layerOfOrdered(t, "sha256:b", db, sym("lib", "usr/lib"), node("lib/apk/", tar.TypeDir))), "DB"},
	} {
		f, ok := filesOne(t, tc.img, "lib/apk/db/installed")
		if ok != (tc.want != "") || string(f.Data) != tc.want {
			t.Errorf("%s: %q (present=%v), want %q", name, f.Data, ok, tc.want)
		}
	}
}
