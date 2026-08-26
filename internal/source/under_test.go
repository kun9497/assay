package source

import (
	"testing"
)

// namesOf renders a FilesUnder result deterministically for comparison. It goes
// through SortedNames rather than ranging the map, so a test cannot pass on an
// iteration order the production path does not share.
func namesOf(m map[string]FileFromLayer) []string { return SortedNames(m) }

func bodiesOf(t *testing.T, m map[string]FileFromLayer) map[string]string {
	t.Helper()
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = string(v.Data)
	}
	return out
}

// TestFilesUnder_DirectChildrenOnly. status.d is flat, and recursing would feed
// this cataloger files from some future image shape that it would then try to
// parse as dpkg stanzas.
//
// The fixture deliberately contains three things a loose prefix match would
// pull in: a file one level deeper, the directory entry itself, and a sibling
// directory whose name has status.d as a prefix.
func TestFilesUnder_DirectChildrenOnly(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		entry{name: "var/lib/dpkg/status.d/base-files", body: "Package: base-files"},
		entry{name: "var/lib/dpkg/status.d/libc6", body: "Package: libc6"},
		entry{name: "var/lib/dpkg/status.d/nested/deeper", body: "Package: nope"},
		entry{name: "var/lib/dpkg/status.d.old/libssl", body: "Package: nope"},
		entry{name: "var/lib/dpkg/status", body: "Package: nope"},
	))
	got, links, err := img.FilesUnder("var/lib/dpkg/status.d")
	if err != nil {
		t.Fatal(err)
	}
	if links != 0 {
		t.Errorf("symlinks = %d, want 0", links)
	}
	want := []string{"var/lib/dpkg/status.d/base-files", "var/lib/dpkg/status.d/libc6"}
	if g := namesOf(got); len(g) != 2 || g[0] != want[0] || g[1] != want[1] {
		t.Errorf("FilesUnder = %v, want exactly %v", g, want)
	}
}

// TestFilesUnder_NewestLayerWins. A distroless image built by copying one
// base's status.d over another's is exactly where this decides the inventory:
// without it the reported version is whichever layer the walk happened to read
// last.
func TestFilesUnder_NewestLayerWins(t *testing.T) {
	img := imageOf(
		layerOfOrdered(t, "sha256:base",
			entry{name: "var/lib/dpkg/status.d/libc6", body: "Version: 1.0"},
			entry{name: "var/lib/dpkg/status.d/only-in-base", body: "Version: 9.9"},
		),
		layerOfOrdered(t, "sha256:top",
			entry{name: "var/lib/dpkg/status.d/libc6", body: "Version: 2.0"},
		),
	)
	got, _, err := img.FilesUnder("var/lib/dpkg/status.d")
	if err != nil {
		t.Fatal(err)
	}
	b := bodiesOf(t, got)
	if b["var/lib/dpkg/status.d/libc6"] != "Version: 2.0" {
		t.Errorf("libc6 = %q, want the newer layer's 2.0", b["var/lib/dpkg/status.d/libc6"])
	}
	// The base's own stanza must survive: newest-wins is per path, not per
	// directory, and an implementation that stopped at the first layer holding
	// anything would drop this.
	if b["var/lib/dpkg/status.d/only-in-base"] != "Version: 9.9" {
		t.Errorf("only-in-base = %q, want the base layer's stanza to survive",
			b["var/lib/dpkg/status.d/only-in-base"])
	}
	if got["var/lib/dpkg/status.d/libc6"].DiffID != "sha256:top" {
		t.Errorf("DiffID = %q, want sha256:top", got["var/lib/dpkg/status.d/libc6"].DiffID)
	}
}

// TestFilesUnder_WhiteoutHidesLowerLayers. `RUN rm` on a stanza emits a .wh.
// marker, and an inventory that still listed the package would report a
// vulnerability for something the image does not ship.
func TestFilesUnder_WhiteoutHidesLowerLayers(t *testing.T) {
	img := imageOf(
		layerOfOrdered(t, "sha256:base",
			entry{name: "var/lib/dpkg/status.d/removed", body: "Package: removed"},
			entry{name: "var/lib/dpkg/status.d/kept", body: "Package: kept"},
		),
		layerOfOrdered(t, "sha256:top",
			entry{name: "var/lib/dpkg/status.d/.wh.removed", body: ""},
		),
	)
	got, _, err := img.FilesUnder("var/lib/dpkg/status.d")
	if err != nil {
		t.Fatal(err)
	}
	if g := namesOf(got); len(g) != 1 || g[0] != "var/lib/dpkg/status.d/kept" {
		t.Errorf("FilesUnder = %v, want only the kept stanza", g)
	}
}

// TestFilesUnder_WhiteoutDoesNotHideItsOwnLayer. The spec is explicit that a
// whiteout affects LOWER layers only. A layer that deletes a stanza and writes
// a new one at the same path in the same step must keep the new one — get this
// wrong and an upgraded package vanishes from the inventory entirely, which is
// a silent miss rather than a wrong version.
func TestFilesUnder_WhiteoutDoesNotHideItsOwnLayer(t *testing.T) {
	img := imageOf(
		layerOfOrdered(t, "sha256:base",
			entry{name: "var/lib/dpkg/status.d/libc6", body: "Version: 1.0"},
		),
		layerOfOrdered(t, "sha256:top",
			entry{name: "var/lib/dpkg/status.d/.wh.libc6", body: ""},
			entry{name: "var/lib/dpkg/status.d/libc6", body: "Version: 2.0"},
		),
	)
	got, _, err := img.FilesUnder("var/lib/dpkg/status.d")
	if err != nil {
		t.Fatal(err)
	}
	if b := bodiesOf(t, got)["var/lib/dpkg/status.d/libc6"]; b != "Version: 2.0" {
		t.Errorf("libc6 = %q, want 2.0 — a whiteout must not hide its own layer's entry", b)
	}
}

// TestFilesUnder_OpaqueHidesEverythingBelow. An opaque marker on the directory
// replaces it wholesale, which is what `COPY --from` of a whole status.d does.
func TestFilesUnder_OpaqueHidesEverythingBelow(t *testing.T) {
	img := imageOf(
		layerOfOrdered(t, "sha256:base",
			entry{name: "var/lib/dpkg/status.d/old-one", body: "Package: old-one"},
			entry{name: "var/lib/dpkg/status.d/old-two", body: "Package: old-two"},
		),
		layerOfOrdered(t, "sha256:top",
			entry{name: "var/lib/dpkg/status.d/.wh..wh..opq", body: ""},
			entry{name: "var/lib/dpkg/status.d/new-one", body: "Package: new-one"},
		),
	)
	got, _, err := img.FilesUnder("var/lib/dpkg/status.d")
	if err != nil {
		t.Fatal(err)
	}
	if g := namesOf(got); len(g) != 1 || g[0] != "var/lib/dpkg/status.d/new-one" {
		t.Errorf("FilesUnder = %v, want only the replacing layer's stanza", g)
	}
}

// TestFilesUnder_SymlinksAreCountedNotFollowed pins the disclosure. A stanza
// this build did not read must not silently disappear from the inventory, and
// the count is what the scan turns into a package whose version is unknown.
//
// The lower layer deliberately holds a regular file at the same path: an
// implementation that let it through would report a version the image does not
// actually ship, which is worse than declining to read the link.
func TestFilesUnder_SymlinksAreCountedNotFollowed(t *testing.T) {
	img := imageOf(
		layerOfOrdered(t, "sha256:base",
			entry{name: "var/lib/dpkg/status.d/libc6", body: "Version: 1.0"},
		),
		layerOfOrdered(t, "sha256:top",
			entry{name: "var/lib/dpkg/status.d/libc6", link: "../status"},
			entry{name: "var/lib/dpkg/status.d/real", body: "Package: real"},
		),
	)
	got, links, err := img.FilesUnder("var/lib/dpkg/status.d")
	if err != nil {
		t.Fatal(err)
	}
	if links != 1 {
		t.Errorf("symlinks = %d, want 1", links)
	}
	if _, ok := got["var/lib/dpkg/status.d/libc6"]; ok {
		t.Errorf("libc6 was returned; the newer layer replaced it with a symlink, so the "+
			"lower layer's regular file is not what this image ships: %q",
			bodiesOf(t, got)["var/lib/dpkg/status.d/libc6"])
	}
	if g := namesOf(got); len(g) != 1 || g[0] != "var/lib/dpkg/status.d/real" {
		t.Errorf("FilesUnder = %v, want only the regular file", g)
	}
}

// TestFilesUnder_AbsentDirectoryIsEmptyNotAnError. An image with no status.d is
// an ordinary image; what that means is the caller's decision, exactly as it is
// for Files.
func TestFilesUnder_AbsentDirectoryIsEmptyNotAnError(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		entry{name: "etc/os-release", body: "ID=debian"},
	))
	got, links, err := img.FilesUnder("var/lib/dpkg/status.d")
	if err != nil {
		t.Fatalf("FilesUnder: %v, want no error for an image without the directory", err)
	}
	if len(got) != 0 || links != 0 {
		t.Errorf("FilesUnder = %v (%d links), want empty", namesOf(got), links)
	}
}

// TestFilesUnder_RefusesTheImageRoot. Nothing wants every regular file in an
// image, and a caller that asked by accident — an empty string reaching this
// from a config — would get an inventory-sized allocation instead of an error.
func TestFilesUnder_RefusesTheImageRoot(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one", entry{name: "etc/os-release", body: "ID=debian"}))
	for _, dir := range []string{"", ".", "/", "./"} {
		if _, _, err := img.FilesUnder(dir); err == nil {
			t.Errorf("FilesUnder(%q) returned no error; the image root must be refused", dir)
		}
	}
}

// TestFilesNamed_MatchesOneLevelDeeper is D97's caller-first proof: pacman's
// local database nests one directory per package
// (var/lib/pacman/local/<name>-<version>/desc), and FilesNamed must find the
// desc files while (a) ignoring a sibling FILE directly inside the parent
// directory that happens to share the same middle path component depth, and
// (b) ignoring a file one level too deep. Both are exactly the shapes
// TestFilesUnder_DirectChildrenOnly pins for FilesUnder's own boundary.
func TestFilesNamed_MatchesOneLevelDeeper(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		entry{name: "var/lib/pacman/local/acl-2.4.0-1/desc", body: "%NAME%\nacl\n"},
		entry{name: "var/lib/pacman/local/bash-5.3.15-1/desc", body: "%NAME%\nbash\n"},
		// ALPM_DB_VERSION: a direct child FILE of local/, not one level
		// deeper, and not named "desc" either — must not be matched by
		// either rule alone, let alone both together.
		entry{name: "var/lib/pacman/local/ALPM_DB_VERSION", body: "9\n"},
		// A file one level too deep (inside a package dir's own
		// subdirectory) must not be matched.
		entry{name: "var/lib/pacman/local/acl-2.4.0-1/files/deeper", body: "nope"},
		// A same-named file directly under local/, not inside a package
		// subdirectory, must not be matched either — filename alone is not
		// enough, the directory nesting has to match too.
		entry{name: "var/lib/pacman/local/desc", body: "nope"},
	))
	got, links, err := img.FilesNamed("var/lib/pacman/local", "desc")
	if err != nil {
		t.Fatal(err)
	}
	if links != 0 {
		t.Errorf("symlinks = %d, want 0", links)
	}
	want := []string{
		"var/lib/pacman/local/acl-2.4.0-1/desc",
		"var/lib/pacman/local/bash-5.3.15-1/desc",
	}
	if g := namesOf(got); len(g) != 2 || g[0] != want[0] || g[1] != want[1] {
		t.Errorf("FilesNamed = %v, want exactly %v", g, want)
	}
}

// TestFilesNamed_NewestLayerWins mirrors TestFilesUnder_NewestLayerWins: a
// package upgraded in a later layer must report that layer's desc, not an
// earlier one's.
func TestFilesNamed_NewestLayerWins(t *testing.T) {
	img := imageOf(
		layerOfOrdered(t, "sha256:base",
			entry{name: "var/lib/pacman/local/bash-5.3.14-1/desc", body: "%VERSION%\n5.3.14-1\n"},
		),
		layerOfOrdered(t, "sha256:top",
			entry{name: "var/lib/pacman/local/bash-5.3.15-1/desc", body: "%VERSION%\n5.3.15-1\n"},
		),
	)
	got, _, err := img.FilesNamed("var/lib/pacman/local", "desc")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("FilesNamed = %v, want both package versions (different directories, not an upgrade in place)",
			namesOf(got))
	}
	if got["var/lib/pacman/local/bash-5.3.15-1/desc"].DiffID != "sha256:top" {
		t.Errorf("bash-5.3.15-1/desc DiffID = %q, want sha256:top",
			got["var/lib/pacman/local/bash-5.3.15-1/desc"].DiffID)
	}
}

// TestFilesNamed_WhiteoutHidesTheWholePackageDirectory mirrors
// TestFilesUnder_WhiteoutHidesLowerLayers, but for a whiteout on the
// PACKAGE DIRECTORY itself (pacman removing a package deletes its whole
// local/<name>-<version>/ directory, not a single file inside it) — proving
// isDeleted's directory-prefix match, not just an exact-path one, still
// applies at this deeper nesting level.
func TestFilesNamed_WhiteoutHidesTheWholePackageDirectory(t *testing.T) {
	img := imageOf(
		layerOfOrdered(t, "sha256:base",
			entry{name: "var/lib/pacman/local/removed-1.0-1/desc", body: "%NAME%\nremoved\n"},
			entry{name: "var/lib/pacman/local/kept-1.0-1/desc", body: "%NAME%\nkept\n"},
		),
		layerOfOrdered(t, "sha256:top",
			entry{name: "var/lib/pacman/local/.wh.removed-1.0-1", body: ""},
		),
	)
	got, _, err := img.FilesNamed("var/lib/pacman/local", "desc")
	if err != nil {
		t.Fatal(err)
	}
	if g := namesOf(got); len(g) != 1 || g[0] != "var/lib/pacman/local/kept-1.0-1/desc" {
		t.Errorf("FilesNamed = %v, want only the kept package's desc", g)
	}
}

// TestFilesNamed_SymlinksAreCountedNotFollowed mirrors
// TestFilesUnder_SymlinksAreCountedNotFollowed.
func TestFilesNamed_SymlinksAreCountedNotFollowed(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		entry{name: "var/lib/pacman/local/linked-1.0-1/desc", link: "../real/desc"},
		entry{name: "var/lib/pacman/local/real-1.0-1/desc", body: "%NAME%\nreal\n"},
	))
	got, links, err := img.FilesNamed("var/lib/pacman/local", "desc")
	if err != nil {
		t.Fatal(err)
	}
	if links != 1 {
		t.Errorf("symlinks = %d, want 1", links)
	}
	if g := namesOf(got); len(g) != 1 || g[0] != "var/lib/pacman/local/real-1.0-1/desc" {
		t.Errorf("FilesNamed = %v, want only the regular file", g)
	}
}

// TestFilesNamed_AbsentDirectoryIsEmptyNotAnError mirrors
// TestFilesUnder_AbsentDirectoryIsEmptyNotAnError: an image with no pacman
// database at all is an ordinary image.
func TestFilesNamed_AbsentDirectoryIsEmptyNotAnError(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		entry{name: "etc/os-release", body: "ID=debian"},
	))
	got, links, err := img.FilesNamed("var/lib/pacman/local", "desc")
	if err != nil {
		t.Fatalf("FilesNamed: %v, want no error for an image without the directory", err)
	}
	if len(got) != 0 || links != 0 {
		t.Errorf("FilesNamed = %v (%d links), want empty", namesOf(got), links)
	}
}

// TestFilesNamed_RefusesTheImageRootOrEmptyFilename mirrors
// TestFilesUnder_RefusesTheImageRoot, plus the one new argument this
// function has that FilesUnder does not.
func TestFilesNamed_RefusesTheImageRootOrEmptyFilename(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one", entry{name: "etc/os-release", body: "ID=debian"}))
	for _, dir := range []string{"", ".", "/", "./"} {
		if _, _, err := img.FilesNamed(dir, "desc"); err == nil {
			t.Errorf("FilesNamed(%q, \"desc\") returned no error; the image root must be refused", dir)
		}
	}
	if _, _, err := img.FilesNamed("var/lib/pacman/local", ""); err == nil {
		t.Error(`FilesNamed("var/lib/pacman/local", "") returned no error; an empty filename must be refused`)
	}
}

// TestFilesNamed_NormalisesTheDirectory mirrors
// TestFilesUnder_NormalisesTheDirectory.
func TestFilesNamed_NormalisesTheDirectory(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		entry{name: "var/lib/pacman/local/acl-2.4.0-1/desc", body: "%NAME%\nacl\n"},
	))
	for _, dir := range []string{
		"var/lib/pacman/local",
		"/var/lib/pacman/local",
		"var/lib/pacman/local/",
		"var/lib/./pacman/local",
	} {
		got, _, err := img.FilesNamed(dir, "desc")
		if err != nil {
			t.Fatalf("FilesNamed(%q, \"desc\"): %v", dir, err)
		}
		if len(got) != 1 {
			t.Errorf("FilesNamed(%q, \"desc\") = %v, want the one desc file", dir, namesOf(got))
		}
	}
}

// TestFilesUnder_NormalisesTheDirectory. Callers spell paths the way the tar
// entries do (no leading slash), but a leading or trailing one must not turn
// into a silent empty result — that is a clean verdict for an image this build
// can actually read.
func TestFilesUnder_NormalisesTheDirectory(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		entry{name: "var/lib/dpkg/status.d/libc6", body: "Package: libc6"},
	))
	for _, dir := range []string{
		"var/lib/dpkg/status.d",
		"/var/lib/dpkg/status.d",
		"var/lib/dpkg/status.d/",
		"var/lib/./dpkg/status.d",
	} {
		got, _, err := img.FilesUnder(dir)
		if err != nil {
			t.Fatalf("FilesUnder(%q): %v", dir, err)
		}
		if len(got) != 1 {
			t.Errorf("FilesUnder(%q) = %v, want the one stanza", dir, namesOf(got))
		}
	}
}
