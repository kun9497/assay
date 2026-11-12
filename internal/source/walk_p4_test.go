package source

import (
	"archive/tar"
	"context"
	"fmt"
	"testing"
)

// Audit 2026-10-22 P4, re-verified 2026-11-02. (A): a name written twice in
// ONE layer is, on disk, its last entry -- docker's and containerd's untar
// and GNU tar all replace as they go -- and the walk kept the first. (B): a
// symlink chain was cut at seven links, Linux follows forty, and a chain cut
// off or a cycle came back as an absent file. The caller tests are in
// scancmd's layer_walk_p4_test.go; these hold the rows the caller cannot
// reach one by one.

func filesOne(t *testing.T, img *Image, want string) (FileFromLayer, bool) {
	t.Helper()
	got, err := img.Files(context.Background(), []string{want})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := got[want]
	return f, ok
}

func TestFiles_P4_LastEntryInALayerWins(t *testing.T) {
	const db = "lib/apk/db/installed"
	for _, tc := range []struct {
		name    string
		layers  [][]entry // base first
		want    string    // "" = absent
		wantDig string
	}{
		{"file twice", [][]entry{{{name: db, body: "FIRST"}, {name: db, body: "LAST"}}}, "LAST", "sha256:l0"},
		{"file then symlink", [][]entry{{{name: db, body: "FIRST"}, {name: "lib/apk/db/real", body: "VIA-LINK"}, sym(db, "real")}}, "VIA-LINK", "sha256:l0"},
		{"symlink then file", [][]entry{{{name: "lib/apk/db/real", body: "VIA-LINK"}, sym(db, "real"), {name: db, body: "LAST"}}}, "LAST", "sha256:l0"},
		{"file then directory", [][]entry{{{name: db, body: "FIRST"}, node(db, tar.TypeDir)}}, "", ""},
		{"directory then file", [][]entry{{node(db, tar.TypeDir), {name: db, body: "LAST"}}}, "LAST", "sha256:l0"},
		{"child then file", [][]entry{{{name: db + "/x", body: "child"}, {name: db, body: "LAST"}}}, "LAST", "sha256:l0"},
		{"file then child", [][]entry{{{name: db, body: "FIRST"}, {name: db + "/x", body: "child"}}}, "", ""},
		{"file then whiteout, lower layer shadowed", [][]entry{
			{{name: db, body: "BASE"}},
			{{name: db, body: "FIRST"}, {name: "lib/apk/db/.wh.installed"}},
		}, "FIRST", "sha256:l1"},
		{"file then whiteout of an ancestor", [][]entry{{{name: db, body: "FIRST"}, {name: "lib/.wh.apk"}}}, "FIRST", "sha256:l0"},
		{"whiteout then file", [][]entry{{{name: "lib/apk/db/.wh.installed"}, {name: db, body: "LAST"}}}, "LAST", "sha256:l0"},
		// Both untars clear only what LOWER layers put under an opaque
		// directory, whatever the order.
		{"file then opaque marker", [][]entry{{{name: db, body: "KEPT"}, {name: "lib/apk/db/.wh..wh..opq"}}}, "KEPT", "sha256:l0"},
		// Across layers nothing changed: the newest layer still wins.
		{"upper layer still wins", [][]entry{{{name: db, body: "BASE"}}, {{name: db, body: "TOP"}}}, "TOP", "sha256:l1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ls []Layer
			for i, es := range tc.layers {
				ls = append(ls, layerOfOrdered(t, fmt.Sprintf("sha256:l%d", i), es...))
			}
			f, ok := filesOne(t, imageOf(ls...), db)
			if tc.want == "" {
				if ok {
					t.Fatalf("got %q from %s, want absent", f.Data, f.DiffID)
				}
				return
			}
			if !ok || string(f.Data) != tc.want || f.DiffID != tc.wantDig {
				t.Fatalf("got %q from %s (present=%v), want %q from %s", f.Data, f.DiffID, ok, tc.want, tc.wantDig)
			}
		})
	}
}

// D130 inside one layer: a hardlink holds what stood at its target when the
// link entry was reached. A later entry rewriting the target -- which now wins
// for the target's own name -- or a later whiteout of it does not reach the
// link's inode.
func TestFiles_P4_HardlinkHoldsTheTargetAsOfItsEntry(t *testing.T) {
	t.Run("rewritten after the link", func(t *testing.T) {
		img := imageOf(layerOfOrdered(t, "sha256:one",
			entry{name: "tmp/pkgdb", body: "AT-LINK-TIME"},
			hard("lib/apk/db/installed", "tmp/pkgdb"),
			entry{name: "tmp/pkgdb", body: "REWRITTEN"},
		))
		got, err := img.Files(context.Background(), []string{"lib/apk/db/installed", "tmp/pkgdb"})
		if err != nil {
			t.Fatal(err)
		}
		if f := got["lib/apk/db/installed"]; string(f.Data) != "AT-LINK-TIME" {
			t.Errorf("hardlinked name = %q, want AT-LINK-TIME: the link holds the inode it was made to", f.Data)
		}
		if f := got["tmp/pkgdb"]; string(f.Data) != "REWRITTEN" {
			t.Errorf("tmp/pkgdb = %q, want REWRITTEN: the name's last entry", f.Data)
		}
	})
	t.Run("whited out after the link", func(t *testing.T) {
		img := imageOf(
			layerOfOrdered(t, "sha256:base", entry{name: "tmp/pkgdb", body: "LOWER"}),
			layerOfOrdered(t, "sha256:top",
				hard("lib/apk/db/installed", "tmp/pkgdb"),
				entry{name: "tmp/.wh.pkgdb"},
			),
		)
		if f, ok := filesOne(t, img, "lib/apk/db/installed"); !ok || string(f.Data) != "LOWER" {
			t.Errorf("got %q (present=%v), want LOWER: the whiteout came after the link was made", f.Data, ok)
		}
	})
	t.Run("whited out before the link", func(t *testing.T) {
		img := imageOf(
			layerOfOrdered(t, "sha256:base", entry{name: "tmp/pkgdb", body: "LOWER"}),
			layerOfOrdered(t, "sha256:top",
				entry{name: "tmp/.wh.pkgdb"},
				hard("lib/apk/db/installed", "tmp/pkgdb"),
			),
		)
		if f, ok := filesOne(t, img, "lib/apk/db/installed"); ok {
			t.Errorf("got %q, want absent: the target was gone when the link entry was reached", f.Data)
		}
	})
	t.Run("same-layer target only after the link", func(t *testing.T) {
		img := imageOf(
			layerOfOrdered(t, "sha256:base", entry{name: "tmp/pkgdb", body: "LOWER"}),
			layerOfOrdered(t, "sha256:top",
				hard("lib/apk/db/installed", "tmp/pkgdb"),
				entry{name: "tmp/pkgdb", body: "AFTER-LINK"},
			),
		)
		if f, ok := filesOne(t, img, "lib/apk/db/installed"); !ok || string(f.Data) != "LOWER" {
			t.Errorf("got %q (present=%v), want LOWER: at the link entry the name still held the lower file", f.Data, ok)
		}
	})
}

// chain is n symlinks from start to final, absolute targets.
func chain(start, final string, n int) []entry {
	var es []entry
	from := start
	for i := 1; i < n; i++ {
		to := fmt.Sprintf("hop/%02d", i)
		es = append(es, sym(from, "/"+to))
		from = to
	}
	return append(es, sym(from, "/"+final))
}

func TestFiles_P4_SymlinkChainLimit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		links      int
		unresolved bool
	}{
		{"1 link", 1, false},
		{"8 links (cut off before the fix)", 8, false},
		{"40 links", 40, false},
		{"41 links", 41, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			es := append([]entry{{name: "usr/lib/os-release", body: "ID=alpine"}}, chain("etc/os-release", "usr/lib/os-release", tc.links)...)
			img := imageOf(layerOfOrdered(t, "sha256:one", es...))
			f, ok := filesOne(t, img, "etc/os-release")
			u := img.Unresolved()
			if tc.unresolved {
				if ok {
					t.Errorf("got %q, want no file: Linux refuses a 41st link", f.Data)
				}
				if len(u) != 1 || u[0].Path != "etc/os-release" || u[0].Reason != unresolvedLinks {
					t.Errorf("Unresolved = %+v, want exactly etc/os-release", u)
				}
				return
			}
			if !ok || string(f.Data) != "ID=alpine" {
				t.Errorf("got %q (present=%v), want ID=alpine through %d link(s)", f.Data, ok, tc.links)
			}
			if len(u) != 0 {
				t.Errorf("Unresolved = %+v, want none", u)
			}
		})
	}
}

// An absent path and a dangling link are not unresolved: the walk finished,
// and the answer is that there is no file. Only a chain cut off is.
func TestFiles_P4_AbsentAndDanglingAreNotUnresolved(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one", sym("etc/os-release", "/nowhere")))
	got, err := img.Files(context.Background(), []string{"etc/os-release", "lib/apk/db/installed"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want nothing", got)
	}
	if u := img.Unresolved(); len(u) != 0 {
		t.Errorf("Unresolved = %+v, want none", u)
	}
}

// Unresolved collects across Files calls on one image, names each path once,
// and comes back sorted.
func TestImage_P4_UnresolvedAccumulatesSortedAndDeduplicated(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "sha256:one",
		sym("z", "y"), sym("y", "z"),
		sym("b", "a"), sym("a", "b"),
	))
	for _, want := range [][]string{{"z"}, {"b", "z"}} {
		if _, err := img.Files(context.Background(), want); err != nil {
			t.Fatal(err)
		}
	}
	u := img.Unresolved()
	if len(u) != 2 || u[0].Path != "b" || u[1].Path != "z" {
		t.Errorf("Unresolved = %+v, want b then z, once each", u)
	}
}

// (A) for the three discovering walks, which share collect.
func TestFilesUnder_P4_LastEntryInALayerWins(t *testing.T) {
	const dir = "var/lib/dpkg/status.d"
	const name = dir + "/libc6"
	for _, tc := range []struct {
		name      string
		layers    [][]entry
		want      string // "" = absent
		wantLinks int
	}{
		{"file twice", [][]entry{{{name: name, body: "FIRST"}, {name: name, body: "LAST"}}}, "LAST", 0},
		{"file then symlink", [][]entry{{{name: name, body: "FIRST"}, sym(name, "elsewhere")}}, "", 1},
		{"symlink then file", [][]entry{{sym(name, "elsewhere"), {name: name, body: "LAST"}}}, "LAST", 0},
		{"file then directory", [][]entry{{{name: name, body: "FIRST"}, node(name, tar.TypeDir)}}, "", 0},
		{"child then file", [][]entry{{{name: name + "/x", body: "child"}, {name: name, body: "LAST"}}}, "LAST", 0},
		{"file then child", [][]entry{{{name: name, body: "FIRST"}, {name: name + "/x", body: "child"}}}, "", 0},
		{"file then whiteout, lower layer shadowed", [][]entry{
			{{name: name, body: "BASE"}},
			{{name: name, body: "FIRST"}, {name: dir + "/.wh.libc6"}},
		}, "FIRST", 0},
		{"whiteout then file", [][]entry{{{name: dir + "/.wh.libc6"}, {name: name, body: "LAST"}}}, "LAST", 0},
		// A whiteout of an ancestor also applies only to lower layers.
		{"file then whiteout of its directory", [][]entry{{{name: name, body: "FIRST"}, {name: "var/lib/dpkg/.wh.status.d"}}}, "FIRST", 0},
		{"file then opaque marker", [][]entry{{{name: name, body: "KEPT"}, {name: dir + "/.wh..wh..opq"}}}, "KEPT", 0},
		{"upper layer still wins", [][]entry{{{name: name, body: "BASE"}}, {{name: name, body: "TOP"}}}, "TOP", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ls []Layer
			for i, es := range tc.layers {
				ls = append(ls, layerOfOrdered(t, fmt.Sprintf("sha256:l%d", i), es...))
			}
			got, links, err := imageOf(ls...).FilesUnder(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			f, ok := got[name]
			if tc.want == "" && ok || tc.want != "" && string(f.Data) != tc.want {
				t.Errorf("got %q (present=%v), want %q", f.Data, ok, tc.want)
			}
			if links != tc.wantLinks {
				t.Errorf("links = %d, want %d", links, tc.wantLinks)
			}
		})
	}
}

func TestFilesNamedAndMatching_P4_LastEntryInALayerWins(t *testing.T) {
	const desc = "var/lib/pacman/local/zlib-1.3-1/desc"
	const marker = "opt/bitnami/redis/.spdx-redis.spdx"
	img := imageOf(layerOfOrdered(t, "sha256:one",
		entry{name: desc, body: "DESC-FIRST"},
		entry{name: marker, body: "SPDX-FIRST"},
		entry{name: desc, body: "DESC-LAST"},
		entry{name: marker, body: "SPDX-LAST"},
	))
	named, _, err := img.FilesNamed(context.Background(), "var/lib/pacman/local", "desc")
	if err != nil {
		t.Fatal(err)
	}
	if f := named[desc]; string(f.Data) != "DESC-LAST" {
		t.Errorf("FilesNamed = %q, want DESC-LAST", f.Data)
	}
	matched, _, err := img.FilesMatching(context.Background(), "opt/bitnami", ".spdx-", ".spdx")
	if err != nil {
		t.Fatal(err)
	}
	if f := matched[marker]; string(f.Data) != "SPDX-LAST" {
		t.Errorf("FilesMatching = %q, want SPDX-LAST", f.Data)
	}
}
