package source

import (
	"archive/tar"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/types"
)

// The same-layer whiteout order is one rule for every layer, whatever media
// type its descriptor carries (release review of v0.18.0, 2026-11-12): a
// rule keyed on the type had judged one image two ways by delivery path,
// because the tarball reader reports every docker-archive layer as a Docker
// layer whatever the manifest said. The rule is the OCI image spec's: a
// whiteout hides lower layers only, so this layer's own entry before the
// marker stands (v0.18.1, after the independent review of 2026-11-12).
func TestFiles_WhiteoutOrderDoesNotDependOnTheLayerMediaType(t *testing.T) {
	const file = "data/db"
	stream, err := layerOfOrdered(t, "fixture", entry{name: file, body: "DB"}, entry{name: "data/.wh.db"}).Open()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	raw, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mt   types.MediaType
		kept bool
	}{{types.OCIUncompressedLayer, true}, {types.OCILayer, true}, {types.DockerUncompressedLayer, true}, {types.DockerLayer, true}} {
		t.Run(string(tc.mt), func(t *testing.T) {
			v, _, _ := d123Image(t, raw, raw, tc.mt)
			img, err := fromV1(v)
			if err != nil {
				t.Fatal(err)
			}
			_, exact := filesOne(t, img, file)
			files, _, err := img.FilesUnder(context.Background(), "data")
			_, listed := files[file]
			if err != nil || exact != tc.kept || listed != tc.kept {
				t.Fatalf("exact=%v listed=%v error=%v; want present=%v", exact, listed, err, tc.kept)
			}
		})
	}
}

// A directory a layer creates and then whiteouts in the same tar stands: the
// marker hides lower layers only (OCI image spec), so the layer's own word
// for the component is kept and a `..` folds over it in either order. The
// marker still hides a LOWER layer's directory of that name (control).
// Goes red when the marker withdraws the layer's own word again.
func TestFiles_DotDotOverADirectoryTheSameLayerWhiteoutsAfterCreating(t *testing.T) {
	const db = "lib/apk/db/installed"
	for _, upper := range [][]entry{
		{node("data/marker", tar.TypeDir), {name: "data/.wh.marker"}},
		{{name: "data/.wh.marker"}, node("data/marker", tar.TypeDir)},
	} {
		img := imageOf(
			layerOfOrdered(t, "base", entry{name: "data/packages", body: "DB"}, sym(db, "/data/marker/../packages")),
			layerOfOrdered(t, "upper", upper...))
		if f, ok := filesOne(t, img, db); !ok || string(f.Data) != "DB" {
			t.Fatalf("database = %q, present=%v; want DB through the directory this layer holds", f.Data, ok)
		}
	}
	// Control: the marker hides the lower layer's directory, and nothing in
	// its own layer puts one back, so the fold leads nowhere.
	img := imageOf(
		layerOfOrdered(t, "base", node("data/marker", tar.TypeDir), entry{name: "data/packages", body: "DB"}, sym(db, "/data/marker/../packages")),
		layerOfOrdered(t, "upper", entry{name: "data/.wh.marker"}))
	if f, ok := filesOne(t, img, db); ok {
		t.Fatalf("database read through a directory an upper layer whited out: %q", f.Data)
	}
}

func TestFiles_ClimbsUseTheCurrentLayerTree(t *testing.T) {
	const db = "lib/apk/db/installed"
	for _, tc := range []struct {
		name  string
		upper []entry
	}{
		{"whiteout then child", []entry{{name: "data/.wh.marker"}, {name: "data/marker/new", body: "new"}}},
		{"opaque directory without its own directory header", []entry{{name: "data/marker/.wh..wh..opq"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := imageOf(layerOfOrdered(t, "base", node("data/first", tar.TypeDir), node("data/marker", tar.TypeDir), entry{name: "data/packages", body: "DB"}, sym(db, "/data/first/../marker/../packages")), layerOfOrdered(t, "upper", tc.upper...))
			if f, ok := filesOne(t, img, db); !ok || string(f.Data) != "DB" {
				t.Fatalf("database = %q, present=%v", f.Data, ok)
			}
		})
	}
	t.Run("old subdirectory behind a replaced ancestor", func(t *testing.T) {
		img := imageOf(layerOfOrdered(t, "base", node("data/first", tar.TypeDir), node("data/route/sub", tar.TypeDir), node("srv/active/deep", tar.TypeDir), sym("srv/root/sub", "/srv/active/deep"), entry{name: "srv/active/packages", body: "DB"}, entry{name: "srv/root/packages", body: "WRONG"}), layerOfOrdered(t, "upper", sym("data/route", "/srv/root"), sym(db, "/data/first/../route/sub/../packages")))
		if f, ok := filesOne(t, img, db); !ok || string(f.Data) != "DB" {
			t.Fatalf("database = %q, present=%v", f.Data, ok)
		}
	})
}

func TestFiles_RepeatedRequestForALinkIsNotACycle(t *testing.T) {
	img := imageOf(layerOfOrdered(t, "base", entry{name: "target", body: "DB"}, hard("alias", "target")))
	got, err := img.Files(context.Background(), []string{"alias", "alias"})
	if err != nil || string(got["alias"].Data) != "DB" || len(img.Unresolved()) != 0 {
		t.Fatalf("files=%v unresolved=%v error=%v", got, img.Unresolved(), err)
	}
}

// Release check of main 60c512c: a ".." inside a link target folds one
// component at a time. `/data/marker/../route/../packages` enters marker (a
// directory), goes up, enters route and goes up from wherever route LEADS:
// a symlink there is followed before the second ".." applies, and a
// deletion or a file put over route in an upper layer ends the path, whatever
// the lower layer had at the name.
func TestFiles_DotDotFoldsOneComponentAtATime(t *testing.T) {
	const want = "lib/apk/db/installed"
	lower := func(extra ...entry) Layer {
		return layerOfOrdered(t, "sha256:lower", append([]entry{
			node("data/marker", tar.TypeDir),
			node("srv/active/deep", tar.TypeDir),
			entry{name: "srv/active/packages", body: "RIGHT"},
			entry{name: "data/packages", body: "WRONG"},
			sym(want, "/data/marker/../route/../packages"),
		}, extra...)...)
	}
	t.Run("marker a directory, route a symlink: the second .. applies to route's target", func(t *testing.T) {
		img := imageOf(lower(sym("data/route", "/srv/active/deep")))
		if f, ok := filesOne(t, img, want); !ok || string(f.Data) != "RIGHT" {
			t.Errorf("got %q (present=%v), want RIGHT: route leads to srv/active/deep, whose parent holds packages", f.Data, ok)
		}
	})
	t.Run("route a real directory below, deleted above: the path leads nowhere", func(t *testing.T) {
		img := imageOf(lower(node("data/route", tar.TypeDir)), layerOfOrdered(t, "sha256:upper", entry{name: "data/.wh.route", body: ""}))
		if f, ok := filesOne(t, img, want); ok {
			t.Errorf("got %q, want nothing: route is gone, and data/packages is not where the link leads", f.Data)
		}
	})
	t.Run("route a real directory below, a regular file above: the path leads nowhere", func(t *testing.T) {
		img := imageOf(lower(node("data/route", tar.TypeDir)), layerOfOrdered(t, "sha256:upper", entry{name: "data/route", body: "ordinary file"}))
		if f, ok := filesOne(t, img, want); ok {
			t.Errorf("got %q, want nothing: a file is not a directory to go up from", f.Data)
		}
	})
	t.Run("route a real directory: both fold (control)", func(t *testing.T) {
		img := imageOf(lower(node("data/route", tar.TypeDir)))
		if f, ok := filesOne(t, img, want); !ok || string(f.Data) != "WRONG" {
			t.Errorf("got %q (present=%v), want the file at data/packages: two plain directories fold", f.Data, ok)
		}
	})
	t.Run("route a symlink to a symlink: each hop before its ..", func(t *testing.T) {
		img := imageOf(lower(sym("data/route", "/srv/hop"), sym("srv/hop", "/srv/active/deep")))
		if f, ok := filesOne(t, img, want); !ok || string(f.Data) != "RIGHT" {
			t.Errorf("got %q (present=%v), want RIGHT", f.Data, ok)
		}
	})
	t.Run("the two folds are not link hops", func(t *testing.T) {
		img := imageOf(lower(sym("data/route", "/srv/active/deep")))
		if _, err := img.Files(t.Context(), []string{want}); err != nil {
			t.Fatal(err)
		}
		for _, u := range img.Unresolved() {
			t.Errorf("unresolved %v, want none", u)
		}
	})
	t.Run("route a symlink below, a directory above: the newest layer's word (fold)", func(t *testing.T) {
		img := imageOf(lower(sym("data/route", "/srv/active/deep")), layerOfOrdered(t, "sha256:upper", node("data/route", tar.TypeDir)))
		if f, ok := filesOne(t, img, want); !ok || string(f.Data) != "WRONG" {
			t.Errorf("got %q (present=%v), want the file at data/packages: the directory above replaced the link", f.Data, ok)
		}
	})
	t.Run("route a symlink, entries beneath it in the same layer: the link stands", func(t *testing.T) {
		// A tar may carry `data/route -> ...` and then `data/route/x`: the
		// untar writes x through the link, and route is still the link.
		img := imageOf(lower(sym("data/route", "/srv/active/deep"), entry{name: "data/route/x", body: "x"}))
		if f, ok := filesOne(t, img, want); !ok || string(f.Data) != "RIGHT" {
			t.Errorf("got %q (present=%v), want RIGHT: the explicit link is not overridden by entries beneath", f.Data, ok)
		}
	})
	t.Run("twenty-one folds between twenty-one links are twenty-one links, not forty-two", func(t *testing.T) {
		// /opt/d/../l/../ repeated: d a directory (fold), l a link to the
		// other tree (hop), whose parent holds the next d and l. After 21
		// pairs the path stands in srv.
		img := imageOf(layerOfOrdered(t, "sha256:one",
			node("opt/d", tar.TypeDir), node("srv/d", tar.TypeDir), node("opt/x", tar.TypeDir), node("srv/x", tar.TypeDir),
			sym("opt/l", "/srv/x"), sym("srv/l", "/opt/x"),
			entry{name: "srv/packages", body: "RIGHT"}, entry{name: "opt/packages", body: "WRONG"},
			sym(want, "/opt/"+strings.Repeat("d/../l/../", 21)+"packages"),
		))
		if f, ok := filesOne(t, img, want); !ok || string(f.Data) != "RIGHT" {
			t.Errorf("got %q (present=%v), want RIGHT: 21 links are within the limit", f.Data, ok)
		}
		for _, u := range img.Unresolved() {
			t.Errorf("unresolved %v, want none", u)
		}
	})
}

// PR #290 review: a component the upper layer recreates -- after a whiteout
// of it, with an opaque marker inside it (`RUN rm -rf /data/marker && mkdir
// /data/marker`), or as a directory over a lower layer's symlink -- is a
// directory, and the ".." after it folds although the lower layers are
// hidden; and entries beneath a name in a newer layer do not turn an older
// layer's symlink there into a directory (the untar writes them through the
// link).
func TestFiles_DotDotOverAComponentAnUpperLayerRecreated(t *testing.T) {
	const want = "lib/apk/db/installed"
	lower := func(extra ...entry) Layer {
		return layerOfOrdered(t, "sha256:lower", append([]entry{
			entry{name: "data/packages", body: "DB"},
			sym(want, "/data/marker/../packages"),
		}, extra...)...)
	}
	for _, tc := range []struct {
		name  string
		lower Layer
		upper []entry
	}{
		{"opaque marker inside the recreated directory", lower(node("data/marker", tar.TypeDir)), []entry{node("data/marker", tar.TypeDir), entry{name: "data/marker/.wh..wh..opq", body: ""}}},
		{"a whiteout then the directory again", lower(node("data/marker", tar.TypeDir)), []entry{entry{name: "data/.wh.marker", body: ""}, node("data/marker", tar.TypeDir)}},
		{"a directory over a lower symlink", lower(sym("data/marker", "/srv/elsewhere"), node("srv/elsewhere", tar.TypeDir)), []entry{node("data/marker", tar.TypeDir)}},
		{"the whole tree recreated above", lower(node("data/marker", tar.TypeDir)), []entry{entry{name: "data/.wh..wh..opq", body: ""}, node("data/marker", tar.TypeDir), entry{name: "data/packages", body: "DB"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := imageOf(tc.lower, layerOfOrdered(t, "sha256:upper", tc.upper...))
			if f, ok := filesOne(t, img, want); !ok || string(f.Data) != "DB" {
				t.Errorf("got %q (present=%v), want DB: marker is a directory in the upper layer, so the .. folds to data/packages", f.Data, ok)
			}
			for _, u := range img.Unresolved() {
				t.Errorf("unresolved %v, want none", u)
			}
		})
	}
	t.Run("a whiteout of the component with nothing recreated leads nowhere (control)", func(t *testing.T) {
		img := imageOf(lower(node("data/marker", tar.TypeDir)), layerOfOrdered(t, "sha256:upper", entry{name: "data/.wh.marker", body: ""}))
		if f, ok := filesOne(t, img, want); ok {
			t.Errorf("got %q, want nothing", f.Data)
		}
	})
	t.Run("entries beneath a lower symlink in a newer layer: the link stands", func(t *testing.T) {
		img := imageOf(layerOfOrdered(t, "sha256:lower",
			node("data/marker", tar.TypeDir), sym("data/route", "/srv/active/deep"), node("srv/active/deep", tar.TypeDir),
			entry{name: "srv/active/packages", body: "RIGHT"}, entry{name: "data/packages", body: "WRONG"},
			sym(want, "/data/marker/../route/../packages"),
		), layerOfOrdered(t, "sha256:upper", entry{name: "data/route/x", body: "x"}))
		if f, ok := filesOne(t, img, want); !ok || string(f.Data) != "RIGHT" {
			t.Errorf("got %q (present=%v), want RIGHT: data/route/x was written through the standing link", f.Data, ok)
		}
	})
	t.Run("a whiteout of the component below, entries beneath it above: the newer directory stands", func(t *testing.T) {
		img := imageOf(layerOfOrdered(t, "sha256:lower",
			entry{name: "data/.wh.marker", body: ""}, entry{name: "data/packages", body: "DB"}, sym(want, "/data/marker/../packages"),
		), layerOfOrdered(t, "sha256:upper", entry{name: "data/marker/x", body: "x"}))
		if f, ok := filesOne(t, img, want); !ok || string(f.Data) != "DB" {
			t.Errorf("got %q (present=%v), want DB: the older deletion does not undo the newer directory", f.Data, ok)
		}
	})
	t.Run("entries beneath a name no layer has an entry for: an implied directory (control)", func(t *testing.T) {
		img := imageOf(layerOfOrdered(t, "sha256:lower",
			entry{name: "data/packages", body: "DB"}, sym(want, "/data/marker/../packages"),
		), layerOfOrdered(t, "sha256:upper", entry{name: "data/marker/x", body: "x"}))
		if f, ok := filesOne(t, img, want); !ok || string(f.Data) != "DB" {
			t.Errorf("got %q (present=%v), want DB", f.Data, ok)
		}
	})
}
