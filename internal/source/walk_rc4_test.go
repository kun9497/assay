package source

import (
	"archive/tar"
	"strings"
	"testing"
)

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
