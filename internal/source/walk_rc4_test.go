package source

import (
	"archive/tar"
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
}
