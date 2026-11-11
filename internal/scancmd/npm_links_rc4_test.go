package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/report"
)

// Release check 2026-11-11 (main 60c512c), end to end: an npm root whose
// external target is itself replaced by an upper layer, the apk database
// behind `marker/../route/../packages`, and the layer every alias of an
// install is located in.
func TestRun_RC4_ReplacedTargetsAndStepwiseDotDot(t *testing.T) {
	v4 := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	v3 := []byte(`{"name":"minimatch","version":"3.0.3"}`)
	const local = "usr/local/lib/node_modules/minimatch/package.json"
	osRel := probeLayerEntry{name: osReleasePath, body: []byte(osReleaseAlpine319)}
	apkVuln := []byte("P:busybox\nV:1.36.1-r0\nA:x86_64\n\n")
	apkClean := []byte("P:qa-owner\nV:1.0-r0\nA:x86_64\n\n")
	dir := func(name string) probeLayerEntry { return probeLayerEntry{name: name, dir: true} }
	base := func(entries ...probeLayerEntry) []probeLayerEntry { return append(alpineLayer(), entries...) }
	// The root -> /opt/current, with /opt/current a lower directory holding
	// a stale copy, and an upper layer putting something else at the name.
	stale := base(probeLayerEntry{name: "opt/current/minimatch/package.json", body: v3}, probeLayerEntry{name: "opt/release/minimatch/package.json", body: v4},
		probeLayerEntry{name: "usr/local/lib/node_modules", link: "/opt/current"})
	// The apk database behind marker/../route/../packages. Exactly one of
	// the three databases holds the vulnerable record, so which one was read
	// shows: the preferred one behind route's target (preferred), the
	// fallback at var/lib (fallback) for a path that leads nowhere, or
	// data/packages (folded) when both ".." fold over plain directories.
	apk := func(vulnerable string, extra ...probeLayerEntry) [][]probeLayerEntry {
		body := func(which string) []byte {
			if which == vulnerable {
				return apkVuln
			}
			return apkClean
		}
		return [][]probeLayerEntry{append([]probeLayerEntry{osRel, probeLayerEntry{name: "var/lib/apk/db/installed", body: body("fallback")}, dir("data/marker"), dir("srv/active/deep"),
			probeLayerEntry{name: "srv/active/packages", body: body("preferred")}, probeLayerEntry{name: "data/packages", body: body("folded")},
			probeLayerEntry{name: "lib/apk/db/installed", link: "/data/marker/../route/../packages"}}, extra...)}
	}
	type want struct {
		versions []string
		paths    []string
		busybox  string
		npm      string
		unread   []string
		code     int
		findings int
	}
	for _, tc := range []struct {
		name   string
		layers [][]probeLayerEntry
		want   want
		apk    bool
	}{
		// --- the target itself replaced above
		{"target re-pointed by a link above (stale copy hidden)", [][]probeLayerEntry{stale, {{name: "opt/current", link: "/opt/release"}}},
			want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1, 1}, false},
		{"the same with a whiteout (control)", [][]probeLayerEntry{stale, {{name: "opt/.wh.current"}, {name: "opt/current", link: "/opt/release"}}},
			want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1, 1}, false},
		{"root linked to the final directory directly (control)", [][]probeLayerEntry{base(probeLayerEntry{name: "opt/release/minimatch/package.json", body: v4}, probeLayerEntry{name: "usr/local/lib/node_modules", link: "/opt/release"})},
			want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1, 1}, false},
		{"target replaced by a regular file above (nothing read, the root unread)", [][]probeLayerEntry{stale, {{name: "opt/current", body: []byte("not a directory")}}},
			want{nil, nil, "", report.ScopePartial, []string{"usr/local/lib/node_modules"}, 2, 0}, false},
		{"the stale copy vulnerable and the link's target fixed (no false finding)", [][]probeLayerEntry{
			base(probeLayerEntry{name: "opt/current/minimatch/package.json", body: v4}, probeLayerEntry{name: "opt/release/minimatch/package.json", body: []byte(`{"name":"minimatch","version":"9.9.9"}`)},
				probeLayerEntry{name: "usr/local/lib/node_modules", link: "/opt/current"}),
			{{name: "opt/current", link: "/opt/release"}}},
			want{nil, nil, "", report.ScopeRead, nil, 0, 0}, false},
		// --- the apk database behind marker/../route/../packages
		{"apk: route a symlink (the preferred database read, BusyBox)", apk("preferred", probeLayerEntry{name: "data/route", link: "/srv/active/deep"}),
			want{nil, nil, "1.36.1-r0", report.ScopeNone, nil, 1, 1}, true},
		{"apk: route a real directory deleted above (fallback database read, BusyBox)", append(apk("fallback", dir("data/route")), []probeLayerEntry{{name: "data/.wh.route"}}),
			want{nil, nil, "1.36.1-r0", report.ScopeNone, nil, 1, 1}, true},
		{"apk: route a real directory, a file above (fallback database read, BusyBox)", append(apk("fallback", dir("data/route")), []probeLayerEntry{{name: "data/route", body: []byte("ordinary file")}}),
			want{nil, nil, "1.36.1-r0", report.ScopeNone, nil, 1, 1}, true},
		{"apk: route a real directory (both fold: data/packages read)", apk("folded", dir("data/route")),
			want{nil, nil, "1.36.1-r0", report.ScopeNone, nil, 1, 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeLayeredProbeImage(t, tarPath, tc.layers...)
			db := probeDB(t)
			if tc.apk {
				db = qa1111DB(t)
			}
			var out, errOut bytes.Buffer
			code := Run(context.Background(), db, "docker-archive:"+tarPath,
				Options{Output: "json", FailOn: &bandLow, FailOnUnknown: true, FailOnIncomplete: true, FailOnIncompleteTarget: true}, &out, &errOut)
			var doc report.Document
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("decode: %v\n%s", err, errOut.String())
			}
			var versions, paths []string
			busybox := ""
			for _, f := range doc.Findings {
				switch f.Package.Name {
				case "minimatch":
					versions = append(versions, f.Package.Version)
					for _, l := range f.Package.Locations {
						paths = append(paths, l.Path)
					}
				case "busybox":
					busybox = f.Package.Version
				}
			}
			state := ""
			for _, a := range doc.InventoryScope.ApplicationScope {
				if a.Ecosystem == "npm" {
					state = a.State
				}
			}
			var unread []string
			for _, u := range doc.Unread {
				unread = append(unread, u.Path)
			}
			got := want{uniqSorted(versions), uniqSorted(paths), busybox, state, uniqSorted(unread), code, len(doc.Findings)}
			if strings.Join(got.versions, ",") != strings.Join(tc.want.versions, ",") || strings.Join(got.paths, ",") != strings.Join(tc.want.paths, ",") ||
				got.busybox != tc.want.busybox || got.npm != tc.want.npm || strings.Join(got.unread, ",") != strings.Join(tc.want.unread, ",") || got.code != tc.want.code || got.findings != tc.want.findings {
				t.Fatalf("got  %+v\nwant %+v\nstderr: %s", got, tc.want, errOut.String())
			}
		})
	}
}

// Every name of an install is located in a layer: the second logical name
// of a physical file two roots lead to carries the layer that gave it that
// name, not nothing (60c512c: the alias had no layerDigest, and the OS
// package that owned the path before the root was re-pointed above was
// reported as the owner).
func TestRun_RC4_EveryAliasOfAnInstallIsLocatedInALayer(t *testing.T) {
	v4 := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	const (
		lib   = "usr/lib/node_modules/minimatch/package.json"
		local = "usr/local/lib/node_modules/minimatch/package.json"
	)
	for _, tc := range []struct {
		name  string
		lower []probeLayerEntry
		upper []probeLayerEntry
		alias string
	}{
		// Lower: an external store one root links to, and a copy at the
		// other root's own name; upper: the other root re-pointed at the
		// store too, so the two names are one install, the second given in
		// the upper layer.
		{"two roots to one external store", append(alpineLayer(), probeLayerEntry{name: "opt/store/minimatch/package.json", body: v4}, probeLayerEntry{name: "usr/local/lib/node_modules", link: "/opt/store"}, probeLayerEntry{name: lib, body: v4}),
			[]probeLayerEntry{{name: "usr/lib/node_modules", link: "/opt/store"}}, lib},
		// Lower: an install under one root; upper: the other root
		// re-pointed at a directory holding that root, so the install's
		// own name is the package and the second name its alias.
		{"a root re-pointed at a directory holding another root's install", append(alpineLayer(), probeLayerEntry{name: local, body: v4}),
			[]probeLayerEntry{{name: "usr/lib/node_modules", link: "/usr/local/lib"}}, "usr/lib/node_modules/node_modules/minimatch/package.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			ids := writeLayeredProbeImage(t, tarPath, tc.lower, tc.upper)
			var out, errOut bytes.Buffer
			code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json", FailOn: &bandLow, FailOnUnknown: true}, &out, &errOut)
			var doc report.Document
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("decode: %v\n%s", err, errOut.String())
			}
			if code != 1 || len(doc.Findings) != 1 {
				t.Fatalf("exit=%d findings=%d; want 1 and one finding (one install, two names)\n%s", code, len(doc.Findings), errOut.String())
			}
			layers := map[string]string{}
			for _, l := range doc.Findings[0].Package.Locations {
				layers[l.Path] = l.LayerDigest
			}
			if layers[local] != ids[0] || layers[tc.alias] != ids[1] {
				t.Errorf("layers %v; want %s at %s (the file's layer) and %s at %s (the layer that re-pointed the root)", layers, ids[0], local, ids[1], tc.alias)
			}
		})
	}
}
