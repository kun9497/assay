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

// Release check 2026-11-11 (main b732cac), end to end: the npm-root and
// APK-path items, each layout beside the control the QA paired it with.
func TestRun_RC3_RootsAndPaths(t *testing.T) {
	v4 := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	v3 := []byte(`{"name":"minimatch","version":"3.0.3"}`)
	clean := []byte(`{"name":"qa-clean-control","version":"1.0.0"}`)
	const (
		lib   = "usr/lib/node_modules/minimatch/package.json"
		local = "usr/local/lib/node_modules/minimatch/package.json"
	)
	osRel := probeLayerEntry{name: osReleasePath, body: []byte(osReleaseAlpine319)}
	apkVuln := []byte("P:busybox\nV:1.36.1-r0\nA:x86_64\n\n")
	apkClean := []byte("P:qa-owner\nV:1.0-r0\nA:x86_64\n\n")
	dir := func(name string) probeLayerEntry { return probeLayerEntry{name: name, dir: true} }
	base := func(entries ...probeLayerEntry) []probeLayerEntry { return append(alpineLayer(), entries...) }
	parents := func(n int) string { return strings.Repeat("a/../", n) }
	type want struct {
		versions []string
		paths    []string
		busybox  string
		npm      string
		unread   []string
		code     int
	}
	for _, tc := range []struct {
		name   string
		layers [][]probeLayerEntry
		want   want
		apk    bool
	}{
		// --- a second hop above the physical root
		{"root -> /opt/active/node_modules, /opt/active re-pointed above (stale copy hidden)", [][]probeLayerEntry{
			base(probeLayerEntry{name: "opt/runtime/node_modules/minimatch/package.json", body: v4}, probeLayerEntry{name: "opt/active/node_modules/minimatch/package.json", body: v3}),
			{{name: "usr/local/lib/node_modules", link: "/opt/active/node_modules"}, {name: "opt/active", link: "/opt/runtime"}},
		}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}, false},
		{"the same with a whiteout (control)", [][]probeLayerEntry{
			base(probeLayerEntry{name: "opt/runtime/node_modules/minimatch/package.json", body: v4}, probeLayerEntry{name: "opt/active/node_modules/minimatch/package.json", body: v3}),
			{{name: "opt/.wh.active"}, {name: "usr/local/lib/node_modules", link: "/opt/active/node_modules"}, {name: "opt/active", link: "/opt/runtime"}},
		}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}, false},
		{"the stale copy vulnerable, the real one fixed (no false finding)", [][]probeLayerEntry{
			base(probeLayerEntry{name: "opt/runtime/node_modules/minimatch/package.json", body: []byte(`{"name":"minimatch","version":"9.9.9"}`)}, probeLayerEntry{name: "opt/active/node_modules/minimatch/package.json", body: v4}),
			{{name: "usr/local/lib/node_modules", link: "/opt/active/node_modules"}, {name: "opt/active", link: "/opt/runtime"}},
		}, want{nil, nil, "", report.ScopeRead, nil, 0}, false},
		// --- the physical directory contains the logical root, or another root
		{"root -> /usr/local (contains the root itself)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/usr/local"},
			probeLayerEntry{name: "usr/local/minimatch/package.json", body: v4},
		)}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}, false},
		{"root -> /usr/local/lib (contains the root; was 1..8 incomplete by run)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/usr/local/lib"},
			probeLayerEntry{name: "usr/local/lib/minimatch/package.json", body: v4},
		)}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}, false},
		{"root -> directory holding another root's install (one package, two names)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules", link: "/usr/local/lib"},
			probeLayerEntry{name: local, body: v4},
		)}, want{[]string{"3.0.4"}, []string{"usr/lib/node_modules/node_modules/minimatch/package.json", local}, "", report.ScopeRead, nil, 1}, false},
		{"root -> a disjoint directory (control)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/opt/global-root"},
			probeLayerEntry{name: "opt/global-root/minimatch/package.json", body: v4},
		)}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}, false},
		// --- two roots to one physical install
		{"two roots -> one external install (one package, both names; was 8 findings)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules", link: "/opt/shared/node_modules"},
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/opt/shared/node_modules"},
			probeLayerEntry{name: "opt/shared/node_modules/minimatch/package.json", body: v4},
		)}, want{[]string{"3.0.4"}, []string{lib, local}, "", report.ScopeRead, nil, 1}, false},
		{"two roots -> one external install that is itself a link", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules", link: "/opt/shared/node_modules"},
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/opt/shared/node_modules"},
			probeLayerEntry{name: "opt/shared/node_modules/minimatch", link: "/opt/single"},
			probeLayerEntry{name: "opt/single/package.json", body: v4},
		)}, want{[]string{"3.0.4"}, []string{lib, local}, "", report.ScopeRead, nil, 1}, false},
		// --- cycles at the root's parent and at the root
		{"root's parent is a link to itself (unread, exit 2)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/local/lib", link: "/usr/local/lib"},
		)}, want{nil, nil, "", report.ScopePartial, []string{"usr/local/lib/node_modules"}, 2}, false},
		{"root is a link to itself (unread, exit 2)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/usr/local/lib/node_modules"},
		)}, want{nil, nil, "", report.ScopePartial, []string{"usr/local/lib/node_modules"}, 2}, false},
		// --- ".." over a component no layer shows
		{"manifest link through an absent directory and .. (unread)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules/managed/candidate.json", body: clean},
			probeLayerEntry{name: lib, link: "/usr/lib/node_modules/managed/absent/../candidate.json"},
		)}, want{nil, nil, "", report.ScopePartial, []string{lib}, 2}, false},
		{"manifest link through a regular file and .. (unread)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules/managed/candidate.json", body: clean},
			probeLayerEntry{name: "usr/lib/node_modules/managed/absent", body: []byte("not a directory")},
			probeLayerEntry{name: lib, link: "/usr/lib/node_modules/managed/absent/../candidate.json"},
		)}, want{nil, nil, "", report.ScopePartial, []string{lib}, 2}, false},
		{"manifest link through a present directory and .. (read: the clean control)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules/managed/candidate.json", body: clean},
			dir("usr/lib/node_modules/managed/absent"),
			probeLayerEntry{name: lib, link: "/usr/lib/node_modules/managed/absent/../candidate.json"},
		)}, want{nil, nil, "", report.ScopeRead, nil, 0}, false},
		// --- the apk database behind such a link falls back to the next path
		{"apk: link through an absent directory and .. (fallback db read)", [][]probeLayerEntry{
			{osRel, probeLayerEntry{name: "var/lib/apk/db/installed", body: apkVuln}, probeLayerEntry{name: "opt/preferred-db", body: apkClean}, probeLayerEntry{name: "lib/apk/db/installed", link: "/opt/never-created/../preferred-db"}},
		}, want{nil, nil, "1.36.1-r0", report.ScopeNone, nil, 1}, true},
		{"apk: the directory exists (preferred db read, clean)", [][]probeLayerEntry{
			{osRel, probeLayerEntry{name: "var/lib/apk/db/installed", body: apkVuln}, probeLayerEntry{name: "opt/preferred-db", body: apkClean}, dir("opt/never-created"), probeLayerEntry{name: "lib/apk/db/installed", link: "/opt/never-created/../preferred-db"}},
		}, want{nil, nil, "", report.ScopeNone, nil, 0}, true},
		{"apk: a regular file in its place (fallback db read)", [][]probeLayerEntry{
			{osRel, probeLayerEntry{name: "var/lib/apk/db/installed", body: apkVuln}, probeLayerEntry{name: "opt/preferred-db", body: apkClean}, probeLayerEntry{name: "opt/never-created", body: []byte("x")}, probeLayerEntry{name: "lib/apk/db/installed", link: "/opt/never-created/../preferred-db"}},
		}, want{nil, nil, "1.36.1-r0", report.ScopeNone, nil, 1}, true},
		{"apk: one symlink and 2 `a/..` over a real directory", [][]probeLayerEntry{
			{osRel, probeLayerEntry{name: "var/lib/apk/db/installed", body: apkClean}, dir("opt/a"), probeLayerEntry{name: "opt/preferred-db", body: apkVuln}, probeLayerEntry{name: "lib/apk/db/installed", link: "/opt/" + parents(2) + "preferred-db"}},
		}, want{nil, nil, "1.36.1-r0", report.ScopeNone, nil, 1}, true},
		{"apk: one symlink and 44 `a/..` over a real directory (not 44 links)", [][]probeLayerEntry{
			{osRel, probeLayerEntry{name: "var/lib/apk/db/installed", body: apkClean}, dir("opt/a"), probeLayerEntry{name: "opt/preferred-db", body: apkVuln}, probeLayerEntry{name: "lib/apk/db/installed", link: "/opt/" + parents(44) + "preferred-db"}},
		}, want{nil, nil, "1.36.1-r0", report.ScopeNone, nil, 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeLayeredProbeImage(t, tarPath, tc.layers...)
			db := probeDB(t)
			if tc.apk {
				db = qa1111DB(t)
			}
			// Three runs of one image must agree (the logical-parent layout
			// had varied).
			var first string
			for i := 0; i < 3; i++ {
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
				got := want{uniqSorted(versions), uniqSorted(paths), busybox, state, uniqSorted(unread), code}
				sig := strings.Join(got.versions, ",") + "|" + strings.Join(got.paths, ",") + "|" + got.busybox + "|" + got.npm + "|" + strings.Join(got.unread, ",") + "|" + string(rune('0'+code))
				if i == 0 {
					first = sig
					if strings.Join(got.versions, ",") != strings.Join(tc.want.versions, ",") || strings.Join(got.paths, ",") != strings.Join(tc.want.paths, ",") ||
						got.busybox != tc.want.busybox || got.npm != tc.want.npm || strings.Join(got.unread, ",") != strings.Join(tc.want.unread, ",") || got.code != tc.want.code {
						t.Fatalf("got  %+v\nwant %+v\nstderr: %s", got, tc.want, errOut.String())
					}
				} else if sig != first {
					t.Fatalf("run %d differs:\n%s\n%s", i, first, sig)
				}
			}
		})
	}
}
