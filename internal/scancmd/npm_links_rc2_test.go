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

// Release check 2026-11-11 (main 5197df4), end to end: the image items --
// a directory restored over a lower symlink (the apk database behind the
// old link, and the npm ghost), a ".." after an unrecorded link (npm and
// apk), and an npm root reached through a linked ancestor or a link of its
// own. Each layout beside the control the QA paired it with.
func TestRun_RC2_LayersAndRoots(t *testing.T) {
	v4 := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	v3 := []byte(`{"name":"minimatch","version":"3.0.3"}`)
	const (
		lib   = "usr/lib/node_modules/minimatch/package.json"
		local = "usr/local/lib/node_modules/minimatch/package.json"
	)
	osRel := probeLayerEntry{name: osReleasePath, body: []byte(osReleaseAlpine319)}
	apkVuln := []byte("P:busybox\nV:1.36.1-r0\nA:x86_64\n\n")
	apkClean := []byte("P:qa-owner\nV:1.0-r0\nA:x86_64\n\n")
	dir := func(name string) probeLayerEntry { return probeLayerEntry{name: name, dir: true} }
	base := func(entries ...probeLayerEntry) []probeLayerEntry { return append(alpineLayer(), entries...) }
	type want struct {
		versions []string // minimatch
		paths    []string
		busybox  string // the busybox version found, "" for none
		npm      string
		unread   []string
		code     int
	}
	for _, tc := range []struct {
		name   string
		layers [][]probeLayerEntry
		want   want
		apk    bool // judged against qa1111DB (an Alpine 3.19 busybox record) rather than probeDB
	}{
		// --- 1. a directory restored over a lower symlink
		{"apk db: directory over the old link reads the current database", [][]probeLayerEntry{
			{osRel, probeLayerEntry{name: "lib/apk/db", link: "/opt/old-apk"}, probeLayerEntry{name: "opt/old-apk/installed", body: apkClean}, probeLayerEntry{name: "var/lib/apk/db/installed", body: apkVuln}},
			{dir("lib/apk/db"), probeLayerEntry{name: "lib/apk/db/README", body: []byte("moved")}},
		}, want{nil, nil, "1.36.1-r0", report.ScopeNone, nil, 1}, true},
		{"apk db: whiteout and directory over the old link (control)", [][]probeLayerEntry{
			{osRel, probeLayerEntry{name: "lib/apk/db", link: "/opt/old-apk"}, probeLayerEntry{name: "opt/old-apk/installed", body: apkClean}, probeLayerEntry{name: "var/lib/apk/db/installed", body: apkVuln}},
			{probeLayerEntry{name: "lib/apk/.wh.db"}, dir("lib/apk/db"), probeLayerEntry{name: "lib/apk/db/README", body: []byte("moved")}},
		}, want{nil, nil, "1.36.1-r0", report.ScopeNone, nil, 1}, true},
		{"npm ghost: the link's target became a directory with no manifest", [][]probeLayerEntry{
			base(probeLayerEntry{name: "opt/current", link: "/opt/base-package"}, probeLayerEntry{name: "opt/base-package/package.json", body: v4}, probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "/opt/current"}),
			{dir("opt/current"), probeLayerEntry{name: "opt/current/README", body: []byte("x")}},
		}, want{nil, nil, "", report.ScopePartial, []string{lib}, 2}, false},
		{"npm ghost: whiteout control", [][]probeLayerEntry{
			base(probeLayerEntry{name: "opt/current", link: "/opt/base-package"}, probeLayerEntry{name: "opt/base-package/package.json", body: v4}, probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "/opt/current"}),
			{probeLayerEntry{name: "opt/.wh.current"}, dir("opt/current"), probeLayerEntry{name: "opt/current/README", body: []byte("x")}},
		}, want{nil, nil, "", report.ScopePartial, []string{lib}, 2}, false},
		{"npm: the link's target still a link (control)", [][]probeLayerEntry{
			base(probeLayerEntry{name: "opt/current", link: "/opt/base-package"}, probeLayerEntry{name: "opt/base-package/package.json", body: v4}, probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "/opt/current"}),
		}, want{[]string{"3.0.4"}, []string{lib}, "", report.ScopeRead, nil, 1}, false},
		// --- 2. ".." after an unrecorded link
		{"directory link, then a manifest link through lib64 and .. (relayout)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "lib64", link: "usr/lib"},
			probeLayerEntry{name: "usr/qa-pkg/package.json", body: v4},
			probeLayerEntry{name: "qa-pkg/package.json", body: v3},
			probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "/opt/redirected"},
			probeLayerEntry{name: "opt/redirected/package.json", link: "/lib64/../qa-pkg/package.json"},
		)}, want{[]string{"3.0.4"}, []string{lib}, "", report.ScopeRead, nil, 1}, false},
		{"manifest link through an unrecorded link and ..", [][]probeLayerEntry{base(
			probeLayerEntry{name: "opt/route", link: "/srv/nested/deep"},
			dir("srv/nested/deep"),
			probeLayerEntry{name: "srv/nested/qa-package/package.json", body: v4},
			probeLayerEntry{name: "opt/qa-package/package.json", body: v3},
			probeLayerEntry{name: lib, link: "/opt/route/../qa-package/package.json"},
		)}, want{[]string{"3.0.4"}, []string{lib}, "", report.ScopeRead, nil, 1}, false},
		{"apk db link through an unrecorded link and ..", [][]probeLayerEntry{
			{osRel, probeLayerEntry{name: "opt/route", link: "/srv/nested/deep"}, dir("srv/nested/deep"), probeLayerEntry{name: "srv/nested/qa-db", body: apkVuln}, probeLayerEntry{name: "opt/qa-db", body: apkClean}, probeLayerEntry{name: "lib/apk/db/installed", link: "/opt/route/../qa-db"}},
		}, want{nil, nil, "1.36.1-r0", report.ScopeNone, nil, 1}, true},
		// --- 3. a root reached through a linked ancestor, or a link of its own
		{"root's parent is a link to another directory", [][]probeLayerEntry{base(
			probeLayerEntry{name: "opt/new-global/node_modules/minimatch/package.json", body: v4},
			probeLayerEntry{name: "usr/local/lib", link: "/opt/new-global"},
		)}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}, false},
		{"root's parent is a link; a package-directory link under the physical tree", [][]probeLayerEntry{base(
			probeLayerEntry{name: "opt/store/package.json", body: v4},
			probeLayerEntry{name: "opt/new-global/node_modules/minimatch", link: "/opt/store"},
			probeLayerEntry{name: "usr/local/lib", link: "/opt/new-global"},
		)}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}, false},
		{"root itself is a link outside every root", [][]probeLayerEntry{base(
			probeLayerEntry{name: "opt/new-global/node_modules/minimatch/package.json", body: v4},
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/opt/new-global/node_modules"},
		)}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}, false},
		{"root's parent re-pointed in an upper layer hides the old tree", [][]probeLayerEntry{
			base(probeLayerEntry{name: "opt/new-global/node_modules/minimatch/package.json", body: v4}, probeLayerEntry{name: local, body: v3}),
			{{name: "usr/local/lib", link: "/opt/new-global"}},
		}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}, false},
		// Nothing readable behind the fixed path: disclosed, so the strict
		// gate sees it.
		{"root's parent is a link to a missing directory", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/local/lib", link: "/opt/nowhere"},
		)}, want{nil, nil, "", report.ScopePartial, []string{"usr/local/lib/node_modules"}, 2}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeLayeredProbeImage(t, tarPath, tc.layers...)
			var out, errOut bytes.Buffer
			db := probeDB(t)
			if tc.apk {
				db = qa1111DB(t)
			}
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
			if strings.Join(got.versions, ",") != strings.Join(tc.want.versions, ",") || strings.Join(got.paths, ",") != strings.Join(tc.want.paths, ",") ||
				got.busybox != tc.want.busybox || got.npm != tc.want.npm || strings.Join(got.unread, ",") != strings.Join(tc.want.unread, ",") || got.code != tc.want.code {
				t.Errorf("got  %+v\nwant %+v\nstderr: %s", got, tc.want, errOut.String())
			}
		})
	}
}
