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

// Release check 2026-11-11 (main 42b0c09), end to end: the image npm-link
// items, each the QA's layout beside its control. The harness and the two
// minimatch spellings are TestRun_QA1111_NpmLinksAndOwners's.
func TestRun_RC1111_NpmLinksAndOwners(t *testing.T) {
	v4 := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	v3 := []byte(`{"name":"minimatch","version":"3.0.3"}`)
	const (
		lib   = "usr/lib/node_modules/minimatch/package.json"
		local = "usr/local/lib/node_modules/minimatch/package.json"
		alias = "usr/lib/node_modules/z-alias/package.json"
	)
	apkOwning := func(dir string) probeLayerEntry {
		return probeLayerEntry{name: apkDBPath, body: []byte("P:qa-owner\nV:1.0-r0\nA:x86_64\nF:" + dir + "\nR:package.json\n\n")}
	}
	base := func(entries ...probeLayerEntry) []probeLayerEntry {
		return append(alpineLayer(), entries...)
	}
	withOwner := func(dir string, entries ...probeLayerEntry) []probeLayerEntry {
		out := []probeLayerEntry{{name: osReleasePath, body: []byte(osReleaseAlpine319)}, apkOwning(dir)}
		return append(out, entries...)
	}
	type want struct {
		versions []string
		paths    []string
		owners   []string // per path, sorted with paths; "" = unowned
		npm      string
		unread   []string
		code     int
	}
	for _, tc := range []struct {
		name   string
		layers [][]probeLayerEntry
		want   want
	}{
		// --- blocker 3: a package directory link whose target's manifest is itself a link through lib64 with ".."
		{"directory link, then a manifest link through lib64 and '..'", [][]probeLayerEntry{base(
			probeLayerEntry{name: "lib64", link: "usr/lib"},
			probeLayerEntry{name: "usr/qa-pkg/package.json", body: v4},
			probeLayerEntry{name: "qa-pkg/package.json", body: v3},
			probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "/usr/local/lib/node_modules/vendor/resources/elsewhere"},
			probeLayerEntry{name: "usr/local/lib/node_modules/vendor/resources/elsewhere/package.json", link: "/lib64/../qa-pkg/package.json"},
		)}, want{[]string{"3.0.4"}, []string{lib}, []string{""}, report.ScopeRead, nil, 1}},
		{"directory link, then a manifest link to the physical path (control)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "lib64", link: "usr/lib"},
			probeLayerEntry{name: "usr/qa-pkg/package.json", body: v4},
			probeLayerEntry{name: "qa-pkg/package.json", body: v3},
			probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "/usr/local/lib/node_modules/vendor/resources/elsewhere"},
			probeLayerEntry{name: "usr/local/lib/node_modules/vendor/resources/elsewhere/package.json", link: "/usr/qa-pkg/package.json"},
		)}, want{[]string{"3.0.4"}, []string{lib}, []string{""}, report.ScopeRead, nil, 1}},
		{"directory link whose target's manifest link is a cycle", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "/usr/local/lib/node_modules/vendor/elsewhere"},
			probeLayerEntry{name: "usr/local/lib/node_modules/vendor/elsewhere/package.json", link: "/usr/local/lib/node_modules/vendor/elsewhere/package.json"},
		)}, want{nil, nil, nil, report.ScopePartial, []string{lib}, 2}},
		// --- blocker 3b: a re-homed relative manifest link with ".." after a link component
		{"root alias: relative manifest link with '..' after a link", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/usr/lib/node_modules/vendor/assets"},
			probeLayerEntry{name: "usr/lib/node_modules/vendor/assets/minimatch/hop", link: "/opt/build/sub"},
			probeLayerEntry{name: "opt/build/meta.json", body: v4},
			probeLayerEntry{name: "usr/lib/node_modules/vendor/assets/minimatch/meta.json", body: v3},
			probeLayerEntry{name: "usr/lib/node_modules/vendor/assets/minimatch/package.json", link: "hop/../meta.json"},
		)}, want{[]string{"3.0.4"}, []string{local}, []string{""}, report.ScopeRead, nil, 1}},
		// --- residual b: an unrecorded intermediate directory re-pointed by an upper layer
		{"intermediate directory outside the roots re-pointed in an upper layer", [][]probeLayerEntry{
			base(probeLayerEntry{name: "opt/current/package.json", body: v3},
				probeLayerEntry{name: "opt/version2/package.json", body: v4},
				probeLayerEntry{name: lib[:len(lib)-len("/package.json")], link: "/opt/current"}),
			{{name: "opt/current", link: "/opt/version2"}},
		}, want{[]string{"3.0.4"}, []string{lib}, []string{""}, report.ScopeRead, nil, 1}},
		{"a regular file replaces the package directory (no whiteout)", [][]probeLayerEntry{
			base(probeLayerEntry{name: lib, body: v4}),
			{{name: "usr/lib/node_modules/minimatch", body: []byte("not a directory")}},
		}, want{nil, nil, nil, report.ScopeNone, nil, 0}},
		{"a regular file replaces the package directory (whiteout control)", [][]probeLayerEntry{
			base(probeLayerEntry{name: lib, body: v4}),
			{{name: "usr/lib/node_modules/.wh.minimatch"}, {name: "usr/lib/node_modules/minimatch", body: []byte("not a directory")}},
		}, want{nil, nil, nil, report.ScopeNone, nil, 0}},
		// --- residual c: alias layers and owners
		{"an alias re-pointed in an upper layer is located there (unowned)", [][]probeLayerEntry{
			withOwner("usr/lib/node_modules/z-alias",
				probeLayerEntry{name: "opt/qa-store/package.json", body: v4},
				probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "/opt/qa-store"},
				probeLayerEntry{name: alias, body: v4}),
			{{name: "usr/lib/node_modules/z-alias", link: "/opt/qa-store"}},
		}, want{[]string{"3.0.4"}, []string{lib, alias}, []string{"", ""}, report.ScopeRead, nil, 1}},
		{"a re-homed root whose physical manifest is a link loses the owner", [][]probeLayerEntry{
			withOwner("usr/lib/node_modules/minimatch",
				probeLayerEntry{name: lib, body: v3},
				probeLayerEntry{name: "usr/local/lib/node_modules/vendor/resources/minimatch/package.json", link: "/opt/qa-stored/package.json"},
				probeLayerEntry{name: "opt/qa-stored/package.json", body: v4}),
			{{name: "usr/lib/node_modules", link: "/usr/local/lib/node_modules/vendor/resources"}},
		}, want{[]string{"3.0.4"}, []string{lib}, []string{""}, report.ScopeRead, nil, 1}},
		{"a re-homed root whose physical manifest is a file (control, unowned too)", [][]probeLayerEntry{
			withOwner("usr/lib/node_modules/minimatch",
				probeLayerEntry{name: lib, body: v3},
				probeLayerEntry{name: "usr/local/lib/node_modules/vendor/resources/minimatch/package.json", body: v4}),
			{{name: "usr/lib/node_modules", link: "/usr/local/lib/node_modules/vendor/resources"}},
		}, want{[]string{"3.0.4"}, []string{lib}, []string{""}, report.ScopeRead, nil, 1}},
		{"two links to one missing target: both unread", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "/opt/not-here"},
			probeLayerEntry{name: "usr/lib/node_modules/z-alias", link: "/opt/not-here"},
		)}, want{nil, nil, nil, report.ScopePartial, []string{lib, alias}, 2}},
		// --- blocker 4, held as it was: a whiteout after the file in the same layer removes it (docker's and containerd's untar)
		{"same-layer whiteout after the file removes it", [][]probeLayerEntry{
			base(probeLayerEntry{name: lib, body: v3}),
			{{name: lib, body: v4}, {name: "usr/lib/node_modules/minimatch/.wh.package.json"}},
		}, want{nil, nil, nil, report.ScopeNone, nil, 0}},
		{"same-layer whiteout before the file is overwritten by it", [][]probeLayerEntry{
			base(probeLayerEntry{name: lib, body: v3}),
			{{name: "usr/lib/node_modules/minimatch/.wh.package.json"}, {name: lib, body: v4}},
		}, want{[]string{"3.0.4"}, []string{lib}, []string{""}, report.ScopeRead, nil, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeLayeredProbeImage(t, tarPath, tc.layers...)
			var out, errOut bytes.Buffer
			code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath,
				Options{Output: "json", FailOn: &bandLow, FailOnIncomplete: true, FailOnIncompleteTarget: true}, &out, &errOut)
			var doc report.Document
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("decode: %v\n%s", err, errOut.String())
			}
			var versions []string
			ownerOf := map[string]string{}
			for _, f := range doc.Findings {
				if f.Package.Name != "minimatch" {
					continue
				}
				versions = append(versions, f.Package.Version)
				for _, l := range f.Package.Locations {
					o := ""
					if l.OwnedBy != nil {
						o = l.OwnedBy.Name + " " + l.OwnedBy.Version
					}
					ownerOf[l.Path] = o
				}
			}
			state := ""
			for _, a := range doc.InventoryScope.ApplicationScope {
				if a.Ecosystem == "npm" {
					state = a.State
				}
			}
			var unread, paths, owners []string
			for _, u := range doc.Unread {
				unread = append(unread, u.Path)
			}
			for p := range ownerOf {
				paths = append(paths, p)
			}
			paths = uniqSorted(paths)
			for _, p := range paths {
				owners = append(owners, ownerOf[p])
			}
			got := want{uniqSorted(versions), paths, owners, state, uniqSorted(unread), code}
			if strings.Join(got.versions, ",") != strings.Join(tc.want.versions, ",") || strings.Join(got.paths, ",") != strings.Join(tc.want.paths, ",") ||
				strings.Join(got.owners, "|") != strings.Join(tc.want.owners, "|") || got.npm != tc.want.npm || strings.Join(got.unread, ",") != strings.Join(tc.want.unread, ",") || got.code != tc.want.code {
				t.Errorf("got  %+v\nwant %+v\nstderr: %s", got, tc.want, errOut.String())
			}
		})
	}
}
