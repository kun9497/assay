package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/report"
)

// QA 2026-11-11, end to end: the image npm-link and owner items, each on its
// own layout beside the control the QA paired it with. Every row holds the
// package's version, logical paths, owner, the npm scope, unread and the
// strict exit -- the fields a finding count alone hides. Two vulnerable
// spellings of minimatch tell the file read apart: 3.0.4 and 3.0.3.
func TestRun_QA1111_NpmLinksAndOwners(t *testing.T) {
	v4 := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	v3 := []byte(`{"name":"minimatch","version":"3.0.3"}`)
	const (
		lib   = "usr/lib/node_modules/minimatch/package.json"
		local = "usr/local/lib/node_modules/minimatch/package.json"
	)
	apkOwning := func(dir string) probeLayerEntry {
		return probeLayerEntry{name: apkDBPath, body: []byte("P:qa-owner\nV:1.0-r0\nA:x86_64\nF:" + dir + "\nR:package.json\n\n")}
	}
	base := func(entries ...probeLayerEntry) []probeLayerEntry {
		return append(alpineLayer(), entries...)
	}
	// withOwner replaces the base layer's apk database with one that owns dir.
	withOwner := func(dir string, entries ...probeLayerEntry) []probeLayerEntry {
		out := []probeLayerEntry{{name: osReleasePath, body: []byte(osReleaseAlpine319)}, apkOwning(dir)}
		return append(out, entries...)
	}
	type want struct {
		versions []string
		paths    []string
		owner    string // "" = unowned
		npm      string
		unread   []string
		code     int
	}
	for _, tc := range []struct {
		name   string
		layers [][]probeLayerEntry
		want   want
	}{
		// --- item 2: a root linked to a directory under another root
		{"root linked to another root's vendor assets", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules/vendor/assets/minimatch/package.json", body: v4},
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/usr/lib/node_modules/vendor/assets"},
		)}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}},
		{"root linked to another root itself (counted once)", [][]probeLayerEntry{base(
			probeLayerEntry{name: lib, body: v4},
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/usr/lib/node_modules"},
		)}, want{[]string{"3.0.4"}, []string{lib}, "", report.ScopeRead, nil, 1}},
		{"root linked to a directory of installed packages (counted at their own paths)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules/vendor/node_modules/minimatch/package.json", body: v4},
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/usr/lib/node_modules/vendor/node_modules"},
		)}, want{[]string{"3.0.4"}, []string{"usr/lib/node_modules/vendor/node_modules/minimatch/package.json"}, "", report.ScopeRead, nil, 1}},
		{"root linked to a missing directory under another root", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules/vendor/package.json", body: []byte(`{"name":"vendor","version":"1.0.0"}`)},
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/usr/lib/node_modules/vendor/missing"},
		)}, want{nil, nil, "", report.ScopePartial, []string{"usr/local/lib/node_modules"}, 2}},
		// --- item 4: link cycles
		{"a package directory linked to itself", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "minimatch"},
		)}, want{nil, nil, "", report.ScopePartial, []string{lib}, 2}},
		{"two package directories linked to each other", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "other"},
			probeLayerEntry{name: "usr/lib/node_modules/other", link: "minimatch"},
		)}, want{nil, nil, "", report.ScopePartial, []string{lib, "usr/lib/node_modules/other/package.json"}, 2}},
		{"a chain of two links to one install (one package, both names)", [][]probeLayerEntry{base(
			probeLayerEntry{name: "opt/mm/package.json", body: v4},
			probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "/opt/mm"},
			probeLayerEntry{name: "usr/local/lib/node_modules/minimatch", link: "/usr/lib/node_modules/minimatch"},
		)}, want{[]string{"3.0.4"}, []string{lib, local}, "", report.ScopeRead, nil, 1}},
		// PR #275 review: a link-shaped install under the alias target.
		{"root alias: a package directory link under the target", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/node_modules/vendor/assets/other/package.json", body: []byte(`{"name":"other","version":"1.0.0"}`)},
			probeLayerEntry{name: "opt/mm/package.json", body: v4},
			probeLayerEntry{name: "usr/lib/node_modules/vendor/assets/minimatch", link: "/opt/mm"},
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/usr/lib/node_modules/vendor/assets"},
		)}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}},
		// The relative target resolves from the PHYSICAL directory: four
		// steps up from vendor/assets/minimatch is usr/lib, from the logical
		// usr/local/lib/node_modules/minimatch it would be usr.
		{"root alias: a manifest link under the target, relative", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/lib/store/package.json", body: v4},
			probeLayerEntry{name: "usr/lib/node_modules/vendor/assets/minimatch/package.json", link: "../../../../store/package.json"},
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/usr/lib/node_modules/vendor/assets"},
		)}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}},
		{"root alias: a manifest hardlink under the target", [][]probeLayerEntry{base(
			probeLayerEntry{name: "opt/mm/package.json", body: v4},
			probeLayerEntry{name: "usr/lib/node_modules/vendor/assets/minimatch/package.json", link: "opt/mm/package.json", hard: true},
			probeLayerEntry{name: "usr/local/lib/node_modules", link: "/usr/lib/node_modules/vendor/assets"},
		)}, want{[]string{"3.0.4"}, []string{local}, "", report.ScopeRead, nil, 1}},
		// PR #275 review: one link crossed twice is not a cycle.
		{"manifest link crossing lib64 twice", [][]probeLayerEntry{base(
			probeLayerEntry{name: "lib64", link: "usr/lib"},
			probeLayerEntry{name: "usr/lib/qa/package.json", body: v4},
			probeLayerEntry{name: lib, link: "/lib64/../../lib64/qa/package.json"},
		)}, want{[]string{"3.0.4"}, []string{lib}, "", report.ScopeRead, nil, 1}},
		// --- item 7.1: a manifest link through a layout link, with and without ".."
		{"manifest link with '..' after lib64", [][]probeLayerEntry{base(
			probeLayerEntry{name: "lib64", link: "usr/lib"},
			probeLayerEntry{name: "usr/qa-pkg/package.json", body: v4},
			probeLayerEntry{name: "qa-pkg/package.json", body: v3},
			probeLayerEntry{name: lib, link: "/lib64/../qa-pkg/package.json"},
		)}, want{[]string{"3.0.4"}, []string{lib}, "", report.ScopeRead, nil, 1}},
		{"manifest link through lib64, no '..'", [][]probeLayerEntry{base(
			probeLayerEntry{name: "lib64", link: "usr/lib"},
			probeLayerEntry{name: "usr/lib/qa-package/package.json", body: v4},
			probeLayerEntry{name: lib, link: "/lib64/qa-package/package.json"},
		)}, want{[]string{"3.0.4"}, []string{lib}, "", report.ScopeRead, nil, 1}},
		// --- item 7.3: a package directory replaced by a link in an upper layer, no whiteout
		{"package directory replaced by a link hides the lower tree", [][]probeLayerEntry{
			base(probeLayerEntry{name: lib, body: v4},
				probeLayerEntry{name: "usr/lib/node_modules/minimatch/node_modules/minimatch/package.json", body: v4}),
			{{name: "opt/content/package.json", body: v3}, {name: "usr/lib/node_modules/minimatch", link: "/opt/content"}},
		}, want{[]string{"3.0.3"}, []string{lib}, "", report.ScopeRead, nil, 1}},
		// PR #275 review: a symlink in a middle layer, a directory put back
		// above it: only the top layer's content remains.
		{"package directory replaced by a link, then a directory again", [][]probeLayerEntry{
			base(probeLayerEntry{name: "usr/lib/node_modules/minimatch/node_modules/minimatch/package.json", body: v4}),
			{{name: "usr/lib/node_modules/minimatch", link: "/opt/x"}},
			{{name: lib, body: v3}},
		}, want{[]string{"3.0.3"}, []string{lib}, "", report.ScopeRead, nil, 1}},
		{"nested copy in one layer is read (control)", [][]probeLayerEntry{base(
			probeLayerEntry{name: lib, body: v4},
			probeLayerEntry{name: "usr/lib/node_modules/minimatch/node_modules/minimatch/package.json", body: v4},
		)}, want{[]string{"3.0.4"}, []string{"usr/lib/node_modules/minimatch/node_modules/minimatch/package.json", lib}, "", report.ScopeRead, nil, 1}},
		{"scope directory replaced by a link hides the lower tree", [][]probeLayerEntry{
			base(probeLayerEntry{name: "usr/lib/node_modules/@qa/minimatch/package.json", body: v4}),
			{{name: "usr/lib/node_modules/@qa", link: "/opt/content"}},
		}, want{nil, nil, "", report.ScopePartial, []string{"usr/lib/node_modules/@qa"}, 2}},
		// --- item 7.5: npm's .bin
		{".bin linked to /usr/bin is not a package", [][]probeLayerEntry{base(
			probeLayerEntry{name: "usr/local/lib/node_modules/vendor/package.json", body: []byte(`{"name":"vendor","version":"1.0.0"}`)},
			probeLayerEntry{name: "usr/lib/node_modules/.bin", link: "/usr/bin"},
		)}, want{nil, nil, "", report.ScopeRead, nil, 0}},
		// --- item 7.4: owners through chained and retargeted links
		{"owner through lib64 -> lib -> usr/lib", [][]probeLayerEntry{withOwner("lib64/node_modules/minimatch",
			probeLayerEntry{name: "lib", link: "usr/lib"},
			probeLayerEntry{name: "lib64", link: "lib"},
			probeLayerEntry{name: lib, body: v4},
		)}, want{[]string{"3.0.4"}, []string{lib}, "qa-owner 1.0-r0", report.ScopeRead, nil, 1}},
		{"no owner through lib64 -> /sbin/../usr/lib (usr/usr/lib)", [][]probeLayerEntry{withOwner("lib64/node_modules/minimatch",
			probeLayerEntry{name: "sbin", link: "usr/bin"},
			probeLayerEntry{name: "lib64", link: "/sbin/../usr/lib"},
			probeLayerEntry{name: lib, body: v4},
		)}, want{[]string{"3.0.4"}, []string{lib}, "", report.ScopeRead, nil, 1}},
		{"owner kept through a middle link (control)", [][]probeLayerEntry{withOwner("usr/lib/node_modules/minimatch",
			probeLayerEntry{name: lib, link: "/opt/alias.json"},
			probeLayerEntry{name: "opt/alias.json", link: "/opt/store/fixed"},
			probeLayerEntry{name: "opt/store/fixed", body: v3},
			probeLayerEntry{name: "opt/store/old", body: v4},
		)}, want{[]string{"3.0.3"}, []string{lib}, "qa-owner 1.0-r0", report.ScopeRead, nil, 1}},
		{"owner dropped when a middle link is retargeted later", [][]probeLayerEntry{
			withOwner("usr/lib/node_modules/minimatch",
				probeLayerEntry{name: lib, link: "/opt/alias.json"},
				probeLayerEntry{name: "opt/alias.json", link: "/opt/store/fixed"},
				probeLayerEntry{name: "opt/store/fixed", body: v3},
				probeLayerEntry{name: "opt/store/old", body: v4}),
			{{name: "opt/alias.json", link: "/opt/store/old"}},
		}, want{[]string{"3.0.4"}, []string{lib}, "", report.ScopeRead, nil, 1}},
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
			var versions, paths []string
			owner := ""
			for _, f := range doc.Findings {
				if f.Package.Name != "minimatch" {
					continue
				}
				versions = append(versions, f.Package.Version)
				for _, l := range f.Package.Locations {
					paths = append(paths, l.Path)
					if l.OwnedBy != nil {
						owner = l.OwnedBy.Name + " " + l.OwnedBy.Version
					}
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
			got := want{uniqSorted(versions), uniqSorted(paths), owner, state, uniqSorted(unread), code}
			if strings.Join(got.versions, ",") != strings.Join(tc.want.versions, ",") || strings.Join(got.paths, ",") != strings.Join(tc.want.paths, ",") ||
				got.owner != tc.want.owner || got.npm != tc.want.npm || strings.Join(got.unread, ",") != strings.Join(tc.want.unread, ",") || got.code != tc.want.code {
				t.Errorf("got  %+v\nwant %+v\nstderr: %s", got, tc.want, errOut.String())
			}
		})
	}
}

func uniqSorted(xs []string) []string {
	m := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
