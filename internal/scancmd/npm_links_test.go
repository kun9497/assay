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
	"github.com/kun9497/assay/internal/source"
)

// A scoped package whose directory is a link: @s/x under node_modules is a
// package directory, the scope directory @s itself is not.
func TestRun_QA1110_LinkedScopedNpmPackage(t *testing.T) {
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeLayeredProbeImage(t, tarPath, append(alpineLayer(),
		probeLayerEntry{name: "opt/mm/package.json", body: []byte(`{"name":"@s/mm","version":"1.0.0"}`)},
		probeLayerEntry{name: "usr/lib/node_modules/@s/mm", link: "/opt/mm"}))
	var out, errOut bytes.Buffer
	Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut)
	var doc report.Document
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, errOut.String())
	}
	state := ""
	for _, a := range doc.InventoryScope.ApplicationScope {
		if a.Ecosystem == "npm" {
			state = a.State
		}
	}
	if state != report.ScopeRead || len(doc.Unread) != 0 {
		t.Errorf("npm scope = %q, unread = %v; want read with nothing unread", state, doc.Unread)
	}
	if n := doc.Summary.Components; n < 2 {
		t.Errorf("components = %d, want the OS package and @s/mm", n)
	}
	for _, c := range []struct {
		name string
		want bool
	}{
		{"usr/lib/node_modules/x", true},
		{"usr/lib/node_modules/@s/x", true},
		{"usr/lib/node_modules/@s", false},
		{"usr/lib/node_modules/x/lib", false},
		{"usr/lib/node_modules/x/node_modules/y", true},
	} {
		if got := isPackageDir(c.name); got != c.want {
			t.Errorf("isPackageDir(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// QA 2026-11-10 ②, end to end. minimatch 3.0.4 installed at the global npm
// root as a regular file is a finding; the same package where package.json
// is a symlink or a hardlink, or where its directory is a symlink, read 0
// findings, exit 0, npm "none" before this change. Each is now the same
// finding at the same logical path. A candidate that does not resolve is
// unread with its reason -- exit 2 under the strict gate -- and npm is
// "partial", not "none". A link in a bin directory is not an npm candidate.
func TestRun_QA1110_LinkedNpmPackages(t *testing.T) {
	pkg := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	const at = "usr/lib/node_modules/minimatch/package.json"
	for _, tc := range []struct {
		name     string
		entries  []probeLayerEntry
		found    bool
		npm      string
		unread   bool
		wantCode int
	}{
		{"regular file", []probeLayerEntry{{name: at, body: pkg}}, true, report.ScopeRead, false, 1},
		{"package.json symlink", []probeLayerEntry{{name: "opt/mm/package.json", body: pkg}, {name: at, link: "../../../../opt/mm/package.json"}}, true, report.ScopeRead, false, 1},
		{"package.json hardlink", []probeLayerEntry{{name: "opt/mm/package.json", body: pkg}, {name: at, link: "opt/mm/package.json", hard: true}}, true, report.ScopeRead, false, 1},
		{"package directory symlink", []probeLayerEntry{{name: "opt/mm/package.json", body: pkg}, {name: "usr/lib/node_modules/minimatch", link: "/opt/mm"}}, true, report.ScopeRead, false, 1},
		{"relative package directory symlink", []probeLayerEntry{{name: "opt/mm/package.json", body: pkg}, {name: "usr/lib/node_modules/minimatch", link: "../../../opt/mm"}}, true, report.ScopeRead, false, 1},
		{"a package.json link in a bin directory is not an npm candidate", []probeLayerEntry{{name: "opt/mm/package.json", body: pkg}, {name: "usr/bin/package.json", link: "/opt/mm/package.json"}}, false, report.ScopeNone, false, 0},
		{"broken package.json symlink", []probeLayerEntry{{name: at, link: "/nowhere/package.json"}}, false, report.ScopePartial, true, 2},
		{"broken directory symlink", []probeLayerEntry{{name: "usr/lib/node_modules/minimatch", link: "/opt/gone"}}, false, report.ScopePartial, true, 2},
		{"a linked scope directory is unread, not walked", []probeLayerEntry{{name: "opt/scope/mm/package.json", body: []byte(`{"name":"@s/mm","version":"1.0.0"}`)}, {name: "usr/lib/node_modules/@s", link: "/opt/scope"}}, false, report.ScopePartial, true, 2},
		{"no npm package at all", nil, false, report.ScopeNone, false, 0},
		{"a link in a bin directory is not an npm candidate", []probeLayerEntry{{name: "usr/bin/tool", link: "/nowhere/tool"}}, false, report.ScopeNone, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeLayeredProbeImage(t, tarPath, append(alpineLayer(), tc.entries...))
			var out, errOut bytes.Buffer
			code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath,
				Options{Output: "json", FailOn: &bandLow, FailOnIncomplete: true, FailOnIncompleteTarget: true}, &out, &errOut)
			var doc report.Document
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("decode: %v\n%s", err, errOut.String())
			}
			var paths []string
			for _, f := range doc.Findings {
				if f.Package.Name == "minimatch" {
					for _, l := range f.Package.Locations {
						paths = append(paths, l.Path)
					}
				}
			}
			if tc.found != (len(paths) > 0) || (tc.found && paths[0] != at) {
				t.Errorf("minimatch locations = %v, want found=%v at %s", paths, tc.found, at)
			}
			state := ""
			if s := doc.InventoryScope; s != nil {
				for _, a := range s.ApplicationScope {
					if a.Ecosystem == "npm" {
						state = a.State
					}
				}
			}
			if state != tc.npm {
				t.Errorf("npm scope = %q, want %q", state, tc.npm)
			}
			var unread []string
			for _, u := range doc.Unread {
				unread = append(unread, u.Path+": "+u.Reason)
			}
			if tc.unread != (len(unread) == 1 && strings.HasPrefix(unread[0], "usr/lib/node_modules/")) || (!tc.unread && len(unread) != 0) {
				t.Errorf("unread = %v, want one entry for the candidate: %v", unread, tc.unread)
			}
			if code != tc.wantCode {
				t.Errorf("exit = %d, want %d\nstderr: %s", code, tc.wantCode, errOut.String())
			}
		})
	}
}

// The partial state through every renderer, not only JSON: an unresolved
// npm link must not read as "npm held nothing" on stderr, in the table or in
// SARIF, and the candidate's path is named as unread in each.
func TestRun_QA1110_UnresolvedNpmLinkInEveryRenderer(t *testing.T) {
	const cand = "usr/lib/node_modules/minimatch/package.json"
	const partial = "(some behind links that did not resolve, listed unread)"
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeLayeredProbeImage(t, tarPath, append(alpineLayer(),
		probeLayerEntry{name: cand, link: "/nowhere/package.json"}))
	for _, output := range []string{"table", "sarif"} {
		var out, errOut bytes.Buffer
		Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: output}, &out, &errOut)
		all := out.String() + errOut.String()
		if !strings.Contains(all, "usr/lib/node_modules"+" "+partial) && !strings.Contains(all, "opt/app-root/src/node_modules "+partial) {
			t.Errorf("%s: no partial npm wording %q:\n%s", output, partial, all)
		}
		if !strings.Contains(all, cand) {
			t.Errorf("%s: the unresolved candidate %s is not named:\n%s", output, cand, all)
		}
		if output == "sarif" && !strings.Contains(out.String(), `"assay/not-read"`) {
			t.Errorf("sarif: no assay/not-read result:\n%s", out.String())
		}
	}
}

// PR #271 review: a target already read at its own path under a root is that
// package, not a second copy (pnpm's node_modules/x -> .pnpm/x@v/node_modules/x,
// and a link from one root into another); a target reached through a
// top-level layout link (lib -> usr/lib) or through another linked package
// directory resolves as the kernel would.
func TestRun_QA1110_LinkedNpmPackagesCountedOnceAndResolvedThroughLinks(t *testing.T) {
	pkg := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	const pnpm = "opt/app-root/src/node_modules/.pnpm/minimatch@3.0.4/node_modules/minimatch"
	for _, tc := range []struct {
		name    string
		entries []probeLayerEntry
		want    []string
	}{
		{"pnpm link to a package already read", []probeLayerEntry{
			{name: pnpm + "/package.json", body: pkg},
			{name: "opt/app-root/src/node_modules/minimatch", link: ".pnpm/minimatch@3.0.4/node_modules/minimatch"},
		}, []string{pnpm + "/package.json"}},
		{"a link from one root into another", []probeLayerEntry{
			{name: "usr/lib/node_modules/minimatch/package.json", body: pkg},
			{name: "usr/local/lib/node_modules/minimatch", link: "/usr/lib/node_modules/minimatch"},
		}, []string{"usr/lib/node_modules/minimatch/package.json"}},
		{"pnpm with the store's manifest hardlinked", []probeLayerEntry{
			{name: "opt/store/minimatch/package.json", body: pkg},
			{name: pnpm + "/package.json", link: "opt/store/minimatch/package.json", hard: true},
			{name: "opt/app-root/src/node_modules/minimatch", link: ".pnpm/minimatch@3.0.4/node_modules/minimatch"},
		}, []string{pnpm + "/package.json"}},
		{"through the top-level lib link", []probeLayerEntry{
			{name: "lib", link: "usr/lib"},
			{name: "usr/lib/mm/package.json", body: pkg},
			{name: "usr/local/lib/node_modules/minimatch", link: "/lib/mm"},
		}, []string{"usr/local/lib/node_modules/minimatch/package.json"}},
		{"through another linked package directory", []probeLayerEntry{
			{name: "opt/mm/package.json", body: pkg},
			{name: "usr/lib/node_modules/b", link: "/opt/mm"},
			{name: "usr/local/lib/node_modules/minimatch", link: "/usr/lib/node_modules/b"},
			// Round 2 of the review: a link to another package directory link
			// is a second name for that install, as a link into another root's
			// real directory is -- counted once, at the link it lands on.
			// One package, located at both names (PR #275 review: the other
			// name was lost).
		}, []string{"usr/lib/node_modules/b/package.json", "usr/local/lib/node_modules/minimatch/package.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeLayeredProbeImage(t, tarPath, append(alpineLayer(), tc.entries...))
			var out, errOut bytes.Buffer
			Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut)
			var doc report.Document
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("decode: %v\n%s", err, errOut.String())
			}
			seen := map[string]bool{}
			for _, f := range doc.Findings {
				if f.Package.Name == "minimatch" || f.Package.Name == "b" {
					for _, l := range f.Package.Locations {
						seen[l.Path] = true
					}
				}
			}
			var got []string
			for p := range seen {
				got = append(got, p)
			}
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") || len(doc.Unread) != 0 {
				t.Errorf("locations = %v, unread = %v; want %v and nothing unread", got, doc.Unread, tc.want)
			}
		})
	}
}

// PR #271 review: an error reading a linked package.json -- here the
// per-file limit (D112) -- fails the scan as the probe pass's own errors do,
// exit 2 without any gate, rather than becoming one more unread path.
func TestRun_QA1110_LinkedNpmReadErrorFailsTheScan(t *testing.T) {
	old := source.MaxFileBytes
	source.MaxFileBytes = 4096
	defer func() { source.MaxFileBytes = old }()
	big := []byte(`{"name":"minimatch","version":"3.0.4","description":"` + strings.Repeat("x", 8192) + `"}`)
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeLayeredProbeImage(t, tarPath, append(alpineLayer(),
		probeLayerEntry{name: "opt/mm/package.json", body: big},
		probeLayerEntry{name: "usr/lib/node_modules/minimatch", link: "/opt/mm"}))
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath, Options{Output: "json"}, &out, &errOut); code != 2 {
		t.Errorf("exit = %d, want 2\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "read the npm packages behind links") {
		t.Errorf("stderr does not name the failing read:\n%s", errOut.String())
	}
}

// PR #271 review, end to end: each of the review's layouts against its own
// control. Every row asserts the package's version and logical location, the
// npm scope, unread and the strict exit -- a finding count alone can hold
// while the wrong file is read.
func TestRun_PR271_ReviewLayouts(t *testing.T) {
	vuln := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	fixed := []byte(`{"name":"minimatch","version":"9.9.9"}`)
	const at = "usr/lib/node_modules/minimatch/package.json"
	for _, tc := range []struct {
		name     string
		entries  []probeLayerEntry
		version  string // "" = no minimatch package
		path     string
		npm      string
		unread   string
		wantCode int
	}{
		{"linked into another package's resources", []probeLayerEntry{
			{name: "usr/lib/node_modules/vendor/package.json", body: []byte(`{"name":"vendor","version":"1.0.0"}`)},
			{name: "usr/lib/node_modules/vendor/resources/minimatch/package.json", body: vuln},
			{name: "usr/lib/node_modules/minimatch", link: "vendor/resources/minimatch"},
		}, "3.0.4", at, report.ScopeRead, "", 1},
		{"'..' after a top-level link", []probeLayerEntry{
			{name: "lib64", link: "usr/lib"},
			{name: "usr/qa-pkg/package.json", body: vuln},
			{name: "qa-pkg/package.json", body: fixed},
			{name: "usr/lib/node_modules/minimatch", link: "/lib64/../qa-pkg"},
		}, "3.0.4", at, report.ScopeRead, "", 1},
		{"'..' control: the direct path", []probeLayerEntry{
			{name: "lib64", link: "usr/lib"},
			{name: "usr/qa-pkg/package.json", body: vuln},
			{name: "qa-pkg/package.json", body: fixed},
			{name: "usr/lib/node_modules/minimatch", link: "/usr/qa-pkg"},
		}, "3.0.4", at, report.ScopeRead, "", 1},
		{"a dangling examples/package.json is not a candidate", []probeLayerEntry{
			{name: at, body: vuln},
			{name: "usr/lib/node_modules/minimatch/examples/package.json", link: "/missing/example"},
		}, "3.0.4", at, report.ScopeRead, "", 1},
		{"a dangling installed manifest still is", []probeLayerEntry{
			{name: at, link: "/missing/package.json"},
		}, "", "", report.ScopePartial, at, 2},
		{"the npm root itself is a link", []probeLayerEntry{
			{name: "usr/lib/node_modules", link: "/opt/npm-global"},
			{name: "opt/npm-global/minimatch/package.json", body: vuln},
		}, "", "", report.ScopePartial, "usr/lib/node_modules", 2},
		{"a linked root over an older layer's directory", nil, "", "", report.ScopePartial, "usr/lib/node_modules", 2},
		{"a root linked to another root that was read", []probeLayerEntry{
			{name: "usr/local/lib/node_modules", link: "../../lib/node_modules"},
			{name: at, body: vuln},
		}, "3.0.4", at, report.ScopeRead, "", 1},
		{"the npm root as a directory (control)", []probeLayerEntry{
			{name: at, body: vuln},
		}, "3.0.4", at, report.ScopeRead, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			layers := [][]probeLayerEntry{append(alpineLayer(), tc.entries...)}
			if tc.entries == nil {
				// Layer 0 installs minimatch 3.0.4 in the root directory; layer 1
				// replaces the root with a link (no whiteout, as `rm -rf && ln -s`
				// leaves it) to a tree holding 9.9.9. The 3.0.4 copy is gone.
				layers = [][]probeLayerEntry{append(alpineLayer(), probeLayerEntry{name: at, body: vuln}),
					{{name: "usr/lib/node_modules", link: "/opt/npm-global"}, {name: "opt/npm-global/minimatch/package.json", body: fixed}}}
			}
			writeLayeredProbeImage(t, tarPath, layers...)
			var out, errOut bytes.Buffer
			code := Run(context.Background(), probeDB(t), "docker-archive:"+tarPath,
				Options{Output: "json", FailOn: &bandLow, FailOnIncomplete: true, FailOnIncompleteTarget: true}, &out, &errOut)
			var doc report.Document
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
				t.Fatalf("decode: %v\n%s", err, errOut.String())
			}
			var got []string
			for _, f := range doc.Findings {
				if f.Package.Name == "minimatch" {
					for _, l := range f.Package.Locations {
						got = append(got, f.Package.Version+"@"+l.Path)
					}
				}
			}
			want := ""
			if tc.version != "" {
				want = tc.version + "@" + tc.path
			}
			if (want == "" && len(got) != 0) || (want != "" && (len(got) == 0 || got[0] != want)) {
				t.Errorf("minimatch = %v, want %q", got, want)
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
			if state != tc.npm || strings.Join(unread, ",") != tc.unread || code != tc.wantCode {
				t.Errorf("npm=%q unread=%v exit=%d, want %q %q %d\n%s", state, unread, code, tc.npm, tc.unread, tc.wantCode, errOut.String())
			}
		})
	}
}

// PR #271 review: an upper layer that replaces the OS-owned manifest with a
// link to a file of its own has put something new at that path -- unowned,
// as the same bytes copied there as a regular file are. A link made in the
// record's own layer, and a hardlink (whose bytes are the layer that made
// it, D130), keep the owner.
func TestRun_PR271_LinkedManifestOwner(t *testing.T) {
	apk := "P:qa-owner\nV:1.0-r0\nA:x86_64\nF:usr/lib/node_modules/minimatch\nR:package.json\n\n"
	pkg := []byte(`{"name":"minimatch","version":"3.0.4"}`)
	const at = "usr/lib/node_modules/minimatch/package.json"
	base := []probeLayerEntry{
		{name: osReleasePath, body: []byte(osReleaseAlpine319)},
		{name: apkDBPath, body: []byte(apk)},
		{name: "opt/src/package.json", body: pkg},
	}
	for _, tc := range []struct {
		name   string
		layers [][]probeLayerEntry
		owner  string
	}{
		{"owned regular file", [][]probeLayerEntry{append(append([]probeLayerEntry{}, base...), probeLayerEntry{name: at, body: pkg})}, "qa-owner 1.0-r0"},
		{"replaced by a link in a later layer", [][]probeLayerEntry{
			append(append([]probeLayerEntry{}, base...), probeLayerEntry{name: at, body: pkg}),
			{{name: "usr/lib/node_modules/minimatch/.wh.package.json"}, {name: at, link: "/opt/src/package.json"}},
		}, ""},
		{"replaced by a copy in a later layer (control)", [][]probeLayerEntry{
			append(append([]probeLayerEntry{}, base...), probeLayerEntry{name: at, body: pkg}),
			{{name: at, body: pkg}},
		}, ""},
		{"a link in the record's own layer", [][]probeLayerEntry{append(append([]probeLayerEntry{}, base...), probeLayerEntry{name: at, link: "/opt/src/package.json"})}, "qa-owner 1.0-r0"},
		{"a hardlink in the record's own layer", [][]probeLayerEntry{append(append([]probeLayerEntry{}, base...), probeLayerEntry{name: at, link: "opt/src/package.json", hard: true})}, "qa-owner 1.0-r0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := filepath.Join(t.TempDir(), "image.tar")
			writeLayeredProbeImage(t, tarPath, tc.layers...)
			got := ownersInJSON(t, tarPath)
			if v, ok := got[at]; !ok || v != tc.owner {
				t.Errorf("%s: present=%v owner=%q, want %q (all: %v)", at, ok, v, tc.owner, got)
			}
		})
	}
}
