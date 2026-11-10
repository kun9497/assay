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
