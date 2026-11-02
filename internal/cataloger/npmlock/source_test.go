package npmlock

import (
	"strings"
	"testing"
)

// ClassifySource is shared with yarnlock's v1 reader, so its rows are the
// spellings both files write. A registry row that classifies as non-registry
// is a package silently not evaluated; a git row that classifies as registry
// is the defect this exists to close (audit 2026-10-22 P4).
func TestClassifySource(t *testing.T) {
	cases := []struct {
		spec     string
		urlIsVCS bool
		want     SourceClass
	}{
		{"4.17.20", true, SourceRegistry},
		{"^4.17.0", true, SourceRegistry},
		{"", false, SourceRegistry},
		// A registry tarball is an https URL on whatever host the registry
		// is. A private one is legitimate and must not be refused, which is
		// why nothing keys on registry.npmjs.org.
		{"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", false, SourceRegistry},
		{"https://npm.internal.example/lodash/-/lodash-4.17.21.tgz", false, SourceRegistry},
		// The same URL as a SPEC (npm 6's version, yarn v1's range) is a
		// tarball dependency, not a registry release.
		{"https://example.invalid/lodash.tgz", true, SourceVCS},
		{"git+ssh://git@github.com/someone/lodash.git#0123", false, SourceVCS},
		{"git+https://github.com/someone/lodash.git#0123", false, SourceVCS},
		{"git://github.com/someone/lodash.git#0123", false, SourceVCS},
		{"github:someone/lodash#0123", false, SourceVCS},
		{"gitlab:someone/lodash#0123", false, SourceVCS},
		{"bitbucket:someone/lodash#0123", false, SourceVCS},
		{"gist:11081aaa", false, SourceVCS},
		{"GIT+HTTPS://github.com/someone/lodash.git", false, SourceVCS},
		{"file:../lodash", false, SourceLocal},
		{"file:vendor/lodash-4.17.20.tgz", true, SourceLocal},
		{"link:../lodash", false, SourceLocal},
	}
	for _, tc := range cases {
		if got := ClassifySource(tc.spec, tc.urlIsVCS); got != tc.want {
			t.Errorf("ClassifySource(%q, %v) = %d, want %d", tc.spec, tc.urlIsVCS, got, tc.want)
		}
	}
}

// Parse-level rows: each refused entry is absent, counted as
// SkippedNoVersion, and named; the registry entry beside it is cataloged.
func TestParse_NonRegistrySourcesAreRefused(t *testing.T) {
	rows := []struct {
		name string
		body string
	}{
		{"v3 resolved git+ssh", `{"lockfileVersion":3,"packages":{"":{"name":"app"},
			"node_modules/kept-pkg":{"version":"1.0.0","resolved":"https://registry.npmjs.org/kept-pkg/-/kept-pkg-1.0.0.tgz"},
			"node_modules/forked-pkg":{"version":"4.17.20","resolved":"git+ssh://git@github.com/someone/forked-pkg.git#0123"}}}`},
		{"v3 resolved github: shorthand", `{"lockfileVersion":3,"packages":{"":{"name":"app"},
			"node_modules/kept-pkg":{"version":"1.0.0"},
			"node_modules/forked-pkg":{"version":"4.17.20","resolved":"github:someone/forked-pkg#0123"}}}`},
		{"v3 resolved file: path", `{"lockfileVersion":3,"packages":{"":{"name":"app"},
			"node_modules/kept-pkg":{"version":"1.0.0"},
			"node_modules/forked-pkg":{"version":"4.17.20","resolved":"file:../forked-pkg"}}}`},
		{"v3 aliased git dependency is refused under its registry name", `{"lockfileVersion":3,"packages":{"":{"name":"app"},
			"node_modules/kept-pkg":{"version":"1.0.0"},
			"node_modules/some-alias":{"name":"forked-pkg","version":"4.17.20","resolved":"git+https://github.com/someone/forked-pkg.git#0123"}}}`},
		{"v1 git version", `{"lockfileVersion":1,"dependencies":{
			"kept-pkg":{"version":"1.0.0"},
			"forked-pkg":{"version":"git+https://github.com/someone/forked-pkg.git#0123"}}}`},
		{"v1 tarball URL version", `{"lockfileVersion":1,"dependencies":{
			"kept-pkg":{"version":"1.0.0"},
			"forked-pkg":{"version":"https://example.invalid/forked-pkg-4.17.20.tgz"}}}`},
		{"v1 file: version", `{"lockfileVersion":1,"dependencies":{
			"kept-pkg":{"version":"1.0.0"},
			"forked-pkg":{"version":"file:../forked-pkg"}}}`},
		{"v1 git resolved", `{"lockfileVersion":1,"dependencies":{
			"kept-pkg":{"version":"1.0.0","resolved":"https://registry.npmjs.org/kept-pkg/-/kept-pkg-1.0.0.tgz"},
			"forked-pkg":{"version":"4.17.20","resolved":"git+https://github.com/someone/forked-pkg.git#0123"}}}`},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			pkgs, stats, skipped, err := Parse(write(t, r.body))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(pkgs) != 1 || pkgs[0].Name != "kept-pkg" {
				t.Errorf("packages = %+v, want kept-pkg alone", pkgs)
			}
			if stats.Components != 2 || stats.Cataloged != 1 || stats.SkippedNoVersion != 1 {
				t.Errorf("stats = %+v, want 2 components, 1 cataloged, 1 SkippedNoVersion", stats)
			}
			if len(skipped) != 1 || skipped[0].Name != "forked-pkg" || skipped[0].Reason == "" {
				t.Errorf("skipped = %+v, want forked-pkg named with a reason", skipped)
			}
		})
	}
}

// A v1 git dependency's own transitive dependencies are still registry
// packages: refusing the parent must not stop the walk under it.
func TestParse_V1GitDependencyStillWalksItsChildren(t *testing.T) {
	pkgs, stats, _, err := Parse(write(t, `{"lockfileVersion":1,"dependencies":{
		"forked-pkg":{"version":"github:someone/forked-pkg#0123","dependencies":{
			"nested-kept":{"version":"2.0.0"}}}}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "nested-kept" || pkgs[0].Version != "2.0.0" {
		t.Errorf("packages = %+v, want nested-kept@2.0.0 alone", pkgs)
	}
	if stats.Components != 2 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want 2 components, 1 skipped", stats)
	}
}

// The disclosure names the class, never the URL: a git+https spec can carry a
// token in its userinfo, and the reason goes to stderr and CI logs.
func TestParse_SkipReasonDoesNotEchoTheURL(t *testing.T) {
	_, _, skipped, err := Parse(write(t, `{"lockfileVersion":3,"packages":{"":{"name":"app"},
		"node_modules/forked-pkg":{"version":"1.0.0","resolved":"git+https://tok3n-s3cret@github.com/someone/forked-pkg.git"}}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped = %+v, want one entry", skipped)
	}
	for _, s := range []string{skipped[0].Name, skipped[0].Reason} {
		if strings.Contains(s, "tok3n-s3cret") || strings.Contains(s, "github.com") {
			t.Errorf("skip disclosure %q echoes the URL", s)
		}
	}
}
