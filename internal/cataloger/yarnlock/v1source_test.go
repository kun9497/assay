package yarnlock

import (
	"testing"

	"github.com/kun9497/assay/internal/cataloger/npmlock"
)

func TestSourceFromSpecs(t *testing.T) {
	cases := []struct {
		header string
		want   npmlock.SourceClass
	}{
		{`lodash@^4.17.0, lodash@~4.17.15`, npmlock.SourceRegistry},
		{`"@babel/core@^7.0.0"`, npmlock.SourceRegistry},
		{`"aliased@npm:lodash@^4.0.0"`, npmlock.SourceRegistry},
		{`"@scope/aliased@npm:@scope/real@^2.0.0"`, npmlock.SourceRegistry},
		{`left-pad@latest`, npmlock.SourceRegistry},
		{`"lodash@git+https://github.com/someone/lodash.git#0123"`, npmlock.SourceVCS},
		// The URL's own '@' must not be taken for the name/range boundary.
		{`"lodash@git+ssh://git@github.com/someone/lodash.git#0123"`, npmlock.SourceVCS},
		{`"lodash@github:someone/lodash#0123"`, npmlock.SourceVCS},
		{`"lodash@https://example.invalid/lodash-4.17.20.tgz"`, npmlock.SourceVCS},
		// GitHub's bare "user/repo" shorthand: no prefix, but no semver range
		// or dist-tag holds a '/'.
		{`"lodash@someone/lodash#0123"`, npmlock.SourceVCS},
		{`"@scope/pkg@someone/pkg"`, npmlock.SourceVCS},
		// Any spec on a header decides: they all resolve to one entry.
		{`lodash@^4.17.0, "lodash@github:someone/lodash"`, npmlock.SourceVCS},
		{`"lodash@file:../lodash"`, npmlock.SourceLocal},
		{`"lodash@link:../lodash"`, npmlock.SourceLocal},
		{`lodash`, npmlock.SourceRegistry},
		{`""`, npmlock.SourceRegistry},
	}
	for _, tc := range cases {
		if got := sourceFromSpecs(tc.header); got != tc.want {
			t.Errorf("sourceFromSpecs(%s) = %d, want %d", tc.header, got, tc.want)
		}
	}
}

func TestNameFromSpecs_GitURLWithAnAt(t *testing.T) {
	if got := nameFromSpecs(`"lodash@git+ssh://git@github.com/someone/lodash.git#0123"`); got != "lodash" {
		t.Errorf("name = %q, want lodash - the URL's own '@' is not the boundary", got)
	}
}

func TestParseV1_NonRegistrySources(t *testing.T) {
	const kept = `kept-pkg@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/kept-pkg/-/kept-pkg-1.0.0.tgz#aaaa"

`
	rows := []struct {
		name    string
		entry   string
		counted bool
	}{
		{"git+ key", `"forked-pkg@git+https://github.com/someone/forked-pkg.git#0123":
  version "4.17.20"
  resolved "git+https://github.com/someone/forked-pkg.git#0123"
`, true},
		{"git+ssh key with an @ in the URL", `"forked-pkg@git+ssh://git@github.com/someone/forked-pkg.git#0123":
  version "4.17.20"
`, true},
		{"github: key, codeload resolved", `"forked-pkg@github:someone/forked-pkg":
  version "4.17.20"
  resolved "https://codeload.github.com/someone/forked-pkg/tar.gz/0123"
`, true},
		{"semver key, git resolved", `forked-pkg@^4.17.0:
  version "4.17.20"
  resolved "git+https://github.com/someone/forked-pkg.git#0123"
`, true},
		{"file: key", `"forked-pkg@file:../forked-pkg":
  version "4.17.20"
`, false},
		{"semver key, file: resolved", `forked-pkg@^4.17.0:
  version "4.17.20"
  resolved "file:../forked-pkg"
`, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			pkgs, stats, skipped, err := Parse(write(t, "# yarn lockfile v1\n\n\n"+kept+r.entry))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(pkgs) != 1 || pkgs[0].Name != "kept-pkg" {
				t.Errorf("packages = %+v, want kept-pkg alone", pkgs)
			}
			wantComponents, wantSkipped := 1, 0
			if r.counted {
				wantComponents, wantSkipped = 2, 1
			}
			if stats.Components != wantComponents || stats.Cataloged != 1 || stats.SkippedNoVersion != wantSkipped {
				t.Errorf("stats = %+v, want %d components, 1 cataloged, %d SkippedNoVersion",
					stats, wantComponents, wantSkipped)
			}
			if len(skipped) != 1 || skipped[0].Name != "forked-pkg" || skipped[0].Reason == "" {
				t.Errorf("skipped = %+v, want forked-pkg named with a reason", skipped)
			}
		})
	}
}

// The reset after a refused entry: the next entry must not inherit its
// resolved line or its header's class.
func TestParseV1_RefusalDoesNotLeakIntoTheNextEntry(t *testing.T) {
	pkgs, _, _, err := Parse(write(t, `# yarn lockfile v1

"forked-pkg@github:someone/forked-pkg":
  version "4.17.20"
  resolved "git+https://github.com/someone/forked-pkg.git#0123"

next-pkg@^1.0.0:
  version "1.0.0"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "next-pkg" {
		t.Errorf("packages = %+v, want next-pkg alone", pkgs)
	}
}
