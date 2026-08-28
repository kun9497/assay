package pnpmlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pnpm-lock.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// TestParseKeyV5 transcribes the lockfileVersion < 6.0 rows of D103's key
// grammar table directly against the key parser, rather than through a full
// YAML fixture — these rows are about the SEPARATOR AND SUFFIX rules alone,
// which parseKeyV5 owns end to end.
func TestParseKeyV5(t *testing.T) {
	cases := []struct {
		key         string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{"/is-glob/4.0.3", "is-glob", "4.0.3", true},
		{"/@babel/core/7.17.10", "@babel/core", "7.17.10", true},
		{"/@babel/helper-compilation-targets/7.17.10_@babel+core@7.17.10",
			"@babel/helper-compilation-targets", "7.17.10", true},
		{"/webpack-cli/4.10.0_fzn43tb6bdtdxy2s3aqevve2su", "webpack-cli", "4.10.0", true},
		{"/@logux/eslint-config/47.2.0_7hz3xvmviof7onfgk6hpedqcom", "@logux/eslint-config", "47.2.0", true},
		// A v5 git-style key carries no leading "/" at all - the split still
		// succeeds syntactically (there is a "/" to split on), which is
		// exactly why key-shape alone cannot be the classifier: the
		// resolution object is (see TestParse_ResolutionClassification for
		// the same two keys carried through a full parse).
		{"github.com/user/repo/abc123", "github.com/user/repo", "abc123", true},
		{"github.com/user/repo/9f3ab12", "github.com/user/repo", "9f3ab12", true},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			name, version, ok := parseKeyV5(tc.key)
			if ok != tc.wantOK || name != tc.wantName || version != tc.wantVersion {
				t.Errorf("parseKeyV5(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.key, name, version, ok, tc.wantName, tc.wantVersion, tc.wantOK)
			}
		})
	}
}

// TestParseKeyV6Plus transcribes the 6.x and 9.x rows - one function since
// the two share a grammar (see shapeFor's own comment on why).
func TestParseKeyV6Plus(t *testing.T) {
	cases := []struct {
		key         string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{"/is-glob@4.0.3", "is-glob", "4.0.3", true},
		{"/@babel/core@7.23.9", "@babel/core", "7.23.9", true},
		{"/@babel/parser@7.18.4(@babel/types@7.19.0)", "@babel/parser", "7.18.4", true},
		{"/@typescript-eslint/eslint-plugin@5.62.0(@typescript-eslint/parser@5.62.0)(eslint@8.56.0)(typescript@5.0.0-beta)",
			"@typescript-eslint/eslint-plugin", "5.62.0", true},
		{"@ampproject/remapping@2.3.0", "@ampproject/remapping", "2.3.0", true},
		{"cross-spawn@7.0.6", "cross-spawn", "7.0.6", true},
		{"JSONStream@1.3.5", "JSONStream", "1.3.5", true},
		{"@pnpm/ramda@0.28.1", "@pnpm/ramda", "0.28.1", true},
		{"foo@1.0.0-beta.1+build.5", "foo", "1.0.0-beta.1+build.5", true},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			name, version, ok := parseKeyV6Plus(tc.key)
			if ok != tc.wantOK || name != tc.wantName || version != tc.wantVersion {
				t.Errorf("parseKeyV6Plus(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.key, name, version, ok, tc.wantName, tc.wantVersion, tc.wantOK)
			}
		})
	}
}

// TestParse_ResolutionClassification carries every packages: -level row of
// the adversarial table through a full Parse: the registry filter, the local
// skip, the git skip (including the two keys TestParseKeyV5 showed a
// version-shape guard could not tell apart), and the alias/dedupe rows that
// need a real YAML document rather than a bare key string.
func TestParse_ResolutionClassification(t *testing.T) {
	t.Run("v9 uppercase name and alias target", func(t *testing.T) {
		path := write(t, "lockfileVersion: '9.0'\n\n"+
			"packages:\n\n"+
			"  JSONStream@1.3.5:\n"+
			"    resolution: {integrity: sha512-uppercase==}\n\n"+
			// The alias itself lives in importers/dependencies, which this
			// parser never reads (rule 1) - what packages: carries for an
			// aliased dependency is the ALIAS TARGET's own real key, which
			// is indistinguishable from an ordinary entry once packages: is
			// the only thing being read.
			"  '@pnpm/ramda@0.28.1':\n"+
			"    resolution: {integrity: sha512-aliastarget==}\n")

		pkgs, stats, skipped, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(skipped) != 0 {
			t.Errorf("skipped = %+v, want none", skipped)
		}
		want := map[string]string{"JSONStream": "1.3.5", "@pnpm/ramda": "0.28.1"}
		if len(pkgs) != len(want) {
			t.Fatalf("pkgs = %+v, want %v", pkgs, want)
		}
		for _, p := range pkgs {
			if want[p.Name] != p.Version {
				t.Errorf("%s = %s, want %s", p.Name, p.Version, want[p.Name])
			}
		}
		if stats.Components != 2 || stats.Cataloged != 2 {
			t.Errorf("stats = %+v, want 2 components, 2 cataloged", stats)
		}
	})

	t.Run("v9 build metadata survives verbatim", func(t *testing.T) {
		path := write(t, "lockfileVersion: '9.0'\n\n"+
			"packages:\n\n"+
			"  foo@1.0.0-beta.1+build.5:\n"+
			"    resolution: {integrity: sha512-buildmeta==}\n")
		pkgs, _, _, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(pkgs) != 1 || pkgs[0].Version != "1.0.0-beta.1+build.5" {
			t.Fatalf("pkgs = %+v, want foo@1.0.0-beta.1+build.5", pkgs)
		}
	})

	t.Run("v9 directory resolution is a local skip", func(t *testing.T) {
		path := write(t, "lockfileVersion: '9.0'\n\n"+
			"packages:\n\n"+
			"  '@scope/name@0.0.0-use.local':\n"+
			"    resolution: {directory: packages/name, type: directory}\n")
		pkgs, stats, skipped, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(pkgs) != 0 {
			t.Fatalf("pkgs = %+v, want none", pkgs)
		}
		// Local: shown, but NOT counted into Stats at all - it is not a
		// coverage gap the --fail-on-incomplete=target gate should trip on.
		if stats.Components != 0 {
			t.Errorf("Components = %d, want 0 - a workspace member is not a component", stats.Components)
		}
		if len(skipped) != 1 || skipped[0].Name != "@scope/name@0.0.0-use.local" {
			t.Fatalf("skipped = %+v, want the workspace member named", skipped)
		}
	})

	t.Run("v5 git resolution is a git skip regardless of how plausible the version looks", func(t *testing.T) {
		// Both keys parse to a syntactically valid (name, version) pair
		// (TestParseKeyV5 above) - what makes them "skip git" is the
		// resolution object alone, never the shape of "abc123" or
		// "9f3ab12". A version-shape heuristic would treat the second as a
		// plausible version (leading digit does not disqualify a semver
		// build tag); resolution-based classification does not care.
		for _, key := range []string{"github.com/user/repo/abc123", "github.com/user/repo/9f3ab12"} {
			path := write(t, "lockfileVersion: 5.4\n\npackages:\n\n  "+key+":\n"+
				"    resolution: {tarball: 'https://codeload.github.com/user/repo/tar.gz/abc123'}\n")
			pkgs, stats, skipped, err := Parse(path)
			if err != nil {
				t.Fatalf("Parse(%s): %v", key, err)
			}
			if len(pkgs) != 0 {
				t.Fatalf("Parse(%s): pkgs = %+v, want none", key, pkgs)
			}
			if stats.Components != 1 || stats.SkippedNoVersion != 1 {
				t.Errorf("Parse(%s): stats = %+v, want 1 component skipped as no-version", key, stats)
			}
			if len(skipped) != 1 {
				t.Fatalf("Parse(%s): skipped = %+v, want one entry", key, skipped)
			}
		}
	})

	t.Run("v9 two documents union", func(t *testing.T) {
		path := write(t, "lockfileVersion: '9.0'\n\npackages:\n\n  first-doc-pkg@1.0.0:\n"+
			"    resolution: {integrity: sha512-firstdoc==}\n"+
			"---\n"+
			"lockfileVersion: '9.0'\n\npackages:\n\n  second-doc-pkg@2.0.0:\n"+
			"    resolution: {integrity: sha512-seconddoc==}\n")
		pkgs, stats, _, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		got := map[string]string{}
		for _, p := range pkgs {
			got[p.Name] = p.Version
		}
		want := map[string]string{"first-doc-pkg": "1.0.0", "second-doc-pkg": "2.0.0"}
		if len(got) != len(want) || got["first-doc-pkg"] != "1.0.0" || got["second-doc-pkg"] != "2.0.0" {
			t.Fatalf("pkgs = %v, want %v", got, want)
		}
		if stats.Components != 2 || stats.Cataloged != 2 {
			t.Errorf("stats = %+v, want 2 components, 2 cataloged (the union of both documents)", stats)
		}
	})

	t.Run("v9 duplicate name at version across documents dedupes silently", func(t *testing.T) {
		path := write(t, "lockfileVersion: '9.0'\n\npackages:\n\n  shared-dep@3.0.0:\n"+
			"    resolution: {integrity: sha512-shareddep==}\n"+
			"---\n"+
			"lockfileVersion: '9.0'\n\npackages:\n\n  shared-dep@3.0.0:\n"+
			"    resolution: {integrity: sha512-shareddep==}\n")
		pkgs, stats, skipped, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(pkgs) != 1 || pkgs[0].Name != "shared-dep" || pkgs[0].Version != "3.0.0" {
			t.Fatalf("pkgs = %+v, want shared-dep@3.0.0 emitted once", pkgs)
		}
		if stats.Components != 1 || stats.Cataloged != 1 {
			t.Errorf("stats = %+v, want the duplicate silently absorbed", stats)
		}
		if len(skipped) != 0 {
			t.Errorf("skipped = %+v, want none - a dedupe is not a skip", skipped)
		}
	})
}

// TestParse_LockfileVersionDispatch covers the three shape ranges and the
// unquoted-vs-quoted scalar form, plus the missing/unparseable error case.
func TestParse_LockfileVersionDispatch(t *testing.T) {
	t.Run("5.4 unquoted number", func(t *testing.T) {
		path := write(t, "lockfileVersion: 5.4\n\npackages:\n\n  /is-glob/4.0.3:\n"+
			"    resolution: {integrity: sha512-unquoted54==}\n")
		pkgs, _, _, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(pkgs) != 1 || pkgs[0].Name != "is-glob" || pkgs[0].Version != "4.0.3" {
			t.Fatalf("pkgs = %+v, want is-glob@4.0.3", pkgs)
		}
	})

	t.Run("6.0 quoted string", func(t *testing.T) {
		path := write(t, "lockfileVersion: '6.0'\n\npackages:\n\n  /is-glob@4.0.3:\n"+
			"    resolution: {integrity: sha512-quoted60==}\n")
		pkgs, _, _, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(pkgs) != 1 || pkgs[0].Name != "is-glob" || pkgs[0].Version != "4.0.3" {
			t.Fatalf("pkgs = %+v, want is-glob@4.0.3", pkgs)
		}
	})

	t.Run("9.0 quoted string", func(t *testing.T) {
		path := write(t, "lockfileVersion: '9.0'\n\npackages:\n\n  cross-spawn@7.0.6:\n"+
			"    resolution: {integrity: sha512-quoted90==}\n")
		pkgs, _, _, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(pkgs) != 1 || pkgs[0].Name != "cross-spawn" {
			t.Fatalf("pkgs = %+v, want cross-spawn@7.0.6", pkgs)
		}
	})

	t.Run("unparseable lockfileVersion is a hard error", func(t *testing.T) {
		path := write(t, "lockfileVersion: v6\n\npackages:\n\n  left-pad@1.3.0:\n"+
			"    resolution: {integrity: sha512-x==}\n")
		_, _, _, err := Parse(path)
		if err == nil {
			t.Fatal("err = nil, want an error - a lockfileVersion this parser cannot range-dispatch on")
		}
		if !strings.Contains(err.Error(), "lockfileVersion") {
			t.Errorf("err = %v, want it to name lockfileVersion", err)
		}
	})

	t.Run("missing lockfileVersion is a hard error", func(t *testing.T) {
		path := write(t, "packages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x==}\n")
		_, _, _, err := Parse(path)
		if err == nil {
			t.Fatal("err = nil, want an error")
		}
	})
}

// TestParse_MultiDocumentDecodeFailureKeepsEarlierDocuments covers the
// malformation disposition specific to streaming: a later document's own
// decode error must not cost the packages an earlier, good document already
// yielded.
func TestParse_MultiDocumentDecodeFailureKeepsEarlierDocuments(t *testing.T) {
	path := write(t, "lockfileVersion: '9.0'\n\npackages:\n\n  good-doc-pkg@1.0.0:\n"+
		"    resolution: {integrity: sha512-gooddoc==}\n"+
		"---\n"+
		"lockfileVersion: '9.0\n"+ // unterminated quote: doc 1 fails to decode
		"packages: {\n")

	pkgs, stats, skipped, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v, want the earlier document's packages kept rather than the whole file refused", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "good-doc-pkg" {
		t.Fatalf("pkgs = %+v, want good-doc-pkg alone", pkgs)
	}
	if stats.Components != 2 || stats.SkippedNoPURL != 1 {
		t.Errorf("stats = %+v, want the broken document counted as a malformed-class skip", stats)
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped = %+v, want the broken document named", skipped)
	}
}

// The very first document failing to decode is a different disposition: with
// nothing kept yet, there is nothing to lose by refusing outright.
func TestParse_FirstDocumentDecodeFailureIsAHardError(t *testing.T) {
	path := write(t, "lockfileVersion: '9.0\npackages: {\n")
	_, _, _, err := Parse(path)
	if err == nil {
		t.Fatal("err = nil, want a decode error")
	}
}

// A malformed entry - one whose resolution carries none of the fields this
// parser recognizes at all - is the third of the three dispositions, and
// distinct from both the local and git skips: there is no field here to
// classify a real disposition from.
func TestParse_ResolutionWithNoRecognizedFieldsIsMalformed(t *testing.T) {
	path := write(t, "lockfileVersion: '9.0'\n\npackages:\n\n  unclassifiable-pkg@1.0.0:\n"+
		"    resolution: {unknownField: something}\n")
	pkgs, stats, skipped, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("pkgs = %+v, want none", pkgs)
	}
	if stats.Components != 1 || stats.SkippedNoPURL != 1 {
		t.Errorf("stats = %+v, want 1 component skipped as no-purl", stats)
	}
	if len(skipped) != 1 || skipped[0].Name != "unclassifiable-pkg@1.0.0" {
		t.Fatalf("skipped = %+v, want the entry named", skipped)
	}
}

// A packages: key that fails the split entirely - 0 observed in the corpus
// this parser was checked against, but any hit must be visible rather than
// silently dropped.
func TestParse_KeyThatFailsTheSplitIsMalformed(t *testing.T) {
	path := write(t, "lockfileVersion: '9.0'\n\npackages:\n\n  \"no-at-sign-at-all\":\n"+
		"    resolution: {integrity: sha512-x==}\n")
	pkgs, stats, skipped, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("pkgs = %+v, want none", pkgs)
	}
	if stats.Components != 1 || stats.SkippedNoPURL != 1 {
		t.Errorf("stats = %+v, want 1 component skipped as no-purl", stats)
	}
	if len(skipped) != 1 || skipped[0].Name != "no-at-sign-at-all" {
		t.Fatalf("skipped = %+v, want the raw key named", skipped)
	}
}

// A registry package whose resolution also carries a tarball field pointed
// at npm's own registry must still be included - a bare "has tarball" check
// would wrongly route it to the git-class skip.
func TestParse_TarballOnNpmRegistryHostIsStillRegistry(t *testing.T) {
	path := write(t, "lockfileVersion: '9.0'\n\npackages:\n\n  explicit-tarball-pkg@1.0.0:\n"+
		"    resolution: {integrity: sha512-x==, tarball: 'https://registry.npmjs.org/explicit-tarball-pkg/-/explicit-tarball-pkg-1.0.0.tgz'}\n")
	pkgs, stats, skipped, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "explicit-tarball-pkg" {
		t.Fatalf("pkgs = %+v, want explicit-tarball-pkg included", pkgs)
	}
	if stats.Cataloged != 1 {
		t.Errorf("stats = %+v, want it cataloged", stats)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped = %+v, want none", skipped)
	}
}

// A tarball hosted elsewhere - the third-party/forked-package case - is the
// non-registry disposition, same bucket as git.
func TestParse_TarballOffNpmRegistryHostIsGit(t *testing.T) {
	path := write(t, "lockfileVersion: '9.0'\n\npackages:\n\n  third-party-tarball-pkg@1.0.0:\n"+
		"    resolution: {tarball: 'https://example.invalid/third-party-tarball-pkg-1.0.0.tgz'}\n")
	pkgs, stats, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("pkgs = %+v, want none", pkgs)
	}
	if stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want 1 skipped as no-version", stats)
	}
}

func TestParse_MissingFile(t *testing.T) {
	_, _, _, err := Parse(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("err = nil, want a read error")
	}
}
