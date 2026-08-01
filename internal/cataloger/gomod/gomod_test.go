package gomod

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// write drops a go.mod into a fresh directory and returns the directory.
func write(t *testing.T, gomod string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// find resolves a package by EXACT name. Module paths nest, so a
// strings.Contains assertion over the inventory would be satisfied by a
// longer path and pass from the wrong package.
func find(t *testing.T, tgt pkgmeta.Target, name string) pkgmeta.Package {
	t.Helper()
	for _, p := range tgt.Packages {
		if p.Name == name {
			return p
		}
	}
	var have []string
	for _, p := range tgt.Packages {
		have = append(have, p.Name)
	}
	t.Fatalf("no package named %q; got %v", name, have)
	return pkgmeta.Package{}
}

// Both require forms, and the `// indirect` marker kept out of the version.
// An indirect module IS reported: it is linked into the build, and advisories
// apply to it exactly as they do to a direct one.
func TestParse_ReadsBothRequireForms(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\ngo 1.26\n"+
		"\nrequire github.com/single/dep v1.0.0\n"+
		"\nrequire (\n"+
		"\tgithub.com/block/direct v2.3.4\n"+
		"\tgithub.com/block/indirect v0.1.0 // indirect\n"+
		")\n")

	tgt, stats, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Packages) != 3 {
		t.Fatalf("got %d packages, want 3: %+v", len(tgt.Packages), tgt.Packages)
	}
	for _, tt := range []struct{ name, version string }{
		{"github.com/single/dep", "v1.0.0"},
		{"github.com/block/direct", "v2.3.4"},
		{"github.com/block/indirect", "v0.1.0"},
	} {
		got := find(t, tgt, tt.name)
		if got.Version != tt.version {
			t.Errorf("%s version = %q, want %q", tt.name, got.Version, tt.version)
		}
		if got.Ecosystem != "Go" || got.Type != "golang" {
			t.Errorf("%s = %q/%q, want Go/golang", tt.name, got.Ecosystem, got.Type)
		}
		if want := filepath.Join(dir, "go.mod"); len(got.Locations) != 1 ||
			got.Locations[0].Path != want {
			t.Errorf("%s locations = %+v, want one naming %s", tt.name, got.Locations, want)
		}
	}
	if stats.Cataloged != 3 || stats.Components != 3 {
		t.Errorf("stats = %+v, want 3 cataloged of 3 components", stats)
	}
}

// A replace redirects to a different module, so the reported package is the
// replacement. An advisory against the replaced-away path does not apply to
// code that is not there, and the code that IS there would go unchecked.
func TestParse_FollowsReplace(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/old/mod v1.0.0\n"+
		"\nreplace github.com/old/mod => github.com/new/mod v2.0.0\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/new/mod"); got.Version != "v2.0.0" {
		t.Errorf("version = %q, want v2.0.0", got.Version)
	}
	for _, p := range tgt.Packages {
		if p.Name == "github.com/old/mod" {
			t.Errorf("the replaced-away module is still reported: %+v", p)
		}
	}

	// The version-qualified form replaces only that one version.
	dir2 := write(t, "module example.test/app\n"+
		"\nrequire github.com/m/n v1.0.0\n"+
		"\nreplace github.com/m/n v1.0.0 => github.com/m/n v1.0.1\n")
	tgt2, _, err := Parse(dir2)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt2, "github.com/m/n"); got.Version != "v1.0.1" {
		t.Errorf("version = %q, want v1.0.1", got.Version)
	}
}

// A version-qualified replace's left-hand version is not a comment to be
// ignored - it is a condition. `replace A v1.0.0 => B` must NOT redirect a
// requirement on A at a different version: with no unqualified replace to
// fall back to, that requirement is untouched. Collapsing "qualified" and
// "unqualified" replace into one lookup - keyed on path alone - would apply
// this redirect regardless of which version A was actually required at.
func TestParse_VersionQualifiedReplaceDoesNotMatchADifferentVersion(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/m/n v2.0.0\n"+
		"\nreplace github.com/m/n v1.0.0 => github.com/m/n v1.5.0\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/m/n"); got.Version != "v2.0.0" {
		t.Errorf("version = %q, want v2.0.0 - the replace's qualifier (v1.0.0) does not match", got.Version)
	}
}

// A filesystem replace has no version to compare against any range, so it is
// a COUNTED skip. Reporting it with an empty version leaves the matcher
// undefined; dropping it silently removes a dependency from the inventory
// without removing it from the count of what was evaluated.
func TestParse_AFilesystemReplaceIsACountedSkip(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/k/l v1.0.0\n"+
		"\nreplace github.com/k/l => ../local\n")

	tgt, stats, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Packages) != 0 {
		t.Errorf("got %+v, want no packages - ../local has no version", tgt.Packages)
	}
	if stats.Components != 1 {
		t.Errorf("Components = %d, want 1 - the module was seen", stats.Components)
	}
	if stats.SkippedNoVersion != 1 {
		t.Errorf("SkippedNoVersion = %d, want 1 - the skip must be counted", stats.SkippedNoVersion)
	}
}

// module, go, toolchain, exclude and retract contribute no packages. Reading
// `go 1.26` as a package named "go" is exactly the mistake D24 names: it
// would report a version nothing was ever built with.
func TestParse_IgnoresNonRequireDirectives(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\ngo 1.26\n"+
		"\ntoolchain go1.26.4\n"+
		"\nexclude github.com/e/f v1.0.0\n"+
		"\nretract v1.0.1\n"+
		"\nrequire github.com/real/dep v1.0.0\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Packages) != 1 {
		t.Fatalf("got %d packages, want only the require: %+v", len(tgt.Packages), tgt.Packages)
	}
	if tgt.Packages[0].Name != "github.com/real/dep" {
		t.Errorf("package = %q, want github.com/real/dep", tgt.Packages[0].Name)
	}
}

// A go.mod with no require block is a valid module with no dependencies:
// zero packages and no error. This repository had exactly that shape until
// slice 2b, so it is not hypothetical.
func TestParse_ModuleWithNoRequires(t *testing.T) {
	dir := write(t, "module example.test/app\n\ngo 1.26\n")

	tgt, stats, err := Parse(dir)
	if err != nil {
		t.Fatalf("a module with no requires is an error: %v", err)
	}
	if len(tgt.Packages) != 0 {
		t.Errorf("got %+v, want none", tgt.Packages)
	}
	if stats.Components != 0 {
		t.Errorf("Components = %d, want 0", stats.Components)
	}
}

// A directory with no go.mod is an error naming the path, not an empty clean
// scan. "Found nothing" and "there was nothing to look at" must not read
// alike - that distinction is what the whole exit-code contract rests on.
func TestParse_NoGoModIsAnError(t *testing.T) {
	dir := t.TempDir()
	_, _, err := Parse(dir)
	if err == nil {
		t.Fatal("a directory with no go.mod scanned clean")
	}
	if !strings.Contains(err.Error(), "go.mod") {
		t.Errorf("error %q does not mention go.mod", err)
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error %q does not name the directory", err)
	}
}

// Parsing this repository's own go.mod pins D23's measured claim: the require
// blocks name 11 modules (2 direct, 9 indirect), including a test-only
// dependency, gotest.tools/v3, that never links into the built binary. That
// gap between "requires" and "links" is the documented limitation this slice
// is honest about - a test that pins the number is what keeps the README's
// stated limitation from silently drifting out of date.
func TestParse_ThisRepositorysOwnGoMod(t *testing.T) {
	tgt, stats, err := Parse(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Packages) != 11 {
		t.Fatalf("got %d modules, want 11: %+v", len(tgt.Packages), tgt.Packages)
	}
	if stats.Cataloged != 11 || stats.Components != 11 {
		t.Errorf("stats = %+v, want 11 cataloged of 11 components", stats)
	}
	if got := find(t, tgt, "gotest.tools/v3"); got.Version == "" {
		t.Errorf("gotest.tools/v3 has no version: %+v", got)
	}
}

// replace has a block form too, exactly like require. A parser that special-
// cased require's `(...)` form without generalizing it would silently ignore
// a replace block instead of erroring - the redirected module would vanish
// and the replaced-away path would keep reporting as itself.
func TestParse_ReplaceBlockForm(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/old/mod v1.0.0\n"+
		"\nreplace (\n"+
		"\tgithub.com/old/mod => github.com/new/mod v2.0.0\n"+
		")\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/new/mod"); got.Version != "v2.0.0" {
		t.Errorf("version = %q, want v2.0.0", got.Version)
	}
	for _, p := range tgt.Packages {
		if p.Name == "github.com/old/mod" {
			t.Errorf("the replaced-away module is still reported: %+v", p)
		}
	}
}

// A `//` comment on the line that opens or closes a `require ( ... )` block
// must not stop the block from being recognized as such: the comment has to
// be stripped before comparing the line against "(" or ")". Getting this
// wrong does not corrupt data - it drops the entire block's dependencies from
// the inventory, which is a much larger silent gap than a single package.
func TestParse_StripsCommentsOnBlockBoundaries(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire ( // direct dependencies\n"+
		"\tgithub.com/x/y v1.0.0\n"+
		") // end direct dependencies\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/x/y"); got.Version != "v1.0.0" {
		t.Errorf("version = %q, want v1.0.0", got.Version)
	}
}

// A trailing comment on a replace line must not be mistaken for a third
// field on its right-hand side: the right-hand side's field count is exactly
// how a module replacement (2 fields) is told apart from a filesystem one (1
// field), so a stray comment token inflating that count would misclassify a
// perfectly good module replacement as malformed and drop it.
func TestParse_StripsTrailingCommentOnReplace(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/old/mod v1.0.0\n"+
		"\nreplace github.com/old/mod => github.com/new/mod v2.0.0 // pinned, see CVE-2026-0001\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/new/mod"); got.Version != "v2.0.0" {
		t.Errorf("version = %q, want v2.0.0", got.Version)
	}
}

// go.mod allows a module path to be a quoted string, not just a bare token.
// It is rare in practice but valid syntax, and the brief calls it out
// explicitly: comments are stripped "outside quotes" precisely because a
// quoted path could otherwise contain a "//" that is not a comment.
func TestParse_QuotedModulePathIsUnquoted(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire \"github.com/quoted/dep\" v1.0.0\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/quoted/dep"); got.Version != "v1.0.0" {
		t.Errorf("version = %q, want v1.0.0", got.Version)
	}
}
