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
	if tgt.Distro != nil {
		t.Errorf("Distro = %+v, want nil - a Go module is not a distro (D7)", tgt.Distro)
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
		if want := "pkg:golang/" + tt.name + "@" + tt.version; got.PURL != want {
			t.Errorf("%s PURL = %q, want %q", tt.name, got.PURL, want)
		}
		if got.Source != nil {
			t.Errorf("%s Source = %+v, want nil - D8's source/binary split is a distro concern and Go has none", tt.name, got.Source)
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

	tgt, stats, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Packages) != 1 {
		t.Fatalf("got %d packages, want only the require: %+v", len(tgt.Packages), tgt.Packages)
	}
	if tgt.Packages[0].Name != "github.com/real/dep" {
		t.Errorf("package = %q, want github.com/real/dep", tgt.Packages[0].Name)
	}
	// The counters, not just the package list. Handing `go 1.26` or
	// `module example.test/app` to the require parser does not fabricate a
	// package - each is a single field, so it lands in the missing-version
	// skip - but it DOES fabricate a counted skip. Asserting only the package
	// count leaves that invisible, and the consequence is user-facing: a
	// directory scan that evaluated everything would report packages it could
	// not evaluate, and `--fail-on-incomplete` would exit 2 on a complete
	// scan. Both mutations survived the suite until this assertion existed.
	if stats.Components != 1 || stats.Cataloged != 1 {
		t.Errorf("stats = %+v, want exactly 1 component and 1 cataloged - a directive "+
			"read as a require inflates Components without adding a package", stats)
	}
	if stats.SkippedNoVersion != 0 {
		t.Errorf("SkippedNoVersion = %d, want 0 - no directive here is a package that "+
			"could not be versioned", stats.SkippedNoVersion)
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

// `require(` with no space before the paren is valid go.mod - confirmed
// against the real toolchain with `go mod edit -json`. Splitting the
// directive keyword on whitespace alone reads "require(" as one
// unrecognized token, silently ignoring the entire block: an entire
// dependency list disappearing into a scan that reports no error and no
// components, which report.Table and Summary.Trustworthy both read as a
// clean, complete scan.
func TestParse_RequireBlockWithNoSpaceBeforeParen(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire(\n"+
		"\tgithub.com/x/y v1.0.0\n"+
		")\n")

	tgt, stats, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/x/y"); got.Version != "v1.0.0" {
		t.Errorf("version = %q, want v1.0.0", got.Version)
	}
	if stats.Cataloged != 1 || stats.Components != 1 {
		t.Errorf("stats = %+v, want 1 cataloged of 1 component", stats)
	}
}

// The same hole, one space further along: extra whitespace between the
// keyword and "(" must not stop the block from being recognized either.
// This specifically exercises the strings.TrimSpace(rest) call that turns
// " (" into "(" for comparison - removing it silently loses the block the
// same way the no-space case does.
func TestParse_RequireBlockWithExtraSpaceBeforeParen(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire  (\n"+
		"\tgithub.com/x/y v1.0.0\n"+
		")\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/x/y"); got.Version != "v1.0.0" {
		t.Errorf("version = %q, want v1.0.0", got.Version)
	}
}

// The no-space-before-paren hole is not require-specific: replace, exclude
// and retract all accept the same block form, so the keyword/paren split
// has to work for all of them, not just the one directive the brief's own
// fixtures happen to exercise.
func TestParse_ReplaceBlockWithNoSpaceBeforeParen(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/old/mod v1.0.0\n"+
		"\nreplace(\n"+
		"\tgithub.com/old/mod => github.com/new/mod v2.0.0\n"+
		")\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/new/mod"); got.Version != "v2.0.0" {
		t.Errorf("version = %q, want v2.0.0", got.Version)
	}
}

// A require line missing its version field is malformed but names a real
// path, so it degrades the same way a filesystem replace does: a counted
// skip, not a silent drop that leaves no trace in Components.
func TestParse_MalformedRequireMissingVersionIsACountedSkip(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/good/dep v1.0.0\n"+
		"\nrequire github.com/bad/dep\n")

	tgt, stats, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Packages) != 1 {
		t.Fatalf("got %+v, want only github.com/good/dep", tgt.Packages)
	}
	find(t, tgt, "github.com/good/dep")
	for _, p := range tgt.Packages {
		if p.Name == "github.com/bad/dep" {
			t.Errorf("a require with no version was cataloged: %+v", p)
		}
	}
	if stats.Components != 2 {
		t.Errorf("Components = %d, want 2 - both requires were seen", stats.Components)
	}
	if stats.Cataloged != 1 {
		t.Errorf("Cataloged = %d, want 1", stats.Cataloged)
	}
	if stats.SkippedNoVersion != 1 {
		t.Errorf("SkippedNoVersion = %d, want 1 - the malformed require must be counted", stats.SkippedNoVersion)
	}
}

// A replace directive with no "=>" at all cannot be told apart from a
// require-like line by field count, and cannot safely be dropped either:
// doing so leaves the original requirement reporting as itself, unreplaced -
// a false positive on code that is not there (whatever the replace intended
// to redirect away from) paired with a silent miss of the code that is
// (whatever it intended to redirect to). Unlike a plain missing version,
// there is no single requirement to attach a skip to, so this is an error.
func TestParse_MalformedReplaceMissingArrowIsAnError(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/a/b v1.0.0\n"+
		"\nreplace github.com/a/b v1.0.0 github.com/c/d v2.0.0\n")

	_, _, err := Parse(dir)
	if err == nil {
		t.Fatal("a replace directive with no => scanned clean")
	}
}

// A replace directive whose right-hand side has three fields instead of one
// or two is equally unparseable, for the same reason: silently dropping it
// leaves the original requirement standing in for a module that was
// supposed to be redirected away.
func TestParse_ReplaceWithTooManyRightHandFieldsIsAnError(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/a/b v1.0.0\n"+
		"\nreplace github.com/a/b => github.com/c/d v2.0.0 extra\n")

	_, _, err := Parse(dir)
	if err == nil {
		t.Fatal("a replace directive with a malformed right-hand side scanned clean")
	}
}

// An unterminated `require ( ... )` block - truncated, or mangled by an
// unresolved merge conflict - must not swallow the directives that follow
// it as body lines. Left unchecked, they get parsed as `path version` pairs:
// exactly the D24 mistake (`go` reported as a package) reproduced by a
// broken file instead of a code bug.
func TestParse_UnterminatedBlockIsAnError(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire (\n"+
		"\tgithub.com/a/b v1.0.0\n")

	_, _, err := Parse(dir)
	if err == nil {
		t.Fatal("an unterminated require block scanned clean")
	}
}

// go.mod directive blocks do not nest. A line inside an open require block
// that itself looks like it is opening another block must not be read as an
// ordinary require entry (which would fabricate a package named after the
// inner keyword) or silently close the outer block early.
func TestParse_NestedBlockIsAnError(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire (\n"+
		"\tgithub.com/a/b v1.0.0\n"+
		"\texclude (\n"+
		"\tgithub.com/c/d v1.0.0\n"+
		")\n"+
		")\n")

	_, _, err := Parse(dir)
	if err == nil {
		t.Fatal("a nested block scanned clean")
	}
}

// A quoted module path containing an internal space is split apart by this
// scan's whitespace-based field splitting before the quote is ever seen as
// one token - it is not just unsupported, it is misread. Reporting a name
// with a stray leading quote and whatever field happened to land next as
// the version would catalog it as evaluated when it is not; the right
// degradation is the same counted skip a missing version gets.
func TestParse_QuotedPathWithInternalSpaceIsACountedSkip(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/good/dep v1.0.0\n"+
		"\nrequire \"github.com/a b\" v1.0.0\n")

	tgt, stats, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Packages) != 1 {
		t.Fatalf("got %+v, want only github.com/good/dep", tgt.Packages)
	}
	for _, p := range tgt.Packages {
		if strings.Contains(p.Name, `"`) {
			t.Errorf("a stray quote leaked into a package name: %+v", p)
		}
	}
	if stats.Components != 2 || stats.Cataloged != 1 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want Components=2 Cataloged=1 SkippedNoVersion=1", stats)
	}
}

// When both an unqualified and a version-qualified replace target the same
// module, the qualified one - being the more specific directive - takes
// precedence for the version it names. Reversing that precedence would
// apply the generic redirect even where a specific one was given.
func TestParse_QualifiedReplaceTakesPrecedenceOverUnqualified(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/m/n v1.0.0\n"+
		"\nreplace github.com/m/n => github.com/other/any v9.9.9\n"+
		"\nreplace github.com/m/n v1.0.0 => github.com/m/n v1.0.1\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/m/n"); got.Version != "v1.0.1" {
		t.Errorf("version = %q, want v1.0.1 - the qualified replace should win", got.Version)
	}
	for _, p := range tgt.Packages {
		if p.Name == "github.com/other/any" {
			t.Errorf("the unqualified replace fired even though a qualified one matched: %+v", p)
		}
	}
}

// Quoting is not require-only: both sides of a replace directive may be
// quoted, and both must be unquoted the same way.
func TestParse_ReplaceUnquotesBothSides(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire \"github.com/quoted/old\" v1.0.0\n"+
		"\nreplace \"github.com/quoted/old\" => \"github.com/quoted/new\" v2.0.0\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := find(t, tgt, "github.com/quoted/new"); got.Version != "v2.0.0" {
		t.Errorf("version = %q, want v2.0.0", got.Version)
	}
	for _, p := range tgt.Packages {
		if strings.Contains(p.Name, `"`) {
			t.Errorf("a stray quote leaked into a package name: %+v", p)
		}
	}
}

// bufio.Scanner's default token buffer is 64KB; a single go.mod line longer
// than that makes Scan() stop with a wrapped bufio.ErrTooLong instead of
// reaching EOF cleanly. That error path is otherwise never exercised by any
// fixture in this file, so a mutation silencing it (`&& false`) would
// survive undetected.
//
// This is a real, accepted divergence from `go mod edit -json`, which has no
// such per-line limit - not a deliberately chosen behaviour, just an
// unraised default this scan has never needed to widen. No real go.mod line
// is remotely this long (the longest directive here is a few dozen
// characters), so the divergence is not expected to matter in practice; this
// test exists to confirm the error path is reachable and surfaced as an
// error rather than silently truncating or panicking, not to bless 64KB as
// a correct or intended limit.
func TestParse_ScannerErrorPropagates(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/good/dep v1.0.0\n"+
		"\n// "+strings.Repeat("x", 70000)+"\n")

	_, _, err := Parse(dir)
	if err == nil {
		t.Fatal("a go.mod with a line over the scanner's token limit scanned clean")
	}
}

// This parser does not deduplicate a module required twice - by two
// separate require lines, possibly at different versions, most plausibly
// from a hand-edited or merge-conflicted go.mod. Deciding which version
// "wins" would require guessing on the user's behalf and silently dropping
// evidence of the other; reporting both, each counted, is what the
// never-drop-silently rule this cataloger otherwise follows calls for. This
// pins that choice so a future change to it is deliberate, not incidental.
func TestParse_DuplicateRequireReportsBothEntries(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/dup/mod v1.0.0\n"+
		"\nrequire github.com/dup/mod v2.0.0\n")

	tgt, stats, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tgt.Packages) != 2 {
		t.Fatalf("got %+v, want both duplicate requires reported", tgt.Packages)
	}
	var versions []string
	for _, p := range tgt.Packages {
		if p.Name != "github.com/dup/mod" {
			t.Errorf("unexpected package: %+v", p)
		}
		versions = append(versions, p.Version)
	}
	if !((versions[0] == "v1.0.0" && versions[1] == "v2.0.0") ||
		(versions[0] == "v2.0.0" && versions[1] == "v1.0.0")) {
		t.Errorf("versions = %v, want v1.0.0 and v2.0.0", versions)
	}
	if stats.Components != 2 || stats.Cataloged != 2 {
		t.Errorf("stats = %+v, want 2 cataloged of 2 components", stats)
	}
}

// A quoted replace target containing an internal space - an ordinary local
// path on Windows, where this repo is developed - is split into two fields
// by this scan's whitespace-based splitting before the quote is ever seen as
// one token. `go mod edit -json` accepts this file; routing the split
// pieces to the "module + version" branch made the whole scan fail instead.
// Indefensible on top of being overly strict: the correct parse is a
// filesystem replacement, and Parse discards a filesystem RHS's value
// regardless (name, version = "", "") - the scan was dying over a token it
// never uses. Same table as the review that found this.
func TestParse_ReplaceWithQuotedWhitespacePathIsACountedSkip(t *testing.T) {
	for _, tt := range []struct {
		name  string
		gomod string
	}{
		{
			name: "unqualified, unix-style path",
			gomod: "module example.test/app\n" +
				"\nrequire example.com/a v1.0.0\n" +
				"\nreplace example.com/a => \"../my dir\"\n",
		},
		{
			name: "unqualified, windows-style path",
			gomod: "module example.test/app\n" +
				"\nrequire example.com/a v1.0.0\n" +
				"\nreplace example.com/a => \"C:\\Users\\John Doe\\a\"\n",
		},
		{
			name: "version-qualified",
			gomod: "module example.test/app\n" +
				"\nrequire example.com/a v1.0.0\n" +
				"\nreplace example.com/a v1.0.0 => \"../a dir\"\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := write(t, tt.gomod)

			tgt, stats, err := Parse(dir)
			if err != nil {
				t.Fatalf("scanned with an error, want a counted skip: %v", err)
			}
			if len(tgt.Packages) != 0 {
				t.Errorf("got %+v, want no packages - the replacement target has no version", tgt.Packages)
			}
			if stats.Components != 1 || stats.Cataloged != 0 || stats.SkippedNoVersion != 1 {
				t.Errorf("stats = %+v, want Components=1 Cataloged=0 SkippedNoVersion=1", stats)
			}
		})
	}
}

// The same malformation on the LEFT-hand side - the module being replaced,
// rather than its target - leaves no key to register a replacement under.
// `go mod edit -json` accepts this file too; the fix must not turn a
// left-side quoted-with-space path into a scan-ending error, and must not
// let the unregistered replace directive fabricate a package either.
func TestParse_ReplaceWithQuotedWhitespaceOldPathDoesNotCrash(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire github.com/good/dep v1.0.0\n"+
		"\nreplace \"example.com/a b\" => example.com/c v2.0.0\n")

	tgt, _, err := Parse(dir)
	if err != nil {
		t.Fatal(err)
	}
	find(t, tgt, "github.com/good/dep")
	for _, p := range tgt.Packages {
		if p.Name == "example.com/c" {
			t.Errorf("an unkeyed replace directive fabricated a package: %+v", p)
		}
	}
}

// `require(path version)` crammed onto one line - no space anywhere - is not
// valid go.mod; go itself rejects it. Before the F1 fix, splitKeyword's
// whitespace-only split read "require(path" as one unrecognized token and
// silently dropped the whole line. Widening splitKeyword to treat "(" as a
// token boundary (so `require(` can open a block) introduced a NEW failure
// mode for this shape instead: the keyword now splits off cleanly, but the
// remainder ("(path version)") is neither exactly "(" (a block open) nor a
// clean single-line body - and was falling through to ordinary parsing,
// fabricating a package with a stray "(" stuck to its name and a stray ")"
// stuck to its version. Rejected instead: a block's opening line is always
// the keyword alone followed by "(" and nothing else.
func TestParse_RequireWithContentCrammedAfterUnspacedParenIsAnError(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire(example.com/a v1.0.0)\n")

	_, _, err := Parse(dir)
	if err == nil {
		t.Fatal("require(path version) on one line scanned clean")
	}
}

// The sibling shape with spaces around the parenthesis - `require ( x
// v1.0.0 )` all on one line - is the same malformation and was already
// fabricating a package (named "(", the stray open-paren token) before this
// round. Rejecting the unspaced form and not this one would leave an
// equivalent hole standing right next to the fix; both are rejected the same
// way, for the same reason: a block's opening line names nothing else.
func TestParse_RequireBlockOpenWithContentOnSameLineIsAnError(t *testing.T) {
	dir := write(t, "module example.test/app\n"+
		"\nrequire ( example.com/a v1.0.0 )\n")

	_, _, err := Parse(dir)
	if err == nil {
		t.Fatal("require ( x v1.0.0 ) on one line scanned clean")
	}
}
