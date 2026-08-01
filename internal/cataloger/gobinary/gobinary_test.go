package gobinary

import (
	"archive/zip"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// find returns the package with the given name, or fails. Never assert with
// strings.Contains over the whole inventory: module paths nest, so
// "golang.org/x/sys" is satisfied by "golang.org/x/sys/unix" and every
// assertion would pass from the wrong package.
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

// gitEnv returns an environment safe for shelling out to git - and to `go
// build`, which shells out to git itself to gather VCS stamping info - from
// a test fixture. Every GIT_* variable is dropped: git exports GIT_DIR for
// every hook it runs, so a fixture built from inside a pre-commit or
// pre-push hook would otherwise have `git init`/`config`/`commit` operate on
// the repository GIT_DIR names instead of the fixture directory. Reproduced
// directly by TestBuildFixture_IgnoresAmbientGitDir. GIT_CONFIG_GLOBAL and
// GIT_CONFIG_SYSTEM are pointed at the null device so a global
// commit.gpgsign=true or core.hooksPath cannot turn the fixture commit into
// a failure either.
func gitEnv() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_SYSTEM="+os.DevNull,
	)
}

// writeModule writes a go.mod and main.go into dir.
func writeModule(t *testing.T, dir, gomod, mainGo string) {
	t.Helper()
	for name, content := range map[string]string{
		"go.mod":  gomod,
		"main.go": mainGo,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// commitFixture commits everything currently in dir to a throwaway git repo,
// using gitEnv() for every subprocess (see its comment for why that is not
// optional). A subsequent `go build -buildvcs=true` in dir then stamps a
// real pseudo-version instead of "(devel)" - see buildFixture's comment for
// why a bare .git directory with no commit does not get you that.
//
// Callers must check for git themselves, with a message naming what THEIR
// test loses without it: "the main module gets a real version" reads
// differently for a test that inspects the version itself
// (TestParse_IncludesTheMainModule) than for one that needs it only so
// find() can see the module at all (TestParse_ReportsModulePathNotPackagePath).
func commitFixture(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "fixture@example.test"},
		{"config", "user.name", "fixture"},
		// The fixture's line endings are already \n; without this git would
		// rewrite them to CRLF on the next checkout on Windows, which is
		// irrelevant here but noisy in the build output.
		{"config", "core.autocrlf", "false"},
		{"add", "-A"},
		{"commit", "-q", "-m", "fixture"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = gitEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

// runGoBuild runs `go build -o <dir>/app.bin <pkg>` in dir, with
// extraGoflags appended to GOFLAGS and extraEnv appended to the environment
// (used to redirect GOMODCACHE - see modCacheEnv), and returns the binary's
// path.
//
// GOFLAGS=-mod=mod lets the build resolve from the module cache without a
// go.sum; GOPROXY=off makes a cache miss an error rather than a silent
// network fetch. A cache miss under GOPROXY=off is an honest, explained
// skip - the fixture could not be built - but folding every other non-zero
// exit into that same "needs modules not in the local cache" message would
// hide a fixture that is simply broken (bad Go syntax, a future Go version
// rejecting `go 1.26`, a real -buildvcs failure) behind the wrong
// explanation, so only that specific, matched failure skips; anything else
// fails the test. This shared-cache skip only makes sense for the fixtures
// in this file that actually depend on a real, previously-downloaded module
// (go.etcd.io/bbolt, golang.org/x/sync) - TestParse_FollowsReplaceDirectives_DifferentModulePath
// builds its own private proxy instead and must not use this helper's skip
// for that reason (see its own comment).
func runGoBuild(t *testing.T, dir, pkg, extraGoflags string, extraEnv ...string) string {
	t.Helper()
	bin := filepath.Join(dir, "app.bin")
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	cmd.Dir = dir
	cmd.Env = append(gitEnv(),
		"GOFLAGS=-mod=mod "+extraGoflags,
		"GOPROXY=off",
		"GOSUMDB=off",
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return bin
	}
	if strings.Contains(string(out), "module lookup disabled by GOPROXY=off") {
		t.Skipf("go build failed (%v); fixture needs modules not in the local cache:\n%s", err, out)
	}
	t.Fatalf("go build failed (%v):\n%s", err, out)
	return ""
}

// modCacheEnv returns a GOMODCACHE override pointed at a fresh scratch
// directory, for fixtures with no real external dependency (nothing to miss
// by not using the shared cache). Without this, `go build -buildvcs=true`
// writes a VCS-derived pseudo-version cache entry for the *main* module
// itself into the shared, machine-wide module cache - one
// $GOMODCACHE/cache/download/example.test/app/@v/<version>.info per run,
// never cleaned, since module cache entries are read-only. The dependency-
// backed fixtures (buildFixtureNoVCS's callers) must NOT use this: they need
// the real bbolt/x-sync modules that only exist in the shared cache, and
// GOPROXY=off means an isolated empty cache could not fetch them either.
func modCacheEnv(t *testing.T) string {
	t.Helper()
	return "GOMODCACHE=" + filepath.Join(t.TempDir(), "modcache")
}

// buildFixture compiles a module with the given go.mod and main.go into
// t.TempDir() and returns the binary's path.
//
// It shells out to `go build`, which is fine in a TEST: the constraint D23
// records is that the SCANNER must not need a toolchain, not that the suite
// cannot use one. A hand-rolled byte fixture would test this parser against a
// file no compiler ever produced.
//
// The directory is committed to a throwaway git repo before building. `go
// build` only stamps the main module with a real pseudo-version when it is
// built from a VCS checkout with at least one commit (measured: a plain
// t.TempDir() with no VCS at all, and one inside a repo with zero commits,
// both report "(devel)" instead - two different environments, same result).
// Without this, TestParse_IncludesTheMainModule's fixture would land on
// exactly the "(devel)" path it exists to distinguish from a real version,
// making the assertion depend on where the OS temp directory happens to sit
// rather than on this package's behavior. It also stops `go build` from
// walking *up* past the fixture directory in search of a repository - with
// no .git of its own, it would otherwise find whatever ambient one encloses
// the OS temp directory and gather (read-only, but real) VCS status over it.
//
// TestParse_IncludesTheMainModule is the only test that uses this: it is the
// one test that actually inspects the main module's version, so it is the
// one test that needs git. Everything else builds with buildFixtureNoVCS,
// which does not.
func buildFixture(t *testing.T, gomod, mainGo string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH; this test needs a toolchain to build its fixture")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH; this test needs a commit so the main module carries a real version instead of (devel)")
	}
	dir := t.TempDir()
	writeModule(t, dir, gomod, mainGo)
	commitFixture(t, dir)
	// This fixture never has a real dependency (see modCacheEnv), so an
	// isolated GOMODCACHE costs nothing and keeps every VCS-stamped build out
	// of the shared, machine-wide module cache.
	return runGoBuild(t, dir, ".", "-buildvcs=true", modCacheEnv(t))
}

// buildFixtureNoVCS forces -buildvcs=false, which guarantees the main
// module reports "(devel)" and - because it skips VCS detection outright -
// needs no git on PATH and never walks up into an enclosing repository. Used
// by every test that does not inspect the main module's own version.
func buildFixtureNoVCS(t *testing.T, gomod, mainGo string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH; this test needs a toolchain to build its fixture")
	}
	dir := t.TempDir()
	writeModule(t, dir, gomod, mainGo)
	return runGoBuild(t, dir, ".", "-buildvcs=false")
}

// A main module built with no VCS stamp reports "(devel)", which is not a
// version any comparer can place in a range. Cataloging it as a package would
// claim it was evaluated when it was not; it must be a counted skip instead.
func TestParse_SkipsUnstampedMainModule(t *testing.T) {
	bin := buildFixtureNoVCS(t, "module example.test/app\n\ngo 1.26\n",
		"package main\n\nfunc main() {}\n")

	tgt, stats, err := Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range tgt.Packages {
		if p.Name == "example.test/app" {
			t.Fatalf("main module reported with version %q; want it skipped, not cataloged", p.Version)
		}
	}
	if stats.SkippedNoVersion != 1 {
		t.Errorf("SkippedNoVersion = %d, want 1", stats.SkippedNoVersion)
	}
	if stats.Components != 1 || stats.Cataloged != 0 {
		t.Errorf("stats = %+v, want 1 component seen and 0 cataloged", stats)
	}
}

// The main module is a package too. It carries a real pseudo-version derived
// from VCS (v0.0.0-20260801032351-e220a8f9e81b on this repo), not "(devel)",
// so it is comparable and an advisory against it would match. Dropping it
// means a scan of an application never reports the application.
func TestParse_IncludesTheMainModule(t *testing.T) {
	bin := buildFixture(t, "module example.test/app\n\ngo 1.26\n",
		"package main\n\nfunc main() {}\n")

	tgt, stats, err := Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	main := find(t, tgt, "example.test/app")
	if main.Ecosystem != "Go" {
		t.Errorf("ecosystem = %q, want Go", main.Ecosystem)
	}
	if main.Type != "golang" {
		t.Errorf("type = %q, want golang", main.Type)
	}
	// Built outside a VCS checkout, the main module is "(devel)" - which is
	// not a version, so it is a counted skip rather than a package claiming
	// a version nothing can compare.
	if main.Version == "(devel)" {
		t.Error("(devel) was reported as a version instead of being skipped")
	}
	if len(main.Locations) != 1 || main.Locations[0].Path != bin {
		t.Errorf("locations = %+v, want one naming %s", main.Locations, bin)
	}
	if main.Locations[0].LayerDigest != "" {
		t.Errorf("layer digest = %q, want empty outside an image scan",
			main.Locations[0].LayerDigest)
	}
	// D8 is nil for Go: there is no separate source package, unlike Alpine
	// or Debian where the binary and its source can carry different names.
	if main.Source != nil {
		t.Errorf("source = %+v, want nil (D8 does not apply to Go)", main.Source)
	}
	if stats.Components != len(tgt.Packages)+stats.SkippedNoVersion {
		t.Errorf("stats do not add up: %+v with %d packages", stats, len(tgt.Packages))
	}
	// Cataloged is what the report subtracts from Components to decide a
	// scan was complete (see cyclonedx.Stats); it must count every package
	// actually produced, not just track along with Components.
	if stats.Cataloged != len(tgt.Packages) {
		t.Errorf("Cataloged = %d, want %d (one per package produced)", stats.Cataloged, len(tgt.Packages))
	}
}

// Every dependency the linker kept, with the version the linker used - not
// what go.mod requested. The fixture imports the dependency so the linker
// actually keeps it; an unused require is absent from build info, which is
// the whole difference between this cataloger and the go.mod one.
//
// Built with buildFixtureNoVCS rather than buildFixture: nothing here
// inspects the main module's version, so this test does not need git. With
// git off PATH, this is what still proves Ecosystem/Type/PURL/Cataloged are
// wired correctly - TestParse_IncludesTheMainModule alone would have let all
// four of those skip silently along with it.
func TestParse_ReportsLinkedDependencies(t *testing.T) {
	// Uses a module already in this repo's module cache, so no download.
	bin := buildFixtureNoVCS(t,
		"module example.test/app\n\ngo 1.26\n\nrequire go.etcd.io/bbolt v1.5.0\n",
		"package main\n\nimport _ \"go.etcd.io/bbolt\"\n\nfunc main() {}\n")

	tgt, stats, err := Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	dep := find(t, tgt, "go.etcd.io/bbolt")
	if dep.Version != "v1.5.0" {
		t.Errorf("version = %q, want v1.5.0 - the version the linker used", dep.Version)
	}
	if want := "pkg:golang/go.etcd.io/bbolt@v1.5.0"; dep.PURL != want {
		t.Errorf("purl = %q, want %q", dep.PURL, want)
	}
	if dep.Ecosystem != "Go" {
		t.Errorf("ecosystem = %q, want Go", dep.Ecosystem)
	}
	if dep.Type != "golang" {
		t.Errorf("type = %q, want golang", dep.Type)
	}
	if dep.Source != nil {
		t.Errorf("source = %+v, want nil (D8 does not apply to Go)", dep.Source)
	}
	if stats.Cataloged != len(tgt.Packages) {
		t.Errorf("Cataloged = %d, want %d (one per package produced)", stats.Cataloged, len(tgt.Packages))
	}
}

// A replace directive means the module you are running is not the module the
// path names. Reporting the replaced-away path would look up advisories for
// code that is not in this binary - a false positive - while missing the
// advisories for the code that IS there - a false negative, silent.
//
// This fixture only varies the VERSION on an otherwise identical path
// (golang.org/x/sync => golang.org/x/sync v0.21.0), so it only proves the
// version substitution; it passes even under a bug that keeps the
// replaced-away PATH but takes the replacement's version. See
// TestParse_FollowsReplaceDirectives_DifferentModulePath for the path half.
//
// Built with buildFixtureNoVCS: this test never inspects the main module's
// version, so it does not need git either.
func TestParse_FollowsReplaceDirectives(t *testing.T) {
	bin := buildFixtureNoVCS(t,
		"module example.test/app\n\ngo 1.26\n\n"+
			"require golang.org/x/sync v0.20.0\n\n"+
			"replace golang.org/x/sync => golang.org/x/sync v0.21.0\n",
		"package main\n\nimport _ \"golang.org/x/sync/errgroup\"\n\nfunc main() {}\n")

	tgt, _, err := Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	dep := find(t, tgt, "golang.org/x/sync")
	if dep.Version != "v0.21.0" {
		t.Errorf("version = %q, want v0.21.0 - the replacement, not the replaced", dep.Version)
	}
	// And the replaced-away version must not also be present: two entries for
	// one module would double-count it in every summary.
	n := 0
	for _, p := range tgt.Packages {
		if p.Name == "golang.org/x/sync" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("golang.org/x/sync appears %d times, want 1", n)
	}
}

// buildProxyModule writes a minimal Go module proxy entry (info/mod/zip) for
// path@version under root, following the module proxy protocol
// (https://go.dev/ref/mod#module-proxy). This lets a replace directive point
// at a genuinely different module - not just a different version of the
// same one - entirely offline. A `replace old => ./localdir` filesystem
// target was considered instead and rejected: it always reports "(devel)"
// for its version (measured), which cannot distinguish "reports the
// replacement's path" from "reports the replaced-away path with the
// replacement's version" - both would be skipped identically as unversioned.
func buildProxyModule(t *testing.T, root, path, version, source string) {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(path), "@v")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gomod := "module " + path + "\n\ngo 1.26\n"
	info := fmt.Sprintf(`{"Version":%q,"Time":"2024-01-01T00:00:00Z"}`, version)
	if err := os.WriteFile(filepath.Join(dir, version+".info"), []byte(info), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, version+".mod"), []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}

	zf, err := os.Create(filepath.Join(dir, version+".zip"))
	if err != nil {
		t.Fatal(err)
	}
	defer zf.Close()
	zw := zip.NewWriter(zf)
	prefix := path + "@" + version + "/"
	write := func(name, content string) {
		w, err := zw.Create(prefix + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", gomod)
	write("lib.go", source)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

// fileProxyURL turns an absolute filesystem directory into a `file://`
// GOPROXY URL. A bare "file://"+dir loses a slash on Windows, where an
// absolute path has no leading slash of its own (C:\...): the result reads
// as a UNC host and `go build` reports "file URL missing drive letter"
// (reproduced directly while developing this fixture). Routing the path
// through url.URL with a leading slash forced on gets this right on both
// platforms.
func fileProxyURL(dir string) string {
	p := filepath.ToSlash(dir)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// A replace directive can point at an entirely different module, not just a
// different version of the same one - real go.mod files do this (e.g.
// `replace github.com/coreos/etcd => go.etcd.io/etcd v3.3.25+incompatible`).
// This is the path half TestParse_FollowsReplaceDirectives cannot cover: it
// builds a throwaway file:// module proxy so the replacement has a real,
// distinct module path and version, entirely offline.
func TestParse_FollowsReplaceDirectives_DifferentModulePath(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH; this test needs a toolchain to build its fixture")
	}

	proxyRoot := t.TempDir()
	buildProxyModule(t, proxyRoot, "example.test/replaced", "v1.2.3",
		"package original\n\nfunc Hello() string { return \"hello\" }\n")

	dir := t.TempDir()
	writeModule(t, dir,
		"module example.test/app\n\ngo 1.26\n\n"+
			"require example.test/original v1.0.0\n\n"+
			"replace example.test/original => example.test/replaced v1.2.3\n",
		"package main\n\nimport \"example.test/original\"\n\nfunc main() { _ = original.Hello() }\n")

	bin := filepath.Join(dir, "app.bin")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	// -buildvcs=false: this test does not care about the main module's
	// version, and dir has no .git of its own, so leaving VCS detection on
	// would send `go build` walking up in search of one (see buildFixture's
	// comment on why that matters). GOPROXY names the local proxy first and
	// falls back to "off" so a lookup this proxy cannot satisfy is a loud
	// failure rather than a silent network fetch. GOMODCACHE is its own
	// scratch directory so this fake module never lands in the shared cache
	// used by every other build on the machine.
	cmd.Env = append(gitEnv(),
		"GOFLAGS=-mod=mod -buildvcs=false",
		"GOPROXY="+fileProxyURL(proxyRoot)+",off",
		"GOSUMDB=off",
		"GOMODCACHE="+filepath.Join(t.TempDir(), "modcache"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Unlike runGoBuild's shared-cache fixtures, this test's only
		// non-stdlib module comes from the file:// proxy built above into
		// its own private, empty GOMODCACHE. A cache miss here can never be
		// environmental - it can only mean the proxy this test built is
		// itself wrong (bad layout, bad version, a path-escaping mistake, or
		// a file:// URL go rejects, which has already happened once on
		// Windows while developing this fixture). Skipping on that message,
		// the way runGoBuild does for the shared cache, would silently
		// delete this test's entire reason to exist - the one place F1's
		// path-vs-version distinction is checked - the moment its own setup
		// broke. So any failure here is fatal, never a skip.
		t.Fatalf("go build failed (%v):\n%s", err, out)
	}

	tgt, _, err := Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	dep := find(t, tgt, "example.test/replaced")
	if dep.Version != "v1.2.3" {
		t.Errorf("version = %q, want v1.2.3 - the replacement, not the replaced", dep.Version)
	}
	if want := "pkg:golang/example.test/replaced@v1.2.3"; dep.PURL != want {
		t.Errorf("purl = %q, want %q", dep.PURL, want)
	}
	for _, p := range tgt.Packages {
		if p.Name == "example.test/original" {
			t.Errorf("replaced-away path %q reported; want only the replacement", p.Name)
		}
	}
}

// A module's main package need not live at the module root: `go build
// ./cmd/foo` produces a binary whose bi.Path is "example.test/app/cmd/foo" -
// the *package* path - but OSV Go advisories are keyed on the *module*
// path, "example.test/app" (bi.Main.Path). "app" is a prefix of
// "app/cmd/foo" (the nesting hazard CLAUDE.md warns about), so reporting the
// wrong one is not even caught by a loose substring check, only an exact
// one - which is what find() does.
func TestParse_ReportsModulePathNotPackagePath(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH; this test needs a toolchain to build its fixture")
	}
	// Needs a real version, same as TestParse_IncludesTheMainModule: with no
	// commit the main module is "(devel)" and Parse skips it, and find()
	// below fails to locate the module at all, regardless of which path
	// would have been reported - this is specifically what this skip gives
	// up, not just "a real version" in the abstract.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH; without a commit the main module is \"(devel)\" and Parse skips it, so this test cannot check whether the module path or the package path was reported")
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "cmd", "foo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module example.test/app\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmd", "foo", "main.go"),
		[]byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	commitFixture(t, dir)
	// No real dependency here either (see modCacheEnv): isolate GOMODCACHE
	// so this VCS-stamped build does not leave a pseudo-version cache entry
	// in the shared module cache either.
	bin := runGoBuild(t, dir, "./cmd/foo", "-buildvcs=true", modCacheEnv(t))

	tgt, _, err := Parse(bin)
	if err != nil {
		t.Fatal(err)
	}
	main := find(t, tgt, "example.test/app")
	if main.Version == "(devel)" {
		t.Fatal("main module reported as (devel); this test needs a real version to be meaningful")
	}
	for _, p := range tgt.Packages {
		if p.Name == "example.test/app/cmd/foo" {
			t.Errorf("reported the package path %q instead of the module path %q", p.Name, main.Name)
		}
	}
}

// Not a Go binary, a directory, and a missing file are three different
// inputs, and Parse's error must name the specific path for each, because a
// message with no path leaves the user unable to tell which of several scan
// targets failed. It does not promise a distinct message *shape* per input:
// today "a file that is not a Go binary" and "a directory" both come back as
// "unrecognized file format" and are told apart only by the path, which is
// enough to act on (the path is the thing the user gave Parse) but is not a
// three-way discrimination this test checks for.
func TestParse_Rejects(t *testing.T) {
	dir := t.TempDir()
	notGo := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(notGo, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ name, path string }{
		{"a file that is not a Go binary", notGo},
		{"a directory", dir},
		{"a path that does not exist", filepath.Join(dir, "absent")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Parse(tt.path)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded", tt.path)
			}
			if !strings.Contains(err.Error(), tt.path) {
				t.Errorf("error %q does not name the path", err)
			}
		})
	}
}

// isUnversioned's two arms are tested directly rather than only through a
// built binary: debug/buildinfo has never been observed, from any fixture
// this package can build, to report an empty string - every reachable shape
// is either "(devel)" or a real version - so the "" arm would otherwise be
// untested. This also gives the "(devel)" arm a second, much cheaper check
// alongside TestParse_SkipsUnstampedMainModule's integration-level one.
func TestIsUnversioned(t *testing.T) {
	for _, tt := range []struct {
		version string
		want    bool
	}{
		{"", true},
		{"(devel)", true},
		{"v1.2.3", false},
		{"v0.0.0-20260801032351-e220a8f9e81b", false},
	} {
		if got := isUnversioned(tt.version); got != tt.want {
			t.Errorf("isUnversioned(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

// A fixture built while GIT_DIR is set - as git exports for every hook -
// must not touch the repository GIT_DIR names. Without gitEnv() stripping
// GIT_*, `git init`/`config`/`commit` in commitFixture operate on GIT_DIR's
// repository instead of the fixture directory - this reproduces that
// failure mode against a scratch repo standing in for "whatever repository
// a pre-commit or pre-push hook belongs to", rather than trusting the fix by
// inspection alone.
func TestBuildFixture_IgnoresAmbientGitDir(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH; this test needs a toolchain to build its fixture")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH; this test needs a commit so the main module gets a real version instead of (devel)")
	}

	scratchRepo := t.TempDir()
	if err := os.WriteFile(filepath.Join(scratchRepo, "keep.txt"), []byte("do not touch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "scratch@example.test"},
		{"config", "user.name", "scratch"},
		{"add", "-A"},
		{"commit", "-q", "-m", "scratch"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = scratchRepo
		cmd.Env = gitEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	headBefore := gitRevParseHead(t, scratchRepo)
	configBefore := readFileString(t, filepath.Join(scratchRepo, ".git", "config"))

	// Simulates running from inside a git hook, which exports GIT_DIR
	// pointing at the repository the hook belongs to - here, scratchRepo.
	t.Setenv("GIT_DIR", filepath.Join(scratchRepo, ".git"))

	bin := buildFixture(t, "module example.test/app\n\ngo 1.26\n",
		"package main\n\nfunc main() {}\n")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("fixture binary missing: %v", err)
	}

	if got := gitRevParseHead(t, scratchRepo); got != headBefore {
		t.Errorf("scratch repo HEAD changed: %s -> %s; the fixture committed into it", headBefore, got)
	}
	if got := readFileString(t, filepath.Join(scratchRepo, ".git", "config")); got != configBefore {
		t.Errorf("scratch repo config changed:\nbefore:\n%s\nafter:\n%s", configBefore, got)
	}
}

func gitRevParseHead(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	cmd.Env = gitEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git rev-parse HEAD: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
