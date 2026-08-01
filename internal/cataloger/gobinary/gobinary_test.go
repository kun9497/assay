package gobinary

import (
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

// buildFixture compiles a module with the given go.mod and main.go into
// t.TempDir() and returns the binary's path.
//
// It shells out to `go build`, which is fine in a TEST: the constraint D23
// records is that the SCANNER must not need a toolchain, not that the suite
// cannot use one. A hand-rolled byte fixture would test this parser against a
// file no compiler ever produced.
//
// GOFLAGS=-mod=mod and the shared module cache keep it offline - every module
// used by these fixtures is already required by this repository.
//
// The directory is committed to a throwaway git repo before building. `go
// build` only stamps the main module with a real pseudo-version when it is
// built from a VCS checkout with at least one commit (measured: a plain
// t.TempDir() with no VCS at all, and one inside a repo with zero commits,
// both report "(devel)" instead - two different environments, same result).
// Without this, TestParse_IncludesTheMainModule's fixture would land on
// exactly the "(devel)" path it exists to distinguish from a real version,
// making the assertion depend on where the OS temp directory happens to sit
// rather than on this package's behavior.
func buildFixture(t *testing.T, gomod, mainGo string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH; this test needs a toolchain to build its fixture")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH; this test needs it to stamp the fixture's VCS version")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  gomod,
		"main.go": mainGo,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
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
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	bin := filepath.Join(dir, "app.bin")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	// GOFLAGS=-mod=mod lets the build resolve from the module cache without
	// a go.sum; GOPROXY=off makes a cache miss an error rather than a silent
	// network fetch, so a fixture that would need the network fails loudly
	// here instead of making the suite depend on it. -buildvcs=true turns a
	// failure to read back the commit just made into a build error rather
	// than a silent "(devel)".
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod -buildvcs=true", "GOPROXY=off", "GOSUMDB=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build failed (%v); fixture needs modules not in the local cache:\n%s", err, out)
	}
	return bin
}

// buildFixtureDevel is buildFixture's counterpart forcing -buildvcs=false, so
// the main module is guaranteed to report "(devel)" regardless of whether the
// OS temp directory happens to sit inside a VCS checkout with commits -
// buildFixture's own comment documents that this is not reliably true or
// false on its own. Without this, the "(devel)" skip in Parse is only
// exercised by luck: buildFixture's fixtures all carry a real pseudo-version,
// so no other test in this file ever hands Parse a "(devel)" main module.
func buildFixtureDevel(t *testing.T, gomod, mainGo string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH; this test needs a toolchain to build its fixture")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  gomod,
		"main.go": mainGo,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(dir, "app.bin")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod -buildvcs=false", "GOPROXY=off", "GOSUMDB=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build failed (%v); fixture needs modules not in the local cache:\n%s", err, out)
	}
	return bin
}

// A main module built with no VCS stamp reports "(devel)", which is not a
// version any comparer can place in a range. Cataloging it as a package would
// claim it was evaluated when it was not; it must be a counted skip instead.
func TestParse_SkipsUnstampedMainModule(t *testing.T) {
	bin := buildFixtureDevel(t, "module example.test/app\n\ngo 1.26\n",
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
func TestParse_ReportsLinkedDependencies(t *testing.T) {
	// Uses a module already in this repo's module cache, so no download.
	bin := buildFixture(t,
		"module example.test/app\n\ngo 1.26\n\nrequire go.etcd.io/bbolt v1.5.0\n",
		"package main\n\nimport _ \"go.etcd.io/bbolt\"\n\nfunc main() {}\n")

	tgt, _, err := Parse(bin)
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
}

// A replace directive means the module you are running is not the module the
// path names. Reporting the replaced-away path would look up advisories for
// code that is not in this binary - a false positive - while missing the
// advisories for the code that IS there - a false negative, silent.
func TestParse_FollowsReplaceDirectives(t *testing.T) {
	bin := buildFixture(t,
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

// Not a Go binary, a directory, and a missing file are three different
// failures and the message must say which, because the user's next action
// differs for each.
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
