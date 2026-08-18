package composerlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "composer.lock")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestParse_MalformedJSONNamesTheFile(t *testing.T) {
	path := write(t, `{"packages": `)

	_, _, err := Parse(path)
	if err == nil {
		t.Fatal("err = nil, want a parse error")
	}
	// The full path, not "composer.lock": the format string already
	// contains that word, so asserting it would pass from a wrapper that
	// dropped both the real path and the cause.
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want it to name %s", err, path)
	}
}

func TestParse_MissingFile(t *testing.T) {
	_, _, err := Parse(filepath.Join(t.TempDir(), "absent.lock"))
	if err == nil {
		t.Fatal("err = nil, want a read error")
	}
}

func TestParse_EmptyArraysAreNotAnError(t *testing.T) {
	path := write(t, `{"packages": [], "packages-dev": []}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 || stats.Components != 0 {
		t.Errorf("pkgs = %+v, stats = %+v; want nothing", pkgs, stats)
	}
}

// The same package pinned to the same version in both packages and
// packages-dev is one component, not two - dedup across the two arrays, the
// same as pipfilelock's default/develop.
func TestParse_DedupAcrossPackagesAndPackagesDev(t *testing.T) {
	path := write(t, `{
  "packages": [{"name": "dedup-fixture/pkg", "version": "1.0.0"}],
  "packages-dev": [{"name": "dedup-fixture/pkg", "version": "1.0.0"}]
}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("packages = %+v, want one", pkgs)
	}
	if stats.Components != 1 || stats.Cataloged != 1 {
		t.Errorf("stats = %+v, want 1 component, 1 cataloged", stats)
	}
}

// Two DIFFERENT versions of the same name are two components - a version
// pinned differently for dev tooling than for the runtime dependency is
// genuinely installed at both, and dedup must key on version too, not name
// alone.
func TestParse_SameNameDifferentVersionsAreTwoComponents(t *testing.T) {
	path := write(t, `{
  "packages": [{"name": "split-fixture/pkg", "version": "1.0.0"}],
  "packages-dev": [{"name": "split-fixture/pkg", "version": "2.0.0"}]
}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("packages = %+v, want two", pkgs)
	}
	if stats.Components != 2 || stats.Cataloged != 2 {
		t.Errorf("stats = %+v, want 2 components, 2 cataloged", stats)
	}
}

// Only a literal "dev-" PREFIX marks a branch alias. A real, orderable
// version that merely contains the substring "dev" elsewhere - a pre-release
// suffix, say - must not be caught by the same check.
func TestParse_DevPrefixIsExactNotASubstringMatch(t *testing.T) {
	path := write(t, `{
  "packages": [
    {"name": "branch-fixture/pkg", "version": "dev-feature/x"},
    {"name": "prerelease-fixture/pkg", "version": "1.0.0-dev.1"}
  ],
  "packages-dev": []
}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "prerelease-fixture/pkg" {
		t.Fatalf("packages = %+v, want prerelease-fixture/pkg alone", pkgs)
	}
	if pkgs[0].Version != "1.0.0-dev.1" {
		t.Errorf("Version = %q, want 1.0.0-dev.1 kept verbatim", pkgs[0].Version)
	}
	if stats.Components != 2 || stats.Cataloged != 1 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want 2 components, 1 cataloged, 1 skipped", stats)
	}
}

func TestParse_EcosystemAndPURL(t *testing.T) {
	path := write(t, `{"packages": [{"name": "eco-fixture/pkg", "version": "3.2.1"}], "packages-dev": []}`)

	pkgs, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("packages = %+v, want one", pkgs)
	}
	p := pkgs[0]
	if p.Type != "composer" {
		t.Errorf("Type = %q, want composer", p.Type)
	}
	if p.Ecosystem != "Packagist" {
		t.Errorf("Ecosystem = %q, want Packagist", p.Ecosystem)
	}
	if p.PURL != "pkg:composer/eco-fixture/pkg@3.2.1" {
		t.Errorf("PURL = %q, want pkg:composer/eco-fixture/pkg@3.2.1", p.PURL)
	}
}
