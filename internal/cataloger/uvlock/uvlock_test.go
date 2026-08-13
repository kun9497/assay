package uvlock

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "uv.lock")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// A block with no version is counted and skipped, never dropped. This is the
// same invariant cargolock holds and it needs its own test here rather than
// riding on that one: the counting lives in each cataloger, not in the shared
// scanner, so the two can diverge without any test noticing.
func TestParse_BlockWithoutAVersionIsCountedAsSkipped(t *testing.T) {
	path := write(t, `version = 1

[[package]]
name = "resolution-failed"

[[package]]
name = "complete"
version = "1.0.0"
`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "complete" {
		t.Fatalf("packages = %+v, want complete alone", pkgs)
	}
	if stats.Components != 2 {
		t.Errorf("Components = %d, want 2 — the versionless block still exists", stats.Components)
	}
	if stats.SkippedNoVersion != 1 {
		t.Errorf("SkippedNoVersion = %d, want 1", stats.SkippedNoVersion)
	}
	if stats.Components != stats.Cataloged+stats.SkippedNoVersion {
		t.Errorf("invariant broken: %d != %d + %d",
			stats.Components, stats.Cataloged, stats.SkippedNoVersion)
	}
}

func TestParse_EcosystemAndPURL(t *testing.T) {
	path := write(t, "[[package]]\nname = \"anyio\"\nversion = \"4.13.0\"\n")

	pkgs, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	p := pkgs[0]
	// uv.lock is PyPI. A different spelling here reaches no advisory bucket
	// and the package reports clean.
	if p.Ecosystem != "PyPI" {
		t.Errorf("Ecosystem = %q, want PyPI", p.Ecosystem)
	}
	if p.Type != "pypi" {
		t.Errorf("Type = %q, want pypi", p.Type)
	}
	if p.PURL != "pkg:pypi/anyio@4.13.0" {
		t.Errorf("PURL = %q, want pkg:pypi/anyio@4.13.0", p.PURL)
	}
	if len(p.Locations) != 1 || p.Locations[0].Path != path {
		t.Errorf("Locations = %+v, want the file it was read from", p.Locations)
	}
}

// The name is emitted as written, not normalized here. PEP 503 normalization
// is applied once at match time (pkgmeta.NormalizeName), and a second copy of
// that rule in a cataloger is how the two drift out of agreement.
func TestParse_NameIsNotNormalizedHere(t *testing.T) {
	path := write(t, "[[package]]\nname = \"Some_Package.Name\"\nversion = \"1.0\"\n")

	pkgs, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pkgs[0].Name != "Some_Package.Name" {
		t.Errorf("Name = %q, want it verbatim", pkgs[0].Name)
	}
}

func TestParse_MissingFile(t *testing.T) {
	_, _, err := Parse(filepath.Join(t.TempDir(), "absent.lock"))
	if err == nil {
		t.Fatal("err = nil, want a read error")
	}
}
