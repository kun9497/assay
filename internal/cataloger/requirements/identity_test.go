package requirements

import (
	"os"
	"path/filepath"
	"testing"
)

// A pinned package carries the identity every other Python reader gives
// one. The purl and location are held through Run (scancmd's
// TestRun_RequirementsTxtPackageCarriesItsPURLAndLocation); Type is not in
// the JSON report, so it is held here.
func TestParse_PinnedPackageCarriesTypePURLAndLocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(path, []byte("id-lib==1.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, _, _, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("packages = %+v, want 1", target.Packages)
	}
	p := target.Packages[0]
	if p.Type != "pypi" || p.PURL != "pkg:pypi/id-lib@1.2.3" || len(p.Locations) != 1 || p.Locations[0].Path != path {
		t.Errorf("package = %+v, want type pypi, purl pkg:pypi/id-lib@1.2.3, location %s", p, path)
	}
}
