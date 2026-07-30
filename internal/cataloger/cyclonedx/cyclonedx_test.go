package cyclonedx

import (
	"os"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/small.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	target, stats, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if stats.Components != 5 {
		t.Errorf("Components = %d, want 5", stats.Components)
	}
	// Go, npm, PyPI are supported in slice 1; apk is not (its ecosystem key
	// needs a release), and the last component has no purl at all.
	if stats.Cataloged != 3 {
		t.Errorf("Cataloged = %d, want 3", stats.Cataloged)
	}
	if stats.SkippedUnsupportedEcosystem != 1 {
		t.Errorf("SkippedUnsupportedEcosystem = %d, want 1", stats.SkippedUnsupportedEcosystem)
	}
	if stats.SkippedNoPURL != 1 {
		t.Errorf("SkippedNoPURL = %d, want 1", stats.SkippedNoPURL)
	}

	if len(target.Packages) != 3 {
		t.Fatalf("Packages = %d, want 3", len(target.Packages))
	}
	byName := map[string]int{}
	for i, p := range target.Packages {
		byName[p.Name] = i
	}
	gp := target.Packages[byName["github.com/foo/bar"]]
	if gp.Ecosystem != "Go" {
		t.Errorf("Go package ecosystem = %q, want Go", gp.Ecosystem)
	}
	if gp.Version != "v1.2.3" {
		t.Errorf("Go package version = %q, want v1.2.3 (verbatim, v intact)", gp.Version)
	}
	if target.Packages[byName["django"]].Ecosystem != "PyPI" {
		t.Errorf("django ecosystem = %q, want PyPI", target.Packages[byName["django"]].Ecosystem)
	}
}

func TestParse_DistroFromSyftProperties(t *testing.T) {
	f, err := os.Open("testdata/small.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	target, _, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro == nil {
		t.Fatal("Distro = nil, want it read from syft properties")
	}
	if target.Distro.ID != "alpine" || target.Distro.VersionID != "3.19" {
		t.Errorf("Distro = %+v, want alpine 3.19", *target.Distro)
	}
}

func TestParse_NoDistroPropertiesLeavesNil(t *testing.T) {
	// syft:distro:* is a syft extension, not part of CycloneDX. An SBOM from
	// another tool may omit it, and guessing would be worse than admitting it.
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[{"type":"library","name":"lodash","version":"1.0",
	                 "purl":"pkg:npm/lodash@1.0"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro != nil {
		t.Errorf("Distro = %+v, want nil when the properties are absent", *target.Distro)
	}
}

func TestParse_VersionFallsBackToComponentField(t *testing.T) {
	// A purl without a version is legal; the component's version field is the
	// fallback rather than treating the package as unversioned.
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[{"type":"library","name":"lodash","version":"4.17.20",
	                 "purl":"pkg:npm/lodash"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 || target.Packages[0].Version != "4.17.20" {
		t.Errorf("Packages = %+v, want version 4.17.20 from the component field", target.Packages)
	}
}

func TestParse_NotCycloneDX(t *testing.T) {
	if _, _, err := Parse(strings.NewReader(`{"spdxVersion":"SPDX-2.3"}`)); err == nil {
		t.Error("Parse(SPDX) = nil error, want error")
	}
	if _, _, err := Parse(strings.NewReader("{not json")); err == nil {
		t.Error("Parse(malformed) = nil error, want error")
	}
}
