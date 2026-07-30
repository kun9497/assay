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

func TestParse_NestedComponentsAreSeen(t *testing.T) {
	// A component may carry its own components array. Reading only the top
	// level would leave the nested one absent from every counter — worse than
	// a counted skip, because the report would give no hint it existed.
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"outer","version":"1.0.0","purl":"pkg:npm/outer@1.0.0",
	   "components":[
	     {"type":"library","name":"inner","version":"2.0.0","purl":"pkg:npm/inner@2.0.0"},
	     {"type":"library","name":"deep","version":"3.0.0","purl":"pkg:npm/deep@3.0.0",
	      "components":[{"type":"library","name":"deeper","version":"4.0.0",
	                     "purl":"pkg:npm/deeper@4.0.0"}]}
	   ]}]}`
	target, stats, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Components != 4 || stats.Cataloged != 4 {
		t.Errorf("Stats = %+v, want 4 components and 4 cataloged", stats)
	}
	got := map[string]bool{}
	for _, p := range target.Packages {
		got[p.Name] = true
	}
	for _, want := range []string{"outer", "inner", "deep", "deeper"} {
		if !got[want] {
			t.Errorf("package %q missing; nested components were not walked", want)
		}
	}
}

func TestParse_UnversionedPackageIsSkippedNotCataloged(t *testing.T) {
	// With no version there is nothing to place inside a range. Counting it as
	// cataloged would claim it was evaluated.
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"lodash","purl":"pkg:npm/lodash"}]}`
	target, stats, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Cataloged != 0 || stats.SkippedNoVersion != 1 {
		t.Errorf("Stats = %+v, want 0 cataloged and 1 skipped for no version", stats)
	}
	if len(target.Packages) != 0 {
		t.Errorf("Packages = %+v, want none", target.Packages)
	}
}

func TestParse_EveryComponentLandsInExactlyOneCounter(t *testing.T) {
	// The summary line is only trustworthy if the buckets add up.
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"ok","version":"1.0.0","purl":"pkg:npm/ok@1.0.0"},
	  {"type":"library","name":"nopurl","version":"1.0.0"},
	  {"type":"library","name":"badpurl","version":"1.0.0","purl":"not-a-purl"},
	  {"type":"library","name":"apk","version":"1.0-r0","purl":"pkg:apk/alpine/apk@1.0-r0"},
	  {"type":"library","name":"noversion","purl":"pkg:npm/noversion"}]}`
	_, stats, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	sum := stats.Cataloged + stats.SkippedNoPURL + stats.SkippedNoVersion +
		stats.SkippedUnsupportedEcosystem
	if sum != stats.Components {
		t.Errorf("counters sum to %d but Components = %d (%+v)", sum, stats.Components, stats)
	}
	if stats.Components != 5 {
		t.Errorf("Components = %d, want 5", stats.Components)
	}
}

func TestParse_HalfPopulatedDistroIsNil(t *testing.T) {
	// An ID with no version would build the ecosystem key "Alpine:", which
	// matches nothing and reports no error while doing it.
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5",
	  "metadata":{"component":{"type":"container","name":"x",
	    "properties":[{"name":"syft:distro:id","value":"alpine"}]}},
	  "components":[]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro != nil {
		t.Errorf("Distro = %+v, want nil when only half the properties are present", *target.Distro)
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
