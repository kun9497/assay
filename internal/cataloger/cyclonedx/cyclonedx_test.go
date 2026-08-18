package cyclonedx

import (
	"os"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
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
	// Go, npm, PyPI are supported in slice 1. apk is cataloged too, but this
	// document carries no operating-system component, so it lands unkeyed
	// (empty Ecosystem) rather than skipped — D6/D7 need the release, not the
	// existence of an ecosystem mapping, to key it. The last component has no
	// purl at all.
	if stats.Cataloged != 4 {
		t.Errorf("Cataloged = %d, want 4", stats.Cataloged)
	}
	if stats.SkippedUnsupportedEcosystem != 0 {
		t.Errorf("SkippedUnsupportedEcosystem = %d, want 0", stats.SkippedUnsupportedEcosystem)
	}
	if stats.SkippedNoPURL != 1 {
		t.Errorf("SkippedNoPURL = %d, want 1", stats.SkippedNoPURL)
	}

	if len(target.Packages) != 4 {
		t.Fatalf("Packages = %d, want 4", len(target.Packages))
	}
	byName := map[string]int{}
	for i, p := range target.Packages {
		byName[p.Name] = i
	}
	// A plain map lookup on a missing key silently returns the zero value (0),
	// which would read Packages[0] under a wrong name and still pass every
	// assertion below — exactly the bug the apk namespace fix corrected for
	// apk, undetectable here without checking `ok`. This is what makes the
	// test actually fail if namespace prefixing regresses for Go/npm/PyPI.
	mustPkg := func(name string) pkgmeta.Package {
		i, ok := byName[name]
		if !ok {
			t.Fatalf("package %q not cataloged; have %+v", name, target.Packages)
		}
		return target.Packages[i]
	}
	gp := mustPkg("github.com/foo/bar")
	if gp.Ecosystem != "Go" {
		t.Errorf("Go package ecosystem = %q, want Go", gp.Ecosystem)
	}
	if gp.Version != "v1.2.3" {
		t.Errorf("Go package version = %q, want v1.2.3 (verbatim, v intact)", gp.Version)
	}
	if eco := mustPkg("django").Ecosystem; eco != "PyPI" {
		t.Errorf("django ecosystem = %q, want PyPI", eco)
	}
	if eco := mustPkg("apache2").Ecosystem; eco != "" {
		t.Errorf("apache2 ecosystem = %q, want empty: no distro component to key it", eco)
	}
}

func TestParse_DistroFromSyftProperties(t *testing.T) {
	// syft emits the distro as a component of type "operating-system" inside
	// components, not on metadata.component — confirmed against the real
	// mirror.gcr.io/library/alpine:3.19 SBOM, where it is components[16] of 17.
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[
	    {"type":"library","name":"lodash","version":"1.0","purl":"pkg:npm/lodash@1.0"},
	    {"type":"operating-system","name":"alpine","version":"3.19.9",
	     "properties":[
	       {"name":"syft:distro:id","value":"alpine"},
	       {"name":"syft:distro:versionID","value":"3.19"},
	       {"name":"syft:distro:prettyName","value":"Alpine Linux v3.19"}
	     ]}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro == nil {
		t.Fatal("Distro = nil, want it read from the operating-system component's syft properties")
	}
	if target.Distro.ID != "alpine" || target.Distro.VersionID != "3.19" ||
		target.Distro.PrettyName != "Alpine Linux v3.19" {
		t.Errorf("Distro = %+v, want alpine/3.19/Alpine Linux v3.19", *target.Distro)
	}
}

func TestParse_NoDistroPropertiesLeavesNil(t *testing.T) {
	// syft:distro:* is a syft extension, not part of CycloneDX, and there is no
	// operating-system component at all here. An SBOM from another tool may
	// omit it, and guessing would be worse than admitting it.
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

// TestParse_MavenNameJoinsGroupAndArtifactWithColon: OSV's Maven advisories are
// keyed "group:artifact" (measured: 12,457/12,457 live records), but the purl
// spec always separates namespace and name with "/". Joining with "/" here —
// the way every other non-apk ecosystem does — would build a name
// "org.apache.logging.log4j/log4j-core" that no Maven advisory is filed
// under, and the package would silently report clean.
func TestParse_MavenNameJoinsGroupAndArtifactWithColon(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"log4j-core","version":"2.14.1",
	   "purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	got := target.Packages[0]
	if got.Name != "org.apache.logging.log4j:log4j-core" {
		t.Errorf("Name = %q, want %q (group:artifact, colon-joined)",
			got.Name, "org.apache.logging.log4j:log4j-core")
	}
	if got.Ecosystem != "Maven" {
		t.Errorf("Ecosystem = %q, want Maven", got.Ecosystem)
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

// An operating-system component with neither a syft:distro:id property nor a
// component name has nothing to build even a partial Distro from.
func TestParse_OperatingSystemComponentWithNoIDIsNil(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[{"type":"operating-system",
	    "properties":[{"name":"syft:distro:versionID","value":"3.19"}]}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro != nil {
		t.Errorf("Distro = %+v, want nil: no id property and no component name to fall back to",
			*target.Distro)
	}
}

// An ID with no version builds a Distro carrying only ID — Ecosystem() then
// errors on the missing release (D6) rather than the cataloger guessing one.
// The Distro itself is not nil: PrettyName and ID are still worth reporting
// even when the release cannot be resolved.
func TestParse_DistroWithIDButNoVersionIsNotNil(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[{"type":"operating-system","name":"alpine",
	    "properties":[{"name":"syft:distro:id","value":"alpine"}]}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	if target.Distro == nil {
		t.Fatal("Distro = nil, want a Distro carrying the ID even without a version")
	}
	if target.Distro.VersionID != "" {
		t.Errorf("VersionID = %q, want empty: this document never supplied one", target.Distro.VersionID)
	}
	if _, err := target.Distro.Ecosystem(); err == nil {
		t.Error("Ecosystem() = nil error, want ErrNoEcosystem: no version to key a release on")
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

func TestParse_AlpineDistroAndSource(t *testing.T) {
	f, err := os.Open("testdata/alpine.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	target, stats, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if target.Distro == nil {
		t.Fatal("Distro is nil; the operating-system component carries syft:distro:*")
	}
	if target.Distro.ID != "alpine" || target.Distro.VersionID != "3.19.9" {
		t.Errorf("Distro = %+v, want alpine/3.19.9", *target.Distro)
	}

	// The operating-system component must land in neither Components nor any
	// skip bucket. Checking only that "alpine" is absent from the packages is
	// not enough: the component has no purl either way, so it would land in
	// SkippedNoPURL and inflate Components to 5 if the exclusion guard were
	// ever removed, and byName["alpine"] would still be absent either way.
	if stats.Components != 4 {
		t.Errorf("Components = %d, want 4 (the operating-system component must not be counted)",
			stats.Components)
	}
	if stats.SkippedNoPURL != 1 {
		t.Errorf("SkippedNoPURL = %d, want 1 (only the no-purl busybox application component)",
			stats.SkippedNoPURL)
	}
	if stats.Cataloged != 3 {
		t.Errorf("Cataloged = %d, want 3", stats.Cataloged)
	}

	byName := map[string]pkgmeta.Package{}
	for _, p := range target.Packages {
		byName[p.Name] = p
	}

	// D8: the advisory is written against the source package. Without Source,
	// an openssl advisory is unreachable from libssl3 — a silent false negative.
	libssl, ok := byName["libssl3"]
	if !ok {
		t.Fatal("libssl3 not cataloged")
	}
	if libssl.Source == nil {
		t.Fatal("libssl3 has no Source; syft reports syft:metadata:originPackage")
	}
	if libssl.Source.Name != "openssl" {
		t.Errorf("libssl3 Source.Name = %q, want %q", libssl.Source.Name, "openssl")
	}
	if libssl.Ecosystem != "Alpine:v3.19" {
		t.Errorf("libssl3 Ecosystem = %q, want Alpine:v3.19 (D6 needs the release)",
			libssl.Ecosystem)
	}
	if len(libssl.Locations) == 0 || libssl.Locations[0].LayerDigest == "" {
		t.Error("libssl3 carries no layer provenance")
	}
	if len(libssl.Locations) == 0 || libssl.Locations[0].Path != "/lib/apk/db/installed" {
		t.Errorf("libssl3 Locations = %+v, want Path /lib/apk/db/installed from syft:location:0:path",
			libssl.Locations)
	}

	// The operating-system component describes the target; it is not a package
	// to scan, and counting it would inflate the component total.
	if _, ok := byName["alpine"]; ok {
		t.Error("the operating-system component was cataloged as a package")
	}
}

// Alpine edge has no OSV ecosystem (Distro.Ecosystem() errors on it). The
// naive key "Alpine:v" + VersionID would still build "Alpine:vedge", which
// looks valid and matches nothing — every package on an edge image would
// silently report clean. The apk package must land unkeyed instead.
func TestParse_EdgeDistroLeavesPackagesUnkeyed(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"libssl3","version":"3.1.4-r5",
	   "purl":"pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64"},
	  {"type":"operating-system","name":"alpine","version":"edge",
	   "properties":[
	     {"name":"syft:distro:id","value":"alpine"},
	     {"name":"syft:distro:versionID","value":"edge"}
	   ]}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if target.Distro == nil || target.Distro.VersionID != "edge" {
		t.Fatalf("Distro = %+v, want a Distro carrying VersionID \"edge\"", target.Distro)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if eco := target.Packages[0].Ecosystem; eco != "" {
		t.Errorf("Ecosystem = %q, want empty: edge has no OSV ecosystem to key on "+
			"(a naive \"Alpine:v\"+VersionID would wrongly produce %q)", eco, "Alpine:vedge")
	}
}

// syft omits syft:metadata:originPackage on nothing in the real fixture, but
// the field is documented as present only when it differs from — or the
// property set is simply absent for — the package. Package.Source is now a
// matcher lookup key (D8), so a component with no origin property must leave
// Source nil, never a SourcePackage with an empty Name that would drive a
// live lookup on "".
func TestParse_APKWithNoOriginPackageHasNilSource(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"libssl3","version":"3.1.4-r5",
	   "purl":"pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64",
	   "properties":[{"name":"syft:package:type","value":"apk"}]}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if s := target.Packages[0].Source; s != nil {
		t.Errorf("Source = %+v, want nil when syft:metadata:originPackage is absent", *s)
	}
}

// distroFrom's fallback to the component's own name/version fields is the
// load-bearing half of retiring the metadata.component path: a tool that
// emits an operating-system component without syft:* properties — the
// CycloneDX spec fields are all it has — must still resolve to a usable
// Distro.
func TestParse_DistroFallsBackToComponentFieldsWithoutSyftProperties(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"operating-system","name":"alpine","version":"3.19.9"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if target.Distro == nil {
		t.Fatal("Distro = nil, want one built from the component's own name/version fields")
	}
	eco, err := target.Distro.Ecosystem()
	if err != nil {
		t.Fatalf("Ecosystem() error: %v", err)
	}
	if eco != "Alpine:v3.19" {
		t.Errorf("Ecosystem() = %q, want Alpine:v3.19", eco)
	}
}

// An SBOM with apk packages but no distro cannot be keyed. The packages must
// still be cataloged so they are counted and reported as skipped — dropping
// them would shrink the denominator and make the scan look complete.
func TestParse_APKWithoutDistroIsKeptUnkeyed(t *testing.T) {
	const doc = `{
	  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
	  "components": [{
	    "type": "library", "name": "libssl3", "version": "3.1.4-r5",
	    "purl": "pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64"
	  }]
	}`
	target, cat, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cat.Components != 1 {
		t.Errorf("Components = %d, want 1", cat.Components)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1: an unkeyable package is still a package",
			len(target.Packages))
	}
	if eco := target.Packages[0].Ecosystem; eco != "" {
		t.Errorf("Ecosystem = %q, want empty: there is no distro to derive a release from", eco)
	}
}
