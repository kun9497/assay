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

// TestParse_BitnamiPurlType is D99's own version of the Go/npm/PyPI purl
// routing this file's own TestParse already pins: a pkg:bitnami purl must
// route through EcosystemForPURLType to "Bitnami" the same generic way, not
// through the apk/rpm/deb/alpm distro core -- proven through Parse itself,
// so deleting the "bitnami" map entry fails here, not only in
// purl_test.go's own direct table.
func TestParse_BitnamiPurlType(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5",
	  "components":[{"type":"library","name":"postgresql","version":"18.6.0-3",
	                 "purl":"pkg:bitnami/postgresql@18.6.0-3?arch=amd64&distro=photon-5"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "Bitnami" {
		t.Errorf("Ecosystem = %q, want Bitnami", got)
	}
	if got := target.Packages[0].Version; got != "18.6.0-3" {
		t.Errorf("Version = %q, want 18.6.0-3", got)
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

// TestParse_DocumentDistroFailureIsNotOverriddenByAResolvablePURLQualifier
// pins ecosystemForQualifiedDistro's own "document cannot disagree with
// itself" rule (distropurl.go's doc comment): the document-level distro
// wins whenever the document carried a distro entity AT ALL, even one whose
// own Ecosystem() resolution failed -- it must NOT fall through to a
// per-purl "distro" qualifier just because that qualifier happens to
// resolve cleanly. TestParse_EdgeDistroLeavesPackagesUnkeyed above proves
// the shape where the purl carries no "distro" qualifier at all; every
// fixture in this file with a document distro either resolves successfully
// or (that test) has nothing on the purl to fall through to, so neither
// tells apart "the document's own failure wins" from "there was simply
// nothing else to try". This purl DOES carry a qualifier that resolves on
// its own (alpine-3.19), and the document's edge identity must still win,
// leaving the package unkeyed rather than judged against a different
// release than the one the document itself names.
func TestParse_DocumentDistroFailureIsNotOverriddenByAResolvablePURLQualifier(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"libssl3","version":"3.1.4-r5",
	   "purl":"pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64&distro=alpine-3.19"},
	  {"type":"operating-system","name":"alpine","version":"edge",
	   "properties":[
	     {"name":"syft:distro:id","value":"alpine"},
	     {"name":"syft:distro:versionID","value":"edge"}
	   ]}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if eco := target.Packages[0].Ecosystem; eco != "" {
		t.Errorf("Ecosystem = %q, want empty: the document's own edge identity failed to resolve "+
			"and must win over the purl's own resolvable distro=alpine-3.19 qualifier -- a document "+
			"must not disagree with itself", eco)
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

// D83: CycloneDX ingestion maps rpm and deb purls, mirroring the apk branch —
// bare Name, ecosystem key from the resolved distro, never the purl namespace
// (D6/D7/D8; the namespace itself drifts "rhel"->"redhat" between syft
// generations, so it must never be load-bearing).

func TestParse_RPMKeyedViaOSComponent(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"audit-libs","version":"3.0.7-104.el9",
	   "purl":"pkg:rpm/rhel/audit-libs@3.0.7-104.el9?arch=x86_64&distro=rhel-9.8"},
	  {"type":"operating-system","name":"rhel","version":"9.8",
	   "properties":[
	     {"name":"syft:distro:id","value":"rhel"},
	     {"name":"syft:distro:versionID","value":"9.8"}
	   ]}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "Red Hat:9" {
		t.Errorf("Ecosystem = %q, want %q (keyed from the operating-system component)",
			got, "Red Hat:9")
	}
}

// No operating-system component at all: the ecosystem key must come from the
// purl's own "distro" qualifier instead of being left empty.
func TestParse_RPMKeyedViaQualifierFallback_NoOSComponent(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"audit-libs","version":"3.0.7-104.el9",
	   "purl":"pkg:rpm/rhel/audit-libs@3.0.7-104.el9?arch=x86_64&distro=rhel-9.8"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "Red Hat:9" {
		t.Errorf("Ecosystem = %q, want %q (keyed from the purl's own distro qualifier)",
			got, "Red Hat:9")
	}
}

// TestParse_HummingbirdKeyedViaQualifierFallback_NoOSComponent is D98's free
// ride on D83/D84's SBOM plumbing: distroFromQualifier's generic
// "id-version" split reads "hummingbird-20251124" into ID "hummingbird" and
// VersionID "20251124" without any Hummingbird-specific code here, and
// pkgmeta.Distro.Ecosystem's "hummingbird" case ignores VersionID entirely
// (D98's own dated-build-snapshot reasoning), so the dated snapshot in the
// qualifier never fragments the key the way it would for a distro that kept
// it. The purl is real, trimmed from cve-2026-50811.json.
func TestParse_HummingbirdKeyedViaQualifierFallback_NoOSComponent(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"freetype","version":"2.14.3-1.2.hum1",
	   "purl":"pkg:rpm/redhat/freetype@2.14.3-1.2.hum1?arch=x86_64&distro=hummingbird-20251124"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "Hummingbird" {
		t.Errorf("Ecosystem = %q, want %q (keyed from the purl's own distro qualifier)",
			got, "Hummingbird")
	}
}

// TestParse_QualifierFallbackSplitsOnTheLastHyphen pins WHICH hyphen the
// fallback splits on. Every other fallback fixture in this file carries
// exactly one hyphen (rhel-9.8, debian-12), where first and last coincide —
// so without this row, flipping LastIndexByte to IndexByte stayed green while
// live it would shred "opensuse-leap-15.6" into ID "opensuse" and VersionID
// "leap-15.6", a key nothing was stored under: a silent clean verdict.
func TestParse_QualifierFallbackSplitsOnTheLastHyphen(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"bash","version":"4.4-150400.27.6.1",
	   "purl":"pkg:rpm/opensuse/bash@4.4-150400.27.6.1?arch=x86_64&distro=opensuse-leap-15.6"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "openSUSE Leap:15.6" {
		t.Errorf("Ecosystem = %q, want %q — the qualifier's ID part itself contains "+
			"a hyphen, and only a last-hyphen split preserves it",
			got, "openSUSE Leap:15.6")
	}
}

// When both an operating-system component and a package's own distro
// qualifier exist and disagree, the OS component wins — a per-package
// fallback would let one document disagree with itself.
func TestParse_OSComponentWinsOverDisagreeingQualifier(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"audit-libs","version":"3.0.7-104.el9",
	   "purl":"pkg:rpm/ol/audit-libs@3.0.7-104.el9?arch=x86_64&distro=ol-9.8"},
	  {"type":"operating-system","name":"rhel","version":"9.8",
	   "properties":[
	     {"name":"syft:distro:id","value":"rhel"},
	     {"name":"syft:distro:versionID","value":"9.8"}
	   ]}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	// The purl's own qualifier says "ol-9.8" (Oracle Linux, which would key
	// "Oracle Linux:9"); the document's operating-system component says rhel.
	if got := target.Packages[0].Ecosystem; got != "Red Hat:9" {
		t.Errorf("Ecosystem = %q, want %q: the operating-system component must win "+
			"over a disagreeing purl qualifier", got, "Red Hat:9")
	}
}

// Neither an operating-system component nor a usable distro qualifier:
// unkeyed, exactly like the apk branch's no-distro path — counted and kept,
// never dropped, so the matcher can report it as skipped rather than the
// package vanishing from every counter.
func TestParse_RPMNeitherOSNorQualifier_UnkeyedAndCounted(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"audit-libs","version":"3.0.7-104.el9",
	   "purl":"pkg:rpm/rhel/audit-libs@3.0.7-104.el9?arch=x86_64"}]}`
	target, stats, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Cataloged != 1 {
		t.Errorf("Cataloged = %d, want 1: an unkeyable rpm package is still cataloged", stats.Cataloged)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "" {
		t.Errorf("Ecosystem = %q, want empty: no operating-system component and no distro qualifier", got)
	}
}

// The purl's @version is version-release WITHOUT the epoch (evr()'s shape,
// rpmdb/header.go); Qualifiers["epoch"] is prepended only when present and
// non-"0" — "0:" is never emitted, matching the installed side's own
// omission.
func TestParse_RPMEpochPrefixedIffNonZero(t *testing.T) {
	for _, tc := range []struct {
		name, purl, want string
	}{
		{"noepoch", "pkg:rpm/rhel/noepoch@1.0-1.el9?arch=x86_64", "1.0-1.el9"},
		{"epoch1", "pkg:rpm/rhel/epoch1@1.0-1.el9?arch=x86_64&epoch=1", "1:1.0-1.el9"},
		{"epoch0", "pkg:rpm/rhel/epoch0@1.0-1.el9?arch=x86_64&epoch=0", "1.0-1.el9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
			  {"type":"library","name":"` + tc.name + `","version":"1.0-1.el9","purl":"` + tc.purl + `"}]}`
			target, _, err := Parse(strings.NewReader(bom))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(target.Packages) != 1 {
				t.Fatalf("Packages = %d, want 1", len(target.Packages))
			}
			if got := target.Packages[0].Version; got != tc.want {
				t.Errorf("Version = %q, want %q", got, tc.want)
			}
		})
	}
}

// gpg-pubkey is a keyring entry, not an installed package (mirrors rpmdb's
// isPubkey). It must be filtered out entirely rather than cataloged as a
// package literally named "gpg-pubkey", while still being counted somewhere
// so the component total is not silently short.
func TestParse_GPGPubkeyFiltered(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"audit-libs","version":"3.0.7-104.el9",
	   "purl":"pkg:rpm/rhel/audit-libs@3.0.7-104.el9?arch=x86_64&distro=rhel-9.8"},
	  {"type":"library","name":"gpg-pubkey","version":"5a6340b3-6229229e",
	   "purl":"pkg:rpm/rhel/gpg-pubkey@5a6340b3-6229229e?distro=rhel-9.8"},
	  {"type":"operating-system","name":"rhel","version":"9.8",
	   "properties":[
	     {"name":"syft:distro:id","value":"rhel"},
	     {"name":"syft:distro:versionID","value":"9.8"}
	   ]}]}`
	target, stats, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Components != 2 {
		t.Errorf("Components = %d, want 2 (gpg-pubkey counted, not silently absent)", stats.Components)
	}
	if stats.Cataloged != 1 {
		t.Errorf("Cataloged = %d, want 1", stats.Cataloged)
	}
	if stats.SkippedUnsupportedEcosystem != 1 {
		t.Errorf("SkippedUnsupportedEcosystem = %d, want 1 (gpg-pubkey routed there)", stats.SkippedUnsupportedEcosystem)
	}
	for _, p := range target.Packages {
		if p.Name == "gpg-pubkey" {
			t.Error("a gpg-pubkey keyring entry was cataloged as an installed package")
		}
	}
}

// Ubuntu's OSV keys carry an ":LTS" suffix read from PRETTY_NAME (D53); the
// full key is asserted, not a Contains check, because "Ubuntu:22.04" is a
// substring of "Ubuntu:22.04:LTS" and would pass on the wrong column.
func TestParse_DebUbuntuKeyedViaOSComponent_LTSSuffix(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"bash","version":"5.1-6ubuntu1.1",
	   "purl":"pkg:deb/ubuntu/bash@5.1-6ubuntu1.1?arch=amd64&distro=ubuntu-22.04"},
	  {"type":"operating-system","name":"ubuntu","version":"22.04",
	   "properties":[
	     {"name":"syft:distro:id","value":"ubuntu"},
	     {"name":"syft:distro:versionID","value":"22.04"},
	     {"name":"syft:distro:prettyName","value":"Ubuntu 22.04.5 LTS"}
	   ]}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	const want = "Ubuntu:22.04:LTS"
	if got := target.Packages[0].Ecosystem; got != want {
		t.Errorf("Ecosystem = %q, want %q (exact match — %q is a substring of it)",
			got, want, "Ubuntu:22.04")
	}
}

// The qualifier-fallback path for deb, mirroring the rpm one above but
// through the "deb" case of the same switch.
func TestParse_DebViaQualifierFallback_Debian12(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"bash","version":"5.2.15-2+b13",
	   "purl":"pkg:deb/debian/bash@5.2.15-2+b13?arch=amd64&distro=debian-12"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "Debian:12" {
		t.Errorf("Ecosystem = %q, want %q (keyed from the purl's own distro qualifier)",
			got, "Debian:12")
	}
}

// Modern syft's purl-less "file" components must not land in any counter,
// including SkippedNoPURL — they are files, not packages, and counting them
// there is what used to drive --fail-on-incomplete=target to exit 2 on an
// otherwise-complete scan.
func TestParse_TypeFileNotCounted(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"lodash","version":"1.0","purl":"pkg:npm/lodash@1.0"},
	  {"type":"file","name":"/usr/bin/something"},
	  {"type":"file","name":"/usr/lib/somelib.so"}]}`
	_, stats, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Components != 1 {
		t.Errorf("Components = %d, want 1 (the two file components must not be counted at all)", stats.Components)
	}
	if stats.SkippedNoPURL != 0 {
		t.Errorf("SkippedNoPURL = %d, want 0: file components have no purl but must not land here either",
			stats.SkippedNoPURL)
	}
	if stats.Cataloged != 1 {
		t.Errorf("Cataloged = %d, want 1", stats.Cataloged)
	}
}

// D80's modularityLabel reading, mirrored from rpmdb/header.go: only the
// first two colon-separated fields become ModuleStream, and fewer than four
// fields leaves it "" rather than guessed at.
func TestParse_ModularityLabelToModuleStream(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"nodejs","version":"1:18.20.8-1.module+el8.10.0+23091+f8fc3a53",
	   "purl":"pkg:rpm/rhel/nodejs@18.20.8-1.module%2Bel8.10.0%2B23091%2Bf8fc3a53?arch=x86_64&epoch=1&distro=rhel-8.10",
	   "properties":[{"name":"syft:metadata:modularityLabel","value":"nodejs:18:8100020250506132245:489197e6"}]},
	  {"type":"library","name":"shortlabel","version":"1.0-1.el8",
	   "purl":"pkg:rpm/rhel/shortlabel@1.0-1.el8?arch=x86_64&distro=rhel-8.10",
	   "properties":[{"name":"syft:metadata:modularityLabel","value":"nodejs:18:onlythree"}]}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	byName := map[string]pkgmeta.Package{}
	for _, p := range target.Packages {
		byName[p.Name] = p
	}
	if got := byName["nodejs"].ModuleStream; got != "nodejs:18" {
		t.Errorf("nodejs ModuleStream = %q, want %q", got, "nodejs:18")
	}
	if got := byName["shortlabel"].ModuleStream; got != "" {
		t.Errorf("shortlabel ModuleStream = %q, want empty: fewer than four colon fields", got)
	}
}

// D83: the "upstream" qualifier for rpm is a source-RPM filename, stripped
// back to the bare name; for deb it is "name" or "name@version", and only
// the name half is taken.
func TestParse_SourceFromUpstreamQualifier(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"audit-libs","version":"3.0.7-104.el9",
	   "purl":"pkg:rpm/rhel/audit-libs@3.0.7-104.el9?arch=x86_64&upstream=audit-3.0.7-104.el9.src.rpm&distro=rhel-9.8"},
	  {"type":"library","name":"bash","version":"5.2.15-2+b13",
	   "purl":"pkg:deb/debian/bash@5.2.15-2+b13?arch=amd64&upstream=bash%405.2.15-2&distro=debian-12"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	byName := map[string]pkgmeta.Package{}
	for _, p := range target.Packages {
		byName[p.Name] = p
	}
	auditLibs, ok := byName["audit-libs"]
	if !ok {
		t.Fatal("audit-libs not cataloged")
	}
	if auditLibs.Source == nil || auditLibs.Source.Name != "audit" {
		t.Errorf("audit-libs Source = %+v, want Name %q", auditLibs.Source, "audit")
	}
	bash, ok := byName["bash"]
	if !ok {
		t.Fatal("bash not cataloged")
	}
	if bash.Source == nil || bash.Source.Name != "bash" {
		t.Errorf("bash Source = %+v, want Name %q (the name half of \"bash@5.2.15-2\")", bash.Source, "bash")
	}
}

// D84: apk gets the same per-purl "distro" qualifier fallback rpm and deb
// already had (D83). Before this fix the apk branch keyed ONLY from the
// document's own operating-system component, so a document with no such
// component left every apk package unkeyed even when the purl itself carried
// a usable "distro" qualifier — exactly the shape a real syft 1.51 SPDX
// document has, since SPDX carries no operating-system entity at all.
func TestParse_APKKeyedViaQualifierFallback_NoOSComponent(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"libssl3","version":"3.1.4-r5",
	   "purl":"pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.9"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "Alpine:v3.19" {
		t.Errorf("Ecosystem = %q, want %q (keyed from the purl's own distro qualifier, D84)",
			got, "Alpine:v3.19")
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

// TestParse_AlpmKeyedViaQualifierFallback_NoOSComponent is D97's own version
// of TestParse_APKKeyedViaQualifierFallback_NoOSComponent: syft's own alpm
// purl shape (arch_package.go's packageURL, researched against syft
// source) writes "distro=arch-rolling" — release.ID with no VersionID, so
// PURLQualifiers falls back to BuildID ("rolling") — and this must resolve
// the shared "Arch:rolling" sentinel with no operating-system component in
// the document at all, exactly the shape a real syft SPDX document (and
// some CycloneDX ones) produces.
func TestParse_AlpmKeyedViaQualifierFallback_NoOSComponent(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"acl","version":"2.4.0-1",
	   "purl":"pkg:alpm/arch/acl@2.4.0-1?arch=x86_64&upstream=acl&distro=arch-rolling"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "Arch:rolling" {
		t.Errorf("Ecosystem = %q, want %q (keyed from the purl's own distro qualifier)", got, "Arch:rolling")
	}
	// The purl's namespace ("arch", the distro id) must never be joined into
	// the name — OSV/Arch's tracker name the bare package, the same rule
	// apk/rpm/deb already follow.
	if got := target.Packages[0].Name; got != "acl" {
		t.Errorf("Name = %q, want bare %q (namespace must not be joined in)", got, "acl")
	}
}

// TestParse_AlpmSourceFromUpstreamQualifierWhenDiffers is D8's exact
// analogue for the SBOM path: syft's alpm purl always carries an "upstream"
// qualifier (arch_package.go sets it whenever BasePackage != "", which is
// every real record measured), so this is set ONLY when it differs from
// the bare package name — libelf's own BASE, elfutils, is where Arch's
// tracker actually files libelf's CVEs.
func TestParse_AlpmSourceFromUpstreamQualifierWhenDiffers(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"libelf","version":"0.196-1",
	   "purl":"pkg:alpm/arch/libelf@0.196-1?arch=x86_64&upstream=elfutils&distro=arch-rolling"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	p := target.Packages[0]
	if p.Source == nil || p.Source.Name != "elfutils" {
		t.Fatalf("libelf Source = %+v, want Name elfutils", p.Source)
	}
}

// TestParse_AlpmSourceNilWhenUpstreamEqualsName is the boundary
// TestParse_AlpmSourceFromUpstreamQualifierWhenDiffers approaches from the
// other side: syft's alpm purl carries "upstream=acl" for a non-split
// package too (its own BASE simply repeats NAME), and setting Source there
// as well would make --explain's D8 wording ("matched via source package")
// print for a package whose "source" is itself — the same reasoning
// pacmandb.ParseDesc's own doc comment gives for the image-scan path, kept
// consistent here on the SBOM path.
func TestParse_AlpmSourceNilWhenUpstreamEqualsName(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
	  {"type":"library","name":"acl","version":"2.4.0-1",
	   "purl":"pkg:alpm/arch/acl@2.4.0-1?arch=x86_64&upstream=acl&distro=arch-rolling"}]}`
	target, _, err := Parse(strings.NewReader(bom))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Source; got != nil {
		t.Errorf("Source = %+v, want nil (upstream repeats the bare name)", got)
	}
}

// TestParse_AlpmWithoutDistroIsKeptUnkeyed mirrors
// TestParse_APKWithoutDistroIsKeptUnkeyed: an alpm package with no distro
// anywhere (no operating-system component, no purl "distro" qualifier) must
// still be cataloged, unkeyed, so it is counted and reported as skipped
// rather than silently shrinking the denominator.
func TestParse_AlpmWithoutDistroIsKeptUnkeyed(t *testing.T) {
	const doc = `{
	  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
	  "components": [{
	    "type": "library", "name": "acl", "version": "2.4.0-1",
	    "purl": "pkg:alpm/arch/acl@2.4.0-1?arch=x86_64"
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
		t.Fatalf("Packages = %d, want 1: an unkeyable package is still a package", len(target.Packages))
	}
	if eco := target.Packages[0].Ecosystem; eco != "" {
		t.Errorf("Ecosystem = %q, want empty: there is no distro to derive a release from", eco)
	}
}
