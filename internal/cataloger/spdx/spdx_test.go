package spdx

import (
	"os"
	"strings"
	"testing"
)

func TestParse_UnsupportedSPDXVersionRefused(t *testing.T) {
	_, _, err := Parse(strings.NewReader(`{"spdxVersion":"SPDX-2.1","packages":[]}`))
	if err == nil {
		t.Fatal("Parse(SPDX-2.1) = nil error, want one naming the unsupported version")
	}
	if !strings.Contains(err.Error(), "SPDX-2.1") {
		t.Errorf("error %q does not name the unsupported version", err)
	}
}

func TestParse_NotSPDX(t *testing.T) {
	if _, _, err := Parse(strings.NewReader(`{"bomFormat":"CycloneDX"}`)); err == nil {
		t.Error("Parse(a CycloneDX document) = nil error, want error: no spdxVersion at all")
	}
	if _, _, err := Parse(strings.NewReader("{not json")); err == nil {
		t.Error("Parse(malformed) = nil error, want error")
	}
}

// TestParse_TinyFixture uses a real, hand-built minimal SPDX-2.3 document
// whose DESCRIBES relationship points directly at its one and only package,
// rather than at a synthetic container/image root the way every OTHER
// fixture in this file does. The exclusion rule is structural — whatever the
// DESCRIBES relationship names, not "whatever looks like a root" — so this
// is not a bug: a document that describes itself as being about exactly one
// package, and says nothing else, legitimately has nothing left to catalog.
func TestParse_TinyFixture(t *testing.T) {
	f, err := os.Open("testdata/tiny.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	target, stats, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Components != 0 {
		t.Errorf("Components = %d, want 0: the document's one package IS the DESCRIBES target",
			stats.Components)
	}
	if len(target.Packages) != 0 {
		t.Errorf("Packages = %+v, want none", target.Packages)
	}
}

// TestParse_RPMKeyedViaDistroQualifier mirrors cyclonedx's own qualifier
// fallback test, but SPDX never has a document-level distro to fall back
// FROM in the first place (D84) — this purl's "distro" qualifier is the
// only place the release survives at all. Also proves epoch prefixing and
// upstream->Source, both moved into the shared core untouched.
func TestParse_RPMKeyedViaDistroQualifier(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"openssl","SPDXID":"SPDXRef-openssl","versionInfo":"3.0.7-1.el9",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:rpm/rhel/openssl@3.0.7-1.el9?arch=x86_64&distro=rhel-9.2&epoch=1&upstream=openssl-3.0.7-1.el9.src.rpm"}]}]}`
	target, stats, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Cataloged != 1 {
		t.Errorf("Cataloged = %d, want 1", stats.Cataloged)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	p := target.Packages[0]
	if p.Ecosystem != "Red Hat:9" {
		t.Errorf("Ecosystem = %q, want %q (keyed from the purl's own distro qualifier)", p.Ecosystem, "Red Hat:9")
	}
	if p.Version != "1:3.0.7-1.el9" {
		t.Errorf("Version = %q, want %q (epoch prefixed)", p.Version, "1:3.0.7-1.el9")
	}
	if p.Source == nil || p.Source.Name != "openssl" {
		t.Errorf("Source = %+v, want Name %q (from the upstream qualifier)", p.Source, "openssl")
	}
}

func TestParse_DebKeyedViaDistroQualifier(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"bash","SPDXID":"SPDXRef-bash","versionInfo":"5.2.15-2",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:deb/debian/bash@5.2.15-2?arch=amd64&distro=debian-12&upstream=bash%405.2.15-2"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	p := target.Packages[0]
	if p.Ecosystem != "Debian:12" {
		t.Errorf("Ecosystem = %q, want %q", p.Ecosystem, "Debian:12")
	}
	if p.Source == nil || p.Source.Name != "bash" {
		t.Errorf("Source = %+v, want Name %q (the name half of upstream=bash@5.2.15-2)", p.Source, "bash")
	}
}

// TestParse_APKKeyedViaDistroQualifier is the fix-2 proof from the SPDX
// side: apk has no property mechanism at all here, so if the shared core's
// apk branch still keyed only from a document-level distro (which SPDX
// never has, D84), every apk package in every SPDX document would be
// permanently unkeyed.
func TestParse_APKKeyedViaDistroQualifier(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"libssl3","SPDXID":"SPDXRef-libssl3","versionInfo":"3.1.4-r5",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.9"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "Alpine:v3.19" {
		t.Errorf("Ecosystem = %q, want %q", got, "Alpine:v3.19")
	}
}

// TestParse_APKSourceFromUpstreamQualifier holds the D8 join on the SPDX
// path: Alpine advisories are keyed on SOURCE names (OSV purls carry
// ?arch=source), and SPDX has no originPackage property — the purl's
// "upstream" qualifier is the only carrier. Losing it loses the libssl3 →
// openssl join: a silent false negative, the exact class D8 exists to
// prevent. The fixture's names share no substring (CLAUDE.md).
func TestParse_APKSourceFromUpstreamQualifier(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"libfoo-data","SPDXID":"SPDXRef-libfoo-data","versionInfo":"3.4.3-r2",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:apk/alpine/libfoo-data@3.4.3-r2?arch=x86_64&upstream=srcorigin&distro=alpine-3.19.9"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	src := target.Packages[0].Source
	if src == nil || src.Name != "srcorigin" {
		t.Errorf("Source = %+v, want Name srcorigin from the upstream qualifier", src)
	}
}

// TestParse_MultiplePURLsPerPackageDedupe: Red Hat's own SBOMs emit one purl
// per repository a package is published from — three here, all naming the
// SAME package at the SAME version, differing only in repository_id. They
// must collapse to exactly one cataloged Package, not three.
func TestParse_MultiplePURLsPerPackageDedupe(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"openssl-libs","SPDXID":"SPDXRef-openssl-libs","versionInfo":"3.0.7-18.el9_2",
	   "externalRefs":[
	     {"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=x86_64&epoch=1&repository_id=rhel-9-for-x86_64-baseos-aus-rpms"},
	     {"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=x86_64&epoch=1&repository_id=rhel-9-for-x86_64-baseos-e4s-rpms"},
	     {"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=x86_64&epoch=1&repository_id=rhel-9-for-x86_64-baseos-eus-rpms"}
	   ]}]}`
	target, stats, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Components != 1 {
		t.Errorf("Components = %d, want 1 (one SPDX package, however many purls)", stats.Components)
	}
	if stats.Cataloged != 1 {
		t.Errorf("Cataloged = %d, want 1", stats.Cataloged)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1 - the three purls describe the same package/version and "+
			"must dedupe to one entry", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "Red Hat:9" {
		t.Errorf("Ecosystem = %q, want %q", got, "Red Hat:9")
	}
	if got := target.Packages[0].Version; got != "1:3.0.7-18.el9_2" {
		t.Errorf("Version = %q, want %q", got, "1:3.0.7-18.el9_2")
	}
}

// TestParse_VersionComesFromPURLNotVersionInfo: Red Hat product SBOMs write
// versionInfo "UNKNOWN" on real packages (measured); the purl's own @version
// must win regardless.
func TestParse_VersionComesFromPURLNotVersionInfo(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"openssl-libs","SPDXID":"SPDXRef-openssl-libs","versionInfo":"UNKNOWN",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=x86_64&repository_id=rhel-9-for-x86_64-baseos-rpms"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Version; got != "3.0.7-18.el9_2" {
		t.Errorf("Version = %q, want %q (the purl's own version, never versionInfo %q)",
			got, "3.0.7-18.el9_2", "UNKNOWN")
	}
}

// TestParse_RootPseudoPackageExcluded_Syft151Shape: syft 1.51's own
// document-root package — empty name, primaryPackagePurpose CONTAINER, no
// purl at all — must be excluded entirely, not counted as a no-purl skip.
func TestParse_RootPseudoPackageExcluded_Syft151Shape(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
	  {"name":"","SPDXID":"SPDXRef-DocumentRoot-Image-","primaryPackagePurpose":"CONTAINER"},
	  {"name":"bash","SPDXID":"SPDXRef-Package-bash","versionInfo":"5.2.15-2",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:deb/debian/bash@5.2.15-2?arch=amd64&distro=debian-12"}]}],
	  "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT",
	    "relatedSpdxElement":"SPDXRef-DocumentRoot-Image-","relationshipType":"DESCRIBES"}]}`
	target, stats, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Components != 1 {
		t.Errorf("Components = %d, want 1 (the root must not be counted at all)", stats.Components)
	}
	if stats.SkippedNoPURL != 0 {
		t.Errorf("SkippedNoPURL = %d, want 0: the root has no purl either, but must not land here",
			stats.SkippedNoPURL)
	}
	if len(target.Packages) != 1 || target.Packages[0].Name != "bash" {
		t.Fatalf("Packages = %+v, want just bash", target.Packages)
	}
}

// TestParse_RootPseudoPackageExcluded_RHOCIShape: Red Hat's own container
// SBOMs describe the document as being about the container/product package
// itself, carrying a pkg:oci purl — which would otherwise land in
// SkippedUnsupportedEcosystem (no ecosystem mapping for "oci") were it not
// excluded first.
func TestParse_RootPseudoPackageExcluded_RHOCIShape(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
	  {"name":"ubi9-micro-container_amd64","SPDXID":"SPDXRef-ubi9-micro-container-amd64","versionInfo":"9.4-6",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:oci/ubi-micro@sha256:213fd2a0116a76eaa274fee20c86eef4dfba9f311784e8fb7d7f5fc38b32f3ef?arch=amd64&repository_url=registry.access.redhat.com/ubi9/ubi-micro&tag=9.4-6"}]},
	  {"name":"openssl-libs","SPDXID":"SPDXRef-openssl-libs","versionInfo":"3.0.7-18.el9_2",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=x86_64&repository_id=rhel-9-for-x86_64-baseos-rpms"}]}],
	  "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT",
	    "relatedSpdxElement":"SPDXRef-ubi9-micro-container-amd64","relationshipType":"DESCRIBES"}]}`
	target, stats, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Components != 1 {
		t.Errorf("Components = %d, want 1 (the pkg:oci root must not be counted at all)", stats.Components)
	}
	if stats.SkippedUnsupportedEcosystem != 0 {
		t.Errorf("SkippedUnsupportedEcosystem = %d, want 0: pkg:oci has no ecosystem mapping, but "+
			"the root must be excluded before that would ever fire", stats.SkippedUnsupportedEcosystem)
	}
	if len(target.Packages) != 1 || target.Packages[0].Name != "openssl-libs" {
		t.Fatalf("Packages = %+v, want just openssl-libs", target.Packages)
	}
}

// TestParse_UnanchoredDescribesExcludesNothing holds findRootPackageID's
// anchor condition: the DESCRIBES relationship only names a document root
// when it originates at the document's OWN SPDXID. Every other
// root-exclusion fixture in this file happens to have its only DESCRIBES
// relationship anchored there, so dropping the anchor check entirely would
// leave them green — this fixture's DESCRIBES instead runs
// package-to-package (bash "describing" coreutils), which is spec-legal but
// says nothing about which package is the document root. Treating it as a
// root anyway would silently exclude coreutils from the scan: uncounted in
// every Stats bucket, invisible to --fail-on-incomplete.
func TestParse_UnanchoredDescribesExcludesNothing(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
	  {"name":"bash","SPDXID":"SPDXRef-Package-bash","versionInfo":"5.2.15-2",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:deb/debian/bash@5.2.15-2?arch=amd64&distro=debian-12"}]},
	  {"name":"coreutils","SPDXID":"SPDXRef-Package-coreutils","versionInfo":"9.1-1",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:deb/debian/coreutils@9.1-1?arch=amd64&distro=debian-12"}]}],
	  "relationships":[{"spdxElementId":"SPDXRef-Package-bash",
	    "relatedSpdxElement":"SPDXRef-Package-coreutils","relationshipType":"DESCRIBES"}]}`
	target, stats, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Components != 2 {
		t.Errorf("Components = %d, want 2 — a DESCRIBES not anchored at the document's own "+
			"SPDXID names no root, so nothing should be excluded", stats.Components)
	}
	names := map[string]bool{}
	for _, p := range target.Packages {
		names[p.Name] = true
	}
	if !names["bash"] || !names["coreutils"] {
		t.Fatalf("Packages = %+v, want both bash and coreutils — coreutils must not be "+
			"silently dropped as a false root", target.Packages)
	}
}

func TestParse_NoPURLPackageCounted(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"mystery","SPDXID":"SPDXRef-mystery","versionInfo":"1.0"}]}`
	target, stats, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Components != 1 || stats.SkippedNoPURL != 1 {
		t.Errorf("Stats = %+v, want 1 component and 1 skipped for no purl", stats)
	}
	if len(target.Packages) != 0 {
		t.Errorf("Packages = %+v, want none", target.Packages)
	}
}

// TestParse_ReferenceCategoryUnderscoreVariantAccepted: real Red Hat SBOMs
// from the SAME generator have been observed writing both
// "PACKAGE-MANAGER" and "PACKAGE_MANAGER" for referenceType "purl" —
// referenceCategory must never gate whether a purl is read at all.
func TestParse_ReferenceCategoryUnderscoreVariantAccepted(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"openssl-libs","SPDXID":"SPDXRef-openssl-libs","versionInfo":"3.0.7-18.el9_2",
	   "externalRefs":[{"referenceCategory":"PACKAGE_MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=x86_64&repository_id=rhel-9-for-x86_64-baseos-rpms"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1: the underscore-spelled referenceCategory must not "+
			"suppress the purl", len(target.Packages))
	}
}

// TestParse_NonPURLReferenceTypeIgnored pins the referenceType=="purl" gate
// itself, independent of pkgmeta.ParsePURL's own rejection of non-"pkg:"
// strings. A real cpe23Type/cpe22Type locator ("cpe:2.3:...") would never
// parse as a purl anyway, so a fixture built from real data cannot tell
// whether the code checks referenceType or is merely saved by ParsePURL
// failing downstream — this uses a deliberately unrealistic locator (purl
// shape, non-purl referenceType) specifically so the two can be told apart:
// only the code's own field check can catch it, and it is the field the
// fixed design (D84) names as the sole gate ("NEVER filter on
// referenceCategory" implies referenceType is what IS filtered on).
func TestParse_NonPURLReferenceTypeIgnored(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"openssl-libs","SPDXID":"SPDXRef-openssl-libs","versionInfo":"3.0.7-18.el9_2",
	   "externalRefs":[
	     {"referenceCategory":"OTHER","referenceType":"other",
	      "referenceLocator":"pkg:rpm/redhat/openssl-libs@9.9.9-9.el9?arch=x86_64&repository_id=rhel-9-for-x86_64-baseos-rpms"},
	     {"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	      "referenceLocator":"pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=x86_64&repository_id=rhel-9-for-x86_64-baseos-rpms"}
	   ]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1: the referenceType=\"other\" entry (a purl-shaped locator "+
			"under the wrong referenceType) must not be read", len(target.Packages))
	}
	if got := target.Packages[0].Version; got != "3.0.7-18.el9_2" {
		t.Errorf("Version = %q, want %q (from the genuine purl ref, not the decoy's 9.9.9-9.el9)",
			got, "3.0.7-18.el9_2")
	}
}

func TestParse_RepositoryIDDerivesRedHatMajor(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"openssl-libs","SPDXID":"SPDXRef-openssl-libs","versionInfo":"3.0.7-18.el9_2",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=x86_64&repository_id=rhel-9-for-x86_64-baseos-rpms"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].Ecosystem; got != "Red Hat:9" {
		t.Errorf("Ecosystem = %q, want %q (derived from repository_id, no distro qualifier present)",
			got, "Red Hat:9")
	}
}

// TestParse_NonRHELRepositoryIDLeavesUnkeyed pins WHICH shape the fallback
// recognizes: only a repository_id starting "rhel-<major>-", not any
// repository_id at all. A CentOS Stream (or any other vendor's) repository
// naming must never be guessed at as if it were Red Hat's own.
func TestParse_NonRHELRepositoryIDLeavesUnkeyed(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"mystery-lib","SPDXID":"SPDXRef-mystery-lib","versionInfo":"1.0-1",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:rpm/centos/mystery-lib@1.0-1?arch=x86_64&repository_id=centos-9-stream-baseos"}]}]}`
	target, stats, err := Parse(strings.NewReader(doc))
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
		t.Errorf("Ecosystem = %q, want empty: repository_id names a non-RHEL repository", got)
	}
}

// TestParse_RPMModQualifierToModuleStream: Red Hat's own SPDX SBOMs write
// the module label directly as a purl qualifier, unlike syft's CycloneDX
// output which uses a property instead (cyclonedx.go's own reading).
func TestParse_RPMModQualifierToModuleStream(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"delve","SPDXID":"SPDXRef-x86-64-delve","versionInfo":"1.7.2-1.module+el8.6.0+12972+ebab5911",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:rpm/redhat/delve@1.7.2-1.module%2Bel8.6.0%2B12972%2Bebab5911?arch=x86_64&repository_id=rhel-8-for-x86_64-appstream-rpms&rpmmod=go-toolset:rhel8:8060020250609110611:97d7f71f"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	p := target.Packages[0]
	if p.ModuleStream != "go-toolset:rhel8" {
		t.Errorf("ModuleStream = %q, want %q", p.ModuleStream, "go-toolset:rhel8")
	}
	if p.Ecosystem != "Red Hat:8" {
		t.Errorf("Ecosystem = %q, want %q", p.Ecosystem, "Red Hat:8")
	}
	if p.Version != "1.7.2-1.module+el8.6.0+12972+ebab5911" {
		t.Errorf("Version = %q, want the purl's own (percent-decoded) version", p.Version)
	}
}

func TestParse_RPMModQualifierShortFieldsLeavesEmpty(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"delve","SPDXID":"SPDXRef-x86-64-delve","versionInfo":"1.7.2-1.el8",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:rpm/redhat/delve@1.7.2-1.el8?arch=x86_64&repository_id=rhel-8-for-x86_64-appstream-rpms&rpmmod=go-toolset:rhel8:onlythree"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	if got := target.Packages[0].ModuleStream; got != "" {
		t.Errorf("ModuleStream = %q, want empty: fewer than four colon fields", got)
	}
}

// TestParse_ArchSrcSkippedAndCounted: an SRPM purl riding alongside its
// binaries in a Red Hat SBOM must never be cataloged — it would double count
// and compare a source RPM's EVR against advisories written for binary
// packages — but it is still a real package entry the summary must account
// for, not one that vanishes from every counter.
func TestParse_ArchSrcSkippedAndCounted(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"openssl","SPDXID":"SPDXRef-SRPM-standalone","versionInfo":"3.0.7-18.el9_2",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&epoch=1&repository_id=rhel-9-for-x86_64-baseos-source-rpms"}]}]}`
	target, stats, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if stats.Components != 1 {
		t.Errorf("Components = %d, want 1", stats.Components)
	}
	if stats.SkippedUnsupportedEcosystem != 1 {
		t.Errorf("SkippedUnsupportedEcosystem = %d, want 1 (arch=src routed there)",
			stats.SkippedUnsupportedEcosystem)
	}
	if len(target.Packages) != 0 {
		t.Errorf("Packages = %+v, want none: an SRPM must never be cataloged", target.Packages)
	}
}

// TestParse_UbuntuQualifierEvenYearLTSFallback lands D84's own change
// (internal/pkgmeta/distro.go's ubuntuEvenYearLTS) end to end: SPDX carries
// no PRETTY_NAME anywhere, so this is the fallback's only way to ever fire
// through a real caller. The full key is asserted, not a Contains check,
// because "Ubuntu:22.04" is a substring of "Ubuntu:22.04:LTS" and would pass
// on the wrong column.
func TestParse_UbuntuQualifierEvenYearLTSFallback(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"bash","SPDXID":"SPDXRef-bash","versionInfo":"5.1-6ubuntu1.1",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:deb/ubuntu/bash@5.1-6ubuntu1.1?arch=amd64&distro=ubuntu-22.04"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
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

// TestParse_NonDistroPurlType exercises the default (non apk/rpm/deb) branch
// directly through Parse, not just through cyclonedx.go's own tests — a Go
// module purl, keyed the ordinary way (EcosystemForPURLType), never through
// the shared distro core.
func TestParse_NonDistroPurlType(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"viper","SPDXID":"SPDXRef-go-viper","versionInfo":"v1.9.0",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:golang/github.com/spf13/viper@v1.9.0"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	p := target.Packages[0]
	if p.Ecosystem != "Go" {
		t.Errorf("Ecosystem = %q, want Go", p.Ecosystem)
	}
	if p.Name != "github.com/spf13/viper" {
		t.Errorf("Name = %q, want %q", p.Name, "github.com/spf13/viper")
	}
	if p.Version != "v1.9.0" {
		t.Errorf("Version = %q, want v1.9.0 (verbatim, v intact)", p.Version)
	}
}

// TestParse_EveryComponentLandsInExactlyOneCounter is the SPDX analogue of
// cyclonedx's own invariant test: the summary line is only trustworthy if
// the buckets add up, across every outcome this cataloger has.
func TestParse_EveryComponentLandsInExactlyOneCounter(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"ok","SPDXID":"SPDXRef-ok","versionInfo":"1.0.0",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:golang/example.com/ok@1.0.0"}]},
	  {"name":"nopurl","SPDXID":"SPDXRef-nopurl","versionInfo":"1.0.0"},
	  {"name":"badpurl","SPDXID":"SPDXRef-badpurl","versionInfo":"1.0.0",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"not-a-purl"}]},
	  {"name":"apk","SPDXID":"SPDXRef-apk","versionInfo":"1.0-r0",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:apk/alpine/apk@1.0-r0"}]},
	  {"name":"noversion","SPDXID":"SPDXRef-noversion",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:golang/example.com/noversion"}]},
	  {"name":"srpm","SPDXID":"SPDXRef-srpm","versionInfo":"1.0-1.el9",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:rpm/redhat/srpm@1.0-1.el9?arch=src&repository_id=rhel-9-for-x86_64-baseos-source-rpms"}]}
	]}`
	_, stats, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sum := stats.Cataloged + stats.SkippedNoPURL + stats.SkippedNoVersion + stats.SkippedUnsupportedEcosystem
	if sum != stats.Components {
		t.Errorf("counters sum to %d but Components = %d (%+v)", sum, stats.Components, stats)
	}
	if stats.Components != 6 {
		t.Errorf("Components = %d, want 6", stats.Components)
	}
}

// TestParse_AlpmKeyedViaDistroQualifier is D97's own version of
// TestParse_APKKeyedViaDistroQualifier: SPDX never has a document-level
// distro (D84), so an alpm package's purl "distro" qualifier is the only
// place the ecosystem key survives at all.
func TestParse_AlpmKeyedViaDistroQualifier(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"acl","SPDXID":"SPDXRef-acl","versionInfo":"2.4.0-1",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:alpm/arch/acl@2.4.0-1?arch=x86_64&upstream=acl&distro=arch-rolling"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	p := target.Packages[0]
	if p.Ecosystem != "Arch:rolling" {
		t.Errorf("Ecosystem = %q, want %q", p.Ecosystem, "Arch:rolling")
	}
	if p.Name != "acl" {
		t.Errorf("Name = %q, want bare %q (namespace \"arch\" must not be joined in)", p.Name, "acl")
	}
	// upstream repeats the bare name here (acl is not a split package) --
	// Source must stay nil, the same D8 boundary
	// TestParse_AlpmSourceNilWhenUpstreamEqualsName pins on the CycloneDX
	// side.
	if p.Source != nil {
		t.Errorf("Source = %+v, want nil (upstream repeats the bare name)", p.Source)
	}
}

// TestParse_AlpmSourceFromUpstreamQualifier holds D8's join on the SPDX
// path, mirroring TestParse_APKSourceFromUpstreamQualifier: Arch's own
// tracker keys advisories on pkgbase (elfutils), which differs from the
// installed libelf package's own name, and SPDX has no property mechanism
// to carry it any other way — the purl's "upstream" qualifier is the only
// carrier.
func TestParse_AlpmSourceFromUpstreamQualifier(t *testing.T) {
	const doc = `{"spdxVersion":"SPDX-2.3","packages":[
	  {"name":"libelf","SPDXID":"SPDXRef-libelf","versionInfo":"0.196-1",
	   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
	     "referenceLocator":"pkg:alpm/arch/libelf@0.196-1?arch=x86_64&upstream=elfutils&distro=arch-rolling"}]}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 1 {
		t.Fatalf("Packages = %d, want 1", len(target.Packages))
	}
	src := target.Packages[0].Source
	if src == nil || src.Name != "elfutils" {
		t.Errorf("Source = %+v, want Name elfutils from the upstream qualifier", src)
	}
}
