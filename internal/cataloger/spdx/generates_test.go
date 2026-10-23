package spdx

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// 2026-10-22 audit, A3. Red Hat's own SPDX SBOMs carry the binary->source
// link as a relationship, not as a purl qualifier: the source rpm is its own
// package (`?arch=src`) and `SRC GENERATES BIN` joins them. Measured on
// rhel-9.6.z.json.bz2 (2026-10-23): 44,854 binary rpms, 970 with an
// `upstream` qualifier, 44,206 reachable through GENERATES. Reading only
// `upstream` left Source nil on the rest, and Red Hat's no-fix entries are
// keyed on the SOURCE name (D8), so a vendor SBOM of an image reported
// openssl-libs, krb5-libs and glibc-common clean where the image scan of the
// same content found them.

// rhDoc builds a Red Hat-shaped SPDX document from packages and
// relationships, with a DESCRIBES root that is not one of the packages.
func rhDoc(packages, relationships string) string {
	return `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
	 "packages":[` + packages + `],
	 "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-product","relationshipType":"DESCRIBES"}` + relationships + `]}`
}

func rhPkg(id, purl string) string {
	return `{"name":"x","SPDXID":"` + id + `","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"` + purl + `"}]}`
}

func rel(a, typ, b string) string {
	return `,{"spdxElementId":"` + a + `","relatedSpdxElement":"` + b + `","relationshipType":"` + typ + `"}`
}

func byName(t *testing.T, target pkgmeta.Target, name string) pkgmeta.Package {
	t.Helper()
	for _, p := range target.Packages {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no package %q in %+v", name, target.Packages)
	return pkgmeta.Package{}
}

const (
	srcOpenSSL = "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src"
	binLibs    = "pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=x86_64&repository_id=rhel-9-for-x86_64-baseos-rpms"
)

func TestParse_A3_GeneratesGivesTheBinaryItsSource(t *testing.T) {
	doc := rhDoc(rhPkg("SPDXRef-src", srcOpenSSL)+","+rhPkg("SPDXRef-bin", binLibs),
		rel("SPDXRef-src", "GENERATES", "SPDXRef-bin"))
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	p := byName(t, target, "openssl-libs")
	if p.Source == nil || p.Source.Name != "openssl" {
		t.Fatalf("openssl-libs Source = %+v, want openssl (from SRC GENERATES BIN)", p.Source)
	}
	// The source rpm itself is still not an inventory entry (D84).
	if len(target.Packages) != 1 {
		t.Errorf("Packages = %d, want 1: the arch=src package is a link, not an installed package", len(target.Packages))
	}
}

// SPDX defines BIN GENERATED_FROM SRC as the same relation, written from
// the other end; generators use either.
func TestParse_A3_GeneratedFromGivesTheBinaryItsSource(t *testing.T) {
	doc := rhDoc(rhPkg("SPDXRef-src", srcOpenSSL)+","+rhPkg("SPDXRef-bin", binLibs),
		rel("SPDXRef-bin", "GENERATED_FROM", "SPDXRef-src"))
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if p := byName(t, target, "openssl-libs"); p.Source == nil || p.Source.Name != "openssl" {
		t.Fatalf("openssl-libs Source = %+v, want openssl (from BIN GENERATED_FROM SRC)", p.Source)
	}
}

// A source rpm also GENERATES the language packages it bundles (106,299
// cargo and 73,748 npm edges in the same SBOM). Those are not built from an
// rpm source in the D8 sense, and an npm package whose Source was an rpm
// name would be looked up under that name in the npm ecosystem.
func TestParse_A3_BundledLanguagePackagesGetNoRPMSource(t *testing.T) {
	doc := rhDoc(rhPkg("SPDXRef-src", srcOpenSSL)+","+rhPkg("SPDXRef-npm", "pkg:npm/lodash@4.17.21"),
		rel("SPDXRef-src", "GENERATES", "SPDXRef-npm"))
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if p := byName(t, target, "lodash"); p.Source != nil {
		t.Errorf("lodash Source = %+v, want nil: an rpm source is not an npm package's source", p.Source)
	}
}

// An explicit `upstream` qualifier on the binary's own purl is the more
// specific statement and wins over the relationship.
func TestParse_A3_UpstreamQualifierWinsOverTheRelationship(t *testing.T) {
	bin := binLibs + "&upstream=openssl-fips-3.0.7-18.el9_2.src.rpm"
	doc := rhDoc(rhPkg("SPDXRef-src", srcOpenSSL)+","+rhPkg("SPDXRef-bin", bin),
		rel("SPDXRef-src", "GENERATES", "SPDXRef-bin"))
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if p := byName(t, target, "openssl-libs"); p.Source == nil || p.Source.Name != "openssl-fips" {
		t.Errorf("openssl-libs Source = %+v, want openssl-fips from its own upstream qualifier", p.Source)
	}
}

// A relationship to a package that is not a source rpm (a binary GENERATES
// a Go module, measured 11,739 times) gives nothing a source.
func TestParse_A3_OnlyASourceRPMIsASource(t *testing.T) {
	other := "pkg:rpm/redhat/openssl-devel@3.0.7-18.el9_2?arch=x86_64&repository_id=rhel-9-for-x86_64-appstream-rpms"
	doc := rhDoc(rhPkg("SPDXRef-a", other)+","+rhPkg("SPDXRef-bin", binLibs),
		rel("SPDXRef-a", "GENERATES", "SPDXRef-bin"))
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if p := byName(t, target, "openssl-libs"); p.Source != nil {
		t.Errorf("openssl-libs Source = %+v, want nil: its GENERATES parent is a binary rpm, not a source", p.Source)
	}
}
