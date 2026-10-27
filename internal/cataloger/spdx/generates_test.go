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
	// Name only, as an upstream qualifier gives: the relationship's source
	// EVR belongs to the relationship's source (openssl), not to this one.
	if p := byName(t, target, "openssl-libs"); p.Source == nil || p.Source.Name != "openssl-fips" || p.Source.Version != "" {
		t.Errorf("openssl-libs Source = %+v, want openssl-fips, no version, from its own upstream qualifier", p.Source)
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

// A source rpm also GENERATES the test-data rpms vendored in its tree: dnf,
// libdnf and rpm-ostree carry fixtures named glibc, kernel and httpd (D143
// review). Taking the bundler's name for those turned every dnf advisory into
// a finding on "glibc". A real subpackage is built in the same build as its
// source, so it shares the source's release, or at least its RHEL dist tag
// (nodejs builds npm 8.19.3-1.16.19.1.1.el9_2 from 16.19.1-1.el9_2); a
// fixture shares neither (2.17-157, .fc25, .el7). Measured on rhel-9.6.z:
// 43,105 edges share the release, 28 more share the dist tag, and the 1,073
// that share neither are all vendored fixtures.
func TestParse_A3_AVendoredFixtureDoesNotTakeTheBundlersName(t *testing.T) {
	src := "pkg:rpm/redhat/dnf@4.14.0-9.el9?arch=src"
	fixture := "pkg:rpm/glibc@2.17-157?arch=x86_64&epoch=0&repository_id=rhel-9-for-x86_64-baseos-rpms__9"
	doc := rhDoc(rhPkg("SPDXRef-src", src)+","+rhPkg("SPDXRef-fx", fixture),
		rel("SPDXRef-src", "GENERATES", "SPDXRef-fx"))
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if p := byName(t, target, "glibc"); p.Source != nil {
		t.Errorf("fixture glibc Source = %+v, want nil: it shares neither dnf's release nor its dist tag", p.Source)
	}
}

func TestParse_A3_ASubpackageWithItsOwnReleaseKeepsItsSource(t *testing.T) {
	src := "pkg:rpm/redhat/nodejs@16.19.1-1.el9_2?arch=src&epoch=1"
	npm := "pkg:rpm/redhat/npm@8.19.3-1.16.19.1.1.el9_2?arch=x86_64&epoch=1&repository_id=rhel-9-for-x86_64-appstream-rpms"
	doc := rhDoc(rhPkg("SPDXRef-src", src)+","+rhPkg("SPDXRef-npm", npm),
		rel("SPDXRef-src", "GENERATES", "SPDXRef-npm"))
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	p := byName(t, target, "npm")
	if p.Source == nil || p.Source.Name != "nodejs" {
		t.Errorf("npm Source = %+v, want nodejs: a different release with the same el9_2 dist tag is a real subpackage", p.Source)
	}
	// The relationship carries the source's EVR, epoch included from the
	// source purl's own qualifier. D143 kept the name only, and the matcher
	// then compared npm's 8.19.3 against nodejs fixes (2026-10-27 review).
	if p.Source == nil || p.Source.Version != "1:16.19.1-1.el9_2" {
		t.Errorf("npm Source = %+v, want version 1:16.19.1-1.el9_2", p.Source)
	}
}

// The source's epoch is the source purl's alone: none when it names none
// or names 0, never borrowed from the binary's (mod_ssl carries epoch 1,
// httpd none), and no version at all when the source purl has none.
func TestParse_SourceEVRComesFromTheSourcePURLOnly(t *testing.T) {
	for _, tc := range []struct {
		name, src, want string
	}{
		{"no epoch qualifier", "pkg:rpm/fedora/httpd@2.4.62-1.fc40?arch=src&distro=fedora-40", "2.4.62-1.fc40"},
		{"epoch 0", "pkg:rpm/fedora/httpd@2.4.62-1.fc40?arch=src&epoch=0&distro=fedora-40", "2.4.62-1.fc40"},
		{"epoch 2", "pkg:rpm/fedora/httpd@2.4.62-1.fc40?arch=src&epoch=2&distro=fedora-40", "2:2.4.62-1.fc40"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := "pkg:rpm/fedora/mod_ssl@2.4.62-1.fc40?arch=x86_64&epoch=1&distro=fedora-40"
			doc := rhDoc(rhPkg("SPDXRef-src", tc.src)+","+rhPkg("SPDXRef-bin", bin),
				rel("SPDXRef-bin", "GENERATED_FROM", "SPDXRef-src"))
			target, _, err := Parse(strings.NewReader(doc))
			if err != nil {
				t.Fatal(err)
			}
			p := byName(t, target, "mod_ssl")
			if p.Source == nil || p.Source.Name != "httpd" || p.Source.Version != tc.want {
				t.Errorf("mod_ssl Source = %+v, want httpd %s", p.Source, tc.want)
			}
			if p.Version != "1:2.4.62-1.fc40" {
				t.Errorf("mod_ssl Version = %q, want its own 1:2.4.62-1.fc40", p.Version)
			}
		})
	}
}
