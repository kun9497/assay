package vex

import (
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
)

const testDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// TestImageProductForms pins which product shapes are images and what each
// identifies (D121). Repositories are compared after go-containerregistry's
// normalisation, so "alpine", "docker.io/library/alpine" and
// "pkg:docker/alpine" are one repository.
func TestImageProductForms(t *testing.T) {
	tests := []struct {
		id     string
		isImg  bool
		wantID imageRef
	}{
		// purls
		{"pkg:docker/dhi/python@3.13", true, imageRef{repository: "index.docker.io/dhi/python", tag: "3.13"}},
		{"pkg:docker/alpine", true, imageRef{repository: "index.docker.io/library/alpine"}},
		{"pkg:docker/team/app@1.0?repository_url=registry.example.com:5000", true,
			imageRef{repository: "registry.example.com:5000/team/app", tag: "1.0"}},
		{"pkg:docker/team/app?repository_url=https://hub.docker.com", true, imageRef{repository: "index.docker.io/team/app"}},
		{"pkg:docker/dhi/python@sha256%3A1111111111111111111111111111111111111111111111111111111111111111", true,
			imageRef{repository: "index.docker.io/dhi/python", digest: testDigest}},
		{"pkg:oci/debian@sha256%3A1111111111111111111111111111111111111111111111111111111111111111?repository_url=docker.io/library/debian",
			true, imageRef{repository: "index.docker.io/library/debian", digest: testDigest}},
		{"pkg:oci/app?repository_url=ghcr.io/org/app&tag=v2", true, imageRef{repository: "ghcr.io/org/app", tag: "v2"}},
		{"pkg:oci/app", true, imageRef{}},
		{"pkg:deb/debian/libssl3", false, imageRef{}},
		// image references
		{"alpine:3.19", true, imageRef{repository: "index.docker.io/library/alpine", tag: "3.19"}},
		{"ghcr.io/org/app", true, imageRef{repository: "ghcr.io/org/app"}},
		{"ghcr.io/org/app@" + testDigest, true, imageRef{repository: "ghcr.io/org/app", digest: testDigest}},
		{"registry.example.com:5000/team/app:1.0", true, imageRef{repository: "registry.example.com:5000/team/app", tag: "1.0"}},
		// not images
		{"nginx", false, imageRef{}},
		{"cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*", false, imageRef{}},
		{"https://example.com/products/app", false, imageRef{}},
		{"urn:uuid:5b5b8b1c-1111-2222-3333-444455556666", false, imageRef{}},
		{"two words/here:1", false, imageRef{}},
	}
	for _, tt := range tests {
		lp, ok := buildLiveProduct(productFor(tt.id), func(msg string) { t.Errorf("%s: warned %s", tt.id, msg) })
		if !ok {
			t.Errorf("%s: not built", tt.id)
			continue
		}
		if (lp.image != nil) != tt.isImg {
			t.Errorf("%s: image product = %v, want %v", tt.id, lp.image != nil, tt.isImg)
			continue
		}
		if lp.image != nil && *lp.image != tt.wantID {
			t.Errorf("%s: identifies %+v, want %+v", tt.id, *lp.image, tt.wantID)
		}
	}
}

func productFor(id string) Product {
	if len(id) > 4 && id[:4] == "pkg:" {
		return Product{PURLAttr: id}
	}
	return Product{ID: id}
}

// TestImageRefMatches is the scope rule itself: a digest matches either
// recorded digest whatever the names say; a tag needs the same repository
// and tag; a bare repository matches any tag of it; nothing matches a
// target that is not an image, and a product that identifies no image
// matches no target.
func TestImageRefMatches(t *testing.T) {
	repo, tag := TargetFromReference("alpine:3.19")
	registry := Target{Image: true, Repository: repo, Tag: tag, Digests: []string{"sha256:aaaa", testDigest}}
	archive := Target{Image: true, Digests: []string{testDigest, ""}}
	tests := []struct {
		name   string
		ref    imageRef
		target Target
		want   bool
	}{
		{"index digest", imageRef{digest: testDigest}, registry, true},
		{"manifest digest, other name", imageRef{repository: "ghcr.io/x/y", digest: "sha256:aaaa"}, registry, true},
		{"other digest", imageRef{digest: "sha256:bbbb"}, registry, false},
		{"tag", imageRef{repository: "index.docker.io/library/alpine", tag: "3.19"}, registry, true},
		{"other tag", imageRef{repository: "index.docker.io/library/alpine", tag: "3.20"}, registry, false},
		{"other repository", imageRef{repository: "index.docker.io/library/debian", tag: "3.19"}, registry, false},
		{"repository only", imageRef{repository: "index.docker.io/library/alpine"}, registry, true},
		{"identifies nothing", imageRef{}, registry, false},
		{"archive by digest", imageRef{digest: testDigest}, archive, true},
		{"archive by name", imageRef{repository: "index.docker.io/library/alpine"}, archive, false},
		{"not an image", imageRef{digest: testDigest}, Target{Digests: []string{testDigest}}, false},
	}
	for _, tt := range tests {
		if got := tt.ref.matches(tt.target); got != tt.want {
			t.Errorf("%s: matches = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestTargetFromReference(t *testing.T) {
	for _, tt := range []struct{ ref, repo, tag string }{
		{"alpine", "index.docker.io/library/alpine", "latest"},
		{"docker.io/library/alpine:3.19", "index.docker.io/library/alpine", "3.19"},
		{"ghcr.io/org/app@" + testDigest, "ghcr.io/org/app", ""},
		{"NOT a ref!!", "", ""},
	} {
		repo, tag := TargetFromReference(tt.ref)
		if repo != tt.repo || tag != tt.tag {
			t.Errorf("TargetFromReference(%q) = %q, %q; want %q, %q", tt.ref, repo, tag, tt.repo, tt.tag)
		}
	}
}

// osFinding is a finding on an OS package with its purl and source, the
// shape an image scan produces after D121.
func osFinding(cve, purl, name, version, srcName, srcVersion string) matcher.Finding {
	return matcher.Finding{
		Package: pkgmeta.Package{
			Name: name, Version: version, PURL: purl,
			Source: &pkgmeta.SourcePackage{Name: srcName, Version: srcVersion},
		},
		Advisory:    advisory.Advisory{ID: "TEST-" + name},
		Identifiers: []string{"TEST-" + name, cve},
	}
}

func suppressedNames(sup []matcher.Suppressed) map[string]bool {
	out := map[string]bool{}
	for _, s := range sup {
		out[s.Finding.Package.Name] = true
	}
	return out
}

func doc1(products ...Product) *Document {
	return &Document{Statements: []Statement{{
		Vulnerability: Vulnerability{Name: "CVE-2031-7001"},
		Status:        "not_affected", Justification: "vulnerable_code_not_present",
		Products: products,
	}}}
}

// Rocky's openssl is both the source and a binary; openssl-libs is built
// from it. Red Hat marks a source arch=src and carries the epoch as a
// qualifier; the cataloger folds it into the version.
func rockyOpenssl() []matcher.Finding {
	return []matcher.Finding{
		osFinding("CVE-2031-7001", "pkg:rpm/rocky/openssl@3.0.7-27.el9?arch=x86_64&distro=rocky-9.3&epoch=1&upstream=openssl-3.0.7-27.el9.src.rpm",
			"openssl", "1:3.0.7-27.el9", "openssl", "1:3.0.7-27.el9"),
		osFinding("CVE-2031-7001", "pkg:rpm/rocky/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=rocky-9.3&epoch=1&upstream=openssl-3.0.7-27.el9.src.rpm",
			"openssl-libs", "1:3.0.7-27.el9", "openssl", "1:3.0.7-27.el9"),
		osFinding("CVE-2031-7001", "pkg:rpm/rocky/glibc@2.34-100.el9?arch=x86_64&distro=rocky-9.3&upstream=glibc-2.34-100.el9.src.rpm",
			"glibc", "2.34-100.el9", "glibc", "2.34-100.el9"),
	}
}

func TestApply_SourceStatements(t *testing.T) {
	tests := []struct {
		name string
		prod string
		want []string
	}{
		{"marked arch=src with epoch covers every binary of the source",
			"pkg:rpm/rocky/openssl@3.0.7-27.el9?arch=src&epoch=1", []string{"openssl", "openssl-libs"}},
		{"version-less marked source covers them too",
			"pkg:rpm/rocky/openssl?arch=src", []string{"openssl", "openssl-libs"}},
		{"unmarked: the binary of that name only",
			"pkg:rpm/rocky/openssl@3.0.7-27.el9?epoch=1", []string{"openssl"}},
		{"marked, but the source without its epoch is another version",
			"pkg:rpm/rocky/openssl@3.0.7-27.el9?arch=src", nil},
		{"marked, other version", "pkg:rpm/rocky/openssl@3.0.7-18.el9?arch=src&epoch=1", nil},
		{"marked, other distro qualifier", "pkg:rpm/rocky/openssl?arch=src&distro=rocky-8.9", nil},
		{"arch=source is deb's marker, not rpm's", "pkg:rpm/rocky/openssl?arch=source", nil},
		{"namespace compared case-insensitively", "pkg:rpm/Rocky/openssl?arch=src", []string{"openssl", "openssl-libs"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, sup, _ := doc1(Product{PURLAttr: tt.prod}).Apply(rockyOpenssl(), Target{}, func(string) {})
			got := suppressedNames(sup)
			if len(got) != len(tt.want) {
				t.Fatalf("suppressed %v, want %v", got, tt.want)
			}
			for _, n := range tt.want {
				if !got[n] {
					t.Errorf("suppressed %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestApply_RPMEpochZeroEqualsNone(t *testing.T) {
	// syft writes epoch=0 for an rpmdb holding an explicit zero; the rpmdb
	// cataloger writes no epoch at all. Same package.
	f := osFinding("CVE-2031-7001", "pkg:rpm/redhat/perl-Errno@1.28-422.el8?arch=x86_64&distro=rhel-8.10&upstream=perl-5.26.3-422.el8.src.rpm",
		"perl-Errno", "1.28-422.el8", "perl", "1.28-422.el8")
	_, sup, _ := doc1(Product{PURLAttr: "pkg:rpm/redhat/perl-Errno@1.28-422.el8?arch=x86_64&distro=rhel-8.10&epoch=0"}).
		Apply([]matcher.Finding{f}, Target{}, func(string) {})
	if len(sup) != 1 {
		t.Errorf("epoch=0 statement did not apply to a package with no epoch")
	}
	_, sup, _ = doc1(Product{PURLAttr: "pkg:rpm/redhat/perl-Errno@1.28-422.el8?epoch=1"}).
		Apply([]matcher.Finding{f}, Target{}, func(string) {})
	if len(sup) != 0 {
		t.Errorf("epoch=1 statement applied to a package with no epoch")
	}
}

func TestApply_NamespaceCase(t *testing.T) {
	deb := osFinding("CVE-2031-7001", "pkg:deb/debian/systemd@252.39-1~deb12u2?arch=amd64&distro=debian-12.15",
		"systemd", "252.39-1~deb12u2", "systemd", "252.39-1~deb12u2")
	// syft's ELF-note cataloger writes the capitalised namespace.
	_, sup, _ := doc1(Product{PURLAttr: "pkg:deb/Debian/systemd@252.39-1~deb12u2"}).Apply([]matcher.Finding{deb}, Target{}, func(string) {})
	if len(sup) != 1 {
		t.Errorf("pkg:deb/Debian did not match pkg:deb/debian")
	}
	// A Go module path is case-sensitive and stays so.
	gomod := finding("CVE-2031-7001", "pkg:golang/github.com/Org/mod@1.0.0")
	_, sup, _ = doc1(Product{PURLAttr: "pkg:golang/github.com/org/mod@1.0.0"}).Apply([]matcher.Finding{gomod}, Target{}, func(string) {})
	if len(sup) != 0 {
		t.Errorf("a golang namespace matched case-insensitively")
	}
}

func TestApply_UbuntuCodename(t *testing.T) {
	ubuntu := osFinding("CVE-2031-7001", "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.18?arch=amd64&distro=ubuntu-22.04&upstream=openssl",
		"libssl3", "3.0.2-0ubuntu1.18", "openssl", "3.0.2-0ubuntu1.18")
	jammy := Target{UbuntuCodename: "jammy"}
	tests := []struct {
		name   string
		prod   string
		f      matcher.Finding
		target Target
		want   bool
	}{
		{"codename on a jammy target", "pkg:deb/ubuntu/libssl3?distro=jammy", ubuntu, jammy, true},
		{"syft's spelling still matches", "pkg:deb/ubuntu/libssl3?distro=ubuntu-22.04", ubuntu, jammy, true},
		{"other codename", "pkg:deb/ubuntu/libssl3?distro=noble", ubuntu, jammy, false},
		{"codename unknown to the scan", "pkg:deb/ubuntu/libssl3?distro=jammy", ubuntu, Target{}, false},
		{"source statement with the codename", "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.18?arch=source&distro=jammy", ubuntu, jammy, true},
		{"a Debian package does not answer to it",
			"pkg:deb/debian/libssl3?distro=jammy",
			osFinding("CVE-2031-7001", "pkg:deb/debian/libssl3@3.0.17-1~deb12u2?arch=amd64&distro=debian-12.11",
				"libssl3", "3.0.17-1~deb12u2", "openssl", "3.0.17-1~deb12u2"), jammy, false},
	}
	for _, tt := range tests {
		_, sup, _ := doc1(Product{PURLAttr: tt.prod}).Apply([]matcher.Finding{tt.f}, tt.target, func(string) {})
		if got := len(sup) == 1; got != tt.want {
			t.Errorf("%s: suppressed = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestApply_ImageScopeCoversEveryProduct: the Docker Hardened Images shape —
// the package under the image and again as a bare top-level product. Out of
// scope, neither applies; in scope, both do. And the counts say so.
func TestApply_ImageScopeCoversEveryProduct(t *testing.T) {
	f := osFinding("CVE-2031-7001", "pkg:deb/debian/libgssapi-krb5-2@1.20.1-2+deb12u4?arch=amd64&distro=debian-12.11",
		"libgssapi-krb5-2", "1.20.1-2+deb12u4", "krb5", "1.20.1-2+deb12u4")
	d := &Document{Statements: []Statement{
		{
			Vulnerability: Vulnerability{Name: "CVE-2031-7001"},
			Status:        "not_affected", Justification: "inline_mitigations_already_exist",
			Products: []Product{
				{PURLAttr: "pkg:docker/dhi/python@3.13", Subcomponents: []Product{{PURLAttr: "pkg:deb/debian/libgssapi-krb5-2"}}},
				{PURLAttr: "pkg:deb/debian/libgssapi-krb5-2"},
			},
		},
		{Vulnerability: Vulnerability{Name: "CVE-2031-7002"}, Status: "fixed",
			Products: []Product{{PURLAttr: "pkg:deb/debian/zlib1g"}}},
		{Vulnerability: Vulnerability{Name: "CVE-2031-7003"}, Status: "resolved",
			Products: []Product{{PURLAttr: "pkg:deb/debian/zlib1g"}}},
	}}
	repo, tag := TargetFromReference("dhi/python:3.13")
	dhi := Target{Image: true, Repository: repo, Tag: tag}
	repo, tag = TargetFromReference("debian:12")
	stock := Target{Image: true, Repository: repo, Tag: tag}

	for _, tt := range []struct {
		name   string
		target Target
		want   Stats
	}{
		{"the named image", dhi, Stats{Statements: 3, Unmatched: 2, Skipped: 1, OutOfScope: 0, Applied: 1}},
		{"another image", stock, Stats{Statements: 3, Unmatched: 3, Skipped: 1, OutOfScope: 1, Applied: 0}},
		{"not an image", Target{}, Stats{Statements: 3, Unmatched: 3, Skipped: 1, OutOfScope: 1, Applied: 0}},
	} {
		_, sup, st := d.Apply([]matcher.Finding{f}, tt.target, func(string) {})
		if len(sup) != tt.want.Applied {
			t.Errorf("%s: suppressed %d, want %d", tt.name, len(sup), tt.want.Applied)
		}
		if st != tt.want {
			t.Errorf("%s: stats = %+v, want %+v", tt.name, st, tt.want)
		}
	}
}
