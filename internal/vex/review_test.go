package vex

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/matcher"
)

// TestApply_UnreadImageProductStillScopes: the Docker Hardened Images shape
// again, but with an image product assay cannot read — a malformed pkg:docker
// purl, or an image named through a transport prefix. Not reading the image
// must not unscope the statement: its bare top-level duplicate would then
// apply to every image, the false suppression D121 exists to stop.
func TestApply_UnreadImageProductStillScopes(t *testing.T) {
	f := osFinding("CVE-2031-7001", "pkg:deb/debian/libgssapi-krb5-2@1.20.1-2+deb12u4?arch=amd64&distro=debian-12.11",
		"libgssapi-krb5-2", "1.20.1-2+deb12u4", "krb5", "1.20.1-2+deb12u4")
	repo, tag := TargetFromReference("debian:12")
	stock := Target{Image: true, Repository: repo, Tag: tag}
	for _, tt := range []struct {
		name     string
		image    Product
		wantWarn string
	}{
		{"malformed pkg:docker purl", Product{PURLAttr: "pkg:docker/dhi/python@3.13?repository_url=%zz"}, "names an image"},
		{"malformed pkg:oci purl, upper-case type", Product{ID: "PKG:OCI/python@sha256:1?repository_url=%zz"}, ""},
		{"docker:// reference", Product{ID: "docker://dhi/python:3.13"}, ""},
		{"docker-archive: file", Product{ID: "docker-archive:/srv/dhi-python.tar"}, ""},
		{"oci-dir: layout", Product{ID: "oci-dir:./dhi-python"}, ""},
		// D124: an image reference whose digest, tag or repository does not
		// parse was read as a plain identifier, which unscoped the statement
		// -- the 2026-10-20 external review's exit 1 -> 0 on another image.
		{"truncated digest", Product{ID: "dhi/python@sha256:truncated"}, `"dhi/python@sha256:truncated" looks like an image reference`},
		{"bad digest algorithm", Product{ID: "dhi/python@sha512:bad"}, `"dhi/python@sha512:bad" looks like an image reference`},
		{"empty digest", Product{ID: "dhi/python@sha256:"}, `"dhi/python@sha256:" looks like an image reference`},
		{"tag that does not parse", Product{ID: "dhi/python:3.13!"}, `"dhi/python:3.13!" looks like an image reference`},
		{"repository that does not parse", Product{ID: "Dhi/Python"}, `"Dhi/Python" looks like an image reference`},
		{"transport reference that does not parse", Product{ID: "docker://Dhi/Python:3.13"}, `"docker://Dhi/Python:3.13" looks like an image reference`},
		{"transport followed by no reference", Product{ID: "docker://not a ref"}, `"docker://not a ref" looks like an image reference`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			img := tt.image
			img.Subcomponents = []Product{{PURLAttr: "pkg:deb/debian/libgssapi-krb5-2"}}
			d := &Document{Statements: []Statement{{
				Vulnerability: Vulnerability{Name: "CVE-2031-7001"},
				Status:        "not_affected", Justification: "inline_mitigations_already_exist",
				Products: []Product{img, {PURLAttr: "pkg:deb/debian/libgssapi-krb5-2"}},
			}}}
			var warnings []string
			_, sup, st := d.Apply([]matcher.Finding{f}, stock, func(m string) { warnings = append(warnings, m) })
			if len(sup) != 0 {
				t.Errorf("suppressed %v on a stock image", suppressedNames(sup))
			}
			if st.OutOfScope != 1 {
				t.Errorf("stats = %+v, want the statement out of scope", st)
			}
			if tt.wantWarn != "" && !strings.Contains(strings.Join(warnings, "\n"), tt.wantWarn) {
				t.Errorf("warnings = %q, want one saying the product %s", warnings, tt.wantWarn)
			}
		})
	}
}

// TestApply_VersionedIdentifierIsNotAnImage: D124 must not read every
// "name@version" as a misspelled image. "@" followed by anything but an
// "algo:hex" digest is never an image reference — it is how npm, Go and
// Python name a package at a version — so a statement that groups its
// subcomponents under such an identifier stays unscoped and applies on every
// target, with no warning. The first D124 cut scoped these to no target and
// lost the suppression (2026-10-20 review of #167).
func TestApply_VersionedIdentifierIsNotAnImage(t *testing.T) {
	f := osFinding("CVE-2031-7001", "pkg:deb/debian/libgssapi-krb5-2@1.20.1-2+deb12u4?arch=amd64&distro=debian-12.11",
		"libgssapi-krb5-2", "1.20.1-2+deb12u4", "krb5", "1.20.1-2+deb12u4")
	repo, tag := TargetFromReference("debian:12")
	stock := Target{Image: true, Repository: repo, Tag: tag}
	for _, id := range []string{
		"lodash@4.17.21",
		"github.com/Azure/azure-sdk-for-go@v68.0.0",
		"dhi/python@latest",
	} {
		t.Run(id, func(t *testing.T) {
			group := Product{ID: id, Subcomponents: []Product{{PURLAttr: "pkg:deb/debian/libgssapi-krb5-2"}}}
			d := &Document{Statements: []Statement{{
				Vulnerability: Vulnerability{Name: "CVE-2031-7001"},
				Status:        "not_affected", Justification: "inline_mitigations_already_exist",
				Products: []Product{group},
			}}}
			var warnings []string
			_, sup, st := d.Apply([]matcher.Finding{f}, stock, func(m string) { warnings = append(warnings, m) })
			if len(sup) != 1 {
				t.Errorf("suppressed %v, want the subcomponent's finding", suppressedNames(sup))
			}
			if st.OutOfScope != 0 {
				t.Errorf("stats = %+v, want the statement in scope", st)
			}
			for _, w := range warnings {
				if strings.Contains(w, "image") {
					t.Errorf("warned %q, want no warning: the product is not an image", w)
				}
			}
		})
	}
}

// A reference behind a transport prefix still identifies its image: the same
// docker:// statement that is out of scope on a stock image applies on the
// image it names.
func TestImageFromReference_TransportPrefix(t *testing.T) {
	for _, tt := range []struct {
		id   string
		want imageRef
	}{
		{"docker://dhi/python:3.13", imageRef{repository: "index.docker.io/dhi/python", tag: "3.13"}},
		{"oci://ghcr.io/org/app@" + testDigest, imageRef{repository: "ghcr.io/org/app", digest: testDigest}},
		{"docker-archive:/srv/app.tar", imageRef{}},
		{"oci-dir:./layout", imageRef{}},
	} {
		lp, ok := buildLiveProduct(Product{ID: tt.id}, func(m string) { t.Errorf("%s: warned %s", tt.id, m) })
		if !ok || lp.image == nil {
			t.Errorf("%s: not an image product", tt.id)
			continue
		}
		if *lp.image != tt.want {
			t.Errorf("%s: identifies %+v, want %+v", tt.id, *lp.image, tt.want)
		}
	}
}

// D121 point 3 on rpm, where a binary's version is not its source's:
// device-mapper-libs is built from lvm2 but carries its own version. Red
// Hat's arch=src statement names lvm2 at the SRPM's version-release, which
// SOURCERPM carries (Package.Upstream, or the purl's upstream qualifier);
// the epoch, which the SRPM file name does not, is compared with the
// binary's.
func TestApply_RPMSourceVersionIsTheSRPMs(t *testing.T) {
	const purl = "pkg:rpm/redhat/device-mapper-libs@1.02.181-15.el8_10?arch=x86_64&distro=rhel-8.10&epoch=8" +
		"&upstream=lvm2-2.03.14-15.el8_10.src.rpm"
	// Each finding carries the binary's epoch in one place only, so each
	// place is held: an SBOM's package has it as the purl's qualifier, the
	// rpmdb cataloger's folded into the version.
	viaPURL := osFinding("CVE-2031-7001", purl, "device-mapper-libs", "1.02.181-15.el8_10", "lvm2", "1.02.181-15.el8_10")
	viaUpstream := osFinding("CVE-2031-7001", "pkg:rpm/redhat/device-mapper-libs@1.02.181-15.el8_10?arch=x86_64&distro=rhel-8.10",
		"device-mapper-libs", "8:1.02.181-15.el8_10", "lvm2", "8:1.02.181-15.el8_10")
	viaUpstream.Package.Upstream = "lvm2-2.03.14-15.el8_10.src.rpm"
	for _, tt := range []struct {
		name string
		prod string
		want bool
	}{
		{"the SRPM's version and epoch", "pkg:rpm/redhat/lvm2@2.03.14-15.el8_10?arch=src&epoch=8", true},
		{"version-less", "pkg:rpm/redhat/lvm2?arch=src", true},
		{"the binary's version is not the source's", "pkg:rpm/redhat/lvm2@1.02.181-15.el8_10?arch=src&epoch=8", false},
		{"another SRPM release", "pkg:rpm/redhat/lvm2@2.03.14-14.el8_10?arch=src&epoch=8", false},
		{"no epoch where the binary has 8", "pkg:rpm/redhat/lvm2@2.03.14-15.el8_10?arch=src", false},
		{"another epoch", "pkg:rpm/redhat/lvm2@2.03.14-15.el8_10?arch=src&epoch=7", false},
	} {
		for _, f := range []struct {
			via string
			f   matcher.Finding
		}{{"purl upstream", viaPURL}, {"Package.Upstream", viaUpstream}} {
			_, sup, _ := doc1(Product{PURLAttr: tt.prod}).Apply([]matcher.Finding{f.f}, Target{}, func(string) {})
			if got := len(sup) == 1; got != tt.want {
				t.Errorf("%s (%s): suppressed = %v, want %v", tt.name, f.via, got, tt.want)
			}
		}
	}
}
