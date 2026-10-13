package pkgmeta

import "testing"

// TestOSPackagePURL_MatchesMeasuredSyft holds OSPackagePURL to syft
// v1.50.0's own output: every want below is copied from a measured syft
// CycloneDX document of a real image (2026-10-13), and each package's fields
// are what assay's catalogers read from that image's database. One row per
// distro row of the namespace table, plus the shapes that differ by type.
// Run against all 2,856 OS packages of the 31 measured images, the function
// reproduced 2,805 byte for byte; the rest were CleanStart (deliberately no
// purl, 49) and two rpm packages whose rpmdb epoch is an explicit 0, which
// syft writes as epoch=0 and the rpmdb cataloger folds away.
func TestOSPackagePURL_MatchesMeasuredSyft(t *testing.T) {
	src := func(name, version string) *SourcePackage { return &SourcePackage{Name: name, Version: version} }
	tests := []struct {
		name   string
		distro Distro
		pkg    Package
		want   string
	}{
		{"alpine: origin differs -> upstream", Distro{ID: "alpine", VersionID: "3.19.9"},
			Package{Name: "busybox-binsh", Version: "1.36.1-r20", Type: "apk", Arch: "x86_64", Source: src("busybox", "")},
			"pkg:apk/alpine/busybox-binsh@1.36.1-r20?arch=x86_64&distro=alpine-3.19.9&upstream=busybox"},
		{"alpine: origin equals name -> no upstream", Distro{ID: "alpine", VersionID: "3.19.9"},
			Package{Name: "busybox", Version: "1.36.1-r20", Type: "apk", Arch: "x86_64", Source: src("busybox", "")},
			"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19.9"},
		{"wolfi", Distro{ID: "wolfi", VersionID: "20230201"},
			Package{Name: "busybox", Version: "1.38.0-r1", Type: "apk", Arch: "x86_64", Source: src("busybox", "")},
			"pkg:apk/wolfi/busybox@1.38.0-r1?arch=x86_64&distro=wolfi-20230201"},
		{"minimos", Distro{ID: "minimos", VersionID: "20241031"},
			Package{Name: "glibc-locale-posix", Version: "2.44-r0", Type: "apk", Arch: "x86_64", Source: src("glibc", "")},
			"pkg:apk/minimos/glibc-locale-posix@2.44-r0?arch=x86_64&distro=minimos-20241031&upstream=glibc"},
		{"alpaquita stream", Distro{ID: "alpaquita", VersionID: "stream"},
			Package{Name: "busybox-binsh", Version: "1.38.0-r2", Type: "apk", Arch: "x86_64", Source: src("busybox", "")},
			"pkg:apk/alpaquita/busybox-binsh@1.38.0-r2?arch=x86_64&distro=alpaquita-stream&upstream=busybox"},
		{"debian: epoch inline and escaped, source name differs", Distro{ID: "debian", VersionID: "12.11"},
			Package{Name: "zlib1g", Version: "1:1.2.13.dfsg-1", Type: "deb", Arch: "amd64", Source: src("zlib", "1:1.2.13.dfsg-1")},
			"pkg:deb/debian/zlib1g@1%3A1.2.13.dfsg-1?arch=amd64&distro=debian-12.11&upstream=zlib"},
		{"debian: binNMU -> upstream name@version even with the same name", Distro{ID: "debian", VersionID: "12.15"},
			Package{Name: "bash", Version: "5.2.15-2+b13", Type: "deb", Arch: "amd64", Source: src("bash", "5.2.15-2")},
			"pkg:deb/debian/bash@5.2.15-2%2Bb13?arch=amd64&distro=debian-12.15&upstream=bash%405.2.15-2"},
		{"debian: name and version both match -> no upstream", Distro{ID: "debian", VersionID: "11.11"},
			Package{Name: "bash", Version: "5.1-2+deb11u1", Type: "deb", Arch: "amd64", Source: src("bash", "5.1-2+deb11u1")},
			"pkg:deb/debian/bash@5.1-2%2Bdeb11u1?arch=amd64&distro=debian-11.11"},
		{"ubuntu: epoch on the binary only", Distro{ID: "ubuntu", VersionID: "22.04", VersionCodename: "jammy"},
			Package{Name: "bsdutils", Version: "1:2.37.2-4ubuntu3.5", Type: "deb", Arch: "amd64", Source: src("util-linux", "2.37.2-4ubuntu3.5")},
			"pkg:deb/ubuntu/bsdutils@1%3A2.37.2-4ubuntu3.5?arch=amd64&distro=ubuntu-22.04&upstream=util-linux%402.37.2-4ubuntu3.5"},
		{"ubuntu: source name differs", Distro{ID: "ubuntu", VersionID: "22.04"},
			Package{Name: "libssl3", Version: "3.0.2-0ubuntu1.26", Type: "deb", Arch: "amd64", Source: src("openssl", "3.0.2-0ubuntu1.26")},
			"pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.26?arch=amd64&distro=ubuntu-22.04&upstream=openssl"},
		{"rhel: namespace redhat, epoch qualifier, SRPM upstream", Distro{ID: "rhel", VersionID: "8.10"},
			Package{Name: "openssl-libs", Version: "1:1.1.1k-14.el8_6", Type: "rpm", Arch: "x86_64", Upstream: "openssl-1.1.1k-14.el8_6.src.rpm"},
			"pkg:rpm/redhat/openssl-libs@1.1.1k-14.el8_6?arch=x86_64&distro=rhel-8.10&epoch=1&upstream=openssl-1.1.1k-14.el8_6.src.rpm"},
		{"rhel: no epoch", Distro{ID: "rhel", VersionID: "8.10"},
			Package{Name: "curl", Version: "7.61.1-34.el8_10.3", Type: "rpm", Arch: "x86_64", Upstream: "curl-7.61.1-34.el8_10.3.src.rpm"},
			"pkg:rpm/redhat/curl@7.61.1-34.el8_10.3?arch=x86_64&distro=rhel-8.10&upstream=curl-7.61.1-34.el8_10.3.src.rpm"},
		{"rpm: an explicit 0 epoch in the version is not written", Distro{ID: "rhel", VersionID: "8.10"},
			Package{Name: "curl", Version: "0:7.61.1-34.el8_10.3", Type: "rpm", Arch: "x86_64", Upstream: "curl-7.61.1-34.el8_10.3.src.rpm"},
			"pkg:rpm/redhat/curl@7.61.1-34.el8_10.3?arch=x86_64&distro=rhel-8.10&upstream=curl-7.61.1-34.el8_10.3.src.rpm"},
		{"hummingbird: namespace redhat, distro the os-release ID", Distro{ID: "hummingbird", VersionID: "20251124"},
			Package{Name: "audit-libs", Version: "4.2.1-2.hum1", Type: "rpm", Arch: "x86_64", Upstream: "audit-4.2.1-2.hum1.src.rpm"},
			"pkg:rpm/redhat/audit-libs@4.2.1-2.hum1?arch=x86_64&distro=hummingbird-20251124&upstream=audit-4.2.1-2.hum1.src.rpm"},
		{"rocky", Distro{ID: "rocky", VersionID: "9.3"},
			Package{Name: "findutils", Version: "1:4.8.0-6.el9", Type: "rpm", Arch: "x86_64", Upstream: "findutils-4.8.0-6.el9.src.rpm"},
			"pkg:rpm/rocky/findutils@4.8.0-6.el9?arch=x86_64&distro=rocky-9.3&epoch=1&upstream=findutils-4.8.0-6.el9.src.rpm"},
		{"almalinux", Distro{ID: "almalinux", VersionID: "9.8"},
			Package{Name: "bash", Version: "5.1.8-9.el9", Type: "rpm", Arch: "x86_64", Upstream: "bash-5.1.8-9.el9.src.rpm"},
			"pkg:rpm/almalinux/bash@5.1.8-9.el9?arch=x86_64&distro=almalinux-9.8&upstream=bash-5.1.8-9.el9.src.rpm"},
		{"ol", Distro{ID: "ol", VersionID: "9.8"},
			Package{Name: "alternatives", Version: "1.24-2.0.1.el9", Type: "rpm", Arch: "x86_64", Upstream: "chkconfig-1.24-2.0.1.el9.src.rpm"},
			"pkg:rpm/ol/alternatives@1.24-2.0.1.el9?arch=x86_64&distro=ol-9.8&upstream=chkconfig-1.24-2.0.1.el9.src.rpm"},
		{"amzn", Distro{ID: "amzn", VersionID: "2023"},
			Package{Name: "bash", Version: "5.2.15-1.amzn2023.0.2", Type: "rpm", Arch: "x86_64", Upstream: "bash-5.2.15-1.amzn2023.0.2.src.rpm"},
			"pkg:rpm/amzn/bash@5.2.15-1.amzn2023.0.2?arch=x86_64&distro=amzn-2023&upstream=bash-5.2.15-1.amzn2023.0.2.src.rpm"},
		{"fedora", Distro{ID: "fedora", VersionID: "44"},
			Package{Name: "bash", Version: "5.3.9-3.fc44", Type: "rpm", Arch: "x86_64", Upstream: "bash-5.3.9-3.fc44.src.rpm"},
			"pkg:rpm/fedora/bash@5.3.9-3.fc44?arch=x86_64&distro=fedora-44&upstream=bash-5.3.9-3.fc44.src.rpm"},
		{"sles", Distro{ID: "sles", VersionID: "15.6"},
			Package{Name: "libopenssl3", Version: "3.1.4-150600.5.39.1", Type: "rpm", Arch: "x86_64", Upstream: "openssl-3-3.1.4-150600.5.39.1.src.rpm"},
			"pkg:rpm/sles/libopenssl3@3.1.4-150600.5.39.1?arch=x86_64&distro=sles-15.6&upstream=openssl-3-3.1.4-150600.5.39.1.src.rpm"},
		{"opensuse-leap: namespace opensuse, '+' escaped in version and upstream", Distro{ID: "opensuse-leap", VersionID: "15.6"},
			Package{Name: "aaa_base", Version: "84.87+git20180409.04c9dae-150300.10.28.2", Type: "rpm", Arch: "x86_64",
				Upstream: "aaa_base-84.87+git20180409.04c9dae-150300.10.28.2.src.rpm"},
			"pkg:rpm/opensuse/aaa_base@84.87%2Bgit20180409.04c9dae-150300.10.28.2?arch=x86_64&distro=opensuse-leap-15.6&upstream=aaa_base-84.87%2Bgit20180409.04c9dae-150300.10.28.2.src.rpm"},
		{"opensuse-tumbleweed", Distro{ID: "opensuse-tumbleweed", VersionID: "20261011"},
			Package{Name: "bash", Version: "5.3.20-9.1", Type: "rpm", Arch: "x86_64", Upstream: "bash-5.3.20-9.1.src.rpm"},
			"pkg:rpm/opensuse/bash@5.3.20-9.1?arch=x86_64&distro=opensuse-tumbleweed-20261011&upstream=bash-5.3.20-9.1.src.rpm"},
		{"mariner", Distro{ID: "mariner", VersionID: "2.0"},
			Package{Name: "bash", Version: "5.1.8-1.cm2", Type: "rpm", Arch: "x86_64", Upstream: "bash-5.1.8-1.cm2.src.rpm"},
			"pkg:rpm/mariner/bash@5.1.8-1.cm2?arch=x86_64&distro=mariner-2.0&upstream=bash-5.1.8-1.cm2.src.rpm"},
		{"azurelinux", Distro{ID: "azurelinux", VersionID: "3.0"},
			Package{Name: "bash", Version: "5.2.15-2.azl3", Type: "rpm", Arch: "x86_64", Upstream: "bash-5.2.15-2.azl3.src.rpm"},
			"pkg:rpm/azurelinux/bash@5.2.15-2.azl3?arch=x86_64&distro=azurelinux-3.0&upstream=bash-5.2.15-2.azl3.src.rpm"},
		{"photon", Distro{ID: "photon", VersionID: "5.0"},
			Package{Name: "bash", Version: "5.3-1.ph5", Type: "rpm", Arch: "x86_64", Upstream: "bash-5.3-1.ph5.src.rpm"},
			"pkg:rpm/photon/bash@5.3-1.ph5?arch=x86_64&distro=photon-5.0&upstream=bash-5.3-1.ph5.src.rpm"},
		{"arch: upstream always, even equal to the name", Distro{ID: "arch", VersionID: "20260823.0.578598"},
			Package{Name: "bash", Version: "5.3.15-1", Type: "alpm", Arch: "x86_64", Upstream: "bash"},
			"pkg:alpm/arch/bash@5.3.15-1?arch=x86_64&distro=arch-20260823.0.578598&upstream=bash"},
		{"arch: split package", Distro{ID: "arch", VersionID: "20260823.0.578598"},
			Package{Name: "libelf", Version: "0.196-1", Type: "alpm", Arch: "x86_64", Upstream: "elfutils", Source: src("elfutils", "")},
			"pkg:alpm/arch/libelf@0.196-1?arch=x86_64&distro=arch-20260823.0.578598&upstream=elfutils"},

		// No purl: no measured row, no release, no package type.
		{"chainguard: no measured row", Distro{ID: "chainguard", VersionID: "20230214"},
			Package{Name: "busybox", Version: "1.38.0-r1", Type: "apk", Arch: "x86_64"}, ""},
		{"cleanstart: syft calls it busybox, not aliased", Distro{ID: "cleanstart"},
			Package{Name: "busybox", Version: "1.38.0-r0", Type: "apk", Arch: "x86_64"}, ""},
		{"echo: no measured row", Distro{ID: "echo", VersionID: "1"},
			Package{Name: "bash", Version: "5.2-r0", Type: "apk", Arch: "x86_64"}, ""},
		{"debian sid: no VERSION_ID", Distro{ID: "debian"},
			Package{Name: "bash", Version: "5.2.37-1", Type: "deb", Arch: "amd64", Source: src("bash", "5.2.37-1")}, ""},
		{"a type that is not an OS package", Distro{ID: "alpine", VersionID: "3.19.9"},
			Package{Name: "postgresql", Version: "18.6.0-3", Type: "bitnami"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.distro
			if got := OSPackagePURL(&d, tt.pkg); got != tt.want {
				t.Errorf("OSPackagePURL =\n  %s\nwant\n  %s", got, tt.want)
			}
		})
	}
	if got := OSPackagePURL(nil, Package{Name: "x", Version: "1", Type: "apk"}); got != "" {
		t.Errorf("OSPackagePURL(nil distro) = %q, want none", got)
	}
}

// TestOSPackagePURL_RoundTripsThroughResolveDistroPURL: a generated purl, read
// back the way an SBOM's purl is read with no document-level distro (D83/
// D84), keys to the same ecosystem with the same comparable version and
// source name the image path gave the package. A purl that read back as a
// different package would make a scan of the image and a scan of its own
// SBOM disagree.
func TestOSPackagePURL_RoundTripsThroughResolveDistroPURL(t *testing.T) {
	tests := []struct {
		distro Distro
		pkg    Package
	}{
		{Distro{ID: "alpine", VersionID: "3.19.9"}, Package{Name: "libssl3", Version: "3.1.4-r5", Type: "apk", Arch: "x86_64",
			Source: &SourcePackage{Name: "openssl"}}},
		{Distro{ID: "alpaquita", VersionID: "stream"}, Package{Name: "musl", Version: "1.2.5-r3", Type: "apk", Arch: "x86_64",
			Source: &SourcePackage{Name: "musl"}}},
		{Distro{ID: "debian", VersionID: "12"}, Package{Name: "zlib1g", Version: "1:1.2.13.dfsg-1", Type: "deb", Arch: "amd64",
			Source: &SourcePackage{Name: "zlib", Version: "1:1.2.13.dfsg-1"}}},
		{Distro{ID: "debian", VersionID: "12"}, Package{Name: "bash", Version: "5.2.15-2+b13", Type: "deb", Arch: "amd64",
			Source: &SourcePackage{Name: "bash", Version: "5.2.15-2"}}},
		{Distro{ID: "ubuntu", VersionID: "22.04", PrettyName: "Ubuntu 22.04.5 LTS"}, Package{Name: "libssl3", Version: "3.0.2-0ubuntu1.26",
			Type: "deb", Arch: "amd64", Source: &SourcePackage{Name: "openssl", Version: "3.0.2-0ubuntu1.26"}}},
		{Distro{ID: "rocky", VersionID: "9.3"}, Package{Name: "findutils", Version: "1:4.8.0-6.el9", Type: "rpm", Arch: "x86_64",
			Upstream: "findutils-4.8.0-6.el9.src.rpm", Source: &SourcePackage{Name: "findutils"}}},
		{Distro{ID: "rhel", VersionID: "9.8"}, Package{Name: "openssl-libs", Version: "1:3.5.5-2.el9_8", Type: "rpm", Arch: "x86_64",
			Upstream: "openssl-3.5.5-2.el9_8.src.rpm", Source: &SourcePackage{Name: "openssl"}}},
		{Distro{ID: "hummingbird", VersionID: "20251124"}, Package{Name: "audit-libs", Version: "4.2.1-2.hum1", Type: "rpm", Arch: "x86_64",
			Upstream: "audit-4.2.1-2.hum1.src.rpm", Source: &SourcePackage{Name: "audit"}}},
		{Distro{ID: "opensuse-leap", VersionID: "15.6"}, Package{Name: "bash", Version: "4.4-150400.27.6.1", Type: "rpm", Arch: "x86_64",
			Upstream: "bash-4.4-150400.27.6.1.src.rpm", Source: &SourcePackage{Name: "bash"}}},
		{Distro{ID: "arch", VersionID: "20260823.0.578598"}, Package{Name: "libelf", Version: "0.196-1", Type: "alpm", Arch: "x86_64",
			Upstream: "elfutils", Source: &SourcePackage{Name: "elfutils"}}},
	}
	for _, tt := range tests {
		d := tt.distro
		s := OSPackagePURL(&d, tt.pkg)
		if s == "" {
			t.Errorf("%s/%s: no purl", d.ID, tt.pkg.Name)
			continue
		}
		p, err := ParsePURL(s)
		if err != nil {
			t.Errorf("ParsePURL(%s): %v", s, err)
			continue
		}
		res := ResolveDistroPURL(p, "", "", false)
		wantEco, err := d.Ecosystem()
		if err != nil {
			t.Fatalf("%s: %v", d.ID, err)
		}
		if res.Skip || res.Ecosystem != wantEco || res.Version != tt.pkg.Version {
			t.Errorf("%s read back as ecosystem %q version %q (skip %v), want %q %q",
				s, res.Ecosystem, res.Version, res.Skip, wantEco, tt.pkg.Version)
		}
		// A source named like the binary is no lookup of its own (the
		// matcher queries the name once), so an absent upstream reads back
		// as the same package.
		gotSrc := p.Name
		if res.Source != nil {
			gotSrc = res.Source.Name
		}
		if p.Name != tt.pkg.Name || gotSrc != tt.pkg.Source.Name {
			t.Errorf("%s read back as name %q source %q, want %q source %q", s, p.Name, gotSrc, tt.pkg.Name, tt.pkg.Source.Name)
		}
	}
}

// SourceRPMVersion is the version-release half of a SOURCERPM file name, the
// part SourceRPMName strips; D121 compares a source statement against it.
func TestSourceRPMVersion(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"lvm2-2.03.14-15.el8_10.src.rpm", "2.03.14-15.el8_10"},
		{"perl-5.26.3-422.el8.src.rpm", "5.26.3-422.el8"},
		{"python3.11-3.11.9-1.el9.src.rpm", "3.11.9-1.el9"},
		{"lvm2-2.03.14-15.el8_10", ""},
		{"lvm2.src.rpm", ""},
		{"", ""},
	} {
		if got := SourceRPMVersion(tt.in); got != tt.want {
			t.Errorf("SourceRPMVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
