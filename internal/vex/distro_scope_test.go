package vex

import (
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

func TestDistroQualifierScope(t *testing.T) {
	for _, tc := range []struct {
		name, typ, namespace, key, local, installed, statement string
		mixed, want                                            bool
	}{
		{"other RHEL point", "rpm", "redhat", "Red Hat:9", "rhel-9.4", "rhel-9.4", "rhel-9.6", false, false},
		{"installed point contradicts local OS", "rpm", "redhat", "Red Hat:9", "rhel-9.4", "rhel-9.6", "rhel-9.6", false, false},
		{"general RHEL statement", "rpm", "redhat", "Red Hat:9", "rhel-9.4", "", "rhel-9", false, true},
		{"SPDX exact installed point", "rpm", "redhat", "Red Hat:9", "", "rhel-9.4", "rhel-9.4", false, true},
		{"repository major alone", "rpm", "redhat", "Red Hat:9", "", "", "rhel-9.4", false, false},
		// Independent review of v0.18.0 (2026-11-12): a statement finer than
		// the installed evidence does not apply. The image path spells Debian's
		// point release from /etc/debian_version (syft's spelling), so the
		// evidence is there; a purl naming the major alone proves no point
		// release, and v0.18.0's acceptance of any point release against it
		// is withdrawn.
		{"installed point release, same statement", "deb", "debian", "Debian:12", "", "debian-12.11", "debian-12.11", false, true},
		{"installed major alone, statement point release", "deb", "debian", "Debian:12", "", "debian-12", "debian-12.11", false, false},
		{"installed major under a broad local OS, statement point release", "deb", "debian", "Debian:12", "debian-12", "debian-12", "debian-12.11", false, false},
		{"installed major under another local point release", "deb", "debian", "Debian:12", "debian-12.10", "debian-12", "debian-12.11", false, false},
		{"installed other point release", "deb", "debian", "Debian:12", "", "debian-12.10", "debian-12.11", false, false},
		// Linux QA of v0.18.1 (2026-11-13): the local OS and the installed
		// purl declare two point releases. Neither point statement applies;
		// only the shared major does.
		{"local point release contradicted by the installed purl, statement the local one", "deb", "debian", "Debian:12", "debian-12.10", "debian-12.11", "debian-12.10", false, false},
		{"local point release contradicted by the installed purl, statement the installed one", "deb", "debian", "Debian:12", "debian-12.10", "debian-12.11", "debian-12.11", false, false},
		{"local point release contradicted by the installed purl, statement the shared major", "deb", "debian", "Debian:12", "debian-12.10", "debian-12.11", "debian-12", false, true},
		{"local point release confirmed by the installed purl, statement that point release", "deb", "debian", "Debian:12", "debian-12.10", "debian-12.10", "debian-12.10", false, true},
		{"local point release, installed purl the major alone, statement that point release", "deb", "debian", "Debian:12", "debian-12.10", "debian-12", "debian-12.10", false, true},
		{"broad local OS refined by the installed point release, statement that point release", "rpm", "redhat", "Red Hat:9", "rhel-9", "rhel-9.4", "rhel-9.4", false, true},
		{"installed point release, statement its major", "deb", "debian", "Debian:12", "", "debian-12.11", "debian-12", false, true},
		{"installed major, statement another major", "deb", "debian", "Debian:12", "", "debian-12", "debian-11.11", false, false},
		{"RHEL installed major alone, statement point release", "rpm", "redhat", "Red Hat:9", "", "rhel-9", "rhel-9.4", false, false},
		{"ambiguous nested points", "rpm", "redhat", "Red Hat:9", "", "rhel-9.4", "rhel-9.4", true, false},
		// PR #321 review: a Debian release keyed with its two-part number
		// (Debian:6.0) is named whole by debian-6.0 and by squeeze, so under
		// a Mixed scope those statements apply as a bookworm one does under
		// Debian:12, while a point of it (6.0.10) does not.
		{"mixed scope, squeeze names the whole key", "deb", "debian", "Debian:6.0", "", "debian-6.0.10", "squeeze", true, true},
		{"mixed scope, debian-6.0 names the whole key", "deb", "debian", "Debian:6.0", "", "debian-6.0.10", "debian-6.0", true, true},
		{"mixed scope, a point of 6.0 does not", "deb", "debian", "Debian:6.0", "", "debian-6.0.10", "debian-6.0.10", true, false},
		{"mixed scope, bookworm names the whole key", "deb", "debian", "Debian:12", "", "debian-12.10", "bookworm", true, true},
		{"patch equality", "apk", "alpine", "Alpine:v3.19", "alpine-3.19.9", "", "alpine-3.19.9", false, true},
		{"different patch", "apk", "alpine", "Alpine:v3.19", "alpine-3.19.9", "alpine-3.19.9", "alpine-3.19.1", false, false},
		{"edge under stable", "apk", "alpine", "Alpine:v3.19", "alpine-3.19", "alpine-edge", "alpine-edge", false, false},
		{"wrong Ubuntu codename", "deb", "ubuntu", "Ubuntu:24.04:LTS", "", "jammy", "jammy", false, false},
		{"matching Ubuntu codename", "deb", "ubuntu", "Ubuntu:24.04:LTS", "", "noble", "noble", false, true},
		{"npm explicit OS", "npm", "", "npm", "alpine-3.19.9", "alpine-3.19", "alpine-3.19", false, true},
		{"npm other OS", "npm", "", "npm", "alpine-3.20", "alpine-3.19", "alpine-3.19", false, false},
		{"rolling repo alone cannot prove release", "apk", "wolfi", "Wolfi", "", "", "wolfi-2026", false, false},
		// Main QA of 672fe7a (2026-11-13): a Debian codename in the purl names
		// the major. It confirms the local OS's point release without
		// contradicting it, proves no point release of its own, and another
		// codename contradicts the local OS.
		{"Debian codename under the local point release, statement that point release", "deb", "debian", "Debian:12", "debian-12.15", "bookworm", "debian-12.15", false, true},
		{"family-prefixed Debian codename under the local point release", "deb", "debian", "Debian:12", "debian-12.15", "debian-bookworm", "debian-12.15", false, true},
		{"Debian codename under the local point release, statement the major", "deb", "debian", "Debian:12", "debian-12.15", "bookworm", "debian-12", false, true},
		{"Debian codename under the major alone, statement a point release", "deb", "debian", "Debian:12", "debian-12", "bookworm", "debian-12.15", false, false},
		{"Debian codename alone, statement a point release", "deb", "debian", "Debian:12", "", "bookworm", "debian-12.15", false, false},
		{"Debian codename under another local point release", "deb", "debian", "Debian:12", "debian-12.14", "bookworm", "debian-12.15", false, false},
		{"another Debian codename under the local point release", "deb", "debian", "Debian:12", "debian-12.15", "bullseye", "debian-12.15", false, false},
		{"Ubuntu codename purl under its local release, statement that release", "deb", "ubuntu", "Ubuntu:22.04:LTS", "ubuntu-22.04", "jammy", "ubuntu-22.04", false, true},
		// The statement spelled as the codename (the SBOM purl copied verbatim)
		// is the major's statement.
		{"statement spelled as the Debian codename applies as the major", "deb", "debian", "Debian:12", "debian-12.15", "bookworm", "bookworm", false, true},
		{"statement spelled as another Debian codename does not", "deb", "debian", "Debian:12", "debian-12.15", "bookworm", "bullseye", false, false},
		{"upper-case numbered release compares as the release", "deb", "debian", "Debian:12", "debian-12.15", "Debian-12", "debian-12.15", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pkgmeta.PURL{Type: tc.typ, Namespace: tc.namespace, Qualifiers: map[string]string{"distro": tc.installed}}
			pkg := pkgmeta.Package{Ecosystem: tc.key, DistroContext: pkgmeta.DistroScope{Qualifier: tc.local, Mixed: tc.mixed}}
			if got := qualifierMatches(p, "distro", tc.statement, "", &pkg); got != tc.want {
				t.Errorf("matched = %v, want %v", got, tc.want)
			}
		})
	}
}
