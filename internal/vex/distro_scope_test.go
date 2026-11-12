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
		{"ambiguous nested points", "rpm", "redhat", "Red Hat:9", "", "rhel-9.4", "rhel-9.4", true, false},
		{"patch equality", "apk", "alpine", "Alpine:v3.19", "alpine-3.19.9", "", "alpine-3.19.9", false, true},
		{"different patch", "apk", "alpine", "Alpine:v3.19", "alpine-3.19.9", "alpine-3.19.9", "alpine-3.19.1", false, false},
		{"edge under stable", "apk", "alpine", "Alpine:v3.19", "alpine-3.19", "alpine-edge", "alpine-edge", false, false},
		{"wrong Ubuntu codename", "deb", "ubuntu", "Ubuntu:24.04:LTS", "", "jammy", "jammy", false, false},
		{"matching Ubuntu codename", "deb", "ubuntu", "Ubuntu:24.04:LTS", "", "noble", "noble", false, true},
		{"npm explicit OS", "npm", "", "npm", "alpine-3.19.9", "alpine-3.19", "alpine-3.19", false, true},
		{"npm other OS", "npm", "", "npm", "alpine-3.20", "alpine-3.19", "alpine-3.19", false, false},
		{"rolling repo alone cannot prove release", "apk", "wolfi", "Wolfi", "", "", "wolfi-2026", false, false},
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
