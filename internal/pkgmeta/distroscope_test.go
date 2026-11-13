package pkgmeta

import "testing"

// Main QA of 672fe7a (2026-11-13): the scope a listing starts with carries a
// contradiction between its local OS and its own purl, so a duplicate
// listing merged onto it in either position cannot lose it.
func TestDistroScope_ForInstallation(t *testing.T) {
	for _, tc := range []struct {
		name, local, installed string
		want                   DistroScope
	}{
		{"no local OS: the purl's release", "", "debian-12.15", DistroScope{Qualifier: "debian-12.15"}},
		{"no purl release: the local OS", "debian-12.15", "", DistroScope{Qualifier: "debian-12.15"}},
		{"purl refines a broad local OS", "rhel-9", "rhel-9.4", DistroScope{Qualifier: "rhel-9.4"}},
		{"purl agrees with the local point release", "debian-12.15", "debian-12.15", DistroScope{Qualifier: "debian-12.15"}},
		{"purl states less than the local OS: the local OS stands", "debian-12.10", "debian-12", DistroScope{Qualifier: "debian-12.10"}},
		{"purl states another point release: mixed", "debian-12.15", "debian-12.14", DistroScope{Mixed: true}},
		{"purl states another major: mixed", "debian-12.15", "debian-11.11", DistroScope{Mixed: true}},
		{"purl states another family: mixed", "debian-12.15", "ubuntu-22.04", DistroScope{Mixed: true}},
		{"already mixed stays mixed", "", "debian-12.15", DistroScope{Mixed: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := DistroScope{Qualifier: tc.local}
			if tc.name == "already mixed stays mixed" {
				s = DistroScope{Mixed: true}
			}
			if got := s.ForInstallation(tc.installed); got != tc.want {
				t.Errorf("ForInstallation(%q) on %+v = %+v, want %+v", tc.installed, s, got, tc.want)
			}
		})
	}
}

// Merge of the two listings' scopes is the same in both orders, and a Mixed
// side makes the whole Mixed.
func TestDistroScope_MergeIsSymmetric(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b DistroScope
		want DistroScope
	}{
		{"agreeing", DistroScope{Qualifier: "debian-12.15"}, DistroScope{Qualifier: "debian-12.15"}, DistroScope{Qualifier: "debian-12.15"}},
		{"one finer", DistroScope{Qualifier: "debian-12"}, DistroScope{Qualifier: "debian-12.15"}, DistroScope{Qualifier: "debian-12.15"}},
		{"two point releases", DistroScope{Qualifier: "debian-12.15"}, DistroScope{Qualifier: "debian-12.14"}, DistroScope{Mixed: true}},
		{"one mixed", DistroScope{Mixed: true}, DistroScope{Qualifier: "debian-12.15"}, DistroScope{Mixed: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Merge(tc.b); got != tc.want {
				t.Errorf("a.Merge(b) = %+v, want %+v", got, tc.want)
			}
			if got := tc.b.Merge(tc.a); got != tc.want {
				t.Errorf("b.Merge(a) = %+v, want %+v", got, tc.want)
			}
		})
	}
}
