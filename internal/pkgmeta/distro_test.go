package pkgmeta

import (
	"errors"
	"strings"
	"testing"
)

func TestDistroEcosystem(t *testing.T) {
	tests := []struct {
		name   string
		distro Distro
		want   string
	}{
		{"syft reports a patch release", Distro{ID: "alpine", VersionID: "3.19.9"}, "Alpine:v3.19"},
		{"already major.minor", Distro{ID: "alpine", VersionID: "3.19"}, "Alpine:v3.19"},
		{"two-digit minor", Distro{ID: "alpine", VersionID: "3.20.1"}, "Alpine:v3.20"},
		{"oldest release in the bucket", Distro{ID: "alpine", VersionID: "3.2.0"}, "Alpine:v3.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.distro.Ecosystem()
			if err != nil {
				t.Fatalf("Ecosystem() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Ecosystem() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Each of these would otherwise produce a key that looks valid and matches
// nothing — every package silently clean. The error is the feature.
func TestDistroEcosystem_Unsupported(t *testing.T) {
	tests := []struct {
		name   string
		distro Distro
	}{
		{"edge has no OSV ecosystem", Distro{ID: "alpine", VersionID: "edge"}},
		{"edge as syft spells it", Distro{ID: "alpine", VersionID: "3.21_alpha20240807"}},
		{"no version at all", Distro{ID: "alpine", VersionID: ""}},
		{"major only", Distro{ID: "alpine", VersionID: "3"}},
		{"trailing dot", Distro{ID: "alpine", VersionID: "3."}},
		// "12" has no dot, so it fails on the X.Y check before the ID check is
		// ever reached — the ID guard needs a version that WOULD parse. Without
		// these, deleting `d.ID != "alpine"` leaves the suite green and
		// Distro{ID: "ubuntu", VersionID: "22.04"} yields "Alpine:v22.04".
		{"unsupported distro", Distro{ID: "fedora", VersionID: "40"}},
		{"unsupported distro with a parseable version", Distro{ID: "opensuse-leap", VersionID: "15.6"}},
		// D50. These are RPM distributions whose packages ARE catalogued, and
		// they must still not resolve: Red Hat's errata describe Red Hat's own
		// builds and nobody else's.
		//
		//   - Alma and Rocky are rebuilds but not byte-identical ones (Alma
		//     writes `module_el` where Red Hat writes `module+el`, and adds
		//     `.alma` release suffixes).
		//   - `centos` covers CentOS Linux, which trailed RHEL, and CentOS
		//     Stream, which runs ahead of it — so one key would be wrong in
		//     opposite directions for the two.
		//   - Fedora and Amazon Linux have their own advisory feeds entirely.
		//
		// Each row has a version that WOULD parse, so the ID is what has to
		// reject it. Without that, deleting the case labels leaves the suite
		// green while an almalinux:9 scan is answered with Red Hat's errata.
		{"almalinux is a rebuild, not the same builds", Distro{ID: "almalinux", VersionID: "9.6"}},
		{"rocky likewise", Distro{ID: "rocky", VersionID: "9.6"}},
		{"centos is ahead of RHEL on Stream and behind it on Linux", Distro{ID: "centos", VersionID: "9"}},
		{"amazon linux has its own advisories", Distro{ID: "amzn", VersionID: "2023"}},
		{"rhel with no VERSION_ID", Distro{ID: "rhel", VersionID: ""}},
		{"rhel with a non-numeric version", Distro{ID: "rhel", VersionID: "beta"}},
		// Ubuntu is deliberately here rather than mapped alongside Debian. OSV
		// keys it "Ubuntu:24.04:LTS", and its Pro and FIPS lineages
		// ("Ubuntu:Pro:FIPS-updates:18.04:LTS") describe the SAME release, so a
		// release-only key cannot separate them and would report an ESM-patched
		// system as vulnerable. It needs its own decision, not a second case
		// here.
		{"ubuntu needs its own decision", Distro{ID: "ubuntu", VersionID: "22.04"}},
		// Debian testing and sid ship no VERSION_ID, and OSV publishes no
		// ecosystem for either. A scan of one must say it could not be checked.
		{"debian testing has no VERSION_ID", Distro{ID: "debian", VersionID: ""}},
		{"debian with a non-numeric version", Distro{ID: "debian", VersionID: "trixie"}},
		{"no id", Distro{ID: "", VersionID: "3.19"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.distro.Ecosystem()
			if err == nil {
				t.Fatalf("Ecosystem() = %q, nil error; want an error so the "+
					"packages are skipped rather than reported clean", got)
			}
			if !errors.Is(err, ErrNoEcosystem) {
				t.Errorf("error %v does not wrap ErrNoEcosystem; callers match on it", err)
			}
			if got != "" {
				t.Errorf("Ecosystem() returned %q alongside an error; a caller that "+
					"checks the value first would key on it", got)
			}
			// The message reaches a human in the skip reason, so it has to name
			// what was wrong, not just that something was.
			if !strings.Contains(err.Error(), tt.distro.ID) &&
				!strings.Contains(err.Error(), "distro") {
				t.Errorf("error %q names neither the distro nor the problem", err)
			}
		})
	}
}

// The key must be exactly what the store is written with. A trailing patch
// component or a missing "v" produces a lookup that always misses, which reads
// as a clean scan rather than a failure.
func TestDistroEcosystem_MatchesTheOSVKeyExactly(t *testing.T) {
	got, err := Distro{ID: "alpine", VersionID: "3.19.9"}.Ecosystem()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, ".") != 1 {
		t.Errorf("Ecosystem() = %q; OSV publishes Alpine:vX.Y, not a patch release", got)
	}
	if !strings.HasPrefix(got, "Alpine:v") {
		t.Errorf("Ecosystem() = %q; OSV keys carry the v prefix", got)
	}
}

// Debian's ecosystem key is the bare major, which is what both OSV and
// /etc/os-release use. The dot-suffixed point release is the shape a real
// bookworm image ships in VERSION_ID on some rebuilds, and it must not become
// part of the key: OSV has no "Debian:12.5".
func TestDistroEcosystem_Debian(t *testing.T) {
	for _, tc := range []struct {
		versionID string
		want      string
	}{
		{"11", "Debian:11"},
		{"12", "Debian:12"},
		{"13", "Debian:13"},
		{"12.5", "Debian:12"},
	} {
		got, err := Distro{ID: "debian", VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("VERSION_ID=%q: %v", tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("VERSION_ID=%q -> %q, want %q", tc.versionID, got, tc.want)
		}
	}
	// And Alpine is untouched: its key keeps the "v" and the minor, because its
	// releases are X.Y and OSV spells them that way.
	if got, err := (Distro{ID: "alpine", VersionID: "3.19"}).Ecosystem(); err != nil || got != "Alpine:v3.19" {
		t.Errorf("alpine 3.19 -> %q, %v; want Alpine:v3.19 — the two schemes must not converge", got, err)
	}
}

// D47: the Red Hat key is the mainline MAJOR, and the minor is dropped.
// /etc/os-release reports "9.8"; the provider writes "Red Hat:9" from the
// mainline CPE's major, because the support channel that distinguishes 9.8's
// EUS errata from mainline's is a subscription attribute with no filesystem
// representation.
func TestDistroEcosystem_RedHat(t *testing.T) {
	for _, tc := range []struct {
		versionID string
		want      string
	}{
		{"9", "Red Hat:9"},
		{"9.8", "Red Hat:9"},
		{"8.10", "Red Hat:8"},
		{"10.2", "Red Hat:10"},
		{"7", "Red Hat:7"},
	} {
		got, err := Distro{ID: "rhel", VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("VERSION_ID=%q: %v", tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("VERSION_ID=%q -> %q, want %q", tc.versionID, got, tc.want)
		}
	}
	// The three schemes must not converge. Each keeps its own shape, and a
	// change that collapsed them would make one distro's advisories reachable
	// under another's key.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"debian", "12", "Debian:12"},
		{"rhel", "9.8", "Red Hat:9"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
}
