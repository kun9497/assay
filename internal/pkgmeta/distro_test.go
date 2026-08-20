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
		//   - `centos` covers CentOS Linux, which trailed RHEL, and CentOS
		//     Stream, which runs ahead of it — so one key would be wrong in
		//     opposite directions for the two.
		//   - Fedora has its own advisory feed entirely (FEDORA-*).
		//
		// Rocky left this list under D71, AlmaLinux under D72, and Amazon
		// Linux's AL2/AL2023 under D73 — see TestDistroEcosystem_Rocky,
		// TestDistroEcosystem_Alma and TestDistroEcosystem_Amazon below —
		// because each ingests from its own feed rather than Red Hat's
		// errata, so the byte-identity hazard these rows guard against
		// (module builds spelled `module_el`/`module+el`, `.alma` release
		// suffixes) never applied to matching either against ITS OWN data.
		// AL1 and AL2022 stay on this list below, alongside amzn — see
		// TestDistroEcosystem_Unsupported's "amzn" rows further down and
		// TestDistroEcosystem_Amazon's own not-evaluated cases.
		//
		// Each row has a version that WOULD parse, so the ID is what has to
		// reject it. Without that, deleting the case labels leaves the suite
		// green while an unsupported distro's scan is answered with Red
		// Hat's errata.
		{"centos is ahead of RHEL on Stream and behind it on Linux", Distro{ID: "centos", VersionID: "9"}},
		{"rhel with no VERSION_ID", Distro{ID: "rhel", VersionID: ""}},
		{"rhel with a non-numeric version", Distro{ID: "rhel", VersionID: "beta"}},
		// D71 gave Rocky its decision, so the same two edge cases apply to it
		// that apply to rhel above.
		{"rocky with no VERSION_ID", Distro{ID: "rocky", VersionID: ""}},
		{"rocky with a non-numeric version", Distro{ID: "rocky", VersionID: "beta"}},
		// D72 gave AlmaLinux its decision, so the same two edge cases apply
		// to it too.
		{"almalinux with no VERSION_ID", Distro{ID: "almalinux", VersionID: ""}},
		{"almalinux with a non-numeric version", Distro{ID: "almalinux", VersionID: "beta"}},
		// D73: one os-release ID spans four Amazon Linux generations, and
		// only AL2/AL2023 have a provider. Each of these has a version that
		// WOULD otherwise look plausible, so the version itself is what has
		// to be rejected — a bug that mapped every amzn VERSION_ID to
		// whichever key came first would let these through.
		{"amazon linux 1 predates VERSION_ID as amzn/2 spells it", Distro{ID: "amzn", VersionID: "2018.03"}},
		{"amazon linux 2022 was an abandoned preview, frozen 2023-01-31", Distro{ID: "amzn", VersionID: "2022"}},
		{"amazon linux with no VERSION_ID", Distro{ID: "amzn", VersionID: ""}},
		{"amazon linux with a non-numeric version", Distro{ID: "amzn", VersionID: "beta"}},
		// D53 gave Ubuntu its decision, so it resolves now — but only for a
		// VERSION_ID shaped like a release. A version this cannot read is
		// refused rather than concatenated into a key that would look
		// plausible and match nothing in the database.
		{"ubuntu with no VERSION_ID", Distro{ID: "ubuntu", VersionID: ""}},
		{"ubuntu codename instead of a version", Distro{ID: "ubuntu", VersionID: "jammy"}},
		{"ubuntu major only", Distro{ID: "ubuntu", VersionID: "22"}},
		{"ubuntu point release", Distro{ID: "ubuntu", VersionID: "22.04.5"}},
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

// D71: Rocky left D50's not-evaluated list once its own OSV archive was
// ingested. The key is the mainline MAJOR, the same shape D47 gave Red Hat's
// key and for the same reason — OSV's own archive keys are release-qualified
// at the major ("Rocky Linux:9"), not below it.
func TestDistroEcosystem_Rocky(t *testing.T) {
	for _, tc := range []struct {
		versionID string
		want      string
	}{
		{"9", "Rocky Linux:9"},
		{"9.4", "Rocky Linux:9"},
		{"8.10", "Rocky Linux:8"},
		{"10.0", "Rocky Linux:10"},
	} {
		got, err := Distro{ID: "rocky", VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("VERSION_ID=%q: %v", tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("VERSION_ID=%q -> %q, want %q", tc.versionID, got, tc.want)
		}
	}
	// Rocky's key must not converge with Red Hat's, Alpine's or AlmaLinux's —
	// a change that collapsed them would make one distro's advisories
	// reachable under another's key.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"rhel", "9.8", "Red Hat:9"},
		{"rocky", "9.4", "Rocky Linux:9"},
		{"almalinux", "9.6", "AlmaLinux:9"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
	// centos must still not resolve (D50) — Rocky leaving the not-evaluated
	// list must not have been a change to the switch's default case that
	// accidentally let every RPM ID through.
	if _, err := (Distro{ID: "centos", VersionID: "9"}).Ecosystem(); err == nil {
		t.Error("centos resolved an ecosystem; D50 still excludes it")
	}
	// The no-VERSION_ID and non-numeric-VERSION_ID refusals are pinned in
	// TestDistroEcosystem_Unsupported, alongside rhel's identical two rows.
}

// D72: AlmaLinux left D50's not-evaluated list once its own OSV archive was
// ingested, the same move D71 made for Rocky and for the same reason — the
// key is the mainline MAJOR, release-qualified the way the archive's own
// ecosystem keys are ("AlmaLinux:9"), not below it.
func TestDistroEcosystem_Alma(t *testing.T) {
	for _, tc := range []struct {
		versionID string
		want      string
	}{
		{"9", "AlmaLinux:9"},
		{"9.6", "AlmaLinux:9"},
		{"8.10", "AlmaLinux:8"},
		{"10.0", "AlmaLinux:10"},
	} {
		got, err := Distro{ID: "almalinux", VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("VERSION_ID=%q: %v", tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("VERSION_ID=%q -> %q, want %q", tc.versionID, got, tc.want)
		}
	}
	// AlmaLinux's key must not converge with Red Hat's, Rocky's or Alpine's —
	// a change that collapsed them would make one distro's advisories
	// reachable under another's key.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"rhel", "9.8", "Red Hat:9"},
		{"rocky", "9.4", "Rocky Linux:9"},
		{"almalinux", "9.6", "AlmaLinux:9"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
	// centos must still not resolve (D50) — AlmaLinux leaving the
	// not-evaluated list must not have been a change to the switch's
	// default case that accidentally let every RPM ID through.
	if _, err := (Distro{ID: "centos", VersionID: "9"}).Ecosystem(); err == nil {
		t.Error("centos resolved an ecosystem; D50 still excludes it")
	}
	// The no-VERSION_ID and non-numeric-VERSION_ID refusals are pinned in
	// TestDistroEcosystem_Unsupported, alongside rhel's identical two rows.
}

// TestDistroEcosystem_Amazon: D73. One os-release ID ("amzn") spans four
// Amazon Linux generations; only AL2 and AL2023 route to a real key, because
// only those two have a provider (internal/provider/amazon's ALAS core
// feed — there is no OSV archive for any Amazon Linux release at all).
// Unlike Rocky and AlmaLinux the key is release-qualified at the WHOLE
// VERSION_ID string ("2", "2023"), not a truncated major: Amazon spells its
// own release numbers that way already, with no minor component to drop.
func TestDistroEcosystem_Amazon(t *testing.T) {
	for _, tc := range []struct {
		versionID string
		want      string
	}{
		{"2", "Amazon Linux:2"},
		{"2023", "Amazon Linux:2023"},
	} {
		got, err := Distro{ID: "amzn", VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("VERSION_ID=%q: %v", tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("VERSION_ID=%q -> %q, want %q", tc.versionID, got, tc.want)
		}
	}
	// Amazon Linux's keys must not converge with Red Hat's, Rocky's,
	// AlmaLinux's or Alpine's — a change that collapsed them would make one
	// distro's advisories reachable under another's key.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"rhel", "9.8", "Red Hat:9"},
		{"rocky", "9.4", "Rocky Linux:9"},
		{"almalinux", "9.6", "AlmaLinux:9"},
		{"amzn", "2023", "Amazon Linux:2023"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
	// centos must still not resolve (D50) — Amazon Linux leaving part of the
	// not-evaluated list must not have been a change to the switch's default
	// case that accidentally let every RPM ID through.
	if _, err := (Distro{ID: "centos", VersionID: "9"}).Ecosystem(); err == nil {
		t.Error("centos resolved an ecosystem; D50 still excludes it")
	}
	// AL1 (VERSION_ID "2018.03") and AL2022 (VERSION_ID "2022") stay
	// not-evaluated: pinned in TestDistroEcosystem_Unsupported, alongside the
	// no-VERSION_ID and non-numeric-VERSION_ID refusals every other RPM
	// distro's decision needed.
}

// TestDistroEcosystem_Ubuntu pins the two shapes OSV gives a mainline Ubuntu
// release (D53): a long-term one carries ":LTS", an interim one does not.
//
// PRETTY_NAME is the only field on Distro that distinguishes them, which is
// why it stopped being reporting-only. The alternative — inferring LTS from
// an even year and an .04 month — is a rule Canonical has never promised.
//
// The lineage keys are NOT here and must never be produced by this function:
// which lineage a system is entitled to is not something /etc/os-release
// carries, and D53 handles those packages at match time instead.
func TestDistroEcosystem_Ubuntu(t *testing.T) {
	for _, tt := range []struct {
		name string
		d    Distro
		want string
	}{
		// PRETTY_NAME verbatim from the real images, pulled 2026-08-10.
		{"22.04 LTS", Distro{ID: "ubuntu", VersionID: "22.04",
			PrettyName: "Ubuntu 22.04.5 LTS"}, "Ubuntu:22.04:LTS"},
		{"24.04 LTS", Distro{ID: "ubuntu", VersionID: "24.04",
			PrettyName: "Ubuntu 24.04.4 LTS"}, "Ubuntu:24.04:LTS"},
		{"25.10 interim", Distro{ID: "ubuntu", VersionID: "25.10",
			PrettyName: "Ubuntu 25.10"}, "Ubuntu:25.10"},
		// 25.04 is an April release and NOT long-term. An implementation
		// that guessed LTS from the .04 month rather than reading
		// PRETTY_NAME gets this one wrong, and OSV really does key it
		// bare.
		{"25.04 is interim despite the month", Distro{ID: "ubuntu", VersionID: "25.04",
			PrettyName: "Ubuntu 25.04"}, "Ubuntu:25.04"},
		// No PRETTY_NAME at all: the key comes out bare, which names an
		// ecosystem the database does not hold, and D20's coverage check
		// turns that into a whole-package skip rather than a clean
		// verdict. Pinned because that safety net is the reason reading a
		// free-text field here is acceptable at all.
		{"no PRETTY_NAME degrades to the bare key",
			Distro{ID: "ubuntu", VersionID: "22.04"}, "Ubuntu:22.04"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.d.Ecosystem()
			if err != nil {
				t.Fatalf("Ecosystem() error = %v, want %q", err, tt.want)
			}
			if got != tt.want {
				t.Errorf("Ecosystem() = %q, want %q", got, tt.want)
			}
		})
	}
}
