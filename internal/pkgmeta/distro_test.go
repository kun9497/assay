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
		{"unsupported distro", Distro{ID: "gentoo", VersionID: "40"}},
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
		// D74 gave Oracle Linux its decision, so the same two edge cases
		// apply to it that apply to rhel/rocky/almalinux above.
		{"ol with no VERSION_ID", Distro{ID: "ol", VersionID: ""}},
		{"ol with a non-numeric version", Distro{ID: "ol", VersionID: "beta"}},
		// D75 gave Fedora its decision. The no-VERSION_ID and non-numeric
		// cases are the same two every other RPM distro's decision needed --
		// but Fedora ALSO refuses a dotted version, unlike rhel/rocky/
		// almalinux/ol above: fedora-release.spec's VERSION_ID has never
		// carried a minor, so a dotted shape is refused outright rather than
		// silently truncated at the major the way the others are.
		{"fedora with no VERSION_ID", Distro{ID: "fedora", VersionID: ""}},
		{"fedora with a non-numeric version", Distro{ID: "fedora", VersionID: "rawhide"}},
		{"fedora VERSION_ID has never carried a minor; a dotted one is refused, not truncated",
			Distro{ID: "fedora", VersionID: "43.1"}},
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
		// D77 gave SLES and openSUSE Leap their decision, so the same
		// no-VERSION_ID and non-numeric-VERSION_ID edge cases every other RPM
		// distro's decision needed apply to them too.
		{"sles with no VERSION_ID", Distro{ID: "sles", VersionID: ""}},
		{"sles with a non-numeric version", Distro{ID: "sles", VersionID: "beta"}},
		{"sles major only, no minor to read the SP number from", Distro{ID: "sles", VersionID: "15"}},
		{"opensuse-leap with no VERSION_ID", Distro{ID: "opensuse-leap", VersionID: ""}},
		{"opensuse-leap with a non-numeric version", Distro{ID: "opensuse-leap", VersionID: "beta"}},
		// D94 gave Azure Linux (CBL-Mariner and its 2024 rename) its
		// decision, so the same no-VERSION_ID and non-numeric-VERSION_ID
		// edge cases every other RPM distro's decision needed apply to
		// both of its os-release IDs too.
		{"mariner with no VERSION_ID", Distro{ID: "mariner", VersionID: ""}},
		{"mariner with a non-numeric version", Distro{ID: "mariner", VersionID: "beta"}},
		{"azurelinux with no VERSION_ID", Distro{ID: "azurelinux", VersionID: ""}},
		{"azurelinux with a non-numeric version", Distro{ID: "azurelinux", VersionID: "beta"}},
		// D96 gave Photon OS its decision, so the same no-VERSION_ID and
		// non-numeric-VERSION_ID edge cases every other truncated-major RPM
		// distro's decision needed apply to it too.
		{"photon with no VERSION_ID", Distro{ID: "photon", VersionID: ""}},
		{"photon with a non-numeric version", Distro{ID: "photon", VersionID: "beta"}},
		// Tumbleweed is refused by NAME, not by version shape (D77) — pinned
		// here with a version that would otherwise parse as a perfectly good
		// X.Y release, and again with its REAL VERSION_ID (a build date,
		// verified by pulling docker.io/opensuse/tumbleweed:latest 2026-08-20)
		// to prove the refusal does not depend on the version failing to parse.
		{"opensuse-tumbleweed refuses even a version shaped like a release", Distro{ID: "opensuse-tumbleweed", VersionID: "15.6"}},
		{"opensuse-tumbleweed's real VERSION_ID is a build date, not a release", Distro{ID: "opensuse-tumbleweed", VersionID: "20260818"}},
		{"opensuse-tumbleweed with no VERSION_ID at all", Distro{ID: "opensuse-tumbleweed", VersionID: ""}},
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
		// D84 changed the no-PRETTY_NAME case: an SBOM purl's distro
		// qualifier carries no PrettyName at all, and Canonical's even-year
		// .04 cadence is deterministic, so the fallback derives LTS rather
		// than degrading — but ONLY when no statement exists.
		{"no PRETTY_NAME, even-year .04 derives LTS",
			Distro{ID: "ubuntu", VersionID: "22.04"}, "Ubuntu:22.04:LTS"},
		{"no PRETTY_NAME, odd-year .04 stays bare",
			Distro{ID: "ubuntu", VersionID: "23.04"}, "Ubuntu:23.04"},
		{"no PRETTY_NAME, October release stays bare",
			Distro{ID: "ubuntu", VersionID: "24.10"}, "Ubuntu:24.10"},
		// A statement beats the policy: a PRETTY_NAME that exists and does
		// NOT say LTS wins over the even-year rule, whatever the version.
		{"PRETTY_NAME without LTS overrides the even-year rule",
			Distro{ID: "ubuntu", VersionID: "24.04", PrettyName: "Ubuntu Custom 24.04"},
			"Ubuntu:24.04"},
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

// TestDistroEcosystem_Oracle: D74. Oracle Linux left D50's not-evaluated
// list once its own OVAL archive was ingested, the same move D71/D72/D73
// made for Rocky, AlmaLinux and Amazon Linux -- the key is the mainline
// MAJOR, the shape the feed's own "Oracle Linux N is installed" criteria
// gate on, not release-qualified any finer.
func TestDistroEcosystem_Oracle(t *testing.T) {
	for _, tc := range []struct {
		versionID string
		want      string
	}{
		{"9", "Oracle Linux:9"},
		{"9.8", "Oracle Linux:9"},
		{"8.10", "Oracle Linux:8"},
		{"10.0", "Oracle Linux:10"},
	} {
		got, err := Distro{ID: "ol", VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("VERSION_ID=%q: %v", tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("VERSION_ID=%q -> %q, want %q", tc.versionID, got, tc.want)
		}
	}
	// Oracle Linux's key must not converge with Red Hat's, Rocky's,
	// AlmaLinux's or Amazon Linux's -- a change that collapsed them would
	// make one distro's advisories reachable under another's key, and an
	// Oracle rebuild's own release suffixes (elNuek, .ksplice1., .0.1
	// rebuild markers) are never comparable against another distro's data.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"rhel", "9.8", "Red Hat:9"},
		{"rocky", "9.4", "Rocky Linux:9"},
		{"almalinux", "9.6", "AlmaLinux:9"},
		{"amzn", "2023", "Amazon Linux:2023"},
		{"ol", "9.8", "Oracle Linux:9"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
	// centos must still not resolve (D50) -- Oracle Linux leaving the
	// not-evaluated list must not have been a change to the switch's
	// default case that accidentally let every RPM ID through.
	if _, err := (Distro{ID: "centos", VersionID: "9"}).Ecosystem(); err == nil {
		t.Error("centos resolved an ecosystem; D50 still excludes it")
	}
	// The no-VERSION_ID and non-numeric-VERSION_ID refusals are pinned in
	// TestDistroEcosystem_Unsupported, alongside rhel's identical two rows.
}

// TestDistroEcosystem_Fedora: D75. Fedora left D50's not-evaluated list once
// Bodhi's own updates feed was ingested (internal/provider/fedora) -- there
// is no OSV archive for it at all. Unlike every other RPM distro above, the
// key is the WHOLE VERSION_ID, never truncated at a '.' -- fedora-release
// .spec's VERSION_ID has never carried a minor, so "43" IS the release, not
// a major with a dropped minor.
func TestDistroEcosystem_Fedora(t *testing.T) {
	for _, tc := range []struct {
		versionID string
		want      string
	}{
		{"43", "Fedora:43"},
		{"44", "Fedora:44"},
	} {
		got, err := Distro{ID: "fedora", VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("VERSION_ID=%q: %v", tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("VERSION_ID=%q -> %q, want %q", tc.versionID, got, tc.want)
		}
	}
	// Fedora's key must not converge with any other RPM distro's -- a
	// change that collapsed them would make one distro's advisories
	// reachable under another's key.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"rhel", "9.8", "Red Hat:9"},
		{"rocky", "9.4", "Rocky Linux:9"},
		{"almalinux", "9.6", "AlmaLinux:9"},
		{"amzn", "2023", "Amazon Linux:2023"},
		{"ol", "9.8", "Oracle Linux:9"},
		{"fedora", "44", "Fedora:44"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
	// centos must still not resolve (D50) -- Fedora leaving the
	// not-evaluated list must not have been a change to the switch's
	// default case that accidentally let every RPM ID through.
	if _, err := (Distro{ID: "centos", VersionID: "9"}).Ecosystem(); err == nil {
		t.Error("centos resolved an ecosystem; D50 still excludes it")
	}
	// A dotted VERSION_ID ("43.1") is refused rather than truncated to
	// "Fedora:43" -- unlike rhel/rocky/almalinux/ol above, Fedora's release
	// number has never had a minor to drop, so a dotted shape is a format
	// this provider has never seen rather than one it should silently
	// tolerate.
	if got, err := (Distro{ID: "fedora", VersionID: "43.1"}).Ecosystem(); err == nil {
		t.Errorf("fedora 43.1 resolved to %q, want a refusal -- Fedora's VERSION_ID is never dotted", got)
	}
	// The no-VERSION_ID and non-numeric-VERSION_ID refusals are pinned in
	// TestDistroEcosystem_Unsupported, alongside rhel's identical two rows.
}

// TestDistroEcosystem_SLES: D77. SLES left D50's not-evaluated list once
// SUSE's own CSAF VEX feed was ingested (internal/provider/suse) — the ndb
// rpmdb backend D76 built made a SLES image catalogable at all, and this is
// the advisory half D76's own doc comment left open.
//
// VERSION_ID's minor digit is the SP number for every release below 16
// (verified against a real 15.6 image); "N.0" is the bare, pre-SP1 release
// and drops the ".SP0" the same way the CSAF feed's own product name does
// ("SUSE Linux Enterprise Server 15", not "... 15 SP0"). 16 and up carry
// VERSION_ID through verbatim because the feed's own product names already
// dropped the "SPn" wording there ("SUSE Linux Enterprise Server 16.0").
func TestDistroEcosystem_SLES(t *testing.T) {
	for _, tc := range []struct {
		versionID string
		want      string
	}{
		{"15.6", "SLES:15.SP6"},
		{"15.0", "SLES:15"},
		{"15.7", "SLES:15.SP7"},
		{"12.5", "SLES:12.SP5"},
		{"12.0", "SLES:12"},
		{"11.4", "SLES:11.SP4"},
		{"16.0", "SLES:16.0"},
		{"16.1", "SLES:16.1"},
	} {
		got, err := Distro{ID: "sles", VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("VERSION_ID=%q: %v", tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("VERSION_ID=%q -> %q, want %q", tc.versionID, got, tc.want)
		}
	}
	// SLES's key must not converge with any other RPM distro's, openSUSE
	// Leap's, or Alpine's -- a change that collapsed them would make one
	// distro's advisories reachable under another's key.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"rhel", "9.8", "Red Hat:9"},
		{"rocky", "9.4", "Rocky Linux:9"},
		{"almalinux", "9.6", "AlmaLinux:9"},
		{"amzn", "2023", "Amazon Linux:2023"},
		{"ol", "9.8", "Oracle Linux:9"},
		{"fedora", "44", "Fedora:44"},
		{"sles", "15.6", "SLES:15.SP6"},
		{"opensuse-leap", "15.6", "openSUSE Leap:15.6"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
	// centos must still not resolve (D50) -- SLES leaving the not-evaluated
	// list must not have been a change to the switch's default case that
	// accidentally let every RPM ID through.
	if _, err := (Distro{ID: "centos", VersionID: "9"}).Ecosystem(); err == nil {
		t.Error("centos resolved an ecosystem; D50 still excludes it")
	}
	// The no-VERSION_ID and non-numeric-VERSION_ID refusals are pinned in
	// TestDistroEcosystem_Unsupported, alongside rhel's identical two rows.
}

// TestDistroEcosystem_OpenSUSELeap: D77. Unlike SLES, openSUSE Leap's CSAF
// product names ("openSUSE Leap 15.6") match /etc/os-release's VERSION_ID
// 1:1 -- verified against a real docker.io/opensuse/leap:15.6 image -- so
// the key is the family prefix plus VERSION_ID verbatim, no per-module fold.
func TestDistroEcosystem_OpenSUSELeap(t *testing.T) {
	for _, tc := range []struct {
		versionID string
		want      string
	}{
		{"15.6", "openSUSE Leap:15.6"},
		{"15.0", "openSUSE Leap:15.0"},
		{"16.0", "openSUSE Leap:16.0"},
	} {
		got, err := Distro{ID: "opensuse-leap", VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("VERSION_ID=%q: %v", tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("VERSION_ID=%q -> %q, want %q", tc.versionID, got, tc.want)
		}
	}
	// A bare major with no minor must not silently truncate to "openSUSE
	// Leap:15" the way SLES's below-16 branch truncates a bare SP0 -- Leap's
	// key keeps the full VERSION_ID unconditionally, so a dotless VERSION_ID
	// is a shape this branch has never seen rather than one to normalize.
	if got, err := (Distro{ID: "opensuse-leap", VersionID: "15"}).Ecosystem(); err == nil {
		t.Errorf("opensuse-leap VERSION_ID=15 resolved to %q, want a refusal -- there is no minor to read", got)
	}
	// opensuse-tumbleweed must never resolve, whatever VERSION_ID it is given
	// (pinned with several shapes in TestDistroEcosystem_Unsupported) -- it is
	// a rolling release refused by ID, not by a version that fails to parse.
	if _, err := (Distro{ID: "opensuse-tumbleweed", VersionID: "15.6"}).Ecosystem(); err == nil {
		t.Error("opensuse-tumbleweed resolved an ecosystem with a release-shaped VERSION_ID; it must always be refused")
	}
}

// TestDistroEcosystem_WolfiAndChainguard: D88. Both keys are release-less --
// OSV publishes "Wolfi" and "Chainguard" bare, with no per-release archive at
// all -- so VERSION_ID is ignored entirely rather than truncated or parsed.
// Pinned with the REAL frozen VERSION_ID every cgr.dev image ships
// ("20230201", measured 2026-08-22 against both wolfi-base and Chainguard's
// own statically-linked images), which would fail every other distro's X.Y
// or bare-major parse above -- proving the ecosystem does not depend on it
// parsing at all, not merely that it happens to survive a value that does.
func TestDistroEcosystem_WolfiAndChainguard(t *testing.T) {
	for _, tc := range []struct {
		id, versionID string
		want          string
	}{
		{"wolfi", "20230201", "Wolfi"},
		{"chainguard", "20230201", "Chainguard"},
		// No VERSION_ID at all, and an ordinary X.Y shape, must resolve
		// identically -- the field is never consulted, not merely tolerant of
		// one shape over another.
		{"wolfi", "", "Wolfi"},
		{"chainguard", "", "Chainguard"},
		{"wolfi", "3.19", "Wolfi"},
	} {
		got, err := Distro{ID: tc.id, VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("id=%q VERSION_ID=%q: %v", tc.id, tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("id=%q VERSION_ID=%q -> %q, want %q", tc.id, tc.versionID, got, tc.want)
		}
	}
	// Wolfi and Chainguard's keys must not converge with any other distro's,
	// or with each other -- a change that collapsed them would make one
	// ecosystem's advisories reachable under another's key.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"rhel", "9.8", "Red Hat:9"},
		{"wolfi", "20230201", "Wolfi"},
		{"chainguard", "20230201", "Chainguard"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
	// opensuse-tumbleweed must still be refused (D77) -- Wolfi and
	// Chainguard leaving VERSION_ID unconsulted must not have loosened the
	// switch's other rolling-release refusal into resolving too.
	if _, err := (Distro{ID: "opensuse-tumbleweed", VersionID: "20260818"}).Ecosystem(); err == nil {
		t.Error("opensuse-tumbleweed resolved an ecosystem; it must always be refused")
	}
}

// TestDistroEcosystem_MinimOSAndEcho: D92, a clean clone of D88's own test
// above. Both keys are release-less too -- OSV publishes "MinimOS" and
// "Echo" bare, no per-release archive for either -- so VERSION_ID is ignored
// entirely.
//
// MinimOS is pinned with the REAL frozen VERSION_ID reg.mini.dev/nginx:latest
// ships (measured 2026-08-26: "20241031", a wolfi-style build-tooling
// artifact), the same "would fail every other distro's parse" proof D88's
// test uses. Echo has no real image to measure a VERSION_ID from (the
// "echo" case in distro.go is UNVERIFIED) -- covered anyway with an
// ordinary X.Y-shaped value and an empty one, since the case ignores
// VERSION_ID unconditionally regardless of what it contains.
func TestDistroEcosystem_MinimOSAndEcho(t *testing.T) {
	for _, tc := range []struct {
		id, versionID string
		want          string
	}{
		{"minimos", "20241031", "MinimOS"},
		{"echo", "12", "Echo"},
		// No VERSION_ID at all must resolve identically -- the field is never
		// consulted, not merely tolerant of one shape over another.
		{"minimos", "", "MinimOS"},
		{"echo", "", "Echo"},
		{"minimos", "3.19", "MinimOS"},
	} {
		got, err := Distro{ID: tc.id, VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("id=%q VERSION_ID=%q: %v", tc.id, tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("id=%q VERSION_ID=%q -> %q, want %q", tc.id, tc.versionID, got, tc.want)
		}
	}
	// MinimOS and Echo's keys must not converge with any other distro's, or
	// with Wolfi/Chainguard's, or with each other -- a change that collapsed
	// them would make one ecosystem's advisories reachable under another's
	// key.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"wolfi", "20230201", "Wolfi"},
		{"chainguard", "20230201", "Chainguard"},
		{"minimos", "20241031", "MinimOS"},
		{"echo", "12", "Echo"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
	// opensuse-tumbleweed must still be refused (D77) -- MinimOS and Echo
	// leaving VERSION_ID unconsulted must not have loosened the switch's
	// other rolling-release refusal into resolving too.
	if _, err := (Distro{ID: "opensuse-tumbleweed", VersionID: "20260818"}).Ecosystem(); err == nil {
		t.Error("opensuse-tumbleweed resolved an ecosystem; it must always be refused")
	}
}

// TestDistroEcosystem_AzureLinux: D94. CBL-Mariner (through 2.0) and Azure
// Linux (3.0 on, Microsoft's mid-2024 rename of the same lineage) share ONE
// OSV ecosystem family -- both os-release IDs route to the same
// "Azure Linux:<major>" key, following the D71/D72 shape (Rocky, AlmaLinux):
// a genuine release axis, release-qualified at the major, not D88/D92's
// release-less one.
func TestDistroEcosystem_AzureLinux(t *testing.T) {
	for _, tc := range []struct {
		id, versionID string
		want          string
	}{
		{"mariner", "2.0", "Azure Linux:2"},
		{"mariner", "2", "Azure Linux:2"},
		{"azurelinux", "3.0", "Azure Linux:3"},
		{"azurelinux", "3", "Azure Linux:3"},
		// A mariner 1.0 image (CBL-Mariner's first release) resolves a KEY
		// this build holds no data for -- that is D20's ordinary coverage
		// skip, not a routing failure, and the case must not special-case
		// which majors the archive happens to populate.
		{"mariner", "1.0", "Azure Linux:1"},
	} {
		got, err := Distro{ID: tc.id, VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("id=%q VERSION_ID=%q: %v", tc.id, tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("id=%q VERSION_ID=%q -> %q, want %q", tc.id, tc.versionID, got, tc.want)
		}
	}
	// Both os-release IDs must land on the SAME key for the same major --
	// the rename is cosmetic on the advisory side, and a change that let them
	// diverge would split one distro's advisories across two unreachable
	// halves.
	m, err := (Distro{ID: "mariner", VersionID: "2.0"}).Ecosystem()
	if err != nil {
		t.Fatal(err)
	}
	a, err := (Distro{ID: "azurelinux", VersionID: "2.0"}).Ecosystem()
	if err != nil {
		t.Fatal(err)
	}
	if m != a {
		t.Errorf("mariner 2.0 -> %q, azurelinux 2.0 -> %q; both os-release IDs must resolve the SAME key family", m, a)
	}
	// Azure Linux's key must not converge with any other RPM distro's, or
	// with Alpine's -- a change that collapsed them would make one distro's
	// advisories reachable under another's key.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"rhel", "9.8", "Red Hat:9"},
		{"rocky", "9.4", "Rocky Linux:9"},
		{"almalinux", "9.6", "AlmaLinux:9"},
		{"amzn", "2023", "Amazon Linux:2023"},
		{"ol", "9.8", "Oracle Linux:9"},
		{"fedora", "44", "Fedora:44"},
		{"sles", "15.6", "SLES:15.SP6"},
		{"opensuse-leap", "15.6", "openSUSE Leap:15.6"},
		{"mariner", "2.0", "Azure Linux:2"},
		{"azurelinux", "3.0", "Azure Linux:3"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
	// centos must still not resolve (D50) -- Azure Linux leaving the
	// not-evaluated list must not have been a change to the switch's default
	// case that accidentally let every RPM ID through.
	if _, err := (Distro{ID: "centos", VersionID: "9"}).Ecosystem(); err == nil {
		t.Error("centos resolved an ecosystem; D50 still excludes it")
	}
	// The no-VERSION_ID and non-numeric-VERSION_ID refusals are pinned in
	// TestDistroEcosystem_Unsupported, alongside rhel's identical two rows.
}

// TestDistroEcosystem_Photon: D96. VMware/Broadcom Photon OS keys on the
// mainline major, the same D71/D72/D74/D94 shape Rocky/AlmaLinux/Oracle
// Linux/Azure Linux already use -- Photon's own CVE metadata feed is
// published one file per major, and every real image's VERSION_ID measured
// is already an X.0 shape with nothing to lose by truncating at the dot.
func TestDistroEcosystem_Photon(t *testing.T) {
	for _, tc := range []struct {
		id, versionID string
		want          string
	}{
		{"photon", "3.0", "Photon OS:3"},
		{"photon", "4.0", "Photon OS:4"},
		{"photon", "5.0", "Photon OS:5"},
		// A bare major (no dot at all) is accepted the same way rhel/rocky/
		// almalinux/ol/azurelinux accept one -- strings.Cut on a string with
		// no separator returns the whole string as the first half.
		{"photon", "5", "Photon OS:5"},
	} {
		got, err := Distro{ID: tc.id, VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("id=%q VERSION_ID=%q: %v", tc.id, tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("id=%q VERSION_ID=%q -> %q, want %q", tc.id, tc.versionID, got, tc.want)
		}
	}
	// Photon's key must not converge with any other RPM distro's, or with
	// Alpine's -- a change that collapsed them would make one distro's
	// advisories reachable under another's key.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"rhel", "9.8", "Red Hat:9"},
		{"rocky", "9.4", "Rocky Linux:9"},
		{"almalinux", "9.6", "AlmaLinux:9"},
		{"amzn", "2023", "Amazon Linux:2023"},
		{"ol", "9.8", "Oracle Linux:9"},
		{"fedora", "44", "Fedora:44"},
		{"mariner", "2.0", "Azure Linux:2"},
		{"photon", "5.0", "Photon OS:5"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
	// centos must still not resolve (D50) -- Photon leaving the not-evaluated
	// list must not have been a change to the switch's default case that
	// accidentally let every RPM ID through.
	if _, err := (Distro{ID: "centos", VersionID: "9"}).Ecosystem(); err == nil {
		t.Error("centos resolved an ecosystem; D50 still excludes it")
	}
	// The no-VERSION_ID and non-numeric-VERSION_ID refusals are pinned in
	// TestDistroEcosystem_Unsupported, alongside rhel's identical two rows.
}

// TestDistroEcosystem_Alpaquita: D95. BellSoft Alpaquita Linux and Hardened
// Containers are apk distros with a genuine release axis (measured on the
// live OSV archive, 2026-08-26: every affected entry on both families is
// release-qualified, 0 bare occurrences), but an unusual one -- "stream" is
// a literal rolling-channel name sitting beside numbered LTS releases
// "23"/"25", so VERSION_ID is used verbatim once validated rather than
// truncated at a dot the way Rocky/AlmaLinux/Azure Linux's numeric majors
// are.
func TestDistroEcosystem_Alpaquita(t *testing.T) {
	for _, tc := range []struct {
		id, versionID string
		want          string
	}{
		{"alpaquita", "stream", "Alpaquita:stream"},
		{"alpaquita", "23", "Alpaquita:23"},
		{"alpaquita", "25", "Alpaquita:25"},
		{"bellsoft-hardened-containers", "stream", "BellSoft Hardened Containers:stream"},
		{"bellsoft-hardened-containers", "23", "BellSoft Hardened Containers:23"},
		{"bellsoft-hardened-containers", "25", "BellSoft Hardened Containers:25"},
	} {
		got, err := Distro{ID: tc.id, VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("id=%q VERSION_ID=%q: %v", tc.id, tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("id=%q VERSION_ID=%q -> %q, want %q", tc.id, tc.versionID, got, tc.want)
		}
	}
	// No VERSION_ID at all, and a channel this build has never measured, must
	// both be refused -- D6's discipline: a key nothing is stored under
	// matches nothing, and a scan that matches nothing must not look clean.
	for _, tc := range []struct{ id, versionID string }{
		{"alpaquita", ""},
		{"alpaquita", "edge"},
		{"bellsoft-hardened-containers", ""},
		{"bellsoft-hardened-containers", "edge"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err == nil {
			t.Errorf("id=%q VERSION_ID=%q -> %q, want an error", tc.id, tc.versionID, got)
		}
	}
	// The two families must not converge with each other or with Alpine --
	// ID_LIKE=alpine (present on every real Alpaquita/BHC os-release, not
	// read anywhere in this path: Distro carries no such field and
	// osrelease.Parse never populates one) must never leak an Alpaquita or
	// BellSoft Hardened Containers package into an Alpine key, which would
	// silently compare it against Alpine's OWN fixed versions rather than
	// BellSoft's.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"alpaquita", "stream", "Alpaquita:stream"},
		{"bellsoft-hardened-containers", "stream", "BellSoft Hardened Containers:stream"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
}

// TestDistroEcosystem_Arch: D97. Arch has no VERSION_ID at all (only
// BUILD_ID=rolling, which Distro does not even carry a field for) — routed
// on ID alone, into the literal sentinel key "Arch:rolling" rather than a
// bare "Arch" the way Wolfi/MinimOS's genuinely release-less keys are, so
// that a reader cannot mistake the key for a truncated release-qualified
// one.
func TestDistroEcosystem_Arch(t *testing.T) {
	for _, tc := range []struct{ id, versionID, want string }{
		// The real shape: no VERSION_ID at all.
		{"arch", "", "Arch:rolling"},
		// VersionID is never consulted, not merely tolerant of one shape over
		// another — any stray value must resolve identically.
		{"arch", "rolling", "Arch:rolling"},
		{"arch", "3.19", "Arch:rolling"},
	} {
		got, err := Distro{ID: tc.id, VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("id=%q VERSION_ID=%q: %v", tc.id, tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("id=%q VERSION_ID=%q -> %q, want %q", tc.id, tc.versionID, got, tc.want)
		}
	}
	// Arch's key must not converge with any other distro's, or with
	// Wolfi/MinimOS's bare release-less keys.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"wolfi", "20230201", "Wolfi"},
		{"minimos", "20241031", "MinimOS"},
		{"arch", "", "Arch:rolling"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
}

// TestDistroEcosystem_Hummingbird: D98. Red Hat's Project Hummingbird is
// rolling and release-less on the cataloger side, the same shape D88 gave
// Wolfi/Chainguard and D92 gave MinimOS/Echo -- VERSION_ID is a dated build
// snapshot ("20251124", the real value a Hummingbird package's purl
// qualifier carries), never a release axis, so it is ignored entirely
// rather than tolerated in one shape over another.
func TestDistroEcosystem_Hummingbird(t *testing.T) {
	for _, tc := range []struct{ id, versionID, want string }{
		{"hummingbird", "20251124", "Hummingbird"},
		// No VERSION_ID at all, and an RHEL-shaped one, must resolve
		// identically -- the field is never consulted.
		{"hummingbird", "", "Hummingbird"},
		{"hummingbird", "9.8", "Hummingbird"},
	} {
		got, err := Distro{ID: tc.id, VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("id=%q VERSION_ID=%q: %v", tc.id, tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("id=%q VERSION_ID=%q -> %q, want %q", tc.id, tc.versionID, got, tc.want)
		}
	}
	// Hummingbird's key must not converge with any other distro's, or with
	// Wolfi/MinimOS/Arch's bare release-less keys.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"wolfi", "20230201", "Wolfi"},
		{"minimos", "20241031", "MinimOS"},
		{"arch", "", "Arch:rolling"},
		{"hummingbird", "20251124", "Hummingbird"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
	// The guard shape the task description asks for: a real Hummingbird
	// image's ID_LIKE reads "fedora rhel", but Distro carries no ID_LIKE
	// field at all and Ecosystem() switches on ID alone, so neither
	// direction can leak -- a genuine rhel image resolves its own key
	// regardless of what its PrettyName happens to say, and a hummingbird
	// image resolves its own key regardless of an RHEL-shaped VersionID.
	if got, err := (Distro{ID: "rhel", VersionID: "9.8",
		PrettyName: "Red Hat Enterprise Linux 9.8 (hardened, hummingbird-based)"}).Ecosystem(); err != nil || got != "Red Hat:9" {
		t.Errorf("rhel with a hummingbird-like PrettyName -> %q, %v, want %q", got, err, "Red Hat:9")
	}
	if got, err := (Distro{ID: "hummingbird", VersionID: "9.8"}).Ecosystem(); err != nil || got != "Hummingbird" {
		t.Errorf("hummingbird with an RHEL-shaped VersionID -> %q, %v, want %q", got, err, "Hummingbird")
	}
}

// TestDistroEcosystem_CleanStart: D101. CleanStart ships no /etc/os-release
// at all, so Distro.ID is never set to "cleanstart" by osrelease.Parse the
// way every other case's own real image is — scancmd's own marker probe is
// what would set it, before Ecosystem() is ever called. This test only
// covers Ecosystem()'s own half: given ID "cleanstart" (however it got
// there), the key resolves bare and release-less, the same shape
// Wolfi/MinimOS/Echo/Bitnami use, and VersionID is never consulted.
func TestDistroEcosystem_CleanStart(t *testing.T) {
	for _, tc := range []struct{ id, versionID, want string }{
		{"cleanstart", "", "CleanStart"},
		// VersionID is never consulted -- any stray value (a real image's apk
		// repo path carries "v3.20", which is not even a value osrelease ever
		// reads into this field, but stray input elsewhere must not change
		// the answer either) must resolve identically.
		{"cleanstart", "v3.20", "CleanStart"},
		{"cleanstart", "3.19", "CleanStart"},
	} {
		got, err := Distro{ID: tc.id, VersionID: tc.versionID}.Ecosystem()
		if err != nil {
			t.Errorf("id=%q VERSION_ID=%q: %v", tc.id, tc.versionID, err)
			continue
		}
		if got != tc.want {
			t.Errorf("id=%q VERSION_ID=%q -> %q, want %q", tc.id, tc.versionID, got, tc.want)
		}
	}
	// CleanStart's key must not converge with any other distro's, or with
	// Wolfi/MinimOS/Arch/Hummingbird's bare release-less keys.
	for _, tc := range []struct{ id, versionID, want string }{
		{"alpine", "3.19", "Alpine:v3.19"},
		{"wolfi", "20230201", "Wolfi"},
		{"minimos", "20241031", "MinimOS"},
		{"arch", "", "Arch:rolling"},
		{"hummingbird", "20251124", "Hummingbird"},
		{"cleanstart", "", "CleanStart"},
	} {
		if got, err := (Distro{ID: tc.id, VersionID: tc.versionID}).Ecosystem(); err != nil || got != tc.want {
			t.Errorf("%s %s -> %q, %v; want %q", tc.id, tc.versionID, got, err, tc.want)
		}
	}
}
