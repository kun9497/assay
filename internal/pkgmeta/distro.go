package pkgmeta

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ErrNoEcosystem means the target's distro has no ecosystem we can look up.
// Callers must surface the affected packages as skipped: a distro we cannot key
// is not a distro with no vulnerabilities.
var ErrNoEcosystem = errors.New("no vulnerability ecosystem for distro")

// Distro identifies the operating system of a Target. It belongs to the target,
// not to each package (D7): an image is Alpine 3.19; its packages are not.
// Fields mirror /etc/os-release, which is also what syft reports.
type Distro struct {
	ID        string // os-release ID, e.g. "alpine"
	VersionID string // os-release VERSION_ID, e.g. "3.19.9"
	// PrettyName is os-release PRETTY_NAME. It was reporting-only until D53,
	// which reads the word LTS out of it: OSV's Ubuntu keys carry the
	// suffix and nothing else on this struct distinguishes a long-term
	// release from an interim one.
	PrettyName string
}

// Ecosystem returns the OSV ecosystem key for this distro — "Alpine:v3.19".
//
// The release is part of the key (D6) because the fixed version of a package
// differs per release. OSV publishes one ecosystem per Alpine minor release and
// nothing for edge, so anything that is not an X.Y release is an error rather
// than a best-effort key: a key nothing is stored under matches nothing, and a
// scan that matches nothing looks exactly like a clean one.
//
// syft reports VersionID as a patch release ("3.19.9") while OSV keys on the
// minor ("Alpine:v3.19"), so the trailing component is dropped here rather than
// at each call site.
// ubuntuRelease is Ubuntu's YY.MM version, the shape every OSV Ubuntu key
// is built on. Anchored: a VERSION_ID this does not match is refused rather
// than concatenated into a key that would look plausible and match nothing.
var ubuntuRelease = regexp.MustCompile(`^[0-9]{2}\.[0-9]{2}$`)

// ubuntuEvenYearLTS reports whether an Ubuntu VERSION_ID names an April
// release of an even year — Canonical's LTS cadence, unbroken since 6.06
// (which is also the one historical exception this rule tolerates: it
// predates every release OSV keys). Consulted ONLY when no PRETTY_NAME
// exists to say so directly (D84); see the ubuntu case's own comment.
func ubuntuEvenYearLTS(versionID string) bool {
	yy, mm, ok := strings.Cut(versionID, ".")
	if !ok || mm != "04" {
		return false
	}
	n, err := strconv.Atoi(yy)
	if err != nil {
		return false
	}
	return n%2 == 0
}

func (d Distro) Ecosystem() (string, error) {
	if d.ID == "" {
		return "", fmt.Errorf("%w: distro has no ID", ErrNoEcosystem)
	}
	switch d.ID {
	case "alpine":
	case "debian":
		// OSV keys modern Debian releases on the bare major — Debian:11 through
		// Debian:14 hold 200,082 of the archive's 211,021 affected entries,
		// and /etc/os-release's VERSION_ID is that same bare major ("12").
		// The ancient releases OSV spells Debian:3.0 / 5.0 / 6.0 are not
		// reachable this way and are not worth a special case: no supported
		// image ships them.
		//
		// testing and sid carry NO VERSION_ID at all, and OSV publishes no
		// ecosystem for them, so they fall through to the error below. That is
		// deliberate: a scan of a sid image must say it could not be checked,
		// because inventing Debian:14 for it would compare against a release
		// whose fixed versions are not the ones sid ships.
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID (testing or sid), "+
				"and OSV publishes no ecosystem for it", ErrNoEcosystem, d.ID)
		}
		major, _, _ := strings.Cut(d.VersionID, ".")
		if !allDigits(major) {
			return "", fmt.Errorf("%w: distro %q version %q is not a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "Debian:" + major, nil
	case "ubuntu":
		// D53. OSV keys Ubuntu as "Ubuntu:22.04:LTS" for a long-term release and
		// "Ubuntu:25.10" for an interim one, so the suffix is part of the key
		// rather than decoration. It is read from PRETTY_NAME first — the
		// system's own statement about itself — and only when no PRETTY_NAME
		// exists at all (an SBOM purl's distro qualifier carries just
		// "ubuntu-22.04", D84) is LTS derived from the even-year .04 rule
		// below. That derivation is Canonical's release cadence, unbroken
		// since 6.06; it stays a fallback rather than the primary read
		// because a statement beats a policy, and it fires only where no
		// statement was ever available.
		//
		// Getting the suffix wrong is safe in the way that matters: the key
		// would name an ecosystem the database does not hold, and D20's
		// coverage check turns that into a whole-package skip and exit 2,
		// never a clean verdict. That holds for the derivation too — if
		// Canonical ever ships an even-year .04 that is not LTS, the wrong
		// key finds no data and the failure is loud.
		//
		// Only the mainline lineage is keyed here. Ubuntu's Pro, FIPS and
		// Realtime lineages have OSV keys of their own describing the SAME
		// release, and which one a system is entitled to is not a fact
		// /etc/os-release carries. Packages built from one of them are
		// detected by the matcher from their own version string and reported
		// as not evaluated (D53).
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		if !ubuntuRelease.MatchString(d.VersionID) {
			return "", fmt.Errorf("%w: distro %q version %q is not a YY.MM release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		if strings.Contains(d.PrettyName, "LTS") {
			return "Ubuntu:" + d.VersionID + ":LTS", nil
		}
		if d.PrettyName == "" && ubuntuEvenYearLTS(d.VersionID) {
			return "Ubuntu:" + d.VersionID + ":LTS", nil
		}
		return "Ubuntu:" + d.VersionID, nil
	case "rhel":
		// D50. `rhel` and nothing else. Red Hat's CSAF VEX feed describes Red
		// Hat's own builds, keyed on the mainline major (D47), and
		// /etc/os-release's VERSION_ID is "9.8" — the minor is dropped because
		// the key is not release-qualified below the major.
		//
		// The other RPM distributions are NOT routed here, and each is a
		// different reason rather than one blanket caution:
		//
		//   - centos: the ID covers CentOS Linux, which trailed RHEL, AND
		//     CentOS Stream, which runs AHEAD of it. A fixed version that has
		//     not reached RHEL yet is already in Stream, so the same key would
		//     be wrong in opposite directions for the two.
		//   - fedora: a different version scheme and its own advisory feed
		//     (FEDORA-*), but see the "fedora" case below — D75 gave it a
		//     provider of its own rather than leaving it on this list
		//     forever.
		//   - amzn: its own version scheme and its own advisory feed (ALAS-*)
		//     too, but see the "amzn" case below — D73 gave it a provider of
		//     its own rather than leaving it on this list forever.
		//
		// Rocky left this list under D71 below, AlmaLinux under D72, Amazon
		// Linux (AL2 and AL2023 only) under D73, and Fedora under D75: each
		// ingests from its own feed now, so none of them needs (or wants) Red
		// Hat's errata routed at it — module builds spelled `module_el`
		// versus Red Hat's `module+el`, and Alma's own `.alma` release
		// suffixes, were the hazard of matching Alma's installed versions
		// against RED HAT's advisory versions (docs/deferred-decisions.md
		// still records that hazard, for anyone tempted to route Alma at Red
		// Hat's feed instead of its own). Matching a distro's installed
		// versions against ITS OWN advisory versions has no such hazard: both
		// sides come from the same build.
		//
		// Every one of those still reaches the cataloger and is reported as
		// not evaluated, so an unrouted distro is a loud skip and never a
		// clean verdict.
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		major, _, _ := strings.Cut(d.VersionID, ".")
		if !allDigits(major) {
			return "", fmt.Errorf("%w: distro %q version %q is not a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "Red Hat:" + major, nil
	case "rocky":
		// D71. Rocky ingests from its OWN OSV archive ("Rocky Linux/all.zip",
		// measured 2026-08-19), not Red Hat's CSAF feed — unlike AlmaLinux,
		// whose module-build spelling and `.alma` release suffixes make
		// matching against another distro's advisory versions a hazard
		// (the "rhel" case above, and docs/deferred-decisions.md), Rocky's
		// OSV records describe Rocky's own builds, so nothing here is
		// borrowed from another distro's data.
		//
		// The key is release-qualified at the major, because that is the
		// shape the archive's own ecosystem keys carry ("Rocky Linux:9",
		// "Rocky Linux:10") and /etc/os-release's VERSION_ID ("9.4") needs
		// the same truncation D47 already applies to Red Hat's.
		//
		// AlmaLinux left D50's not-evaluated list too, under D72 below —
		// see that case for what made ITS feed usable (0% CVSS, CVE only in
		// `related`), which is a different set of hazards than Rocky's own
		// feed ever had (84.1% native CVSS v3, CVE via `upstream`).
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		major, _, _ := strings.Cut(d.VersionID, ".")
		if !allDigits(major) {
			return "", fmt.Errorf("%w: distro %q version %q is not a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "Rocky Linux:" + major, nil
	case "almalinux":
		// D72. AlmaLinux ingests from its OWN OSV archive ("AlmaLinux/all.zip",
		// measured 2026-08-19), not Red Hat's CSAF feed — the same move D71
		// made for Rocky, and for the same reason: an archive of Alma's own
		// builds carries no byte-identity hazard against Alma's own installed
		// versions, unlike matching Alma against Red Hat's errata (the "rhel"
		// case above).
		//
		// What made Alma's OWN feed usable took two of D71's five decisions,
		// neither of which Rocky needed: the archive carries 0% CVSS anywhere
		// (severity exists only as the summary's leading word, stored as a
		// VENDOR_WORD severity entry and banded by internal/severity), and
		// every CVE lives ONLY in `related` (aliases and upstream are empty
		// on every record) — read here because osv.distroAuthored scopes that
		// read to distro-authored namespaces, so a GHSA record's unrelated
		// `related` entries are never mistaken for aliases.
		//
		// The key is release-qualified at the major for the same reason as
		// Rocky's: the archive's own ecosystem keys carry it ("AlmaLinux:9"),
		// and /etc/os-release's VERSION_ID ("9.6") needs the same truncation.
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		major, _, _ := strings.Cut(d.VersionID, ".")
		if !allDigits(major) {
			return "", fmt.Errorf("%w: distro %q version %q is not a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "AlmaLinux:" + major, nil
	case "amzn":
		// D73. One os-release ID spans four generations: AL1 (EOL, frozen
		// RSS, VERSION_ID "2018.03"), AL2022 (abandoned preview, frozen
		// 2023-01-31, VERSION_ID "2022"), AL2 ("2") and AL2023 ("2023") --
		// and only the latter two have a provider at all
		// (internal/provider/amazon's ALAS core feed; there is no OSV
		// archive for any of them, measured 2026-08-19 against
		// osv-vulnerabilities.storage.googleapis.com/ecosystems.txt).
		// VERSION_ID is what tells the four apart; routing on ID alone would
		// key an AL1 or AL2022 package against fixed versions built for a
		// different release entirely.
		switch d.VersionID {
		case "2":
			return "Amazon Linux:2", nil
		case "2023":
			return "Amazon Linux:2023", nil
		default:
			return "", fmt.Errorf("%w: distro %q version %q is not AL2 or AL2023 "+
				"(AL1 and AL2022 have no provider)", ErrNoEcosystem, d.ID, d.VersionID)
		}
	case "ol":
		// D74. Oracle Linux ingests from its own OVAL feed
		// (internal/provider/oracle), keyed on the mainline MAJOR the same
		// way D47 keyed Red Hat's and D71/D72 keyed Rocky's and AlmaLinux's:
		// the feed's own criteria gate only on "Oracle Linux N is
		// installed", nothing finer, and /etc/os-release's VERSION_ID
		// ("9.8") needs the same truncation.
		//
		// Oracle Linux is NOT routed to Red Hat's CSAF feed (the "rhel" case
		// above), for the same byte-identity reason AlmaLinux is not: an
		// Oracle rebuild carries its own release suffixes (elNuek for the
		// UEK kernel lineage, .ksplice1. for live-patched packages, .0.1
		// rebuild markers) that Red Hat never built and must never be
		// compared against Red Hat's advisory versions.
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		major, _, _ := strings.Cut(d.VersionID, ".")
		if !allDigits(major) {
			return "", fmt.Errorf("%w: distro %q version %q is not a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "Oracle Linux:" + major, nil
	case "fedora":
		// D75. Fedora ingests from Bodhi's own updates REST API
		// (internal/provider/fedora) -- there is no OSV archive for it at
		// all, measured 2026-08-19 against
		// osv-vulnerabilities.storage.googleapis.com/ecosystems.txt (a bare
		// 404) and against api.osv.dev (rejects both "Fedora" and
		// "Fedora:43" as an invalid ecosystem).
		//
		// The key is the WHOLE VERSION_ID, not a truncated major the way
		// rhel/rocky/almalinux/ol above are: fedora-release.spec's f43
		// branch sets VERSION_ID=%{dist_version}, a bare integer with no
		// minor to drop ("43", never "43.1"). Truncating at the first '.'
		// the way the other RPM distros' keys are built would be silently
		// wrong the one time Fedora's own versioning shape changed, so this
		// refuses anything that is not ALL digits rather than reusing the
		// dotted-major helper below.
		//
		// Fedora is NOT routed to Red Hat's CSAF feed (the "rhel" case
		// above) — Red Hat's errata do not describe Fedora at all, and
		// never have; Fedora has always had its own advisory namespace
		// (FEDORA-*).
		if d.VersionID == "" || !allDigits(d.VersionID) {
			return "", fmt.Errorf("%w: distro %q version %q is not a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "Fedora:" + d.VersionID, nil
	case "sles":
		// D77. SLES ingests from SUSE's own CSAF VEX feed (internal/provider/suse),
		// keyed on the release the way D47 keyed Red Hat's — but SUSE spreads one
		// release's advisories over ~20 per-module product names in the raw feed
		// ("SUSE Linux Enterprise Module for Basesystem 15 SP6" etc.), which the
		// provider folds into ONE key per release at ingestion (suse.foldKey).
		// This side of the key has to land on the exact same string byte for
		// byte, or every SLES scan looks up a key nothing was ever stored under
		// and reports clean (D20 turns that into a whole-ecosystem skip instead,
		// but only if the two sides genuinely disagree in a way that resolves to
		// NO key at all — a MISMATCHED key is silent, which is why
		// TestDistroEcosystem_SLES cross-checks this against suse.foldKey's own
		// table rather than trusting the two were written consistently).
		//
		// Verified against a real image (registry.suse.com/bci/bci-base:15.6,
		// pulled 2026-08-20): NAME="SLES", VERSION_ID="15.6",
		// PRETTY_NAME="SUSE Linux Enterprise Server 15 SP6". The minor digit IS
		// the SP number for every release SLES has shipped as "N SPm" in the CSAF
		// product tree (measured across the whole 2026-08-19 CSAF VEX archive:
		// SP0 through SP7 on 15.x, SP1 through SP5 on 12.x, SP1 through SP4 on
		// 11.x) — "15.0" is the bare, pre-SP1 release the feed calls
		// "SUSE Linux Enterprise Server 15" with no suffix at all, which is why a
		// minor of "0" drops the ".SP0" rather than keeping it.
		//
		// SLES 16 broke that pattern: the feed's own product names are already
		// "SUSE Linux Enterprise Server 16.0" / "16.1" (no "SPn" wording anywhere,
		// sampled from the live CSAF archive — no 16.x image has been pulled to
		// verify os-release independently, so VERSION_ID "16.0" is inferred from
		// the CPE the feed carries, cpe:/o:suse:sles:16:16.0:server, not
		// image-verified the way 15.6 is), so major 16 and up are carried through
		// VERSION_ID verbatim instead of being reshaped into "SPn".
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		major, minor, ok := strings.Cut(d.VersionID, ".")
		if !ok || !allDigits(major) || !allDigits(minor) {
			return "", fmt.Errorf("%w: distro %q version %q is not an X.Y release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		if n, err := strconv.Atoi(major); err == nil && n >= 16 {
			return "SLES:" + d.VersionID, nil
		}
		if minor == "0" {
			return "SLES:" + major, nil
		}
		return "SLES:" + major + ".SP" + minor, nil
	case "opensuse-leap":
		// D77. openSUSE Leap's os-release VERSION_ID ("15.6", verified by
		// pulling docker.io/opensuse/leap:15.6 2026-08-20: NAME="openSUSE Leap",
		// ID="opensuse-leap", VERSION_ID="15.6") matches the CSAF feed's own
		// product name 1:1 ("openSUSE Leap 15.6") — no per-module fold needed,
		// only the family prefix, unlike SLES above.
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		major, minor, ok := strings.Cut(d.VersionID, ".")
		if !ok || !allDigits(major) || !allDigits(minor) {
			return "", fmt.Errorf("%w: distro %q version %q is not an X.Y release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "openSUSE Leap:" + d.VersionID, nil
	case "opensuse-tumbleweed":
		// D77. Refused by NAME, not by version shape: Tumbleweed is a rolling
		// release with no stable release axis to key on (SUSE's CSAF feed
		// carries its advisories under the single unqualified "openSUSE
		// Tumbleweed" product, which the provider refuses to fold for the same
		// reason). Verified by pulling docker.io/opensuse/tumbleweed:latest
		// 2026-08-20: VERSION_ID is a build date ("20260818"), not a release —
		// even if that happened to parse as an X.Y version it must never resolve
		// a key, so this is refused before the version is even inspected.
		//
		// This is NOT the same refusal the "wolfi"/"chainguard" cases below
		// decline to make, even though both distros ship no stable release
		// axis. Tumbleweed is a rolling TARGET measured against a
		// release-keyed feed — SUSE's CSAF product tree has no "openSUSE
		// Tumbleweed" entry at all, so there is no key a Tumbleweed package
		// could ever be looked up under, and inventing one would be
		// concatenating a build date into a shape that only coincidentally
		// looks like a version. Wolfi and Chainguard are the opposite: OSV's
		// own archive keys them bare too ("Wolfi", "Chainguard", no release
		// suffix at all, D88) — a rolling PUBLISHER keying one stream per
		// ecosystem, not a release-keyed feed being asked to describe a
		// rolling target. D6 ("the ecosystem key includes the release,
		// because the fixed version differs per release") is satisfied
		// vacuously there: there is no release axis on either side to omit,
		// so nothing is lost by keying bare the way there would be for a
		// real distro with real per-release fixed versions.
		return "", fmt.Errorf("%w: distro %q is a rolling release with no stable "+
			"release to key advisories on", ErrNoEcosystem, d.ID)
	case "minimos":
		// D92. Same shape as "wolfi"/"chainguard" below: OSV keys MinimOS bare
		// ("MinimOS", no release suffix), because MinimOS itself ships no
		// release axis to qualify -- one rolling stream, so D6 is satisfied
		// vacuously the same way it is for Wolfi and Chainguard. VERSION_ID is
		// ignored entirely rather than parsed.
		//
		// VERIFIED against a real image: reg.mini.dev/nginx:latest, pulled
		// 2026-08-26, reports ID=minimos and a frozen VERSION_ID="20241031" --
		// a wolfi-style build-tooling artifact, not a release, so reading it
		// would either always resolve the same stale-looking (but ignored) key
		// or invite a future change to start trusting it and silently stop
		// matching -- the same hazard the "wolfi" case's own comment gives for
		// its two frozen VERSION_IDs.
		//
		// Minimus (the org behind MinimOS) announced it is shutting down
		// 2026-10-22: the registry goes away and the feed freezes after that
		// date. That does not retire this case -- an image already pulled
		// before the shutdown keeps whatever scan value the frozen feed can
		// still provide, which is the whole reason this coverage ships despite
		// the sunset date being known in advance.
		return "MinimOS", nil
	case "echo":
		// D92. Symmetric with "minimos" above -- OSV genuinely keys an "Echo"
		// family, bare, with no release axis -- but UNVERIFIED in the same way
		// the "chainguard" case below is: no public Echo image has been found
		// (the registry requires real credentials and Echo's Docker Hub org is
		// empty, checked 2026-08-26). Kept because an os-release ID this
		// project has never seen firsthand is a more honest gap than a distro
		// it cannot key advisories for at all -- but treat the routing itself,
		// not just the version handling, as a guess until a real image is
		// found that sets it.
		return "Echo", nil
	case "mariner", "azurelinux":
		// D94. One distro lineage, two os-release IDs: Microsoft shipped it as
		// "CBL-Mariner" through 2.0 (ID=mariner) and renamed it "Azure Linux"
		// starting with 3.0 (ID=azurelinux) mid-2024. OSV keeps both releases
		// in ONE ecosystem family, "Azure Linux" — verified against the live
		// archive, 2026-08-26: every affected entry's ecosystem is
		// release-qualified ("Azure Linux:2": 6,614 entries, "Azure Linux:3":
		// 5,402, 0 bare) — so both os-release IDs route to the SAME key
		// family here, the rename is cosmetic on the advisory side, and
		// nothing about the fixed versions differs because of which name a
		// given release shipped under.
		//
		// The key is release-qualified at the major, following the D71/D72
		// shape (Rocky, AlmaLinux) rather than D88/D92's release-less one
		// (Wolfi, Chainguard, MinimOS, Echo): unlike those, Azure Linux
		// genuinely has a release axis and OSV genuinely keys on it, so D6
		// applies with full force here, not vacuously.
		//
		// VERIFIED against real images, 2026-08-26: CBL-Mariner 2.0
		// (mcr.microsoft.com/cbl-mariner/base/core:2.0) reports ID=mariner,
		// VERSION_ID="2.0"; Azure Linux 3.0
		// (mcr.microsoft.com/azurelinux/base/core:3.0) reports ID=azurelinux,
		// VERSION_ID="3.0". Truncating at the first '.' the same way
		// rhel/rocky/almalinux/ol do above resolves both correctly. A
		// mariner 1.0 image (VERSION_ID "1.0", CBL-Mariner's first release)
		// resolves to "Azure Linux:1" by the identical rule — a key this
		// build holds no data for, which is D20's ordinary coverage skip, not
		// a routing failure; the case does not need to know which majors the
		// archive actually populated.
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		major, _, _ := strings.Cut(d.VersionID, ".")
		if !allDigits(major) {
			return "", fmt.Errorf("%w: distro %q version %q is not a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "Azure Linux:" + major, nil
	case "alpaquita", "bellsoft-hardened-containers":
		// D95. BellSoft's two apk distros share one release axis and one
		// ecosystem-family shape, verified against the live OSV archive,
		// 2026-08-26: every affected entry on both "Alpaquita" (13,627
		// records) and "BellSoft Hardened Containers" (635 records, a
		// measured byte-identical filename subset of Alpaquita's own zip —
		// see fetch.go's Ecosystems comment) is release-qualified —
		// "Alpaquita:stream" (14,470 entries), "Alpaquita:25" (10,946),
		// "Alpaquita:23" (9,659), and the three BellSoft Hardened Containers
		// equivalents — 0 occurrences of a bare, unqualified key on either
		// family. So unlike Wolfi/Chainguard/MinimOS/Echo below, D6 applies
		// with full force here, the same as it does for Rocky/AlmaLinux/
		// Azure Linux: the release is genuinely part of the key.
		//
		// The release axis itself is unusual, though: "stream" is a literal
		// channel name, not a truncatable X.Y version, sitting alongside
		// numbered LTS releases "23"/"25" — so VERSION_ID is used VERBATIM
		// once validated, rather than truncated at the first dot the way
		// Rocky/AlmaLinux/Azure Linux's numeric majors are. Verified against
		// real images, 2026-08-26: bellsoft/alpaquita-linux-base:musl and
		// :glibc both report ID=alpaquita, ID_LIKE=alpine,
		// VERSION_ID=stream, PRETTY_NAME="BellSoft Alpaquita Linux Stream
		// (musl)"/"(glibc)"; a Liberica JDK image built on Alpaquita
		// (bellsoft/liberica-runtime-container) reports the identical
		// ID/VERSION_ID, and BellSoft Hardened Containers images
		// (bellsoft/hardened-base, bellsoft/hardened-liberica-runtime-
		// container) report ID=bellsoft-hardened-containers with the same
		// VERSION_ID shape.
		//
		// ID_LIKE=alpine is never read on this path — Distro carries no such
		// field, and osrelease.Parse never populates one — so there is no
		// code path by which an Alpaquita or BellSoft Hardened Containers
		// package could be routed into an Alpine key by accident (D6's
		// "release differs per distro" reasoning would be silently violated
		// if it were: Alpaquita's own fixed versions are BellSoft's, not
		// Alpine's, even where a package shares Alpine's name).
		//
		// No LIBC_TYPE distinction is made, and none is needed: the feed
		// measured 0 affected entries keyed or qualified by musl versus
		// glibc. A "glibc" package genuinely exists as its own advisory
		// subject on every release key (BellSoft ships glibc itself as an
		// apk package on the glibc variant), ordinary D8 source/binary
		// matching the same way any other package name is — the musl/glibc
		// split is which packages an image HAS installed, never a second
		// axis on the advisory key.
		switch {
		case d.VersionID == "stream":
			// fine
		case d.VersionID != "" && allDigits(d.VersionID):
			// fine
		default:
			return "", fmt.Errorf(
				"%w: distro %q version %q is neither \"stream\" nor a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		if d.ID == "alpaquita" {
			return "Alpaquita:" + d.VersionID, nil
		}
		return "BellSoft Hardened Containers:" + d.VersionID, nil
	case "photon":
		// D96. VMware/Broadcom Photon OS ingests from its own CVE metadata
		// feed (internal/provider/photon) -- there is no OSV archive for it
		// at all, verified absent from
		// osv-vulnerabilities.storage.googleapis.com/ecosystems.txt,
		// 2026-08-26. The key is the mainline MAJOR, following the same
		// D71/D72/D74/D94 shape as Rocky/AlmaLinux/Oracle Linux/Azure Linux:
		// Photon's feed is published one FILE per major
		// (cve_data_photon{3.0,4.0,5.0}.json), never per minor, and every
		// VERSION_ID measured against a real image is already an X.0 shape
		// with no minor variance to lose ("3.0", "4.0", "5.0" -- Photon does
		// not ship point releases the way RHEL does), so truncating at the
		// first '.' the way rhel/rocky/almalinux/ol/azurelinux do is exact,
		// not lossy, here.
		//
		// Verified against real images, 2026-08-26 (mirror.gcr.io/library/
		// photon:{3.0,4.0,5.0}): all three report ID=photon, VERSION_ID
		// verbatim "3.0"/"4.0"/"5.0", and no ID_LIKE at all -- unlike
		// mariner/azurelinux, there is no sibling os-release ID to route
		// here alongside this one.
		//
		// endoflife.date's own Photon release names ("3.0", "4.0", "5.0",
		// verified live) are NOT what this key uses -- scancmd.eolCycle
		// reshapes the truncated major back to the dotted form before
		// looking an EOL row up, the same "reshape at the READ side, not the
		// key side" convention SLES's ".SP" fold already established, kept
		// here so the ecosystem key stays release-qualified at the same
		// granularity the feed itself publishes at.
		if d.VersionID == "" {
			return "", fmt.Errorf("%w: distro %q has no VERSION_ID", ErrNoEcosystem, d.ID)
		}
		major, _, _ := strings.Cut(d.VersionID, ".")
		if !allDigits(major) {
			return "", fmt.Errorf("%w: distro %q version %q is not a numbered release",
				ErrNoEcosystem, d.ID, d.VersionID)
		}
		return "Photon OS:" + major, nil
	case "wolfi":
		// D88. OSV keys Wolfi bare ("Wolfi", no release suffix) because Wolfi
		// itself ships no release axis — it is a single rolling stream, and
		// the fixed version of a package does not differ "per release" the
		// way it does for Alpine or Debian because there is only ever one
		// release. VERSION_ID is deliberately never consulted: every cgr.dev
		// image measured (wolfi-base and Chainguard's own statically-linked
		// images alike, 2026-08-22) ships the same frozen
		// VERSION_ID="20230201" — a build-tooling artifact, not a release —
		// so reading it would either always resolve the same stale-looking
		// key (harmless, since it is ignored) or, worse, invite a future
		// change to start trusting it and silently stop matching.
		//
		// See the "opensuse-tumbleweed" case above for why a bare key here
		// satisfies D6 rather than being the same refusal Tumbleweed gets:
		// this is a rolling PUBLISHER with no release axis on the ADVISORY
		// side either, not a rolling target measured against a release-keyed
		// feed.
		return "Wolfi", nil
	case "chainguard":
		// D88. Symmetric with "wolfi" above, and UNVERIFIED: every real
		// cgr.dev image measured (2026-08-22), including Chainguard's own
		// static base images, reports ID=wolfi in /etc/os-release, never
		// ID=chainguard. No public image has been found that would exercise
		// this branch. It is kept because the OSV archive genuinely does key
		// a "Chainguard" ecosystem family (distinct from "Wolfi", D88's own
		// "one feed, two keys" fetch), and an os-release ID this project has
		// simply never seen is a more honest gap than a distro this package
		// cannot key advisories for at all — but treat the routing itself,
		// not just the version handling, as a guess until a real image is
		// found that sets it.
		return "Chainguard", nil
	case "arch":
		// D97. Arch Linux is rolling — there is no VERSION_ID at all in its
		// os-release (only BUILD_ID=rolling, verified against a real image,
		// mirror.gcr.io/library/archlinux, pulled 2026-08-26), so this routes
		// on ID alone and ignores VersionID entirely rather than requiring it
		// the way every release-qualified case above does.
		//
		// The key is the literal sentinel "Arch:rolling" — vunnel's and
		// syft's own shared convention for a distro with no release axis at
		// all, NOT a bare unqualified name like "Wolfi"/"MinimOS" above:
		// those are release-less because OSV never gave them a release
		// dimension; Arch is release-less because the distro itself has
		// none, and "rolling" is written into the key so a reader cannot
		// mistake it for a truncated one the way a bare "Arch" might read.
		// internal/version's registry entry and internal/provider/arch's own
		// advisory keys must spell the identical string.
		//
		// Distro carries no BuildID field — only ID, VersionID and
		// PrettyName — so even if this case wanted to distinguish "rolling"
		// from some hypothetical other BUILD_ID, there is nowhere on this
		// struct to read it from today; os-release's BUILD_ID is simply not
		// parsed. That is fine here: Arch Linux has shipped exactly one
		// rolling stream for as long as this project has looked, so there is
		// nothing a second value would need to distinguish.
		return "Arch:rolling", nil
	case "cleanstart":
		// D101. CleanStart (apk-based hardened containers) ships NO
		// /etc/os-release at all — verified against 11/11 real pulled images
		// (busybox, kafka, mariadb, mysql, nginx, node, postgres, python,
		// redis, ruby, rust), every one reporting zero bytes at that path.
		// Distro.ID here is therefore never set by osrelease.Parse the way
		// every other case in this switch is: scancmd's own marker probe
		// (the apk installed-db package "clnstrt-baselayout", present 11/11)
		// is what sets it to the literal "cleanstart" before Ecosystem() is
		// ever called, only when no real os-release was found at all — see
		// that probe's own comment for why a real os-release always wins.
		//
		// The key is the bare, release-less "CleanStart" sentinel, the same
		// shape as Wolfi/Chainguard/MinimOS/Echo/Bitnami (D88/D92/D99):
		// measured against the live OSV archive 2026-08-27 (the GCS bucket
		// still serves the same 1,988-record snapshot Last-Modified
		// 2026-08-19 that a five-times-larger live upstream git tree has
		// since outgrown — this build ingests whatever that bucket serves,
		// so 1,988 is the number that matters here), every one of the
		// archive's affected entries carries the bare "CleanStart" key, 0
		// release-qualified occurrences — apk-repo "v3.20" and VERSION_ID
		// are real facts about a CleanStart image but neither is a release
		// axis OSV keys advisories on, so VersionID is not consulted at all
		// (D6 satisfied vacuously, not violated).
		return "CleanStart", nil
	case "hummingbird":
		// D98. Red Hat's Project Hummingbird (a minimal hardened container
		// line, April 2026) ingests from the SAME CSAF VEX feed as mainline
		// RHEL (internal/provider/redhat), scoped by its own CPE
		// ("cpe:/a:redhat:hummingbird:1") rather than routed here by
		// VERSION_ID the way rhel/rocky/almalinux/ol truncate a dotted
		// major — there is no dotted major to truncate.
		//
		// VersionID is deliberately ignored entirely, the same shape D88 gave
		// Wolfi/Chainguard and D92 gave MinimOS/Echo: os-release's own
		// VERSION_ID ("20251124", verified against the purl qualifier a real
		// Hummingbird package carries, distro=hummingbird-20251124) and that
		// purl qualifier itself are both DATED BUILD SNAPSHOTS, not a release
		// axis — they change on every rebuild the way MinimOS's frozen
		// VERSION_ID never does, so reading either would fragment one
		// rolling stream into phantom per-snapshot releases (D92's own
		// MinimOS reasoning, restated for a snapshot that actually DOES
		// change rather than one that happens to stay frozen). This is also
		// grype's own convention: vunnel assigns Hummingbird
		// {Alias: "hummingbird", Rolling: true}, the identical shape it gives
		// Wolfi and Chainguard.
		//
		// The key is the bare "Hummingbird" sentinel, not "Hummingbird:1" or
		// "Hummingbird:20251124" — internal/provider/redhat's own
		// hummingbirdEcosystem constant must spell the identical string, and
		// TestEcosystemAgreesWithCataloger_Hummingbird (in that package)
		// cross-checks the two directly, the same discipline D77's
		// TestKeyAgreesWithCataloger holds for SLES's fold.
		//
		// ID_LIKE on a real Hummingbird image reads "fedora rhel" (Red Hat's
		// hardened images inherit RHEL's os-release lineage fields), but
		// Distro carries no ID_LIKE field at all and this switch keys on ID
		// alone, so a real rhel image can never be misrouted here by sharing
		// that lineage, nor can a hummingbird image fall through to the
		// "rhel" case above it.
		return "Hummingbird", nil
	default:
		return "", fmt.Errorf("%w: distro %q is not supported yet", ErrNoEcosystem, d.ID)
	}

	major, rest, ok := strings.Cut(d.VersionID, ".")
	if !ok {
		return "", fmt.Errorf("%w: distro %q version %q is not an X.Y release",
			ErrNoEcosystem, d.ID, d.VersionID)
	}
	minor, _, _ := strings.Cut(rest, ".")
	if !allDigits(major) || !allDigits(minor) {
		// edge and pre-releases land here. They have no OSV ecosystem at all,
		// so there is no key to fall back to.
		return "", fmt.Errorf("%w: distro %q version %q is not an X.Y release",
			ErrNoEcosystem, d.ID, d.VersionID)
	}
	return "Alpine:v" + major + "." + minor, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
