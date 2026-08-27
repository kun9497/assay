// Package version implements per-ecosystem version ordering.
//
// There is deliberately no shared compareVersions (D9). Debian epochs, RPM
// release ordering, semver pre-release precedence, and PEP 440 all disagree,
// and a single function that tries to serve them is the bug this design avoids.
package version

import (
	"errors"
	"regexp"
	"strings"
)

// ErrInvalid marks a version string that cannot be ordered. Callers must treat
// it as "unknown", never as "not vulnerable" — a swallowed error here is a
// missed vulnerability.
var ErrInvalid = errors.New("invalid version")

// Cause says which side of a comparison could not be read (D36). D35 put that
// in the message; this puts it in the type, because a caller deciding whether
// to fail a build cannot match on prose.
//
// The distinction is whether the person running the scan can act on it. An
// unreadable target version usually means their own inventory; an unreadable
// advisory bound is upstream data they will never be able to fix, and a gate
// that cannot tell the two apart is one that stays red forever and gets turned
// off.
type Cause int

const (
	// CauseUnknown is the zero value, for an error this package did not
	// classify. It is deliberately not one of the two real answers: a caller
	// that has to guess should get "unknown" rather than a plausible default,
	// and a new error site that forgets to classify itself shows up as this
	// rather than silently joining whichever side the zero value named.
	CauseUnknown Cause = iota
	// CauseAdvisoryData: a bound in the advisory could not be read.
	CauseAdvisoryData
	// CauseTargetVersion: the version being tested could not be read.
	CauseTargetVersion
)

// causeErr carries a Cause without changing the message. Error() delegates, so
// D35's wording is untouched and this is purely a second, machine-readable
// channel for the same fact.
type causeErr struct {
	cause Cause
	err   error
}

func (e causeErr) Error() string { return e.err.Error() }
func (e causeErr) Unwrap() error { return e.err }

// withCause tags err, leaving its message exactly as written.
func withCause(c Cause, err error) error { return causeErr{cause: c, err: err} }

// CauseOf reports which side of a comparison an error blames, or CauseUnknown.
func CauseOf(err error) Cause {
	var ce causeErr
	if errors.As(err, &ce) {
		return ce.cause
	}
	return CauseUnknown
}

type Comparer interface {
	// Compare returns -1, 0, or 1. It returns an error wrapping ErrInvalid
	// rather than guessing an ordering for input it cannot parse.
	Compare(a, b string) (int, error)
}

var registry = map[string]Comparer{
	"Go":   SemVer{},
	"npm":  SemVer{},
	"PyPI": PEP440{},
	// Cargo requires a semver-compliant version of every crate it publishes,
	// and Cargo.lock records the resolved one, so the comparer written for npm
	// and Go applies unchanged. crates.io is not a distro: the key carries no
	// release, so it is a plain map entry rather than a prefix rule (D6).
	"crates.io": SemVer{},
	// RubyGems, Packagist, NuGet and Maven are language ecosystems like the
	// four above, not distros: their OSV keys carry no release, so each is a
	// plain map entry rather than a prefix rule (D6).
	"RubyGems":  Gem{},
	"Packagist": Composer{},
	"NuGet":     NuGet{},
	"Maven":     Maven{},
	// D88. Wolfi and Chainguard are apk distros, so APK{} (the same comparer
	// Alpine uses) orders their versions -- measured 2026-08-22 against the
	// live archive: plain apk shapes throughout (X.Y.Z-rN), no epochs, no
	// exotic suffixes. Unlike Alpine's "Alpine:vX.Y" they are plain map
	// entries here, not a prefix rule, because OSV keys them bare with no
	// release at all (D6, satisfied vacuously -- see
	// pkgmeta.Distro.Ecosystem's "wolfi"/"chainguard" cases). The bare
	// "Alpine" comment two entries up already explains why a distro whose
	// key DOES carry a release must never resolve unqualified; that reasoning
	// does not apply here because "Wolfi" and "Chainguard" ARE the whole key
	// this project ever builds for them, not a truncated one.
	"Wolfi":      APK{},
	"Chainguard": APK{},
	// D92. MinimOS is an apk distro too, and a clean clone of the "wolfi"
	// entry above for the identical reason: OSV keys it bare ("MinimOS", no
	// release), so it is a plain map entry rather than a prefix rule (D6
	// satisfied vacuously -- see pkgmeta.Distro.Ecosystem's "minimos" case).
	// Measured 2026-08-26: 10 live versions, all plain apk X.Y.Z-rN shapes.
	"MinimOS": APK{},
	// D92. Echo is deb-based, so Deb{} (the same comparer Debian and Ubuntu
	// use) orders its versions -- measured 2026-08-26: Debian-standard shapes
	// throughout (epochs, ~debNuN backports), plus two custom build suffixes
	// this project has not seen on Debian or Ubuntu itself: "+eN" (898
	// events, e.g. "3.7.4-4+e5") and "+echo.N" (104 events, e.g.
	// "5.2.1+echo.1"). Both are ordinary dpkg revision/upstream characters
	// (deb.go's firstNotIn already allows '+'), so verrevcmp orders them
	// correctly with no comparer change -- deb_test.go pins both shapes.
	// Bare map entry, not a prefix rule, for the same reason "Wolfi" and
	// "Chainguard" are: OSV keys Echo with no release axis at all (D6
	// satisfied vacuously -- see pkgmeta.Distro.Ecosystem's "echo" case), so
	// "Echo" IS the whole key this project ever builds for it.
	"Echo": Deb{},
	// D97. Arch Linux is rolling, release-less on both sides — the tracker's
	// own AVG groups carry no release axis, and neither does the distro
	// itself — so unlike every "X:"-prefixed RPM/apk/deb family above, "Arch"
	// never needs a prefix rule: pkgmeta.Distro.Ecosystem's "arch" case
	// writes the literal sentinel "Arch:rolling" (vunnel's and syft's own
	// shared convention), never a truncated one, so a plain map entry for
	// that EXACT string is the whole key this project ever builds for it —
	// the same shape "Wolfi"/"MinimOS"/"Echo" already use, just with a colon
	// baked into the literal itself rather than a bare name.
	"Arch:rolling": Pacman{},
	// D98. Project Hummingbird is RPM too -- Red Hat's own CSAF VEX feed
	// (internal/provider/redhat) scopes Hummingbird content by CPE within
	// the SAME archive mainline RHEL ingests, and rpmvercmp does not care
	// which distro built the package: measured live, every Hummingbird
	// fixed version is a standard RPM EVR carrying a ".humN" dist tag
	// (e.g. "2.14.3-1.2.hum1"), ordered by rpmvercmp's ordinary
	// trailing-segment rule with no new comparer logic needed, the same way
	// Photon's ".phN" and Azure Linux's ".azl3"/".cm2" tags already are.
	//
	// A bare, plain registry entry rather than a "Hummingbird:"-prefixed
	// rule, following the D88/D92/D97 shape (Wolfi, Chainguard, MinimOS,
	// Echo, Arch:rolling) rather than the D71/D72/D94 release-qualified one
	// (Rocky, AlmaLinux, Azure Linux): Hummingbird is rolling, ships one
	// stream, and pkgmeta.Distro.Ecosystem's "hummingbird" case writes the
	// literal bare string with no release suffix at all — "Hummingbird" IS
	// the whole key this project ever builds for it, not a truncated one.
	"Hummingbird": RPM{},
}

// mainlineUbuntu matches the two shapes OSV gives a mainline Ubuntu release:
// a long-term one carries the suffix, an interim one does not. Anchored, so
// that no lineage key can satisfy it.
var mainlineUbuntu = regexp.MustCompile(`^Ubuntu:[0-9]{2}\.[0-9]{2}(:LTS)?$`)

func For(ecosystem string) (Comparer, bool) {
	// Distro ecosystems carry their release (D6), so "Alpine:v3.19" cannot be a
	// map key — the map would need one entry per release, forever. The bare
	// "Alpine" must NOT resolve: it is not a key we ever build, and letting it
	// through would make a bug that drops the release look like it worked, every
	// lookup landing in an empty bucket and reporting clean.
	if rel, ok := strings.CutPrefix(ecosystem, "Alpine:"); ok && rel != "" {
		return APK{}, true
	}
	// Same rule, same reason: "Debian" bare is not a key this project ever
	// builds, and resolving it would make a bug that drops the release look
	// like it worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Debian:"); ok && rel != "" {
		return Deb{}, true
	}
	// Same rule again. "Red Hat" bare is not a key this project builds — the
	// provider writes "Red Hat:9" from the mainline CPE's major (D47) — and
	// resolving it would make a bug that drops the release look like it
	// worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Red Hat:"); ok && rel != "" {
		return RPM{}, true
	}
	// D71. Rocky is RPM too — its OSV archive is release-qualified the same
	// way ("Rocky Linux:9"), and rpmvercmp does not care which distro built
	// the package. Same rule, same reason as the two clauses above: "Rocky
	// Linux" bare is not a key this project ever builds, and resolving it
	// would make a bug that drops the release look like it worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Rocky Linux:"); ok && rel != "" {
		return RPM{}, true
	}
	// D72. AlmaLinux is RPM too — its own OSV archive is release-qualified the
	// same way ("AlmaLinux:9"), and rpmvercmp does not care which distro built
	// the package (nor that Alma's module builds spell the platform tag
	// "module_el" where Red Hat and Rocky write "module+el" — both are
	// ordinary rpmvercmp separators, D46, and rpmModuleBuild in
	// internal/matcher already recognizes both spellings). Same rule, same
	// reason as the two clauses above: "AlmaLinux" bare is not a key this
	// project ever builds, and resolving it would make a bug that drops the
	// release look like it worked.
	if rel, ok := strings.CutPrefix(ecosystem, "AlmaLinux:"); ok && rel != "" {
		return RPM{}, true
	}
	// D73. Amazon Linux is RPM too -- its ALAS feed is release-qualified the
	// same way ("Amazon Linux:2", "Amazon Linux:2023"), and rpmvercmp does
	// not care which distro built the package (rpm.go's own doc comment
	// already names Amazon Linux as one of the four it orders). Same rule,
	// same reason as the three clauses above: "Amazon Linux" bare is not a
	// key this project ever builds, and resolving it would make a bug that
	// drops the release look like it worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Amazon Linux:"); ok && rel != "" {
		return RPM{}, true
	}
	// D74. Oracle Linux is RPM too -- its own OVAL archive is
	// release-qualified the same way ("Oracle Linux:9"), and rpmvercmp does
	// not care which distro built the package. Same rule, same reason as
	// the four clauses above: "Oracle Linux" bare is not a key this project
	// ever builds, and resolving it would make a bug that drops the release
	// look like it worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Oracle Linux:"); ok && rel != "" {
		return RPM{}, true
	}
	// D75. Fedora is RPM too -- Bodhi's updates feed is release-qualified
	// the same way ("Fedora:43"), and rpmvercmp does not care which distro
	// built the package. Same rule, same reason as the five clauses above:
	// "Fedora" bare is not a key this project ever builds -- the provider
	// writes "Fedora:"+VERSION_ID from a bare-integer release (D75) -- and
	// resolving it would make a bug that drops the release look like it
	// worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Fedora:"); ok && rel != "" {
		return RPM{}, true
	}
	// D77. SLES and openSUSE Leap are RPM too -- SUSE's own CSAF VEX feed
	// (internal/provider/suse) folds SLES's per-module product names into
	// release-qualified keys ("SLES:15.SP6") and openSUSE Leap's map 1:1
	// ("openSUSE Leap:15.6"), and rpmvercmp does not care which distro built
	// the package. Same rule, same reason as the six clauses above: neither
	// bare family name is a key this project ever builds -- distro.go writes
	// "SLES:"+the derived release and "openSUSE Leap:"+VERSION_ID -- and
	// resolving the bare form would make a bug that drops the release look
	// like it worked.
	if rel, ok := strings.CutPrefix(ecosystem, "SLES:"); ok && rel != "" {
		return RPM{}, true
	}
	if rel, ok := strings.CutPrefix(ecosystem, "openSUSE Leap:"); ok && rel != "" {
		return RPM{}, true
	}
	// D94. Azure Linux (CBL-Mariner through 2.0, renamed Azure Linux at 3.0)
	// is RPM too -- its own OSV archive is release-qualified the same way
	// ("Azure Linux:2", "Azure Linux:3"), and rpmvercmp does not care which
	// distro built the package. No new comparer logic was needed: OSV's
	// export already strips both the epoch and the release's .azl3/.cm2 dist
	// tag from every `fixed` bound, and rpmvercmp's own trailing-segment rule
	// ("2.0.1a" > "2.0.1") is what makes an installed "1.42.0-7.azl3" still
	// order at-or-above the stripped fixed "1.42.0-7" correctly. Same rule,
	// same reason as the clauses above: "Azure Linux" bare is not a key this
	// project ever builds -- distro.go writes "Azure Linux:"+major -- and
	// resolving it would make a bug that drops the release look like it
	// worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Azure Linux:"); ok && rel != "" {
		return RPM{}, true
	}
	// D95. Alpaquita and BellSoft Hardened Containers are apk distros too --
	// APK{} (the same comparer Alpine, Wolfi, Chainguard and MinimOS use)
	// orders their versions, and rpmvercmp-shaped concerns do not apply.
	// Unlike Wolfi/Chainguard/MinimOS's bare keys, both families genuinely
	// have a release axis and OSV genuinely keys it ("Alpaquita:stream",
	// "Alpaquita:23", "BellSoft Hardened Containers:25", ... — measured
	// 2026-08-26, 0 bare occurrences on either family), so this is a prefix
	// rule following the D71/D72/D94 shape, not a plain map entry. Same rule,
	// same reason as the clauses above: neither bare family name is a key
	// this project ever builds — pkgmeta.Distro.Ecosystem's "alpaquita"/
	// "bellsoft-hardened-containers" case writes VERSION_ID (verbatim, not
	// truncated — "stream" is not a dotted version) after the colon — and
	// resolving the bare form would make a bug that dropped the release look
	// like it worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Alpaquita:"); ok && rel != "" {
		return APK{}, true
	}
	if rel, ok := strings.CutPrefix(ecosystem, "BellSoft Hardened Containers:"); ok && rel != "" {
		return APK{}, true
	}
	// D96. Photon OS is RPM too -- its own CVE metadata feed
	// (internal/provider/photon) is release-qualified the same way
	// ("Photon OS:3", "Photon OS:4", "Photon OS:5"), and rpmvercmp does not
	// care which distro built the package. res_ver carries a ".phN" distro
	// tag (e.g. "1.20.2-10.ph5") the same way every other RPM family's fixed
	// bound carries its own dist tag, ordered by rpmvercmp's ordinary
	// trailing-segment rule with no new comparer logic needed. Same rule,
	// same reason as the clauses above: "Photon OS" bare is not a key this
	// project ever builds -- distro.go writes "Photon OS:"+major -- and
	// resolving it would make a bug that drops the release look like it
	// worked.
	if rel, ok := strings.CutPrefix(ecosystem, "Photon OS:"); ok && rel != "" {
		return RPM{}, true
	}
	// D53. Ubuntu is dpkg, so the comparer D40 wrote for Debian handles its
	// revisions (2.4.4-2ubuntu17.10) unchanged — the version scheme was never
	// the blocker. The KEY was.
	//
	// Matched by an anchored pattern rather than by prefix, and that is the
	// whole point. Ubuntu:Pro:22.04:LTS and Ubuntu:Pro:FIPS-updates:22.04:LTS
	// are real OSV keys describing the SAME release, and this build does not
	// ingest them (D53). A prefix match would hand them a comparer, and a
	// package carrying such a key would then be evaluated against a database
	// holding nothing for it — the silent clean D20 exists to prevent.
	// Refusing them here routes those packages to the coverage skip instead.
	if mainlineUbuntu.MatchString(ecosystem) {
		return Deb{}, true
	}
	c, ok := registry[ecosystem]
	return c, ok
}
